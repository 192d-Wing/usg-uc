//! DTLS record layer implementation.
//!
//! Implements the DTLS 1.2 record layer per RFC 6347.
//!
//! ## Record Format (RFC 6347 Section 4.1)
//!
//! ```text
//! struct {
//!     ContentType type;           // 1 byte
//!     ProtocolVersion version;    // 2 bytes
//!     uint16 epoch;               // 2 bytes
//!     uint48 sequence_number;     // 6 bytes
//!     uint16 length;              // 2 bytes
//!     opaque fragment[length];    // variable
//! } DTLSRecord;
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-13**: Cryptographic Protection (AES-256-GCM in the FIPS module)
//! - **SC-12**: record keys live only in aws-lc contexts; the implicit IVs
//!   are wiped on drop ([`AssociationRecordLayer`])
//! - **SC-23**: anti-replay window (RFC 6347 §4.1.2.6)
//! - **SC-5 / SI-10**: bounds-checked parsing, a cap on records per
//!   datagram, silent discard of records that cannot be accepted

use crate::error::{DtlsError, DtlsResult};
use crate::wire::reader::Reader;
use uc_crypto::aead::{Aes256GcmKey, KEY_LEN, NONCE_LEN, TAG_LEN};
use uc_crypto::tls12::Tls12GcmSealer;

/// DTLS record header length.
pub const RECORD_HEADER_LEN: usize = 13;

/// Maximum DTLS record size (including header).
pub const MAX_RECORD_SIZE: usize = 16384 + RECORD_HEADER_LEN + TAG_LEN;

/// Maximum plaintext fragment size.
pub const MAX_FRAGMENT_SIZE: usize = 16384;

/// DTLS version 1.2 (0xFEFD per RFC 6347).
pub const DTLS_1_2_VERSION: u16 = 0xFEFD;

/// DTLS version 1.0 (0xFEFF). Accepted only as the record-layer version of
/// plaintext (epoch 0) records, where some stacks still use it for hellos.
pub const DTLS_1_0_VERSION: u16 = 0xFEFF;

/// Most records read from one datagram; the rest of the datagram is dropped.
pub const MAX_RECORDS_PER_DATAGRAM: usize = 16;

/// Highest record sequence number (uint48). Sealing stops here.
pub const MAX_SEQUENCE_NUMBER: u64 = (1 << 48) - 1;

/// Length of the explicit part of the AES-GCM nonce (RFC 5288 §3).
const EXPLICIT_NONCE_LEN: usize = 8;

/// DTLS content types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// Change cipher spec message.
    ChangeCipherSpec = 20,
    /// Alert message.
    Alert = 21,
    /// Handshake message.
    Handshake = 22,
    /// Application data.
    ApplicationData = 23,
}

impl ContentType {
    /// Maps a wire value to a content type without allocating.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

impl TryFrom<u8> for ContentType {
    type Error = DtlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            _ => Err(DtlsError::RecordError {
                reason: format!("invalid content type: {value}"),
            }),
        }
    }
}

/// DTLS record header.
#[derive(Debug, Clone)]
pub struct RecordHeader {
    /// Content type.
    pub content_type: ContentType,
    /// Protocol version.
    pub version: u16,
    /// Epoch (incremented on key change).
    pub epoch: u16,
    /// Sequence number within epoch.
    pub sequence_number: u64,
    /// Fragment length.
    pub length: u16,
}

impl RecordHeader {
    /// Parses a record header from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the buffer is too small or contains invalid data.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> DtlsResult<Self> {
        if data.len() < RECORD_HEADER_LEN {
            return Err(DtlsError::RecordError {
                reason: format!("buffer too small: {} < {RECORD_HEADER_LEN}", data.len()),
            });
        }

        let content_type = ContentType::try_from(data[0])?;
        let version = u16::from_be_bytes([data[1], data[2]]);
        let epoch = u16::from_be_bytes([data[3], data[4]]);

        // Sequence number is 6 bytes (uint48)
        let sequence_number =
            u64::from_be_bytes([0, 0, data[5], data[6], data[7], data[8], data[9], data[10]]);

        let length = u16::from_be_bytes([data[11], data[12]]);

        Ok(Self {
            content_type,
            version,
            epoch,
            sequence_number,
            length,
        })
    }

    /// Serializes the header to bytes.
    #[must_use]
    pub fn serialize(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut header = [0u8; RECORD_HEADER_LEN];

        header[0] = self.content_type as u8;
        header[1..3].copy_from_slice(&self.version.to_be_bytes());
        header[3..5].copy_from_slice(&self.epoch.to_be_bytes());

        // Sequence number is 6 bytes
        let seq_bytes = self.sequence_number.to_be_bytes();
        header[5..11].copy_from_slice(&seq_bytes[2..8]);

        header[11..13].copy_from_slice(&self.length.to_be_bytes());

        header
    }

    /// Returns the explicit nonce for AES-GCM.
    ///
    /// Per RFC 5288, the nonce is constructed as:
    /// - 4 bytes: implicit IV from key derivation
    /// - 8 bytes: explicit nonce = epoch (2) + `sequence_number` (6)
    #[must_use]
    pub fn explicit_nonce(&self) -> [u8; 8] {
        let mut nonce = [0u8; 8];
        nonce[0..2].copy_from_slice(&self.epoch.to_be_bytes());
        let seq_bytes = self.sequence_number.to_be_bytes();
        nonce[2..8].copy_from_slice(&seq_bytes[2..8]);
        nonce
    }
}

/// DTLS record layer for encryption/decryption.
///
/// Handles AES-256-GCM encryption with CNSA 2.0 compliance.
pub struct RecordLayer {
    /// Write key: the module's TLS 1.2 GCM seal.
    write_key: Option<Tls12GcmSealer>,
    /// Read key for decryption.
    read_key: Option<Aes256GcmKey>,
    /// Write implicit IV (first 4 bytes of nonce).
    write_iv: [u8; 4],
    /// Read implicit IV (first 4 bytes of nonce).
    read_iv: [u8; 4],
    /// Current epoch for writing.
    write_epoch: u16,
    /// Current sequence number for writing.
    write_seq: u64,
    /// Expected read epoch.
    read_epoch: u16,
    /// Anti-replay window.
    replay_window: ReplayWindow,
}

impl RecordLayer {
    /// Creates a new record layer in plaintext mode.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            write_key: None,
            read_key: None,
            write_iv: [0u8; 4],
            read_iv: [0u8; 4],
            write_epoch: 0,
            write_seq: 0,
            read_epoch: 0,
            replay_window: ReplayWindow::new(),
        }
    }

    /// Activates encryption with the given keys.
    ///
    /// This should be called after the `ChangeCipherSpec` message.
    pub fn activate_cipher(
        &mut self,
        write_key: Tls12GcmSealer,
        read_key: Aes256GcmKey,
        write_iv: [u8; 4],
        read_iv: [u8; 4],
    ) {
        self.write_key = Some(write_key);
        self.read_key = Some(read_key);
        self.write_iv = write_iv;
        self.read_iv = read_iv;
        self.write_epoch += 1;
        self.write_seq = 0;
        self.read_epoch += 1;
        self.replay_window = ReplayWindow::new();
    }

    /// Checks if encryption is active.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.write_key.is_some()
    }

    /// Encrypts and frames a record.
    ///
    /// ## Errors
    ///
    /// Returns an error if encryption fails, including a non-increasing
    /// explicit nonce (refused by the module's TLS 1.2 seal).
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        fragment: &[u8],
    ) -> DtlsResult<Vec<u8>> {
        if fragment.len() > MAX_FRAGMENT_SIZE {
            return Err(DtlsError::RecordError {
                reason: format!(
                    "fragment too large: {} > {MAX_FRAGMENT_SIZE}",
                    fragment.len()
                ),
            });
        }

        let header = RecordHeader {
            content_type,
            version: DTLS_1_2_VERSION,
            epoch: self.write_epoch,
            sequence_number: self.write_seq,
            length: 0, // Will be set after encryption
        };

        let output = if let Some(ref mut key) = self.write_key {
            // Build nonce: 4 byte implicit IV + 8 byte explicit nonce
            let explicit_nonce = header.explicit_nonce();
            let mut nonce = [0u8; NONCE_LEN];
            nonce[0..4].copy_from_slice(&self.write_iv);
            nonce[4..12].copy_from_slice(&explicit_nonce);

            // Additional authenticated data is the record header (without length)
            let mut aad = [0u8; 13];
            aad[0] = content_type as u8;
            aad[1..3].copy_from_slice(&DTLS_1_2_VERSION.to_be_bytes());
            aad[3..5].copy_from_slice(&header.epoch.to_be_bytes());
            let seq_bytes = header.sequence_number.to_be_bytes();
            aad[5..11].copy_from_slice(&seq_bytes[2..8]);
            // Length in AAD is the plaintext length - fragment len is bounded by MAX_FRAGMENT_SIZE
            #[allow(clippy::cast_possible_truncation)]
            aad[11..13].copy_from_slice(&(fragment.len() as u16).to_be_bytes());

            // Encrypt. RFC 5288 §3: the explicit nonce (epoch || seq) only
            // increases, which the module's TLS 1.2 seal enforces.
            let ciphertext =
                key.seal(&nonce, &aad, fragment)
                    .map_err(|e| DtlsError::EncryptionFailed {
                        reason: format!("AES-256-GCM seal failed: {e}"),
                    })?;

            // Build output: header + explicit_nonce + ciphertext_with_tag
            let total_len = explicit_nonce.len() + ciphertext.len();
            let mut header_with_len = header;
            // total_len is bounded by MAX_FRAGMENT_SIZE + TAG_LEN + 8 which fits in u16
            #[allow(clippy::cast_possible_truncation)]
            {
                header_with_len.length = total_len as u16;
            }

            let mut output = Vec::with_capacity(RECORD_HEADER_LEN + total_len);
            output.extend_from_slice(&header_with_len.serialize());
            output.extend_from_slice(&explicit_nonce);
            output.extend_from_slice(&ciphertext);
            output
        } else {
            // Plaintext mode
            let mut header_with_len = header;
            // fragment.len() is bounded by MAX_FRAGMENT_SIZE which fits in u16
            #[allow(clippy::cast_possible_truncation)]
            {
                header_with_len.length = fragment.len() as u16;
            }

            let mut output = Vec::with_capacity(RECORD_HEADER_LEN + fragment.len());
            output.extend_from_slice(&header_with_len.serialize());
            output.extend_from_slice(fragment);
            output
        };

        self.write_seq += 1;
        Ok(output)
    }

    /// Decrypts a record.
    ///
    /// ## Returns
    ///
    /// The content type and decrypted fragment.
    ///
    /// ## Errors
    ///
    /// Returns an error if decryption fails or replay is detected.
    pub fn decrypt_record(&mut self, record: &[u8]) -> DtlsResult<(ContentType, Vec<u8>)> {
        let header = RecordHeader::parse(record)?;

        if record.len() < RECORD_HEADER_LEN + header.length as usize {
            return Err(DtlsError::RecordError {
                reason: "truncated record".to_string(),
            });
        }

        let payload = &record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + header.length as usize];

        let fragment = if let Some(ref key) = self.read_key {
            // Validate epoch and replay before decryption
            validate_record_epoch(header.epoch, self.read_epoch)?;
            validate_replay(&self.replay_window, header.sequence_number)?;

            // Decrypt the payload
            let plaintext = decrypt_aes_gcm_payload(key, self.read_iv, &header, payload)?;

            // Update replay window after successful decryption
            self.replay_window.update(header.sequence_number);

            plaintext
        } else {
            payload.to_vec()
        };

        Ok((header.content_type, fragment))
    }

    /// Returns the current write epoch and sequence number.
    #[must_use]
    pub const fn write_sequence(&self) -> (u16, u64) {
        (self.write_epoch, self.write_seq)
    }
}

impl Default for RecordLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the 12-byte nonce for decryption.
fn build_decryption_nonce(read_iv: [u8; 4], explicit_nonce: &[u8]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0..4].copy_from_slice(&read_iv);
    nonce[4..12].copy_from_slice(explicit_nonce);
    nonce
}

/// Builds the 13-byte AAD for AEAD decryption.
#[allow(clippy::cast_possible_truncation)]
fn build_aad(header: &RecordHeader, plaintext_len: usize) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[0] = header.content_type as u8;
    aad[1..3].copy_from_slice(&header.version.to_be_bytes());
    aad[3..5].copy_from_slice(&header.epoch.to_be_bytes());
    let seq_bytes = header.sequence_number.to_be_bytes();
    aad[5..11].copy_from_slice(&seq_bytes[2..8]);
    // plaintext_len is bounded by ciphertext length which fits in u16
    aad[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
    aad
}

/// Validates that the record epoch matches the expected epoch.
fn validate_record_epoch(record_epoch: u16, expected_epoch: u16) -> DtlsResult<()> {
    if record_epoch != expected_epoch {
        return Err(DtlsError::RecordError {
            reason: format!("epoch mismatch: expected {expected_epoch}, got {record_epoch}"),
        });
    }
    Ok(())
}

/// Validates that the sequence number is not a replay.
const fn validate_replay(replay_window: &ReplayWindow, sequence_number: u64) -> DtlsResult<()> {
    if !replay_window.check(sequence_number) {
        return Err(DtlsError::ReplayDetected);
    }
    Ok(())
}

/// Decrypts an AES-256-GCM encrypted payload.
fn decrypt_aes_gcm_payload(
    key: &Aes256GcmKey,
    read_iv: [u8; 4],
    header: &RecordHeader,
    payload: &[u8],
) -> DtlsResult<Vec<u8>> {
    if payload.len() < 8 + TAG_LEN {
        return Err(DtlsError::RecordError {
            reason: "ciphertext too short".to_string(),
        });
    }

    let explicit_nonce = &payload[0..8];
    let ciphertext = &payload[8..];

    let nonce = build_decryption_nonce(read_iv, explicit_nonce);
    let aad = build_aad(header, ciphertext.len() - TAG_LEN);

    key.open(&nonce, &aad, ciphertext)
        .map_err(|_| DtlsError::DecryptionFailed {
            reason: "AES-256-GCM authentication failed".to_string(),
        })
}

/// Why a received record was dropped. Dropping never changes any state
/// (RFC 6347 §4.1.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDiscard {
    /// The header or length is malformed, or the content type is unknown.
    Malformed,
    /// The record version is not acceptable.
    Version,
    /// The epoch is not the current read epoch.
    Epoch,
    /// The sequence number was already received or is too old.
    Replay,
    /// AEAD authentication failed.
    Authentication,
    /// The datagram holds more records than [`MAX_RECORDS_PER_DATAGRAM`].
    TooManyRecords,
}

/// One record borrowed from a datagram, not yet authenticated.
#[derive(Debug, Clone, Copy)]
pub struct RecordView<'a> {
    /// Content type.
    pub content_type: ContentType,
    /// Record-layer version.
    pub version: u16,
    /// Epoch.
    pub epoch: u16,
    /// Sequence number within the epoch.
    pub sequence_number: u64,
    /// Record payload (ciphertext for epoch 1).
    pub payload: &'a [u8],
}

/// Iterator over the records packed into one UDP datagram (RFC 6347 §4.1.1).
///
/// Yields `Err` once and then stops when the remainder cannot be parsed, so a
/// corrupt tail does not hide the valid records before it.
///
/// NIST 800-53 Rev5: SI-10 (bounds-checked), SC-5 (record count is capped).
#[derive(Debug)]
pub struct DatagramRecords<'a> {
    reader: Reader<'a>,
    yielded: usize,
    done: bool,
}

impl<'a> DatagramRecords<'a> {
    /// Starts reading records from `datagram`.
    #[must_use]
    pub const fn new(datagram: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(datagram),
            yielded: 0,
            done: false,
        }
    }

    fn read_one(&mut self) -> Option<RecordView<'a>> {
        let content_type = ContentType::from_u8(self.reader.u8().ok()?)?;
        let version = self.reader.u16().ok()?;
        let epoch = self.reader.u16().ok()?;
        let sequence_number = self.reader.u48().ok()?;
        let payload = self.reader.vec16().ok()?;
        Some(RecordView {
            content_type,
            version,
            epoch,
            sequence_number,
            payload,
        })
    }
}

impl<'a> Iterator for DatagramRecords<'a> {
    type Item = Result<RecordView<'a>, RecordDiscard>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.reader.is_empty() {
            return None;
        }
        if self.yielded >= MAX_RECORDS_PER_DATAGRAM {
            self.done = true;
            return Some(Err(RecordDiscard::TooManyRecords));
        }
        self.yielded += 1;
        let record = self.read_one();
        if record.is_none() {
            self.done = true;
        }
        Some(record.ok_or(RecordDiscard::Malformed))
    }
}

/// Encodes a plaintext (epoch 0) record with an explicit sequence number.
///
/// Used for the stateless `HelloVerifyRequest`, which must reuse the sequence
/// number of the `ClientHello` it answers (RFC 6347 §4.2.1).
///
/// # Errors
/// Returns an error if the fragment or sequence number is out of range.
pub fn encode_plaintext_record(
    content_type: ContentType,
    sequence_number: u64,
    fragment: &[u8],
) -> DtlsResult<Vec<u8>> {
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + fragment.len());
    put_record_header(&mut out, content_type, 0, sequence_number, fragment.len())?;
    out.extend_from_slice(fragment);
    Ok(out)
}

/// Appends a 13-byte record header.
fn put_record_header(
    out: &mut Vec<u8>,
    content_type: ContentType,
    epoch: u16,
    sequence_number: u64,
    payload_len: usize,
) -> DtlsResult<()> {
    let length = u16::try_from(payload_len).map_err(|_| DtlsError::RecordError {
        reason: "record payload too large".to_string(),
    })?;
    let [0, 0, seq @ ..] = sequence_number.to_be_bytes() else {
        return Err(DtlsError::RecordError {
            reason: "record sequence number exhausted".to_string(),
        });
    };
    out.push(content_type as u8);
    out.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&seq);
    out.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

/// The 13-byte AEAD additional data: `seq_num(8) || type || version || length`
/// (RFC 5246 §6.2.3.3, with epoch and sequence number as `seq_num` per
/// RFC 6347 §4.1.2.1).
const fn aead_additional_data(
    content_type: ContentType,
    version: u16,
    epoch: u16,
    sequence_number: u64,
    plaintext_len: u16,
) -> Option<[u8; 13]> {
    let [0, 0, s0, s1, s2, s3, s4, s5] = sequence_number.to_be_bytes() else {
        return None;
    };
    let [e0, e1] = epoch.to_be_bytes();
    let [v0, v1] = version.to_be_bytes();
    let [l0, l1] = plaintext_len.to_be_bytes();
    Some([
        e0,
        e1,
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        content_type as u8,
        v0,
        v1,
        l0,
        l1,
    ])
}

/// Joins the 4-byte implicit IV and the 8-byte explicit nonce.
const fn gcm_nonce(iv: [u8; 4], explicit: [u8; EXPLICIT_NONCE_LEN]) -> [u8; NONCE_LEN] {
    let [i0, i1, i2, i3] = iv;
    let [x0, x1, x2, x3, x4, x5, x6, x7] = explicit;
    [i0, i1, i2, i3, x0, x1, x2, x3, x4, x5, x6, x7]
}

/// The 4-byte implicit part of the GCM nonce (RFC 5288 §3), wiped on drop.
type ImplicitIv = zeroize::Zeroizing<[u8; 4]>;

/// Record protection for [`crate::association::DtlsAssociation`].
///
/// Differences from the legacy [`RecordLayer`]:
///
/// - Read and write epochs switch separately, each at its own
///   `ChangeCipherSpec` (RFC 6347 §4.1: the epoch changes per direction).
/// - Epoch-0 records can still be written after the write side moved to
///   epoch 1, with their own sequence counter, so a flight that spans the
///   cipher change can be retransmitted with fresh sequence numbers.
/// - Sealing goes through the FIPS module's TLS 1.2 GCM construction, which
///   refuses a repeated or decreasing nonce.
/// - A record that cannot be accepted is reported as a [`RecordDiscard`] and
///   leaves all state untouched (RFC 6347 §4.1.2.7).
///
/// Only epochs 0 and 1 exist: there is no renegotiation.
///
/// NIST 800-53 Rev5: SC-8 (confidentiality and integrity), SC-13, SC-23
/// (replay window).
pub struct AssociationRecordLayer {
    /// Next epoch-0 write sequence number.
    write_seq_plain: u64,
    /// Next epoch-1 write sequence number.
    write_seq_sealed: u64,
    /// Active epoch-1 write protection.
    write: Option<(Tls12GcmSealer, ImplicitIv)>,
    /// Write protection waiting for our `ChangeCipherSpec`.
    pending_write: Option<(Tls12GcmSealer, ImplicitIv)>,
    /// Active epoch-1 read protection.
    read: Option<(Aes256GcmKey, ImplicitIv)>,
    /// Read protection waiting for the peer's `ChangeCipherSpec`.
    pending_read: Option<(Aes256GcmKey, ImplicitIv)>,
    /// Anti-replay window for epoch 1.
    replay_window: ReplayWindow,
}

impl AssociationRecordLayer {
    /// Creates a record layer with both directions in epoch 0 (plaintext).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            write_seq_plain: 0,
            write_seq_sealed: 0,
            write: None,
            pending_write: None,
            read: None,
            pending_read: None,
            replay_window: ReplayWindow::new(),
        }
    }

    /// Stores the epoch-1 keys. Nothing is protected until
    /// [`Self::activate_write`] / [`Self::activate_read`].
    ///
    /// The caller keeps ownership of (and wipes) the key and IV arrays it
    /// passes; the copies of the IVs kept here are wiped on drop, and the
    /// keys live only inside aws-lc contexts.
    ///
    /// # Errors
    /// Returns an error if keys were already installed or a key is rejected.
    pub fn install_pending_keys(
        &mut self,
        write_key: &[u8; KEY_LEN],
        write_iv: &[u8; 4],
        read_key: &[u8; KEY_LEN],
        read_iv: &[u8; 4],
    ) -> DtlsResult<()> {
        if self.write.is_some()
            || self.read.is_some()
            || self.pending_write.is_some()
            || self.pending_read.is_some()
        {
            return Err(DtlsError::RecordError {
                reason: "record keys already installed".to_string(),
            });
        }
        let sealer = Tls12GcmSealer::new(write_key).map_err(|e| DtlsError::EncryptionFailed {
            reason: e.to_string(),
        })?;
        let opener = Aes256GcmKey::new(*read_key).map_err(|e| DtlsError::DecryptionFailed {
            reason: e.to_string(),
        })?;
        self.pending_write = Some((sealer, ImplicitIv::new(*write_iv)));
        self.pending_read = Some((opener, ImplicitIv::new(*read_iv)));
        Ok(())
    }

    /// Switches the write side to epoch 1. Call right after queueing our
    /// `ChangeCipherSpec`.
    ///
    /// # Errors
    /// Returns an error if no keys are pending.
    pub fn activate_write(&mut self) -> DtlsResult<()> {
        let pending = self
            .pending_write
            .take()
            .ok_or_else(|| DtlsError::RecordError {
                reason: "no pending write keys".to_string(),
            })?;
        self.write = Some(pending);
        self.write_seq_sealed = 0;
        Ok(())
    }

    /// Switches the read side to epoch 1. Call when the peer's
    /// `ChangeCipherSpec` is accepted.
    ///
    /// # Errors
    /// Returns an error if no keys are pending.
    pub fn activate_read(&mut self) -> DtlsResult<()> {
        let pending = self
            .pending_read
            .take()
            .ok_or_else(|| DtlsError::RecordError {
                reason: "no pending read keys".to_string(),
            })?;
        self.read = Some(pending);
        self.replay_window = ReplayWindow::new();
        Ok(())
    }

    /// Current write epoch (0 or 1).
    #[must_use]
    pub const fn write_epoch(&self) -> u16 {
        if self.write.is_some() { 1 } else { 0 }
    }

    /// Current read epoch (0 or 1).
    #[must_use]
    pub const fn read_epoch(&self) -> u16 {
        if self.read.is_some() { 1 } else { 0 }
    }

    /// True when keys are installed and waiting for the peer's `ChangeCipherSpec`.
    #[must_use]
    pub const fn has_pending_read(&self) -> bool {
        self.pending_read.is_some()
    }

    /// Raises the next epoch-0 write sequence number to at least `sequence`.
    ///
    /// RFC 6347 §4.2.1: the first `ServerHello` uses the record sequence
    /// number of the `ClientHello` it answers.
    pub const fn raise_plaintext_write_sequence(&mut self, sequence: u64) {
        if sequence <= MAX_SEQUENCE_NUMBER && sequence > self.write_seq_plain {
            self.write_seq_plain = sequence;
        }
    }

    /// Encodes one record in `epoch`, consuming one sequence number.
    ///
    /// Epoch 0 is plaintext; epoch 1 is AES-256-GCM with the explicit nonce
    /// `epoch || sequence_number` (RFC 5288 §3, RFC 6347 §4.1.2.1).
    ///
    /// # Errors
    /// Returns an error if `epoch` has no keys, the fragment is too large,
    /// the sequence number space is used up, or sealing fails.
    pub fn seal(
        &mut self,
        epoch: u16,
        content_type: ContentType,
        fragment: &[u8],
    ) -> DtlsResult<Vec<u8>> {
        if fragment.len() > MAX_FRAGMENT_SIZE {
            return Err(DtlsError::RecordError {
                reason: "fragment too large".to_string(),
            });
        }
        if epoch == 0 {
            let seq = self.write_seq_plain;
            let out = encode_plaintext_record(content_type, seq, fragment)?;
            self.write_seq_plain = seq + 1;
            return Ok(out);
        }
        let Some((sealer, iv)) = self.write.as_mut().filter(|_| epoch == 1) else {
            return Err(DtlsError::RecordError {
                reason: "no write keys for epoch".to_string(),
            });
        };
        let seq = self.write_seq_sealed;
        // NIST 800-53 Rev5: SC-12 -- never wrap the 48-bit sequence number
        // (RFC 6347 §4.1): the association stops instead of reusing a nonce.
        let exhausted = || DtlsError::RecordError {
            reason: "record sequence number exhausted".to_string(),
        };
        let plaintext_len = u16::try_from(fragment.len()).map_err(|_| exhausted())?;
        let aad = aead_additional_data(content_type, DTLS_1_2_VERSION, epoch, seq, plaintext_len)
            .ok_or_else(exhausted)?;
        let [a0, a1, a2, a3, a4, a5, a6, a7, ..] = aad;
        let explicit = [a0, a1, a2, a3, a4, a5, a6, a7];
        let ciphertext = sealer
            .seal(&gcm_nonce(**iv, explicit), &aad, fragment)
            .map_err(|e| DtlsError::EncryptionFailed {
                reason: e.to_string(),
            })?;
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + EXPLICIT_NONCE_LEN + ciphertext.len());
        put_record_header(
            &mut out,
            content_type,
            epoch,
            seq,
            EXPLICIT_NONCE_LEN + ciphertext.len(),
        )?;
        out.extend_from_slice(&explicit);
        out.extend_from_slice(&ciphertext);
        self.write_seq_sealed = seq + 1;
        Ok(out)
    }

    /// Authenticates and decrypts one received record.
    ///
    /// - Epoch 0 is accepted only while the read side is still in epoch 0.
    ///   No replay window is kept for it: the records are unauthenticated,
    ///   so a forged sequence number must not be able to shut out real ones;
    ///   handshake messages are de-duplicated by `message_seq` instead.
    /// - Epoch 1 is accepted only after [`Self::activate_read`], must be
    ///   version 1.2, must pass the replay window (RFC 6347 §4.1.2.6) and
    ///   the AEAD check; the window moves only after the tag verifies.
    ///
    /// # Errors
    /// Returns the reason the record must be dropped. No state changes.
    pub fn open(&mut self, record: &RecordView<'_>) -> Result<Vec<u8>, RecordDiscard> {
        if record.epoch == 0 {
            if self.read.is_some() {
                return Err(RecordDiscard::Epoch);
            }
            if record.version != DTLS_1_2_VERSION && record.version != DTLS_1_0_VERSION {
                return Err(RecordDiscard::Version);
            }
            if record.payload.len() > MAX_FRAGMENT_SIZE {
                return Err(RecordDiscard::Malformed);
            }
            return Ok(record.payload.to_vec());
        }
        let Some((key, iv)) = self.read.as_ref().filter(|_| record.epoch == 1) else {
            return Err(RecordDiscard::Epoch);
        };
        if record.version != DTLS_1_2_VERSION {
            return Err(RecordDiscard::Version);
        }
        let mut payload = Reader::new(record.payload);
        let explicit: [u8; EXPLICIT_NONCE_LEN] =
            payload.array().map_err(|_| RecordDiscard::Malformed)?;
        let ciphertext = payload.rest();
        let plaintext_len = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .filter(|len| *len <= MAX_FRAGMENT_SIZE)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or(RecordDiscard::Malformed)?;
        if !self.replay_window.check(record.sequence_number) {
            return Err(RecordDiscard::Replay);
        }
        let aad = aead_additional_data(
            record.content_type,
            record.version,
            record.epoch,
            record.sequence_number,
            plaintext_len,
        )
        .ok_or(RecordDiscard::Malformed)?;
        let plaintext = key
            .open(&gcm_nonce(**iv, explicit), &aad, ciphertext)
            .map_err(|_| RecordDiscard::Authentication)?;
        self.replay_window.update(record.sequence_number);
        Ok(plaintext)
    }
}

impl Default for AssociationRecordLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AssociationRecordLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssociationRecordLayer")
            .field("write_epoch", &self.write_epoch())
            .field("read_epoch", &self.read_epoch())
            .field("keys", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Anti-replay window using a bitmap.
///
/// Implements sliding window replay protection per RFC 6347.
struct ReplayWindow {
    /// Highest sequence number seen.
    max_seq: u64,
    /// Bitmap of recent sequence numbers (64 bits).
    bitmap: u64,
}

impl ReplayWindow {
    /// Window size in bits.
    const WINDOW_SIZE: u64 = 64;

    const fn new() -> Self {
        Self {
            max_seq: 0,
            bitmap: 0,
        }
    }

    /// Checks if a sequence number is acceptable (not a replay).
    const fn check(&self, seq: u64) -> bool {
        if seq > self.max_seq {
            // New sequence number, always acceptable
            true
        } else if self.max_seq - seq >= Self::WINDOW_SIZE {
            // Too old, reject
            false
        } else {
            // Check bitmap
            let bit = 1u64 << (self.max_seq - seq);
            (self.bitmap & bit) == 0
        }
    }

    /// Updates the window with a verified sequence number.
    const fn update(&mut self, seq: u64) {
        if seq > self.max_seq {
            // Shift window
            let shift = seq - self.max_seq;
            if shift < Self::WINDOW_SIZE {
                self.bitmap = (self.bitmap << shift) | 1;
            } else {
                self.bitmap = 1;
            }
            self.max_seq = seq;
        } else {
            // Mark bit in window
            let bit = 1u64 << (self.max_seq - seq);
            self.bitmap |= bit;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_record_header_parse_serialize() {
        let header = RecordHeader {
            content_type: ContentType::ApplicationData,
            version: DTLS_1_2_VERSION,
            epoch: 1,
            sequence_number: 12345,
            length: 100,
        };

        let serialized = header.serialize();
        let parsed = RecordHeader::parse(&serialized).unwrap();

        assert_eq!(parsed.content_type, header.content_type);
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.epoch, header.epoch);
        assert_eq!(parsed.sequence_number, header.sequence_number);
        assert_eq!(parsed.length, header.length);
    }

    #[test]
    fn test_content_type_conversion() {
        assert_eq!(
            ContentType::try_from(20).unwrap(),
            ContentType::ChangeCipherSpec
        );
        assert_eq!(ContentType::try_from(21).unwrap(), ContentType::Alert);
        assert_eq!(ContentType::try_from(22).unwrap(), ContentType::Handshake);
        assert_eq!(
            ContentType::try_from(23).unwrap(),
            ContentType::ApplicationData
        );
        assert!(ContentType::try_from(99).is_err());
    }

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new();

        // First packet should be accepted
        assert!(window.check(1));
        window.update(1);

        // Same packet should be rejected
        assert!(!window.check(1));

        // Next packet should be accepted
        assert!(window.check(2));
        window.update(2);

        // Old packet still in window should be rejected
        assert!(!window.check(1));

        // Packet beyond window should be accepted
        assert!(window.check(100));
        window.update(100);

        // Now old packets are outside window
        assert!(!window.check(1));
        assert!(!window.check(35)); // 100 - 64 = 36, so 35 is outside
    }

    #[test]
    fn test_plaintext_record() {
        let mut layer = RecordLayer::new();

        let plaintext = b"Hello, DTLS!";
        let record = layer
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert!(record.len() >= RECORD_HEADER_LEN + plaintext.len());

        let (content_type, decrypted) = layer.decrypt_record(&record).unwrap();
        assert_eq!(content_type, ContentType::ApplicationData);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_record() {
        let mut layer = RecordLayer::new();

        // Generate keys
        let key_bytes = zeroize::Zeroizing::new(uc_crypto::random::generate_key_256().unwrap());
        let write_key = Tls12GcmSealer::new(&key_bytes).unwrap();
        let read_key = Aes256GcmKey::new(*key_bytes).unwrap();
        let write_iv = [1u8, 2, 3, 4];
        let read_iv = write_iv;

        layer.activate_cipher(write_key, read_key, write_iv, read_iv);
        assert!(layer.is_encrypted());

        let plaintext = b"Secret message";
        let record = layer
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // Encrypted record should be larger (explicit nonce + tag)
        assert!(record.len() > RECORD_HEADER_LEN + plaintext.len());

        let (content_type, decrypted) = layer.decrypt_record(&record).unwrap();
        assert_eq!(content_type, ContentType::ApplicationData);
        assert_eq!(decrypted, plaintext);
    }

    fn keyed_pair() -> (AssociationRecordLayer, AssociationRecordLayer) {
        let (ka, kb) = ([0x11u8; KEY_LEN], [0x22u8; KEY_LEN]);
        let mut a = AssociationRecordLayer::new();
        let mut b = AssociationRecordLayer::new();
        a.install_pending_keys(&ka, &[1; 4], &kb, &[2; 4]).unwrap();
        b.install_pending_keys(&kb, &[2; 4], &ka, &[1; 4]).unwrap();
        (a, b)
    }

    fn only_record(datagram: &[u8]) -> RecordView<'_> {
        let mut records = DatagramRecords::new(datagram);
        let record = records.next().unwrap().unwrap();
        assert!(records.next().is_none());
        record
    }

    #[test]
    fn association_epochs_switch_per_direction() {
        let (mut a, mut b) = keyed_pair();
        assert_eq!((a.write_epoch(), a.read_epoch()), (0, 0));

        // A sends CCS in epoch 0, then switches only its write side.
        let ccs = a.seal(0, ContentType::ChangeCipherSpec, &[1]).unwrap();
        a.activate_write().unwrap();
        assert_eq!((a.write_epoch(), a.read_epoch()), (1, 0));
        let fin = a.seal(1, ContentType::Handshake, b"finished").unwrap();

        // B still reads epoch 0: the CCS is accepted, epoch 1 is not yet.
        assert_eq!(b.open(&only_record(&ccs)).unwrap(), vec![1]);
        assert_eq!(b.open(&only_record(&fin)), Err(RecordDiscard::Epoch));
        b.activate_read().unwrap();
        assert_eq!(b.open(&only_record(&fin)).unwrap(), b"finished");

        // B's own CCS still goes out in epoch 0 and A, whose read side has
        // not switched, accepts it.
        let ccs_b = b.seal(0, ContentType::ChangeCipherSpec, &[1]).unwrap();
        assert_eq!(only_record(&ccs_b).epoch, 0);
        assert_eq!(a.open(&only_record(&ccs_b)).unwrap(), vec![1]);
        assert!(a.activate_write().is_err());
    }

    #[test]
    fn association_sealed_record_layout_and_nonce() {
        let (mut a, _) = keyed_pair();
        a.activate_write().unwrap();
        a.seal(1, ContentType::Alert, &[1, 0]).unwrap();
        let rec = a.seal(1, ContentType::Alert, &[1, 0]).unwrap();
        assert_eq!(rec.len(), RECORD_HEADER_LEN + 8 + 2 + TAG_LEN);
        let view = only_record(&rec);
        assert_eq!((view.epoch, view.sequence_number), (1, 1));
        assert_eq!(view.version, DTLS_1_2_VERSION);
        // Explicit nonce is epoch || sequence number.
        assert_eq!(&view.payload[..8], &[0, 1, 0, 0, 0, 0, 0, 1]);
        // Epoch-0 records keep their own counter after the switch.
        let plain = a.seal(0, ContentType::Handshake, b"x").unwrap();
        assert_eq!(only_record(&plain).sequence_number, 0);
    }

    #[test]
    fn association_replay_accepted_once_then_rejected() {
        let (mut a, mut b) = keyed_pair();
        a.activate_write().unwrap();
        b.activate_read().unwrap();
        let r0 = a.seal(1, ContentType::Alert, &[1, 0]).unwrap();
        let r1 = a.seal(1, ContentType::Alert, &[1, 0]).unwrap();
        // Out of order is fine; each is accepted once.
        assert!(b.open(&only_record(&r1)).is_ok());
        assert!(b.open(&only_record(&r0)).is_ok());
        assert_eq!(b.open(&only_record(&r0)), Err(RecordDiscard::Replay));
        assert_eq!(b.open(&only_record(&r1)), Err(RecordDiscard::Replay));
    }

    #[test]
    fn association_bad_records_are_discarded_without_state_change() {
        let (mut a, mut b) = keyed_pair();
        a.activate_write().unwrap();
        b.activate_read().unwrap();
        let good = a.seal(1, ContentType::Alert, &[1, 0]).unwrap();

        // Bad tag: dropped, and the replay window did not move, so the
        // genuine record is still accepted afterwards.
        let mut bad_tag = good.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        assert_eq!(
            b.open(&only_record(&bad_tag)),
            Err(RecordDiscard::Authentication)
        );
        // Header fields are authenticated.
        let mut bad_type = good.clone();
        bad_type[0] = ContentType::Handshake as u8;
        assert_eq!(
            b.open(&only_record(&bad_type)),
            Err(RecordDiscard::Authentication)
        );
        // Wrong version.
        let mut bad_version = good.clone();
        bad_version[2] = 0xFF;
        assert_eq!(
            b.open(&only_record(&bad_version)),
            Err(RecordDiscard::Version)
        );
        // Wrong epochs: 2 is unknown, 0 is closed once epoch 1 is read.
        let mut epoch2 = good.clone();
        epoch2[4] = 2;
        assert_eq!(b.open(&only_record(&epoch2)), Err(RecordDiscard::Epoch));
        let plain = encode_plaintext_record(ContentType::Alert, 9, &[2, 40]).unwrap();
        assert_eq!(b.open(&only_record(&plain)), Err(RecordDiscard::Epoch));
        // Too short for nonce + tag.
        let short = [21, 0xFE, 0xFD, 0, 1, 0, 0, 0, 0, 0, 5, 0, 3, 1, 2, 3];
        assert_eq!(b.open(&only_record(&short)), Err(RecordDiscard::Malformed));

        assert_eq!(b.open(&only_record(&good)).unwrap(), vec![1, 0]);
    }

    #[test]
    fn association_plaintext_version_rules() {
        let mut layer = AssociationRecordLayer::new();
        let mut rec = encode_plaintext_record(ContentType::Handshake, 0, b"hi").unwrap();
        assert_eq!(layer.open(&only_record(&rec)).unwrap(), b"hi");
        rec[2] = 0xFF; // DTLS 1.0 record version on a hello
        assert_eq!(layer.open(&only_record(&rec)).unwrap(), b"hi");
        rec[1] = 0x03; // TLS
        assert_eq!(layer.open(&only_record(&rec)), Err(RecordDiscard::Version));
    }

    #[test]
    fn datagram_iterator_reads_packed_records_and_stops_at_garbage() {
        let mut datagram = Vec::new();
        for seq in 0..3u64 {
            datagram.extend(encode_plaintext_record(ContentType::Handshake, seq, &[7; 5]).unwrap());
        }
        let seqs: Vec<u64> = DatagramRecords::new(&datagram)
            .map(|r| r.unwrap().sequence_number)
            .collect();
        assert_eq!(seqs, vec![0, 1, 2]);

        // Two good records then a truncated one: two Ok, one Err, then end.
        let cut = datagram.len() - 3;
        let got: Vec<bool> = DatagramRecords::new(&datagram[..cut])
            .map(|r| r.is_ok())
            .collect();
        assert_eq!(got, vec![true, true, false]);

        // Unknown content type.
        let mut bad = datagram.clone();
        bad[0] = 99;
        let got: Vec<bool> = DatagramRecords::new(&bad).map(|r| r.is_ok()).collect();
        assert_eq!(got, vec![false]);

        // Every truncation of a datagram is handled without panicking.
        for cut in 0..datagram.len() {
            let _ = DatagramRecords::new(&datagram[..cut]).count();
        }
        assert_eq!(DatagramRecords::new(&[]).count(), 0);
    }

    #[test]
    fn datagram_iterator_caps_record_count() {
        let mut datagram = Vec::new();
        for seq in 0..20u64 {
            datagram.extend(encode_plaintext_record(ContentType::Alert, seq, &[1, 0]).unwrap());
        }
        let items: Vec<_> = DatagramRecords::new(&datagram).collect();
        assert_eq!(items.len(), MAX_RECORDS_PER_DATAGRAM + 1);
        assert_eq!(
            items.last().unwrap().as_ref().unwrap_err(),
            &RecordDiscard::TooManyRecords
        );
    }

    #[test]
    fn association_sequence_limit_stops_sealing() {
        let (mut a, _) = keyed_pair();
        a.activate_write().unwrap();
        a.write_seq_sealed = MAX_SEQUENCE_NUMBER;
        assert!(a.seal(1, ContentType::Alert, &[1, 0]).is_ok());
        assert!(a.seal(1, ContentType::Alert, &[1, 0]).is_err());
        a.write_seq_plain = MAX_SEQUENCE_NUMBER + 1;
        assert!(a.seal(0, ContentType::Alert, &[1, 0]).is_err());
    }

    #[test]
    fn association_seal_requires_keys_and_reinstall_is_refused() {
        let mut layer = AssociationRecordLayer::new();
        assert!(layer.seal(1, ContentType::Alert, &[1, 0]).is_err());
        assert!(layer.activate_write().is_err());
        assert!(layer.activate_read().is_err());
        let (mut a, _) = keyed_pair();
        assert!(
            a.install_pending_keys(&[0; KEY_LEN], &[0; 4], &[0; KEY_LEN], &[0; 4])
                .is_err()
        );
        a.raise_plaintext_write_sequence(5);
        let rec = a.seal(0, ContentType::Handshake, b"x").unwrap();
        assert_eq!(only_record(&rec).sequence_number, 5);
    }
}

/// SR-15: the legacy `RecordLayer` write key is the module's TLS 1.2 GCM
/// sealer (`Tls12GcmSealer`); the record bytes do not change. Random runtime
/// keys only.
///
/// Note: the legacy layer's AAD is `type || version || epoch || seq || len`,
/// not the RFC 5246 §6.2.3.3 order used by `AssociationRecordLayer`
/// (`epoch || seq || type || version || len`), so legacy records do not open
/// with the association reader before or after SR-15. The reference below
/// pins the legacy layout instead.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod sr15_legacy_record_layer_tests {
    use super::*;
    use uc_crypto::aead::CachedAeadKey;
    use zeroize::Zeroizing;

    /// The record the pre-SR-15 `RecordLayer` produced (caller-IV GCM seal,
    /// legacy AAD order), built independently of the production helpers.
    fn reference_record(
        key: &[u8; KEY_LEN],
        iv: [u8; 4],
        content_type: ContentType,
        epoch: u16,
        seq: u64,
        fragment: &[u8],
    ) -> Vec<u8> {
        let seq6 = &seq.to_be_bytes()[2..];
        let mut explicit = Vec::with_capacity(8);
        explicit.extend_from_slice(&epoch.to_be_bytes());
        explicit.extend_from_slice(seq6);
        let nonce: [u8; NONCE_LEN] = [&iv[..], &explicit].concat().try_into().unwrap();
        let mut aad = vec![content_type as u8];
        aad.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());
        aad.extend_from_slice(&epoch.to_be_bytes());
        aad.extend_from_slice(seq6);
        aad.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
        let ct = CachedAeadKey::new(key)
            .unwrap()
            .seal(&nonce, &aad, fragment)
            .unwrap();
        let mut out = vec![content_type as u8];
        out.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(seq6);
        out.extend_from_slice(&u16::try_from(8 + ct.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&explicit);
        out.extend_from_slice(&ct);
        out
    }

    #[test]
    fn legacy_record_layer_record_bytes_unchanged() {
        let key = Zeroizing::new(uc_crypto::random::generate_key_256().unwrap());
        let iv: [u8; 4] = uc_crypto::random::generate_random::<4>().unwrap();

        let mut writer = RecordLayer::new();
        writer.activate_cipher(
            Tls12GcmSealer::new(&key).unwrap(),
            Aes256GcmKey::new(*key).unwrap(),
            iv,
            iv,
        );
        assert!(writer.is_encrypted());
        let mut reader = RecordLayer::new();
        reader.activate_cipher(
            Tls12GcmSealer::new(&key).unwrap(),
            Aes256GcmKey::new(*key).unwrap(),
            iv,
            iv,
        );

        // Several records: the TLS 1.2 sealer's monotonic-nonce check must
        // accept the layer's increasing sequence numbers.
        let cases: [(ContentType, &[u8]); 4] = [
            (ContentType::Handshake, b"finished"),
            (ContentType::ApplicationData, b""),
            (ContentType::ApplicationData, &[0xA5; 1200]),
            (ContentType::Alert, &[1, 0]),
        ];
        for (seq, (ct, frag)) in (0u64..).zip(cases) {
            assert_eq!(writer.write_sequence(), (1, seq));
            let record = writer.encrypt_record(ct, frag).unwrap();
            assert_eq!(
                record,
                reference_record(&key, iv, ct, 1, seq, frag),
                "record bytes changed at seq {seq}"
            );
            let (got_type, got) = reader.decrypt_record(&record).unwrap();
            assert_eq!(got_type, ct);
            assert_eq!(got, frag);
        }
        assert_eq!(writer.write_sequence(), (1, 4));
    }
}
