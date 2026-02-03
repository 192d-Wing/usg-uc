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
//! - **SC-13**: Cryptographic Protection

use crate::error::{DtlsError, DtlsResult};
use uc_crypto::aead::{Aes256GcmKey, NONCE_LEN, TAG_LEN};

/// DTLS record header length.
pub const RECORD_HEADER_LEN: usize = 13;

/// Maximum DTLS record size (including header).
pub const MAX_RECORD_SIZE: usize = 16384 + RECORD_HEADER_LEN + TAG_LEN;

/// Maximum plaintext fragment size.
pub const MAX_FRAGMENT_SIZE: usize = 16384;

/// DTLS version 1.2 (0xFEFD per RFC 6347).
pub const DTLS_1_2_VERSION: u16 = 0xFEFD;

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
    /// Write key for encryption.
    write_key: Option<Aes256GcmKey>,
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
    pub fn new() -> Self {
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
        write_key: Aes256GcmKey,
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
    /// Returns an error if encryption fails.
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

        let output = if let Some(ref key) = self.write_key {
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
            // Length in AAD is the plaintext length
            aad[11..13].copy_from_slice(&(fragment.len() as u16).to_be_bytes());

            // Encrypt
            let ciphertext =
                key.seal(&nonce, &aad, fragment)
                    .map_err(|e| DtlsError::EncryptionFailed {
                        reason: format!("AES-256-GCM seal failed: {e}"),
                    })?;

            // Build output: header + explicit_nonce + ciphertext_with_tag
            let total_len = explicit_nonce.len() + ciphertext.len();
            let mut header_with_len = header;
            header_with_len.length = total_len as u16;

            let mut output = Vec::with_capacity(RECORD_HEADER_LEN + total_len);
            output.extend_from_slice(&header_with_len.serialize());
            output.extend_from_slice(&explicit_nonce);
            output.extend_from_slice(&ciphertext);
            output
        } else {
            // Plaintext mode
            let mut header_with_len = header;
            header_with_len.length = fragment.len() as u16;

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
            // Check epoch
            if header.epoch != self.read_epoch {
                return Err(DtlsError::RecordError {
                    reason: format!(
                        "epoch mismatch: expected {}, got {}",
                        self.read_epoch, header.epoch
                    ),
                });
            }

            // Check replay
            if !self.replay_window.check(header.sequence_number) {
                return Err(DtlsError::ReplayDetected);
            }

            // Extract explicit nonce (8 bytes)
            if payload.len() < 8 + TAG_LEN {
                return Err(DtlsError::RecordError {
                    reason: "ciphertext too short".to_string(),
                });
            }

            let explicit_nonce = &payload[0..8];
            let ciphertext = &payload[8..];

            // Build nonce
            let mut nonce = [0u8; NONCE_LEN];
            nonce[0..4].copy_from_slice(&self.read_iv);
            nonce[4..12].copy_from_slice(explicit_nonce);

            // Build AAD
            let plaintext_len = ciphertext.len() - TAG_LEN;
            let mut aad = [0u8; 13];
            aad[0] = header.content_type as u8;
            aad[1..3].copy_from_slice(&header.version.to_be_bytes());
            aad[3..5].copy_from_slice(&header.epoch.to_be_bytes());
            let seq_bytes = header.sequence_number.to_be_bytes();
            aad[5..11].copy_from_slice(&seq_bytes[2..8]);
            aad[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());

            // Decrypt
            let plaintext =
                key.open(&nonce, &aad, ciphertext)
                    .map_err(|_| DtlsError::DecryptionFailed {
                        reason: "AES-256-GCM authentication failed".to_string(),
                    })?;

            // Update replay window
            self.replay_window.update(header.sequence_number);

            plaintext
        } else {
            // Plaintext mode
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
        let write_key = Aes256GcmKey::generate().unwrap();
        let read_key = Aes256GcmKey::new(*write_key.as_bytes()).unwrap();
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
}
