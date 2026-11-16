//! DTLS 1.2 key schedule for the CNSA profile.
//!
//! - Handshake transcript (RFC 6347 §4.2.6).
//! - Extended master secret (RFC 7627 §4); the plain RFC 5246 master secret
//!   derivation is not implemented.
//! - Key block for `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
//!   (RFC 5246 §6.3, RFC 5288 §3).
//! - `Finished` `verify_data` (RFC 5246 §7.4.9).
//! - DTLS-SRTP exporter (RFC 5705 §4, RFC 5764 §4.2).
//! - Stateless `HelloVerifyRequest` cookie (RFC 6347 §4.2.1).
//!
//! ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment), SC-13
//!
//! Every derivation is computed by the FIPS module's TLS 1.2 KDF with
//! SHA-384, through [`uc_crypto::tls12::prf_sha384`]. The module's
//! approved-service indicator is set for the extended master secret label
//! only; key expansion, `Finished` and the exporter compute inside the
//! module without it (see [`uc_crypto::tls12`], POA&M-332).
//!
//! Secrets -- the master secret, the record keys and the implicit GCM IVs --
//! are held in zeroizing buffers, are not `Clone`, and have redacted `Debug`
//! output. The exported [`SrtpKeyingMaterial`] is wiped by its own `Drop`;
//! what happens to copies its consumers make is POA&M-330.

#![deny(clippy::indexing_slicing)]

use crate::error::{DtlsError, DtlsResult};
use crate::flight::handshake_message_bytes;
use crate::record::AssociationRecordLayer;
use crate::srtp_export::SrtpKeyExporter;
use crate::wire::handshake_msg::{ClientHelloParts, RANDOM_LEN, VERIFY_DATA_LEN};
use crate::wire::reader::Reader;
use crate::{DtlsRole, SrtpKeyingMaterial, SrtpProfile};
use uc_crypto::aead::KEY_LEN;
use uc_crypto::hash::SHA384_OUTPUT_LEN;
use uc_crypto::tls12::{Tls12Label, prf_sha384};
use zeroize::Zeroizing;

/// Length of the TLS master secret.
pub const MASTER_SECRET_LEN: usize = 48;
/// Upper bound on the handshake transcript.
pub const MAX_TRANSCRIPT_LEN: usize = 32 * 1024;
/// Length of the stateless cookie.
pub const COOKIE_LEN: usize = 32;
/// Length of the per-association cookie secret.
pub const COOKIE_SECRET_LEN: usize = 48;
/// Longest peer binding mixed into the cookie (an IPv6 address, port and
/// scope fit several times over).
pub const MAX_PEER_BINDING_LEN: usize = 64;

/// Implicit GCM IV length (`fixed_iv_length`, RFC 5288 §3).
const IV_LEN: usize = 4;
/// Key block: two AES-256 keys and two implicit IVs; AEAD suites have no MAC keys.
const KEY_BLOCK_LEN: usize = 2 * KEY_LEN + 2 * IV_LEN;
/// Exporter output for `AEAD_AES_256_GCM`: two 32-byte keys, two 12-byte salts.
const SRTP_EXPORT_LEN: usize = 88;

fn kdf_error() -> DtlsError {
    DtlsError::KeyDerivationFailed {
        reason: "TLS 1.2 PRF failed".to_string(),
    }
}

/// The handshake messages hashed for `Finished`, `CertificateVerify` and the
/// extended master secret.
///
/// Raw bytes are kept (bounded by [`MAX_TRANSCRIPT_LEN`]) because the hash is
/// needed at several points and `CertificateVerify` signs the messages
/// themselves.
#[derive(Debug, Default)]
pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    /// Creates an empty transcript.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends a message in its unfragmented form (RFC 6347 §4.2.6).
    ///
    /// # Errors
    /// Returns an error if the transcript limit would be exceeded.
    pub fn push(&mut self, msg_type: u8, message_seq: u16, body: &[u8]) -> DtlsResult<()> {
        let message = handshake_message_bytes(msg_type, message_seq, body)?;
        self.push_raw(&message)
    }

    /// Appends an already encoded unfragmented message.
    ///
    /// # Errors
    /// Returns an error if the transcript limit would be exceeded.
    pub fn push_raw(&mut self, message: &[u8]) -> DtlsResult<()> {
        // NIST 800-53 Rev5: SC-5 -- the transcript cannot grow without bound.
        if self.bytes.len() + message.len() > MAX_TRANSCRIPT_LEN {
            return Err(DtlsError::HandshakeFailed {
                reason: "handshake transcript limit exceeded".to_string(),
            });
        }
        self.bytes.extend_from_slice(message);
        Ok(())
    }

    /// The concatenated messages.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-384 of the messages so far.
    #[must_use]
    pub fn hash(&self) -> [u8; SHA384_OUTPUT_LEN] {
        uc_crypto::hash::sha384(&self.bytes)
    }
}

/// The 48-byte TLS master secret.
///
/// Wiped on drop, not `Clone`, redacted `Debug`.
pub struct MasterSecret(Zeroizing<[u8; MASTER_SECRET_LEN]>);

impl MasterSecret {
    /// Derives the extended master secret (RFC 7627 §4):
    /// `PRF(pre_master_secret, "extended master secret", session_hash)`.
    ///
    /// `session_hash` is the transcript hash through `ClientKeyExchange`.
    ///
    /// # Errors
    /// Returns an error if the KDF fails.
    pub fn derive_extended(
        pre_master_secret: &[u8],
        session_hash: &[u8; SHA384_OUTPUT_LEN],
    ) -> DtlsResult<Self> {
        let mut master = Zeroizing::new([0u8; MASTER_SECRET_LEN]);
        prf_sha384(
            pre_master_secret,
            Tls12Label::ExtendedMasterSecret,
            session_hash,
            master.as_mut_slice(),
        )
        .map_err(|_| kdf_error())?;
        Ok(Self(master))
    }

    /// Derives the record keys (RFC 5246 §6.3):
    /// `PRF(master, "key expansion", server_random || client_random)`.
    ///
    /// # Errors
    /// Returns an error if the KDF fails.
    pub fn key_block(
        &self,
        client_random: &[u8; RANDOM_LEN],
        server_random: &[u8; RANDOM_LEN],
    ) -> DtlsResult<KeyBlock> {
        let mut seed = [0u8; 2 * RANDOM_LEN];
        let (head, tail) = seed.split_at_mut(RANDOM_LEN);
        head.copy_from_slice(server_random);
        tail.copy_from_slice(client_random);
        let mut block = Zeroizing::new([0u8; KEY_BLOCK_LEN]);
        prf_sha384(
            self.0.as_slice(),
            Tls12Label::KeyExpansion,
            &seed,
            block.as_mut_slice(),
        )
        .map_err(|_| kdf_error())?;
        let mut r = Reader::new(block.as_slice());
        let client_write_key = Zeroizing::new(r.array().map_err(|_| kdf_error())?);
        let server_write_key = Zeroizing::new(r.array().map_err(|_| kdf_error())?);
        // NIST 800-53 Rev5: SC-12 -- the implicit IVs are key material too
        // (RFC 5288 §3) and are wiped like the keys.
        let client_write_iv = Zeroizing::new(r.array().map_err(|_| kdf_error())?);
        let server_write_iv = Zeroizing::new(r.array().map_err(|_| kdf_error())?);
        Ok(KeyBlock {
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        })
    }

    /// Computes `verify_data` for the `Finished` sent by `sender`
    /// (RFC 5246 §7.4.9): `PRF(master, finished_label, Hash(handshake_messages))[0..12]`.
    ///
    /// # Errors
    /// Returns an error if the KDF fails.
    pub fn verify_data(
        &self,
        sender: DtlsRole,
        transcript_hash: &[u8; SHA384_OUTPUT_LEN],
    ) -> DtlsResult<[u8; VERIFY_DATA_LEN]> {
        let label = match sender {
            DtlsRole::Client => Tls12Label::ClientFinished,
            DtlsRole::Server => Tls12Label::ServerFinished,
        };
        let mut out = [0u8; VERIFY_DATA_LEN];
        prf_sha384(self.0.as_slice(), label, transcript_hash, &mut out).map_err(|_| kdf_error())?;
        Ok(out)
    }

    /// Exports the SRTP master keys and salts (RFC 5764 §4.2) with the
    /// RFC 5705 exporter and no context:
    /// `PRF(master, "EXTRACTOR-dtls_srtp", client_random || server_random)`.
    ///
    /// # Errors
    /// Returns an error if the KDF fails.
    pub fn export_srtp(
        &self,
        client_random: &[u8; RANDOM_LEN],
        server_random: &[u8; RANDOM_LEN],
    ) -> DtlsResult<SrtpKeyingMaterial> {
        let mut seed = [0u8; 2 * RANDOM_LEN];
        let (head, tail) = seed.split_at_mut(RANDOM_LEN);
        head.copy_from_slice(client_random);
        tail.copy_from_slice(server_random);
        let mut exported = Zeroizing::new([0u8; SRTP_EXPORT_LEN]);
        prf_sha384(
            self.0.as_slice(),
            Tls12Label::ExporterDtlsSrtp,
            &seed,
            exported.as_mut_slice(),
        )
        .map_err(|_| DtlsError::SrtpKeyExportFailed {
            reason: "TLS exporter failed".to_string(),
        })?;
        SrtpKeyExporter::new(SrtpProfile::AeadAes256Gcm).parse_keying_material(exported.as_slice())
    }
}

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret([REDACTED])")
    }
}

/// Record keys for both directions. Wiped on drop, not `Clone`.
pub struct KeyBlock {
    client_write_key: Zeroizing<[u8; KEY_LEN]>,
    server_write_key: Zeroizing<[u8; KEY_LEN]>,
    client_write_iv: Zeroizing<[u8; IV_LEN]>,
    server_write_iv: Zeroizing<[u8; IV_LEN]>,
}

impl KeyBlock {
    /// Installs the keys into `records` as pending, with the write/read
    /// direction chosen by our `role`.
    ///
    /// # Errors
    /// Returns an error if the record layer already has keys.
    pub fn install(&self, role: DtlsRole, records: &mut AssociationRecordLayer) -> DtlsResult<()> {
        match role {
            DtlsRole::Client => records.install_pending_keys(
                &self.client_write_key,
                &self.client_write_iv,
                &self.server_write_key,
                &self.server_write_iv,
            ),
            DtlsRole::Server => records.install_pending_keys(
                &self.server_write_key,
                &self.server_write_iv,
                &self.client_write_key,
                &self.client_write_iv,
            ),
        }
    }
}

impl std::fmt::Debug for KeyBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyBlock([REDACTED])")
    }
}

/// The bytes a server signs in `ServerKeyExchange` (RFC 8422 §5.4):
/// `client_random || server_random || ServerECDHParams`.
#[must_use]
pub fn server_key_exchange_signed_content(
    client_random: &[u8; RANDOM_LEN],
    server_random: &[u8; RANDOM_LEN],
    params: &[u8],
) -> Vec<u8> {
    let mut content = Vec::with_capacity(2 * RANDOM_LEN + params.len());
    content.extend_from_slice(client_random);
    content.extend_from_slice(server_random);
    content.extend_from_slice(params);
    content
}

/// Computes the stateless cookie for a `ClientHello` (RFC 6347 §4.2.1).
///
/// HMAC-SHA-384 under a per-association random secret over `peer_binding`
/// (length-prefixed) and every `ClientHello` field except the cookie itself,
/// truncated to 32 bytes.
///
/// `peer_binding` is whatever the driver uses to identify the peer's
/// transport address (RFC 6347 §4.2.1 has the cookie cover the client's IP
/// address); it is opaque here and may be empty when the driver passes
/// datagrams from one fixed remote only.
///
/// NIST 800-53 Rev5: SC-5 -- a second `ClientHello` that differs from the
/// first in any field, or comes with another binding, does not verify, and
/// no handshake state is created before the cookie comes back.
#[must_use]
pub fn compute_cookie(
    secret: &[u8; COOKIE_SECRET_LEN],
    peer_binding: &[u8],
    hello: &ClientHelloParts<'_>,
) -> [u8; COOKIE_LEN] {
    // The binding is at most MAX_PEER_BINDING_LEN bytes; a longer one is
    // refused at construction, so the saturated length is never reached.
    let binding_len = u16::try_from(peer_binding.len())
        .unwrap_or(u16::MAX)
        .to_be_bytes();
    let mac = uc_crypto::hkdf::hmac_sha384_multi(
        secret,
        &[&binding_len, peer_binding, hello.before, hello.after],
    );
    let mut cookie = [0u8; COOKIE_LEN];
    for (out, byte) in cookie.iter_mut().zip(mac) {
        *out = byte;
    }
    cookie
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::record::{ContentType, DatagramRecords};
    use crate::wire::handshake_msg::ClientHello;

    /// Reference `P_SHA384` composed from HMAC, independent of the module KDF.
    fn reference_prf(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        use uc_crypto::hkdf::hmac_sha384_multi as hmac;
        let mut out = Vec::new();
        let mut a = hmac(secret, &[label, seed]);
        while out.len() < len {
            out.extend_from_slice(&hmac(secret, &[&a, label, seed]));
            a = hmac(secret, &[&a]);
        }
        out.truncate(len);
        out
    }

    const CR: [u8; RANDOM_LEN] = [0x11; RANDOM_LEN];
    const SR: [u8; RANDOM_LEN] = [0x22; RANDOM_LEN];

    fn master() -> (MasterSecret, Vec<u8>) {
        let pms = [0x33u8; 48];
        let session_hash = [0x44u8; SHA384_OUTPUT_LEN];
        let expected = reference_prf(&pms, b"extended master secret", &session_hash, 48);
        (
            MasterSecret::derive_extended(&pms, &session_hash).unwrap(),
            expected,
        )
    }

    #[test]
    fn extended_master_secret_layout() {
        let (ms, expected) = master();
        assert_eq!(ms.0.as_slice(), expected.as_slice());
        assert!(MasterSecret::derive_extended(&[], &[0; SHA384_OUTPUT_LEN]).is_err());
    }

    #[test]
    fn key_block_split_and_role_direction() {
        let (ms, raw) = master();
        let seed = [SR, CR].concat();
        let block = reference_prf(&raw, b"key expansion", &seed, 72);
        let keys = ms.key_block(&CR, &SR).unwrap();
        assert_eq!(keys.client_write_key.as_slice(), &block[..32]);
        assert_eq!(keys.server_write_key.as_slice(), &block[32..64]);
        assert_eq!(keys.client_write_iv.as_slice(), &block[64..68]);
        assert_eq!(keys.server_write_iv.as_slice(), &block[68..72]);

        // What the client writes, the server reads, and the reverse.
        let mut client = AssociationRecordLayer::new();
        let mut server = AssociationRecordLayer::new();
        keys.install(DtlsRole::Client, &mut client).unwrap();
        keys.install(DtlsRole::Server, &mut server).unwrap();
        client.activate_write().unwrap();
        server.activate_read().unwrap();
        let record = client.seal(1, ContentType::Alert, &[1, 0]).unwrap();
        let view = DatagramRecords::new(&record).next().unwrap().unwrap();
        assert_eq!(server.open(&view).unwrap(), vec![1, 0]);
        server.activate_write().unwrap();
        client.activate_read().unwrap();
        let record = server.seal(1, ContentType::Alert, &[2, 40]).unwrap();
        let view = DatagramRecords::new(&record).next().unwrap().unwrap();
        assert_eq!(client.open(&view).unwrap(), vec![2, 40]);
    }

    #[test]
    fn verify_data_labels() {
        let (ms, raw) = master();
        let hash = [0x55u8; SHA384_OUTPUT_LEN];
        let client = ms.verify_data(DtlsRole::Client, &hash).unwrap();
        let server = ms.verify_data(DtlsRole::Server, &hash).unwrap();
        assert_eq!(
            client.as_slice(),
            reference_prf(&raw, b"client finished", &hash, 12)
        );
        assert_eq!(
            server.as_slice(),
            reference_prf(&raw, b"server finished", &hash, 12)
        );
        assert_ne!(client, server);
    }

    #[test]
    fn srtp_export_layout_rfc5764() {
        let (ms, raw) = master();
        let seed = [CR, SR].concat();
        let exported = reference_prf(&raw, b"EXTRACTOR-dtls_srtp", &seed, 88);
        let keys = ms.export_srtp(&CR, &SR).unwrap();
        assert_eq!(keys.client_write_key, &exported[..32]);
        assert_eq!(keys.server_write_key, &exported[32..64]);
        assert_eq!(keys.client_write_salt, &exported[64..76]);
        assert_eq!(keys.server_write_salt, &exported[76..88]);
        assert_eq!(keys.profile, SrtpProfile::AeadAes256Gcm);
    }

    #[test]
    fn secrets_have_redacted_debug() {
        let (ms, _) = master();
        let keys = ms.key_block(&CR, &SR).unwrap();
        assert_eq!(format!("{ms:?}"), "MasterSecret([REDACTED])");
        assert_eq!(format!("{keys:?}"), "KeyBlock([REDACTED])");
    }

    #[test]
    fn transcript_is_bounded_and_uses_unfragmented_headers() {
        let mut t = Transcript::new();
        t.push(14, 2, &[]).unwrap();
        assert_eq!(t.bytes(), &[14, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(t.hash(), uc_crypto::hash::sha384(t.bytes()));
        let chunk = vec![0u8; 8000];
        for _ in 0..4 {
            t.push_raw(&chunk).unwrap();
        }
        assert!(t.push_raw(&chunk).is_err());
        assert!(t.bytes().len() <= MAX_TRANSCRIPT_LEN);
    }

    #[test]
    fn cookie_covers_every_field_but_the_cookie() {
        let secret = [9u8; COOKIE_SECRET_LEN];
        let hello = |cookie: Vec<u8>, random: u8, suite: u16| {
            let mut out = Vec::new();
            ClientHello {
                version: 0xFEFD,
                random: [random; RANDOM_LEN],
                session_id: Vec::new(),
                cookie,
                cipher_suites: vec![suite],
                compression_methods: vec![0],
                extensions: crate::wire::extensions::Extensions::default(),
            }
            .encode(&mut out)
            .unwrap();
            out
        };
        let cookie_for = |binding: &[u8], bytes: &[u8]| {
            compute_cookie(&secret, binding, &ClientHello::split_cookie(bytes).unwrap())
        };
        let cookie_of = |bytes: &[u8]| cookie_for(b"", bytes);
        let base = cookie_of(&hello(Vec::new(), 1, 0xC02C));
        assert_eq!(base, cookie_of(&hello(base.to_vec(), 1, 0xC02C)));
        assert_ne!(base, cookie_of(&hello(Vec::new(), 2, 0xC02C)));
        assert_ne!(base, cookie_of(&hello(Vec::new(), 1, 0xC02B)));
        let other = compute_cookie(
            &[8u8; COOKIE_SECRET_LEN],
            b"",
            &ClientHello::split_cookie(&hello(Vec::new(), 1, 0xC02C)).unwrap(),
        );
        assert_ne!(base, other);

        // RFC 6347 §4.2.1: the cookie is bound to the peer's address.
        let plain = hello(Vec::new(), 1, 0xC02C);
        let bound = cookie_for(b"192.0.2.1:5004", &plain);
        assert_eq!(bound, cookie_for(b"192.0.2.1:5004", &plain));
        assert_ne!(bound, base);
        assert_ne!(bound, cookie_for(b"192.0.2.1:5005", &plain));
        assert_ne!(bound, cookie_for(b"192.0.2.2:5004", &plain));
    }
}
