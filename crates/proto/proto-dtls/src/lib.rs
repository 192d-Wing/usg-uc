//! DTLS implementation for secure media transport.
//!
//! This crate provides DTLS (Datagram Transport Layer Security) functionality
//! for securing RTP media streams in VoIP and WebRTC applications.
//!
//! ## CNSA 2.0 Compliance
//!
//! DTLS is configured with CNSA 2.0 compliant settings:
//! - **DTLS 1.2/1.3** with approved cipher suites
//! - **Cipher Suite**: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//! - **Key Exchange**: P-384 ECDHE
//! - **Certificates**: P-384 ECDSA
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-12**: Cryptographic Key Establishment
//! - **SC-13**: Cryptographic Protection
//!
//! ## RFC Compliance
//!
//! - **RFC 6347**: DTLS 1.2
//! - **RFC 5763**: DTLS-SRTP Framework
//! - **RFC 5764**: DTLS Extension for SRTP Key Establishment

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod cipher_suite;
pub mod config;
pub mod connection;
pub mod error;
pub mod fingerprint;
pub mod handshake;
pub mod record;
pub mod session;
pub mod srtp_export;
pub mod verify;

pub use cipher_suite::{cnsa_cipher_suites, is_cnsa_compliant};
pub use config::DtlsConfig;
pub use connection::{DtlsConnection, DtlsConnectionManager};
pub use error::{DtlsError, DtlsResult};
pub use fingerprint::CertificateFingerprint;
pub use handshake::{Handshake, HandshakeState};
pub use record::{RecordHeader, RecordLayer};
pub use session::DtlsSession;
pub use srtp_export::{SrtpKeyExporter, UseSrtpExtension, SRTP_EXPORTER_LABEL};
pub use verify::{CertificateValidationResult, CertificateValidator, FinishedVerifier, ServerKeyExchangeVerifier};

/// DTLS role in the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    /// Client (initiates handshake).
    Client,
    /// Server (responds to handshake).
    Server,
}

impl DtlsRole {
    /// Returns true if this is the client role.
    #[must_use]
    pub fn is_client(&self) -> bool {
        matches!(self, Self::Client)
    }

    /// Returns true if this is the server role.
    #[must_use]
    pub fn is_server(&self) -> bool {
        matches!(self, Self::Server)
    }
}

/// DTLS connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsState {
    /// Initial state, no handshake started.
    New,
    /// Handshake in progress.
    Connecting,
    /// Handshake complete, connection established.
    Connected,
    /// Connection is being closed.
    Closing,
    /// Connection is closed.
    Closed,
    /// Connection failed.
    Failed,
}

impl DtlsState {
    /// Returns true if handshake is complete.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Returns true if connection is closed or failed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }
}

/// SRTP protection profile for DTLS-SRTP.
///
/// ## CNSA 2.0 Compliance
///
/// Only AES-256-GCM profiles are exposed. AES-128 profiles
/// are not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    /// AEAD_AES_256_GCM (RFC 7714)
    ///
    /// CNSA 2.0 compliant profile.
    AeadAes256Gcm,
}

impl SrtpProfile {
    /// Returns the IANA profile ID.
    #[must_use]
    pub fn profile_id(&self) -> u16 {
        match self {
            // AEAD_AES_256_GCM defined in RFC 7714
            Self::AeadAes256Gcm => 0x0008,
        }
    }

    /// Returns the key length in bytes.
    #[must_use]
    pub fn key_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 32, // 256 bits
        }
    }

    /// Returns the salt length in bytes.
    #[must_use]
    pub fn salt_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 12,
        }
    }

    /// Returns the authentication tag length in bytes.
    #[must_use]
    pub fn auth_tag_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 16,
        }
    }
}

/// Keying material exported from DTLS for SRTP.
///
/// ## RFC 5764
///
/// This contains the master key and salt derived via DTLS-SRTP
/// for use with SRTP encryption.
#[derive(Clone)]
pub struct SrtpKeyingMaterial {
    /// Client write master key.
    pub client_write_key: Vec<u8>,
    /// Server write master key.
    pub server_write_key: Vec<u8>,
    /// Client write master salt.
    pub client_write_salt: Vec<u8>,
    /// Server write master salt.
    pub server_write_salt: Vec<u8>,
    /// Negotiated SRTP profile.
    pub profile: SrtpProfile,
}

impl SrtpKeyingMaterial {
    /// Returns the local write key based on DTLS role.
    #[must_use]
    pub fn local_key(&self, role: DtlsRole) -> &[u8] {
        match role {
            DtlsRole::Client => &self.client_write_key,
            DtlsRole::Server => &self.server_write_key,
        }
    }

    /// Returns the remote write key based on DTLS role.
    #[must_use]
    pub fn remote_key(&self, role: DtlsRole) -> &[u8] {
        match role {
            DtlsRole::Client => &self.server_write_key,
            DtlsRole::Server => &self.client_write_key,
        }
    }

    /// Returns the local write salt based on DTLS role.
    #[must_use]
    pub fn local_salt(&self, role: DtlsRole) -> &[u8] {
        match role {
            DtlsRole::Client => &self.client_write_salt,
            DtlsRole::Server => &self.server_write_salt,
        }
    }

    /// Returns the remote write salt based on DTLS role.
    #[must_use]
    pub fn remote_salt(&self, role: DtlsRole) -> &[u8] {
        match role {
            DtlsRole::Client => &self.server_write_salt,
            DtlsRole::Server => &self.client_write_salt,
        }
    }
}

impl std::fmt::Debug for SrtpKeyingMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpKeyingMaterial")
            .field("client_write_key", &"[REDACTED]")
            .field("server_write_key", &"[REDACTED]")
            .field("client_write_salt", &"[REDACTED]")
            .field("server_write_salt", &"[REDACTED]")
            .field("profile", &self.profile)
            .finish()
    }
}

impl Drop for SrtpKeyingMaterial {
    fn drop(&mut self) {
        // Zeroize sensitive material
        self.client_write_key.fill(0);
        self.server_write_key.fill(0);
        self.client_write_salt.fill(0);
        self.server_write_salt.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls_role() {
        assert!(DtlsRole::Client.is_client());
        assert!(!DtlsRole::Client.is_server());
        assert!(DtlsRole::Server.is_server());
        assert!(!DtlsRole::Server.is_client());
    }

    #[test]
    fn test_dtls_state() {
        assert!(!DtlsState::New.is_connected());
        assert!(!DtlsState::New.is_closed());
        assert!(DtlsState::Connected.is_connected());
        assert!(!DtlsState::Connected.is_closed());
        assert!(!DtlsState::Closed.is_connected());
        assert!(DtlsState::Closed.is_closed());
        assert!(DtlsState::Failed.is_closed());
    }

    #[test]
    fn test_srtp_profile() {
        let profile = SrtpProfile::AeadAes256Gcm;
        assert_eq!(profile.profile_id(), 0x0008);
        assert_eq!(profile.key_len(), 32);
        assert_eq!(profile.salt_len(), 12);
        assert_eq!(profile.auth_tag_len(), 16);
    }

    #[test]
    fn test_keying_material_roles() {
        let material = SrtpKeyingMaterial {
            client_write_key: vec![1; 32],
            server_write_key: vec![2; 32],
            client_write_salt: vec![3; 12],
            server_write_salt: vec![4; 12],
            profile: SrtpProfile::AeadAes256Gcm,
        };

        // Client perspective
        assert_eq!(material.local_key(DtlsRole::Client), &[1; 32]);
        assert_eq!(material.remote_key(DtlsRole::Client), &[2; 32]);
        assert_eq!(material.local_salt(DtlsRole::Client), &[3; 12]);
        assert_eq!(material.remote_salt(DtlsRole::Client), &[4; 12]);

        // Server perspective
        assert_eq!(material.local_key(DtlsRole::Server), &[2; 32]);
        assert_eq!(material.remote_key(DtlsRole::Server), &[1; 32]);
        assert_eq!(material.local_salt(DtlsRole::Server), &[4; 12]);
        assert_eq!(material.remote_salt(DtlsRole::Server), &[3; 12]);
    }

    #[test]
    fn test_keying_material_debug_redacted() {
        let material = SrtpKeyingMaterial {
            client_write_key: vec![1; 32],
            server_write_key: vec![2; 32],
            client_write_salt: vec![3; 12],
            server_write_salt: vec![4; 12],
            profile: SrtpProfile::AeadAes256Gcm,
        };

        let debug_str = format!("{material:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("[1, 1, 1"));
    }
}
