//! SRTP encryption with CNSA 2.0 compliance.
//!
//! This crate provides Secure Real-time Transport Protocol (SRTP) encryption
//! using CNSA 2.0 approved cryptographic algorithms for government-grade security.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-13**: Cryptographic Protection
//!
//! ## CNSA 2.0 Compliance
//!
//! This implementation uses only CNSA 2.0 approved algorithms:
//! - **Cipher**: AES-256-GCM (AEAD_AES_256_GCM per RFC 7714)
//! - **Key Derivation**: HKDF-SHA384
//! - **Authentication Tag**: 16 bytes
//!
//! **NOT supported** (CNSA 2.0 non-compliant):
//! - AES-128-CM
//! - HMAC-SHA1
//! - SHA-1 based key derivation
//!
//! ## RFC Compliance
//!
//! - **RFC 3711**: SRTP
//! - **RFC 7714**: AES-GCM for SRTP
//! - **RFC 5764**: DTLS-SRTP
//!
//! ## Security
//!
//! - 96-bit nonce (IV) per RFC 7714
//! - 128-bit authentication tag
//! - Replay protection via packet index
//! - Key derivation using HKDF-SHA384

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// TODO: Fix these warnings in a dedicated cleanup pass
#![allow(clippy::unreadable_literal)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
// Allow unwrap in tests
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod context;
pub mod error;
pub mod key;
pub mod protect;

pub use context::{SrtpContext, SrtpDirection};
pub use error::{SrtpError, SrtpResult};
pub use key::SrtpKeyMaterial;
pub use protect::{SrtpProtect, SrtpUnprotect};

/// SRTP protection profile.
///
/// ## CNSA 2.0 Compliance
///
/// Only AEAD_AES_256_GCM is available. Other profiles
/// (AES-128, HMAC-SHA1) are not exposed per CNSA 2.0 requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrtpProfile {
    /// AEAD_AES_256_GCM (RFC 7714)
    ///
    /// - 256-bit key
    /// - 96-bit salt (12 bytes)
    /// - 128-bit auth tag (16 bytes)
    AeadAes256Gcm,
}

impl SrtpProfile {
    /// Returns the IANA profile ID per RFC 5764.
    #[must_use]
    pub fn profile_id(&self) -> u16 {
        match self {
            Self::AeadAes256Gcm => 0x0008,
        }
    }

    /// Returns the master key length in bytes.
    #[must_use]
    pub fn master_key_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 32, // 256 bits
        }
    }

    /// Returns the master salt length in bytes.
    #[must_use]
    pub fn master_salt_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 12, // 96 bits
        }
    }

    /// Returns the session key length in bytes.
    #[must_use]
    pub fn session_key_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 32, // 256 bits
        }
    }

    /// Returns the authentication tag length in bytes.
    #[must_use]
    pub fn auth_tag_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 16, // 128 bits
        }
    }

    /// Returns the nonce length in bytes.
    #[must_use]
    pub fn nonce_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 12, // 96 bits
        }
    }
}

/// Default window size for replay protection.
pub const DEFAULT_REPLAY_WINDOW_SIZE: u64 = 64;

/// Maximum SRTP packet index (2^48 - 1).
pub const MAX_PACKET_INDEX: u64 = (1 << 48) - 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_properties() {
        let profile = SrtpProfile::AeadAes256Gcm;
        assert_eq!(profile.profile_id(), 0x0008);
        assert_eq!(profile.master_key_len(), 32);
        assert_eq!(profile.master_salt_len(), 12);
        assert_eq!(profile.auth_tag_len(), 16);
    }
}
