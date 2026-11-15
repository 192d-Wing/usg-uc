//! Media security mode for the audio pipeline (fail-closed SRTP gate).
//!
//! A pipeline can only be built from a [`MediaSecurity`] value. In a default
//! build the only variant is [`MediaSecurity::Srtp`], so plaintext RTP cannot
//! be constructed at all; `MediaSecurity::Plaintext` exists only behind the
//! `insecure-rtp` feature (lab / UDP-TCP accounts).
//!
//! ```compile_fail
//! # // Fails to compile unless the `insecure-rtp` feature is enabled.
//! # #[cfg(feature = "insecure-rtp")] compile_error!("feature enabled");
//! let _ = client_audio::MediaSecurity::Plaintext;
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8 / SC-8(1)**: media confidentiality; no plaintext RTP path in
//!   default builds (fail closed).
//! - **SC-13**: `AEAD_AES_256_GCM` only (CNSA 2.0).
//! - **SC-12**: key management -- key halves held in `Zeroizing` (wiped on
//!   drop), private fields, redacted `Debug`, no `Clone`.
//! - **CM-7**: plaintext media only under an explicit build feature.
//!
//! ## RFC Compliance
//!
//! - RFC 5764 §4.1: media on a DTLS-SRTP stream MUST be SRTP.
//! - RFC 5764 §4.2: separate client-write / server-write keys per direction.
//! - RFC 7714: AES-256-GCM SRTP/SRTCP.

use crate::{AudioError, AudioResult};
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile};
use zeroize::Zeroizing;

/// AES-256-GCM master key length (RFC 7714 §12).
pub const SRTP_KEY_LEN: usize = 32;
/// AES-256-GCM master salt length (RFC 7714 §12).
pub const SRTP_SALT_LEN: usize = 12;

/// Security mode for one media stream.
#[derive(Debug)]
pub enum MediaSecurity {
    /// SRTP/SRTCP with per-direction keys. Always available.
    Srtp(SrtpSessionKeys),
    /// Plaintext RTP/RTCP. Only for lab / non-TLS accounts.
    #[cfg(feature = "insecure-rtp")]
    Plaintext,
}

/// Per-direction SRTP master keys and salts, e.g. resolved from a DTLS-SRTP
/// export by the final DTLS role (RFC 5764 §4.2).
///
/// Not `Clone`; `Debug` never prints key bytes; buffers are wiped on drop.
pub struct SrtpSessionKeys {
    /// SRTP protection profile. Only `AeadAes256Gcm` is accepted (CNSA 2.0).
    profile: SrtpProfile,
    /// Master key for media we send.
    tx_key: Zeroizing<Vec<u8>>,
    /// Master salt for media we send.
    tx_salt: Zeroizing<Vec<u8>>,
    /// Master key for media we receive.
    rx_key: Zeroizing<Vec<u8>>,
    /// Master salt for media we receive.
    rx_salt: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SrtpSessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpSessionKeys")
            .field("profile", &self.profile)
            .field("tx_key", &"<redacted>")
            .field("rx_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl SrtpSessionKeys {
    /// Wraps per-direction key material. Call [`Self::validate`] (or
    /// [`build_srtp_contexts`], which does) before use.
    #[must_use]
    pub const fn new(
        profile: SrtpProfile,
        tx_key: Zeroizing<Vec<u8>>,
        tx_salt: Zeroizing<Vec<u8>>,
        rx_key: Zeroizing<Vec<u8>>,
        rx_salt: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            profile,
            tx_key,
            tx_salt,
            rx_key,
            rx_salt,
        }
    }

    /// SRTP protection profile.
    #[must_use]
    pub const fn profile(&self) -> SrtpProfile {
        self.profile
    }

    /// Master key for media we send.
    #[must_use]
    pub fn tx_key(&self) -> &[u8] {
        &self.tx_key
    }

    /// Master salt for media we send.
    #[must_use]
    pub fn tx_salt(&self) -> &[u8] {
        &self.tx_salt
    }

    /// Master key for media we receive.
    #[must_use]
    pub fn rx_key(&self) -> &[u8] {
        &self.rx_key
    }

    /// Master salt for media we receive.
    #[must_use]
    pub fn rx_salt(&self) -> &[u8] {
        &self.rx_salt
    }

    /// Validates profile and key/salt lengths without touching any I/O.
    ///
    /// # Errors
    /// Returns [`AudioError::SrtpError`] for a non-CNSA profile or a key or
    /// salt of the wrong length.
    pub fn validate(&self) -> AudioResult<()> {
        // CNSA 2.0: AES-256-GCM only.
        if self.profile != SrtpProfile::AeadAes256Gcm {
            return Err(AudioError::SrtpError(
                "only AEAD_AES_256_GCM is permitted (CNSA 2.0)".to_string(),
            ));
        }
        if self.tx_key.len() != SRTP_KEY_LEN || self.rx_key.len() != SRTP_KEY_LEN {
            return Err(AudioError::SrtpError(
                "SRTP master key must be 32 bytes".to_string(),
            ));
        }
        if self.tx_salt.len() != SRTP_SALT_LEN || self.rx_salt.len() != SRTP_SALT_LEN {
            return Err(AudioError::SrtpError(
                "SRTP master salt must be 12 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

/// Independent SRTP/SRTCP contexts for one stream. Each context owns its
/// own index and replay state, so RTP and RTCP never share mutable state.
pub struct SrtpContextSet {
    /// Outbound RTP.
    pub rtp_tx: SrtpContext,
    /// Inbound RTP.
    pub rtp_rx: SrtpContext,
    /// Outbound RTCP (SRTCP).
    pub rtcp_tx: SrtpContext,
    /// Inbound RTCP (SRTCP).
    pub rtcp_rx: SrtpContext,
}

/// Builds the four SRTP contexts for a stream from validated keys.
///
/// `local_ssrc` is the pipeline's own transmit SSRC.
///
/// # Errors
/// Returns [`AudioError::SrtpError`] if validation or key derivation fails.
pub fn build_srtp_contexts(keys: &SrtpSessionKeys, local_ssrc: u32) -> AudioResult<SrtpContextSet> {
    keys.validate()?;
    let material = |key: &[u8], salt: &[u8]| {
        SrtpKeyMaterial::new(keys.profile, key.to_vec(), salt.to_vec())
            .map_err(|e| AudioError::SrtpError(format!("invalid SRTP key material: {e}")))
    };
    let tx = material(&keys.tx_key, &keys.tx_salt)?;
    let rx = material(&keys.rx_key, &keys.rx_salt)?;
    let ctx = |m: &SrtpKeyMaterial, dir, ssrc| {
        SrtpContext::new(m, dir, ssrc)
            .map_err(|e| AudioError::SrtpError(format!("failed to create SRTP context: {e}")))
    };
    Ok(SrtpContextSet {
        rtp_tx: ctx(&tx, SrtpDirection::Outbound, local_ssrc)?,
        rtp_rx: ctx(&rx, SrtpDirection::Inbound, 0)?,
        rtcp_tx: ctx(&tx, SrtpDirection::Outbound, local_ssrc)?,
        rtcp_rx: ctx(&rx, SrtpDirection::Inbound, 0)?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Keys shaped like a DTLS-SRTP export (RFC 5764 §4.2): `a` is the
    /// client-write half, `b` the server-write half.
    pub fn keys(tx: u8, rx: u8) -> SrtpSessionKeys {
        SrtpSessionKeys::new(
            SrtpProfile::AeadAes256Gcm,
            Zeroizing::new(vec![tx; SRTP_KEY_LEN]),
            Zeroizing::new(vec![tx ^ 0x5A; SRTP_SALT_LEN]),
            Zeroizing::new(vec![rx; SRTP_KEY_LEN]),
            Zeroizing::new(vec![rx ^ 0x5A; SRTP_SALT_LEN]),
        )
    }

    #[test]
    fn wrong_lengths_rejected() {
        let mut k = keys(1, 2);
        k.tx_key = Zeroizing::new(vec![0; 16]);
        assert!(k.validate().is_err());
        assert!(build_srtp_contexts(&k, 1).is_err());

        let mut k = keys(1, 2);
        k.rx_salt = Zeroizing::new(vec![0; 14]);
        assert!(k.validate().is_err());

        keys(1, 2).validate().unwrap();
    }

    #[test]
    fn debug_is_redacted() {
        let s = format!("{:?}", keys(0xAB, 0xCD));
        assert!(s.contains("redacted"));
        assert!(!s.contains("171"), "key byte value leaked: {s}");
    }
}
