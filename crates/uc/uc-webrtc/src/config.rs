//! WebRTC gateway configuration.

use crate::error::{WebRtcError, WebRtcResult};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// WebRTC gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRtcConfig {
    /// Enable WebRTC gateway.
    pub enabled: bool,

    /// STUN server addresses for ICE.
    pub stun_servers: Vec<SocketAddr>,

    /// TURN server addresses for ICE relay.
    pub turn_servers: Vec<TurnServerConfig>,

    /// ICE configuration.
    pub ice: IceConfig,

    /// DTLS configuration.
    pub dtls: DtlsConfig,

    /// Session configuration.
    pub session: SessionConfig,

    /// SDP munging configuration.
    pub sdp: SdpConfig,
}

impl WebRtcConfig {
    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WebRtcError::ConfigError`] if any section is invalid.
    pub fn validate(&self) -> WebRtcResult<()> {
        self.sdp.validate()
    }
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stun_servers: vec![],
            turn_servers: vec![],
            ice: IceConfig::default(),
            dtls: DtlsConfig::default(),
            session: SessionConfig::default(),
            sdp: SdpConfig::default(),
        }
    }
}

/// TURN server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServerConfig {
    /// TURN server address.
    pub address: SocketAddr,

    /// Username for TURN authentication.
    pub username: String,

    /// Credential for TURN authentication.
    pub credential: String,

    /// Transport protocol (udp, tcp, tls).
    pub transport: String,
}

/// ICE configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceConfig {
    /// Enable ICE trickling.
    pub trickle_enabled: bool,

    /// ICE gathering timeout.
    #[serde(with = "humantime_serde")]
    pub gathering_timeout: Duration,

    /// ICE connectivity check timeout.
    #[serde(with = "humantime_serde")]
    pub connectivity_timeout: Duration,

    /// Enable ICE-lite mode (server-side optimization).
    pub lite_mode: bool,

    /// Enable aggressive nomination.
    pub aggressive_nomination: bool,

    /// Maximum number of candidate pairs to check.
    pub max_candidate_pairs: usize,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            trickle_enabled: true,
            gathering_timeout: Duration::from_secs(10),
            connectivity_timeout: Duration::from_secs(30),
            lite_mode: true,
            aggressive_nomination: true,
            max_candidate_pairs: 100,
        }
    }
}

/// DTLS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtlsConfig {
    /// DTLS handshake timeout.
    #[serde(with = "humantime_serde")]
    pub handshake_timeout: Duration,

    /// DTLS role preference (client, server, auto).
    pub role: DtlsRole,

    /// Certificate fingerprint algorithm.
    pub fingerprint_algorithm: String,
}

impl Default for DtlsConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            role: DtlsRole::Auto,
            fingerprint_algorithm: "sha-384".to_string(),
        }
    }
}

/// DTLS role preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DtlsRole {
    /// Prefer client role.
    Client,
    /// Prefer server role.
    Server,
    /// Automatically determine role based on setup attribute.
    Auto,
}

/// Session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum concurrent WebRTC sessions.
    pub max_sessions: usize,

    /// Session idle timeout.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,

    /// Enable session recording.
    pub recording_enabled: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            idle_timeout: Duration::from_mins(5),
            recording_enabled: false,
        }
    }
}

/// SDP munging configuration.
///
/// Keys that the munger does not implement yet (`rewrite_connection`,
/// `strip_non_webrtc_codecs`, `audio_codecs`, `video_codecs`) only accept their
/// inert value; anything else is rejected by [`SdpConfig::validate`] rather than
/// silently ignored.
// NIST 800-53 Rev5: CM-6 (Configuration Settings) - accepted keys are enforced or rejected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpConfig {
    /// Rewrite c= line to SBC external address.
    ///
    /// Not implemented: must be `false`.
    // POAM: POA&M-284 c= rewriting (topology hiding) not implemented in uc-webrtc.
    #[serde(default)]
    pub rewrite_connection: bool,

    /// Strip non-WebRTC codecs.
    ///
    /// Not implemented: must be `false`.
    // POAM: POA&M-284 codec filtering not implemented in uc-webrtc.
    #[serde(default)]
    pub strip_non_webrtc_codecs: bool,

    /// Force DTLS-SRTP (remove SDES crypto).
    pub force_dtls_srtp: bool,

    /// Enable rtcp-mux.
    pub rtcp_mux: bool,

    /// Enable bundle.
    pub bundle: bool,

    /// Preferred audio codecs (in order).
    ///
    /// Not implemented: must be empty.
    // POAM: POA&M-284 codec preference ordering not implemented in uc-webrtc.
    #[serde(default)]
    pub audio_codecs: Vec<String>,

    /// Preferred video codecs (in order).
    ///
    /// Not implemented: must be empty.
    // POAM: POA&M-284 codec preference ordering not implemented in uc-webrtc.
    #[serde(default)]
    pub video_codecs: Vec<String>,

    /// Maximum m-sections accepted in one SDP.
    // NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
    #[serde(default = "default_max_media_sections")]
    pub max_media_sections: usize,

    /// Maximum total SDP size in bytes.
    // NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
    #[serde(default = "default_max_sdp_bytes")]
    pub max_sdp_bytes: usize,

    /// Maximum `a=` lines per section (session level or one m-section).
    // NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
    #[serde(default = "default_max_attributes_per_section")]
    pub max_attributes_per_section: usize,
}

const fn default_max_sdp_bytes() -> usize {
    crate::sdp_munge::DEFAULT_MAX_SDP_BYTES
}

const fn default_max_attributes_per_section() -> usize {
    crate::sdp_munge::DEFAULT_MAX_ATTRIBUTES_PER_SECTION
}

impl SdpConfig {
    /// Validates the configuration, failing closed on unsupported values.
    ///
    /// # Errors
    ///
    /// Returns [`WebRtcError::ConfigError`] if DTLS-SRTP is disabled, an
    /// unimplemented key carries a non-inert value, or a limit is zero.
    // NIST 800-53 Rev5: CM-6, SC-8(1) (fail closed on unenforceable settings)
    pub fn validate(&self) -> WebRtcResult<()> {
        let err = |reason: &str| {
            Err(WebRtcError::ConfigError {
                reason: reason.to_string(),
            })
        };
        // RFC 8827 §6.5: WebRTC media MUST be DTLS-SRTP.
        if !self.force_dtls_srtp {
            return err("force_dtls_srtp=false is not supported for WebRTC");
        }
        if self.rewrite_connection {
            return err("sdp.rewrite_connection=true is not implemented");
        }
        if self.strip_non_webrtc_codecs {
            return err("sdp.strip_non_webrtc_codecs=true is not implemented");
        }
        if !self.audio_codecs.is_empty() {
            return err("sdp.audio_codecs is not implemented; must be empty");
        }
        if !self.video_codecs.is_empty() {
            return err("sdp.video_codecs is not implemented; must be empty");
        }
        if self.max_media_sections == 0
            || self.max_sdp_bytes == 0
            || self.max_attributes_per_section == 0
        {
            return err("sdp limits must be non-zero");
        }
        Ok(())
    }
}

const fn default_max_media_sections() -> usize {
    crate::sdp_munge::DEFAULT_MAX_MEDIA_SECTIONS
}

impl Default for SdpConfig {
    fn default() -> Self {
        Self {
            rewrite_connection: false,
            strip_non_webrtc_codecs: false,
            force_dtls_srtp: true,
            rtcp_mux: true,
            bundle: true,
            audio_codecs: Vec::new(),
            video_codecs: Vec::new(),
            max_media_sections: default_max_media_sections(),
            max_sdp_bytes: default_max_sdp_bytes(),
            max_attributes_per_section: default_max_attributes_per_section(),
        }
    }
}

/// Serde helper for Duration using humantime format.
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}s", duration.as_secs()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Simple parser for "Ns" format
        if let Some(secs) = s.strip_suffix('s') {
            secs.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(serde::de::Error::custom)
        } else {
            Err(serde::de::Error::custom("expected duration in 'Ns' format"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WebRtcConfig::default();
        assert!(config.enabled);
        assert!(config.ice.trickle_enabled);
        assert!(config.sdp.force_dtls_srtp);
    }

    #[test]
    fn test_default_sdp_config_validates() {
        assert!(SdpConfig::default().validate().is_ok());
        assert!(WebRtcConfig::default().validate().is_ok());
    }

    #[test]
    fn test_unenforced_sdp_keys_rejected() {
        let cases: [fn(&mut SdpConfig); 7] = [
            |c| c.force_dtls_srtp = false,
            |c| c.rewrite_connection = true,
            |c| c.strip_non_webrtc_codecs = true,
            |c| c.audio_codecs = vec!["opus".to_string()],
            |c| c.video_codecs = vec!["VP8".to_string()],
            |c| c.max_sdp_bytes = 0,
            |c| c.max_attributes_per_section = 0,
        ];
        for mutate in cases {
            let mut c = SdpConfig::default();
            mutate(&mut c);
            assert!(matches!(c.validate(), Err(WebRtcError::ConfigError { .. })));
        }
    }

    #[test]
    fn test_dtls_role() {
        assert_eq!(DtlsRole::Auto, DtlsRole::Auto);
        assert_ne!(DtlsRole::Client, DtlsRole::Server);
    }
}
