//! WebRTC gateway configuration.

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
            idle_timeout: Duration::from_secs(300),
            recording_enabled: false,
        }
    }
}

/// SDP munging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpConfig {
    /// Rewrite c= line to SBC external address.
    pub rewrite_connection: bool,

    /// Strip non-WebRTC codecs.
    pub strip_non_webrtc_codecs: bool,

    /// Force DTLS-SRTP (remove SDES crypto).
    pub force_dtls_srtp: bool,

    /// Enable rtcp-mux.
    pub rtcp_mux: bool,

    /// Enable bundle.
    pub bundle: bool,

    /// Preferred audio codecs (in order).
    pub audio_codecs: Vec<String>,

    /// Preferred video codecs (in order).
    pub video_codecs: Vec<String>,
}

impl Default for SdpConfig {
    fn default() -> Self {
        Self {
            rewrite_connection: true,
            strip_non_webrtc_codecs: true,
            force_dtls_srtp: true,
            rtcp_mux: true,
            bundle: true,
            audio_codecs: vec!["opus".to_string(), "PCMU".to_string(), "PCMA".to_string()],
            video_codecs: vec!["VP8".to_string(), "VP9".to_string(), "H264".to_string()],
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
    fn test_dtls_role() {
        assert_eq!(DtlsRole::Auto, DtlsRole::Auto);
        assert_ne!(DtlsRole::Client, DtlsRole::Server);
    }
}
