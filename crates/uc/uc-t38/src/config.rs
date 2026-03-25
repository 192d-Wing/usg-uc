//! T.38 configuration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// T.38 configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct T38Config {
    /// Enable T.38 support.
    pub enabled: bool,

    /// Maximum bit rate (bps).
    pub max_bit_rate: u32,

    /// Error correction mode.
    pub error_correction: ErrorCorrectionMode,

    /// Number of redundant IFP packets for FEC.
    pub redundancy_count: u8,

    /// Maximum buffer size (bytes).
    pub max_buffer_size: usize,

    /// Fill bit removal.
    pub fill_bit_removal: bool,

    /// Transcoding MMR.
    pub transcoding_mmr: bool,

    /// Transcoding JBIG.
    pub transcoding_jbig: bool,

    /// Rate management method.
    pub rate_management: RateManagement,

    /// Maximum datagram size.
    pub max_datagram_size: u16,

    /// UDPTL configuration.
    pub udptl: UdptlConfig,

    /// Session configuration.
    pub session: SessionConfig,
}

impl Default for T38Config {
    fn default() -> Self {
        Self {
            enabled: true,
            max_bit_rate: 14400,
            error_correction: ErrorCorrectionMode::Redundancy,
            redundancy_count: 3,
            max_buffer_size: 65535,
            fill_bit_removal: false,
            transcoding_mmr: false,
            transcoding_jbig: false,
            rate_management: RateManagement::TransferredTcf,
            max_datagram_size: 400,
            udptl: UdptlConfig::default(),
            session: SessionConfig::default(),
        }
    }
}

/// Error correction mode per ITU-T T.38.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCorrectionMode {
    /// No error correction.
    None,
    /// Redundancy-based error correction.
    #[default]
    Redundancy,
    /// Forward Error Correction.
    Fec,
}

impl std::fmt::Display for ErrorCorrectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Redundancy => write!(f, "redundancy"),
            Self::Fec => write!(f, "fec"),
        }
    }
}

/// Rate management method.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateManagement {
    /// Local TCF (Training Check Frame).
    LocalTcf,
    /// Transferred TCF.
    #[default]
    TransferredTcf,
}

/// UDPTL transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdptlConfig {
    /// Local port range start.
    pub port_range_start: u16,

    /// Local port range end.
    pub port_range_end: u16,

    /// Retransmission timeout.
    #[serde(with = "humantime_serde")]
    pub retransmit_timeout: Duration,

    /// Maximum retransmissions.
    pub max_retransmissions: u8,
}

impl Default for UdptlConfig {
    fn default() -> Self {
        Self {
            port_range_start: 20000,
            port_range_end: 21000,
            retransmit_timeout: Duration::from_millis(500),
            max_retransmissions: 3,
        }
    }
}

/// T.38 session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum concurrent sessions.
    pub max_sessions: usize,

    /// Session idle timeout.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,

    /// Fax page timeout.
    #[serde(with = "humantime_serde")]
    pub page_timeout: Duration,

    /// Auto-switch from audio to T.38 on CNG detection.
    pub auto_switch_on_cng: bool,

    /// Auto-switch from audio to T.38 on CED detection.
    pub auto_switch_on_ced: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 100,
            idle_timeout: Duration::from_secs(300),
            page_timeout: Duration::from_secs(60),
            auto_switch_on_cng: true,
            auto_switch_on_ced: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = T38Config::default();
        assert!(config.enabled);
        assert_eq!(config.max_bit_rate, 14400);
        assert_eq!(config.error_correction, ErrorCorrectionMode::Redundancy);
        assert_eq!(config.redundancy_count, 3);
    }

    #[test]
    fn test_error_correction_display() {
        assert_eq!(ErrorCorrectionMode::None.to_string(), "none");
        assert_eq!(ErrorCorrectionMode::Redundancy.to_string(), "redundancy");
        assert_eq!(ErrorCorrectionMode::Fec.to_string(), "fec");
    }

    #[test]
    fn test_udptl_config() {
        let config = UdptlConfig::default();
        assert_eq!(config.port_range_start, 20000);
        assert_eq!(config.port_range_end, 21000);
        assert_eq!(config.max_retransmissions, 3);
    }

    #[test]
    fn test_session_config() {
        let config = SessionConfig::default();
        assert_eq!(config.max_sessions, 100);
        assert!(config.auto_switch_on_cng);
        assert!(config.auto_switch_on_ced);
    }
}
