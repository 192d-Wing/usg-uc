//! SIPREC configuration types.
//!
//! Defines recording server endpoints, recording modes, and trigger conditions.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

/// Recording server endpoint configuration.
#[derive(Debug, Clone)]
pub struct SrsEndpoint {
    /// Server address (hostname or IP with port).
    pub address: String,
    /// Optional SIP URI for the server.
    pub sip_uri: Option<String>,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Whether this server is primary (vs backup).
    pub is_primary: bool,
    /// Weight for load balancing (higher = more traffic).
    pub weight: u32,
    /// Server health check interval.
    pub health_check_interval: Duration,
    /// Whether server is currently healthy.
    pub healthy: bool,
}

impl Default for SrsEndpoint {
    fn default() -> Self {
        Self {
            address: String::new(),
            sip_uri: None,
            connect_timeout: Duration::from_secs(5),
            is_primary: true,
            weight: 100,
            health_check_interval: Duration::from_secs(30),
            healthy: true,
        }
    }
}

impl SrsEndpoint {
    /// Creates a new SRS endpoint with the given address.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            ..Default::default()
        }
    }

    /// Sets the SIP URI.
    #[must_use]
    pub fn with_sip_uri(mut self, uri: impl Into<String>) -> Self {
        self.sip_uri = Some(uri.into());
        self
    }

    /// Sets as backup server.
    #[must_use]
    pub const fn as_backup(mut self) -> Self {
        self.is_primary = false;
        self
    }

    /// Sets the weight for load balancing.
    #[must_use]
    pub const fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Gets the effective SIP URI.
    #[must_use]
    pub fn effective_uri(&self) -> String {
        self.sip_uri
            .clone()
            .unwrap_or_else(|| format!("sip:{}", self.address))
    }

    /// Parses address as socket address if possible.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address.parse().ok()
    }
}

/// Recording mode configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RecordingMode {
    /// Record all calls matching trigger conditions.
    #[default]
    Selective,
    /// Record all calls (compliance mode).
    AllCalls,
    /// Record on-demand when explicitly requested.
    OnDemand,
    /// Recording disabled.
    Disabled,
}

impl fmt::Display for RecordingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selective => write!(f, "selective"),
            Self::AllCalls => write!(f, "all-calls"),
            Self::OnDemand => write!(f, "on-demand"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Trigger conditions for selective recording.
#[derive(Debug, Clone)]
pub enum RecordingTrigger {
    /// Record calls from specific trunk.
    Trunk(String),
    /// Record calls matching caller pattern (regex).
    CallerPattern(String),
    /// Record calls matching callee pattern (regex).
    CalleePattern(String),
    /// Record calls with specific header value.
    HeaderMatch {
        /// Header name.
        name: String,
        /// Value pattern (substring match).
        pattern: String,
    },
    /// Record calls in specific time window.
    TimeWindow {
        /// Start hour (0-23).
        start_hour: u8,
        /// End hour (0-23).
        end_hour: u8,
    },
    /// Record calls explicitly flagged.
    ExplicitFlag,
    /// Record inbound calls only.
    InboundOnly,
    /// Record outbound calls only.
    OutboundOnly,
    /// Multiple conditions (any must match).
    Any(Vec<Self>),
    /// Multiple conditions (all must match).
    All(Vec<Self>),
    /// Negation of a condition.
    Not(Box<Self>),
}

impl RecordingTrigger {
    /// Creates a trunk trigger.
    #[must_use]
    pub fn trunk(name: impl Into<String>) -> Self {
        Self::Trunk(name.into())
    }

    /// Creates a caller pattern trigger.
    #[must_use]
    pub fn caller_pattern(pattern: impl Into<String>) -> Self {
        Self::CallerPattern(pattern.into())
    }

    /// Creates a callee pattern trigger.
    #[must_use]
    pub fn callee_pattern(pattern: impl Into<String>) -> Self {
        Self::CalleePattern(pattern.into())
    }

    /// Creates an inbound-only trigger.
    #[must_use]
    pub const fn inbound_only() -> Self {
        Self::InboundOnly
    }

    /// Creates an outbound-only trigger.
    #[must_use]
    pub const fn outbound_only() -> Self {
        Self::OutboundOnly
    }

    /// Creates an ANY trigger combining multiple triggers.
    #[must_use]
    pub const fn any(triggers: Vec<Self>) -> Self {
        Self::Any(triggers)
    }

    /// Creates an ALL trigger requiring all conditions.
    #[must_use]
    pub const fn all(triggers: Vec<Self>) -> Self {
        Self::All(triggers)
    }

    /// Creates a NOT trigger.
    #[must_use]
    pub fn negate(trigger: Self) -> Self {
        Self::Not(Box::new(trigger))
    }
}

/// Recording media options.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecordingMediaOptions {
    /// Record audio streams.
    pub record_audio: bool,
    /// Record video streams (if present).
    pub record_video: bool,
    /// Mix audio from both parties into single stream.
    pub mix_audio: bool,
    /// Include DTMF tones in recording.
    pub include_dtmf: bool,
    /// Preferred codec for recording (if transcoding needed).
    pub preferred_codec: Option<String>,
}

impl Default for RecordingMediaOptions {
    fn default() -> Self {
        Self {
            record_audio: true,
            record_video: false,
            mix_audio: false,
            include_dtmf: true,
            preferred_codec: None,
        }
    }
}

/// Full recording configuration.
#[derive(Debug, Clone)]
pub struct RecordingConfig {
    /// Recording mode.
    pub mode: RecordingMode,
    /// Primary recording servers.
    pub primary_servers: Vec<SrsEndpoint>,
    /// Backup recording servers.
    pub backup_servers: Vec<SrsEndpoint>,
    /// Recording triggers (for selective mode).
    pub triggers: Vec<RecordingTrigger>,
    /// Media options.
    pub media_options: RecordingMediaOptions,
    /// Maximum concurrent recording sessions.
    pub max_sessions: usize,
    /// Session timeout for recording setup.
    pub session_timeout: Duration,
    /// Retry attempts for recording server.
    pub retry_attempts: u32,
    /// Retry delay between attempts.
    pub retry_delay: Duration,
    /// Include recording metadata in SIP headers.
    pub include_headers: bool,
    /// Trunks exempt from recording.
    pub exempt_trunks: HashSet<String>,
    /// Enable encryption for recording session (SRTP).
    pub encrypt_recording: bool,
    /// Recording session User-Agent header.
    pub user_agent: String,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            mode: RecordingMode::Disabled,
            primary_servers: Vec::new(),
            backup_servers: Vec::new(),
            triggers: Vec::new(),
            media_options: RecordingMediaOptions::default(),
            max_sessions: 1000,
            session_timeout: Duration::from_secs(30),
            retry_attempts: 2,
            retry_delay: Duration::from_secs(1),
            include_headers: true,
            exempt_trunks: HashSet::new(),
            encrypt_recording: true,
            user_agent: "USG-SBC-SIPREC/1.0".to_string(),
        }
    }
}

impl RecordingConfig {
    /// Creates a new config with recording disabled.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Creates a config for recording all calls.
    #[must_use]
    pub fn all_calls() -> Self {
        Self {
            mode: RecordingMode::AllCalls,
            ..Default::default()
        }
    }

    /// Creates a config for selective recording.
    #[must_use]
    pub fn selective() -> Self {
        Self {
            mode: RecordingMode::Selective,
            ..Default::default()
        }
    }

    /// Adds a primary recording server.
    #[must_use]
    pub fn with_primary_server(mut self, server: SrsEndpoint) -> Self {
        self.primary_servers.push(server);
        self
    }

    /// Adds a backup recording server.
    #[must_use]
    pub fn with_backup_server(mut self, server: SrsEndpoint) -> Self {
        self.backup_servers.push(server);
        self
    }

    /// Adds a recording trigger.
    #[must_use]
    pub fn with_trigger(mut self, trigger: RecordingTrigger) -> Self {
        self.triggers.push(trigger);
        self
    }

    /// Sets an exempt trunk.
    #[must_use]
    pub fn with_exempt_trunk(mut self, trunk: impl Into<String>) -> Self {
        self.exempt_trunks.insert(trunk.into());
        self
    }

    /// Returns whether recording is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.mode != RecordingMode::Disabled && !self.primary_servers.is_empty()
    }

    /// Gets available recording servers (primary first, then backup).
    #[must_use]
    pub fn available_servers(&self) -> Vec<&SrsEndpoint> {
        let mut servers: Vec<&SrsEndpoint> =
            self.primary_servers.iter().filter(|s| s.healthy).collect();

        if servers.is_empty() {
            // Fall back to backup servers
            servers = self.backup_servers.iter().filter(|s| s.healthy).collect();
        }

        servers
    }

    /// Checks if a trunk is exempt from recording.
    #[must_use]
    pub fn is_trunk_exempt(&self, trunk_id: &str) -> bool {
        self.exempt_trunks.contains(trunk_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srs_endpoint_creation() {
        let endpoint = SrsEndpoint::new("192.168.1.100:5060")
            .with_sip_uri("sip:recorder@example.com")
            .with_weight(50);

        assert_eq!(endpoint.address, "192.168.1.100:5060");
        assert_eq!(
            endpoint.sip_uri.as_deref(),
            Some("sip:recorder@example.com")
        );
        assert_eq!(endpoint.weight, 50);
        assert!(endpoint.is_primary);
    }

    #[test]
    fn test_srs_endpoint_effective_uri() {
        let endpoint = SrsEndpoint::new("192.168.1.100:5060");
        assert_eq!(endpoint.effective_uri(), "sip:192.168.1.100:5060");

        let endpoint_with_uri =
            SrsEndpoint::new("192.168.1.100:5060").with_sip_uri("sip:recorder@example.com");
        assert_eq!(
            endpoint_with_uri.effective_uri(),
            "sip:recorder@example.com"
        );
    }

    #[test]
    fn test_recording_mode_display() {
        assert_eq!(format!("{}", RecordingMode::Selective), "selective");
        assert_eq!(format!("{}", RecordingMode::AllCalls), "all-calls");
        assert_eq!(format!("{}", RecordingMode::OnDemand), "on-demand");
        assert_eq!(format!("{}", RecordingMode::Disabled), "disabled");
    }

    #[test]
    fn test_recording_config_builder() {
        let config = RecordingConfig::selective()
            .with_primary_server(SrsEndpoint::new("10.0.0.1:5060"))
            .with_backup_server(SrsEndpoint::new("10.0.0.2:5060").as_backup())
            .with_trigger(RecordingTrigger::trunk("pstn-trunk"))
            .with_exempt_trunk("internal-trunk");

        assert_eq!(config.mode, RecordingMode::Selective);
        assert_eq!(config.primary_servers.len(), 1);
        assert_eq!(config.backup_servers.len(), 1);
        assert!(config.is_enabled());
        assert!(config.is_trunk_exempt("internal-trunk"));
        assert!(!config.is_trunk_exempt("pstn-trunk"));
    }

    #[test]
    fn test_available_servers() {
        let mut config = RecordingConfig::all_calls()
            .with_primary_server(SrsEndpoint::new("10.0.0.1:5060"))
            .with_backup_server(SrsEndpoint::new("10.0.0.2:5060"));

        // Both healthy - should return primary
        assert_eq!(config.available_servers().len(), 1);
        assert_eq!(config.available_servers()[0].address, "10.0.0.1:5060");

        // Mark primary unhealthy
        config.primary_servers[0].healthy = false;
        assert_eq!(config.available_servers().len(), 1);
        assert_eq!(config.available_servers()[0].address, "10.0.0.2:5060");
    }

    #[test]
    fn test_recording_triggers() {
        let trigger = RecordingTrigger::all(vec![
            RecordingTrigger::trunk("pstn"),
            RecordingTrigger::inbound_only(),
        ]);

        match trigger {
            RecordingTrigger::All(conditions) => {
                assert_eq!(conditions.len(), 2);
            }
            _ => panic!("Expected All trigger"),
        }
    }

    #[test]
    fn test_disabled_config() {
        let config = RecordingConfig::disabled();
        assert_eq!(config.mode, RecordingMode::Disabled);
        assert!(!config.is_enabled());
    }
}
