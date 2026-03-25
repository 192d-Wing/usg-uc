//! `QoS` (Quality of Service) DSCP marking for network traffic.
//!
//! This module provides DSCP (Differentiated Services Code Point) marking
//! capabilities for SIP signaling and RTP media traffic.
//!
//! ## RFC Compliance
//!
//! - **RFC 2474**: Definition of the Differentiated Services Field (DSCP)
//! - **RFC 4594**: Configuration Guidelines for `DiffServ` Service Classes
//!
//! ## Common DSCP Values for `VoIP`
//!
//! | Traffic Type    | DSCP Class | DSCP Value | TOS Byte |
//! |-----------------|------------|------------|----------|
//! | Voice RTP       | EF         | 46         | 0xB8     |
//! | Video RTP       | AF41       | 34         | 0x88     |
//! | Voice Signaling | CS3        | 24         | 0x60     |
//! | Video Signaling | AF31       | 26         | 0x68     |
//! | Best Effort     | BE         | 0          | 0x00     |
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-5**: Denial of Service Protection (traffic prioritization)
//! - **SC-7**: Boundary Protection (traffic classification)

use socket2::Socket;
use std::fmt;
use std::io;

#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

/// DSCP (Differentiated Services Code Point) values.
///
/// Per RFC 4594, these are recommended values for various traffic types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[derive(Default)]
pub enum DscpValue {
    /// Best Effort (default, no marking).
    #[default]
    BestEffort = 0,

    // Class Selector (CS) PHBs - RFC 2474
    /// Class Selector 1 - Low priority data (scavenger).
    Cs1 = 8,
    /// Class Selector 2 - OAM (Network management).
    Cs2 = 16,
    /// Class Selector 3 - Signaling (Call Signaling).
    Cs3 = 24,
    /// Class Selector 4 - Real-time interactive.
    Cs4 = 32,
    /// Class Selector 5 - Broadcast video.
    Cs5 = 40,
    /// Class Selector 6 - Network control.
    Cs6 = 48,
    /// Class Selector 7 - Reserved.
    Cs7 = 56,

    // Assured Forwarding (AF) PHBs - RFC 2597
    /// AF11 - Low drop probability, class 1.
    Af11 = 10,
    /// AF12 - Medium drop probability, class 1.
    Af12 = 12,
    /// AF13 - High drop probability, class 1.
    Af13 = 14,
    /// AF21 - Low drop probability, class 2.
    Af21 = 18,
    /// AF22 - Medium drop probability, class 2.
    Af22 = 20,
    /// AF23 - High drop probability, class 2.
    Af23 = 22,
    /// AF31 - Low drop probability, class 3 (Video signaling).
    Af31 = 26,
    /// AF32 - Medium drop probability, class 3.
    Af32 = 28,
    /// AF33 - High drop probability, class 3.
    Af33 = 30,
    /// AF41 - Low drop probability, class 4 (Video RTP).
    Af41 = 34,
    /// AF42 - Medium drop probability, class 4.
    Af42 = 36,
    /// AF43 - High drop probability, class 4.
    Af43 = 38,

    // Expedited Forwarding (EF) PHB - RFC 3246
    /// Expedited Forwarding - Voice RTP (highest priority).
    Ef = 46,

    /// Custom DSCP value.
    Custom(u8),
}

impl DscpValue {
    /// Creates a custom DSCP value.
    ///
    /// # Panics
    ///
    /// Debug assertion if value > 63 (DSCP is 6 bits).
    #[must_use]
    pub fn custom(value: u8) -> Self {
        debug_assert!(value <= 63, "DSCP value must be 0-63");
        Self::Custom(value & 0x3F)
    }

    /// Returns the numeric DSCP value (0-63).
    #[must_use]
    pub const fn value(&self) -> u8 {
        match *self {
            Self::BestEffort => 0,
            Self::Cs1 => 8,
            Self::Cs2 => 16,
            Self::Cs3 => 24,
            Self::Cs4 => 32,
            Self::Cs5 => 40,
            Self::Cs6 => 48,
            Self::Cs7 => 56,
            Self::Af11 => 10,
            Self::Af12 => 12,
            Self::Af13 => 14,
            Self::Af21 => 18,
            Self::Af22 => 20,
            Self::Af23 => 22,
            Self::Af31 => 26,
            Self::Af32 => 28,
            Self::Af33 => 30,
            Self::Af41 => 34,
            Self::Af42 => 36,
            Self::Af43 => 38,
            Self::Ef => 46,
            Self::Custom(v) => v,
        }
    }

    /// Converts DSCP value to TOS byte (DSCP << 2).
    ///
    /// The TOS byte has DSCP in the upper 6 bits and ECN in the lower 2 bits.
    #[must_use]
    pub const fn to_tos(&self) -> u8 {
        self.value() << 2
    }

    /// Returns the DSCP value for voice RTP traffic (EF).
    #[must_use]
    pub const fn voice_rtp() -> Self {
        Self::Ef
    }

    /// Returns the DSCP value for video RTP traffic (AF41).
    #[must_use]
    pub const fn video_rtp() -> Self {
        Self::Af41
    }

    /// Returns the DSCP value for voice signaling (CS3).
    #[must_use]
    pub const fn voice_signaling() -> Self {
        Self::Cs3
    }

    /// Returns the DSCP value for video signaling (AF31).
    #[must_use]
    pub const fn video_signaling() -> Self {
        Self::Af31
    }

    /// Returns the DSCP value for network management/OAM (CS2).
    #[must_use]
    pub const fn oam() -> Self {
        Self::Cs2
    }

    /// Returns the name of this DSCP class.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match *self {
            Self::BestEffort => "BE",
            Self::Cs1 => "CS1",
            Self::Cs2 => "CS2",
            Self::Cs3 => "CS3",
            Self::Cs4 => "CS4",
            Self::Cs5 => "CS5",
            Self::Cs6 => "CS6",
            Self::Cs7 => "CS7",
            Self::Af11 => "AF11",
            Self::Af12 => "AF12",
            Self::Af13 => "AF13",
            Self::Af21 => "AF21",
            Self::Af22 => "AF22",
            Self::Af23 => "AF23",
            Self::Af31 => "AF31",
            Self::Af32 => "AF32",
            Self::Af33 => "AF33",
            Self::Af41 => "AF41",
            Self::Af42 => "AF42",
            Self::Af43 => "AF43",
            Self::Ef => "EF",
            Self::Custom(_) => "CUSTOM",
        }
    }
}

impl fmt::Display for DscpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.value())
    }
}

impl From<DscpValue> for u8 {
    fn from(dscp: DscpValue) -> Self {
        dscp.value()
    }
}

impl From<u8> for DscpValue {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::BestEffort,
            8 => Self::Cs1,
            16 => Self::Cs2,
            24 => Self::Cs3,
            32 => Self::Cs4,
            40 => Self::Cs5,
            48 => Self::Cs6,
            56 => Self::Cs7,
            10 => Self::Af11,
            12 => Self::Af12,
            14 => Self::Af13,
            18 => Self::Af21,
            20 => Self::Af22,
            22 => Self::Af23,
            26 => Self::Af31,
            28 => Self::Af32,
            30 => Self::Af33,
            34 => Self::Af41,
            36 => Self::Af42,
            38 => Self::Af43,
            46 => Self::Ef,
            v => Self::Custom(v & 0x3F),
        }
    }
}

/// Traffic type classification for automatic DSCP assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TrafficType {
    /// Voice RTP media.
    VoiceMedia,
    /// Video RTP media.
    VideoMedia,
    /// Voice SIP signaling.
    VoiceSignaling,
    /// Video signaling.
    VideoSignaling,
    /// Network management/monitoring.
    Management,
    /// Best effort (default).
    #[default]
    BestEffort,
}

impl TrafficType {
    /// Returns the recommended DSCP value for this traffic type.
    #[must_use]
    pub const fn recommended_dscp(&self) -> DscpValue {
        match self {
            Self::VoiceMedia => DscpValue::Ef,
            Self::VideoMedia => DscpValue::Af41,
            Self::VoiceSignaling => DscpValue::Cs3,
            Self::VideoSignaling => DscpValue::Af31,
            Self::Management => DscpValue::Cs2,
            Self::BestEffort => DscpValue::BestEffort,
        }
    }
}

impl fmt::Display for TrafficType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VoiceMedia => write!(f, "voice-media"),
            Self::VideoMedia => write!(f, "video-media"),
            Self::VoiceSignaling => write!(f, "voice-signaling"),
            Self::VideoSignaling => write!(f, "video-signaling"),
            Self::Management => write!(f, "management"),
            Self::BestEffort => write!(f, "best-effort"),
        }
    }
}

/// `QoS` configuration for a socket or transport.
#[derive(Debug, Clone)]
pub struct QosConfig {
    /// DSCP value to apply.
    pub dscp: DscpValue,
    /// Traffic type (for informational purposes).
    pub traffic_type: TrafficType,
    /// Whether to apply `QoS` marking.
    pub enabled: bool,
}

impl Default for QosConfig {
    fn default() -> Self {
        Self {
            dscp: DscpValue::BestEffort,
            traffic_type: TrafficType::BestEffort,
            enabled: false,
        }
    }
}

impl QosConfig {
    /// Creates a `QoS` config for voice signaling (CS3).
    #[must_use]
    pub const fn voice_signaling() -> Self {
        Self {
            dscp: DscpValue::voice_signaling(),
            traffic_type: TrafficType::VoiceSignaling,
            enabled: true,
        }
    }

    /// Creates a `QoS` config for voice media (EF).
    #[must_use]
    pub const fn voice_media() -> Self {
        Self {
            dscp: DscpValue::voice_rtp(),
            traffic_type: TrafficType::VoiceMedia,
            enabled: true,
        }
    }

    /// Creates a `QoS` config for video signaling (AF31).
    #[must_use]
    pub const fn video_signaling() -> Self {
        Self {
            dscp: DscpValue::video_signaling(),
            traffic_type: TrafficType::VideoSignaling,
            enabled: true,
        }
    }

    /// Creates a `QoS` config for video media (AF41).
    #[must_use]
    pub const fn video_media() -> Self {
        Self {
            dscp: DscpValue::video_rtp(),
            traffic_type: TrafficType::VideoMedia,
            enabled: true,
        }
    }

    /// Creates a `QoS` config for management traffic (CS2).
    #[must_use]
    pub const fn management() -> Self {
        Self {
            dscp: DscpValue::oam(),
            traffic_type: TrafficType::Management,
            enabled: true,
        }
    }

    /// Creates a custom `QoS` config.
    #[must_use]
    pub const fn custom(dscp: DscpValue, traffic_type: TrafficType) -> Self {
        Self {
            dscp,
            traffic_type,
            enabled: true,
        }
    }

    /// Disables `QoS` marking.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Returns the TOS byte value.
    #[must_use]
    pub const fn tos_byte(&self) -> u8 {
        if self.enabled { self.dscp.to_tos() } else { 0 }
    }
}

/// Applies DSCP marking to a socket.
///
/// This sets the IP TOS byte which contains the DSCP value in the upper 6 bits.
///
/// # IPv4 vs IPv6
///
/// - For IPv4, sets `IP_TOS` socket option
/// - For IPv6, sets `IPV6_TCLASS` socket option
///
/// # Platform Support
///
/// - **Linux/macOS/BSD**: Full support via socket2
/// - **Windows**: Full support via platform-specific API (requires unsafe code)
///
/// # Errors
///
/// Returns an error if the socket option cannot be set.
///
/// # Errors
/// Returns an error if the operation fails.
///
/// # Windows IPv6 Implementation
///
/// On Windows, IPv6 traffic class setting uses unsafe code with safety protections:
/// - Validates socket handle before use
/// - Uses correct parameter sizes
/// - Properly handles error codes
#[cfg(windows)]
#[allow(unsafe_code)]
fn set_ipv6_tclass_windows(socket: &Socket, tclass: u32) -> io::Result<()> {
    use windows::Win32::Networking::WinSock::{
        IPPROTO_IPV6, IPV6_TCLASS, SOCKET, SOCKET_ERROR, setsockopt,
    };

    let raw_socket = socket.as_raw_socket() as usize;

    // Safety check: Ensure we have a valid socket handle
    if raw_socket == 0 || raw_socket == usize::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socket handle",
        ));
    }

    // SAFETY: This is safe because:
    // 1. We verified the socket handle is valid (non-zero, not INVALID_SOCKET)
    // 2. We're creating a valid byte slice from a u32 reference
    // 3. The tclass value lifetime extends through the unsafe call
    // 4. IPPROTO_IPV6 and IPV6_TCLASS are valid constants from Windows API
    let result = unsafe {
        let tclass_bytes = std::slice::from_raw_parts(
            &tclass as *const u32 as *const u8,
            std::mem::size_of::<u32>(),
        );
        setsockopt(
            SOCKET(raw_socket),
            IPPROTO_IPV6.0 as i32,
            IPV6_TCLASS,
            Some(tclass_bytes),
        )
    };

    if result == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Applies DSCP marking to a socket.
///
/// # Arguments
///
/// * `socket` - The socket to apply DSCP marking to
/// * `dscp` - The DSCP value to apply
/// * `is_ipv6` - Whether this is an IPv6 socket
///
/// # Errors
///
/// Returns an error if the socket option cannot be set.
pub fn apply_dscp(socket: &Socket, dscp: DscpValue, is_ipv6: bool) -> io::Result<()> {
    let tos = u32::from(dscp.to_tos());

    #[cfg(not(windows))]
    {
        if is_ipv6 {
            socket.set_tclass_v6(tos)?;
        } else {
            socket.set_tos_v4(tos)?;
        }
    }

    #[cfg(windows)]
    {
        if is_ipv6 {
            set_ipv6_tclass_windows(socket, tos)?;
        } else {
            socket.set_tos_v4(tos)?;
        }
    }

    tracing::debug!(
        dscp = %dscp,
        tos = tos,
        ipv6 = is_ipv6,
        "applied DSCP marking to socket"
    );

    Ok(())
}

/// Applies `QoS` configuration to a socket.
///
/// # Errors
///
/// Returns an error if `QoS` marking cannot be applied.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn apply_qos_config(socket: &Socket, config: &QosConfig, is_ipv6: bool) -> io::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    apply_dscp(socket, config.dscp, is_ipv6)?;

    tracing::info!(
        traffic_type = %config.traffic_type,
        dscp = %config.dscp,
        "QoS configuration applied"
    );

    Ok(())
}

/// Per-trunk `QoS` policy.
#[derive(Debug, Clone)]
pub struct TrunkQosPolicy {
    /// Trunk identifier.
    pub trunk_id: String,
    /// `QoS` config for signaling traffic.
    pub signaling: QosConfig,
    /// `QoS` config for media traffic.
    pub media: QosConfig,
}

impl TrunkQosPolicy {
    /// Creates a new trunk `QoS` policy with default voice settings.
    #[must_use]
    pub fn voice_default(trunk_id: impl Into<String>) -> Self {
        Self {
            trunk_id: trunk_id.into(),
            signaling: QosConfig::voice_signaling(),
            media: QosConfig::voice_media(),
        }
    }

    /// Creates a new trunk `QoS` policy with video settings.
    #[must_use]
    pub fn video_default(trunk_id: impl Into<String>) -> Self {
        Self {
            trunk_id: trunk_id.into(),
            signaling: QosConfig::video_signaling(),
            media: QosConfig::video_media(),
        }
    }

    /// Creates a trunk policy with `QoS` disabled.
    #[must_use]
    pub fn disabled(trunk_id: impl Into<String>) -> Self {
        Self {
            trunk_id: trunk_id.into(),
            signaling: QosConfig::disabled(),
            media: QosConfig::disabled(),
        }
    }
}

/// `QoS` policy manager for managing per-trunk `QoS` settings.
#[derive(Debug, Clone, Default)]
pub struct QosPolicyManager {
    /// Default `QoS` for signaling.
    default_signaling: QosConfig,
    /// Default `QoS` for media.
    default_media: QosConfig,
    /// Per-trunk overrides.
    trunk_policies: std::collections::HashMap<String, TrunkQosPolicy>,
}

impl QosPolicyManager {
    /// Creates a new `QoS` policy manager with default voice settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_signaling: QosConfig::voice_signaling(),
            default_media: QosConfig::voice_media(),
            trunk_policies: std::collections::HashMap::new(),
        }
    }

    /// Creates a policy manager with `QoS` disabled by default.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            default_signaling: QosConfig::disabled(),
            default_media: QosConfig::disabled(),
            trunk_policies: std::collections::HashMap::new(),
        }
    }

    /// Sets the default signaling `QoS`.
    pub const fn set_default_signaling(&mut self, config: QosConfig) {
        self.default_signaling = config;
    }

    /// Sets the default media `QoS`.
    pub const fn set_default_media(&mut self, config: QosConfig) {
        self.default_media = config;
    }

    /// Adds a trunk-specific `QoS` policy.
    pub fn add_trunk_policy(&mut self, policy: TrunkQosPolicy) {
        self.trunk_policies.insert(policy.trunk_id.clone(), policy);
    }

    /// Removes a trunk-specific policy.
    pub fn remove_trunk_policy(&mut self, trunk_id: &str) {
        self.trunk_policies.remove(trunk_id);
    }

    /// Gets the signaling `QoS` config for a trunk.
    #[must_use]
    pub fn signaling_config(&self, trunk_id: Option<&str>) -> &QosConfig {
        trunk_id
            .and_then(|id| self.trunk_policies.get(id))
            .map_or(&self.default_signaling, |p| &p.signaling)
    }

    /// Gets the media `QoS` config for a trunk.
    #[must_use]
    pub fn media_config(&self, trunk_id: Option<&str>) -> &QosConfig {
        trunk_id
            .and_then(|id| self.trunk_policies.get(id))
            .map_or(&self.default_media, |p| &p.media)
    }
}

#[cfg(test)]
#[allow(
    clippy::decimal_literal_representation,
    clippy::decimal_bitwise_operands
)]
mod tests {
    use super::*;

    #[test]
    fn test_dscp_values() {
        assert_eq!(DscpValue::BestEffort.value(), 0);
        assert_eq!(DscpValue::Ef.value(), 46);
        assert_eq!(DscpValue::Cs3.value(), 24);
        assert_eq!(DscpValue::Af41.value(), 34);
    }

    #[test]
    fn test_dscp_to_tos() {
        // EF (46) -> TOS 0xB8 (184)
        assert_eq!(DscpValue::Ef.to_tos(), 0xB8);
        // CS3 (24) -> TOS 0x60 (96)
        assert_eq!(DscpValue::Cs3.to_tos(), 0x60);
        // AF41 (34) -> TOS 0x88 (136)
        assert_eq!(DscpValue::Af41.to_tos(), 0x88);
        // BE (0) -> TOS 0x00
        assert_eq!(DscpValue::BestEffort.to_tos(), 0x00);
    }

    #[test]
    fn test_dscp_names() {
        assert_eq!(DscpValue::Ef.name(), "EF");
        assert_eq!(DscpValue::Cs3.name(), "CS3");
        assert_eq!(DscpValue::Af41.name(), "AF41");
        assert_eq!(DscpValue::BestEffort.name(), "BE");
    }

    #[test]
    fn test_dscp_conversions() {
        assert_eq!(DscpValue::from(46), DscpValue::Ef);
        assert_eq!(DscpValue::from(24), DscpValue::Cs3);
        assert_eq!(DscpValue::from(99), DscpValue::Custom(99 & 0x3F));

        let dscp: u8 = DscpValue::Ef.into();
        assert_eq!(dscp, 46);
    }

    #[test]
    fn test_traffic_type_dscp() {
        assert_eq!(TrafficType::VoiceMedia.recommended_dscp(), DscpValue::Ef);
        assert_eq!(TrafficType::VideoMedia.recommended_dscp(), DscpValue::Af41);
        assert_eq!(
            TrafficType::VoiceSignaling.recommended_dscp(),
            DscpValue::Cs3
        );
        assert_eq!(
            TrafficType::VideoSignaling.recommended_dscp(),
            DscpValue::Af31
        );
    }

    #[test]
    fn test_qos_config_presets() {
        let voice_sig = QosConfig::voice_signaling();
        assert!(voice_sig.enabled);
        assert_eq!(voice_sig.dscp, DscpValue::Cs3);
        assert_eq!(voice_sig.traffic_type, TrafficType::VoiceSignaling);

        let voice_media = QosConfig::voice_media();
        assert!(voice_media.enabled);
        assert_eq!(voice_media.dscp, DscpValue::Ef);

        let disabled = QosConfig::disabled();
        assert!(!disabled.enabled);
    }

    #[test]
    fn test_qos_config_tos_byte() {
        let config = QosConfig::voice_media();
        assert_eq!(config.tos_byte(), 0xB8); // EF << 2

        let disabled = QosConfig::disabled();
        assert_eq!(disabled.tos_byte(), 0);
    }

    #[test]
    fn test_trunk_qos_policy() {
        let policy = TrunkQosPolicy::voice_default("pstn-trunk");
        assert_eq!(policy.trunk_id, "pstn-trunk");
        assert_eq!(policy.signaling.dscp, DscpValue::Cs3);
        assert_eq!(policy.media.dscp, DscpValue::Ef);

        let video_policy = TrunkQosPolicy::video_default("video-trunk");
        assert_eq!(video_policy.signaling.dscp, DscpValue::Af31);
        assert_eq!(video_policy.media.dscp, DscpValue::Af41);
    }

    #[test]
    fn test_qos_policy_manager() {
        let mut manager = QosPolicyManager::new();

        // Default should be voice
        assert_eq!(manager.signaling_config(None).dscp, DscpValue::Cs3);
        assert_eq!(manager.media_config(None).dscp, DscpValue::Ef);

        // Add trunk override
        let video_policy = TrunkQosPolicy::video_default("video-trunk");
        manager.add_trunk_policy(video_policy);

        // Trunk should have video settings
        assert_eq!(
            manager.signaling_config(Some("video-trunk")).dscp,
            DscpValue::Af31
        );
        assert_eq!(
            manager.media_config(Some("video-trunk")).dscp,
            DscpValue::Af41
        );

        // Unknown trunk should use default
        assert_eq!(
            manager.signaling_config(Some("unknown")).dscp,
            DscpValue::Cs3
        );
    }

    #[test]
    fn test_dscp_display() {
        assert_eq!(format!("{}", DscpValue::Ef), "EF (46)");
        assert_eq!(format!("{}", DscpValue::Cs3), "CS3 (24)");
        assert_eq!(format!("{}", DscpValue::BestEffort), "BE (0)");
    }

    #[test]
    fn test_custom_dscp() {
        let custom = DscpValue::custom(42);
        assert_eq!(custom.value(), 42);
        assert_eq!(custom.name(), "CUSTOM");
    }
}
