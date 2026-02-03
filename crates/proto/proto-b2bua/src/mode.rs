//! B2BUA mode-specific behavior per RFC 7092.
//!
//! This module implements the behavioral differences between B2BUA modes
//! as defined in RFC 7092 (B2BUA Taxonomy) and RFC 5853 (SBC Requirements).
//!
//! ## Mode Behaviors
//!
//! - **SignalingOnly**: SDP passthrough, signaling modification only
//! - **MediaRelay**: SDP rewrite, RTP anchoring without inspection
//! - **MediaAware**: Media inspection, recording, DTMF detection
//! - **MediaTermination**: Full transcoding, independent codec negotiation

use crate::B2buaMode;

/// SDP modification requirements for a B2BUA mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpModification {
    /// Pass SDP through unchanged.
    Passthrough,
    /// Rewrite connection and port information.
    RewriteConnection,
    /// Full codec modification and transcoding support.
    FullModification,
}

/// Media handling requirements for a B2BUA mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaHandling {
    /// Media flows directly between endpoints.
    Direct,
    /// Media flows through B2BUA (relay).
    Relay,
    /// Media is inspected but forwarded.
    Inspect,
    /// Media is terminated and re-originated.
    Terminate,
}

/// Topology hiding level for a B2BUA mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyHiding {
    /// No topology hiding.
    None,
    /// Hide signaling topology only.
    SignalingOnly,
    /// Hide both signaling and media topology.
    Full,
}

/// Media processing capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaCapabilities {
    /// Whether transcoding is supported.
    pub transcoding: bool,
    /// Whether media recording is supported.
    pub recording: bool,
    /// Whether DTMF detection is supported.
    pub dtmf_detection: bool,
    /// Whether RTP inspection is supported.
    pub rtp_inspection: bool,
}

/// Mode-specific behavioral characteristics.
#[derive(Debug, Clone)]
pub struct ModeCharacteristics {
    /// SDP modification type.
    pub sdp_modification: SdpModification,
    /// Media handling type.
    pub media_handling: MediaHandling,
    /// Topology hiding level.
    pub topology_hiding: TopologyHiding,
    /// Media processing capabilities.
    pub capabilities: MediaCapabilities,
}

impl ModeCharacteristics {
    /// Returns characteristics for the given B2BUA mode.
    ///
    /// Per RFC 7092 Section 3:
    /// - Signaling-only: Only signaling modified, media direct
    /// - Media-relay: Media anchored, packets forwarded
    /// - Media-aware: Media inspected, can modify
    /// - Media-termination: Full control, independent legs
    pub fn for_mode(mode: B2buaMode) -> Self {
        match mode {
            B2buaMode::SignalingOnly => Self {
                sdp_modification: SdpModification::Passthrough,
                media_handling: MediaHandling::Direct,
                topology_hiding: TopologyHiding::SignalingOnly,
                capabilities: MediaCapabilities::default(),
            },
            B2buaMode::MediaRelay => Self {
                sdp_modification: SdpModification::RewriteConnection,
                media_handling: MediaHandling::Relay,
                topology_hiding: TopologyHiding::Full,
                capabilities: MediaCapabilities::default(),
            },
            B2buaMode::MediaAware => Self {
                sdp_modification: SdpModification::RewriteConnection,
                media_handling: MediaHandling::Inspect,
                topology_hiding: TopologyHiding::Full,
                capabilities: MediaCapabilities {
                    transcoding: false,
                    recording: true,
                    dtmf_detection: true,
                    rtp_inspection: true,
                },
            },
            B2buaMode::MediaTermination => Self {
                sdp_modification: SdpModification::FullModification,
                media_handling: MediaHandling::Terminate,
                topology_hiding: TopologyHiding::Full,
                capabilities: MediaCapabilities {
                    transcoding: true,
                    recording: true,
                    dtmf_detection: true,
                    rtp_inspection: true,
                },
            },
        }
    }

    /// Returns true if the mode requires SDP rewriting.
    pub fn requires_sdp_rewrite(&self) -> bool {
        !matches!(self.sdp_modification, SdpModification::Passthrough)
    }

    /// Returns true if the mode anchors media.
    pub fn anchors_media(&self) -> bool {
        !matches!(self.media_handling, MediaHandling::Direct)
    }

    /// Returns true if the mode can inspect media.
    pub fn can_inspect_media(&self) -> bool {
        matches!(
            self.media_handling,
            MediaHandling::Inspect | MediaHandling::Terminate
        )
    }

    /// Returns true if the mode can transcode.
    pub fn can_transcode(&self) -> bool {
        self.capabilities.transcoding
    }
}

/// Media address information for SDP rewriting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaAddress {
    /// IP address (IPv4 or IPv6).
    pub address: String,
    /// RTP port.
    pub port: u16,
    /// RTCP port (defaults to RTP port + 1).
    pub rtcp_port: Option<u16>,
}

impl MediaAddress {
    /// Creates a new media address.
    pub fn new(address: impl Into<String>, port: u16) -> Self {
        Self {
            address: address.into(),
            port,
            rtcp_port: None,
        }
    }

    /// Creates a media address with explicit RTCP port.
    pub fn with_rtcp(address: impl Into<String>, port: u16, rtcp_port: u16) -> Self {
        Self {
            address: address.into(),
            port,
            rtcp_port: Some(rtcp_port),
        }
    }

    /// Returns the RTCP port (default: RTP port + 1).
    pub fn get_rtcp_port(&self) -> u16 {
        self.rtcp_port.unwrap_or(self.port + 1)
    }
}

/// SDP rewrite context for a B2BUA session.
#[derive(Debug, Clone)]
pub struct SdpRewriteContext {
    /// B2BUA mode.
    mode: B2buaMode,
    /// Local media address for A-leg.
    a_leg_address: Option<MediaAddress>,
    /// Local media address for B-leg.
    b_leg_address: Option<MediaAddress>,
    /// Original A-leg remote address (caller's).
    a_leg_remote_address: Option<MediaAddress>,
    /// Original B-leg remote address (callee's).
    b_leg_remote_address: Option<MediaAddress>,
}

impl SdpRewriteContext {
    /// Creates a new SDP rewrite context.
    pub fn new(mode: B2buaMode) -> Self {
        Self {
            mode,
            a_leg_address: None,
            b_leg_address: None,
            a_leg_remote_address: None,
            b_leg_remote_address: None,
        }
    }

    /// Sets the local media address for the A-leg.
    pub fn set_a_leg_address(&mut self, address: MediaAddress) {
        self.a_leg_address = Some(address);
    }

    /// Sets the local media address for the B-leg.
    pub fn set_b_leg_address(&mut self, address: MediaAddress) {
        self.b_leg_address = Some(address);
    }

    /// Stores the A-leg remote address from incoming INVITE.
    pub fn set_a_leg_remote_address(&mut self, address: MediaAddress) {
        self.a_leg_remote_address = Some(address);
    }

    /// Stores the B-leg remote address from callee's response.
    pub fn set_b_leg_remote_address(&mut self, address: MediaAddress) {
        self.b_leg_remote_address = Some(address);
    }

    /// Returns the address to use in SDP sent to A-leg.
    ///
    /// In SignalingOnly mode, returns the B-leg remote (callee's) address.
    /// In other modes, returns the B2BUA's local A-leg address.
    pub fn address_for_a_leg(&self) -> Option<&MediaAddress> {
        let characteristics = ModeCharacteristics::for_mode(self.mode);

        if characteristics.anchors_media() {
            // B2BUA anchors media - use our local address
            self.a_leg_address.as_ref()
        } else {
            // Signaling-only - pass through callee's address
            self.b_leg_remote_address.as_ref()
        }
    }

    /// Returns the address to use in SDP sent to B-leg.
    ///
    /// In SignalingOnly mode, returns the A-leg remote (caller's) address.
    /// In other modes, returns the B2BUA's local B-leg address.
    pub fn address_for_b_leg(&self) -> Option<&MediaAddress> {
        let characteristics = ModeCharacteristics::for_mode(self.mode);

        if characteristics.anchors_media() {
            // B2BUA anchors media - use our local address
            self.b_leg_address.as_ref()
        } else {
            // Signaling-only - pass through caller's address
            self.a_leg_remote_address.as_ref()
        }
    }

    /// Returns the mode.
    pub fn mode(&self) -> B2buaMode {
        self.mode
    }

    /// Returns the characteristics for this context's mode.
    pub fn characteristics(&self) -> ModeCharacteristics {
        ModeCharacteristics::for_mode(self.mode)
    }
}

/// Header hiding flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeaderHiding {
    /// Replace Via headers.
    pub via: bool,
    /// Replace Record-Route headers.
    pub record_route: bool,
    /// Replace Contact header.
    pub contact: bool,
    /// Strip internal headers (e.g., P-Asserted-Identity).
    pub internal_headers: bool,
}

/// Identity hiding flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IdentityHiding {
    /// Replace Call-ID on B-leg.
    pub call_id: bool,
    /// Anonymize From/To display names.
    pub display_names: bool,
}

/// Topology hiding configuration.
#[derive(Debug, Clone)]
pub struct TopologyHidingConfig {
    /// Header replacement configuration.
    pub headers: HeaderHiding,
    /// Identity hiding configuration.
    pub identity: IdentityHiding,
}

impl TopologyHidingConfig {
    /// Creates a configuration for the given topology hiding level.
    pub fn for_level(level: TopologyHiding) -> Self {
        match level {
            TopologyHiding::None => Self {
                headers: HeaderHiding::default(),
                identity: IdentityHiding::default(),
            },
            TopologyHiding::SignalingOnly | TopologyHiding::Full => Self {
                headers: HeaderHiding {
                    via: true,
                    record_route: true,
                    contact: true,
                    internal_headers: true,
                },
                identity: IdentityHiding {
                    call_id: true,
                    display_names: false,
                },
            },
        }
    }

    /// Creates a configuration for the given B2BUA mode.
    pub fn for_mode(mode: B2buaMode) -> Self {
        let characteristics = ModeCharacteristics::for_mode(mode);
        Self::for_level(characteristics.topology_hiding)
    }

    /// Returns true if any topology hiding is enabled.
    pub fn is_enabled(&self) -> bool {
        self.headers.via
            || self.headers.record_route
            || self.headers.contact
            || self.headers.internal_headers
            || self.identity.call_id
            || self.identity.display_names
    }
}

impl Default for TopologyHidingConfig {
    fn default() -> Self {
        Self::for_level(TopologyHiding::Full)
    }
}

/// Codec negotiation mode for media-termination B2BUA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecNegotiationMode {
    /// Negotiate the same codec on both legs (common codec).
    Common,
    /// Allow different codecs on each leg (transcoding).
    Independent,
    /// Prefer local codec preferences, transcode if needed.
    PreferLocal,
}

/// Media termination configuration.
#[derive(Debug, Clone)]
pub struct MediaTerminationConfig {
    /// Codec negotiation mode.
    pub codec_negotiation: CodecNegotiationMode,
    /// Preferred codecs in priority order.
    pub preferred_codecs: Vec<String>,
    /// Enable jitter buffer.
    pub jitter_buffer_enabled: bool,
    /// Jitter buffer size in milliseconds.
    pub jitter_buffer_ms: u32,
    /// Enable packet loss concealment.
    pub plc_enabled: bool,
    /// Enable comfort noise generation.
    pub cng_enabled: bool,
}

impl Default for MediaTerminationConfig {
    fn default() -> Self {
        Self {
            codec_negotiation: CodecNegotiationMode::Common,
            preferred_codecs: vec![
                "opus/48000/2".to_string(),
                "PCMU/8000".to_string(),
                "PCMA/8000".to_string(),
            ],
            jitter_buffer_enabled: true,
            jitter_buffer_ms: 60,
            plc_enabled: true,
            cng_enabled: false,
        }
    }
}

/// Media relay configuration.
#[derive(Debug, Clone)]
pub struct MediaRelayConfig {
    /// Timeout for media inactivity (seconds).
    pub media_timeout_secs: u32,
    /// Enable RTCP relay.
    pub rtcp_relay_enabled: bool,
    /// Enable RTP multiplexing (rtcp-mux).
    pub rtp_mux_enabled: bool,
    /// Symmetric RTP enabled.
    pub symmetric_rtp: bool,
}

impl Default for MediaRelayConfig {
    fn default() -> Self {
        Self {
            media_timeout_secs: 30,
            rtcp_relay_enabled: true,
            rtp_mux_enabled: true,
            symmetric_rtp: true,
        }
    }
}

/// Complete B2BUA mode configuration.
#[derive(Debug, Clone)]
pub struct ModeConfig {
    /// B2BUA mode.
    pub mode: B2buaMode,
    /// Topology hiding configuration.
    pub topology_hiding: TopologyHidingConfig,
    /// Media relay configuration (for relay/aware modes).
    pub media_relay: MediaRelayConfig,
    /// Media termination configuration (for termination mode).
    pub media_termination: MediaTerminationConfig,
}

impl ModeConfig {
    /// Creates a configuration for the given mode.
    pub fn for_mode(mode: B2buaMode) -> Self {
        Self {
            mode,
            topology_hiding: TopologyHidingConfig::for_mode(mode),
            media_relay: MediaRelayConfig::default(),
            media_termination: MediaTerminationConfig::default(),
        }
    }

    /// Returns the mode characteristics.
    pub fn characteristics(&self) -> ModeCharacteristics {
        ModeCharacteristics::for_mode(self.mode)
    }
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self::for_mode(B2buaMode::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signaling_only_characteristics() {
        let chars = ModeCharacteristics::for_mode(B2buaMode::SignalingOnly);

        assert_eq!(chars.sdp_modification, SdpModification::Passthrough);
        assert_eq!(chars.media_handling, MediaHandling::Direct);
        assert_eq!(chars.topology_hiding, TopologyHiding::SignalingOnly);
        assert!(!chars.transcoding_supported);
        assert!(!chars.recording_supported);
        assert!(!chars.anchors_media());
        assert!(!chars.can_transcode());
    }

    #[test]
    fn test_media_relay_characteristics() {
        let chars = ModeCharacteristics::for_mode(B2buaMode::MediaRelay);

        assert_eq!(chars.sdp_modification, SdpModification::RewriteConnection);
        assert_eq!(chars.media_handling, MediaHandling::Relay);
        assert_eq!(chars.topology_hiding, TopologyHiding::Full);
        assert!(!chars.transcoding_supported);
        assert!(chars.anchors_media());
        assert!(chars.requires_sdp_rewrite());
    }

    #[test]
    fn test_media_aware_characteristics() {
        let chars = ModeCharacteristics::for_mode(B2buaMode::MediaAware);

        assert_eq!(chars.media_handling, MediaHandling::Inspect);
        assert!(chars.recording_supported);
        assert!(chars.dtmf_detection_supported);
        assert!(chars.rtp_inspection_supported);
        assert!(!chars.transcoding_supported);
        assert!(chars.can_inspect_media());
    }

    #[test]
    fn test_media_termination_characteristics() {
        let chars = ModeCharacteristics::for_mode(B2buaMode::MediaTermination);

        assert_eq!(chars.sdp_modification, SdpModification::FullModification);
        assert_eq!(chars.media_handling, MediaHandling::Terminate);
        assert!(chars.transcoding_supported);
        assert!(chars.recording_supported);
        assert!(chars.can_transcode());
        assert!(chars.can_inspect_media());
    }

    #[test]
    fn test_media_address() {
        let addr = MediaAddress::new("192.168.1.100", 10000);
        assert_eq!(addr.address, "192.168.1.100");
        assert_eq!(addr.port, 10000);
        assert_eq!(addr.get_rtcp_port(), 10001);

        let addr_explicit = MediaAddress::with_rtcp("192.168.1.100", 10000, 10005);
        assert_eq!(addr_explicit.get_rtcp_port(), 10005);
    }

    #[test]
    fn test_sdp_rewrite_context_signaling_only() {
        let mut ctx = SdpRewriteContext::new(B2buaMode::SignalingOnly);

        // Set up addresses
        ctx.set_a_leg_address(MediaAddress::new("10.0.0.1", 20000));
        ctx.set_b_leg_address(MediaAddress::new("10.0.0.1", 20002));
        ctx.set_a_leg_remote_address(MediaAddress::new("192.168.1.10", 30000));
        ctx.set_b_leg_remote_address(MediaAddress::new("172.16.0.10", 40000));

        // In signaling-only mode, pass through remote addresses
        let addr_for_a = ctx.address_for_a_leg().cloned();
        assert_eq!(
            addr_for_a.as_ref().map(|a| a.address.as_str()),
            Some("172.16.0.10")
        );

        let addr_for_b = ctx.address_for_b_leg().cloned();
        assert_eq!(
            addr_for_b.as_ref().map(|a| a.address.as_str()),
            Some("192.168.1.10")
        );
    }

    #[test]
    fn test_sdp_rewrite_context_media_relay() {
        let mut ctx = SdpRewriteContext::new(B2buaMode::MediaRelay);

        // Set up addresses
        ctx.set_a_leg_address(MediaAddress::new("10.0.0.1", 20000));
        ctx.set_b_leg_address(MediaAddress::new("10.0.0.1", 20002));
        ctx.set_a_leg_remote_address(MediaAddress::new("192.168.1.10", 30000));
        ctx.set_b_leg_remote_address(MediaAddress::new("172.16.0.10", 40000));

        // In media-relay mode, use B2BUA's local addresses
        let addr_for_a = ctx.address_for_a_leg().cloned();
        assert_eq!(
            addr_for_a.as_ref().map(|a| a.address.as_str()),
            Some("10.0.0.1")
        );
        assert_eq!(addr_for_a.as_ref().map(|a| a.port), Some(20000));

        let addr_for_b = ctx.address_for_b_leg().cloned();
        assert_eq!(
            addr_for_b.as_ref().map(|a| a.address.as_str()),
            Some("10.0.0.1")
        );
        assert_eq!(addr_for_b.as_ref().map(|a| a.port), Some(20002));
    }

    #[test]
    fn test_topology_hiding_config_none() {
        let config = TopologyHidingConfig::for_level(TopologyHiding::None);
        assert!(!config.is_enabled());
        assert!(!config.hide_via);
        assert!(!config.hide_contact);
    }

    #[test]
    fn test_topology_hiding_config_full() {
        let config = TopologyHidingConfig::for_level(TopologyHiding::Full);
        assert!(config.is_enabled());
        assert!(config.hide_via);
        assert!(config.hide_record_route);
        assert!(config.hide_contact);
        assert!(config.strip_internal_headers);
        assert!(config.replace_call_id);
    }

    #[test]
    fn test_topology_hiding_for_modes() {
        // Signaling-only should hide signaling
        let config = TopologyHidingConfig::for_mode(B2buaMode::SignalingOnly);
        assert!(config.is_enabled());

        // Media relay should have full hiding
        let config = TopologyHidingConfig::for_mode(B2buaMode::MediaRelay);
        assert!(config.is_enabled());
        assert!(config.hide_via);
    }

    #[test]
    fn test_media_termination_config() {
        let config = MediaTerminationConfig::default();
        assert_eq!(config.codec_negotiation, CodecNegotiationMode::Common);
        assert!(config.jitter_buffer_enabled);
        assert!(!config.preferred_codecs.is_empty());
    }

    #[test]
    fn test_media_relay_config() {
        let config = MediaRelayConfig::default();
        assert!(config.rtcp_relay_enabled);
        assert!(config.symmetric_rtp);
        assert_eq!(config.media_timeout_secs, 30);
    }

    #[test]
    fn test_mode_config() {
        let config = ModeConfig::for_mode(B2buaMode::MediaRelay);
        assert_eq!(config.mode, B2buaMode::MediaRelay);
        assert!(config.characteristics().anchors_media());

        let default_config = ModeConfig::default();
        assert_eq!(default_config.mode, B2buaMode::MediaRelay);
    }

    #[test]
    fn test_all_modes_have_characteristics() {
        let modes = [
            B2buaMode::SignalingOnly,
            B2buaMode::MediaRelay,
            B2buaMode::MediaAware,
            B2buaMode::MediaTermination,
        ];

        for mode in modes {
            let chars = ModeCharacteristics::for_mode(mode);
            // Verify each mode has valid characteristics
            assert!(
                chars.sdp_modification == SdpModification::Passthrough
                    || chars.sdp_modification == SdpModification::RewriteConnection
                    || chars.sdp_modification == SdpModification::FullModification
            );
        }
    }
}
