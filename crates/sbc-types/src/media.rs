//! Media processing types and modes.
//!
//! ## RFC 7092 B2BUA Taxonomy
//!
//! This module defines media handling modes per RFC 7092 Section 3.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Media processing mode per RFC 7092 B2BUA taxonomy.
///
/// Determines how the SBC handles media (RTP/RTCP) for a call.
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
///
/// Media mode selection affects security posture:
/// - `Relay`: Full visibility and control over media, can enforce SRTP
/// - `PassThrough`: Limited control, relies on endpoint security
/// - `SignalingOnly`: No media involvement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MediaMode {
    /// B2BUA terminates media on both sides.
    ///
    /// - Media flows: Endpoint A <-> SBC <-> Endpoint B
    /// - SBC can transcode, apply policies, record
    /// - Full SRTP encryption/decryption at SBC
    /// - Topology fully hidden
    #[default]
    Relay,

    /// B2BUA passes media with minimal modification.
    ///
    /// - Media flows through SBC but minimal processing
    /// - IP/port rewriting only
    /// - No transcoding capability
    /// - Still provides topology hiding via NAT
    PassThrough,

    /// B2BUA handles signaling only.
    ///
    /// - Media flows directly: Endpoint A <-> Endpoint B
    /// - SBC not in media path
    /// - No topology hiding for media
    /// - Used when ICE negotiates direct path
    SignalingOnly,
}

impl MediaMode {
    /// Returns true if media flows through the SBC.
    #[must_use]
    pub fn media_through_sbc(&self) -> bool {
        matches!(self, Self::Relay | Self::PassThrough)
    }

    /// Returns true if transcoding is possible in this mode.
    #[must_use]
    pub fn supports_transcoding(&self) -> bool {
        matches!(self, Self::Relay)
    }

    /// Returns true if topology hiding is provided.
    #[must_use]
    pub fn provides_topology_hiding(&self) -> bool {
        matches!(self, Self::Relay | Self::PassThrough)
    }
}

impl std::fmt::Display for MediaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relay => write!(f, "relay"),
            Self::PassThrough => write!(f, "pass-through"),
            Self::SignalingOnly => write!(f, "signaling-only"),
        }
    }
}

/// Media direction indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MediaDirection {
    /// Send and receive.
    #[default]
    SendRecv,
    /// Send only.
    SendOnly,
    /// Receive only.
    RecvOnly,
    /// Inactive (hold).
    Inactive,
}

impl MediaDirection {
    /// Returns true if sending is enabled.
    #[must_use]
    pub fn can_send(&self) -> bool {
        matches!(self, Self::SendRecv | Self::SendOnly)
    }

    /// Returns true if receiving is enabled.
    #[must_use]
    pub fn can_recv(&self) -> bool {
        matches!(self, Self::SendRecv | Self::RecvOnly)
    }
}

impl std::fmt::Display for MediaDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendRecv => write!(f, "sendrecv"),
            Self::SendOnly => write!(f, "sendonly"),
            Self::RecvOnly => write!(f, "recvonly"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

/// Media type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MediaType {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Application data (e.g., MSRP).
    Application,
    /// Text (e.g., RTT).
    Text,
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Audio => write!(f, "audio"),
            Self::Video => write!(f, "video"),
            Self::Application => write!(f, "application"),
            Self::Text => write!(f, "text"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_mode_capabilities() {
        assert!(MediaMode::Relay.media_through_sbc());
        assert!(MediaMode::Relay.supports_transcoding());
        assert!(MediaMode::Relay.provides_topology_hiding());

        assert!(MediaMode::PassThrough.media_through_sbc());
        assert!(!MediaMode::PassThrough.supports_transcoding());
        assert!(MediaMode::PassThrough.provides_topology_hiding());

        assert!(!MediaMode::SignalingOnly.media_through_sbc());
        assert!(!MediaMode::SignalingOnly.supports_transcoding());
        assert!(!MediaMode::SignalingOnly.provides_topology_hiding());
    }

    #[test]
    fn test_media_direction() {
        assert!(MediaDirection::SendRecv.can_send());
        assert!(MediaDirection::SendRecv.can_recv());

        assert!(MediaDirection::SendOnly.can_send());
        assert!(!MediaDirection::SendOnly.can_recv());

        assert!(!MediaDirection::RecvOnly.can_send());
        assert!(MediaDirection::RecvOnly.can_recv());

        assert!(!MediaDirection::Inactive.can_send());
        assert!(!MediaDirection::Inactive.can_recv());
    }
}
