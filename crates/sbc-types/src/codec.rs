//! Audio and video codec identifiers and parameters.
//!
//! This module defines supported codecs and their RTP payload type mappings.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Codec identifier.
///
/// Represents the supported audio codecs for the SBC.
/// Per project requirements: Opus, G.711 (A-law/mu-law), G.722.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CodecId {
    /// Opus codec (RFC 6716).
    ///
    /// Modern wideband codec supporting 8-48 kHz sample rates.
    /// Dynamic payload type (typically 96-127).
    Opus,

    /// G.711 A-law (ITU-T G.711).
    ///
    /// 8 kHz narrowband codec, static payload type 8.
    /// Common in European telephony networks.
    G711Alaw,

    /// G.711 mu-law (ITU-T G.711).
    ///
    /// 8 kHz narrowband codec, static payload type 0.
    /// Common in North American telephony networks.
    G711Ulaw,

    /// G.722 (ITU-T G.722).
    ///
    /// 16 kHz wideband codec, static payload type 9.
    /// HD voice for legacy interoperability.
    G722,

    /// Telephone event (RFC 4733).
    ///
    /// DTMF tones, typically payload type 101.
    TelephoneEvent,
}

impl CodecId {
    /// Returns the static RTP payload type, if applicable.
    ///
    /// Dynamic codecs (Opus, telephone-event) return `None`.
    #[must_use]
    pub fn static_payload_type(&self) -> Option<u8> {
        match self {
            Self::G711Ulaw => Some(0),
            Self::G711Alaw => Some(8),
            Self::G722 => Some(9),
            Self::Opus | Self::TelephoneEvent => None,
        }
    }

    /// Returns the default dynamic payload type suggestion.
    ///
    /// For static codecs, returns the static type.
    #[must_use]
    pub fn suggested_payload_type(&self) -> u8 {
        match self {
            Self::G711Ulaw => 0,
            Self::G711Alaw => 8,
            Self::G722 => 9,
            Self::Opus => 111,
            Self::TelephoneEvent => 101,
        }
    }

    /// Returns the clock rate in Hz.
    ///
    /// Note: G.722 uses 8000 in RTP timestamps despite having 16kHz audio.
    #[must_use]
    pub fn clock_rate(&self) -> u32 {
        match self {
            Self::G711Ulaw | Self::G711Alaw | Self::TelephoneEvent | Self::G722 => 8000,
            Self::Opus => 48000,
        }
    }

    /// Returns the encoding name for SDP.
    #[must_use]
    pub fn encoding_name(&self) -> &'static str {
        match self {
            Self::G711Ulaw => "PCMU",
            Self::G711Alaw => "PCMA",
            Self::G722 => "G722",
            Self::Opus => "opus",
            Self::TelephoneEvent => "telephone-event",
        }
    }

    /// Returns the number of audio channels.
    #[must_use]
    pub fn channels(&self) -> u8 {
        match self {
            Self::Opus => 2, // Stereo capable
            _ => 1,
        }
    }

    /// Returns true if this is a wideband codec.
    #[must_use]
    pub fn is_wideband(&self) -> bool {
        matches!(self, Self::Opus | Self::G722)
    }

    /// Returns the SDP format parameters (fmtp), if any.
    #[must_use]
    pub fn format_parameters(&self) -> Option<&'static str> {
        match self {
            Self::Opus => Some("minptime=10;useinbandfec=1"),
            Self::TelephoneEvent => Some("0-16"),
            _ => None,
        }
    }
}

impl std::fmt::Display for CodecId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoding_name())
    }
}

/// Codec parameters for SDP negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodecParameters {
    /// Codec identifier.
    pub codec: CodecId,
    /// RTP payload type (0-127).
    pub payload_type: u8,
    /// Additional format parameters.
    pub fmtp: Option<String>,
}

impl CodecParameters {
    /// Creates codec parameters with default payload type.
    #[must_use]
    pub fn new(codec: CodecId) -> Self {
        Self {
            payload_type: codec.suggested_payload_type(),
            fmtp: codec.format_parameters().map(String::from),
            codec,
        }
    }

    /// Creates codec parameters with specified payload type.
    #[must_use]
    pub fn with_payload_type(codec: CodecId, payload_type: u8) -> Self {
        Self {
            codec,
            payload_type,
            fmtp: codec.format_parameters().map(String::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_payload_types() {
        assert_eq!(CodecId::G711Ulaw.static_payload_type(), Some(0));
        assert_eq!(CodecId::G711Alaw.static_payload_type(), Some(8));
        assert_eq!(CodecId::G722.static_payload_type(), Some(9));
        assert_eq!(CodecId::Opus.static_payload_type(), None);
    }

    #[test]
    fn test_clock_rates() {
        assert_eq!(CodecId::G711Ulaw.clock_rate(), 8000);
        assert_eq!(CodecId::G711Alaw.clock_rate(), 8000);
        assert_eq!(CodecId::G722.clock_rate(), 8000);
        assert_eq!(CodecId::Opus.clock_rate(), 48000);
    }

    #[test]
    fn test_wideband_detection() {
        assert!(CodecId::Opus.is_wideband());
        assert!(CodecId::G722.is_wideband());
        assert!(!CodecId::G711Ulaw.is_wideband());
        assert!(!CodecId::G711Alaw.is_wideband());
    }

    #[test]
    fn test_encoding_names() {
        assert_eq!(CodecId::G711Ulaw.encoding_name(), "PCMU");
        assert_eq!(CodecId::G711Alaw.encoding_name(), "PCMA");
        assert_eq!(CodecId::Opus.encoding_name(), "opus");
    }
}
