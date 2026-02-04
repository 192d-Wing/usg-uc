//! Audio codec support including Opus, G.711, and G.722.
//!
//! This crate provides audio encoding and decoding functionality for
//! common VoIP codecs used in real-time communications.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//!
//! ## Supported Codecs
//!
//! - **Opus**: Modern high-quality codec (RFC 6716)
//! - **G.711**: PCM a-law and mu-law (ITU-T G.711)
//! - **G.722**: Wideband codec (ITU-T G.722)
//!
//! ## Features
//!
//! - Codec negotiation and selection
//! - Sample rate conversion
//! - Payload type mapping
//!
//! ## Note
//!
//! This crate provides codec abstractions and pure-Rust implementations
//! for G.711 and G.722. For production Opus support, enable the `opus-ffi`
//! feature which provides FFI bindings to libopus (documented exception
//! to pure-Rust policy).
//!
//! ## Feature Flags
//!
//! - `opus-ffi`: Enable Opus FFI bindings (requires libopus installed)

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// Clippy style preferences for codec implementation code
#![allow(clippy::unreadable_literal)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::use_self)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

pub mod error;
pub mod g711;
pub mod g722;
pub mod g722_adpcm;
pub mod opus;
#[cfg(feature = "opus-ffi")]
pub mod opus_ffi;

pub use error::{CodecError, CodecResult};
pub use g711::{G711Alaw, G711Ulaw};
pub use g722::G722Codec;
pub use opus::OpusCodec;
#[cfg(feature = "opus-ffi")]
pub use opus_ffi::{FfiOpusCodec, FfiOpusDecoder, FfiOpusEncoder};

/// Audio codec trait.
pub trait AudioCodec: Send + Sync {
    /// Returns the codec name.
    fn name(&self) -> &'static str;

    /// Returns the RTP payload type (static or dynamic).
    fn payload_type(&self) -> PayloadType;

    /// Returns the clock rate in Hz.
    fn clock_rate(&self) -> u32;

    /// Returns the number of audio channels.
    fn channels(&self) -> u8;

    /// Returns the frame duration in milliseconds.
    fn frame_duration_ms(&self) -> u32;

    /// Returns samples per frame.
    fn samples_per_frame(&self) -> usize {
        (self.clock_rate() * self.frame_duration_ms() / 1000) as usize
    }

    /// Encodes PCM samples to codec format.
    fn encode(&self, pcm: &[i16], output: &mut [u8]) -> CodecResult<usize>;

    /// Decodes codec format to PCM samples.
    fn decode(&self, encoded: &[u8], output: &mut [i16]) -> CodecResult<usize>;
}

/// RTP payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// Static payload type (0-95).
    Static(u8),
    /// Dynamic payload type (96-127).
    Dynamic(u8),
}

impl PayloadType {
    /// Returns the numeric payload type value.
    pub fn value(&self) -> u8 {
        match self {
            Self::Static(v) | Self::Dynamic(v) => *v,
        }
    }

    /// Returns true if this is a dynamic payload type.
    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

/// Standard payload types per RFC 3551.
pub mod payload_types {
    /// G.711 mu-law (PCMU).
    pub const PCMU: u8 = 0;
    /// G.711 a-law (PCMA).
    pub const PCMA: u8 = 8;
    /// G.722.
    pub const G722: u8 = 9;
    /// Dynamic payload type range start.
    pub const DYNAMIC_START: u8 = 96;
    /// Dynamic payload type range end.
    pub const DYNAMIC_END: u8 = 127;
}

/// Codec capability for SDP negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecCapability {
    /// Codec name (e.g., "opus", "PCMU").
    pub name: String,
    /// Payload type.
    pub payload_type: u8,
    /// Clock rate in Hz.
    pub clock_rate: u32,
    /// Number of channels.
    pub channels: u8,
    /// Format-specific parameters.
    pub fmtp: Option<String>,
}

impl CodecCapability {
    /// Creates a new codec capability.
    pub fn new(name: &str, payload_type: u8, clock_rate: u32, channels: u8) -> Self {
        Self {
            name: name.to_string(),
            payload_type,
            clock_rate,
            channels,
            fmtp: None,
        }
    }

    /// Sets format parameters.
    #[must_use]
    pub fn with_fmtp(mut self, fmtp: &str) -> Self {
        self.fmtp = Some(fmtp.to_string());
        self
    }

    /// Creates capability for G.711 mu-law.
    pub fn pcmu() -> Self {
        Self::new("PCMU", payload_types::PCMU, 8000, 1)
    }

    /// Creates capability for G.711 a-law.
    pub fn pcma() -> Self {
        Self::new("PCMA", payload_types::PCMA, 8000, 1)
    }

    /// Creates capability for G.722.
    pub fn g722() -> Self {
        Self::new("G722", payload_types::G722, 8000, 1)
    }

    /// Creates capability for Opus.
    pub fn opus(payload_type: u8) -> Self {
        Self::new("opus", payload_type, 48000, 2).with_fmtp("minptime=10;useinbandfec=1")
    }

    /// Formats as SDP rtpmap attribute.
    pub fn to_rtpmap(&self) -> String {
        if self.channels > 1 {
            format!(
                "a=rtpmap:{} {}/{}/{}",
                self.payload_type, self.name, self.clock_rate, self.channels
            )
        } else {
            format!(
                "a=rtpmap:{} {}/{}",
                self.payload_type, self.name, self.clock_rate
            )
        }
    }

    /// Formats as SDP fmtp attribute if present.
    pub fn to_fmtp(&self) -> Option<String> {
        self.fmtp
            .as_ref()
            .map(|fmtp| format!("a=fmtp:{} {}", self.payload_type, fmtp))
    }
}

/// Codec registry for managing available codecs.
#[derive(Debug, Default)]
pub struct CodecRegistry {
    /// Registered codec capabilities.
    capabilities: Vec<CodecCapability>,
}

impl CodecRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry with default codecs.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(CodecCapability::pcmu());
        registry.register(CodecCapability::pcma());
        registry.register(CodecCapability::g722());
        registry.register(CodecCapability::opus(111));
        registry
    }

    /// Registers a codec capability.
    pub fn register(&mut self, capability: CodecCapability) {
        self.capabilities.push(capability);
    }

    /// Returns all registered capabilities.
    pub fn capabilities(&self) -> &[CodecCapability] {
        &self.capabilities
    }

    /// Finds a capability by name.
    pub fn find_by_name(&self, name: &str) -> Option<&CodecCapability> {
        self.capabilities
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Finds a capability by payload type.
    pub fn find_by_payload_type(&self, pt: u8) -> Option<&CodecCapability> {
        self.capabilities.iter().find(|c| c.payload_type == pt)
    }

    /// Negotiates codecs with remote capabilities.
    ///
    /// Returns the intersection of local and remote codecs in preference order.
    pub fn negotiate(&self, remote: &[CodecCapability]) -> Vec<CodecCapability> {
        let mut result = Vec::new();

        for local in &self.capabilities {
            for remote_cap in remote {
                if local.name.eq_ignore_ascii_case(&remote_cap.name)
                    && local.clock_rate == remote_cap.clock_rate
                {
                    // Use remote payload type for dynamic codecs
                    let mut negotiated = local.clone();
                    if remote_cap.payload_type >= payload_types::DYNAMIC_START {
                        negotiated.payload_type = remote_cap.payload_type;
                    }
                    result.push(negotiated);
                    break;
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_type() {
        let static_pt = PayloadType::Static(0);
        assert_eq!(static_pt.value(), 0);
        assert!(!static_pt.is_dynamic());

        let dynamic_pt = PayloadType::Dynamic(111);
        assert_eq!(dynamic_pt.value(), 111);
        assert!(dynamic_pt.is_dynamic());
    }

    #[test]
    fn test_codec_capability() {
        let cap = CodecCapability::pcmu();
        assert_eq!(cap.name, "PCMU");
        assert_eq!(cap.payload_type, 0);
        assert_eq!(cap.clock_rate, 8000);

        let rtpmap = cap.to_rtpmap();
        assert!(rtpmap.contains("PCMU/8000"));
    }

    #[test]
    fn test_opus_capability() {
        let cap = CodecCapability::opus(111);
        assert_eq!(cap.name, "opus");
        assert_eq!(cap.clock_rate, 48000);
        assert_eq!(cap.channels, 2);
        assert!(cap.fmtp.is_some());

        let rtpmap = cap.to_rtpmap();
        assert!(rtpmap.contains("opus/48000/2"));
    }

    #[test]
    fn test_codec_registry() {
        let registry = CodecRegistry::with_defaults();

        assert!(registry.find_by_name("PCMU").is_some());
        assert!(registry.find_by_name("pcmu").is_some());
        assert!(registry.find_by_payload_type(0).is_some());
        assert!(registry.find_by_payload_type(8).is_some());
    }

    #[test]
    fn test_codec_negotiation() {
        let local = CodecRegistry::with_defaults();

        let remote = vec![CodecCapability::opus(96), CodecCapability::pcmu()];

        let negotiated = local.negotiate(&remote);

        // Should have PCMU and Opus
        assert_eq!(negotiated.len(), 2);

        // PCMU should be first (local preference)
        assert_eq!(negotiated[0].name, "PCMU");

        // Opus should use remote payload type
        let opus = negotiated.iter().find(|c| c.name == "opus");
        assert!(opus.is_some());
        assert_eq!(opus.unwrap().payload_type, 96);
    }
}
