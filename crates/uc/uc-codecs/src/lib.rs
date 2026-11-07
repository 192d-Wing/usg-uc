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
//! - `opus-ffi`: Enable Opus FFI bindings (bundles and builds libopus via
//!   `opusic-c`; needs `cmake` on the build host)

#![forbid(unsafe_code)]
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
pub mod fmtp;
pub mod g711;
pub mod g722;
pub mod g722_adpcm;
pub mod opus;
#[cfg(feature = "opus-ffi")]
pub mod opus_ffi;
pub mod opus_toc;

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

    /// Rebuilds a lost frame from the in-band FEC data carried in the next
    /// packet (RFC 7587 §3.4, RFC 6716 §2.1.7 LBRR).
    ///
    /// `next_packet` is the payload of the packet that followed the lost one.
    /// `output` must be sized to exactly the lost frame's duration (samples
    /// per channel x channels); it is never grown or shrunk by the codec.
    ///
    /// The default implementation returns an error indicating FEC is not supported.
    fn decode_fec(&self, _next_packet: &[u8], _output: &mut [i16]) -> CodecResult<usize> {
        Err(CodecError::LossRecoveryFailed {
            reason: "FEC not supported for this codec",
        })
    }

    /// Generates codec-native packet loss concealment for one lost frame
    /// (e.g. Opus PLC, RFC 6716 §4.4). `output` must be sized to one ptime.
    ///
    /// The default implementation returns an error: callers fall back to a
    /// codec-independent concealer.
    fn conceal(&self, _output: &mut [i16]) -> CodecResult<usize> {
        Err(CodecError::LossRecoveryFailed {
            reason: "native PLC not supported for this codec",
        })
    }

    /// Returns true if this codec supports Forward Error Correction.
    fn supports_fec(&self) -> bool {
        false
    }

    /// Returns true if [`AudioCodec::conceal`] is implemented natively.
    ///
    /// Lets real-time callers pick a concealment path without paying for an
    /// error allocation on every lost frame.
    fn supports_plc(&self) -> bool {
        false
    }
}

/// RTP payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// Static payload type (RFC 3551 §6 assigned values, e.g. 0, 8, 9).
    Static(u8),
    /// Dynamic payload type (see [`payload_types::is_dynamic`]).
    Dynamic(u8),
}

impl PayloadType {
    /// Returns the numeric payload type value.
    pub fn value(&self) -> u8 {
        match self {
            Self::Static(v) | Self::Dynamic(v) => *v,
        }
    }

    /// Returns true if this payload type value lies in a range usable for
    /// dynamic mapping (see [`payload_types::is_dynamic`]).
    pub fn is_dynamic(&self) -> bool {
        payload_types::is_dynamic(self.value())
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
    /// Default telephone-event payload type (RFC 4733).
    pub const TELEPHONE_EVENT: u8 = 101;
    /// Default telephone-event/48000 payload type (RFC 4733, with Opus).
    pub const TELEPHONE_EVENT_48K: u8 = 110;

    /// Returns true if `pt` may be bound dynamically via `a=rtpmap`.
    ///
    /// RFC 3551 §6: 96-127 is the dynamic range, and the unassigned ranges
    /// 35-71 and 77-95 may also be used dynamically. 72-76 are excluded so
    /// RTP payload types never collide with RTCP packet types 200-204 when
    /// the marker bit is set (RFC 5761 §4).
    // POAM: POA&M-143 -- with rtcp-mux RFC 5761 §4 also advises avoiding
    // 64-95; those PTs are still adopted when a peer offers them.
    pub const fn is_dynamic(pt: u8) -> bool {
        matches!(pt, 35..=71 | 77..=95 | 96..=127)
    }

    /// Returns true if `pt` must never be used for RTP (RFC 5761 §4: 72-76
    /// collide with RTCP SR/RR/SDES/BYE/APP; >127 does not fit 7 bits).
    pub const fn is_reserved(pt: u8) -> bool {
        matches!(pt, 72..=76) || pt > 127
    }
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
    /// Peer's declared fmtp, set only on a negotiated result
    /// ([`CodecRegistry::negotiate`]). Rebuilt from parsed, range-checked
    /// values by [`fmtp::remote_params`]; use it to configure the encoder
    /// towards the peer (e.g. Opus `useinbandfec`, `maxplaybackrate`).
    /// It is never written into the answer SDP.
    pub remote_fmtp: Option<String>,
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
            remote_fmtp: None,
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

    /// Creates capability for RFC 4733 telephone-event (DTMF) at 8 kHz,
    /// advertising events 0-16 (DTMF digits plus flash).
    pub fn telephone_event(payload_type: u8) -> Self {
        Self::new("telephone-event", payload_type, 8000, 1).with_fmtp("0-16")
    }

    /// Creates capability for RFC 4733 telephone-event at 48 kHz, for use
    /// alongside Opus (RFC 4733 §2.1: the event clock rate SHOULD match the
    /// audio codec's), advertising events 0-16.
    pub fn telephone_event_48k(payload_type: u8) -> Self {
        Self::new("telephone-event", payload_type, 48000, 1).with_fmtp("0-16")
    }

    /// Returns true if this codec carries audio samples (as opposed to
    /// telephone-event or comfort noise), i.e. it can feed a transcoder.
    pub fn is_audio_payload(&self) -> bool {
        !(self.name.eq_ignore_ascii_case("telephone-event") || self.name.eq_ignore_ascii_case("CN"))
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
        registry.register(CodecCapability::telephone_event(
            payload_types::TELEPHONE_EVENT,
        ));
        registry.register(CodecCapability::telephone_event_48k(
            payload_types::TELEPHONE_EVENT_48K,
        ));
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

    /// Negotiates codecs with remote capabilities (RFC 3264 §6.1).
    ///
    /// Returns the intersection of local and remote codecs in local
    /// preference order. A pair matches on encoding name (case-insensitive),
    /// clock rate and channel count; Opus is always `opus/48000/2` on the
    /// wire (RFC 7587 §7), so its channel use is reconciled through the
    /// `stereo`/`sprop-stereo` fmtp instead. The answer:
    ///
    /// - adopts the remote payload type whenever it is not reserved
    ///   ([`payload_types::is_reserved`]), including unassigned PTs such as
    ///   34; the offer's `a=rtpmap` binding is authoritative,
    /// - carries the fmtp from [`fmtp::intersect_fmtp`] (our declarative
    ///   values; never remote fmtp text) and records the peer's parsed
    ///   values in [`CodecCapability::remote_fmtp`],
    /// - drops codecs whose fmtp cannot be reconciled (e.g. disjoint
    ///   telephone-event ranges).
    ///
    /// Remote entries are skipped if their PT is reserved (72-76, >127) or
    /// is bound to more than one distinct codec in the same offer.
    // RFC 3264 §6.1: the answer MUST use the offer's PT for each format.
    // NIST 800-53 Rev5: SI-10 (PT and fmtp from remote SDP are untrusted)
    pub fn negotiate(&self, remote: &[CodecCapability]) -> Vec<CodecCapability> {
        // NIST 800-53 Rev5: SC-5 (bound per-offer work)
        let remote = &remote[..remote.len().min(MAX_REMOTE_CODECS)];
        let mut result: Vec<CodecCapability> = Vec::new();

        for local in &self.capabilities {
            for (idx, remote_cap) in remote.iter().enumerate() {
                if !Self::caps_match(local, remote_cap) {
                    continue;
                }
                if payload_types::is_reserved(remote_cap.payload_type)
                    || Self::pt_conflicts(remote, idx)
                {
                    continue;
                }

                let fmtp = match fmtp::intersect_fmtp(
                    &local.name,
                    local.fmtp.as_deref(),
                    remote_cap.fmtp.as_deref(),
                ) {
                    fmtp::FmtpIntersection::Compatible(f) => f,
                    fmtp::FmtpIntersection::Incompatible => continue,
                };

                let mut negotiated = local.clone();
                negotiated.fmtp = fmtp;
                negotiated.remote_fmtp =
                    fmtp::remote_params(&local.name, remote_cap.fmtp.as_deref());
                // Reserved PTs were skipped above. A static PT bound to a
                // different codec by the offer (e.g. opus on 0) is adopted
                // as the offer's rtpmap says; the duplicate-PT checks keep
                // the answer to one format per PT.
                negotiated.payload_type = remote_cap.payload_type;
                // Never answer two formats on one PT.
                if result
                    .iter()
                    .any(|c| c.payload_type == negotiated.payload_type)
                {
                    continue;
                }
                result.push(negotiated);
                break;
            }
        }

        result
    }

    /// Name, clock rate and channel match (RFC 4566 §6: absent channels = 1).
    fn caps_match(local: &CodecCapability, remote: &CodecCapability) -> bool {
        if !local.name.eq_ignore_ascii_case(&remote.name) || local.clock_rate != remote.clock_rate {
            return false;
        }
        // RFC 7587 §7: Opus rtpmap channels MUST be 2; stereo is negotiated
        // through fmtp, so do not compare the rtpmap channel count.
        if local.name.eq_ignore_ascii_case("opus") {
            return true;
        }
        local.channels.max(1) == remote.channels.max(1)
    }

    /// True if the PT at `idx` is also bound to a different codec in `remote`.
    fn pt_conflicts(remote: &[CodecCapability], idx: usize) -> bool {
        let Some(me) = remote.get(idx) else {
            return true;
        };
        remote.iter().any(|other| {
            other.payload_type == me.payload_type
                && (!other.name.eq_ignore_ascii_case(&me.name)
                    || other.clock_rate != me.clock_rate
                    || other.channels.max(1) != me.channels.max(1))
        })
    }
}

/// Maximum remote codec entries considered per offer (SC-5).
pub const MAX_REMOTE_CODECS: usize = 64;

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

    #[test]
    fn test_is_dynamic_ranges() {
        for pt in [35u8, 71, 77, 95, 96, 127] {
            assert!(payload_types::is_dynamic(pt), "{pt}");
        }
        for pt in [0u8, 8, 9, 34, 72, 76, 128, 255] {
            assert!(!payload_types::is_dynamic(pt), "{pt}");
        }
        assert!(PayloadType::Dynamic(77).is_dynamic());
        assert!(!PayloadType::Dynamic(72).is_dynamic());
    }

    #[test]
    fn test_negotiate_channel_mismatch() {
        let mut local = CodecRegistry::new();
        local.register(CodecCapability::new("L16", 120, 16000, 1));
        let remote = vec![CodecCapability::new("L16", 120, 16000, 2)];
        assert_eq!(local.negotiate(&remote), [] as [CodecCapability; 0]);
        // Channels 0 (absent) is treated as 1.
        let remote = vec![CodecCapability::new("L16", 120, 16000, 0)];
        assert_eq!(local.negotiate(&remote).len(), 1);
    }

    #[test]
    fn test_negotiate_opus_fmtp_intersection() {
        let mut local = CodecRegistry::new();
        local.register(CodecCapability::opus(111).with_fmtp("useinbandfec=1;stereo=1"));
        let remote =
            vec![CodecCapability::new("opus", 109, 48000, 2).with_fmtp("useinbandfec=0;stereo=0")];
        let n = local.negotiate(&remote);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].payload_type, 109);
        // RFC 7587 §6.1: answer declares our values; peer's are kept apart.
        assert_eq!(n[0].fmtp.as_deref(), Some("useinbandfec=1;stereo=1"));
        assert_eq!(n[0].remote_fmtp.as_deref(), Some("useinbandfec=0;stereo=0"));
    }

    #[test]
    fn test_negotiate_opus_keeps_local_fec_when_remote_silent() {
        let local = CodecRegistry::with_defaults();
        let remote = vec![CodecCapability::new("opus", 96, 48000, 2).with_fmtp("minptime=20")];
        let n = local.negotiate(&remote);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].fmtp.as_deref(), Some("minptime=20;useinbandfec=1"));
        assert_eq!(n[0].remote_fmtp.as_deref(), Some("minptime=20"));
        // No remote fmtp at all.
        let n = local.negotiate(&[CodecCapability::new("opus", 96, 48000, 2)]);
        assert_eq!(n[0].fmtp.as_deref(), Some("minptime=10;useinbandfec=1"));
        assert_eq!(n[0].remote_fmtp, None);
    }

    #[test]
    fn test_negotiate_adopts_unassigned_pt() {
        let local = CodecRegistry::with_defaults();
        let n = local.negotiate(&[CodecCapability::opus(34)]);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].payload_type, 34);
        // Static PT rebound by the offer: adopted, one format per PT.
        let n = local.negotiate(&[CodecCapability::opus(0)]);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].payload_type, 0);
        assert_eq!(n[0].name, "opus");
    }

    #[test]
    fn test_negotiate_telephone_event_48k() {
        let local = CodecRegistry::with_defaults();
        let remote = vec![
            CodecCapability::opus(111),
            CodecCapability::telephone_event_48k(126).with_fmtp("0-15"),
        ];
        let n = local.negotiate(&remote);
        let te = n.iter().find(|c| c.name == "telephone-event").unwrap();
        assert_eq!(te.clock_rate, 48000);
        assert_eq!(te.payload_type, 126);
        assert_eq!(te.fmtp.as_deref(), Some("0-15"));
        assert_eq!(n.iter().filter(|c| c.name == "telephone-event").count(), 1);
        // Both rates offered: both answered on their own PTs.
        let remote = vec![
            CodecCapability::pcmu(),
            CodecCapability::telephone_event(101),
            CodecCapability::telephone_event_48k(110),
        ];
        let n = local.negotiate(&remote);
        assert_eq!(n.iter().filter(|c| c.name == "telephone-event").count(), 2);
    }

    #[test]
    fn test_negotiate_adopts_remote_dynamic_pts() {
        for pt in [35u8, 77, 120] {
            let local = CodecRegistry::with_defaults();
            let n = local.negotiate(&[CodecCapability::opus(pt)]);
            assert_eq!(n.len(), 1);
            assert_eq!(n[0].payload_type, pt);
        }
    }

    #[test]
    fn test_negotiate_rejects_rtcp_colliding_pt() {
        let local = CodecRegistry::with_defaults();
        assert_eq!(
            local.negotiate(&[CodecCapability::opus(72)]),
            [] as [CodecCapability; 0]
        );
        assert_eq!(
            local.negotiate(&[CodecCapability::opus(200)]),
            [] as [CodecCapability; 0]
        );
    }

    #[test]
    fn test_negotiate_keeps_static_pt() {
        let local = CodecRegistry::with_defaults();
        let n = local.negotiate(&[CodecCapability::pcmu()]);
        assert_eq!(n[0].payload_type, 0);
    }

    #[test]
    fn test_negotiate_rejects_duplicate_pt_bindings() {
        let local = CodecRegistry::with_defaults();
        let remote = vec![
            CodecCapability::opus(100),
            CodecCapability::telephone_event(100),
            CodecCapability::pcmu(),
        ];
        let n = local.negotiate(&remote);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].name, "PCMU");
    }

    #[test]
    fn test_negotiate_telephone_event() {
        let local = CodecRegistry::with_defaults();
        assert!(local.find_by_name("telephone-event").is_some());

        let remote = vec![
            CodecCapability::pcmu(),
            CodecCapability::telephone_event(96).with_fmtp("0-15"),
        ];
        let n = local.negotiate(&remote);
        let te = n.iter().find(|c| c.name == "telephone-event").unwrap();
        assert_eq!(te.payload_type, 96);
        assert_eq!(te.fmtp.as_deref(), Some("0-15"));
        assert!(!te.is_audio_payload());
        assert!(n[0].is_audio_payload());

        // Disjoint event ranges drop telephone-event, keep audio.
        let remote = vec![
            CodecCapability::pcmu(),
            CodecCapability::telephone_event(96).with_fmtp("32-40"),
        ];
        let n = local.negotiate(&remote);
        assert!(n.iter().all(|c| c.name != "telephone-event"));
    }

    #[test]
    fn test_negotiate_strips_injected_fmtp() {
        let local = CodecRegistry::with_defaults();
        // CRLF in remote fmtp: the codec is refused outright.
        let remote = vec![CodecCapability::opus(96).with_fmtp("useinbandfec=1\r\na=evil")];
        assert_eq!(local.negotiate(&remote), [] as [CodecCapability; 0]);

        // Unknown keys are dropped; the answer is rebuilt from known values.
        let remote = vec![CodecCapability::opus(96).with_fmtp("useinbandfec=1;a=evil")];
        let n = local.negotiate(&remote);
        assert_eq!(n[0].fmtp.as_deref(), Some("minptime=10;useinbandfec=1"));
    }

    // QA: PT 72-76 and duplicate PT bindings (RFC 5761 §4, RFC 3264).
    #[test]
    fn test_qa_negotiate_rejects_all_rtcp_colliding_pts() {
        let local = CodecRegistry::with_defaults();
        for pt in 72u8..=76 {
            assert!(!payload_types::is_dynamic(pt));
            assert!(
                local.negotiate(&[CodecCapability::opus(pt)]).is_empty(),
                "{pt}"
            );
            assert!(
                local
                    .negotiate(&[CodecCapability::telephone_event(pt)])
                    .is_empty(),
                "{pt}"
            );
        }
        for pt in [71u8, 77] {
            assert_eq!(
                local.negotiate(&[CodecCapability::opus(pt)]).len(),
                1,
                "{pt}"
            );
        }
    }

    #[test]
    fn test_qa_negotiate_duplicate_pt_variants() {
        let local = CodecRegistry::with_defaults();
        // Same PT, same codec repeated: not a conflict.
        let n = local.negotiate(&[CodecCapability::opus(111), CodecCapability::opus(111)]);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].payload_type, 111);
        // Same name, different clock rate on one PT: conflict, both dropped.
        let remote = vec![
            CodecCapability::telephone_event(101),
            CodecCapability::new("telephone-event", 101, 48000, 1),
            CodecCapability::pcma(),
        ];
        let n = local.negotiate(&remote);
        assert!(n.iter().all(|c| c.payload_type != 101), "{n:?}");
        assert!(n.iter().any(|c| c.name == "PCMA"));
        // Remote reuses a static PT for a dynamic codec: neither is answered on 0
        // with two formats.
        let remote = vec![CodecCapability::pcmu(), CodecCapability::opus(0)];
        let n = local.negotiate(&remote);
        assert!(n.is_empty(), "{n:?}");
    }
}
