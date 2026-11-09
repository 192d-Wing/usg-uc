//! T.38 fax switchover policy for the B2BUA (`[media.t38]`).
//!
//! Pure decisions used by `sip_stack`: classify an SDP offer (which m-line
//! the relay anchors, and whether it is a T.38 `m=image` stream the SBC may
//! carry), check the far side's answer, and clamp T.38 capacity attributes.
//! The relay carries UDPTL opaquely on the call's existing anchored ports;
//! it never decodes UDPTL/IFP (POA&M-290).
//!
//! ## NIST 800-53 Rev5
//!
//! - **CM-7**: fail-closed (`enabled = false` refuses image with 488)
//! - **SC-5**: `T38MaxBitRate` / `T38FaxMaxDatagram` / `T38FaxMaxBuffer` are
//!   clamped to the configured caps before forwarding
//! - **SI-10**: SDP and T.38 attributes are parsed by the total `proto-sdp`
//!   parser; malformed values are refused
//! - **SC-8**: UDPTL is cleartext; gated by `allow_cleartext` and refused on
//!   DTLS-SRTP terminated legs (POA&M-291)
//!
//! ## RFC / ITU-T
//!
//! - RFC 3362 (`image/t38`, `udptl`), RFC 4612, ITU-T T.38 Annex D
//! - RFC 3264 §6, §8: m-lines are never removed; refused streams get port 0
//! - RFC 3261 §14.1: a failed re-INVITE leaves the session unchanged

use proto_b2bua::{
    AnchoredStream, StreamKind, StreamPreference, has_image_stream, rewrite_t38_attributes,
    select_anchored_stream, stream_at, t38_params_at,
};
use proto_sdp::{T38UdpEc, TransportProtocol};
use sbc_config::{T38Config, T38EcMode};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use uc_audit::event::{
    MediaSwitchover, SwitchoverMediaKind, SwitchoverOriginator, SwitchoverOutcome,
    SwitchoverReason, SwitchoverTransport,
};

/// What a call's anchored stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallMediaKind {
    /// RTP audio (and any non-image stream).
    #[default]
    Audio,
    /// T.38 fax over UDPTL.
    Image,
}

impl CallMediaKind {
    const fn of(kind: StreamKind) -> Self {
        match kind {
            StreamKind::Image => Self::Image,
            StreamKind::Audio | StreamKind::Other => Self::Audio,
        }
    }

    /// Audit representation.
    pub const fn audit(self) -> SwitchoverMediaKind {
        match self {
            Self::Audio => SwitchoverMediaKind::Audio,
            Self::Image => SwitchoverMediaKind::Image,
        }
    }

    /// CDR representation (schema v3 `media_kinds`).
    pub const fn cdr(self) -> uc_cdr::MediaKindTag {
        match self {
            Self::Audio => uc_cdr::MediaKindTag::Audio,
            Self::Image => uc_cdr::MediaKindTag::Image,
        }
    }

    /// Media-pipeline representation.
    pub const fn pipeline(self) -> sbc_media_core::media_pipeline::MediaKind {
        match self {
            Self::Audio => sbc_media_core::media_pipeline::MediaKind::Audio,
            Self::Image => sbc_media_core::media_pipeline::MediaKind::Image,
        }
    }
}

/// How a call's relay handles media security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelaySecurity {
    /// Opaque forwarding (plain RTP or SRTP pass-through).
    #[default]
    Opaque,
    /// DTLS-SRTP terminated on both legs; UDPTL is refused (POA&M-291).
    DtlsTerminated,
}

/// An offer (or answer) the T.38 policy accepted.
#[derive(Debug, Clone)]
pub struct Classified {
    /// The anchored m-line.
    pub stream: AnchoredStream,
    /// Kind of the anchored stream.
    pub kind: CallMediaKind,
    /// The SDP with T.38 attributes clamped (unchanged for audio).
    pub sdp: String,
    /// `T38MaxBitRate` after clamping, for the audit record.
    pub max_bit_rate: Option<u32>,
}

const fn ec_mode(ec: T38UdpEc) -> T38EcMode {
    match ec {
        T38UdpEc::Redundancy => T38EcMode::Redundancy,
        T38UdpEc::Fec => T38EcMode::Fec,
        T38UdpEc::NoEc => T38EcMode::NoEc,
    }
}

/// Validates and clamps the T.38 image m-line `stream` of `sdp`.
fn check_image(
    sdp: &str,
    stream: &AnchoredStream,
    cfg: &T38Config,
) -> Result<(String, Option<u32>), SwitchoverReason> {
    // RFC 3362: only `udptl` is relayed; TCP / TPKT is unsupported (POA&M-291).
    if stream.proto != TransportProtocol::Udptl {
        return Err(SwitchoverReason::UnsupportedTransport);
    }
    let mut params = t38_params_at(sdp, stream.index).ok_or(SwitchoverReason::MalformedT38Sdp)?;
    // ITU-T T.38 Annex D: an absent T38FaxUdpEC means t38UDPNoEC.
    if !cfg.allowed_ec.contains(&ec_mode(params.effective_udp_ec())) {
        return Err(SwitchoverReason::EcNotAllowed);
    }
    // NIST 800-53 Rev5: SC-5 - only ever lowers values, which keeps an answer
    // within the offer (T.38 Annex D).
    let sdp = if params.clamp(cfg.max_bit_rate, cfg.max_datagram, cfg.max_buffer) {
        rewrite_t38_attributes(sdp, stream.index, &params)
    } else {
        sdp.to_string()
    };
    Ok((sdp, params.max_bit_rate))
}

/// Classifies an offer.
///
/// Returns `Ok(None)` when no image stream is involved and the call is in
/// audio mode: the caller keeps its legacy (pre-T.38) handling unchanged.
/// `Err(reason)` means refuse locally with 488. `initial` selects the
/// initial-INVITE preference (audio first; image-only SDP selects image);
/// re-INVITEs prefer an active image m-line.
pub fn classify_offer(
    sdp: &str,
    current: CallMediaKind,
    cfg: &T38Config,
    terminated: bool,
    initial: bool,
) -> Result<Option<Classified>, SwitchoverReason> {
    if current == CallMediaKind::Audio && !has_image_stream(sdp) {
        return Ok(None);
    }
    let prefer = if initial {
        StreamPreference::Audio
    } else {
        StreamPreference::Image
    };
    let stream = select_anchored_stream(sdp, prefer).ok_or(SwitchoverReason::MalformedT38Sdp)?;
    let kind = CallMediaKind::of(stream.kind);
    if kind == CallMediaKind::Audio {
        return Ok(Some(Classified {
            stream,
            kind,
            sdp: sdp.to_string(),
            max_bit_rate: None,
        }));
    }
    // NIST 800-53 Rev5: CM-7 - fail closed.
    if !cfg.enabled {
        return Err(SwitchoverReason::T38Disabled);
    }
    if stream.proto != TransportProtocol::Udptl {
        return Err(SwitchoverReason::UnsupportedTransport);
    }
    // NIST 800-53 Rev5: SC-8 - no SRTP -> cleartext downgrade on a
    // DTLS-terminated call (POA&M-291).
    if terminated {
        return Err(SwitchoverReason::SrtpTerminate);
    }
    let (sdp, max_bit_rate) = check_image(sdp, &stream, cfg)?;
    Ok(Some(Classified {
        stream,
        kind,
        sdp,
        max_bit_rate,
    }))
}

/// The far side's answer to a classified offer.
#[derive(Debug)]
pub enum AnswerCheck {
    /// The offered stream is active and of the offered kind.
    Accepted(Classified),
    /// The stream was declined (port 0) or is of another kind; the relay
    /// keeps its previous state.
    Declined,
    /// The answer accepted an image stream the SBC cannot anchor; the
    /// dialog is committed, so the call is torn down.
    Failed(SwitchoverReason),
}

/// Checks the answer's m-line `index` against the offered `kind`.
// POAM: POA&M-294 - the answer is clamped to the caps, not checked against
// the offer per T.38 Annex D (version downgrade, EC fallback); no CDR fax
// flag; `sip.fax` (RFC 6913) is passed through uninterpreted.
pub fn check_answer(sdp: &str, index: usize, kind: CallMediaKind, cfg: &T38Config) -> AnswerCheck {
    let Some(stream) = stream_at(sdp, index) else {
        // Unparseable answer: only fatal when an image stream was offered.
        return if kind == CallMediaKind::Image {
            AnswerCheck::Failed(SwitchoverReason::MalformedT38Sdp)
        } else {
            AnswerCheck::Declined
        };
    };
    if stream.port == 0 || CallMediaKind::of(stream.kind) != kind {
        return AnswerCheck::Declined;
    }
    if kind == CallMediaKind::Audio {
        return AnswerCheck::Accepted(Classified {
            stream,
            kind,
            sdp: sdp.to_string(),
            max_bit_rate: None,
        });
    }
    match check_image(sdp, &stream, cfg) {
        Ok((sdp, max_bit_rate)) => AnswerCheck::Accepted(Classified {
            stream,
            kind,
            sdp,
            max_bit_rate,
        }),
        Err(reason) => AnswerCheck::Failed(reason),
    }
}

/// Audit policy string for an INVITE refused by the T.38 policy.
pub const fn reason_policy(reason: SwitchoverReason) -> &'static str {
    match reason {
        SwitchoverReason::T38Disabled => "t38:t38_disabled",
        SwitchoverReason::SrtpTerminate => "t38:srtp_terminate",
        SwitchoverReason::UnsupportedTransport => "t38:unsupported_transport",
        SwitchoverReason::MalformedT38Sdp => "t38:malformed_t38_sdp",
        SwitchoverReason::EcNotAllowed => "t38:ec_not_allowed",
        SwitchoverReason::Remote488 => "t38:remote_488",
        SwitchoverReason::RemoteDialogLost => "t38:remote_dialog_lost",
        SwitchoverReason::RemoteRejected => "t38:remote_rejected",
        SwitchoverReason::RemotePort0 => "t38:remote_port0",
        SwitchoverReason::RelayUpdateFailed => "t38:relay_update_failed",
    }
}

/// `Warning` header value for a local 488 (RFC 3261 §20.43). The code
/// tells the offerer whether to retry: 304 "Media type not available" only
/// when T.38 is disabled; 305 "Incompatible media format" when image/t38 is
/// available but the transport, EC mode or leg security is not; 399 for a
/// malformed T.38 SDP (and, defensively, any reason not raised locally).
pub fn warning_for(reason: SwitchoverReason, host: &str) -> String {
    match reason {
        SwitchoverReason::T38Disabled => format!("304 {host} \"Media type not available\""),
        SwitchoverReason::UnsupportedTransport
        | SwitchoverReason::EcNotAllowed
        | SwitchoverReason::SrtpTerminate => {
            format!("305 {host} \"Incompatible media format\"")
        }
        SwitchoverReason::MalformedT38Sdp
        | SwitchoverReason::Remote488
        | SwitchoverReason::RemoteDialogLost
        | SwitchoverReason::RemoteRejected
        | SwitchoverReason::RemotePort0
        | SwitchoverReason::RelayUpdateFailed => format!("399 {host} \"Malformed T.38 SDP\""),
    }
}

/// Builds the `media_switchover` audit event. Every field is SBC-chosen.
pub fn audit_event(
    session: &str,
    from: CallMediaKind,
    to: CallMediaKind,
    from_a_leg: bool,
    outcome: SwitchoverOutcome,
    reason: Option<SwitchoverReason>,
    max_bit_rate: Option<u32>,
) -> uc_audit::AuditEvent {
    uc_audit::AuditEvent::MediaSwitchover(MediaSwitchover {
        call_id: session.to_string(),
        from_kind: from.audit(),
        to_kind: to.audit(),
        originator: if from_a_leg {
            SwitchoverOriginator::ALeg
        } else {
            SwitchoverOriginator::BLeg
        },
        outcome,
        reason,
        transport: (to == CallMediaKind::Image).then_some(SwitchoverTransport::Udptl),
        max_bit_rate,
        remote_media: None,
    })
}

/// Sets the SBC-validated new remote media address on a `media_switchover`
/// event (NIST 800-53 Rev5: AU-3 "where").
#[must_use]
pub fn with_remote_media(
    mut event: uc_audit::AuditEvent,
    addr: Option<std::net::SocketAddr>,
) -> uc_audit::AuditEvent {
    if let uc_audit::AuditEvent::MediaSwitchover(ref mut m) = event {
        m.remote_media = addr;
    }
    event
}

/// Switchover counter names, `[direction][outcome]` (bounded: 8 series).
/// Flattened like the daemon's other counters (one gauge per outcome).
///
/// ## NIST 800-53 Rev5: SI-4 (System Monitoring)
pub const SWITCHOVER_METRIC_NAMES: [[&str; 4]; 2] = [
    [
        "sbc_t38_switchover_to_t38_accepted_total",
        "sbc_t38_switchover_to_t38_rejected_local_total",
        "sbc_t38_switchover_to_t38_rejected_remote_total",
        "sbc_t38_switchover_to_t38_failed_total",
    ],
    [
        "sbc_t38_switchover_to_audio_accepted_total",
        "sbc_t38_switchover_to_audio_rejected_local_total",
        "sbc_t38_switchover_to_audio_rejected_remote_total",
        "sbc_t38_switchover_to_audio_failed_total",
    ],
];
/// Gauge: calls whose anchored stream is currently T.38.
pub const METRIC_ACTIVE_CALLS: &str = "sbc_t38_active_calls";
/// Gauge mirroring the UDPTL datagrams the local relay forwarded.
pub const METRIC_UDPTL_RELAYED: &str = "sbc_udptl_packets_relayed_total";
/// Help text for the T.38 metrics.
pub const METRIC_HELP: &str = "T.38 fax switchovers (audio <-> image), active T.38 calls and \
                               UDPTL datagrams relayed";

/// T.38 switchover counters, exported as gauges by the metrics endpoint.
#[derive(Debug, Default)]
pub struct T38Counters {
    switchovers: [[AtomicU64; 4]; 2],
    active: AtomicI64,
}

const fn outcome_index(outcome: SwitchoverOutcome) -> usize {
    match outcome {
        SwitchoverOutcome::Accepted => 0,
        SwitchoverOutcome::RejectedLocal => 1,
        SwitchoverOutcome::RejectedRemote => 2,
        SwitchoverOutcome::Failed => 3,
    }
}

impl T38Counters {
    /// Counts one switchover toward `to`.
    pub fn record(&self, to: CallMediaKind, outcome: SwitchoverOutcome) {
        let dir = usize::from(to == CallMediaKind::Audio);
        if let Some(c) = self
            .switchovers
            .get(dir)
            .and_then(|d| d.get(outcome_index(outcome)))
        {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A call entered image mode.
    pub fn image_started(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// A call left image mode (switch back or teardown).
    pub fn image_ended(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Calls currently in image mode.
    pub fn active(&self) -> i64 {
        self.active.load(Ordering::Relaxed)
    }

    /// `(name, value)` for every T.38 metric.
    pub fn metric_values(&self) -> Vec<(&'static str, u64)> {
        let mut out = Vec::with_capacity(10);
        for (names, counters) in SWITCHOVER_METRIC_NAMES.iter().zip(&self.switchovers) {
            for (name, c) in names.iter().zip(counters) {
                out.push((*name, c.load(Ordering::Relaxed)));
            }
        }
        out.push((
            METRIC_ACTIVE_CALLS,
            u64::try_from(self.active()).unwrap_or(0),
        ));
        out.push((
            METRIC_UDPTL_RELAYED,
            sbc_media_core::media_pipeline::udptl_packets_relayed(),
        ));
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sdp(mlines: &str) -> String {
        format!("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{mlines}")
    }

    fn enabled() -> T38Config {
        T38Config {
            enabled: true,
            allow_cleartext: true,
            ..T38Config::default()
        }
    }

    const IMAGE: &str = "m=audio 0 RTP/AVP 0\r\nm=image 5000 udptl t38\r\n\
                         a=T38FaxVersion:0\r\na=T38MaxBitRate:33600\r\n\
                         a=T38FaxMaxDatagram:9000\r\na=T38FaxUdpEC:t38UDPRedundancy\r\n";

    #[test]
    fn audio_only_is_legacy() {
        let s = sdp("m=audio 4000 RTP/AVP 0\r\n");
        assert!(
            classify_offer(&s, CallMediaKind::Audio, &enabled(), false, false)
                .unwrap()
                .is_none()
        );
        // Back to audio from image mode is classified.
        let c = classify_offer(&s, CallMediaKind::Image, &enabled(), false, false)
            .unwrap()
            .unwrap();
        assert_eq!(c.kind, CallMediaKind::Audio);
    }

    #[test]
    fn local_reject_reasons() {
        let s = sdp(IMAGE);
        let off = T38Config::default();
        assert_eq!(
            classify_offer(&s, CallMediaKind::Audio, &off, false, false).unwrap_err(),
            SwitchoverReason::T38Disabled
        );
        assert_eq!(
            classify_offer(&s, CallMediaKind::Audio, &enabled(), true, false).unwrap_err(),
            SwitchoverReason::SrtpTerminate
        );
        let tcp = sdp("m=image 5000 TCP t38\r\n");
        assert_eq!(
            classify_offer(&tcp, CallMediaKind::Audio, &enabled(), false, false).unwrap_err(),
            SwitchoverReason::UnsupportedTransport
        );
        let bad = sdp("m=image 5000 udptl t38\r\na=T38FaxVersion:9\r\n");
        assert_eq!(
            classify_offer(&bad, CallMediaKind::Audio, &enabled(), false, false).unwrap_err(),
            SwitchoverReason::MalformedT38Sdp
        );
        let mut no_ec = enabled();
        no_ec.allowed_ec = vec![T38EcMode::Fec];
        assert_eq!(
            classify_offer(&s, CallMediaKind::Audio, &no_ec, false, false).unwrap_err(),
            SwitchoverReason::EcNotAllowed
        );
        // Absent T38FaxUdpEC means NoEC.
        let absent = sdp("m=image 5000 udptl t38\r\n");
        assert_eq!(
            classify_offer(&absent, CallMediaKind::Audio, &no_ec, false, false).unwrap_err(),
            SwitchoverReason::EcNotAllowed
        );
    }

    #[test]
    fn accepted_offer_is_clamped() {
        let c = classify_offer(&sdp(IMAGE), CallMediaKind::Audio, &enabled(), false, false)
            .unwrap()
            .unwrap();
        assert_eq!((c.kind, c.stream.index), (CallMediaKind::Image, 1));
        assert_eq!(c.max_bit_rate, Some(14_400));
        assert!(c.sdp.contains("a=T38FaxMaxDatagram:1400\r\n"));
        assert!(!c.sdp.contains("33600"));
    }

    #[test]
    fn initial_invite_prefers_audio() {
        let both = sdp("m=audio 4000 RTP/AVP 0\r\nm=image 5000 udptl t38\r\n");
        let c = classify_offer(
            &both,
            CallMediaKind::Audio,
            &T38Config::default(),
            false,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.kind, CallMediaKind::Audio);
    }

    #[test]
    fn answers() {
        let cfg = enabled();
        let ok = sdp(IMAGE);
        assert!(matches!(
            check_answer(&ok, 1, CallMediaKind::Image, &cfg),
            AnswerCheck::Accepted(c) if c.max_bit_rate == Some(14_400)
        ));
        let declined = sdp("m=audio 4000 RTP/AVP 0\r\nm=image 0 udptl t38\r\n");
        assert!(matches!(
            check_answer(&declined, 1, CallMediaKind::Image, &cfg),
            AnswerCheck::Declined
        ));
        let bad = sdp("m=audio 0 RTP/AVP 0\r\nm=image 5000 udptl t38\r\na=T38MaxBitRate:x\r\n");
        assert!(matches!(
            check_answer(&bad, 1, CallMediaKind::Image, &cfg),
            AnswerCheck::Failed(SwitchoverReason::MalformedT38Sdp)
        ));
        assert!(matches!(
            check_answer("garbage", 1, CallMediaKind::Image, &cfg),
            AnswerCheck::Failed(_)
        ));
    }

    /// QA: hostile and malformed `image/t38` offers never panic, never
    /// forward attacker values above the caps, and fail closed (488).
    #[test]
    fn hostile_image_offers() {
        let cfg = enabled();
        let reject = |body: &str| {
            classify_offer(&sdp(body), CallMediaKind::Audio, &cfg, false, false).unwrap_err()
        };
        // Every m-line declined: nothing to anchor -> 488, not a panic.
        assert_eq!(
            reject("m=audio 0 RTP/AVP 0\r\nm=image 0 udptl t38\r\n"),
            SwitchoverReason::MalformedT38Sdp
        );
        // Bad m-line port / transport / format.
        assert_eq!(
            reject("m=image 70000 udptl t38\r\n"),
            SwitchoverReason::MalformedT38Sdp
        );
        assert_eq!(
            reject("m=image 5000 TCPTL t38\r\n"),
            SwitchoverReason::MalformedT38Sdp
        );
        assert_eq!(
            reject("m=image 5000 TCP t38\r\n"),
            SwitchoverReason::UnsupportedTransport
        );
        // Duplicates, overflow, non-ASCII, non-numeric.
        for attrs in [
            "a=T38FaxMaxBuffer:1\r\na=t38faxmaxbuffer:2\r\n",
            "a=T38FaxMaxDatagram:65536\r\n",
            "a=T38MaxBitRate:18446744073709551616\r\n",
            "a=T38MaxBitRate:+1\r\n",
            "a=T38FaxVersion:\u{0663}\r\n",
            "a=T38FaxUdpEC:\r\n",
        ] {
            assert_eq!(
                reject(&format!("m=image 5000 udptl t38\r\n{attrs}")),
                SwitchoverReason::MalformedT38Sdp,
                "{attrs:?}"
            );
        }
    }

    /// QA: an injected bare CR/LF inside a T.38 attribute cannot smuggle a
    /// line into the forwarded SDP that the SBC did not parse.
    #[test]
    fn crlf_in_t38_value_is_not_forwarded_raw() {
        let cfg = enabled();
        // Lone CR inside a value: refused, nothing forwarded.
        let body = "m=image 5000 udptl t38\r\na=T38MaxBitRate:33600\rc=IN IP4 203.0.113.9\r\n";
        assert_eq!(
            classify_offer(&sdp(body), CallMediaKind::Audio, &cfg, false, false).unwrap_err(),
            SwitchoverReason::MalformedT38Sdp
        );
        // Bare LF is an RFC 8866 line end: the parser sees (and classifies)
        // the second m-line, so it is not a smuggled line. The image stream
        // is still the one anchored.
        let body = "m=image 5000 udptl t38\r\na=T38VendorInfo:0\nm=audio 9 RTP/AVP 0\r\n";
        let c = classify_offer(&sdp(body), CallMediaKind::Audio, &cfg, false, false)
            .unwrap()
            .unwrap();
        assert_eq!((c.kind, c.stream.index), (CallMediaKind::Image, 0));
    }

    /// QA: two active image m-lines anchor the first and decline nothing
    /// else silently; values at the caps pass unchanged.
    #[test]
    fn two_image_streams_and_boundary_values() {
        let cfg = enabled();
        let two = sdp("m=image 5000 udptl t38\r\nm=image 5002 udptl t38\r\n");
        let c = classify_offer(&two, CallMediaKind::Audio, &cfg, false, false)
            .unwrap()
            .unwrap();
        assert_eq!((c.kind, c.stream.index), (CallMediaKind::Image, 0));

        let at_cap = sdp("m=image 5000 udptl t38\r\na=T38MaxBitRate:14400\r\n\
                          a=T38FaxMaxDatagram:1400\r\na=T38FaxMaxBuffer:4096\r\n");
        let c = classify_offer(&at_cap, CallMediaKind::Audio, &cfg, false, false)
            .unwrap()
            .unwrap();
        assert_eq!(c.sdp, at_cap, "no rewrite when nothing is above the caps");
        let over = at_cap.replace("1400\r", "1401\r").replace("4096", "4097");
        let c = classify_offer(&over, CallMediaKind::Audio, &cfg, false, false)
            .unwrap()
            .unwrap();
        assert!(c.sdp.contains("a=T38FaxMaxDatagram:1400\r\n"));
        assert!(c.sdp.contains("a=T38FaxMaxBuffer:4096\r\n"));
    }

    /// QA: answers to a back-to-audio offer, and audit field set.
    #[test]
    fn audio_answers_and_audit_fields() {
        let cfg = enabled();
        let audio = sdp("m=audio 4000 RTP/AVP 0\r\nm=image 0 udptl t38\r\n");
        assert!(matches!(
            check_answer(&audio, 0, CallMediaKind::Audio, &cfg),
            AnswerCheck::Accepted(c) if c.kind == CallMediaKind::Audio
        ));
        // Answer keeps image active at the audio index: declined, no change.
        let image = sdp("m=image 5000 udptl t38\r\n");
        assert!(matches!(
            check_answer(&image, 0, CallMediaKind::Audio, &cfg),
            AnswerCheck::Declined
        ));
        // Unparseable answer to an audio offer is not fatal.
        assert!(matches!(
            check_answer("x", 0, CallMediaKind::Audio, &cfg),
            AnswerCheck::Declined
        ));
        // Index beyond the answer's m-lines.
        assert!(matches!(
            check_answer(&audio, 5, CallMediaKind::Image, &cfg),
            AnswerCheck::Failed(SwitchoverReason::MalformedT38Sdp)
        ));

        let event = audit_event(
            "sess-1",
            CallMediaKind::Image,
            CallMediaKind::Audio,
            false,
            SwitchoverOutcome::RejectedRemote,
            Some(SwitchoverReason::Remote488),
            None,
        );
        let ev = match event {
            uc_audit::AuditEvent::MediaSwitchover(ev) => Some(ev),
            _ => None,
        }
        .expect("media_switchover variant");
        assert_eq!(ev.originator, SwitchoverOriginator::BLeg);
        assert_eq!(ev.from_kind, SwitchoverMediaKind::Image);
        assert_eq!(ev.to_kind, SwitchoverMediaKind::Audio);
        assert_eq!(ev.transport, None, "no transport toward audio");
        assert_eq!(
            warning_for(SwitchoverReason::T38Disabled, "sbc.example"),
            "304 sbc.example \"Media type not available\""
        );
        for r in [
            SwitchoverReason::UnsupportedTransport,
            SwitchoverReason::EcNotAllowed,
            SwitchoverReason::SrtpTerminate,
        ] {
            assert!(warning_for(r, "h").starts_with("305 h "), "{r:?}");
        }
        assert!(warning_for(SwitchoverReason::MalformedT38Sdp, "h").starts_with("399 h "));
        for r in [
            SwitchoverReason::T38Disabled,
            SwitchoverReason::SrtpTerminate,
            SwitchoverReason::UnsupportedTransport,
            SwitchoverReason::MalformedT38Sdp,
            SwitchoverReason::EcNotAllowed,
            SwitchoverReason::Remote488,
            SwitchoverReason::RemotePort0,
            SwitchoverReason::RelayUpdateFailed,
        ] {
            assert!(reason_policy(r).starts_with("t38:"));
        }
    }

    #[test]
    fn counters() {
        let c = T38Counters::default();
        c.record(CallMediaKind::Image, SwitchoverOutcome::Accepted);
        c.record(CallMediaKind::Audio, SwitchoverOutcome::Failed);
        c.image_started();
        let v = c.metric_values();
        assert_eq!(v.len(), 10);
        assert!(v.contains(&("sbc_t38_switchover_to_t38_accepted_total", 1)));
        assert!(v.contains(&("sbc_t38_switchover_to_audio_failed_total", 1)));
        assert!(v.contains(&(METRIC_ACTIVE_CALLS, 1)));
        c.image_ended();
        assert_eq!(c.active(), 0);
    }
}
