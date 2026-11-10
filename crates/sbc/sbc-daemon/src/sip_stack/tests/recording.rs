//! SIPREC recording session tests (RFC 7866 SRC; POA&M-300, -302, -306).
//!
//! Sans-IO: a trunk stack, a mock media controller that records the fork
//! calls, a ring-only CDR pipeline and the thread-local audit capture. The
//! fake SRS is the test itself: it answers the RS INVITE the stack returns.

use super::*;
use crate::recording::{RecordingSettings, RsState};
use sbc_config::schema::{RecordingConfig, RecordingFailureAction, RecordprefPolicy};
use sbc_media_core::media_pipeline::{
    AllocatedPorts, LegDtlsParams, MediaController, MediaKind, MediaPipelineError,
    RecordingForkPorts,
};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use uc_audit::event::{
    RecordingFailAction, RecordingFailReason, RecordingFailed, RecordingRelay, RecordingStarted,
    RecordingStopReason, RecordingStopped,
};
use uc_cdr::RecordingTag;

const REJECT: RecordingFailureAction = RecordingFailureAction::Reject;
const CONTINUE: RecordingFailureAction = RecordingFailureAction::Continue;

/// 44 zero octets in base64: a syntactically valid key || salt, not a secret.
const SRS_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn srs() -> SbcSocketAddr {
    SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 0, 2, 50), 5061)
}

/// Media controller that logs the calls the recording glue makes.
#[derive(Default)]
struct ForkMedia {
    log: std::sync::Mutex<Vec<String>>,
    /// Model a remote media node (trait default: no fork).
    unsupported: AtomicBool,
    fail_prepare: AtomicBool,
    fail_activate: AtomicBool,
    /// Master key || salt of each stream key the pipeline was given.
    keys: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl ForkMedia {
    fn push(&self, s: impl Into<String>) {
        self.log.lock().unwrap().push(s.into());
    }
    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    fn count(&self, prefix: &str) -> usize {
        self.log().iter().filter(|l| l.starts_with(prefix)).count()
    }
}

#[async_trait::async_trait]
impl MediaController for ForkMedia {
    async fn create_session_with_zones(
        &self,
        _call_id: &str,
        _mode: Option<uc_media_engine::MediaMode>,
        _a: Option<std::net::IpAddr>,
        _b: Option<std::net::IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        Ok(AllocatedPorts {
            a_leg_rtp_port: 20_000,
            b_leg_rtp_port: 20_002,
            media_ip: None,
            dtls_fingerprint: None,
        })
    }
    async fn set_remote_address(
        &self,
        _call_id: &str,
        _is_a_leg: bool,
        _address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        Ok(())
    }
    async fn start_relay(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        Ok(())
    }
    async fn start_relay_terminate(
        &self,
        _call_id: &str,
        _a: LegDtlsParams,
        _b: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        Ok(())
    }
    async fn stop_relay(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        self.push("stop-relay");
        Ok(())
    }
    async fn remove_session(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        Ok(())
    }
    async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError> {
        Ok((30_100, 30_101))
    }
    async fn set_media_kind(
        &self,
        _call_id: &str,
        _kind: MediaKind,
    ) -> Result<(), MediaPipelineError> {
        Ok(())
    }
    async fn prepare_recording_fork(
        &self,
        _call_id: &str,
        keys: [proto_srtp::SrtpKeyMaterial; 2],
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<RecordingForkPorts, MediaPipelineError> {
        if self.unsupported.load(AtomicOrdering::Relaxed) {
            return Err(MediaPipelineError::RecordingUnsupported);
        }
        if self.fail_prepare.load(AtomicOrdering::Relaxed) {
            return Err(MediaPipelineError::PortExhausted);
        }
        self.push(format!("prepare {bind_ip:?}"));
        *self.keys.lock().unwrap() = keys
            .iter()
            .map(|k| [k.master_key(), k.master_salt()].concat())
            .collect();
        Ok(RecordingForkPorts {
            a_leg_port: 30_000,
            b_leg_port: 30_002,
        })
    }
    async fn activate_recording_fork(
        &self,
        _call_id: &str,
        remotes: [std::net::SocketAddr; 2],
    ) -> Result<(), MediaPipelineError> {
        if self.fail_activate.load(AtomicOrdering::Relaxed) {
            return Err(MediaPipelineError::RecordingFork("test".to_string()));
        }
        self.push(format!("activate {} {}", remotes[0], remotes[1]));
        Ok(())
    }
    async fn stop_recording_fork(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        self.push("fork-stop");
        Ok(())
    }
}

fn settings(on_failure: RecordingFailureAction) -> RecordingSettings {
    let rec = RecordingConfig {
        enabled: true,
        notice_acknowledged: true,
        srs_uri: Some("sips:srs.example.test:5061".to_string()),
        srs_tls_ca_file: Some("/unused".to_string()),
        record_all: true,
        on_failure,
        ..RecordingConfig::default()
    };
    RecordingSettings::from_config(
        &rec,
        srs(),
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))),
    )
    .unwrap()
}

/// For server tests: a stack recording toward `srs_addr` under `on_failure`
/// with one answered call, and the RS INVITE it produced.
pub async fn rs_invite_for_server(
    srs_addr: SbcSocketAddr,
    on_failure: RecordingFailureAction,
) -> (SipStack, ProcessResult) {
    let f = fixture_with(on_failure, |s| s.srs_addr = srs_addr).await;
    let invite = answered(&f.stack, "server-rs@test")
        .await
        .into_iter()
        .find(|r| {
            matches!(r, ProcessResult::Forward { message: SipMessage::Request(q), destination, .. }
                if q.method == Method::Invite && *destination == srs_addr)
        })
        .expect("RS INVITE");
    (f.stack, invite)
}

/// For server tests: a recording stack with two established recordings
/// ended by shutdown, and its SRS address. Their RS BYEs sit on the
/// wind-down queue, as after `end_remaining_calls_for_shutdown` at daemon
/// shutdown; the queue is then padded with copies up to `queued` requests
/// (a mass teardown without placing that many calls).
pub async fn rs_byes_queued_at_shutdown(queued: usize) -> (SipStack, SbcSocketAddr) {
    const CALLS: usize = 2;
    let f = fixture(CONTINUE).await;
    for n in 0..CALLS {
        let results = answered(&f.stack, &format!("sd-{n}@test")).await;
        srs_ok(&f.stack, &rs_invite(&results)).await;
    }
    assert_eq!(f.stack.end_remaining_calls_for_shutdown().await, CALLS);
    {
        let mut q = lock_leaf(&f.stack.rs_wind_down);
        assert_eq!(q.len(), CALLS);
        assert!(q.iter().all(|r| r.method == Method::Bye));
        while q.len() < queued {
            let copy = q.front().cloned().unwrap();
            q.push_back(copy);
        }
    }
    (f.stack, srs())
}

struct Fixture {
    stack: SipStack,
    media: Arc<ForkMedia>,
    cdr: Arc<uc_cdr::CdrEmitter>,
}

/// A trunk stack (alice on inbound trunk "pbx", callee on "carriers" t1)
/// with recording enabled.
async fn fixture_with(
    on_failure: RecordingFailureAction,
    tweak: impl FnOnce(&mut RecordingSettings),
) -> Fixture {
    let (mut stack, cdr) = cdr_stack().await;
    let media = Arc::new(ForkMedia::default());
    stack.set_media_pipeline(Arc::clone(&media) as _);
    let mut s = settings(on_failure);
    tweak(&mut s);
    stack.set_recording(s);
    Fixture { stack, media, cdr }
}

async fn fixture(on_failure: RecordingFailureAction) -> Fixture {
    fixture_with(on_failure, |_| {}).await
}

/// The callee's 200 (from t1) to the forwarded INVITE of `call_id`.
async fn answer_with(
    stack: &SipStack,
    placed: &[ProcessResult],
    answer_sdp: &str,
) -> Vec<ProcessResult> {
    let inv = forwarded(placed, &Method::Invite).unwrap().0.clone();
    flatten(
        stack
            .process_message(
                &response_to(&inv, 200, Some("bobtag"), Some(answer_sdp)),
                t1(),
                None,
            )
            .await,
    )
}

/// Places `call_id`, answers it and has the caller ACK the 200 (so the
/// A-leg dialog is confirmed, RFC 3261 §13.2.2.4); returns what the 200
/// produced.
async fn answered(stack: &SipStack, call_id: &str) -> Vec<ProcessResult> {
    let placed = place_call(stack, call_id).await;
    let results = answer_with(stack, &placed, BOB_SDP).await;
    if responded(&results, 200).is_some() {
        caller_ack(stack, call_id).await;
    }
    results
}

/// The caller's ACK for the 200 to its INVITE (its own transaction, so a
/// branch of its own, RFC 3261 §13.2.2.4 / §17.1.1.3); returns what it
/// released.
async fn caller_ack(stack: &SipStack, call_id: &str) -> Vec<ProcessResult> {
    caller_ack_for(stack, DIALED, call_id, 1).await
}

/// The caller's ACK for the 2xx to its INVITE number `cseq` toward `user`.
async fn caller_ack_for(
    stack: &SipStack,
    user: &str,
    call_id: &str,
    cseq: u32,
) -> Vec<ProcessResult> {
    let ack = caller_request("ACK", user, call_id, cseq, Some("bobtag"), None);
    let ack = Bytes::from(String::from_utf8(ack.to_vec()).unwrap().replace(
        &format!("z9hG4bK-{call_id}-{cseq}"),
        &format!("z9hG4bK-{call_id}-ack{cseq}"),
    ));
    flatten(stack.process_message(&ack, alice(), None).await)
}

/// The SBC's BYEs toward the call legs (not the SRS), by destination.
fn leg_byes(results: &[ProcessResult]) -> Vec<SbcSocketAddr> {
    results
        .iter()
        .filter_map(|r| match r {
            ProcessResult::Forward {
                message: SipMessage::Request(req),
                destination,
                ..
            } if req.method == Method::Bye && *destination != srs() => Some(*destination),
            _ => None,
        })
        .collect()
}

/// The request of `method` the stack sent to the SRS, if any.
fn to_srs(results: &[ProcessResult], method: &Method) -> Option<SipRequest> {
    results.iter().find_map(|r| match r {
        ProcessResult::Forward {
            message: SipMessage::Request(req),
            destination,
            flow: Flow::Leg(flow),
        } if req.method == *method && *destination == srs() => {
            assert!(flow.recorder, "RS requests ride the recorder flow only");
            assert_eq!(flow.transport, AddrTransport::Tls);
            assert_eq!(flow.dial.as_deref(), Some("srs.example.test"));
            Some(req.clone())
        }
        _ => None,
    })
}

fn rs_invite(results: &[ProcessResult]) -> SipRequest {
    to_srs(results, &Method::Invite).expect("RS INVITE to the SRS")
}

fn srs_answer_sdp() -> String {
    let stream = |port: u16| {
        format!(
            "m=audio {port} RTP/SAVP 0\r\na=recvonly\r\na=rtcp-mux\r\n\
             a=crypto:1 AEAD_AES_256_GCM inline:{SRS_KEY}\r\n"
        )
    };
    format!(
        "v=0\r\no=- 9 9 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n{}{}",
        stream(40_000),
        stream(40_002)
    )
}

/// Feeds a message from the SRS (on its TLS connection).
async fn from_srs(stack: &SipStack, data: &Bytes) -> Vec<ProcessResult> {
    flatten(
        stack
            .process_message_on(data, srs(), None, AddrTransport::Tls)
            .await,
    )
}

/// The SRS answers the RS INVITE 200 with a valid answer (tag `srstag`).
async fn srs_ok(stack: &SipStack, invite: &SipRequest) -> Vec<ProcessResult> {
    from_srs(
        stack,
        &response_to(invite, 200, Some("srstag"), Some(&srs_answer_sdp())),
    )
    .await
}

/// An in-dialog request from the SRS on the RS dialog of `invite`.
fn srs_request(invite: &SipRequest, method: &str, from_tag: &str) -> Bytes {
    let from = format!(
        "{};tag={from_tag}",
        invite.headers.get_value(&HeaderName::To).unwrap()
    );
    let to = invite.headers.get_value(&HeaderName::From).unwrap();
    Bytes::from(format!(
        "{method} sips:192.0.2.9:5061 SIP/2.0\r\n\
         Via: SIP/2.0/TLS 192.0.2.50:5061;branch=z9hG4bK-srs-{method}\r\n\
         From: {from}\r\nTo: {to}\r\nCall-ID: {}\r\nCSeq: 7 {method}\r\n\
         Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        invite.headers.call_id().unwrap()
    ))
}

async fn caller_bye(stack: &SipStack, call_id: &str) -> Vec<ProcessResult> {
    let bye = caller_request("BYE", DIALED, call_id, 2, Some("bobtag"), None);
    flatten(stack.process_message(&bye, alice(), None).await)
}

async fn poll(stack: &SipStack) -> Vec<ProcessResult> {
    stack
        .poll_timers()
        .await
        .into_iter()
        .flat_map(flatten)
        .collect()
}

async fn recording_of(stack: &SipStack, call_id: &str) -> crate::recording::CallRecording {
    let id = internal_id(stack, call_id).await;
    stack
        .call_correlation
        .read()
        .await
        .addresses
        .get(&id)
        .unwrap()
        .recording
        .clone()
}

async fn call_is_up(stack: &SipStack, call_id: &str) -> bool {
    stack
        .call_correlation
        .read()
        .await
        .a_leg
        .contains_key(call_id)
}

fn started(events: &[uc_audit::AuditEvent]) -> Vec<RecordingStarted> {
    events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::RecordingStarted(x) => Some(x.clone()),
            _ => None,
        })
        .collect()
}

fn stopped(events: &[uc_audit::AuditEvent]) -> Vec<RecordingStopped> {
    events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::RecordingStopped(x) => Some(x.clone()),
            _ => None,
        })
        .collect()
}

fn failed(events: &[uc_audit::AuditEvent]) -> Vec<RecordingFailed> {
    events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::RecordingFailed(x) => Some(x.clone()),
            _ => None,
        })
        .collect()
}

fn skipped(events: &[uc_audit::AuditEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, uc_audit::AuditEvent::RecordingSkipped(_)))
        .count()
}

/// Both legs of the call got a BYE from the SBC.
fn assert_both_legs_byed(results: &[ProcessResult]) {
    let byes = leg_byes(results);
    assert!(byes.contains(&alice()), "BYE to the caller: {results:?}");
    assert!(byes.contains(&t1()), "BYE to the callee: {results:?}");
}

fn assert_no_leg_bye(results: &[ProcessResult]) {
    assert!(
        !results.iter().any(|r| matches!(r, ProcessResult::Forward {
            message: SipMessage::Request(req), destination, ..
        } if req.method == Method::Bye && *destination != srs())),
        "the call must stay up: {results:?}"
    );
}

/// SC-5: every recording resource of an ended call is released.
async fn assert_recording_released(f: &Fixture) {
    assert_eq!(
        f.stack.recording_counters().slots_held(),
        0,
        "max_sessions slots released"
    );
    assert!(
        f.stack.call_correlation.read().await.rs_leg.is_empty(),
        "no RS correlation left"
    );
    assert_all_released(&f.stack).await;
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.split('-').map(str::len).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
        && s.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

// ----------------------------------------------------------------------
// Happy path
// ----------------------------------------------------------------------

// POA&M-300 acceptance (RFC 7866 §6.1.1, §7.1.1, §9.1): the answered call
// yields an RS INVITE on the recorder TLS flow; the caller's 200 and the
// callee's ACK are unchanged.
#[tokio::test]
async fn answered_call_sends_rs_invite_on_the_recorder_flow() {
    let f = fixture(REJECT).await;
    let results = answered(&f.stack, "rec-1@test").await;
    assert!(responded(&results, 200).is_some(), "200 to the caller");
    let (ack, dest) = forwarded(&results, &Method::Ack).expect("ACK to the callee");
    assert_eq!(dest, t1());
    assert_eq!(ack.headers.cseq(), Some("1 ACK"));
    assert_no_leg_bye(&results);

    let inv = rs_invite(&results);
    assert_eq!(inv.uri.to_string(), "sips:srs.example.test:5061");
    assert_eq!(
        inv.headers.get_value(&HeaderName::Require),
        Some("siprec"),
        "RFC 7866 §6.1.1"
    );
    let contact = inv.headers.get_value(&HeaderName::Contact).unwrap();
    assert!(
        contact.starts_with("<sips:") && contact.ends_with(">;+sip.src"),
        "{contact}"
    );
    assert!(contact.contains(":5061"), "TLS listener port: {contact}");
    let via = inv.headers.get_value(&HeaderName::Via).unwrap();
    assert!(via.starts_with("SIP/2.0/TLS "), "{via}");
    assert_eq!(inv.headers.cseq(), Some("1 INVITE"));
    assert_eq!(
        inv.headers.get_value(&HeaderName::To),
        Some("<sips:srs.example.test:5061>")
    );
    // No value of the call's own dialogs leaks into the RS headers.
    let rs_call_id = inv.headers.call_id().unwrap();
    assert!(!rs_call_id.contains("rec-1"), "{rs_call_id}");
    let headers = SipMessage::Request(inv.clone()).to_string();
    let head = headers.split("\r\n\r\n").next().unwrap();
    assert!(
        !head.contains("alice") && !head.contains("bobtag"),
        "{head}"
    );

    let ct = inv.headers.get_value(&HeaderName::ContentType).unwrap();
    assert!(ct.starts_with("multipart/mixed;boundary="), "{ct}");
    let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
    assert!(body.contains("Content-Disposition: recording-session"));
    assert!(body.contains("Content-Type: application/rs-metadata+xml"));
    assert!(body.contains("aor=\"sip:alice@example.com\""), "{body}");
    assert!(
        body.contains(&format!("aor=\"sip:{DIALED}@sbc.local\"")),
        "{body}"
    );
    assert_eq!(body.matches("RTP/SAVP 0").count(), 2, "the call's format");
    assert!(body.contains("m=audio 30000 ") && body.contains("m=audio 30002 "));
    assert_eq!(body.matches("a=sendonly").count(), 2);
    assert_eq!(
        body.matches("a=crypto:1 AEAD_AES_256_GCM inline:").count(),
        2
    );
    assert!(
        body.contains("c=IN IP4 192.0.2.9"),
        "SBC media address: {body}"
    );
    assert!(body.contains("a=label:1") && body.contains("a=label:2"));

    // The fork is prepared (bound to the SBC's address) but not active.
    assert_eq!(
        f.media.count("prepare Some(192.0.2.9)"),
        1,
        "{:?}",
        f.media.log()
    );
    assert_eq!(f.media.count("activate"), 0);
    let rec = recording_of(&f.stack, "rec-1@test").await;
    assert_eq!(rec.leg.as_ref().unwrap().state, RsState::Inviting);
    assert!(is_uuid(rec.session_id.as_deref().unwrap()));
    assert_eq!(f.stack.recording_counters().slots_held(), 1);
}

// RS 200 -> ACK + fork activated; BYE from the caller -> RS BYE with the
// dialog's identifiers; CDR `recorded`; audit started / stopped.
#[tokio::test]
async fn rs_answer_activates_the_fork_and_call_end_byes_the_srs() {
    let f = fixture(REJECT).await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "rec-2@test").await);

    // RFC 3261 §17.1.1: a provisional first.
    assert!(
        from_srs(&f.stack, &response_to(&inv, 180, Some("srstag"), None))
            .await
            .is_empty()
    );
    let results = srs_ok(&f.stack, &inv).await;
    let ack = to_srs(&results, &Method::Ack).expect("ACK to the SRS");
    assert_eq!(ack.headers.cseq(), Some("1 ACK"));
    assert_eq!(ack.headers.call_id(), inv.headers.call_id());
    assert_eq!(ack.headers.to_tag().as_deref(), Some("srstag"));
    assert_eq!(ack.headers.from_tag(), inv.headers.from_tag());
    assert_eq!(results.len(), 1, "only the ACK: {results:?}");
    assert_eq!(
        f.media
            .count("activate 198.51.100.7:40000 198.51.100.7:40002"),
        1,
        "stream order: caller's media first: {:?}",
        f.media.log()
    );
    let session_id = {
        let rec = recording_of(&f.stack, "rec-2@test").await;
        assert_eq!(rec.tag, Some(RecordingTag::Recorded));
        assert!(rec.leg.as_ref().unwrap().active_since.is_some());
        // (`rec` is a clone of the call's state and holds its slot.)
        rec.session_id.unwrap()
    };

    // RFC 3261 §13.2.2.4: a retransmitted 2xx is re-ACKed, nothing else.
    let again = srs_ok(&f.stack, &inv).await;
    assert!(to_srs(&again, &Method::Ack).is_some());
    assert_eq!(again.len(), 1);
    assert_eq!(f.media.count("activate"), 1, "the fork is not re-activated");

    let events = capture.events();
    let s = started(&events);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].recording_session_id, session_id);
    assert_eq!(s[0].relay, RecordingRelay::Opaque);
    assert_eq!(
        s[0].call_id,
        internal_id(&f.stack, "rec-2@test").await.to_string(),
        "internal session id, not a SIP Call-ID"
    );

    // Call end: 200 to the caller, BYE to the callee, RS BYE via the timer
    // loop (deferred send), with the RS dialog identifiers.
    let ended = caller_bye(&f.stack, "rec-2@test").await;
    assert!(responded(&ended, 200).is_some());
    assert!(to_srs(&ended, &Method::Bye).is_none());
    let bye = to_srs(&poll(&f.stack).await, &Method::Bye).expect("RS BYE");
    assert_eq!(bye.headers.call_id(), inv.headers.call_id());
    assert_eq!(bye.headers.cseq(), Some("2 BYE"));
    assert_eq!(bye.headers.to_tag().as_deref(), Some("srstag"));
    assert_eq!(bye.headers.from_tag(), inv.headers.from_tag());
    assert!(
        to_srs(&poll(&f.stack).await, &Method::Bye).is_none(),
        "once"
    );

    let events = capture.events();
    let st = stopped(&events);
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].reason, RecordingStopReason::CallEnded);
    assert_eq!(st[0].recording_session_id, session_id);
    assert!(failed(&events).is_empty());
    let c = one_cdr(&f.cdr);
    assert_eq!(c.recording, Some(RecordingTag::Recorded));
    assert_eq!(c.recording_session_id.as_deref(), Some(session_id.as_str()));
    assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
    let m: HashMap<_, _> = f
        .stack
        .recording_counters()
        .metric_values()
        .into_iter()
        .collect();
    assert_eq!(m["sbc_recording_started_total"], 1);
    assert_eq!(m["sbc_recording_stopped_total"], 1);
    assert_eq!(m["sbc_recording_sessions_active"], 0);
    assert_recording_released(&f).await;
}

// The callee hanging up ends the RS the same way.
#[tokio::test]
async fn callee_bye_ends_the_recording_session() {
    let f = fixture(REJECT).await;
    let placed = place_call(&f.stack, "rec-3@test").await;
    let b_invite = forwarded(&placed, &Method::Invite).unwrap().0.clone();
    let inv = rs_invite(&answer_with(&f.stack, &placed, BOB_SDP).await);
    srs_ok(&f.stack, &inv).await;
    let from = format!(
        "{};tag=bobtag",
        b_invite.headers.get_value(&HeaderName::To).unwrap()
    );
    let bye = Bytes::from(format!(
        "BYE sip:sbc@sbc.local SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.2:5060;branch=z9hG4bK-cb\r\n\
         From: {from}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: 5 BYE\r\nContent-Length: 0\r\n\r\n",
        b_invite.headers.get_value(&HeaderName::From).unwrap(),
        b_invite.headers.call_id().unwrap()
    ));
    let ended = flatten(f.stack.process_message(&bye, t1(), None).await);
    assert!(responded(&ended, 200).is_some(), "{ended:?}");
    assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_some());
    assert_eq!(one_cdr(&f.cdr).recording, Some(RecordingTag::Recorded));
    assert_recording_released(&f).await;
}

// A media failure (SBC-initiated teardown) and shutdown end the RS too:
// one hook in `finish_call_record` covers every end path.
#[tokio::test]
async fn media_failure_and_shutdown_end_the_recording_session() {
    let f = fixture(REJECT).await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "rec-mf@test").await);
    srs_ok(&f.stack, &inv).await;
    let id = internal_id(&f.stack, "rec-mf@test").await;
    let byes = f
        .stack
        .terminate_call_on_media_failure(&id.to_string())
        .await;
    assert_eq!(byes.len(), 2);
    assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_some());

    let inv = rs_invite(&answered(&f.stack, "rec-sd@test").await);
    srs_ok(&f.stack, &inv).await;
    assert_eq!(f.stack.end_remaining_calls_for_shutdown().await, 1);
    assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_some());
    let reasons: Vec<_> = stopped(&capture.events())
        .iter()
        .map(|s| s.reason)
        .collect();
    assert_eq!(
        reasons,
        vec![
            RecordingStopReason::CallEnded,
            RecordingStopReason::Shutdown
        ]
    );
    let tags: Vec<_> = cdrs(&f.cdr).iter().map(|c| c.recording).collect();
    assert_eq!(tags, vec![Some(RecordingTag::Recorded); 2]);
    assert_recording_released(&f).await;
}

/// Standard base64 decoder for the test's own key comparison.
fn b64(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in input.bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            _ => 63,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

// SC-12 / RFC 4568 §6.1: the key offered for each RS stream is the key the
// pipeline protects that stream with (m-line 1 = the caller's media =
// pipeline key 0), the two streams have different keys, and each call gets
// fresh ones.
#[tokio::test]
async fn rs_offer_keys_are_the_pipeline_keys_in_stream_order() {
    let f = fixture(CONTINUE).await;
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for call_id in ["k-1@test", "k-2@test"] {
        let inv = rs_invite(&answered(&f.stack, call_id).await);
        let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
        let offered: Vec<Vec<u8>> = body
            .lines()
            .filter_map(|l| l.strip_prefix("a=crypto:1 AEAD_AES_256_GCM inline:"))
            .map(|k| b64(k.trim()))
            .collect();
        assert_eq!(offered.len(), 2);
        assert!(
            offered.iter().all(|k| k.len() == 44),
            "32-byte key + 12-byte salt"
        );
        assert_eq!(offered, *f.media.keys.lock().unwrap(), "{call_id}");
        // The label order matches: stream 1 first.
        assert!(body.find("a=label:1").unwrap() < body.find("a=label:2").unwrap());
        seen.extend(offered);
    }
    let unique: HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 4, "one fresh key per stream and per call");
}

// SC-12 / SI-12 (plan §7): no Debug form of what the stack returns shows
// the SDES keys or any part of the RS body.
#[tokio::test]
async fn rs_invite_debug_output_holds_no_key_material() {
    let f = fixture(REJECT).await;
    let results = answered(&f.stack, "rec-dbg@test").await;
    let inv = rs_invite(&results);
    let body = String::from_utf8(inv.body.as_ref().unwrap().to_vec()).unwrap();
    let at = body.find("inline:").unwrap() + "inline:".len();
    let key = &body[at..at + 20];
    let dbg = format!("{results:?} {results:#?}");
    assert!(dbg.contains("INVITE sips:srs.example.test:5061"), "{dbg}");
    assert!(!dbg.contains("inline:"), "{dbg}");
    assert!(!dbg.contains(key), "{dbg}");
    assert!(
        !dbg.contains("a=crypto") && !dbg.contains("rs-metadata"),
        "{dbg}"
    );
    let state = format!("{:?}", recording_of(&f.stack, "rec-dbg@test").await);
    assert!(
        !state.contains(key) && !state.contains("inline:"),
        "{state}"
    );
}

// ----------------------------------------------------------------------
// Failure policy (POA&M-302): reject tears the call down, continue keeps it
// ----------------------------------------------------------------------

/// How `on_failure = reject` shows on the wire, by the moment the failure
/// is found (RFC 3261 §15: the caller never gets a BYE before its ACK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reject {
    /// At INVITE: the caller gets this final status, the B-leg is never
    /// dialled.
    AtInvite(u16),
    /// At the callee's 2xx: the 2xx is not relayed; the caller gets this
    /// final status, the callee ACK + BYE.
    AtAnswer(u16),
    /// After the 2xx was relayed (and ACKed): BYE to both legs.
    Teardown,
}

/// What the policy must have done after a post-answer failure with `reason`.
async fn assert_policy(
    f: &Fixture,
    call_id: &str,
    policy: RecordingFailureAction,
    results: &[ProcessResult],
    events: &[uc_audit::AuditEvent],
    reason: RecordingFailReason,
    tag: RecordingTag,
) {
    assert_policy_as(
        f,
        call_id,
        policy,
        results,
        events,
        (reason, tag, Reject::Teardown),
    )
    .await;
}

/// What the policy must have done after a failure with `reason`; under
/// `reject` the call was refused or torn down as `how` says. `results` is
/// what the failing step produced (the INVITE for [`Reject::AtInvite`]).
async fn assert_policy_as(
    f: &Fixture,
    call_id: &str,
    policy: RecordingFailureAction,
    results: &[ProcessResult],
    events: &[uc_audit::AuditEvent],
    (reason, tag, how): (RecordingFailReason, RecordingTag, Reject),
) {
    let fails = failed(events);
    assert_eq!(fails.len(), 1, "one recording_failed: {fails:?}");
    assert_eq!(fails[0].reason, reason);
    assert_eq!(f.stack.recording_counters().failed(reason), 1);
    assert_eq!(
        f.stack.recording_counters().slots_held(),
        0,
        "the slot is released on failure"
    );
    assert!(f.stack.call_correlation.read().await.rs_leg.is_empty());
    if policy == REJECT {
        assert_eq!(fails[0].action, RecordingFailAction::CallRejected);
        assert!(!call_is_up(&f.stack, call_id).await);
        let c = one_cdr(&f.cdr);
        assert_eq!(c.release_cause, uc_cdr::ReleaseCause::RecordingFailure);
        assert_eq!(c.release_side, uc_cdr::ReleaseSide::Sbc);
        assert_eq!(c.recording, Some(tag));
        assert_eq!(f.stack.recording_counters().calls_rejected(), 1);
        let policy_terminated = events.iter().any(|e| {
            matches!(e, uc_audit::AuditEvent::CallTerminated(t)
                if matches!(t.reason, uc_audit::event::TerminationReason::PolicyTerminated))
        });
        match how {
            Reject::Teardown => {
                assert_both_legs_byed(results);
                assert_eq!(c.disposition, uc_cdr::Disposition::RecordingFailure);
                assert!(policy_terminated, "audited as policy-terminated");
            }
            Reject::AtAnswer(status) => {
                // RFC 3261 §15: nothing was relayed, so no BYE to the caller.
                assert!(responded(results, 200).is_none(), "{results:?}");
                let (resp, dest) = responded(results, status)
                    .unwrap_or_else(|| panic!("{status} to the caller: {results:?}"));
                assert_eq!(dest, alice());
                assert_eq!(
                    resp.headers.get_value(&HeaderName::Warning).is_some(),
                    status == 488,
                    "488 explains itself (RFC 3261 §20.43)"
                );
                assert_eq!(leg_byes(results), vec![t1()], "BYE to the callee only");
                let (_, ack_dest) = forwarded(results, &Method::Ack).expect("callee's 2xx ACKed");
                assert_eq!(ack_dest, t1());
                assert!(f.stack.pending_2xx.read().await.is_empty());
                assert_eq!(c.disposition, uc_cdr::Disposition::RecordingFailure);
                assert_eq!(c.final_sip_status, status);
                assert!(policy_terminated, "audited as policy-terminated");
            }
            Reject::AtInvite(status) => {
                let (resp, dest) = responded(results, status)
                    .unwrap_or_else(|| panic!("{status} to the caller: {results:?}"));
                assert_eq!(dest, alice());
                assert_eq!(
                    resp.headers.get_value(&HeaderName::Warning).is_some(),
                    status == 488
                );
                assert!(
                    forwarded(results, &Method::Invite).is_none(),
                    "the B-leg is never dialled: {results:?}"
                );
                assert_eq!(leg_byes(results), Vec::new(), "no BYE at all");
                assert_eq!(c.disposition, uc_cdr::Disposition::Rejected);
                assert_eq!(c.final_sip_status, status);
            }
        }
    } else {
        assert_eq!(fails[0].action, RecordingFailAction::ContinuedUnrecorded);
        assert_no_leg_bye(results);
        assert!(call_is_up(&f.stack, call_id).await, "call kept");
        assert_eq!(recording_of(&f.stack, call_id).await.tag, Some(tag));
        assert_eq!(f.stack.recording_counters().calls_rejected(), 0);
        // The call then ends normally: no RS BYE, CDR carries the tag.
        caller_bye(&f.stack, call_id).await;
        assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_none());
        let c = one_cdr(&f.cdr);
        assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
        assert_eq!(c.recording, Some(tag));
    }
    assert_recording_released(f).await;
}

// Dial / TLS failure of the RS INVITE (`on_invite_sent(.., false)`): there
// is no failover (one SRS); the reason tells TLS from unreachable.
#[tokio::test]
async fn rs_invite_send_failure_applies_the_policy() {
    for policy in [REJECT, CONTINUE] {
        for (tls, reason) in [
            (true, RecordingFailReason::SrsTls),
            (false, RecordingFailReason::SrsUnreachable),
        ] {
            let f = fixture(policy).await;
            let capture = uc_audit::capture::start();
            let inv = SipMessage::Request(rs_invite(&answered(&f.stack, "sf@test").await));
            assert!(
                f.stack
                    .on_invite_sent_with(&inv, true, false)
                    .await
                    .is_empty(),
                "a successful send changes nothing"
            );
            let results = f.stack.on_invite_sent_with(&inv, false, tls).await;
            assert!(
                f.stack
                    .on_invite_sent_with(&inv, false, tls)
                    .await
                    .is_empty(),
                "reported once"
            );
            assert_eq!(f.media.count("fork-stop"), 1, "the fork is dropped");
            let events = capture.events();
            assert_policy(
                &f,
                "sf@test",
                policy,
                &results,
                &events,
                reason,
                RecordingTag::Failed,
            )
            .await;
            // The dead attempt's transaction is gone: no Timer B later.
            assert!(
                f.stack
                    .transactions
                    .read()
                    .await
                    .client_invite
                    .values()
                    .all(|st| !matches!(&st.request, SipMessage::Request(r)
                    if r.headers.call_id() == inv.call_id()))
            );
        }
    }
}

// Non-2xx finals: 488 is named separately (an AES-128-only recorder).
#[tokio::test]
async fn rs_invite_rejection_applies_the_policy() {
    for policy in [REJECT, CONTINUE] {
        for (status, reason) in [
            (488, RecordingFailReason::SrsNotAcceptable488),
            (503, RecordingFailReason::SrsRejected),
        ] {
            let f = fixture(policy).await;
            let capture = uc_audit::capture::start();
            let inv = rs_invite(&answered(&f.stack, "rej@test").await);
            let results =
                from_srs(&f.stack, &response_to(&inv, status, Some("srstag"), None)).await;
            // RFC 3261 §17.1.1.3: the transaction layer ACKs the non-2xx.
            let ack = to_srs(&results, &Method::Ack).expect("ACK for the non-2xx");
            assert_eq!(ack.headers.via_branch(), inv.headers.via_branch());
            let events = capture.events();
            assert_eq!(failed(&events)[0].sip_status, Some(status));
            assert_policy(
                &f,
                "rej@test",
                policy,
                &results,
                &events,
                reason,
                RecordingTag::Failed,
            )
            .await;
        }
    }
}

// `recording.rs_invite_timeout_ms` via the timer loop; a 2xx that still
// arrives is ACKed and BYE'd (RFC 3261 §13.2.2.4).
#[tokio::test]
async fn rs_invite_timeout_applies_the_policy() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture_with(policy, |s| s.invite_timeout = std::time::Duration::ZERO).await;
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "to@test").await);
        let results = poll(&f.stack).await;
        assert!(
            to_srs(&results, &Method::Cancel).is_none(),
            "no CANCEL before a provisional (RFC 3261 §9.1)"
        );
        // The late 2xx: ACK + BYE toward the SRS, the fork stays off.
        let late = srs_ok(&f.stack, &inv).await;
        assert!(to_srs(&late, &Method::Ack).is_some(), "{late:?}");
        let bye = to_srs(&late, &Method::Bye).expect("BYE for the unwanted RS dialog");
        assert_eq!(bye.headers.call_id(), inv.headers.call_id());
        assert_eq!(f.media.count("activate"), 0);
        let events = capture.events();
        assert_policy(
            &f,
            "to@test",
            policy,
            &results,
            &events,
            RecordingFailReason::SrsTimeout,
            RecordingTag::Failed,
        )
        .await;
        assert!(
            poll(&f.stack)
                .await
                .iter()
                .all(|r| !matches!(r, ProcessResult::Forward {
            message: SipMessage::Request(q), .. } if q.method == Method::Bye))
        );
    }
}

// Timer B on the RS INVITE (RFC 3261 §17.1.1.2) is the same failure.
#[tokio::test]
async fn rs_invite_timer_b_applies_the_policy() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "tb@test").await);
        let id = internal_id(&f.stack, "tb@test").await;
        let branch = inv.headers.via_branch().unwrap();
        let results = f.stack.fail_timed_out_request(&branch, &id).await;
        let events = capture.events();
        assert_policy(
            &f,
            "tb@test",
            policy,
            &results,
            &events,
            RecordingFailReason::SrsTimeout,
            RecordingTag::Failed,
        )
        .await;
    }
}

/// An SRS 2xx built by hand (for defective bodies / headers).
fn srs_2xx(
    invite: &SipRequest,
    extra_headers: &str,
    content_type: Option<&str>,
    body: &str,
) -> Bytes {
    let mut msg = format!(
        "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=srstag\r\nCall-ID: {}\r\n\
         CSeq: 1 INVITE\r\n{extra_headers}",
        invite.headers.get_value(&HeaderName::Via).unwrap(),
        invite.headers.get_value(&HeaderName::From).unwrap(),
        invite.headers.get_value(&HeaderName::To).unwrap(),
        invite.headers.call_id().unwrap(),
    );
    if let Some(ct) = content_type {
        let _ = write!(msg, "Content-Type: {ct}\r\n");
    }
    let _ = write!(msg, "Content-Length: {}\r\n\r\n{body}", body.len());
    Bytes::from(msg)
}

// SI-10: an unusable SRS answer is ACKed, the RS is BYE'd and the policy
// applies; the fork is never activated toward an unvalidated address.
#[tokio::test]
async fn bad_rs_answer_is_acked_byed_and_applies_the_policy() {
    let good = srs_answer_sdp();
    let oversized = format!(
        "{good}{}",
        "a=x:y\r\n".repeat(crate::recording::MAX_RS_ANSWER_BYTES / 7 + 1)
    );
    let cases: Vec<(&str, Option<&str>, String)> = vec![
        ("no body", None, String::new()),
        ("non-SDP body", Some("text/plain"), good.clone()),
        ("oversized body", Some("application/sdp"), oversized),
        (
            "AES-128 answer",
            Some("application/sdp"),
            good.replace("AEAD_AES_256_GCM", "AES_CM_128_HMAC_SHA1_80"),
        ),
        (
            "loopback media address",
            Some("application/sdp"),
            good.replace("198.51.100.7", "127.0.0.1"),
        ),
        (
            "garbage",
            Some("application/sdp"),
            "\u{0}\u{1}garbage".to_string(),
        ),
    ];
    for policy in [REJECT, CONTINUE] {
        for (what, ct, body) in &cases {
            let f = fixture(policy).await;
            let capture = uc_audit::capture::start();
            let inv = rs_invite(&answered(&f.stack, "bad@test").await);
            let mut results = from_srs(&f.stack, &srs_2xx(&inv, "", *ct, body)).await;
            assert!(
                to_srs(&results, &Method::Ack).is_some(),
                "{what}: 2xx is ACKed"
            );
            let queued = poll(&f.stack).await;
            let bye = to_srs(&queued, &Method::Bye).unwrap_or_else(|| panic!("{what}: RS BYE"));
            assert_eq!(bye.headers.to_tag().as_deref(), Some("srstag"));
            assert_eq!(f.media.count("activate"), 0, "{what}");
            assert_eq!(f.media.count("fork-stop"), 1, "{what}");
            results.extend(queued);
            let events = capture.events();
            assert_eq!(failed(&events)[0].sip_status, Some(200), "{what}");
            assert_policy(
                &f,
                "bad@test",
                policy,
                &results,
                &events,
                RecordingFailReason::SrsBadAnswer,
                RecordingTag::Failed,
            )
            .await;
        }
    }
}

// A 2xx without a To tag cannot be ACKed; it is still a bad answer.
#[tokio::test]
async fn rs_2xx_without_to_tag_is_a_bad_answer() {
    let f = fixture(CONTINUE).await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "notag@test").await);
    let results = from_srs(
        &f.stack,
        &response_to(&inv, 200, None, Some(&srs_answer_sdp())),
    )
    .await;
    assert!(to_srs(&results, &Method::Ack).is_none(), "{results:?}");
    assert_eq!(
        failed(&capture.events())[0].reason,
        RecordingFailReason::SrsBadAnswer
    );
    assert_eq!(f.media.count("activate"), 0);
    assert!(call_is_up(&f.stack, "notag@test").await);
}

// RFC-006: the SRS Contact is the in-dialog Request-URI (RFC 3261
// §12.1.2); a sip: Contact is upgraded to sips: keeping user, host and
// port, a garbage one falls back to the configured SRS URI. Either way the
// request goes to the pinned SRS address and flow.
#[tokio::test]
async fn srs_contact_never_redirects_the_recording_session() {
    for (contact, expect_uri) in [
        (
            "Contact: <sips:rec7@198.51.100.99:5099>\r\n",
            "sips:rec7@198.51.100.99:5099",
        ),
        (
            "Contact: <sip:rec7@198.51.100.99:5060;transport=tcp>\r\n",
            "sips:rec7@198.51.100.99:5060",
        ),
        (
            "Contact: \"<<>>garbage sips:\r\n",
            "sips:srs.example.test:5061",
        ),
        (
            "Contact: <tel:+15550001111>\r\n",
            "sips:srs.example.test:5061",
        ),
    ] {
        let f = fixture(REJECT).await;
        let inv = rs_invite(&answered(&f.stack, "ct@test").await);
        let extra = format!(
            "{contact}Record-Route: <sips:edge1.example.test;lr>, <sips:edge2.example.test;lr>\r\n"
        );
        let results = from_srs(
            &f.stack,
            &srs_2xx(&inv, &extra, Some("application/sdp"), &srs_answer_sdp()),
        )
        .await;
        // `to_srs` asserts destination == the pinned SRS and the recorder flow.
        let ack =
            to_srs(&results, &Method::Ack).unwrap_or_else(|| panic!("{contact}: ACK: {results:?}"));
        assert_eq!(ack.uri.to_string(), expect_uri, "{contact}");
        assert_eq!(f.media.count("activate"), 1, "{contact}: still recorded");
        caller_bye(&f.stack, "ct@test").await;
        let bye = to_srs(&poll(&f.stack).await, &Method::Bye).expect("RS BYE");
        assert_eq!(bye.uri.to_string(), expect_uri, "{contact}");
        // RFC 3261 §12.1.2: the route set is the Record-Route reversed.
        let routes: Vec<_> = bye
            .headers
            .get_all(&HeaderName::Route)
            .map(|h| h.value.clone())
            .collect();
        assert_eq!(
            routes,
            vec![
                "<sips:edge2.example.test;lr>",
                "<sips:edge1.example.test;lr>"
            ]
        );
    }
}

// Fork preparation / activation errors and a controller without the fork.
#[tokio::test]
async fn fork_errors_apply_the_policy() {
    for policy in [REJECT, CONTINUE] {
        // prepare fails: no RS INVITE is sent at all.
        let f = fixture(policy).await;
        f.media.fail_prepare.store(true, AtomicOrdering::Relaxed);
        let capture = uc_audit::capture::start();
        let results = answered(&f.stack, "prep@test").await;
        assert!(to_srs(&results, &Method::Invite).is_none());
        assert_policy_as(
            &f,
            "prep@test",
            policy,
            &results,
            &capture.events(),
            (
                RecordingFailReason::ForkSetup,
                RecordingTag::Failed,
                Reject::AtAnswer(503),
            ),
        )
        .await;
        drop(capture);

        // A remote media node (trait default): remote_media_unsupported.
        let f = fixture(policy).await;
        f.media.unsupported.store(true, AtomicOrdering::Relaxed);
        let capture = uc_audit::capture::start();
        let results = answered(&f.stack, "remote@test").await;
        assert!(to_srs(&results, &Method::Invite).is_none());
        assert_policy_as(
            &f,
            "remote@test",
            policy,
            &results,
            &capture.events(),
            (
                RecordingFailReason::RemoteMediaUnsupported,
                RecordingTag::NotRecordable,
                Reject::AtAnswer(488),
            ),
        )
        .await;
        drop(capture);

        // activate fails: ACK + BYE to the SRS; activate is not retried.
        let f = fixture(policy).await;
        f.media.fail_activate.store(true, AtomicOrdering::Relaxed);
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "act@test").await);
        let mut results = srs_ok(&f.stack, &inv).await;
        assert!(to_srs(&results, &Method::Ack).is_some());
        let queued = poll(&f.stack).await;
        assert!(to_srs(&queued, &Method::Bye).is_some(), "RS BYE");
        results.extend(queued);
        srs_ok(&f.stack, &inv).await;
        assert_eq!(f.media.count("activate"), 0, "no retry");
        assert_policy(
            &f,
            "act@test",
            policy,
            &results,
            &capture.events(),
            RecordingFailReason::ForkSetup,
            RecordingTag::Failed,
        )
        .await;
    }
}

const SAVP_OFFER: &str = "v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\n\
    m=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n";
const SAVP_ANSWER: &str = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
    m=audio 5000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n";

/// Places a call with `offer` that the INVITE alone shows to be
/// unrecordable. Under `reject` it must be refused there (RFC-001 a);
/// under `continue` it is answered with `answer` and stays up unrecorded.
async fn assert_refused_at_invite(
    f: &Fixture,
    call_id: &str,
    policy: RecordingFailureAction,
    offer: Option<&str>,
    answer: &str,
) {
    let capture = uc_audit::capture::start();
    let placed = flatten(
        f.stack
            .process_message(
                &caller_request("INVITE", DIALED, call_id, 1, None, offer),
                alice(),
                None,
            )
            .await,
    );
    let results = if policy == REJECT {
        assert_eq!(active(&f.stack, "t1").await, 0, "trunk slot released");
        placed
    } else {
        let results = answer_with(&f.stack, &placed, answer).await;
        assert!(responded(&results, 200).is_some(), "call answered");
        results
    };
    assert!(to_srs(&results, &Method::Invite).is_none(), "no RS INVITE");
    assert_eq!(f.media.count("prepare"), 0, "no fork");
    assert_policy_as(
        f,
        call_id,
        policy,
        &results,
        &capture.events(),
        (
            RecordingFailReason::MediaNotRecordable,
            RecordingTag::NotRecordable,
            Reject::AtInvite(488),
        ),
    )
    .await;
}

// POA&M-301: media the SBC cannot read (SDES passthrough) is never forked;
// the call is "not recordable" and obeys the policy. RFC-001 (a): the offer
// alone decides this, so under `reject` the INVITE is refused with 488 and
// a Warning before the B-leg is dialled (and the CDR carries the recording
// tag, NIST-010).
#[tokio::test]
async fn srtp_passthrough_call_is_not_recordable() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        assert_refused_at_invite(&f, "savp@test", policy, Some(SAVP_OFFER), SAVP_ANSWER).await;
    }
}

// No in-process media pipeline at all: not recordable, known at INVITE.
#[tokio::test]
async fn call_without_a_media_relay_is_not_recordable() {
    let (mut stack, cdr) = cdr_stack().await;
    stack.set_recording(settings(REJECT));
    let f = Fixture {
        stack,
        media: Arc::new(ForkMedia::default()),
        cdr,
    };
    assert_refused_at_invite(&f, "norelay@test", REJECT, Some(ALICE_SDP), BOB_SDP).await;
}

// SEC-006: an offer that announces ZRTP is refused at INVITE; ZRTP that
// first shows in the answer is refused there.
#[tokio::test]
async fn zrtp_call_is_not_recordable() {
    const HASH: &str =
        "a=zrtp-hash:1.10 fe30efd02423cb054e50efd0248742ac7a52c8f91bc2df881ae642c371ba46df\r\n";
    let offer = format!("{ALICE_SDP}{HASH}");
    let answer = format!("{BOB_SDP}{HASH}");
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        assert_refused_at_invite(&f, "zrtp-o@test", policy, Some(&offer), BOB_SDP).await;

        let f = fixture(policy).await;
        let capture = uc_audit::capture::start();
        let placed = place_call(&f.stack, "zrtp-a@test").await;
        let results = answer_with(&f.stack, &placed, &answer).await;
        assert!(to_srs(&results, &Method::Invite).is_none());
        assert_eq!(f.media.count("prepare"), 0, "no fork for ZRTP media");
        assert_policy_as(
            &f,
            "zrtp-a@test",
            policy,
            &results,
            &capture.events(),
            (
                RecordingFailReason::MediaNotRecordable,
                RecordingTag::NotRecordable,
                Reject::AtAnswer(488),
            ),
        )
        .await;
    }
}

// RFC-001 (b): what only the callee's answer shows (here opportunistic
// SRTP, `a=crypto` on RTP/AVP, accepted by the callee) is found at the
// 2xx. Under `reject` the 2xx is not relayed: the caller gets 488 with a
// Warning on its INVITE transaction, the callee ACK + BYE, the relay is
// stopped, and no 2xx retransmission is armed. A retransmitted 2xx from
// the callee is still ACKed.
#[tokio::test]
async fn answer_dependent_unrecordable_call_is_refused_before_the_200_is_relayed() {
    const CRYPTO: &str =
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n";
    let offer = format!("{ALICE_SDP}{CRYPTO}");
    let answer = format!("{BOB_SDP}{CRYPTO}");
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        let capture = uc_audit::capture::start();
        let placed = flatten(
            f.stack
                .process_message(
                    &caller_request("INVITE", DIALED, "osrtp@test", 1, None, Some(&offer)),
                    alice(),
                    None,
                )
                .await,
        );
        let b_invite = forwarded(&placed, &Method::Invite)
            .expect("the offer alone does not rule the call out")
            .0
            .clone();
        assert_eq!(f.stack.recording_counters().slots_held(), 1);
        let results = answer_with(&f.stack, &placed, &answer).await;
        assert!(to_srs(&results, &Method::Invite).is_none(), "no RS INVITE");
        assert_eq!(f.media.count("prepare"), 0, "no fork for ciphertext");
        if policy == REJECT {
            assert_eq!(f.media.count("stop-relay"), 1, "the relay is stopped");
            // The callee's dialog is ended in its own CSeq space.
            let (bye, _) = forwarded(&results, &Method::Bye).unwrap();
            assert_eq!(bye.headers.call_id(), b_invite.headers.call_id());
            assert_eq!(bye.headers.to_tag().as_deref(), Some("bobtag"));
            assert_eq!(active(&f.stack, "t1").await, 0, "trunk slot released");
            // A retransmitted 2xx (the ACK was lost) is ACKed again.
            let again = flatten(
                f.stack
                    .process_message(
                        &response_to(&b_invite, 200, Some("bobtag"), Some(&answer)),
                        t1(),
                        None,
                    )
                    .await,
            );
            assert!(forwarded(&again, &Method::Ack).is_some(), "{again:?}");
            assert!(responded(&again, 200).is_none(), "never relayed");
        }
        assert_policy_as(
            &f,
            "osrtp@test",
            policy,
            &results,
            &capture.events(),
            (
                RecordingFailReason::MediaNotRecordable,
                RecordingTag::NotRecordable,
                Reject::AtAnswer(488),
            ),
        )
        .await;
    }
}

// RFC-001 (c), RFC 3261 §15 / §13.3.1.4: a recording failure after the 2xx
// was relayed tears the call down, but the caller's BYE never precedes the
// caller's ACK. Until the ACK the 2xx keeps being retransmitted; the BYE
// goes out with the ACK, or when the retransmission gives up after 64*T1.
#[tokio::test]
async fn caller_bye_is_held_until_the_caller_acks_the_200() {
    for acked in [true, false] {
        let f = fixture(REJECT).await;
        let capture = uc_audit::capture::start();
        let placed = place_call(&f.stack, "hold@test").await;
        let answered = answer_with(&f.stack, &placed, BOB_SDP).await;
        assert!(responded(&answered, 200).is_some());
        let inv = SipMessage::Request(rs_invite(&answered));

        // The RS INVITE cannot be sent while the caller has not ACKed yet.
        let results = f.stack.on_invite_sent_with(&inv, false, false).await;
        assert_eq!(
            leg_byes(&results),
            vec![t1()],
            "the callee is BYE'd at once, the caller is not: {results:?}"
        );
        assert!(!call_is_up(&f.stack, "hold@test").await, "call released");
        assert_eq!(f.media.count("stop-relay"), 1, "media stopped at once");
        let c = one_cdr(&f.cdr);
        assert_eq!(c.disposition, uc_cdr::Disposition::RecordingFailure);
        assert_eq!(c.recording, Some(RecordingTag::Failed));
        assert_eq!(failed(&capture.events()).len(), 1);

        // The 2xx is still retransmitted (the caller may not have it).
        assert_eq!(f.stack.pending_2xx.read().await.len(), 1);
        for p in f.stack.pending_2xx.write().await.values_mut() {
            p.next_at = Instant::now();
        }
        let tick = poll(&f.stack).await;
        assert!(
            responded(&tick, 200).is_some(),
            "2xx retransmitted: {tick:?}"
        );
        assert!(leg_byes(&tick).is_empty(), "still no BYE: {tick:?}");

        let released = if acked {
            let released = caller_ack(&f.stack, "hold@test").await;
            assert!(
                caller_ack(&f.stack, "hold@test").await.is_empty(),
                "a repeated ACK releases nothing more"
            );
            released
        } else {
            // 64*T1 without an ACK.
            for p in f.stack.pending_2xx.write().await.values_mut() {
                p.deadline = Instant::now();
            }
            poll(&f.stack).await
        };
        assert_eq!(leg_byes(&released), vec![alice()], "{released:?}");
        let (bye, _) = forwarded(&released, &Method::Bye).unwrap();
        assert_eq!(bye.headers.call_id(), Some("hold@test"));
        assert_eq!(bye.headers.from_tag().as_deref(), Some("bobtag"));
        // The released BYE rides a client transaction like any other.
        assert!(
            f.stack
                .transactions
                .read()
                .await
                .client_non_invite
                .values()
                .any(|st| matches!(&st.request, SipMessage::Request(r)
                    if r.method == Method::Bye && r.headers.call_id() == Some("hold@test")))
        );
        assert!(f.stack.pending_2xx.read().await.is_empty());
        assert!(leg_byes(&poll(&f.stack).await).is_empty(), "sent once");
        assert_recording_released(&f).await;
    }
}

/// A recording stack (`reject`) whose route is a route list over two trunk
/// groups: "carriers" (t1) first, then "backup" (t2). A call that fails on
/// t1 fails over across groups to t2.
async fn cross_group_fixture(tweak: impl FnOnce(&mut RecordingSettings)) -> Fixture {
    let mut stack = SipStack::new(SipStackConfig::default());
    let (routing, dial_plans, mut groups) = carrier_routing(10, ("none", ""), ["udp", "udp"]);
    let t2 = groups[0].trunks.pop().unwrap();
    let mut backup = groups[0].clone();
    backup.id = "backup".to_string();
    backup.name = "Backup".to_string();
    backup.trunks = vec![t2];
    groups.push(backup);
    stack.init_router_from_config(&routing, &dial_plans, &groups);

    let mut sbc = uc_routing::SbcRouter::new();
    sbc.add_partition(uc_routing::Partition::new("pt", "Pt"));
    let mut list = uc_routing::RouteList::new("rl", "Rl");
    list.add_member(uc_routing::RouteListMember::new("carriers", 1));
    list.add_member(uc_routing::RouteListMember::new("backup", 2));
    sbc.add_route_list(list);
    sbc.add_route_pattern(
        uc_routing::RoutePattern::new("rp", DialPattern::prefix("+1"), "pt").with_route_list("rl"),
    );
    let mut css = uc_routing::CallingSearchSpace::new("css", "Css");
    css.add_partition("pt");
    sbc.add_css(css);
    sbc.set_default_css("css");
    stack.set_sbc_router(Arc::new(RwLock::new(sbc)));
    stack
        .register_inbound_trunk("pbx", None, &[("192.168.1.1".to_string(), 5060)])
        .await;
    let cdr = cdr_emitter();
    stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
        Arc::clone(&cdr),
        &sbc_config::schema::CdrConfig::default(),
    )));
    let media = Arc::new(ForkMedia::default());
    stack.set_media_pipeline(Arc::clone(&media) as _);
    let mut s = settings(REJECT);
    tweak(&mut s);
    stack.set_recording(s);
    Fixture { stack, media, cdr }
}

// SEC-001 / NIST-001 (AU-14): the trunk-group trigger is evaluated against
// every trunk the call may use. A call whose first trunk is in an unlisted
// group but whose failover target is in a listed one is matched at INVITE,
// so after the failover it is recorded (or goes through the policy), never
// silently unrecorded.
#[tokio::test]
async fn trigger_covers_failover_targets() {
    for (listed, recorded) in [("backup", true), ("carriers", true), ("other", false)] {
        let f = cross_group_fixture(|s| {
            s.record_all = false;
            s.trunk_groups = vec![listed.to_string()];
        })
        .await;
        let placed = place_call(&f.stack, "failover@test").await;
        assert_eq!(
            forwarded(&placed, &Method::Invite).map(|(_, dest)| dest),
            Some(t1()),
            "first attempt on the carriers group"
        );
        assert_eq!(
            recording_of(&f.stack, "failover@test").await.matched,
            recorded,
            "{listed}"
        );
        assert_eq!(
            f.stack.recording_counters().slots_held(),
            usize::from(recorded),
            "{listed}"
        );
        // t1 fails with 503: the call fails over to t2.
        let inv = forwarded(&placed, &Method::Invite).unwrap().0.clone();
        let failed_over = flatten(
            f.stack
                .process_message(&response_to(&inv, 503, Some("t1tag"), None), t1(), None)
                .await,
        );
        let (inv2, dest) = forwarded(&failed_over, &Method::Invite)
            .unwrap_or_else(|| panic!("{listed}: failover INVITE: {failed_over:?}"));
        assert_eq!(dest, t2(), "{listed}");
        let results = flatten(
            f.stack
                .process_message(
                    &response_to(inv2, 200, Some("bobtag"), Some(BOB_SDP)),
                    t2(),
                    None,
                )
                .await,
        );
        assert!(responded(&results, 200).is_some(), "{listed}");
        assert_eq!(
            to_srs(&results, &Method::Invite).is_some(),
            recorded,
            "{listed}: the call on the failover trunk is recorded"
        );
        caller_bye(&f.stack, "failover@test").await;
        assert_eq!(f.stack.recording_counters().slots_held(), 0, "{listed}");
        assert!(f.stack.call_correlation.read().await.rs_leg.is_empty());
        let c = one_cdr(&f.cdr);
        assert_eq!(c.recording.is_some(), recorded, "{listed}: CDR tag");
    }
}

// 47 CFR 9.16 / Q5: an emergency call is never torn down for a recording
// failure, even under `reject`; it continues unrecorded and is audited.
#[tokio::test]
async fn emergency_call_survives_recording_failure_under_reject() {
    let f = fixture(REJECT).await;
    let capture = uc_audit::capture::start();
    let placed = place_call_to(&f.stack, "911", "e911@test").await;
    let inv = SipMessage::Request(rs_invite(&answer_with(&f.stack, &placed, BOB_SDP).await));
    let results = f.stack.on_invite_sent_with(&inv, false, false).await;
    assert_no_leg_bye(&results);
    assert!(
        call_is_up(&f.stack, "e911@test").await,
        "emergency call kept"
    );
    let fails = failed(&capture.events());
    assert_eq!(fails.len(), 1);
    assert_eq!(fails[0].action, RecordingFailAction::EmergencyContinued);
    assert_eq!(fails[0].reason, RecordingFailReason::SrsUnreachable);
    assert_eq!(f.stack.recording_counters().calls_rejected(), 0);
    assert_eq!(f.stack.recording_counters().slots_held(), 0);
    let bye = caller_request("BYE", "911", "e911@test", 2, Some("bobtag"), None);
    f.stack.process_message(&bye, alice(), None).await;
    let c = one_cdr(&f.cdr);
    assert!(c.emergency);
    assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
    assert_eq!(c.recording, Some(RecordingTag::Failed));
}

// ----------------------------------------------------------------------
// max_sessions (SC-5)
// ----------------------------------------------------------------------

// No free slot: 503 before the B-leg is dialled under `reject`; the slot
// comes back when the recorded call ends.
#[tokio::test]
async fn max_sessions_refuses_the_next_call_under_reject() {
    let f = fixture_with(REJECT, |s| s.max_sessions = 1).await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "slot-1@test").await);
    srs_ok(&f.stack, &inv).await;
    assert_eq!(f.stack.recording_counters().slots_held(), 1);

    let second = place_call(&f.stack, "slot-2@test").await;
    let (resp, dest) = responded(&second, 503).expect("503 to the caller");
    assert_eq!(dest, alice());
    assert!(resp.headers.get_value(&HeaderName::RetryAfter).is_some());
    assert!(
        forwarded(&second, &Method::Invite).is_none(),
        "the B-leg is not dialled"
    );
    assert!(!call_is_up(&f.stack, "slot-2@test").await);
    assert_eq!(
        active(&f.stack, "t1").await,
        1,
        "its trunk slot was released"
    );
    let fails = failed(&capture.events());
    assert_eq!(fails.len(), 1);
    assert_eq!(fails[0].reason, RecordingFailReason::NoSessionSlot);
    assert_eq!(fails[0].action, RecordingFailAction::CallRejected);
    assert_eq!(fails[0].recording_session_id, None);
    assert_eq!(f.stack.recording_counters().calls_rejected(), 1);
    // NIST-010: the reject CDR of a matched call carries the recording tag.
    let rejected = cdrs(&f.cdr)
        .into_iter()
        .find(|c| c.a_call_id == "slot-2@test")
        .expect("reject CDR");
    assert_eq!(rejected.disposition, uc_cdr::Disposition::Rejected);
    assert_eq!(rejected.final_sip_status, 503);
    assert_eq!(
        rejected.release_cause,
        uc_cdr::ReleaseCause::RecordingFailure
    );
    assert_eq!(rejected.recording, Some(RecordingTag::NotRecordable));

    // An emergency call is admitted without a slot, unrecorded.
    let e = place_call_to(&f.stack, "911", "slot-e@test").await;
    assert!(
        forwarded(&e, &Method::Invite).is_some(),
        "emergency call routed"
    );
    let e_results = answer_with(&f.stack, &e, BOB_SDP).await;
    assert!(to_srs(&e_results, &Method::Invite).is_none());
    assert_eq!(
        failed(&capture.events())[1].action,
        RecordingFailAction::EmergencyContinued
    );
    let bye = caller_request("BYE", "911", "slot-e@test", 2, Some("bobtag"), None);
    f.stack.process_message(&bye, alice(), None).await;

    // The first call ends: the slot is free again.
    caller_bye(&f.stack, "slot-1@test").await;
    assert_eq!(f.stack.recording_counters().slots_held(), 0);
    let third = answered(&f.stack, "slot-3@test").await;
    assert!(to_srs(&third, &Method::Invite).is_some(), "slot reused");
    caller_bye(&f.stack, "slot-3@test").await;
    let tags: Vec<_> = cdrs(&f.cdr)
        .iter()
        .map(|c| (c.a_call_id.clone(), c.recording, c.release_cause))
        .collect();
    assert!(
        tags.contains(&(
            "slot-e@test".to_string(),
            Some(RecordingTag::NotRecordable),
            uc_cdr::ReleaseCause::Normal
        )),
        "{tags:?}"
    );
    assert_recording_released(&f).await;
}

// Under `continue` the call without a slot proceeds unrecorded.
#[tokio::test]
async fn max_sessions_continues_unrecorded_under_continue() {
    let f = fixture_with(CONTINUE, |s| s.max_sessions = 1).await;
    let capture = uc_audit::capture::start();
    rs_invite(&answered(&f.stack, "c-1@test").await);
    let second = answered(&f.stack, "c-2@test").await;
    assert!(responded(&second, 200).is_some(), "second call answered");
    assert!(
        to_srs(&second, &Method::Invite).is_none(),
        "but not recorded"
    );
    let fails = failed(&capture.events());
    assert_eq!(fails.len(), 1);
    assert_eq!(fails[0].reason, RecordingFailReason::NoSessionSlot);
    assert_eq!(fails[0].action, RecordingFailAction::ContinuedUnrecorded);
    assert_eq!(
        recording_of(&f.stack, "c-2@test").await.tag,
        Some(RecordingTag::NotRecordable)
    );
    assert_eq!(f.stack.recording_counters().slots_held(), 1);
    caller_bye(&f.stack, "c-1@test").await;
    caller_bye(&f.stack, "c-2@test").await;
    assert_recording_released(&f).await;
}

// A matched call that never gets answered gives its slot back and carries
// no recording outcome.
#[tokio::test]
async fn unanswered_call_releases_its_slot() {
    let f = fixture_with(REJECT, |s| s.max_sessions = 1).await;
    place_call(&f.stack, "cancel@test").await;
    assert_eq!(f.stack.recording_counters().slots_held(), 1);
    let cancel = caller_request("CANCEL", DIALED, "cancel@test", 1, None, None);
    f.stack.process_message(&cancel, alice(), None).await;
    assert_eq!(f.stack.recording_counters().slots_held(), 0);
    let c = one_cdr(&f.cdr);
    assert_eq!(c.recording, None);
    assert_eq!(c.recording_session_id, None);
}

// ----------------------------------------------------------------------
// Call end while the RS is still being set up
// ----------------------------------------------------------------------

// The call ends before the SRS answers: the late 2xx gets ACK + BYE
// (RFC 3261 §13.2.2.4) and, once a provisional was seen, a CANCEL (§9.1).
#[tokio::test]
async fn call_end_while_rs_invite_pending_cancels_and_tears_down_late_2xx() {
    let f = fixture(REJECT).await;
    let capture = uc_audit::capture::start();
    let inv = rs_invite(&answered(&f.stack, "pend@test").await);
    from_srs(&f.stack, &response_to(&inv, 180, Some("srstag"), None)).await;
    caller_bye(&f.stack, "pend@test").await;

    let queued = poll(&f.stack).await;
    let cancel = to_srs(&queued, &Method::Cancel).expect("CANCEL after a provisional");
    assert_eq!(cancel.headers.via_branch(), inv.headers.via_branch());
    assert_eq!(cancel.headers.cseq(), Some("1 CANCEL"));
    assert_eq!(cancel.uri, inv.uri);
    assert!(to_srs(&queued, &Method::Bye).is_none());

    let late = srs_ok(&f.stack, &inv).await;
    assert!(to_srs(&late, &Method::Ack).is_some(), "{late:?}");
    assert!(to_srs(&late, &Method::Bye).is_some(), "{late:?}");
    assert_eq!(f.media.count("activate"), 0);

    let events = capture.events();
    assert!(started(&events).is_empty() && stopped(&events).is_empty());
    let fails = failed(&events);
    assert_eq!(fails.len(), 1);
    // NIST-005: not an SRS failure and not a policy decision, even under
    // `reject`.
    assert_eq!(fails[0].reason, RecordingFailReason::CallEndedDuringSetup);
    assert_eq!(fails[0].action, RecordingFailAction::CallAlreadyEnded);
    assert_eq!(
        f.stack
            .recording_counters()
            .failed(RecordingFailReason::SrsTimeout),
        0
    );
    assert_eq!(f.stack.recording_counters().calls_rejected(), 0);
    let c = one_cdr(&f.cdr);
    assert_eq!(
        c.disposition,
        uc_cdr::Disposition::Answered,
        "ended by the caller"
    );
    assert_eq!(c.recording, Some(RecordingTag::Failed));
    assert!(c.recording_session_id.is_some());
    assert_recording_released(&f).await;
}

// ----------------------------------------------------------------------
// Requests from the SRS (SC-23, POA&M-308)
// ----------------------------------------------------------------------

// SRS BYE mid-call: answered 200, then the policy applies. The recording
// covered part of the call: stopped (srs_bye) + failed, CDR `partial`.
#[tokio::test]
async fn srs_bye_mid_call_applies_the_policy() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        let capture = uc_audit::capture::start();
        let inv = rs_invite(&answered(&f.stack, "sbye@test").await);
        srs_ok(&f.stack, &inv).await;
        let results = from_srs(&f.stack, &srs_request(&inv, "BYE", "srstag")).await;
        let (ok, dest) = responded(&results, 200).expect("200 to the SRS BYE");
        assert_eq!(dest, srs());
        assert_eq!(ok.headers.cseq(), Some("7 BYE"));
        assert!(to_srs(&results, &Method::Bye).is_none(), "no BYE back");
        assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_none());
        assert_eq!(f.media.count("fork-stop"), 1);
        let events = capture.events();
        let st = stopped(&events);
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].reason, RecordingStopReason::SrsBye);
        assert_policy(
            &f,
            "sbye@test",
            policy,
            &results,
            &events,
            RecordingFailReason::SrsBye,
            RecordingTag::Partial,
        )
        .await;
    }
}

// A BYE with the wrong tag, from another source, or not over TLS is 481
// and changes nothing.
#[tokio::test]
async fn forged_srs_bye_is_481() {
    let f = fixture(REJECT).await;
    let inv = rs_invite(&answered(&f.stack, "forge@test").await);
    srs_ok(&f.stack, &inv).await;
    let other = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 66), 5061);
    let good = srs_request(&inv, "BYE", "srstag");
    let attempts = [
        (
            srs_request(&inv, "BYE", "wrongtag"),
            srs(),
            AddrTransport::Tls,
            "wrong tag",
        ),
        (good.clone(), other, AddrTransport::Tls, "another source"),
        (good.clone(), srs(), AddrTransport::Udp, "not TLS"),
    ];
    for (i, (data, source, transport, what)) in attempts.into_iter().enumerate() {
        // A fresh branch per attempt (each is a new request).
        let data = Bytes::from(
            String::from_utf8(data.to_vec())
                .unwrap()
                .replace("z9hG4bK-srs-BYE", &format!("z9hG4bK-forged-{i}")),
        );
        let results = flatten(
            f.stack
                .process_message_on(&data, source, None, transport)
                .await,
        );
        assert!(responded(&results, 481).is_some(), "{what}: {results:?}");
        assert_eq!(results.len(), 1, "{what}");
        assert!(call_is_up(&f.stack, "forge@test").await, "{what}");
        assert!(
            recording_of(&f.stack, "forge@test").await.leg.is_some(),
            "{what}: still recording"
        );
    }
    // A BYE before the RS dialog is established is 481 too.
    let f = fixture(REJECT).await;
    let inv = rs_invite(&answered(&f.stack, "early@test").await);
    let results = from_srs(&f.stack, &srs_request(&inv, "BYE", "srstag")).await;
    assert!(responded(&results, 481).is_some(), "{results:?}");
    assert!(call_is_up(&f.stack, "early@test").await);
}

// POA&M-308 / RFC-008: an SRS re-INVITE gets 488 with a Warning (RFC 3261
// §14.2, §20.43); OPTIONS is answered with Allow; UPDATE and other methods
// are 405 with Allow (§21.4.6). None of them reaches the B2BUA handlers.
#[tokio::test]
async fn srs_reinvite_gets_488_and_update_405() {
    const ALLOW: &str = "INVITE, ACK, BYE, CANCEL, OPTIONS";
    let f = fixture(REJECT).await;
    let inv = rs_invite(&answered(&f.stack, "re@test").await);
    assert_eq!(
        inv.headers.get_value(&HeaderName::Allow),
        Some(ALLOW),
        "the RS INVITE says what the SBC accepts in the dialog"
    );
    srs_ok(&f.stack, &inv).await;
    for (method, status, allow, warning) in [
        ("INVITE", 488, false, true),
        ("UPDATE", 405, true, false),
        ("OPTIONS", 200, true, false),
        ("INFO", 405, true, false),
    ] {
        let results = from_srs(&f.stack, &srs_request(&inv, method, "srstag")).await;
        let (resp, _) =
            responded(&results, status).unwrap_or_else(|| panic!("{method}: {results:?}"));
        assert_eq!(
            resp.headers.get_value(&HeaderName::Allow),
            allow.then_some(ALLOW),
            "{method}"
        );
        assert_eq!(
            resp.headers.get_value(&HeaderName::Warning).is_some(),
            warning,
            "{method}"
        );
        assert_eq!(results.len(), 1, "{method}: nothing relayed");
    }
    assert!(call_is_up(&f.stack, "re@test").await);
    assert!(recording_of(&f.stack, "re@test").await.leg.is_some());
    assert_eq!(
        f.stack.call_count().await,
        1,
        "no call created by the SRS INVITE"
    );
}

// ----------------------------------------------------------------------
// Trigger, opt-out
// ----------------------------------------------------------------------

// Trunk group and zone triggers on either leg; no match: no RS and no CDR
// recording field.
#[tokio::test]
async fn trigger_matches_trunk_group_or_zone_of_either_leg() {
    type Tweak = fn(&mut RecordingSettings);
    let cases: [(&str, Tweak, bool); 5] = [
        (
            "egress trunk group",
            |s| s.trunk_groups = vec!["carriers".to_string()],
            true,
        ),
        (
            "ingress trunk group",
            |s| s.trunk_groups = vec!["pbx".to_string()],
            true,
        ),
        ("ingress zone", |s| s.zones = vec!["lan".to_string()], true),
        (
            "other group and zone",
            |s| {
                s.trunk_groups = vec!["other".to_string()];
                s.zones = vec!["dmz".to_string()];
            },
            false,
        ),
        ("nothing listed", |_| {}, false),
    ];
    for (what, tweak, recorded) in cases {
        let f = fixture_with(REJECT, |s| {
            s.record_all = false;
            tweak(s);
        })
        .await;
        let capture = uc_audit::capture::start();
        let placed = flatten(
            f.stack
                .process_message(
                    &caller_request("INVITE", DIALED, "trig@test", 1, None, Some(ALICE_SDP)),
                    alice(),
                    Some("lan"),
                )
                .await,
        );
        let results = answer_with(&f.stack, &placed, BOB_SDP).await;
        assert_eq!(
            to_srs(&results, &Method::Invite).is_some(),
            recorded,
            "{what}"
        );
        assert_eq!(
            recording_of(&f.stack, "trig@test").await.matched,
            recorded,
            "{what}"
        );
        caller_bye(&f.stack, "trig@test").await;
        let c = one_cdr(&f.cdr);
        if recorded {
            assert_eq!(
                c.recording,
                Some(RecordingTag::Failed),
                "{what}: RS never answered"
            );
        } else {
            assert_eq!(c.recording, None, "{what}: field absent");
            assert_eq!(c.recording_session_id, None, "{what}");
            let events = capture.events();
            assert!(
                failed(&events).is_empty() && skipped(&events) == 0,
                "{what}"
            );
            assert_eq!(f.media.count("prepare"), 0, "{what}");
        }
        assert_recording_released(&f).await;
    }
}

// RFC 7866 §7.1.3 / PT-5: `a=recordpref:off` (and the legacy `never`) in
// the offer or the answer skips recording under `honour`; `ignore` records.
#[tokio::test]
async fn recordpref_opt_out_is_honoured_or_ignored_by_policy() {
    let offer_off = format!("{ALICE_SDP}a=recordpref:off\r\n");
    let answer_never = format!("{BOB_SDP}a=recordpref:never\r\n");
    for (offer, answer, what) in [
        (offer_off.as_str(), BOB_SDP, "caller opts out"),
        (ALICE_SDP, answer_never.as_str(), "callee opts out"),
    ] {
        for policy in [RecordprefPolicy::Honour, RecordprefPolicy::Ignore] {
            let honour = policy == RecordprefPolicy::Honour;
            let f = fixture_with(REJECT, |s| s.honour_recordpref = honour).await;
            let capture = uc_audit::capture::start();
            let placed = flatten(
                f.stack
                    .process_message(
                        &caller_request("INVITE", DIALED, "opt@test", 1, None, Some(offer)),
                        alice(),
                        None,
                    )
                    .await,
            );
            let results = answer_with(&f.stack, &placed, answer).await;
            let events = capture.events();
            if honour {
                assert!(to_srs(&results, &Method::Invite).is_none(), "{what}");
                assert_no_leg_bye(&results);
                assert!(
                    call_is_up(&f.stack, "opt@test").await,
                    "{what}: a skip, not a failure"
                );
                assert_eq!(skipped(&events), 1, "{what}");
                assert!(failed(&events).is_empty(), "{what}");
                assert_eq!(f.stack.recording_counters().slots_held(), 0, "{what}");
                assert_eq!(f.media.count("prepare"), 0, "{what}");
                caller_bye(&f.stack, "opt@test").await;
                assert_eq!(
                    one_cdr(&f.cdr).recording,
                    Some(RecordingTag::OptOut),
                    "{what}"
                );
                let m: HashMap<_, _> = f
                    .stack
                    .recording_counters()
                    .metric_values()
                    .into_iter()
                    .collect();
                assert_eq!(m["sbc_recording_skipped_total"], 1);
            } else {
                assert!(
                    to_srs(&results, &Method::Invite).is_some(),
                    "{what}: recorded anyway"
                );
                assert_eq!(skipped(&events), 0, "{what}");
                caller_bye(&f.stack, "opt@test").await;
            }
            assert_recording_released(&f).await;
        }
    }
}

// ----------------------------------------------------------------------
// T.38 switch on a recorded call (plan §1.6)
// ----------------------------------------------------------------------

async fn t38_fixture(policy: RecordingFailureAction) -> (Fixture, SipRequest) {
    let mut f = fixture(policy).await;
    f.stack.set_t38_config(t38_enabled());
    let inv = rs_invite(&answered(&f.stack, "fax@test").await);
    srs_ok(&f.stack, &inv).await;
    f.stack
        .process_message(
            &caller_request("ACK", DIALED, "fax@test", 1, Some("bobtag"), None),
            alice(),
            None,
        )
        .await;
    (f, inv)
}

// Under `reject` the switch is refused locally with 488 and the recording
// goes on (RFC 3261 §14.2: the session is unchanged).
#[tokio::test]
async fn t38_switch_on_recorded_call_is_refused_under_reject() {
    let (f, _inv) = Box::pin(t38_fixture(REJECT)).await;
    let capture = uc_audit::capture::start();
    let results = flatten(
        f.stack
            .process_message(
                &caller_request(
                    "INVITE",
                    DIALED,
                    "fax@test",
                    2,
                    Some("bobtag"),
                    Some(ALICE_T38),
                ),
                alice(),
                None,
            )
            .await,
    );
    let (resp, dest) = responded(&results, 488).expect("488 to the offerer");
    assert_eq!(dest, alice());
    let warning = resp.headers.get_value(&HeaderName::Warning).unwrap();
    assert!(warning.starts_with("304 "), "{warning}");
    assert!(
        forwarded(&results, &Method::Invite).is_none(),
        "not relayed"
    );
    let sw = switchovers(&capture.events());
    assert_eq!(sw.len(), 1);
    assert_eq!(sw[0].reason, Some(SwitchoverReason::RecordingActive));
    assert_eq!(sw[0].outcome, SwitchoverOutcome::RejectedLocal);
    let rec = recording_of(&f.stack, "fax@test").await;
    assert!(rec.leg.is_some(), "still recording");
    assert_eq!(rec.tag, Some(RecordingTag::Recorded));
    assert_eq!(call_kind(&f.stack).await, crate::t38::CallMediaKind::Audio);
}

// Under `continue` the switch goes through and the recording ends:
// recording_stopped (media_not_recordable), RS BYE, CDR `partial`.
#[tokio::test]
async fn t38_switch_on_recorded_call_ends_the_recording_under_continue() {
    let (f, inv) = Box::pin(t38_fixture(CONTINUE)).await;
    let capture = uc_audit::capture::start();
    let results = flatten(
        f.stack
            .process_message(
                &caller_request(
                    "INVITE",
                    DIALED,
                    "fax@test",
                    2,
                    Some("bobtag"),
                    Some(ALICE_T38),
                ),
                alice(),
                None,
            )
            .await,
    );
    let (reinvite, _) = forwarded(&results, &Method::Invite).expect("T.38 offer relayed");
    let reinvite = reinvite.clone();
    let results = flatten(
        f.stack
            .process_message(
                &response_to(&reinvite, 200, Some("bobtag"), Some(BOB_T38)),
                t1(),
                None,
            )
            .await,
    );
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert_eq!(call_kind(&f.stack).await, crate::t38::CallMediaKind::Image);
    let bye = to_srs(&poll(&f.stack).await, &Method::Bye).expect("RS BYE");
    assert_eq!(bye.headers.call_id(), inv.headers.call_id());
    assert_eq!(f.media.count("fork-stop"), 1);
    let events = capture.events();
    let st = stopped(&events);
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].reason, RecordingStopReason::MediaNotRecordable);
    assert!(failed(&events).is_empty());
    let rec = recording_of(&f.stack, "fax@test").await;
    assert!(rec.leg.is_none());
    assert_eq!(rec.tag, Some(RecordingTag::Partial));
    assert_eq!(f.stack.recording_counters().slots_held(), 0);
    assert!(call_is_up(&f.stack, "fax@test").await);
    f.stack
        .process_message(
            &caller_request("BYE", DIALED, "fax@test", 3, Some("bobtag"), None),
            alice(),
            None,
        )
        .await;
    assert!(
        to_srs(&poll(&f.stack).await, &Method::Bye).is_none(),
        "one RS BYE"
    );
    let c = one_cdr(&f.cdr);
    assert_eq!(c.recording, Some(RecordingTag::Partial));
    assert_eq!(
        c.media_kinds,
        vec![uc_cdr::MediaKindTag::Audio, uc_cdr::MediaKindTag::Image]
    );
}

// A recorded cleartext call re-negotiated to SDES SRTP (which the SBC
// passes through unread) stops being recordable: the policy applies, the
// recorder is never sent ciphertext behind a `recorded` CDR. A hold does
// not disturb the recording.
#[tokio::test]
async fn mid_call_switch_to_srtp_passthrough_ends_the_recording() {
    for policy in [REJECT, CONTINUE] {
        let f = fixture(policy).await;
        let inv = rs_invite(&answered(&f.stack, "up@test").await);
        srs_ok(&f.stack, &inv).await;
        f.stack
            .process_message(
                &caller_request("ACK", DIALED, "up@test", 1, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;
        // Hold (still RTP/AVP): the recording goes on.
        let hold_offer = ALICE_SDP.replace("a=sendrecv", "a=sendonly");
        let hold_answer = BOB_SDP.replace("a=sendrecv", "a=recvonly");
        let results = flatten(
            f.stack
                .process_message(
                    &caller_request(
                        "INVITE",
                        DIALED,
                        "up@test",
                        2,
                        Some("bobtag"),
                        Some(&hold_offer),
                    ),
                    alice(),
                    None,
                )
                .await,
        );
        let reinvite = forwarded(&results, &Method::Invite).unwrap().0.clone();
        let results = flatten(
            f.stack
                .process_message(
                    &response_to(&reinvite, 200, Some("bobtag"), Some(&hold_answer)),
                    t1(),
                    None,
                )
                .await,
        );
        assert_no_leg_bye(&results);
        assert!(
            recording_of(&f.stack, "up@test").await.leg.is_some(),
            "hold keeps recording"
        );
        f.stack
            .process_message(
                &caller_request("ACK", DIALED, "up@test", 2, Some("bobtag"), None),
                alice(),
                None,
            )
            .await;

        // Upgrade to SDES SRTP.
        let capture = uc_audit::capture::start();
        let results = flatten(
            f.stack
                .process_message(
                    &caller_request(
                        "INVITE",
                        DIALED,
                        "up@test",
                        3,
                        Some("bobtag"),
                        Some(SAVP_OFFER),
                    ),
                    alice(),
                    None,
                )
                .await,
        );
        let reinvite = forwarded(&results, &Method::Invite).unwrap().0.clone();
        let mut results = flatten(
            f.stack
                .process_message(
                    &response_to(&reinvite, 200, Some("bobtag"), Some(SAVP_ANSWER)),
                    t1(),
                    None,
                )
                .await,
        );
        assert!(
            responded(&results, 200).is_some(),
            "the 2xx is still relayed"
        );
        let queued = poll(&f.stack).await;
        assert!(to_srs(&queued, &Method::Bye).is_some(), "RS BYE");
        results.extend(queued);
        if policy == REJECT {
            // RFC 3261 §15: the caller's BYE waits for its ACK of the
            // re-INVITE's 2xx.
            assert_eq!(leg_byes(&results), vec![t1()], "{results:?}");
            results.extend(caller_ack_for(&f.stack, DIALED, "up@test", 3).await);
        }
        assert_eq!(f.media.count("fork-stop"), 1);
        let events = capture.events();
        let st = stopped(&events);
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].reason, RecordingStopReason::MediaNotRecordable);
        let fails = failed(&events);
        assert_eq!(fails.len(), 1);
        assert_eq!(fails[0].reason, RecordingFailReason::MediaNotRecordable);
        assert_eq!(f.stack.recording_counters().slots_held(), 0);
        if policy == REJECT {
            assert_eq!(fails[0].action, RecordingFailAction::CallRejected);
            assert_both_legs_byed(&results);
            let c = one_cdr(&f.cdr);
            assert_eq!(c.disposition, uc_cdr::Disposition::RecordingFailure);
            assert_eq!(c.recording, Some(RecordingTag::Partial));
        } else {
            assert_eq!(fails[0].action, RecordingFailAction::ContinuedUnrecorded);
            assert_no_leg_bye(&results);
            assert!(call_is_up(&f.stack, "up@test").await);
            assert_eq!(
                recording_of(&f.stack, "up@test").await.tag,
                Some(RecordingTag::Partial)
            );
        }
    }
}

// ----------------------------------------------------------------------
// Topology hiding and bounded state
// ----------------------------------------------------------------------

// The RS INVITE is never rewritten by the topology hider (its headers are
// SBC-built; rewriting Contact would drop `+sip.src`), while the BYEs of a
// policy teardown still are hidden on their own legs.
#[tokio::test]
async fn rs_messages_bypass_topology_hiding() {
    let (mut stack, cdr) = cdr_stack().await;
    enable_hider(&mut stack).await;
    let media = Arc::new(ForkMedia::default());
    stack.set_media_pipeline(Arc::clone(&media) as _);
    stack.set_recording(settings(REJECT));
    let f = Fixture { stack, media, cdr };
    let results = answered(&f.stack, "th@test").await;
    let inv = rs_invite(&results);
    assert!(
        inv.headers
            .get_value(&HeaderName::Contact)
            .is_some_and(|c| c.ends_with(">;+sip.src")),
        "Contact kept"
    );
    assert_eq!(inv.headers.get_value(&HeaderName::Require), Some("siprec"));
    assert!(inv.body.as_ref().is_some_and(|b| !b.is_empty()));
    let results = srs_ok(&f.stack, &inv).await;
    assert!(to_srs(&results, &Method::Ack).is_some(), "{results:?}");
    assert_eq!(f.media.count("activate"), 1);
    // SRS BYE under reject: 200 to the SRS, hidden BYEs to both legs.
    let results = from_srs(&f.stack, &srs_request(&inv, "BYE", "srstag")).await;
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert_both_legs_byed(&results);
    for r in &results {
        if let ProcessResult::Forward {
            message: SipMessage::Request(req),
            ..
        } = r
        {
            let via = req.headers.get_value(&HeaderName::Via).unwrap();
            assert!(via.contains(TH_EXTERNAL), "leg BYE is hidden: {via}");
        }
    }
    assert_eq!(
        f.stack
            .routing_counters()
            .topology_hiding_failures
            .load(Ordering::Relaxed),
        0
    );
}

// RFC-016 (fix round 2), SC-7: a teardown BYE held for the caller's ACK is
// topology-hidden exactly once, whichever way it is released. The BYE the
// ACK releases (through the egress pass of the ACK's `process_message`)
// carries the same Via sent-by and Contact as the one sent after 64*T1
// (hidden on the timer path).
#[tokio::test]
async fn held_bye_is_hidden_the_same_on_ack_and_on_timeout() {
    let mut seen = Vec::new();
    for acked in [true, false] {
        let (mut stack, cdr) = cdr_stack().await;
        enable_hider(&mut stack).await;
        let media = Arc::new(ForkMedia::default());
        stack.set_media_pipeline(Arc::clone(&media) as _);
        stack.set_recording(settings(REJECT));
        let f = Fixture { stack, media, cdr };
        let placed = place_call(&f.stack, "th-hold@test").await;
        let answered = answer_with(&f.stack, &placed, BOB_SDP).await;
        assert!(responded(&answered, 200).is_some());
        let inv = SipMessage::Request(rs_invite(&answered));
        let results = f.stack.on_invite_sent_with(&inv, false, false).await;
        assert_eq!(leg_byes(&results), vec![t1()], "{results:?}");

        let released = if acked {
            caller_ack(&f.stack, "th-hold@test").await
        } else {
            for p in f.stack.pending_2xx.write().await.values_mut() {
                p.deadline = Instant::now();
            }
            poll(&f.stack).await
        };
        assert_eq!(leg_byes(&released), vec![alice()], "{released:?}");
        let (bye, _) = forwarded(&released, &Method::Bye).unwrap();
        let vias: Vec<String> = bye
            .headers
            .get_all(&HeaderName::Via)
            .map(|h| {
                // The branch is per transaction; the rest is the hiding.
                h.value
                    .split(";branch=")
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        assert_eq!(vias.len(), 1, "one Via: {vias:?}");
        assert!(vias[0].contains(TH_EXTERNAL), "hidden: {vias:?}");
        let contact = bye
            .headers
            .get_value(&HeaderName::Contact)
            .map(str::to_string);
        seen.push((vias, contact, bye.uri.to_string()));
        assert_eq!(
            f.stack
                .routing_counters()
                .topology_hiding_failures
                .load(Ordering::Relaxed),
            0
        );
    }
    assert_eq!(seen[0], seen[1], "ACK path == 64*T1 path");
}

// NIST-011 (fix round 2), AU-12: an answered call that matched the trigger
// but ends with no recording outcome is `not_recordable` in the CDR and has
// its `recording_failed` record (`media_not_recordable`,
// `call_already_ended`) and count; with an honoured opt-out in its offer it
// is a skip. No signaling sequence leaves a non-opt-out call in this state
// (every answer path records an outcome or a leg), so the state is set up
// directly.
#[tokio::test]
async fn answered_matched_call_without_outcome_is_audited_at_call_end() {
    for opt_out in [false, true] {
        let f = fixture(CONTINUE).await;
        let capture = uc_audit::capture::start();
        answered(&f.stack, "nr@test").await;
        {
            let mut corr = f.stack.call_correlation.write().await;
            let id = corr.a_leg.get("nr@test").cloned().unwrap();
            let a = corr.addresses.get_mut(&id).unwrap();
            let leg = a.recording.leg.take().unwrap();
            a.recording.slot = None;
            a.recording.session_id = None;
            a.recording.opt_out_offer = opt_out;
            assert!(a.recording.matched && a.recording.tag.is_none());
            corr.rs_leg.remove(&leg.call_id);
        }
        let ended = caller_bye(&f.stack, "nr@test").await;
        assert!(responded(&ended, 200).is_some(), "{ended:?}");
        let events = capture.events();
        let c = one_cdr(&f.cdr);
        let counters = f.stack.recording_counters();
        if opt_out {
            assert_eq!(c.recording, Some(RecordingTag::OptOut));
            assert_eq!(skipped(&events), 1);
            assert!(failed(&events).is_empty());
        } else {
            assert_eq!(c.recording, Some(RecordingTag::NotRecordable));
            let failures = failed(&events);
            assert_eq!(failures.len(), 1, "{failures:?}");
            assert_eq!(failures[0].reason, RecordingFailReason::MediaNotRecordable);
            assert_eq!(failures[0].action, RecordingFailAction::CallAlreadyEnded);
            assert_eq!(counters.failed(RecordingFailReason::MediaNotRecordable), 1);
            assert_eq!(skipped(&events), 0);
        }
        assert_eq!(counters.calls_rejected(), 0);
        assert_eq!(counters.slots_held(), 0);
        assert!(to_srs(&poll(&f.stack).await, &Method::Bye).is_none());
    }
}

// SC-5: the RS deadline queue stays bounded by the slot count however many
// short calls come and go.
#[tokio::test]
async fn rs_deadline_queue_is_bounded() {
    let f = fixture_with(CONTINUE, |s| {
        s.max_sessions = 2;
        s.invite_timeout = std::time::Duration::from_secs(3600);
    })
    .await;
    for i in 0..40 {
        let id = format!("dq-{i}@test");
        rs_invite(&answered(&f.stack, &id).await);
        caller_bye(&f.stack, &id).await;
    }
    let len = lock_leaf(&f.stack.rs_deadlines).len();
    assert!(len <= 2 * 2 + 16, "bounded: {len}");
    assert_recording_released(&f).await;
}

// QA additions (real pipeline, Timer B, DTLS-terminated, IPv6, emergency
// matrix, hostile SRS, config keys, log hygiene).
mod qa;
