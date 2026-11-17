//! Shared harness for the DTLS-SRTP call tests: a `CallManager` on a TLS
//! account, scripted SIP messages (as in `media_security_gate.rs`), and an
//! in-process DTLS peer on the address written into the SDP.
//!
//! The DTLS side is not duplicated here: the `proto-dtls` test harness
//! (`dtls`) and the soft client's test peer (`peer`) are included by path.
//!
//! Test-only code: panicking on an unexpected shape is the intended failure
//! mode, and not every test binary uses every helper.
#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

#[path = "../../../../proto/proto-dtls/tests/common/mod.rs"]
pub mod dtls;
#[path = "../../../client-sip-ua/tests/common/peer.rs"]
pub mod peer;

pub use peer::{Peer, hex, opposite};

use client_core::{CallManager, CallManagerEvent, SipTransportKind, build_response_from_request};
use client_sip_ua::CallEvent;
use client_types::{CallEndReason, CallState, SipAccount};
use proto_dtls::CertificateFingerprint;
use proto_sip::header::{Header, HeaderName};
use proto_sip::message::{SipMessage, SipRequest};
use proto_sip::response::StatusCode;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Where the scripted SIP peer "is". Only ever a source address handed to
/// the call manager; nothing is sent there.
pub const SIP_PEER: &str = "192.0.2.50:5061";

pub fn sip_peer() -> SocketAddr {
    SIP_PEER.parse().unwrap()
}

/// A call manager on a TLS-only account with loopback media.
pub fn manager() -> (CallManager, mpsc::Receiver<CallManagerEvent>) {
    let (tx, rx) = mpsc::channel(256);
    let sip: SocketAddr = "127.0.0.1:5061".parse().unwrap();
    let media: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut manager = CallManager::new(sip, media, tx);
    // No microphone or speaker is opened by these tests; the call path up
    // to and including the media-security gate is the production one.
    manager.set_audio_devices_enabled(false);
    // SipAccount::new defaults to TLS-only transport.
    manager.configure_account(&SipAccount::new(
        "test-account",
        "Test User",
        "sips:testuser@example.com",
        "sips:192.0.2.1:5061",
    ));
    (manager, rx)
}

pub fn drain(rx: &mut mpsc::Receiver<CallManagerEvent>) -> Vec<CallManagerEvent> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// The remote's DTLS-SRTP audio SDP: media at `media`, certificate
/// `fingerprint`, `a=setup:<setup>`, rtcp-mux, no ICE.
pub fn remote_sdp(media: SocketAddr, fingerprint: &CertificateFingerprint, setup: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
         a=fingerprint:{fp}\r\na=setup:{setup}\r\na=rtcp-mux\r\na=sendrecv\r\n",
        ip = media.ip(),
        port = media.port(),
        fp = fingerprint.to_sdp(),
    )
}

/// Our media address and certificate fingerprint as our own SDP states
/// them (what a real peer would learn from signalling).
pub fn local_media(sdp: &str) -> (SocketAddr, CertificateFingerprint) {
    let line = |prefix: &str| {
        sdp.lines()
            .map(str::trim_end)
            .find_map(|l| l.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("no {prefix} line in {sdp}"))
    };
    let ip = line("c=IN IP4 ");
    let port = line("m=audio ").split(' ').next().unwrap();
    let addr = format!("{ip}:{port}").parse().unwrap();
    let fingerprint = CertificateFingerprint::from_sdp_strict(line("a=fingerprint:")).unwrap();
    (addr, fingerprint)
}

/// Places a call and returns its ID and the INVITE the call agent queued.
pub async fn place_call(manager: &mut CallManager) -> (String, SipRequest) {
    let call_id = manager
        .make_call(&format!("sips:bob@{SIP_PEER}"))
        .await
        .unwrap();
    let invite = manager
        .poll_call_events()
        .into_iter()
        .find_map(|e| match e {
            CallEvent::SendRequest { request, .. } if request.method.as_str() == "INVITE" => {
                Some(request)
            }
            _ => None,
        })
        .expect("INVITE queued");
    (call_id, invite)
}

pub fn body_of(request: &SipRequest) -> String {
    String::from_utf8_lossy(request.body.as_ref().expect("SDP body")).into_owned()
}

/// Runs the call-agent event pump once. Returns the methods of the
/// requests the call agent queued.
pub async fn pump_call_events(manager: &mut CallManager) -> Vec<String> {
    let mut methods = Vec::new();
    for _ in 0..4 {
        let events = manager.poll_call_events();
        if events.is_empty() {
            break;
        }
        for event in events {
            if let CallEvent::SendRequest { request, .. } = &event {
                methods.push(request.method.as_str().to_string());
            }
            let _ = manager.handle_call_event(event).await;
        }
    }
    methods
}

/// Delivers a 200 OK carrying `answer` and pumps the call-agent events
/// into the call manager. Returns the requests the call agent queued.
pub async fn answer_call(
    manager: &mut CallManager,
    invite: &SipRequest,
    answer: &str,
) -> Vec<String> {
    let mut ok = build_response_from_request(invite, StatusCode::OK, Some("remote-tag"));
    ok.add_header(Header::new(
        HeaderName::Contact,
        format!("<sips:bob@{SIP_PEER}>"),
    ));
    ok.add_header(Header::new(HeaderName::ContentType, "application/sdp"));
    ok.headers
        .set(HeaderName::ContentLength, answer.len().to_string());
    let ok = ok.with_body(answer.to_string());
    manager.handle_sip_response(&ok).await.unwrap();
    pump_call_events(manager).await
}

fn parse_request(text: &str) -> SipRequest {
    match SipMessage::parse(text.as_bytes()).unwrap() {
        SipMessage::Request(r) => r,
        SipMessage::Response(_) => panic!("expected request"),
    }
}

/// An initial INVITE from the scripted peer.
pub fn invite(call_id: &str, body: &str) -> SipRequest {
    parse_request(&format!(
        "INVITE sips:testuser@example.com SIP/2.0\r\n\
         Via: SIP/2.0/TLS {SIP_PEER};branch=z9hG4bK{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sips:caller@example.com>;tag=remote\r\n\
         To: <sips:testuser@example.com>\r\n\
         Call-ID: {call_id}@192.0.2.50\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sips:caller@{SIP_PEER}>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    ))
}

/// An in-dialog request without a body from the scripted peer, for a call
/// the peer started (`invite`).
pub fn in_dialog(method: &str, call_id: &str, to_tag: &str, cseq: u32) -> SipRequest {
    parse_request(&format!(
        "{method} sips:testuser@example.com SIP/2.0\r\n\
         Via: SIP/2.0/TLS {SIP_PEER};branch=z9hG4bK{call_id}{cseq}{method}\r\n\
         Max-Forwards: 70\r\n\
         From: <sips:caller@example.com>;tag=remote\r\n\
         To: <sips:testuser@example.com>;tag={to_tag}\r\n\
         Call-ID: {call_id}@192.0.2.50\r\n\
         CSeq: {cseq} {method}\r\n\
         Contact: <sips:caller@{SIP_PEER}>\r\n\
         Content-Length: 0\r\n\
         \r\n"
    ))
}

/// A BYE from the remote party of a call we placed (`place_call`), built
/// from our INVITE: the dialog's Call-ID, our From tag as the To tag.
pub fn bye_for_outbound(invite: &SipRequest) -> SipRequest {
    let call_id = invite.headers.get_value(&HeaderName::CallId).unwrap();
    let our_tag = invite.headers.from_tag().expect("From tag");
    parse_request(&format!(
        "BYE sips:testuser@127.0.0.1:5061 SIP/2.0\r\n\
         Via: SIP/2.0/TLS {SIP_PEER};branch=z9hG4bKbye{our_tag}\r\n\
         Max-Forwards: 70\r\n\
         From: <sips:bob@{SIP_PEER}>;tag=remote-tag\r\n\
         To: <sips:testuser@example.com>;tag={our_tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 BYE\r\n\
         Content-Length: 0\r\n\
         \r\n"
    ))
}

/// Body of the first 200 among `events`.
pub fn ok_body(events: &[CallManagerEvent]) -> Option<String> {
    events.iter().find_map(|e| match e {
        CallManagerEvent::SendResponse { response, .. } if response.status.code() == 200 => {
            response
                .body
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
        }
        _ => None,
    })
}

/// The call states reported to the application, in order.
pub fn reported_states(events: &[CallManagerEvent]) -> Vec<CallState> {
    events
        .iter()
        .filter_map(|e| match e {
            CallManagerEvent::CallStateChanged { state, .. } => Some(*state),
            _ => None,
        })
        .collect()
}

pub fn reported_connected(events: &[CallManagerEvent]) -> bool {
    reported_states(events).contains(&CallState::Connected)
}

/// The messages of the error events, in order.
pub fn error_messages(events: &[CallManagerEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            CallManagerEvent::Error { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect()
}

/// The reason of the first `CallEnded`.
pub fn end_reason(events: &[CallManagerEvent]) -> Option<CallEndReason> {
    events.iter().find_map(|e| match e {
        CallManagerEvent::CallEnded { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}

/// Everything the application and the wire saw while the manager was
/// being pumped.
#[derive(Default, Debug)]
pub struct Seen {
    pub events: Vec<CallManagerEvent>,
    /// Methods of the SIP requests the call agent queued.
    pub methods: Vec<String>,
}

/// Runs what the application's pump runs (timers, call-agent events) every
/// 10 ms until `done` says so or `limit` is over.
pub async fn pump(
    manager: &mut CallManager,
    rx: &mut mpsc::Receiver<CallManagerEvent>,
    seen: &mut Seen,
    limit: Duration,
    done: impl Fn(&Seen) -> bool,
) {
    let deadline = Instant::now() + limit;
    loop {
        manager.process_timers().await.unwrap();
        seen.methods.extend(pump_call_events(manager).await);
        seen.events.extend(drain(rx));
        if done(seen) || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub fn connected(seen: &Seen) -> bool {
    reported_connected(&seen.events)
}

pub fn ended(seen: &Seen) -> bool {
    seen.events.iter().any(|e| {
        matches!(
            e,
            CallManagerEvent::CallEnded { .. }
                | CallManagerEvent::CallStateChanged {
                    state: CallState::Terminated,
                    ..
                }
        )
    })
}
