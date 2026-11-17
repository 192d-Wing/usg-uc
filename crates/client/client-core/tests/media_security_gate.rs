//! B2: the media-security gate fails closed on TLS-account calls.
//!
//! Default (TLS-only) builds signal every stream as `UDP/TLS/RTP/SAVPF`, so
//! audio must never start without DTLS-SRTP keys. A call whose DTLS
//! handshake does not complete ends with no audio and is never reported
//! Connected (here: nothing answers DTLS at the peer's address, so the
//! handshake times out). These tests drive the public `CallManager` API
//! through the outbound connect, the inbound accept + ACK, and the
//! re-INVITE paths. Successful handshakes are in `dtls_srtp_call.rs`.
// NIST 800-53 Rev5: SC-8(1) (no plaintext media), SI-10 (SDP preflight).
// RFC 5764 §4.1, RFC 5763 §5, RFC 8122 §5, RFC 3264 §6.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use client_core::{CallManager, CallManagerEvent, SipTransportKind, build_response_from_request};
use client_sip_ua::CallEvent;
use client_types::{CallEndReason, CallState, SipAccount};
use proto_sip::header::{Header, HeaderName};
use proto_sip::message::{SipMessage, SipRequest};
use proto_sip::response::StatusCode;
use std::net::SocketAddr;
use tokio::sync::mpsc;

const PEER: &str = "192.0.2.50:5061";

fn fingerprint(alg: &str, octets: u8) -> String {
    let hex: Vec<String> = (0..octets).map(|b| format!("{b:02X}")).collect();
    format!("{alg} {}", hex.join(":"))
}

fn sdp(proto: &str, attrs: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.50\r\ns=-\r\nc=IN IP4 192.0.2.50\r\nt=0 0\r\n\
         m=audio 40000 {proto} 0\r\na=rtpmap:0 PCMU/8000\r\n{attrs}a=rtcp-mux\r\na=sendrecv\r\n"
    )
}

fn good_attrs(setup: &str) -> String {
    format!(
        "a=fingerprint:{}\r\na=setup:{setup}\r\n",
        fingerprint("sha-384", 48)
    )
}

fn manager() -> (CallManager, mpsc::Receiver<CallManagerEvent>) {
    let (tx, rx) = mpsc::channel(256);
    let sip: SocketAddr = "127.0.0.1:5061".parse().unwrap();
    let media: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut manager = CallManager::new(sip, media, tx);
    // SipAccount::new defaults to TLS-only transport.
    manager.configure_account(&SipAccount::new(
        "test-account",
        "Test User",
        "sips:testuser@example.com",
        "sips:192.0.2.1:5061",
    ));
    (manager, rx)
}

fn drain(rx: &mut mpsc::Receiver<CallManagerEvent>) -> Vec<CallManagerEvent> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn statuses(events: &[CallManagerEvent]) -> Vec<u16> {
    events
        .iter()
        .filter_map(|e| match e {
            CallManagerEvent::SendResponse { response, .. } => Some(response.status.code()),
            _ => None,
        })
        .collect()
}

fn media_security_failed(events: &[CallManagerEvent], call_id: &str) -> bool {
    let error = events.iter().any(|e| {
        matches!(e, CallManagerEvent::Error { call_id: Some(id), message }
            if id == call_id && message.starts_with("media-security: "))
    });
    let ended = events.iter().any(|e| {
        matches!(e, CallManagerEvent::CallEnded { call_id: id, reason: CallEndReason::Failed, .. }
            if id == call_id)
    });
    error && ended
}

fn reported_connected(events: &[CallManagerEvent]) -> bool {
    events.iter().any(|e| {
        matches!(
            e,
            CallManagerEvent::CallStateChanged {
                state: CallState::Connected,
                ..
            }
        )
    })
}

/// Runs the timer pass (which polls the DTLS handshake) and the call-agent
/// event pump until the call has ended or `limit` is over. Returns the
/// application events seen and the methods of the requests queued.
async fn pump_until_ended(
    manager: &mut CallManager,
    rx: &mut mpsc::Receiver<CallManagerEvent>,
    limit: std::time::Duration,
) -> (Vec<CallManagerEvent>, Vec<String>) {
    let deadline = std::time::Instant::now() + limit;
    let mut events = Vec::new();
    let mut methods = Vec::new();
    loop {
        manager.process_timers().await.unwrap();
        for event in manager.poll_call_events() {
            if let CallEvent::SendRequest { request, .. } = &event {
                methods.push(request.method.as_str().to_string());
            }
            let _ = manager.handle_call_event(event).await;
        }
        events.extend(drain(rx));
        let ended = events
            .iter()
            .any(|e| matches!(e, CallManagerEvent::CallEnded { .. }));
        if ended || std::time::Instant::now() >= deadline {
            return (events, methods);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn error_messages(events: &[CallManagerEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| match e {
            CallManagerEvent::Error { message, .. } => Some(message.as_str()),
            _ => None,
        })
        .collect()
}

/// Places a call and returns its ID and the INVITE the call agent queued.
async fn place_call(manager: &mut CallManager) -> (String, SipRequest) {
    let call_id = manager
        .make_call(&format!("sips:bob@{PEER}"))
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

/// Delivers a 200 OK carrying `answer` and pumps the call-agent events
/// into the call manager. Returns the requests the call agent queued.
async fn answer_call(manager: &mut CallManager, invite: &SipRequest, answer: &str) -> Vec<String> {
    let mut ok = build_response_from_request(invite, StatusCode::OK, Some("remote-tag"));
    ok.add_header(Header::new(
        HeaderName::Contact,
        format!("<sips:bob@{PEER}>"),
    ));
    ok.add_header(Header::new(HeaderName::ContentType, "application/sdp"));
    ok.headers
        .set(HeaderName::ContentLength, answer.len().to_string());
    let ok = ok.with_body(answer.to_string());
    manager.handle_sip_response(&ok).await.unwrap();

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

/// Our offer: exactly one `a=fingerprint:sha-384 XX:...` with 48 octets,
/// `a=setup:actpass`, and the DTLS-SRTP profile.
#[tokio::test]
async fn offer_carries_one_full_sha384_fingerprint() {
    let (mut manager, _rx) = manager();
    let (_call_id, invite) = place_call(&mut manager).await;
    let body = std::str::from_utf8(invite.body.as_ref().unwrap()).unwrap();

    let fps: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim_end().strip_prefix("a=fingerprint:"))
        .collect();
    assert_eq!(fps.len(), 1, "{body}");
    let hex = fps[0].strip_prefix("sha-384 ").expect("one sha-384 prefix");
    assert!(!hex.contains("sha-"), "double prefix: {}", fps[0]);
    assert_eq!(hex.split(':').count(), 48);
    assert!(body.contains("UDP/TLS/RTP/SAVPF"));
    assert!(body.contains("a=setup:actpass\r\n"));
}

/// Establish error -> call ends: a valid SAVPF answer passes the preflight
/// and the DTLS handshake starts (the call is reported Connecting, not
/// Connected); nothing answers at the peer's address, so the handshake
/// times out, BYE is sent, no audio starts and the call is never reported
/// Connected.
#[tokio::test]
async fn outbound_establish_error_ends_call_with_bye() {
    let (mut manager, mut rx) = manager();
    manager.set_dtls_handshake_budget(std::time::Duration::from_secs(1));
    let (call_id, invite) = place_call(&mut manager).await;
    let _ = drain(&mut rx);

    let mut sent = answer_call(
        &mut manager,
        &invite,
        &sdp("UDP/TLS/RTP/SAVPF", &good_attrs("active")),
    )
    .await;

    // The handshake runs; the call is not connected and not ended.
    let mut events = drain(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            CallManagerEvent::CallStateChanged {
                state: CallState::Connecting,
                ..
            }
        )),
        "{events:?}"
    );
    assert!(!media_security_failed(&events, &call_id), "{events:?}");
    assert!(manager.get_audio_session(&call_id).is_none());

    let (later, methods) =
        pump_until_ended(&mut manager, &mut rx, std::time::Duration::from_secs(8)).await;
    events.extend(later);
    sent.extend(methods);
    assert!(media_security_failed(&events, &call_id), "{events:?}");
    assert_eq!(
        error_messages(&events),
        ["media-security: dtls-timeout"],
        "{events:?}"
    );
    assert!(!reported_connected(&events), "{events:?}");
    assert!(sent.iter().any(|m| m == "BYE"), "no BYE sent: {sent:?}");
    assert!(manager.get_audio_session(&call_id).is_none());
    assert!(manager.get_media_session(&call_id).is_none());
    assert_eq!(manager.all_call_ids(), &[] as &[String]);
}

/// Downgrades in the answer end the call without any DTLS attempt:
/// RTP/AVP, no fingerprint, a sha-256-only fingerprint, a malformed
/// fingerprint, and `a=setup:actpass` in an answer.
#[tokio::test]
async fn outbound_insecure_answers_end_call() {
    let cases = [
        sdp("RTP/AVP", &good_attrs("active")),
        sdp("RTP/SAVP", &good_attrs("active")),
        sdp("UDP/TLS/RTP/SAVPF", "a=setup:active\r\n"),
        sdp(
            "UDP/TLS/RTP/SAVPF",
            &format!(
                "a=fingerprint:{}\r\na=setup:active\r\n",
                fingerprint("sha-256", 32)
            ),
        ),
        sdp(
            "UDP/TLS/RTP/SAVPF",
            "a=fingerprint:sha-384 ZZ:00\r\na=setup:active\r\n",
        ),
        sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass")),
        // RFC-B2-001: answer without a=rtcp-mux.
        sdp("UDP/TLS/RTP/SAVPF", &good_attrs("active")).replace("a=rtcp-mux\r\n", ""),
        // NIST-008: answer with an extra active plaintext stream.
        format!(
            "{}m=video 40002 RTP/AVP 96\r\n",
            sdp("UDP/TLS/RTP/SAVPF", &good_attrs("active"))
        ),
    ];
    for answer in cases {
        let (mut manager, mut rx) = manager();
        let (call_id, invite) = place_call(&mut manager).await;
        let sent = answer_call(&mut manager, &invite, &answer).await;
        let events = drain(&mut rx);
        assert!(
            media_security_failed(&events, &call_id),
            "{answer}\n{events:?}"
        );
        assert!(!reported_connected(&events), "{answer}");
        assert!(sent.iter().any(|m| m == "BYE"), "{answer}: {sent:?}");
        assert!(manager.get_audio_session(&call_id).is_none(), "{answer}");
        assert_eq!(manager.all_call_ids(), &[] as &[String], "{answer}");
    }
}

fn invite(call_id: &str, body: &str) -> SipRequest {
    let content = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    let text = format!(
        "INVITE sips:testuser@example.com SIP/2.0\r\n\
         Via: SIP/2.0/TLS {PEER};branch=z9hG4bK{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sips:caller@example.com>;tag=remote\r\n\
         To: <sips:testuser@example.com>\r\n\
         Call-ID: {call_id}@192.0.2.50\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sips:caller@{PEER}>\r\n\
         {content}Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    );
    match SipMessage::parse(text.as_bytes()).unwrap() {
        SipMessage::Request(r) => r,
        SipMessage::Response(_) => panic!("expected request"),
    }
}

fn in_dialog(method: &str, call_id: &str, to_tag: &str, cseq: u32, body: &str) -> SipRequest {
    let content = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    let text = format!(
        "{method} sips:testuser@example.com SIP/2.0\r\n\
         Via: SIP/2.0/TLS {PEER};branch=z9hG4bK{call_id}{cseq}{method}\r\n\
         Max-Forwards: 70\r\n\
         From: <sips:caller@example.com>;tag=remote\r\n\
         To: <sips:testuser@example.com>;tag={to_tag}\r\n\
         Call-ID: {call_id}@192.0.2.50\r\n\
         CSeq: {cseq} {method}\r\n\
         Contact: <sips:caller@{PEER}>\r\n\
         {content}Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    );
    match SipMessage::parse(text.as_bytes()).unwrap() {
        SipMessage::Request(r) => r,
        SipMessage::Response(_) => panic!("expected request"),
    }
}

/// Inbound offers failing the preflight get 488 (with the fixed Warning)
/// before any 180/200, and no call is created.
#[tokio::test]
async fn inbound_insecure_offer_gets_488() {
    let source: SocketAddr = PEER.parse().unwrap();
    for (n, body) in [
        String::new(),
        sdp("RTP/AVP", &good_attrs("actpass")),
        sdp("UDP/TLS/RTP/SAVPF", "a=setup:actpass\r\n"),
        sdp(
            "UDP/TLS/RTP/SAVPF",
            &format!(
                "a=fingerprint:{}\r\na=setup:actpass\r\n",
                fingerprint("sha-256", 32)
            ),
        ),
        sdp("UDP/TLS/RTP/SAVPF", &good_attrs("holdconn")),
        // RFC-B2-001: no a=rtcp-mux (no RTCP DTLS association exists).
        sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass")).replace("a=rtcp-mux\r\n", ""),
        // NIST-008: a second, active, plaintext m= section.
        format!(
            "{}m=video 40002 RTP/AVP 96\r\n",
            sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass"))
        ),
        // QA gap 1: conflicting duplicate a=setup.
        sdp(
            "UDP/TLS/RTP/SAVPF",
            &format!("{}a=setup:passive\r\n", good_attrs("actpass")),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (mut manager, mut rx) = manager();
        let request = invite(&format!("insecure{n}"), &body);
        manager
            .handle_sip_request_from(&request, source, SipTransportKind::Tls)
            .await
            .unwrap();
        let events = drain(&mut rx);
        assert_eq!(statuses(&events), vec![488], "{body}");
        let warning = events.iter().find_map(|e| match e {
            CallManagerEvent::SendResponse { response, .. } => response
                .headers
                .get_value(&HeaderName::Warning)
                .map(str::to_string),
            _ => None,
        });
        assert_eq!(
            warning.as_deref(),
            Some("399 usg-client \"SRTP/DTLS required\"")
        );
        assert!(!manager.has_incoming_call(), "{body}");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, CallManagerEvent::IncomingCall { .. }))
        );
    }
}

/// Inbound accept path hits the gate: the 200 answers `a=setup:active`
/// with our fingerprint, no audio starts before the ACK, the call is
/// reported Connecting (never Connected), and after the ACK the DTLS
/// handshake that nobody answers ends the call (BYE) without audio.
#[tokio::test]
async fn inbound_accept_then_ack_fails_closed() {
    let source: SocketAddr = PEER.parse().unwrap();
    let (mut manager, mut rx) = manager();
    manager.set_dtls_handshake_budget(std::time::Duration::from_secs(1));
    let request = invite(
        "secure-in",
        &sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass")),
    );
    manager
        .handle_sip_request_from(&request, source, SipTransportKind::Tls)
        .await
        .unwrap();
    assert_eq!(statuses(&drain(&mut rx)), vec![100, 180]);
    let (call_id, local_tag) = {
        let incoming = manager.incoming_calls()[0];
        (incoming.call_id.clone(), incoming.local_tag.clone())
    };

    manager.accept_incoming_call(&call_id).await.unwrap();
    let events = drain(&mut rx);
    let answer = events
        .iter()
        .find_map(|e| match e {
            CallManagerEvent::SendResponse { response, .. } if response.status.code() == 200 => {
                response
                    .body
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
            }
            _ => None,
        })
        .expect("200 with SDP");
    assert!(answer.contains("a=setup:active\r\n"), "{answer}");
    assert!(answer.contains("a=fingerprint:sha-384 "), "{answer}");
    assert!(manager.get_audio_session(&call_id).is_none());
    // Answered, but not connected as far as the application is told.
    assert!(!reported_connected(&events), "{events:?}");
    assert!(
        events.iter().any(|e| matches!(
            e,
            CallManagerEvent::CallStateChanged {
                state: CallState::Connecting,
                ..
            }
        )),
        "{events:?}"
    );
    let mut all_events = events;

    let ack = in_dialog("ACK", "secure-in", &local_tag, 1, "");
    manager
        .handle_sip_request_from(&ack, source, SipTransportKind::Tls)
        .await
        .unwrap();
    // The ACK starts the handshake; it does not wait for it.
    let after_ack = drain(&mut rx);
    assert!(
        !media_security_failed(&after_ack, &call_id),
        "{after_ack:?}"
    );
    all_events.extend(after_ack);

    let (later, sent) =
        pump_until_ended(&mut manager, &mut rx, std::time::Duration::from_secs(8)).await;
    all_events.extend(later);
    let events = all_events;
    assert!(media_security_failed(&events, &call_id), "{events:?}");
    assert_eq!(
        error_messages(&events),
        ["media-security: dtls-timeout"],
        "{events:?}"
    );
    assert!(!reported_connected(&events), "{events:?}");
    assert!(sent.iter().any(|m| m == "BYE"), "{sent:?}");
    assert!(manager.get_audio_session(&call_id).is_none());
    assert_eq!(manager.all_call_ids(), &[] as &[String]);
}

/// Re-INVITE path: an insecure re-offer on an answered TLS call is
/// refused with 488 and does not start audio.
#[tokio::test]
async fn reinvite_insecure_reoffer_gets_488() {
    let source: SocketAddr = PEER.parse().unwrap();
    let (mut manager, mut rx) = manager();
    let request = invite("reinv", &sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass")));
    manager
        .handle_sip_request_from(&request, source, SipTransportKind::Tls)
        .await
        .unwrap();
    let (call_id, local_tag) = {
        let incoming = manager.incoming_calls()[0];
        (incoming.call_id.clone(), incoming.local_tag.clone())
    };
    manager.accept_incoming_call(&call_id).await.unwrap();
    let _ = drain(&mut rx);

    let reinvite = in_dialog(
        "INVITE",
        "reinv",
        &local_tag,
        2,
        &sdp("RTP/AVP", "a=sendrecv\r\n"),
    );
    manager
        .handle_sip_request_from(&reinvite, source, SipTransportKind::Tls)
        .await
        .unwrap();
    let events = drain(&mut rx);
    assert_eq!(statuses(&events), vec![488], "{events:?}");
    assert!(manager.get_audio_session(&call_id).is_none());
}

/// Body of the first 200 among `events`, if it has one.
fn ok_body(events: &[CallManagerEvent]) -> Option<String> {
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

/// RFC-R1-003: an offerless re-INVITE makes our SDP in the 200 an offer
/// (RFC 3261 §14.2), so it carries `a=setup:actpass` and `a=rtcp-mux`; a
/// re-INVITE with an offer is answered with our established role.
#[tokio::test]
async fn offerless_reinvite_200_offers_actpass() {
    let source: SocketAddr = PEER.parse().unwrap();
    let (mut manager, mut rx) = manager();
    let request = invite("delayed", &sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass")));
    manager
        .handle_sip_request_from(&request, source, SipTransportKind::Tls)
        .await
        .unwrap();
    let (call_id, local_tag) = {
        let incoming = manager.incoming_calls()[0];
        (incoming.call_id.clone(), incoming.local_tag.clone())
    };
    manager.accept_incoming_call(&call_id).await.unwrap();
    let _ = drain(&mut rx);

    let offerless = in_dialog("INVITE", "delayed", &local_tag, 2, "");
    manager
        .handle_sip_request_from(&offerless, source, SipTransportKind::Tls)
        .await
        .unwrap();
    let events = drain(&mut rx);
    assert_eq!(statuses(&events), vec![200], "{events:?}");
    let offer = ok_body(&events).expect("200 with SDP");
    assert!(offer.contains("a=setup:actpass\r\n"), "{offer}");
    assert!(offer.contains("a=rtcp-mux\r\n"), "{offer}");
    assert!(offer.contains("a=fingerprint:sha-384 "), "{offer}");

    let with_offer = in_dialog(
        "INVITE",
        "delayed",
        &local_tag,
        3,
        &sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass")),
    );
    manager
        .handle_sip_request_from(&with_offer, source, SipTransportKind::Tls)
        .await
        .unwrap();
    let events = drain(&mut rx);
    assert_eq!(statuses(&events), vec![200], "{events:?}");
    let answer = ok_body(&events).expect("200 with SDP");
    assert!(answer.contains("a=setup:active\r\n"), "{answer}");
    assert!(!answer.contains("actpass"), "{answer}");
    assert!(manager.get_audio_session(&call_id).is_none());
}

/// SEC-002 / SEC-008, `insecure-transports` builds: a non-TLS account
/// cannot run DTLS-SRTP, so an offer asking for SAVP(F) is never answered
/// in plaintext. The initial INVITE gets 488 before any ringing; a
/// re-INVITE gets 488 and leaves the session as it was.
#[cfg(feature = "insecure-transports")]
mod udp_account {
    use super::*;

    const UDP_PEER: &str = "192.0.2.50:5060";
    const SAVP_PROTOS: [&str; 3] = ["RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVPF"];

    fn udp_manager() -> (CallManager, mpsc::Receiver<CallManagerEvent>) {
        let (tx, rx) = mpsc::channel(256);
        let sip: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let media: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut manager = CallManager::new(sip, media, tx);
        let mut account = SipAccount::new(
            "udp-account",
            "Test User",
            "sip:testuser@example.com",
            "sip:192.0.2.1:5060",
        );
        account.transport = client_types::TransportPreference::Udp;
        manager.configure_account(&account);
        (manager, rx)
    }

    fn udp_request(call_id: &str, to_tag: Option<&str>, cseq: u32, body: &str) -> SipRequest {
        let to_tag = to_tag.map_or_else(String::new, |t| format!(";tag={t}"));
        let text = format!(
            "INVITE sip:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP {UDP_PEER};branch=z9hG4bK{call_id}{cseq}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:caller@example.com>;tag=remote\r\n\
             To: <sip:testuser@example.com>{to_tag}\r\n\
             Call-ID: {call_id}@192.0.2.50\r\n\
             CSeq: {cseq} INVITE\r\n\
             Contact: <sip:caller@{UDP_PEER}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len()
        );
        match SipMessage::parse(text.as_bytes()).unwrap() {
            SipMessage::Request(r) => r,
            SipMessage::Response(_) => panic!("expected request"),
        }
    }

    fn warning(events: &[CallManagerEvent]) -> Option<String> {
        events.iter().find_map(|e| match e {
            CallManagerEvent::SendResponse { response, .. } => response
                .headers
                .get_value(&HeaderName::Warning)
                .map(str::to_string),
            _ => None,
        })
    }

    #[tokio::test]
    async fn initial_invite_asking_for_srtp_gets_488() {
        let source: SocketAddr = UDP_PEER.parse().unwrap();
        for (n, proto) in SAVP_PROTOS.into_iter().enumerate() {
            let (mut manager, mut rx) = udp_manager();
            let request = udp_request(
                &format!("udp-savp{n}"),
                None,
                1,
                &sdp(proto, &good_attrs("actpass")),
            );
            manager
                .handle_sip_request_from(&request, source, SipTransportKind::Udp)
                .await
                .unwrap();
            let events = drain(&mut rx);
            assert_eq!(statuses(&events), vec![488], "{proto}");
            assert_eq!(
                warning(&events).as_deref(),
                Some("399 usg-client \"SRTP/DTLS required\""),
                "{proto}"
            );
            assert!(!manager.has_incoming_call(), "{proto}");
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, CallManagerEvent::IncomingCall { .. })),
                "{proto}"
            );
        }
    }

    #[tokio::test]
    async fn reinvite_asking_for_srtp_gets_488_session_unchanged() {
        let source: SocketAddr = UDP_PEER.parse().unwrap();
        let (mut manager, mut rx) = udp_manager();
        let plain = sdp("RTP/AVP", "");
        let request = udp_request("udp-reinv", None, 1, &plain);
        manager
            .handle_sip_request_from(&request, source, SipTransportKind::Udp)
            .await
            .unwrap();
        assert_eq!(statuses(&drain(&mut rx)), vec![100, 180]);
        let (call_id, local_tag) = {
            let incoming = manager.incoming_calls()[0];
            (incoming.call_id.clone(), incoming.local_tag.clone())
        };
        manager.accept_incoming_call(&call_id).await.unwrap();
        let _ = drain(&mut rx);

        for (n, proto) in SAVP_PROTOS.into_iter().enumerate() {
            let cseq = 2 + u32::try_from(n).unwrap();
            let reinvite = udp_request(
                "udp-reinv",
                Some(&local_tag),
                cseq,
                &sdp(proto, &good_attrs("actpass")),
            );
            manager
                .handle_sip_request_from(&reinvite, source, SipTransportKind::Udp)
                .await
                .unwrap();
            let events = drain(&mut rx);
            assert_eq!(statuses(&events), vec![488], "{proto}: {events:?}");
            assert_eq!(
                warning(&events).as_deref(),
                Some("399 usg-client \"SRTP/DTLS required\""),
                "{proto}"
            );
            assert_eq!(
                manager.all_call_ids(),
                std::slice::from_ref(&call_id),
                "{proto}"
            );
        }

        // The refused re-offers did not make SRTP sticky for the call: a
        // plain re-offer is still answered, in plaintext profile.
        let refresh = udp_request("udp-reinv", Some(&local_tag), 9, &plain);
        manager
            .handle_sip_request_from(&refresh, source, SipTransportKind::Udp)
            .await
            .unwrap();
        let events = drain(&mut rx);
        assert_eq!(statuses(&events), vec![200], "{events:?}");
        let answer = ok_body(&events).expect("200 with SDP");
        assert!(answer.contains(" RTP/AVP "), "{answer}");
        assert!(!answer.contains("SAVP"), "{answer}");
        let _ = manager.hangup_call(&call_id).await;
    }
}

/// QA (B2): hostile fingerprint/setup lines in an inbound offer get 488
/// before any ringing: oversized value, too many lines, weak-only mixed
/// list, wrong octet count, garbage/oversized `a=setup`, and an offer
/// whose only audio stream is `RTP/SAVP` (SDES-shaped).
#[tokio::test]
async fn qa_inbound_hostile_dtls_attrs_get_488_no_ring() {
    let source: SocketAddr = PEER.parse().unwrap();
    let good = format!("a=fingerprint:{}\r\n", fingerprint("sha-384", 48));
    let cases = [
        format!(
            "a=fingerprint:{}{}\r\na=setup:actpass\r\n",
            fingerprint("sha-384", 48),
            " ".repeat(300)
        ),
        format!("{}a=setup:actpass\r\n", good.repeat(9)),
        format!(
            "a=fingerprint:{}\r\na=fingerprint:{}\r\na=fingerprint:{}\r\na=setup:actpass\r\n",
            fingerprint("sha-1", 20),
            fingerprint("md5", 16),
            fingerprint("sha-256", 32)
        ),
        format!(
            "a=fingerprint:{}\r\na=setup:actpass\r\n",
            fingerprint("sha-384", 47)
        ),
        format!(
            "a=fingerprint:{}\r\na=setup:actpass\r\n",
            fingerprint("sha-512", 48)
        ),
        format!("{good}a=setup:sideways\r\n"),
        format!("{good}a=setup:{}\r\n", "x".repeat(4096)),
    ];
    let mut bodies: Vec<String> = cases.iter().map(|a| sdp("UDP/TLS/RTP/SAVPF", a)).collect();
    bodies.push(sdp(
        "RTP/SAVP",
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
    ));
    for (n, body) in bodies.iter().enumerate() {
        let (mut manager, mut rx) = manager();
        let request = invite(&format!("qa-hostile{n}"), body);
        manager
            .handle_sip_request_from(&request, source, SipTransportKind::Tls)
            .await
            .unwrap();
        let events = drain(&mut rx);
        assert_eq!(statuses(&events), vec![488], "case {n}: {body}");
        assert!(!manager.has_incoming_call(), "case {n}");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, CallManagerEvent::IncomingCall { .. })),
            "case {n}: user was rung"
        );
    }
}

/// QA (B2): a mixed list where weak hashes surround one sha-384 entry is
/// accepted (RFC 8122 §5: match at least one); the call rings normally.
#[tokio::test]
async fn qa_inbound_mixed_hash_list_with_cnsa_entry_rings() {
    let source: SocketAddr = PEER.parse().unwrap();
    let attrs = format!(
        "a=fingerprint:{}\r\na=fingerprint:{}\r\na=fingerprint:{}\r\na=setup:actpass\r\n",
        fingerprint("sha-256", 32),
        fingerprint("SHA-384", 48),
        fingerprint("sha-1", 20)
    );
    let (mut manager, mut rx) = manager();
    let request = invite("qa-mixed", &sdp("UDP/TLS/RTP/SAVPF", &attrs));
    manager
        .handle_sip_request_from(&request, source, SipTransportKind::Tls)
        .await
        .unwrap();
    assert_eq!(statuses(&drain(&mut rx)), vec![100, 180]);
    assert!(manager.has_incoming_call());
}

/// QA (B2): outbound answers with hostile DTLS attributes end the call
/// with BYE, never Connected, no audio: holdconn, oversized fingerprint,
/// weak-only mixed list, wrong octet count, garbage setup.
#[tokio::test]
async fn qa_outbound_hostile_answers_end_call() {
    let cases = [
        good_attrs("holdconn"),
        format!(
            "a=fingerprint:{}{}\r\na=setup:active\r\n",
            fingerprint("sha-384", 48),
            " ".repeat(300)
        ),
        format!(
            "a=fingerprint:{}\r\na=fingerprint:{}\r\na=setup:active\r\n",
            fingerprint("sha-1", 20),
            fingerprint("sha-256", 32)
        ),
        format!(
            "a=fingerprint:{}\r\na=setup:active\r\n",
            fingerprint("sha-384", 49)
        ),
        format!(
            "a=fingerprint:{}\r\na=setup:bogus\r\n",
            fingerprint("sha-384", 48)
        ),
    ];
    for attrs in cases {
        let answer = sdp("UDP/TLS/RTP/SAVPF", &attrs);
        let (mut manager, mut rx) = manager();
        let (call_id, invite) = place_call(&mut manager).await;
        let sent = answer_call(&mut manager, &invite, &answer).await;
        let events = drain(&mut rx);
        assert!(
            media_security_failed(&events, &call_id),
            "{answer}\n{events:?}"
        );
        assert!(!reported_connected(&events), "{answer}");
        assert!(sent.iter().any(|m| m == "BYE"), "{answer}: {sent:?}");
        assert!(manager.get_audio_session(&call_id).is_none(), "{answer}");
        assert!(manager.get_media_session(&call_id).is_none(), "{answer}");
    }
}

/// QA (B2): re-INVITE re-offers that keep SAVPF but drop or weaken the
/// fingerprint, or offer holdconn, are refused with 488; no audio starts.
#[tokio::test]
async fn qa_reinvite_downgraded_dtls_attrs_get_488() {
    let source: SocketAddr = PEER.parse().unwrap();
    for (n, attrs) in [
        "a=setup:actpass\r\n".to_string(),
        format!(
            "a=fingerprint:{}\r\na=setup:actpass\r\n",
            fingerprint("sha-256", 32)
        ),
        good_attrs("holdconn"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("qa-reinv{n}");
        let (mut manager, mut rx) = manager();
        let request = invite(&id, &sdp("UDP/TLS/RTP/SAVPF", &good_attrs("actpass")));
        manager
            .handle_sip_request_from(&request, source, SipTransportKind::Tls)
            .await
            .unwrap();
        let (call_id, local_tag) = {
            let incoming = manager.incoming_calls()[0];
            (incoming.call_id.clone(), incoming.local_tag.clone())
        };
        manager.accept_incoming_call(&call_id).await.unwrap();
        let _ = drain(&mut rx);

        let reinvite = in_dialog(
            "INVITE",
            &id,
            &local_tag,
            2,
            &sdp("UDP/TLS/RTP/SAVPF", &attrs),
        );
        manager
            .handle_sip_request_from(&reinvite, source, SipTransportKind::Tls)
            .await
            .unwrap();
        let events = drain(&mut rx);
        assert_eq!(statuses(&events), vec![488], "case {n}: {events:?}");
        assert!(manager.get_audio_session(&call_id).is_none(), "case {n}");
    }
}
