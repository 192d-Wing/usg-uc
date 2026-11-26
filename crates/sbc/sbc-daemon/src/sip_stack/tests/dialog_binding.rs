//! Dialog and CANCEL matching in the B2BUA (RFC 3261 §9.2, §12.2.2,
//! §13.2.2.4, §15, §17.2.3; peer binding is local SC-23 policy).
//!
//! An in-dialog request (re-INVITE, UPDATE, INFO, MESSAGE, NOTIFY, BYE,
//! ACK) acts on a dialog only when its Call-ID, From tag and To tag name
//! that dialog and it arrives from the leg's peer. A CANCEL acts on an
//! INVITE only when it matches that INVITE's transaction (branch, sent-by,
//! From tag, CSeq number) and peer; once the INVITE has a final response
//! the CANCEL has no effect.
//!
//! Status contract: identifiers that name no dialog get 481; a request
//! that names the dialog but comes from somewhere other than the leg's peer
//! gets 403. A CANCEL that matches nothing gets 481.
//!
//! Sans-IO through `process_message*`, with the shared fixtures of the
//! parent test module (`ringing_call`, `established_call`, `t38_call`,
//! `cdr_stack`, `place_call`, ...).

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

/// An off-path host on another network (TEST-NET-3).
fn outsider() -> SbcSocketAddr {
    SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 66), 40000)
}

/// The test call's INVITE branch (`alice_request("INVITE", 1, ..)`).
const A_INVITE_BRANCH: &str = "z9hG4bK-alice-1-INVITE";

/// SDP whose connection address is the outsider's. DTLS-SRTP with a
/// `sha-384` fingerprint, like the shared fixtures, so `media.srtp.required`
/// admits it and only the dialog match decides.
const OUTSIDER_SDP: &str = "v=0\r\no=- 9 9 IN IP4 203.0.113.66\r\ns=-\r\nc=IN IP4 203.0.113.66\r\nt=0 0\r\nm=audio 6666 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\na=fingerprint:sha-384 71:72:73:74:75:76:77:78:79:7A:7B:7C:7D:7E:7F:80:81:82:83:84:85:86:87:88:89:8A:8B:8C:8D:8E:8F:90:91:92:93:94:95:96:97:98:99:9A:9B:9C:9D:9E:9F:A0\r\na=sendrecv\r\n";

/// Alice's own new media address (a legitimate re-offer; DTLS-SRTP as
/// [`OUTSIDER_SDP`]).
const ALICE_MOVED_SDP: &str = "v=0\r\no=- 1 3 IN IP4 192.168.1.50\r\ns=-\r\nc=IN IP4 192.168.1.50\r\nt=0 0\r\nm=audio 4400 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\na=fingerprint:sha-384 11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F:30:31:32:33:34:35:36:37:38:39:3A:3B:3C:3D:3E:3F:40\r\na=sendrecv\r\n";

/// A CANCEL on the test call (`call-relay@test`) with the given top-Via
/// branch, From tag and CSeq number.
fn alice_cancel(branch: &str, from_tag: &str, cseq: u32) -> Bytes {
    Bytes::from(format!(
        "CANCEL sip:bob@sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.168.1.1:5060;branch={branch}\r\n\
         From: <sip:alice@example.com>;tag={from_tag}\r\n\
         To: <sip:bob@sbc.local>\r\n\
         Call-ID: call-relay@test\r\n\
         CSeq: {cseq} CANCEL\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

/// The in-flight entry `handle_invite` keeps for `invite` from `source`
/// (UDP) while it is routed.
fn in_flight_of(invite: &Bytes, source: SbcSocketAddr) -> InFlightInvite {
    let SipMessage::Request(r) = SipMessage::parse(invite).unwrap() else {
        panic!("not a request")
    };
    InFlightInvite {
        identity: InviteIdentity::of_request(&r, &Method::Invite),
        source,
        transport: AddrTransport::Udp,
        conn: None,
        cancelled: false,
    }
}

fn replace(msg: &Bytes, from: &str, to: &str) -> Bytes {
    let text = String::from_utf8(msg.to_vec()).unwrap();
    assert!(text.contains(from), "fixture lacks {from:?}: {text}");
    Bytes::from(text.replacen(from, to, 1))
}

fn drop_line(msg: &Bytes, prefix: &str) -> Bytes {
    let text = String::from_utf8(msg.to_vec()).unwrap();
    let out: Vec<&str> = text
        .split("\r\n")
        .filter(|l| !l.starts_with(prefix))
        .collect();
    assert_ne!(out.len(), text.split("\r\n").count(), "no {prefix:?} line");
    Bytes::from(out.join("\r\n"))
}

fn statuses(results: &[ProcessResult]) -> Vec<u16> {
    results
        .iter()
        .filter_map(|r| match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } => Some(resp.status.code()),
            _ => None,
        })
        .collect()
}

fn forwarded_methods(results: &[ProcessResult]) -> Vec<String> {
    results
        .iter()
        .filter_map(|r| match r {
            ProcessResult::Forward {
                message: SipMessage::Request(q),
                ..
            } => Some(q.method.to_string()),
            _ => None,
        })
        .collect()
}

fn a_leg_remote_moves(log: &[String]) -> Vec<String> {
    log.iter()
        .filter(|l| l.starts_with("remote a"))
        .cloned()
        .collect()
}

async fn send(stack: &SipStack, msg: &Bytes, from: SbcSocketAddr) -> Vec<ProcessResult> {
    flatten(stack.process_message(msg, from, None).await)
}

async fn send_on(
    stack: &SipStack,
    msg: &Bytes,
    from: SbcSocketAddr,
    transport: AddrTransport,
    conn: Option<crate::stir_binding::ConnId>,
) -> Vec<ProcessResult> {
    flatten(
        stack
            .process_message_conn(msg, from, None, transport, conn)
            .await,
    )
}

/// `ringing_call` answered by bob; alice has not ACKed, so the 2xx is
/// still being retransmitted.
async fn answered_unacked() -> SipStack {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    let r = send(
        &stack,
        &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
        bob(),
    )
    .await;
    assert!(responded(&r, 200).is_some());
    assert_eq!(stack.pending_2xx.read().await.len(), 1);
    stack
}

// ---------------------------------------------------------------------
// Re-INVITE / UPDATE (RFC 3261 §12.2.2, §14; RFC 3311)
// ---------------------------------------------------------------------

/// T1: a re-INVITE that names the dialog correctly but comes from a host
/// that is not the A-leg peer is refused with 403, is not relayed, and does
/// not move the A-leg media relay to the address in its SDP.
#[tokio::test]
async fn reinvite_from_foreign_source_is_403_and_media_unmoved() {
    let (stack, _b, media) = Box::pin(t38_call(t38_enabled())).await;
    let cap = uc_audit::capture::start();
    let req = alice_request("INVITE", 2, Some("bobtag"), Some(OUTSIDER_SDP));
    let r = send(&stack, &req, outsider()).await;
    let log = media.take();
    let mut failures = Vec::new();
    let fwd = forwarded_methods(&r);
    if !fwd.is_empty() {
        failures.push(format!("relayed to the callee: {fwd:?}"));
    }
    let moved = a_leg_remote_moves(&log);
    if !moved.is_empty() {
        failures.push(format!("A-leg media relay re-pointed: {moved:?}"));
    }
    if statuses(&r) != vec![403] {
        failures.push(format!("responses {:?}, want [403]", statuses(&r)));
    }
    let p = denied_policies(&cap.events());
    if !p.iter().any(|x| x == "in-dialog:foreign-source") {
        failures.push(format!("no foreign-source audit ({p:?})"));
    }
    if stack.call_count().await != 1 {
        failures.push("call torn down".to_string());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// T2: a re-INVITE or UPDATE from the true peer whose To tag is not the
/// dialog's local tag names no dialog: 481, not relayed, media untouched.
#[tokio::test]
async fn reinvite_and_update_with_wrong_to_tag_are_481() {
    let (stack, _b, media) = Box::pin(t38_call(t38_enabled())).await;
    let cap = uc_audit::capture::start();
    let mut failures = Vec::new();
    for (method, cseq) in [("INVITE", 2), ("UPDATE", 3)] {
        let req = alice_request(method, cseq, Some("not-the-tag"), Some(OUTSIDER_SDP));
        let r = send(&stack, &req, alice()).await;
        let log = media.take();
        let fwd = forwarded_methods(&r);
        if !fwd.is_empty() {
            failures.push(format!("{method}: relayed {fwd:?}"));
        }
        let moved = a_leg_remote_moves(&log);
        if !moved.is_empty() {
            failures.push(format!("{method}: A-leg media re-pointed {moved:?}"));
        }
        if statuses(&r) != vec![481] {
            failures.push(format!(
                "{method}: responses {:?}, want [481]",
                statuses(&r)
            ));
        }
        // Complete a relayed re-INVITE so UPDATE is not refused as glare.
        if let Some((q, _)) = forwarded(&r, &Method::Invite) {
            let q = q.clone();
            send(&stack, &response_to(&q, 200, None, Some(BOB_AUDIO)), bob()).await;
            send(
                &stack,
                &alice_request("ACK", cseq, Some("bobtag"), None),
                alice(),
            )
            .await;
            media.take();
        }
    }
    let p = denied_policies(&cap.events());
    if !p.iter().any(|x| x == "in-dialog:to-tag-mismatch") {
        failures.push(format!("no to-tag-mismatch audit ({p:?})"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Malformed: an empty `tag=` in To matches no dialog.
#[tokio::test]
async fn reinvite_with_empty_to_tag_is_481() {
    let (stack, _b) = Box::pin(established_call()).await;
    let req = alice_request("INVITE", 2, Some(""), Some(ALICE_SDP));
    let r = send(&stack, &req, alice()).await;
    assert!(forwarded(&r, &Method::Invite).is_none());
    assert_eq!(statuses(&r), vec![481]);
}

/// Malformed: with two `tag` parameters in To, the dialog is matched on the
/// first one only; a wrong first tag cannot be rescued by a correct second.
#[tokio::test]
async fn reinvite_with_duplicate_to_tag_uses_first() {
    let (stack, _b) = Box::pin(established_call()).await;
    let req = alice_request("INVITE", 2, Some("not-the-tag;tag=bobtag"), Some(ALICE_SDP));
    let r = send(&stack, &req, alice()).await;
    assert!(forwarded(&r, &Method::Invite).is_none());
    assert_eq!(statuses(&r), vec![481]);
}

/// Positive: a re-INVITE from the true A-leg peer with the right tags is
/// relayed, and its new media address is applied.
#[tokio::test]
async fn reinvite_from_dialog_peer_is_relayed() {
    let (stack, _b, media) = Box::pin(t38_call(t38_enabled())).await;
    let req = alice_request("INVITE", 2, Some("bobtag"), Some(ALICE_MOVED_SDP));
    let r = send(&stack, &req, alice()).await;
    let (fwd, dest) = forwarded(&r, &Method::Invite).expect("re-INVITE relayed");
    assert_eq!(dest, bob());
    assert!(fwd.body.is_some());
    assert!(
        a_leg_remote_moves(&media.take())
            .iter()
            .any(|l| l.contains("192.168.1.50")),
        "the legitimate offerer's new address is applied"
    );
}

/// T2b positive: the callee's in-dialog requests carry the tags swapped
/// (From = callee tag, To = the SBC's B-leg tag) and are relayed.
#[tokio::test]
async fn callee_reinvite_and_bye_with_swapped_tags_are_relayed() {
    let (stack, b_invite) = Box::pin(established_call()).await;
    let reinvite = bob_request(&b_invite, "INVITE", 2, Some(BOB_SDP));
    let r = send(&stack, &reinvite, bob()).await;
    let (_, dest) = forwarded(&r, &Method::Invite).expect("callee re-INVITE relayed");
    assert_eq!(dest, alice());

    let (stack, b_invite) = Box::pin(established_call()).await;
    let bye = bob_request(&b_invite, "BYE", 2, None);
    let r = send(&stack, &bye, bob()).await;
    assert!(responded(&r, 200).is_some(), "{:?}", statuses(&r));
    let (_, dest) = forwarded(&r, &Method::Bye).expect("callee BYE relayed");
    assert_eq!(dest, alice());
    assert_eq!(stack.call_count().await, 0);
}

/// T2b negative: a B-leg re-INVITE from a foreign host gets 403; one from
/// the callee whose To tag is not the SBC's B-leg tag gets 481.
#[tokio::test]
async fn callee_leg_reinvite_foreign_source_403_wrong_to_tag_481() {
    let mut failures = Vec::new();
    let (stack, b_invite) = Box::pin(established_call()).await;
    let reinvite = bob_request(&b_invite, "INVITE", 2, Some(OUTSIDER_SDP));
    let r = send(&stack, &reinvite, outsider()).await;
    if forwarded(&r, &Method::Invite).is_some() || statuses(&r) != vec![403] {
        failures.push(format!(
            "foreign host: responses {:?} (want [403]), forwarded {:?}",
            statuses(&r),
            forwarded_methods(&r)
        ));
    }

    // Fresh call: the case above may have left a re-INVITE pending.
    let (stack, b_invite) = Box::pin(established_call()).await;
    let sbc_tag = b_invite.headers.from_tag().expect("SBC B-leg From tag");
    let wrong = replace(
        &bob_request(&b_invite, "INVITE", 2, Some(BOB_SDP)),
        &format!("tag={sbc_tag}"),
        "tag=not-the-tag",
    );
    let r = send(&stack, &wrong, bob()).await;
    if forwarded(&r, &Method::Invite).is_some() || statuses(&r) != vec![481] {
        failures.push(format!(
            "wrong To tag: responses {:?} (want [481]), forwarded {:?}",
            statuses(&r),
            forwarded_methods(&r)
        ));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------
// Non-session in-dialog requests (MESSAGE, NOTIFY, INFO)
// ---------------------------------------------------------------------

/// T5: MESSAGE, NOTIFY and INFO with the right tags from a foreign host get
/// 403; from the peer with a wrong To tag, 481. Nothing is relayed.
#[tokio::test]
async fn non_session_requests_bound_to_dialog_peer() {
    let (stack, _b) = Box::pin(established_call()).await;
    let notify_extra = "Event: dialog\r\nSubscription-State: active\r\n";
    let mut failures = Vec::new();
    let mut cseq = 10;
    for method in ["MESSAGE", "NOTIFY", "INFO"] {
        for (to_tag, from, want) in [("bobtag", outsider(), 403), ("not-the-tag", alice(), 481)] {
            cseq += 1;
            let mut req = alice_request(method, cseq, Some(to_tag), None);
            if method == "NOTIFY" {
                req = with_extra(&req, notify_extra, None);
            }
            let r = send(&stack, &req, from).await;
            let fwd = forwarded_methods(&r);
            let st = statuses(&r);
            if !fwd.is_empty() || st != vec![want] {
                failures.push(format!(
                    "{method} to_tag={to_tag} from={from}: responses {st:?} (want [{want}]), forwarded {fwd:?}"
                ));
            }
        }
    }
    // Positive: the peer's INFO with the right tags is relayed.
    let info = alice_request("INFO", 50, Some("bobtag"), None);
    let r = send(&stack, &info, alice()).await;
    if forwarded(&r, &Method::Info).is_none() {
        failures.push("peer INFO not relayed".to_string());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------
// Peer binding: endpoint port / connection, trunk group (local SC-23
// policy; re-registered flows per RFC 5626 §4.4, §5.3)
// ---------------------------------------------------------------------

/// A caller that is a registered endpoint (not a trunk).
struct Endpoint {
    src: SbcSocketAddr,
    transport: AddrTransport,
    conn: Option<crate::stir_binding::ConnId>,
}

impl Endpoint {
    fn via(&self) -> &'static str {
        match self.transport {
            AddrTransport::Tcp => "TCP",
            _ => "UDP",
        }
    }

    fn request(&self, method: &str, cseq: u32, to_tag: Option<&str>, body: Option<&str>) -> Bytes {
        let to = to_tag.map_or_else(
            || "<sip:bob@sbc.local>".to_string(),
            |t| format!("<sip:bob@sbc.local>;tag={t}"),
        );
        let mut msg = format!(
            "{method} sip:bob@sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/{} {};branch=z9hG4bK-carol-{cseq}-{method}\r\n\
             From: <sip:carol@sbc.local>;tag=c1\r\n\
             To: {to}\r\n\
             Call-ID: ep-call@test\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:carol@{}>\r\n",
            self.via(),
            self.src,
            self.src,
        );
        match body {
            Some(b) => drop(write!(
                msg,
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            )),
            None => msg.push_str("Content-Length: 0\r\n\r\n"),
        }
        Bytes::from(msg)
    }
}

/// Registers bob and the endpoint caller, then places, answers and ACKs a
/// call from the endpoint. Returns the stack.
async fn endpoint_call(ep: &Endpoint) -> SipStack {
    let stack = SipStack::new(SipStackConfig::default());
    let reg_bob = b"REGISTER sip:sbc.local SIP/2.0\r\n\
        Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-reg\r\n\
        From: <sip:bob@sbc.local>;tag=r1\r\n\
        To: <sip:bob@sbc.local>\r\n\
        Call-ID: reg-bob@relay\r\n\
        CSeq: 1 REGISTER\r\n\
        Contact: <sip:bob@127.0.0.1:5060>\r\n\
        Expires: 3600\r\n\
        Content-Length: 0\r\n\r\n";
    send(&stack, &Bytes::from_static(reg_bob), bob()).await;
    let transport_param = if ep.transport == AddrTransport::Tcp {
        ";transport=tcp"
    } else {
        ""
    };
    let reg = Bytes::from(format!(
        "REGISTER sip:sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/{} {};branch=z9hG4bK-reg-carol\r\n\
         From: <sip:carol@sbc.local>;tag=r2\r\n\
         To: <sip:carol@sbc.local>\r\n\
         Call-ID: reg-carol@test\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <sip:carol@{}{transport_param}>\r\n\
         Expires: 3600\r\n\
         Content-Length: 0\r\n\r\n",
        ep.via(),
        ep.src,
        ep.src,
    ));
    let r = send_on(&stack, &reg, ep.src, ep.transport, ep.conn).await;
    assert!(
        responded(&r, 200).is_some(),
        "carol registered: {:?}",
        statuses(&r)
    );
    let r = send_on(
        &stack,
        &ep.request("INVITE", 1, None, Some(ALICE_SDP)),
        ep.src,
        ep.transport,
        ep.conn,
    )
    .await;
    let b_invite = forwarded(&r, &Method::Invite)
        .unwrap_or_else(|| panic!("endpoint INVITE forwarded: {:?}", statuses(&r)))
        .0
        .clone();
    let r = send(
        &stack,
        &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
        bob(),
    )
    .await;
    assert!(responded(&r, 200).is_some());
    send_on(
        &stack,
        &ep.request("ACK", 1, Some("bobtag"), None),
        ep.src,
        ep.transport,
        ep.conn,
    )
    .await;
    assert!(stack.pending_2xx.read().await.is_empty(), "ACK accepted");
    stack
}

/// T7: a registered UDP endpoint's dialog is pinned to its IP and port: a
/// re-INVITE from the same IP on another port gets 403; from the exact
/// flow it is relayed.
#[tokio::test]
async fn udp_endpoint_dialog_pinned_to_port() {
    let carol = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5060);
    let ep = Endpoint {
        src: carol,
        transport: AddrTransport::Udp,
        conn: None,
    };
    let stack = Box::pin(endpoint_call(&ep)).await;
    let neighbour = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5999);
    let r = send(
        &stack,
        &ep.request("INVITE", 2, Some("bobtag"), Some(OUTSIDER_SDP)),
        neighbour,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_none(),
        "re-INVITE from another port of the endpoint's IP relayed"
    );
    assert_eq!(statuses(&r), vec![403]);
    let r = send(
        &stack,
        &ep.request("INVITE", 3, Some("bobtag"), Some(ALICE_SDP)),
        carol,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "exact flow relayed"
    );
}

/// Positive half of T7: the exact-flow re-INVITE of a registered UDP
/// endpoint is relayed (guards the fixture of the negative test).
#[tokio::test]
async fn udp_endpoint_reinvite_on_its_flow_is_relayed() {
    let carol = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5060);
    let ep = Endpoint {
        src: carol,
        transport: AddrTransport::Udp,
        conn: None,
    };
    let stack = Box::pin(endpoint_call(&ep)).await;
    let r = send(
        &stack,
        &ep.request("INVITE", 2, Some("bobtag"), Some(ALICE_SDP)),
        carol,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "{:?}",
        statuses(&r)
    );
}

/// T6: a stream endpoint's dialog is bound to the connection it called on:
/// the same IP:port on another connection gets 403; on the original
/// connection the re-INVITE is relayed.
#[tokio::test]
async fn stream_endpoint_dialog_bound_to_connection() {
    let carol = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 8), 40_123);
    let c1 = Some(crate::stir_binding::ConnId::next());
    let c2 = Some(crate::stir_binding::ConnId::next());
    let ep = Endpoint {
        src: carol,
        transport: AddrTransport::Tcp,
        conn: c1,
    };
    let stack = Box::pin(endpoint_call(&ep)).await;
    let r = send_on(
        &stack,
        &ep.request("INVITE", 2, Some("bobtag"), Some(OUTSIDER_SDP)),
        carol,
        AddrTransport::Tcp,
        c2,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_none(),
        "re-INVITE on another connection relayed"
    );
    assert_eq!(statuses(&r), vec![403]);
    let r = send_on(
        &stack,
        &ep.request("INVITE", 3, Some("bobtag"), Some(ALICE_SDP)),
        carol,
        AddrTransport::Tcp,
        c1,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "original connection relayed"
    );
}

/// A call from trunk group `test-trunk` (192.168.1.1 and 192.168.1.2), with
/// a second trunk group `other-trunk` (192.168.1.9) configured.
async fn two_group_call() -> SipStack {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .register_inbound_trunk(
            "test-trunk",
            None,
            &[
                ("192.168.1.1".to_string(), AddrTransport::Udp),
                ("192.168.1.2".to_string(), AddrTransport::Udp),
            ],
        )
        .await;
    stack
        .register_inbound_trunk(
            "other-trunk",
            None,
            &[("192.168.1.9".to_string(), AddrTransport::Udp)],
        )
        .await;
    let reg_bob = b"REGISTER sip:sbc.local SIP/2.0\r\n\
        Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-reg\r\n\
        From: <sip:bob@sbc.local>;tag=r1\r\n\
        To: <sip:bob@sbc.local>\r\n\
        Call-ID: reg-bob@relay\r\n\
        CSeq: 1 REGISTER\r\n\
        Contact: <sip:bob@127.0.0.1:5060>\r\n\
        Expires: 3600\r\n\
        Content-Length: 0\r\n\r\n";
    send(&stack, &Bytes::from_static(reg_bob), bob()).await;
    let r = send(
        &stack,
        &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
        alice(),
    )
    .await;
    let b_invite = forwarded(&r, &Method::Invite).unwrap().0.clone();
    send(
        &stack,
        &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
        bob(),
    )
    .await;
    send(
        &stack,
        &alice_request("ACK", 1, Some("bobtag"), None),
        alice(),
    )
    .await;
    stack
}

/// T7 / trunk legs: in-dialog requests are accepted from any port and any
/// address of the leg's own trunk group (carriers send from several
/// hosts and ports).
#[tokio::test]
async fn trunk_leg_accepts_other_port_and_same_group_address() {
    let stack = Box::pin(two_group_call()).await;
    let mut cseq = 1;
    for from in [
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5999),
        SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 2), 5060),
    ] {
        cseq += 1;
        let r = send(
            &stack,
            &alice_request("INVITE", cseq, Some("bobtag"), Some(ALICE_SDP)),
            from,
        )
        .await;
        let (b_re, _) = forwarded(&r, &Method::Invite)
            .unwrap_or_else(|| panic!("trunk re-INVITE from {from}: {:?}", statuses(&r)));
        let b_re = b_re.clone();
        // Complete the transaction so the next re-INVITE is not glare.
        send(&stack, &response_to(&b_re, 200, None, Some(BOB_SDP)), bob()).await;
        send(
            &stack,
            &alice_request("ACK", cseq, Some("bobtag"), None),
            from,
        )
        .await;
    }
}

/// Trunk legs: a host of another trunk group is not the dialog peer: 403.
/// The leg's own trunk address on a stronger transport is (RFC 3261
/// §18.1.1: UDP to TCP for a large request; the transport is a floor).
#[tokio::test]
async fn trunk_leg_rejects_other_group_and_admits_stronger_transport() {
    let mut failures = Vec::new();
    let other_group = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 9), 5060);
    let stack = Box::pin(two_group_call()).await;
    let r = send(
        &stack,
        &alice_request("INVITE", 2, Some("bobtag"), Some(OUTSIDER_SDP)),
        other_group,
    )
    .await;
    if forwarded(&r, &Method::Invite).is_some() || statuses(&r) != vec![403] {
        failures.push(format!(
            "other trunk group: responses {:?}, forwarded {:?}",
            statuses(&r),
            forwarded_methods(&r)
        ));
    }
    // Fresh call: the case above may have left a re-INVITE pending.
    let stack = Box::pin(two_group_call()).await;
    let r = send_on(
        &stack,
        &alice_request("INVITE", 2, Some("bobtag"), Some(OUTSIDER_SDP)),
        alice(),
        AddrTransport::Tcp,
        Some(crate::stir_binding::ConnId::next()),
    )
    .await;
    if forwarded(&r, &Method::Invite).is_none() {
        failures.push(format!(
            "UDP trunk over TCP: responses {:?}, forwarded {:?}",
            statuses(&r),
            forwarded_methods(&r)
        ));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------
// ACK for a 2xx (RFC 3261 §13.2.2.4, §13.3.1.4)
// ---------------------------------------------------------------------

/// T3: the 2xx keeps being retransmitted until the ACK of the dialog
/// arrives: an ACK from a foreign host (with or without the right tags),
/// with a wrong To tag, with a wrong CSeq or with no CSeq does not stop it.
#[tokio::test]
async fn mismatched_ack_leaves_2xx_retransmission_pending() {
    let cases: [(&str, Bytes, SbcSocketAddr); 5] = [
        (
            "foreign host, no To tag",
            Bytes::from_static(
                b"ACK sip:bob@sbc.local SIP/2.0\r\n\
                Via: SIP/2.0/UDP 203.0.113.66:40000;branch=z9hG4bK-other-a\r\n\
                From: <sip:x@elsewhere.example>;tag=zz\r\n\
                To: <sip:bob@sbc.local>\r\n\
                Call-ID: call-relay@test\r\n\
                CSeq: 1 ACK\r\n\
                Content-Length: 0\r\n\r\n",
            ),
            outsider(),
        ),
        (
            "foreign host, dialog tags",
            alice_request("ACK", 1, Some("bobtag"), None),
            outsider(),
        ),
        (
            "peer, wrong To tag",
            alice_request("ACK", 1, Some("not-the-tag"), None),
            alice(),
        ),
        (
            "peer, wrong CSeq",
            alice_request("ACK", 7, Some("bobtag"), None),
            alice(),
        ),
        (
            "peer, no CSeq",
            drop_line(&alice_request("ACK", 1, Some("bobtag"), None), "CSeq:"),
            alice(),
        ),
    ];
    let mut failures = Vec::new();
    for (name, ack, from) in cases {
        let stack = Box::pin(answered_unacked()).await;
        let cap = uc_audit::capture::start();
        send(&stack, &ack, from).await;
        let left = stack.pending_2xx.read().await.len();
        if left != 1 {
            failures.push(format!("{name}: 2xx retransmission stopped"));
        }
        let p = denied_policies(&cap.events());
        if !p.iter().any(|x| x == "in-dialog:ack-mismatch") {
            failures.push(format!("{name}: no ack-mismatch audit ({p:?})"));
        }
        // The dialog's own ACK still stops it.
        send(
            &stack,
            &alice_request("ACK", 1, Some("bobtag"), None),
            alice(),
        )
        .await;
        if !stack.pending_2xx.read().await.is_empty() {
            failures.push(format!("{name}: the true ACK did not stop the 2xx"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Positive: the dialog's ACK (peer, CSeq 1, both tags) stops the 2xx.
#[tokio::test]
async fn dialog_ack_stops_2xx_retransmission() {
    let stack = Box::pin(answered_unacked()).await;
    let r = stack
        .process_message(
            &alice_request("ACK", 1, Some("bobtag"), None),
            alice(),
            None,
        )
        .await;
    assert!(matches!(r, ProcessResult::NoAction));
    assert!(stack.pending_2xx.read().await.is_empty());
}

// ---------------------------------------------------------------------
// BYE (RFC 3261 §15, §15.1.2)
// ---------------------------------------------------------------------

/// T4: after the dialog is confirmed, a BYE without a To tag names no
/// dialog: 481, the call stays up, nothing goes to the callee.
#[tokio::test]
async fn bye_without_to_tag_after_answer_is_481() {
    let (stack, _b) = Box::pin(established_call()).await;
    let cap = uc_audit::capture::start();
    let r = send(&stack, &alice_request("BYE", 2, None, None), alice()).await;
    let mut failures = Vec::new();
    if forwarded(&r, &Method::Bye).is_some() {
        failures.push("untagged BYE relayed to the callee".to_string());
    }
    if stack.call_count().await != 1 {
        failures.push("untagged BYE tore the call down".to_string());
    }
    if statuses(&r) != vec![481] {
        failures.push(format!("responses {:?}, want [481]", statuses(&r)));
    }
    let p = denied_policies(&cap.events());
    if !p.iter().any(|x| x == "in-dialog:to-tag-mismatch") {
        failures.push(format!("no to-tag-mismatch audit ({p:?})"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Positive: the caller's BYE with both tags from the peer ends the call.
#[tokio::test]
async fn bye_from_dialog_peer_ends_call() {
    let (stack, _b) = Box::pin(established_call()).await;
    let r = send(
        &stack,
        &alice_request("BYE", 2, Some("bobtag"), None),
        alice(),
    )
    .await;
    assert!(responded(&r, 200).is_some());
    let (_, dest) = forwarded(&r, &Method::Bye).expect("BYE relayed");
    assert_eq!(dest, bob());
    assert_eq!(stack.call_count().await, 0);
}

// ---------------------------------------------------------------------
// CANCEL (RFC 3261 §9.2, §17.2.3)
// ---------------------------------------------------------------------

/// Media controller that counts relay teardown calls.
#[derive(Default)]
struct TeardownMedia {
    inner: RecordingMedia,
    stops: AtomicUsize,
    removes: AtomicUsize,
    /// A relay was started after the last stop (a leaked relay once the
    /// call is gone).
    running: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl sbc_media_core::media_pipeline::MediaController for TeardownMedia {
    async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<uc_media_engine::MediaMode>,
        a: Option<std::net::IpAddr>,
        b: Option<std::net::IpAddr>,
    ) -> Result<
        sbc_media_core::media_pipeline::AllocatedPorts,
        sbc_media_core::media_pipeline::MediaPipelineError,
    > {
        self.inner
            .create_session_with_zones(call_id, mode, a, b)
            .await
    }
    async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), sbc_media_core::media_pipeline::MediaPipelineError> {
        self.inner
            .set_remote_address(call_id, is_a_leg, address)
            .await
    }
    async fn start_relay(
        &self,
        call_id: &str,
    ) -> Result<(), sbc_media_core::media_pipeline::MediaPipelineError> {
        self.running.store(true, AtomicOrdering::SeqCst);
        self.inner.start_relay(call_id).await
    }
    async fn start_relay_terminate(
        &self,
        call_id: &str,
        a: sbc_media_core::media_pipeline::LegDtlsParams,
        b: sbc_media_core::media_pipeline::LegDtlsParams,
    ) -> Result<(), sbc_media_core::media_pipeline::MediaPipelineError> {
        self.running.store(true, AtomicOrdering::SeqCst);
        self.inner.start_relay_terminate(call_id, a, b).await
    }
    async fn stop_relay(
        &self,
        _call_id: &str,
    ) -> Result<(), sbc_media_core::media_pipeline::MediaPipelineError> {
        self.running.store(false, AtomicOrdering::SeqCst);
        self.stops.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(())
    }
    async fn remove_session(
        &self,
        _call_id: &str,
    ) -> Result<(), sbc_media_core::media_pipeline::MediaPipelineError> {
        self.removes.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(())
    }
    async fn allocate_ports(
        &self,
    ) -> Result<(u16, u16), sbc_media_core::media_pipeline::MediaPipelineError> {
        self.inner.allocate_ports().await
    }
    async fn set_media_kind(
        &self,
        call_id: &str,
        kind: sbc_media_core::media_pipeline::MediaKind,
    ) -> Result<(), sbc_media_core::media_pipeline::MediaPipelineError> {
        self.inner.set_media_kind(call_id, kind).await
    }
}

/// A trunk call (`cdr_stack`) with a CDR ring and a teardown-counting media
/// controller, placed (ringing) with Call-ID `call_id`.
async fn cdr_media_call(
    call_id: &str,
) -> (
    SipStack,
    Arc<uc_cdr::CdrEmitter>,
    Arc<TeardownMedia>,
    SipRequest,
) {
    let (mut stack, em) = cdr_stack().await;
    let media = Arc::new(TeardownMedia::default());
    stack.set_media_pipeline(Arc::clone(&media) as _);
    let r = place_call(&stack, call_id).await;
    let inv = forwarded(&r, &Method::Invite)
        .expect("INVITE to the trunk")
        .0
        .clone();
    (stack, em, media, inv)
}

/// T9: a CANCEL that does not match the pending INVITE's transaction (wrong
/// branch, foreign host, wrong From tag, wrong CSeq number) gets 481 and
/// changes nothing: no 487, no CANCEL to the callee, no CDR, the call keeps
/// ringing and the caller's real CANCEL still works afterwards.
#[tokio::test]
async fn nonmatching_cancel_is_481_and_call_keeps_ringing() {
    let mut failures = Vec::new();
    for (n, case) in [
        "wrong branch",
        "foreign host",
        "wrong From tag",
        "wrong CSeq",
    ]
    .into_iter()
    .enumerate()
    {
        let cid = format!("cnm{n}@cdr");
        let (stack, em, media, _inv) = Box::pin(cdr_media_call(&cid)).await;
        let cap = uc_audit::capture::start();
        let good = caller_request("CANCEL", DIALED, &cid, 1, None, None);
        let (msg, from) = match case {
            "wrong branch" => (
                replace(
                    &good,
                    &format!("branch=z9hG4bK-{cid}-1"),
                    "branch=z9hG4bK-guess-1",
                ),
                alice(),
            ),
            "foreign host" => (good.clone(), outsider()),
            "wrong From tag" => (
                replace(&good, &format!("tag=a-{cid}"), "tag=guess"),
                alice(),
            ),
            _ => (replace(&good, "CSeq: 1 CANCEL", "CSeq: 2 CANCEL"), alice()),
        };
        let r = send(&stack, &msg, from).await;
        let st = statuses(&r);
        if st != vec![481] {
            failures.push(format!("{case}: responses {st:?}, want [481]"));
        }
        let fwd = forwarded_methods(&r);
        if !fwd.is_empty() {
            failures.push(format!("{case}: forwarded {fwd:?}"));
        }
        if stack.call_count().await != 1 {
            failures.push(format!("{case}: call torn down"));
        }
        if media.stops.load(AtomicOrdering::Relaxed) != 0 {
            failures.push(format!("{case}: media relay stopped"));
        }
        let written = cdrs(&em);
        if !written.is_empty() {
            failures.push(format!(
                "{case}: CDR written: {:?}",
                written.iter().map(|c| c.disposition).collect::<Vec<_>>()
            ));
        }
        let p = denied_policies(&cap.events());
        if !p.iter().any(|x| x == "in-dialog:cancel-no-match") {
            failures.push(format!("{case}: no cancel-no-match audit ({p:?})"));
        }
        // The call is still ringing: the caller's own CANCEL ends it.
        if stack.call_count().await == 1 {
            let r = send(&stack, &good, alice()).await;
            if responded(&r, 200).is_none() || responded(&r, 487).is_none() {
                failures.push(format!(
                    "{case}: true CANCEL then failed: {:?}",
                    statuses(&r)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Malformed CANCELs (no Via branch, no CSeq, no From tag) never tear the
/// call down; when answered at all, the answer is 481.
#[tokio::test]
async fn malformed_cancel_never_tears_down() {
    let mut failures = Vec::new();
    for (n, case) in ["no branch", "no CSeq", "no From tag"]
        .into_iter()
        .enumerate()
    {
        let cid = format!("cmal{n}@cdr");
        let (stack, em, _media, _inv) = Box::pin(cdr_media_call(&cid)).await;
        let good = caller_request("CANCEL", DIALED, &cid, 1, None, None);
        let msg = match case {
            "no branch" => replace(&good, &format!(";branch=z9hG4bK-{cid}-1"), ""),
            "no CSeq" => drop_line(&good, "CSeq:"),
            _ => replace(&good, &format!(";tag=a-{cid}"), ""),
        };
        let r = send(&stack, &msg, alice()).await;
        let st = statuses(&r);
        if st.iter().any(|s| *s != 481) {
            failures.push(format!("{case}: responses {st:?}"));
        }
        if !forwarded_methods(&r).is_empty() || stack.call_count().await != 1 {
            failures.push(format!("{case}: call torn down"));
        }
        if !cdrs(&em).is_empty() {
            failures.push(format!("{case}: CDR written"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// T10: a CANCEL that matches the INVITE after its 2xx was sent has no
/// effect (RFC 3261 §9.2): one 200, no 487, nothing to the
/// callee, the call and its media stay up and no "cancel" CDR is written.
/// A later BYE ends the call normally.
#[tokio::test]
async fn cancel_after_answer_is_200_and_call_intact() {
    let cid = "can-after-200@cdr";
    let (stack, em, media, inv) = Box::pin(cdr_media_call(cid)).await;
    answer(&stack, &inv, t1()).await;
    let ack = replace(
        &caller_request("ACK", DIALED, cid, 1, Some("bobtag"), None),
        &format!("branch=z9hG4bK-{cid}-1"),
        &format!("branch=z9hG4bK-{cid}-1-ack"),
    );
    send(&stack, &ack, alice()).await;
    assert!(stack.pending_2xx.read().await.is_empty(), "ACK accepted");

    let cancel = caller_request("CANCEL", DIALED, cid, 1, None, None);
    let r = send(&stack, &cancel, alice()).await;
    let mut failures = Vec::new();
    if statuses(&r) != vec![200] {
        failures.push(format!("responses {:?}, want exactly [200]", statuses(&r)));
    }
    let fwd = forwarded_methods(&r);
    if !fwd.is_empty() {
        failures.push(format!("forwarded to the callee: {fwd:?}"));
    }
    if stack.call_count().await != 1 {
        failures.push("call torn down".to_string());
    }
    if media.stops.load(AtomicOrdering::Relaxed) != 0
        || media.removes.load(AtomicOrdering::Relaxed) != 0
    {
        failures.push("media relay stopped".to_string());
    }
    let written = cdrs(&em);
    if !written.is_empty() {
        failures.push(format!(
            "CDR written: {:?}",
            written
                .iter()
                .map(|c| (c.disposition, c.release_cause))
                .collect::<Vec<_>>()
        ));
    }
    assert!(failures.is_empty(), "{failures:#?}");

    let bye = caller_request("BYE", DIALED, cid, 2, Some("bobtag"), None);
    let r = send(&stack, &bye, alice()).await;
    assert!(responded(&r, 200).is_some());
    assert!(forwarded(&r, &Method::Bye).is_some());
    assert_eq!(stack.call_count().await, 0);
    let c = one_cdr(&em);
    assert_eq!(c.disposition, uc_cdr::Disposition::Answered);
    assert_eq!(c.release_side, uc_cdr::ReleaseSide::Caller);
}

/// T10b: a CANCEL from a foreign host that carries only the answered call's
/// Call-ID gets 481 and the call stays up.
#[tokio::test]
async fn foreign_cancel_after_answer_is_481() {
    let (stack, _b) = Box::pin(established_call()).await;
    let cancel = Bytes::from_static(
        b"CANCEL sip:bob@sbc.local SIP/2.0\r\n\
        Via: SIP/2.0/UDP 203.0.113.66:40000;branch=z9hG4bK-other-c\r\n\
        From: <sip:x@elsewhere.example>;tag=zz\r\n\
        To: <sip:bob@sbc.local>\r\n\
        Call-ID: call-relay@test\r\n\
        CSeq: 1 CANCEL\r\n\
        Content-Length: 0\r\n\r\n",
    );
    let r = send(&stack, &cancel, outsider()).await;
    let mut failures = Vec::new();
    let fwd = forwarded_methods(&r);
    if !fwd.is_empty() {
        failures.push(format!("foreign CANCEL reached the callee: {fwd:?}"));
    }
    if stack.call_count().await != 1 {
        failures.push("foreign CANCEL tore down the call".to_string());
    }
    if statuses(&r) != vec![481] {
        failures.push(format!("responses {:?}, want [481]", statuses(&r)));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Positive: the caller's CANCEL of its pending INVITE (same branch, From
/// tag, CSeq number, from the INVITE's source) gets 200, the INVITE gets a
/// 487 (sent to the INVITE's source, with the INVITE's Via and CSeq), and
/// the callee gets a CANCEL.
#[tokio::test]
async fn matching_cancel_of_pending_invite_terminates_it() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    callee_trying(&stack, "call-relay@test").await;
    let r = send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    let (ok, dest) = responded(&r, 200).expect("200 to the CANCEL");
    assert_eq!(dest, alice());
    assert_eq!(ok.headers.cseq(), Some("1 CANCEL"));
    let (t, dest) = responded(&r, 487).expect("487 to the INVITE");
    assert_eq!(dest, alice());
    assert_eq!(t.headers.cseq(), Some("1 INVITE"));
    assert_eq!(t.headers.via_branch().as_deref(), Some(A_INVITE_BRANCH));
    assert_eq!(t.headers.from_tag().as_deref(), Some("i1"));
    assert!(t.headers.to_tag().is_some(), "487 carries a To tag");
    let (c, dest) = forwarded(&r, &Method::Cancel).expect("CANCEL to the callee");
    assert_eq!(dest, bob());
    assert_eq!(c.headers.via_branch(), b_invite.headers.via_branch());
    assert_eq!(stack.call_count().await, 0);
}

/// T11: the 487 belongs to the INVITE server transaction: a retransmitted
/// INVITE is answered with that 487, and the ACK for it is absorbed.
#[tokio::test]
async fn cancel_487_is_on_the_invite_transaction() {
    let (stack, _b) = Box::pin(ringing_call()).await;
    let r = send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    let (t, _) = responded(&r, 487).expect("487");
    let to_tag = t.headers.to_tag().expect("487 To tag");
    let r = send(
        &stack,
        &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
        alice(),
    )
    .await;
    let mut failures = Vec::new();
    if statuses(&r) != vec![487] || !forwarded_methods(&r).is_empty() {
        failures.push(format!(
            "INVITE retransmission: responses {:?} (want the stored [487]), forwarded {:?}",
            statuses(&r),
            forwarded_methods(&r)
        ));
    }
    let ack = replace(
        &alice_request("ACK", 1, Some(&to_tag), None),
        "branch=z9hG4bK-alice-1-ACK",
        &format!("branch={A_INVITE_BRANCH}"),
    );
    let r = send(&stack, &ack, alice()).await;
    if !r.is_empty() {
        failures.push(format!("ACK for the 487 not absorbed: {} results", r.len()));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// T12: a CANCEL that matches no INVITE transaction is answered at once,
/// even while some INVITE with its Call-ID is still being processed; it
/// never waits for that INVITE.
#[tokio::test(start_paused = true)]
async fn nonmatching_cancel_never_waits() {
    let stack = SipStack::new(SipStackConfig::default());
    stack.in_flight_invites.write().await.insert(
        "call-relay@test".to_string(),
        in_flight_of(&alice_request("INVITE", 1, None, Some(ALICE_SDP)), alice()),
    );
    let t0 = tokio::time::Instant::now();
    let r = send(
        &stack,
        &alice_cancel("z9hG4bK-unknown", "i1", 1),
        outsider(),
    )
    .await;
    let waited = t0.elapsed();
    assert_eq!(statuses(&r), vec![481]);
    assert_eq!(
        waited,
        std::time::Duration::ZERO,
        "unmatched CANCEL parked for {waited:?}"
    );
}

// ---------------------------------------------------------------------
// Audit / metrics (AU-2, SI-4)
// ---------------------------------------------------------------------

/// T13: every new dialog-binding reject policy has an exported gauge and an
/// audit policy name, and the policy and gauge lists stay aligned.
#[test]
fn dialog_binding_reject_policies_exported() {
    use crate::signaling_audit::{IN_DIALOG_METRIC_NAMES, InDialogPolicy};
    assert_eq!(InDialogPolicy::ALL.len(), IN_DIALOG_METRIC_NAMES.len());
    let names: Vec<&str> = InDialogPolicy::ALL.iter().map(|p| p.as_str()).collect();
    let mut failures = Vec::new();
    for (policy, gauge) in [
        (
            "in-dialog:to-tag-mismatch",
            "sbc_in_dialog_rejects_to_tag_mismatch_total",
        ),
        (
            "in-dialog:foreign-source",
            "sbc_in_dialog_rejects_foreign_source_total",
        ),
        (
            "in-dialog:ack-mismatch",
            "sbc_in_dialog_rejects_ack_mismatch_total",
        ),
        (
            "in-dialog:cancel-no-match",
            "sbc_in_dialog_rejects_cancel_no_match_total",
        ),
    ] {
        if !names.contains(&policy) {
            failures.push(format!("policy {policy} missing"));
        }
        if !IN_DIALOG_METRIC_NAMES.contains(&gauge) {
            failures.push(format!("gauge {gauge} missing"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------
// Round 1: re-registered flows, atomic CANCEL claim, RFC 2543, null tags
// ---------------------------------------------------------------------

/// Re-registers `aor_user` from `src` (UDP unless `conn` is given) with a
/// Contact naming that flow.
async fn reregister(
    stack: &SipStack,
    aor_user: &str,
    src: SbcSocketAddr,
    transport: AddrTransport,
    conn: Option<crate::stir_binding::ConnId>,
    cseq: u32,
) {
    let (via, param) = if transport == AddrTransport::Tcp {
        ("TCP", ";transport=tcp")
    } else {
        ("UDP", "")
    };
    let reg = Bytes::from(format!(
        "REGISTER sip:sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/{via} {src};branch=z9hG4bK-rereg-{aor_user}-{cseq}\r\n\
         From: <sip:{aor_user}@sbc.local>;tag=rr{cseq}\r\n\
         To: <sip:{aor_user}@sbc.local>\r\n\
         Call-ID: rereg-{aor_user}@test\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <sip:{aor_user}@{src}{param}>\r\n\
         Expires: 3600\r\n\
         Content-Length: 0\r\n\r\n"
    ));
    let r = send_on(stack, &reg, src, transport, conn).await;
    assert!(
        responded(&r, 200).is_some(),
        "{aor_user} re-registered: {:?}",
        statuses(&r)
    );
}

/// The one call's record.
async fn the_call(stack: &SipStack) -> CallAddresses {
    let corr = stack.call_correlation.read().await;
    assert_eq!(corr.addresses.len(), 1);
    corr.addresses.values().next().cloned().unwrap()
}

/// Decision A (RFC 5626 §4.4, §5.3): a registered UDP endpoint whose NAT
/// mapping moved re-registers from the new port; with REGISTER
/// authentication on, its in-dialog request from that port is its own and
/// the leg follows the new port. Without authentication (or unregistered,
/// see T7) the new port stays foreign.
#[tokio::test]
async fn registered_udp_endpoint_follows_its_new_nat_port() {
    let carol = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5060);
    let ep = Endpoint {
        src: carol,
        transport: AddrTransport::Udp,
        conn: None,
    };
    let mut stack = Box::pin(endpoint_call(&ep)).await;
    let moved = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 6000);
    reregister(&stack, "carol", moved, AddrTransport::Udp, None, 2).await;
    let r = send(
        &stack,
        &ep.request("INVITE", 2, Some("bobtag"), Some(ALICE_SDP)),
        moved,
    )
    .await;
    assert_eq!(
        statuses(&r),
        vec![403],
        "unauthenticated registration grants nothing"
    );

    stack.config.require_auth = true;
    let r = send(
        &stack,
        &ep.request("INVITE", 3, Some("bobtag"), Some(ALICE_SDP)),
        moved,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "re-registered flow relayed: {:?}",
        statuses(&r)
    );
    assert_eq!(the_call(&stack).await.a_leg_source, moved, "leg re-pinned");
    // A port of the same IP that holds no registration is still foreign.
    let other = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 6001);
    let r = send(&stack, &ep.request("INFO", 4, Some("bobtag"), None), other).await;
    assert_eq!(statuses(&r), vec![403]);
}

/// Decision A: a TCP endpoint that reconnected and re-registered on the new
/// connection keeps its dialog on it; a connection without the
/// registration is still foreign.
#[tokio::test]
async fn registered_stream_endpoint_follows_its_reconnected_flow() {
    let carol = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 8), 40_123);
    let c1 = Some(crate::stir_binding::ConnId::next());
    let ep = Endpoint {
        src: carol,
        transport: AddrTransport::Tcp,
        conn: c1,
    };
    let mut stack = Box::pin(endpoint_call(&ep)).await;
    stack.config.require_auth = true;
    let reconnected = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 8), 40_124);
    let c2 = Some(crate::stir_binding::ConnId::next());
    let c3 = Some(crate::stir_binding::ConnId::next());
    let r = send_on(
        &stack,
        &ep.request("INVITE", 2, Some("bobtag"), Some(OUTSIDER_SDP)),
        reconnected,
        AddrTransport::Tcp,
        c3,
    )
    .await;
    assert_eq!(statuses(&r), vec![403], "unregistered connection");
    stack.config.require_auth = false;
    reregister(&stack, "carol", reconnected, AddrTransport::Tcp, c2, 2).await;
    stack.config.require_auth = true;
    let r = send_on(
        &stack,
        &ep.request("INVITE", 3, Some("bobtag"), Some(ALICE_SDP)),
        reconnected,
        AddrTransport::Tcp,
        c2,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "reconnected flow relayed: {:?}",
        statuses(&r)
    );
    let call = the_call(&stack).await;
    assert_eq!(call.a_leg_conn, c2);
    assert_eq!(call.a_leg_source, reconnected);
}

/// Decision A on the B-leg: the registered callee re-registers from a new
/// port; its request from there is accepted and requests toward the
/// callee follow the new flow.
#[tokio::test]
async fn registered_callee_follows_its_new_flow() {
    let (mut stack, b_invite) = Box::pin(established_call()).await;
    let moved = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5070);
    reregister(&stack, "bob", moved, AddrTransport::Udp, None, 2).await;
    let reinvite = bob_request(&b_invite, "INVITE", 2, Some(BOB_SDP));
    let r = send(&stack, &reinvite, moved).await;
    assert_eq!(statuses(&r), vec![403], "auth off: not the peer");
    stack.config.require_auth = true;
    let reinvite = bob_request(&b_invite, "INVITE", 3, Some(BOB_SDP));
    let r = send(&stack, &reinvite, moved).await;
    let (_, dest) = forwarded(&r, &Method::Invite).expect("callee re-INVITE relayed");
    assert_eq!(dest, alice());
    assert_eq!(the_call(&stack).await.b_leg_destination, moved);
}

/// SEC-1: the 2xx is processed between the CANCEL's transaction match and
/// its teardown (here: the record is already answered when the CANCEL
/// claims it). The claim refuses: exactly one 200, no 487, nothing toward
/// the callee, the call stays.
#[tokio::test]
async fn cancel_loses_to_an_answer_that_lands_first() {
    let (stack, _b) = Box::pin(ringing_call()).await;
    for a in stack.call_correlation.write().await.addresses.values_mut() {
        a.b_leg_answered = true;
    }
    let r = send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    assert_eq!(statuses(&r), vec![200]);
    assert!(
        forwarded_methods(&r).is_empty(),
        "{:?}",
        forwarded_methods(&r)
    );
    assert_eq!(stack.call_count().await, 1);
}

/// SEC-1, interleaved: the caller's CANCEL and the callee's 200 race on
/// worker threads. Whatever wins, the caller never gets both the 487 and
/// the relayed 200 for its INVITE, and a refused CANCEL leaves the call up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_racing_the_answer_never_ends_the_call_twice() {
    for _ in 0..16 {
        let (stack, b_invite) = Box::pin(ringing_call()).await;
        let stack = Arc::new(stack);
        let (s1, s2) = (Arc::clone(&stack), Arc::clone(&stack));
        let cancel = alice_cancel(A_INVITE_BRANCH, "i1", 1);
        let ok = response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP));
        let c = tokio::spawn(async move { send(&s1, &cancel, alice()).await });
        let a = tokio::spawn(async move { send(&s2, &ok, bob()).await });
        let (rc, ra) = (c.await.unwrap(), a.await.unwrap());
        let terminated = responded(&rc, 487).is_some();
        let answered = ra.iter().any(|r| {
            matches!(r, ProcessResult::Response { message: SipMessage::Response(resp), destination, .. }
                if resp.status.code() == 200
                    && *destination == alice()
                    && resp.headers.cseq_parsed().is_some_and(|c| c.method == Method::Invite))
        });
        assert!(
            !(terminated && answered),
            "487 and 200 both sent: cancel {:?}, answer {:?}",
            statuses(&rc),
            statuses(&ra)
        );
        if !terminated {
            assert_eq!(stack.call_count().await, 1, "refused CANCEL kept the call");
        }
    }
}

/// RFC-06 / NIST-06: a matching CANCEL that arrives while the INVITE is
/// still being routed (no call record yet) gets 200 and marks the INVITE;
/// when routing ends the INVITE is answered 487 and never forwarded.
#[tokio::test]
async fn cancel_while_routing_answers_487_instead_of_forwarding() {
    let (stack, _b) = Box::pin(ringing_call()).await;
    let cid = "call-relay@test";
    // Rewind to "routing": the record is not stored yet, the INVITE is in
    // flight.
    let (id, rec) = {
        let mut corr = stack.call_correlation.write().await;
        let id = corr.a_leg.remove(cid).unwrap();
        let rec = corr.addresses.remove(&id).unwrap();
        (id, rec)
    };
    stack.in_flight_invites.write().await.insert(
        cid.to_string(),
        in_flight_of(&alice_request("INVITE", 1, None, Some(ALICE_SDP)), alice()),
    );
    let r = send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    assert_eq!(statuses(&r), vec![200]);
    assert_eq!(forwarded_methods(&r), Vec::<String>::new());
    assert!(
        stack
            .in_flight_invites
            .read()
            .await
            .get(cid)
            .is_some_and(|e| e.cancelled),
        "INVITE marked cancelled"
    );
    // Routing ends: the INVITE path stores the record, sees the mark.
    {
        let mut corr = stack.call_correlation.write().await;
        corr.a_leg.insert(cid.to_string(), id.clone());
        corr.addresses.insert(id.clone(), rec);
    }
    let marked = stack.in_flight_invites.write().await.remove(cid);
    assert!(marked.is_some_and(|e| e.cancelled));
    let out = flatten(stack.invite_cancelled_while_routing(&id).await);
    let (t, dest) = responded(&out, 487).expect("487 to the INVITE");
    assert_eq!(dest, alice());
    assert_eq!(t.headers.cseq(), Some("1 INVITE"));
    assert_eq!(forwarded_methods(&out), Vec::<String>::new());
    assert_eq!(stack.call_count().await, 0);
}

/// RFC-05 (backed out) / RFC-14: a CANCEL of the caller's pending
/// re-INVITE gets 200 and changes nothing: nothing is relayed and the
/// re-INVITE completes. A far-leg response with the re-INVITE's branch but
/// CSeq method CANCEL (the shape of a 200 to a CANCEL) is never taken as
/// the re-INVITE's final response.
#[tokio::test]
async fn cancel_of_pending_reinvite_changes_nothing() {
    let (stack, _b) = Box::pin(established_call()).await;
    let r = send(
        &stack,
        &alice_request("INVITE", 2, Some("bobtag"), Some(ALICE_MOVED_SDP)),
        alice(),
    )
    .await;
    let (fwd, _) = forwarded(&r, &Method::Invite).expect("re-INVITE relayed");
    let fwd = fwd.clone();
    let r = send(
        &stack,
        &alice_cancel("z9hG4bK-alice-2-INVITE", "i1", 2),
        alice(),
    )
    .await;
    assert_eq!(statuses(&r), vec![200]);
    assert_eq!(forwarded_methods(&r), Vec::<String>::new());
    assert!(the_call(&stack).await.pending_reinvite.is_some());

    // A 200 shaped like the answer to a CANCEL of the relayed re-INVITE.
    let cancel_shaped = replace(
        &response_to(&fwd, 200, None, None),
        &format!("{} INVITE", fwd.headers.cseq_parsed().unwrap().sequence),
        &format!("{} CANCEL", fwd.headers.cseq_parsed().unwrap().sequence),
    );
    let r = send(&stack, &cancel_shaped, bob()).await;
    assert!(
        r.iter().all(|x| matches!(x, ProcessResult::NoAction)),
        "{r:?}"
    );
    assert!(
        the_call(&stack).await.pending_reinvite.is_some(),
        "re-INVITE still pending"
    );
    // The far leg's real answer completes it.
    let r = send(&stack, &response_to(&fwd, 200, None, Some(BOB_SDP)), bob()).await;
    let (ok, dest) = responded(&r, 200).expect("re-INVITE 200 relayed");
    assert_eq!(dest, alice());
    assert_eq!(ok.headers.cseq(), Some("2 INVITE"));
    assert_eq!(stack.call_count().await, 1);
}

/// SEC-2: a foreign request on the caller's branch has a transaction of its
/// own: the caller's MESSAGE is relayed once, its retransmission is
/// answered from the caller's own transaction, and the foreign host never
/// gets the caller's response.
#[tokio::test]
async fn foreign_request_on_callers_branch_neither_blocks_nor_reads_it() {
    let (stack, _b) = Box::pin(established_call()).await;
    let msg = alice_request("MESSAGE", 3, Some("bobtag"), None);
    let forged = replace(&msg, "tag=i1", "tag=evil");
    let r = send(&stack, &forged, outsider()).await;
    assert_eq!(forwarded_methods(&r), Vec::<String>::new());
    let foreign_status = statuses(&r);
    let r = send(&stack, &msg, alice()).await;
    let (relayed, _) = forwarded(&r, &Method::Message).expect("caller's MESSAGE relayed");
    let relayed = relayed.clone();
    let r = send(&stack, &response_to(&relayed, 200, None, None), bob()).await;
    assert!(responded(&r, 200).is_some(), "{:?}", statuses(&r));
    let r = send(&stack, &msg, alice()).await;
    assert!(
        forwarded_methods(&r).is_empty(),
        "retransmission relayed again: {:?}",
        forwarded_methods(&r)
    );
    assert_eq!(statuses(&r), vec![200], "answered from its transaction");
    let r = send(&stack, &forged, outsider()).await;
    assert_eq!(
        statuses(&r),
        foreign_status,
        "foreign copy keeps its own answer"
    );
}

/// RFC-03: a trunk B-leg's peers are all configured hosts of the routed
/// trunk group, also hosts that are not in the inbound trunk map.
#[tokio::test]
async fn trunk_peer_set_is_the_groups_configured_hosts() {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .index_trunk_group_hosts(
            "carrier",
            &[
                ("198.51.100.20".to_string(), 5060),
                ("198.51.100.21".to_string(), 5060),
            ],
        )
        .await;
    let host = |last: u8| SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, last), 5060);
    let peer = DialogPeer::b_leg(
        host(20),
        AddrTransport::Udp,
        BLegPeerKind::Trunk,
        Some("carrier"),
        None,
    );
    let at = |source| Ingress {
        source,
        transport: AddrTransport::Udp,
        conn: None,
    };
    assert_eq!(
        stack.peer_admits(&peer, &at(host(21))).await,
        PeerMatch::Same
    );
    assert_eq!(stack.peer_admits(&peer, &at(host(22))).await, PeerMatch::No);
    stack.remove_trunk_group_from_router("carrier").await;
    assert_eq!(stack.peer_admits(&peer, &at(host(21))).await, PeerMatch::No);
}

/// RFC-07: an RFC 2543 caller (no magic cookie in its branch) cancels its
/// INVITE with a CANCEL whose Request-URI, tags, Call-ID, CSeq number and
/// top Via equal the INVITE's; one that differs gets 481. RFC-10: the 200
/// to the CANCEL and the 487 carry the same To tag.
#[tokio::test]
async fn rfc2543_cancel_ends_the_invite_with_one_to_tag() {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .register_inbound_trunk(
            "test-trunk",
            None,
            &[("192.168.1.1".to_string(), AddrTransport::Udp)],
        )
        .await;
    let register = Bytes::from_static(
        b"REGISTER sip:sbc.local SIP/2.0\r\n\
        Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-reg\r\n\
        From: <sip:bob@sbc.local>;tag=r1\r\n\
        To: <sip:bob@sbc.local>\r\n\
        Call-ID: reg-bob@relay\r\n\
        CSeq: 1 REGISTER\r\n\
        Contact: <sip:bob@127.0.0.1:5060>\r\n\
        Expires: 3600\r\n\
        Content-Length: 0\r\n\r\n",
    );
    send(&stack, &register, bob()).await;
    let invite = replace(
        &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
        "branch=z9hG4bK-alice-1-INVITE",
        "branch=legacy1",
    );
    let r = send(&stack, &invite, alice()).await;
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "{:?}",
        statuses(&r)
    );

    let r = send(&stack, &alice_cancel("legacy1", "i1", 2), alice()).await;
    assert_eq!(statuses(&r), vec![481], "CSeq number differs");
    let r = send(&stack, &alice_cancel("legacy1", "i1", 1), outsider()).await;
    assert_eq!(statuses(&r), vec![481], "not the caller's peer");
    callee_trying(&stack, "call-relay@test").await;
    let r = send(&stack, &alice_cancel("legacy1", "i1", 1), alice()).await;
    let (ok, _) = responded(&r, 200).expect("200 to the CANCEL");
    let (t, _) = responded(&r, 487).expect("487 to the INVITE");
    assert!(ok.headers.to_tag().is_some());
    assert_eq!(ok.headers.to_tag(), t.headers.to_tag(), "one To tag");
    assert!(forwarded(&r, &Method::Cancel).is_some());
    assert_eq!(stack.call_count().await, 0);
}

/// RFC-08 / SEC-7: a callee that answers without a To tag (RFC 2543) still
/// has a dialog: the caller sees the SBC's own tag, its ACK stops the 2xx
/// (null tags match null tags) and its BYE ends the call.
#[tokio::test]
async fn untagged_answer_still_makes_a_dialog() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    let r = send(
        &stack,
        &response_to(&b_invite, 200, None, Some(BOB_SDP)),
        bob(),
    )
    .await;
    let (ok, _) = responded(&r, 200).expect("200 relayed to the caller");
    let tag = ok.headers.to_tag().expect("the SBC tags the caller's 200");
    let r = send(&stack, &alice_request("ACK", 1, Some(&tag), None), alice()).await;
    assert!(r.iter().all(|x| matches!(x, ProcessResult::NoAction)) || r.is_empty());
    assert!(stack.pending_2xx.read().await.is_empty(), "ACK accepted");
    let r = send(&stack, &alice_request("BYE", 2, Some(&tag), None), alice()).await;
    assert!(responded(&r, 200).is_some(), "{:?}", statuses(&r));
    let (bye, _) = forwarded(&r, &Method::Bye).expect("BYE toward the callee");
    assert_eq!(bye.headers.to_tag(), None, "callee's null tag kept");
    assert_eq!(stack.call_count().await, 0);
}

/// RFC-11: the tag of an unreliable 1xx relayed to the caller names an
/// early dialog: the caller's request in it is not rejected as a tag
/// mismatch.
#[tokio::test]
async fn relayed_provisional_tag_is_an_early_local_tag() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    let r = send(&stack, &response_to(&b_invite, 180, None, None), bob()).await;
    let (ringing, _) = responded(&r, 180).expect("180 relayed");
    let tag = ringing.headers.to_tag().expect("tagged 180");
    assert!(the_call(&stack).await.a_leg_early_tags.contains(&tag));
    let r = send(&stack, &alice_request("INFO", 2, Some(&tag), None), alice()).await;
    assert!(
        !statuses(&r).contains(&481) && !statuses(&r).contains(&403),
        "{:?}",
        statuses(&r)
    );
}

// ---------------------------------------------------------------------
// Round 2: CANCEL after a provisional, BYE conversion, answer races, AORs
// ---------------------------------------------------------------------

/// RFC-15 (RFC 3261 §9.1): a CANCEL before the callee sent any provisional
/// waits on the B-leg INVITE transaction: the caller gets 200 and 487 at
/// once, the CANCEL goes out with the callee's first 1xx (the INVITE's
/// branch), and nothing goes to the callee before.
#[tokio::test]
async fn b_leg_cancel_waits_for_a_provisional() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    let r = send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    assert!(responded(&r, 200).is_some() && responded(&r, 487).is_some());
    assert_eq!(forwarded_methods(&r), Vec::<String>::new(), "no CANCEL yet");
    let r = send(
        &stack,
        &response_to(&b_invite, 180, Some("bobtag"), None),
        bob(),
    )
    .await;
    let (c, dest) = forwarded(&r, &Method::Cancel).expect("CANCEL with the 1xx");
    assert_eq!(dest, bob());
    assert_eq!(c.headers.via_branch(), b_invite.headers.via_branch());
    assert!(
        responded(&r, 180).is_none(),
        "1xx of a cancelled call not relayed"
    );
    // Only once.
    let r = send(
        &stack,
        &response_to(&b_invite, 183, Some("bobtag"), None),
        bob(),
    )
    .await;
    assert!(forwarded(&r, &Method::Cancel).is_none());
}

/// RFC-15: a final response before any provisional makes the queued
/// CANCEL moot: the final is ACKed, no CANCEL is ever sent.
#[tokio::test]
async fn queued_b_leg_cancel_dropped_on_a_final() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    let r = send(
        &stack,
        &response_to(&b_invite, 486, Some("bobtag"), None),
        bob(),
    )
    .await;
    assert_eq!(forwarded_methods(&r), vec!["ACK".to_string()]);
    let r = send(
        &stack,
        &response_to(&b_invite, 180, Some("bobtag"), None),
        bob(),
    )
    .await;
    assert!(forwarded(&r, &Method::Cancel).is_none());
}

/// RFC-17: the caller's BYE before the answer is carried out as the CANCEL
/// of the B-leg INVITE (its Request-URI, Call-ID, From, To and top Via
/// branch) and a 487 on the caller's INVITE, with the BYE's 200 and the 487
/// sharing one To tag.
#[tokio::test]
async fn early_bye_cancels_the_b_leg_invite_and_487s_the_caller() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    callee_trying(&stack, "call-relay@test").await;
    let r = send(&stack, &alice_request("BYE", 2, None, None), alice()).await;
    let (ok, _) = responded(&r, 200).expect("200 to the BYE");
    assert_eq!(ok.headers.cseq(), Some("2 BYE"));
    let (t, dest) = responded(&r, 487).expect("487 to the INVITE");
    assert_eq!(dest, alice());
    assert_eq!(t.headers.cseq(), Some("1 INVITE"));
    assert_eq!(ok.headers.to_tag(), t.headers.to_tag(), "one To tag");
    let (c, dest) = forwarded(&r, &Method::Cancel).expect("CANCEL toward the callee");
    assert_eq!(dest, bob());
    assert_eq!(c.uri, b_invite.uri);
    assert_eq!(c.headers.call_id(), b_invite.headers.call_id());
    assert_eq!(c.headers.via_branch(), b_invite.headers.via_branch());
    assert_eq!(
        c.headers.via_parsed().map(|v| (v.host, v.port)),
        b_invite.headers.via_parsed().map(|v| (v.host, v.port)),
        "same sent-by"
    );
    assert_eq!(c.headers.cseq(), Some("1 CANCEL"));
    assert_eq!(stack.call_count().await, 0);
}

/// SEC-9: the caller's early BYE and the callee's 200 race. If the BYE
/// wins, the call ends and no media relay is left running for it; if the
/// answer lands first, the untagged BYE names no confirmed dialog (481) and
/// the call stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_bye_racing_the_answer_leaves_no_relay_running() {
    for n in 0..16 {
        let cid = format!("bye-race-{n}@cdr");
        let (stack, em, media, inv) = Box::pin(cdr_media_call(&cid)).await;
        let stack = Arc::new(stack);
        let (s1, s2) = (Arc::clone(&stack), Arc::clone(&stack));
        let bye = caller_request("BYE", DIALED, &cid, 2, None, None);
        let ok = response_to(&inv, 200, Some("bobtag"), Some(BOB_SDP));
        let b = tokio::spawn(async move { send(&s1, &bye, alice()).await });
        let a = tokio::spawn(async move { send(&s2, &ok, t1()).await });
        let (rb, ra) = (b.await.unwrap(), a.await.unwrap());
        if statuses(&rb) == vec![481] {
            assert_eq!(stack.call_count().await, 1, "answered call stays up");
            assert_eq!(cdrs(&em).len(), 0, "no CDR for a call still up");
            continue;
        }
        let ok_tag = responded(&rb, 200)
            .unwrap_or_else(|| panic!("{:?}", statuses(&rb)))
            .0
            .headers
            .to_tag();
        assert_eq!(stack.call_count().await, 0, "call ended");
        assert!(
            !media.running.load(AtomicOrdering::SeqCst),
            "relay left running after the call ended"
        );
        let all: Vec<ProcessResult> = rb.into_iter().chain(ra).collect();
        let to_callee = forwarded_methods(&all);
        let invite_200 = all.iter().any(|r| {
            matches!(r, ProcessResult::Response { message: SipMessage::Response(x), .. }
                if x.status.code() == 200 && x.headers.cseq() == Some("1 INVITE"))
        });
        if invite_200 {
            // The answer committed first: the BYE then ended the confirmed
            // call (BYE toward the callee), and no 487 is due.
            assert!(responded(&all, 487).is_none(), "487 after the 200");
            assert!(to_callee.contains(&"BYE".to_string()), "{to_callee:?}");
        } else {
            // RFC-21: the BYE won: the caller's INVITE got a 487 with the
            // BYE's To tag, and the callee's INVITE/dialog was ended (ACK
            // and BYE for its 2xx, or a CANCEL sent or queued).
            let (t, dest) = responded(&all, 487)
                .unwrap_or_else(|| panic!("487 to the INVITE: {:?} {to_callee:?}", statuses(&all)));
            assert_eq!(dest, alice());
            assert_eq!(t.headers.cseq(), Some("1 INVITE"));
            assert_eq!(t.headers.to_tag(), ok_tag, "one To tag");
            let txns = stack.transactions.read().await;
            assert!(
                (to_callee.contains(&"ACK".to_string()) && to_callee.contains(&"BYE".to_string()))
                    || to_callee.contains(&"CANCEL".to_string())
                    || !txns.early_cancels.is_empty()
                    || txns
                        .client_invite
                        .values()
                        .any(|t| t.pending_cancel.is_some()),
                "callee's INVITE / dialog not ended: {to_callee:?}"
            );
        }
        assert_eq!(cdrs(&em).len(), 1, "exactly one CDR");
    }
}

/// SEC-10: two AORs share the caller's flow (a shared NAT address). The
/// dialog follows only the From user's own registration: another AOR's
/// new flow is foreign; the caller's own re-registration from a new port
/// is accepted. Without an instance-id a new flow from another IP is
/// foreign even when it holds the caller's registration.
#[tokio::test]
async fn new_flow_must_hold_the_callers_own_registration() {
    let carol = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5060);
    let ep = Endpoint {
        src: carol,
        transport: AddrTransport::Udp,
        conn: None,
    };
    let mut stack = Box::pin(endpoint_call(&ep)).await;
    reregister(&stack, "dave", carol, AddrTransport::Udp, None, 1).await;
    let dave_moved = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 6100);
    reregister(&stack, "dave", dave_moved, AddrTransport::Udp, None, 2).await;
    let carol_moved = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 6200);
    reregister(&stack, "carol", carol_moved, AddrTransport::Udp, None, 2).await;
    stack.config.require_auth = true;

    let r = send(
        &stack,
        &ep.request("INFO", 2, Some("bobtag"), None),
        dave_moved,
    )
    .await;
    assert_eq!(statuses(&r), vec![403], "another AOR's flow");
    assert_eq!(the_call(&stack).await.a_leg_source, carol, "not re-pinned");
    let r = send(
        &stack,
        &ep.request("INVITE", 3, Some("bobtag"), Some(ALICE_SDP)),
        carol_moved,
    )
    .await;
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "{:?}",
        statuses(&r)
    );
    assert_eq!(the_call(&stack).await.a_leg_source, carol_moved);

    // Carol's registration moves to another IP: without an instance-id
    // that flow is not hers to claim.
    stack.config.require_auth = false;
    let elsewhere = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 77), 6300);
    reregister(&stack, "carol", elsewhere, AddrTransport::Udp, None, 3).await;
    stack.config.require_auth = true;
    let r = send(
        &stack,
        &ep.request("INFO", 4, Some("bobtag"), None),
        elsewhere,
    )
    .await;
    assert_eq!(statuses(&r), vec![403], "another IP without an instance-id");
    assert_eq!(the_call(&stack).await.a_leg_source, carol_moved);
}

/// SEC-10: a request from a re-registered flow that the handler refuses
/// (here: 491, a re-INVITE while one is pending) does not move the leg.
#[tokio::test]
async fn refused_request_from_a_new_flow_does_not_repin() {
    let carol = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 5060);
    let ep = Endpoint {
        src: carol,
        transport: AddrTransport::Udp,
        conn: None,
    };
    let mut stack = Box::pin(endpoint_call(&ep)).await;
    let moved = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 7), 6000);
    reregister(&stack, "carol", moved, AddrTransport::Udp, None, 2).await;
    stack.config.require_auth = true;
    let r = send(
        &stack,
        &ep.request("INVITE", 2, Some("bobtag"), Some(ALICE_SDP)),
        carol,
    )
    .await;
    assert!(forwarded(&r, &Method::Invite).is_some());
    let r = send(
        &stack,
        &ep.request("INVITE", 3, Some("bobtag"), Some(ALICE_SDP)),
        moved,
    )
    .await;
    assert_eq!(statuses(&r), vec![491]);
    assert_eq!(the_call(&stack).await.a_leg_source, carol);
}

/// RFC-16: a 2xx without a To tag (RFC 2543 UAS) that arrives after the
/// call was cancelled is still ACKed and BYEd (the null tag is a tag of its
/// own), from the stored B-leg dialog.
#[tokio::test]
async fn late_untagged_2xx_after_cancel_is_acked_and_byed() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    callee_trying(&stack, "call-relay@test").await;
    let r = send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    assert!(responded(&r, 487).is_some());
    let r = send(
        &stack,
        &response_to(&b_invite, 200, None, Some(BOB_SDP)),
        bob(),
    )
    .await;
    let (ack, _) = forwarded(&r, &Method::Ack).expect("late 2xx ACKed");
    let (bye, _) = forwarded(&r, &Method::Bye).expect("late 2xx BYEd");
    assert_eq!(ack.headers.to_tag(), None);
    assert_eq!(bye.headers.to_tag(), None);
    assert!(responded(&r, 200).is_none(), "nothing to the caller");
}

/// RFC-23: a CANCEL that finds no B-leg client transaction yet (the INVITE
/// is still being handed to the transport) waits for that transaction even
/// though the call is already released, then for the first provisional.
#[tokio::test]
async fn cancel_before_the_b_leg_transaction_opens_waits_for_it() {
    let (stack, b_invite) = Box::pin(ringing_call()).await;
    let key = TransactionKey::client(b_invite.headers.via_branch().unwrap(), "INVITE");
    let st = stack
        .transactions
        .write()
        .await
        .client_invite
        .remove(&key)
        .expect("B-leg INVITE transaction");
    let r = send(&stack, &alice_cancel(A_INVITE_BRANCH, "i1", 1), alice()).await;
    assert!(responded(&r, 487).is_some());
    assert_eq!(forwarded_methods(&r), Vec::<String>::new());
    assert_eq!(stack.transactions.read().await.early_cancels.len(), 1);
    // The INVITE's transaction opens now (its call record is gone).
    stack
        .open_client_transaction(&st.request, st.destination, st.flow.clone())
        .await;
    assert!(stack.transactions.read().await.early_cancels.is_empty());
    let r = send(&stack, &response_to(&b_invite, 100, None, None), bob()).await;
    let (c, _) = forwarded(&r, &Method::Cancel).expect("CANCEL with the 100");
    assert_eq!(c.headers.via_branch(), b_invite.headers.via_branch());
}

/// RFC-21, deterministic: the caller's BYE lands while the callee's 2xx is
/// being set up (answer claimed, not committed). The BYE gets 200 at once;
/// when the 2xx commits, the caller's INVITE gets a 487 with the same To
/// tag (on the INVITE transaction), the callee gets ACK and BYE, no 200
/// reaches the caller, no relay is left running and one CDR is written.
#[tokio::test]
async fn bye_during_answer_setup_487s_the_invite_when_the_answer_commits() {
    let cid = "bye-pending@cdr";
    let (stack, em, media, inv) = Box::pin(cdr_media_call(cid)).await;
    set_answer_claimed(&stack, true).await;
    let r = send(
        &stack,
        &caller_request("BYE", DIALED, cid, 2, None, None),
        alice(),
    )
    .await;
    assert_eq!(statuses(&r), vec![200]);
    assert_eq!(forwarded_methods(&r), Vec::<String>::new());
    let bye_tag = responded(&r, 200).unwrap().0.headers.to_tag();
    // Hand the answer back to the 2xx path, which now runs and commits.
    set_answer_claimed(&stack, false).await;
    let r = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(BOB_SDP)),
        t1(),
    )
    .await;
    let (t, dest) = responded(&r, 487).expect("487 to the INVITE");
    assert_eq!(dest, alice());
    assert_eq!(t.headers.cseq(), Some("1 INVITE"));
    assert_eq!(t.headers.to_tag(), bye_tag, "one To tag");
    assert!(responded(&r, 200).is_none(), "no 200 to the caller");
    let fwd = forwarded_methods(&r);
    assert!(
        fwd.contains(&"ACK".to_string()) && fwd.contains(&"BYE".to_string()),
        "{fwd:?}"
    );
    assert_eq!(stack.call_count().await, 0);
    assert!(!media.running.load(AtomicOrdering::SeqCst));
    assert_eq!(cdrs(&em).len(), 1);
    // The 487 is on the INVITE transaction: a retransmitted INVITE gets it.
    let r = send(
        &stack,
        &caller_request("INVITE", DIALED, cid, 1, None, Some(ALICE_SDP)),
        alice(),
    )
    .await;
    assert!(responded(&r, 487).is_some(), "{:?}", statuses(&r));
}

/// Sets `b_leg_answer_claimed` on every call record (a 2xx being set up).
async fn set_answer_claimed(stack: &SipStack, v: bool) {
    for a in stack.call_correlation.write().await.addresses.values_mut() {
        a.b_leg_answer_claimed = v;
    }
}
