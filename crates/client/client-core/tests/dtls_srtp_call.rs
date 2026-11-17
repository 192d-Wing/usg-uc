//! DTLS-SRTP on TLS-account calls, end to end through the public
//! `CallManager` API (POA&M-324): scripted SIP messages plus an in-process
//! DTLS peer on the media address written into the SDP.
//!
//! What is shown: a call is reported `Connecting` while the handshake
//! runs and `Connected` only after it completed, in both call directions
//! and both DTLS roles, with SRTP keys that the peer's keys open; every
//! other outcome ends the call as a media-security failure with a fixed
//! cause and is never reported `Connected`; the SIP pump stays responsive
//! while a handshake is pending; a mid-call `close_notify` or fatal alert
//! ends the call.
//!
//! Not asserted: that an audio session exists. Without an audio device
//! (CI) the pipeline does not start and the call still connects, so where
//! a test needs a post-handshake DTLS record to reach the driver it pushes
//! it through `MediaSession::dtls_forward_tx` itself.
// NIST 800-53 Rev5: SC-8(1), SC-23, SC-5. RFC 5763 §5, RFC 5764 §4.1/§4.2.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

mod common;

use client_core::{CallManager, CallManagerEvent, SipTransportKind};
use client_sip_ua::MediaSession;
use client_types::{CallEndReason, CallState};
use common::dtls::{self, Puppet};
use common::{
    Peer, Seen, answer_call, body_of, bye_for_outbound, connected, drain, end_reason, ended,
    error_messages, in_dialog, invite, local_media, manager, ok_body, opposite, place_call, pump,
    remote_sdp, reported_connected, reported_states, sip_peer,
};
use proto_dtls::record::ContentType;
use proto_dtls::{CertificateFingerprint, DtlsRole};
use proto_rtp::{RtpHeader, RtpPacket};
use proto_srtp::{SrtpDirection, SrtpProtect, SrtpUnprotect};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

type Events = mpsc::Receiver<CallManagerEvent>;

/// RFC 5764 §4.2: SRTP protected with our send key opens with the peer's
/// receive key and the reverse, so the key direction follows the role.
fn assert_srtp_both_ways(session: &MediaSession, peer: &Peer, our_role: DtlsRole) {
    let ours = session.negotiated_srtp_keys().expect("client keys");
    let theirs = peer.keys.as_ref().expect("peer keys");
    let peer_role = opposite(our_role);
    let payload = vec![0x5Au8; 160];
    let round_trip = |tx_key: &[u8], tx_salt: &[u8], rx_key: &[u8], rx_salt: &[u8], ssrc: u32| {
        let tx = dtls::srtp_context(tx_key, tx_salt, SrtpDirection::Outbound, ssrc);
        let rx = dtls::srtp_context(rx_key, rx_salt, SrtpDirection::Inbound, ssrc);
        let packet = RtpPacket::new(RtpHeader::new(0, 7, 1120, ssrc), payload.clone());
        let protected = SrtpProtect::new(&tx).protect_rtp(&packet).unwrap();
        let opened = SrtpUnprotect::new(&rx).unprotect_rtp(&protected).unwrap();
        assert_eq!(opened.payload.as_ref(), payload.as_slice());
    };
    round_trip(
        ours.local_key(),
        ours.local_salt(),
        theirs.remote_key(peer_role),
        theirs.remote_salt(peer_role),
        0x1111_2222,
    );
    round_trip(
        theirs.local_key(peer_role),
        theirs.local_salt(peer_role),
        ours.remote_key(),
        ours.remote_salt(),
        0x3333_4444,
    );
    assert_ne!(ours.local_key(), ours.remote_key());
}

/// `Connecting` came before `Connected`, and `Connected` came once.
fn assert_connecting_then_connected(events: &[CallManagerEvent]) {
    let states = reported_states(events);
    let connecting = states.iter().position(|s| *s == CallState::Connecting);
    let connected = states.iter().position(|s| *s == CallState::Connected);
    assert!(connecting.is_some() && connecting < connected, "{states:?}");
    assert_eq!(
        states
            .iter()
            .filter(|s| **s == CallState::Connected)
            .count(),
        1,
        "{states:?}"
    );
}

/// The call is gone from every table the public API shows.
fn assert_call_gone(manager: &CallManager, call_id: &str) {
    assert!(manager.get_audio_session(call_id).is_none());
    assert!(manager.get_media_session(call_id).is_none());
    assert_eq!(manager.all_call_ids(), &[] as &[String]);
}

/// An outbound call answered by a peer in DTLS role `opposite(our_role)`.
struct Outbound {
    manager: CallManager,
    rx: Events,
    call_id: String,
    invite: proto_sip::message::SipRequest,
    /// Our media address, as our offer states it.
    media: SocketAddr,
    /// Our certificate fingerprint, as our offer states it.
    fingerprint: CertificateFingerprint,
    seen: Seen,
}

async fn place() -> Outbound {
    let (mut manager, mut rx) = manager();
    let (call_id, invite) = place_call(&mut manager).await;
    let (media, fingerprint) = local_media(&body_of(&invite));
    let seen = Seen {
        events: drain(&mut rx),
        methods: Vec::new(),
    };
    Outbound {
        manager,
        rx,
        call_id,
        invite,
        media,
        fingerprint,
        seen,
    }
}

impl Outbound {
    /// Delivers the 200 with `answer`.
    async fn answer(&mut self, answer: &str) {
        let methods = answer_call(&mut self.manager, &self.invite, answer).await;
        self.seen.methods.extend(methods);
        self.seen.events.extend(drain(&mut self.rx));
    }

    async fn pump(&mut self, limit: Duration, done: impl Fn(&Seen) -> bool) {
        pump(&mut self.manager, &mut self.rx, &mut self.seen, limit, done).await;
    }

    /// Pumps the manager and drives `peer` until the call is connected or
    /// ended and the peer has settled.
    async fn run_with(&mut self, peer: &mut Peer, limit: Duration) {
        let media = self.media;
        tokio::join!(
            pump(
                &mut self.manager,
                &mut self.rx,
                &mut self.seen,
                limit,
                |seen| connected(seen) || ended(seen)
            ),
            peer.drive(media, limit, Peer::settled, |_| true),
        );
    }
}

/// An outbound call connected to a real in-process peer; we are `our_role`.
async fn connected_outbound(our_role: DtlsRole) -> (Outbound, Peer) {
    // RFC 5763 §5: the answerer's `passive` makes us the DTLS client,
    // its `active` the server.
    let setup = if our_role == DtlsRole::Client {
        "passive"
    } else {
        "active"
    };
    let mut call = place().await;
    let mut peer = Peer::new().await;
    peer.start(opposite(our_role), call.fingerprint.clone());
    call.answer(&remote_sdp(peer.addr, &peer.fingerprint(), setup))
        .await;
    // The 200 alone does not connect the call.
    assert!(!reported_connected(&call.seen.events), "{:?}", call.seen);
    assert!(reported_states(&call.seen.events).contains(&CallState::Connecting));
    call.run_with(&mut peer, Duration::from_secs(5)).await;
    assert!(connected(&call.seen), "as {our_role:?}: {:?}", call.seen);
    (call, peer)
}

#[tokio::test]
async fn outbound_call_connects_only_after_the_handshake_in_both_roles() {
    for our_role in [DtlsRole::Client, DtlsRole::Server] {
        let (mut call, mut peer) = connected_outbound(our_role).await;
        assert_connecting_then_connected(&call.seen.events);
        assert_eq!(error_messages(&call.seen.events), Vec::<String>::new());
        assert!(!call.seen.methods.iter().any(|m| m == "BYE"));
        assert_eq!(peer.failed, None);

        let session = call.manager.get_media_session(&call.call_id).unwrap();
        assert!(session.is_ready());
        assert_eq!(session.dtls_role(), our_role);
        assert_eq!(session.dtls_remote(), Some(peer.addr));
        assert_srtp_both_ways(session, &peer, our_role);

        // Local hang-up: BYE, and one close_notify to the DTLS peer.
        call.manager.hangup_call(&call.call_id).await.unwrap();
        let media = call.media;
        peer.drive(media, Duration::from_secs(2), |p| p.saw_close, |_| true)
            .await;
        assert!(peer.saw_close, "as {our_role:?}");
        call.seen.events.extend(drain(&mut call.rx));
        assert_eq!(
            end_reason(&call.seen.events),
            Some(CallEndReason::LocalHangup)
        );
        assert_eq!(error_messages(&call.seen.events), Vec::<String>::new());
        assert_call_gone(&call.manager, &call.call_id);
    }
}

/// Inbound: nothing is reported `Connected` at the 200 or before the ACK,
/// and no DTLS leaves us before the ACK; then the handshake completes in
/// the role the offer's `a=setup` gave us. When the peer is the DTLS
/// client its `ClientHello` arrives before our ACK and must not be lost
/// (RFC 5763 §5): the peer never has to retransmit.
#[tokio::test]
async fn inbound_call_connects_only_after_ack_and_handshake_in_both_roles() {
    for (n, (offer_setup, our_role, answer_setup)) in [
        ("actpass", DtlsRole::Client, "active"),
        ("active", DtlsRole::Server, "passive"),
    ]
    .into_iter()
    .enumerate()
    {
        let (mut manager, mut rx) = manager();
        let mut peer = Peer::new().await;
        let dialog = format!("secure-in-{n}");
        let request = invite(
            &dialog,
            &remote_sdp(peer.addr, &peer.fingerprint(), offer_setup),
        );
        manager
            .handle_sip_request_from(&request, sip_peer(), SipTransportKind::Tls)
            .await
            .unwrap();
        let (call_id, local_tag) = {
            let incoming = manager.incoming_calls()[0];
            (incoming.call_id.clone(), incoming.local_tag.clone())
        };
        manager.accept_incoming_call(&call_id).await.unwrap();
        let mut seen = Seen {
            events: drain(&mut rx),
            methods: Vec::new(),
        };
        let answer = ok_body(&seen.events).expect("200 with SDP");
        assert!(
            answer.contains(&format!("a=setup:{answer_setup}\r\n")),
            "{answer}"
        );
        let (media, fingerprint) = local_media(&answer);
        assert!(!connected(&seen), "{seen:?}");
        assert!(reported_states(&seen.events).contains(&CallState::Connecting));

        // The peer is up before our ACK arrives.
        peer.start(opposite(our_role), fingerprint);
        tokio::join!(
            pump(
                &mut manager,
                &mut rx,
                &mut seen,
                Duration::from_millis(300),
                connected
            ),
            peer.drive(media, Duration::from_millis(300), Peer::settled, |_| true),
        );
        assert!(!connected(&seen), "connected before the ACK: {seen:?}");
        assert!(peer.received.is_empty(), "DTLS sent before the ACK");
        assert_eq!(peer.sent.len(), usize::from(our_role == DtlsRole::Server));

        let ack = in_dialog("ACK", &dialog, &local_tag, 1);
        manager
            .handle_sip_request_from(&ack, sip_peer(), SipTransportKind::Tls)
            .await
            .unwrap();
        tokio::join!(
            pump(
                &mut manager,
                &mut rx,
                &mut seen,
                Duration::from_secs(5),
                |seen| connected(seen) || ended(seen)
            ),
            peer.drive(media, Duration::from_secs(5), Peer::settled, |_| true),
        );
        assert!(connected(&seen), "as {our_role:?}: {seen:?}");
        assert_connecting_then_connected(&seen.events);
        assert_eq!(error_messages(&seen.events), Vec::<String>::new());
        assert_eq!(peer.failed, None);
        if our_role == DtlsRole::Server {
            assert_eq!(peer.association().stats().retransmits, 0);
        }
        let session = manager.get_media_session(&call_id).unwrap();
        assert!(session.is_ready());
        assert_eq!(session.dtls_role(), our_role);
        assert_srtp_both_ways(session, &peer, our_role);
    }
}

/// RFC 8122 §5: the peer's certificate is not the one in the SDP.
#[tokio::test]
async fn fingerprint_mismatch_ends_the_call_and_is_never_connected() {
    for our_role in [DtlsRole::Client, DtlsRole::Server] {
        let setup = if our_role == DtlsRole::Client {
            "passive"
        } else {
            "active"
        };
        let mut call = place().await;
        let mut peer = Peer::new().await;
        peer.start(opposite(our_role), call.fingerprint.clone());
        let someone_else = dtls::identity().fingerprint().clone();
        call.answer(&remote_sdp(peer.addr, &someone_else, setup))
            .await;
        call.run_with(&mut peer, Duration::from_secs(6)).await;
        call.pump(Duration::from_secs(2), ended).await;

        assert_eq!(
            error_messages(&call.seen.events),
            ["media-security: dtls-fingerprint-mismatch"],
            "as {our_role:?}: {:?}",
            call.seen
        );
        assert_eq!(end_reason(&call.seen.events), Some(CallEndReason::Failed));
        assert!(!connected(&call.seen));
        assert!(call.seen.methods.iter().any(|m| m == "BYE"));
        assert_call_gone(&call.manager, &call.call_id);
    }
}

/// The peer answers our `ClientHello` with a fatal alert.
#[tokio::test]
async fn fatal_alert_during_the_handshake_ends_the_call() {
    let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut call = place().await;
    let fingerprint = dtls::identity().fingerprint().clone();
    call.answer(&remote_sdp(
        responder.local_addr().unwrap(),
        &fingerprint,
        "passive",
    ))
    .await;
    let refuse = async {
        let mut buf = [0u8; 2048];
        let (_, from) = responder.recv_from(&mut buf).await.unwrap();
        // handshake_failure (40), fatal (2).
        responder
            .send_to(&dtls::plaintext_alert(0, 2, 40), from)
            .await
            .unwrap();
    };
    tokio::join!(
        pump(
            &mut call.manager,
            &mut call.rx,
            &mut call.seen,
            Duration::from_secs(6),
            ended
        ),
        refuse
    );
    assert_eq!(
        error_messages(&call.seen.events),
        ["media-security: dtls-alert"],
        "{:?}",
        call.seen
    );
    assert_eq!(end_reason(&call.seen.events), Some(CallEndReason::Failed));
    assert!(!connected(&call.seen));
    assert!(call.seen.methods.iter().any(|m| m == "BYE"));
    assert_call_gone(&call.manager, &call.call_id);
}

/// Hang-up while the handshake runs: the driver is cancelled (it sends its
/// one `close_notify` and stops), the call ends as a local hang-up and no
/// media-security error follows.
#[tokio::test]
async fn hangup_during_the_handshake_cancels_it_without_an_error() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut call = place().await;
    let fingerprint = dtls::identity().fingerprint().clone();
    call.answer(&remote_sdp(
        silent.local_addr().unwrap(),
        &fingerprint,
        "passive",
    ))
    .await;
    call.pump(Duration::from_millis(100), ended).await;
    assert!(!ended(&call.seen) && !connected(&call.seen));

    call.manager.hangup_call(&call.call_id).await.unwrap();
    // Well past one retransmission interval: nothing more may happen.
    call.pump(Duration::from_millis(1500), |_| false).await;
    assert_eq!(
        end_reason(&call.seen.events),
        Some(CallEndReason::LocalHangup)
    );
    assert_eq!(error_messages(&call.seen.events), Vec::<String>::new());
    assert!(!connected(&call.seen));
    assert_call_gone(&call.manager, &call.call_id);

    // On the wire: our ClientHello, then one alert record, then silence
    // (no retransmission after the cancel).
    let mut kinds = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(100), silent.recv_from(&mut buf)).await
    {
        kinds.push(buf[0]);
    }
    assert_eq!(kinds, vec![22, 21]);
}

/// The SIP pump is not held by a pending handshake: with a peer that never
/// answers DTLS (10 s budget), the remote party's BYE is answered and the
/// call ended in one pass.
#[tokio::test]
async fn pump_stays_live_while_a_handshake_is_pending() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut call = place().await;
    let fingerprint = dtls::identity().fingerprint().clone();
    let started = Instant::now();
    call.answer(&remote_sdp(
        silent.local_addr().unwrap(),
        &fingerprint,
        "active",
    ))
    .await;
    call.pump(Duration::from_millis(100), ended).await;
    assert!(!ended(&call.seen) && !connected(&call.seen));

    let bye = bye_for_outbound(&call.invite);
    call.manager
        .handle_sip_request_from(&bye, sip_peer(), SipTransportKind::Tls)
        .await
        .unwrap();
    call.manager.process_timers().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    call.seen.events.extend(drain(&mut call.rx));
    let answered = call.seen.events.iter().any(|e| {
        matches!(e, CallManagerEvent::SendResponse { response, .. }
            if response.status.code() == 200)
    });
    assert!(answered, "{:?}", call.seen);
    assert!(reported_states(&call.seen.events).contains(&CallState::Terminated));
    assert_call_gone(&call.manager, &call.call_id);

    // The cancelled handshake produces nothing later.
    call.pump(Duration::from_millis(300), |_| false).await;
    assert_eq!(error_messages(&call.seen.events), Vec::<String>::new());
    assert!(!connected(&call.seen));
}

/// Pushes the peer's `close_notify` to the call's DTLS driver the way the
/// audio I/O thread would.
fn forward_close_notify(call: &mut Outbound, peer: &mut Peer) {
    let mut forward = call
        .manager
        .get_media_session_mut(&call.call_id)
        .unwrap()
        .dtls_forward_tx()
        .expect("forward ring of a connected call");
    peer.association().close();
    let close_notify = peer.association().poll_transmit().expect("close_notify");
    assert!(forward.try_forward(&close_notify));
}

/// Mid-call `close_notify` with no BYE: audio stops at once, the call
/// waits one second for the BYE and then ends as a media-security failure.
#[tokio::test]
async fn close_notify_without_bye_ends_the_call_after_the_grace_time() {
    let (mut call, mut peer) = connected_outbound(DtlsRole::Client).await;
    forward_close_notify(&mut call, &mut peer);
    let closed_at = Instant::now();

    call.pump(Duration::from_millis(500), ended).await;
    assert!(!ended(&call.seen), "ended inside the grace time");
    assert!(call.manager.get_audio_session(&call.call_id).is_none());
    // The keys of the closed association are gone.
    let session = call.manager.get_media_session(&call.call_id).unwrap();
    assert!(!session.is_ready());
    assert!(session.negotiated_srtp_keys().is_none());

    call.pump(Duration::from_secs(3), ended).await;
    assert!(closed_at.elapsed() >= Duration::from_secs(1));
    assert_eq!(
        error_messages(&call.seen.events),
        ["media-security: dtls-closed-by-peer"],
        "{:?}",
        call.seen
    );
    assert_eq!(end_reason(&call.seen.events), Some(CallEndReason::Failed));
    assert!(call.seen.methods.iter().any(|m| m == "BYE"));
    assert_call_gone(&call.manager, &call.call_id);
}

/// Mid-call `close_notify` followed by the peer's BYE within the grace
/// time is a normal remote hang-up: no media-security error, ever.
#[tokio::test]
async fn close_notify_followed_by_bye_is_a_normal_hangup() {
    let (mut call, mut peer) = connected_outbound(DtlsRole::Server).await;
    forward_close_notify(&mut call, &mut peer);
    call.pump(Duration::from_millis(200), ended).await;
    assert!(!ended(&call.seen));

    let bye = bye_for_outbound(&call.invite);
    call.manager
        .handle_sip_request_from(&bye, sip_peer(), SipTransportKind::Tls)
        .await
        .unwrap();
    // Past the end of the grace time.
    call.pump(Duration::from_millis(1500), |_| false).await;
    assert!(reported_states(&call.seen.events).contains(&CallState::Terminated));
    assert_eq!(error_messages(&call.seen.events), Vec::<String>::new());
    assert_eq!(end_reason(&call.seen.events), None);
    assert!(!call.seen.methods.iter().any(|m| m == "BYE"));
    assert_call_gone(&call.manager, &call.call_id);
}

/// A fatal alert protected with the session keys ends the call at once,
/// with no grace time. The peer is a scripted server that knows the keys.
#[tokio::test]
async fn authenticated_fatal_alert_mid_call_ends_the_call_at_once() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut puppet = Puppet::new(DtlsRole::Server);
    let mut call = place().await;
    call.answer(&remote_sdp(
        socket.local_addr().unwrap(),
        &puppet.fingerprint(),
        "passive",
    ))
    .await;

    // The driver task runs the client side while the script answers it.
    let mut buf = [0u8; 4096];
    let (len, from) = receive(&socket, &mut buf).await;
    assert_eq!(from, call.media);
    puppet.absorb(&buf[..len]);
    socket
        .send_to(&puppet.server_flight4(), from)
        .await
        .unwrap();
    while puppet.peer_finished_ok.is_none() {
        let (len, _) = receive(&socket, &mut buf).await;
        puppet.absorb(&buf[..len]);
    }
    assert_eq!(puppet.peer_finished_ok, Some(true));
    socket
        .send_to(&puppet.server_flight6(), from)
        .await
        .unwrap();
    call.pump(Duration::from_secs(3), |seen| {
        connected(seen) || ended(seen)
    })
    .await;
    assert!(connected(&call.seen), "{:?}", call.seen);

    let mut forward = call
        .manager
        .get_media_session_mut(&call.call_id)
        .unwrap()
        .dtls_forward_tx()
        .expect("forward ring");
    // A forged plaintext alert does nothing.
    assert!(forward.try_forward(&dtls::plaintext_alert(9, 2, 40)));
    call.pump(Duration::from_millis(200), ended).await;
    assert!(!ended(&call.seen), "{:?}", call.seen);

    // internal_error (80), fatal (2), in epoch 1.
    let alert = puppet.seal(1, ContentType::Alert, &[2, 80]);
    assert!(forward.try_forward(&alert));
    let alerted = Instant::now();
    call.pump(Duration::from_secs(3), ended).await;
    assert!(alerted.elapsed() < Duration::from_millis(900), "no grace");
    assert_eq!(
        error_messages(&call.seen.events),
        ["media-security: dtls-alert"],
        "{:?}",
        call.seen
    );
    assert_eq!(end_reason(&call.seen.events), Some(CallEndReason::Failed));
    assert!(call.seen.methods.iter().any(|m| m == "BYE"));
    assert_call_gone(&call.manager, &call.call_id);
}

async fn receive(socket: &UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(3), socket.recv_from(buf))
        .await
        .expect("datagram from the client")
        .unwrap()
}
