//! Two `DtlsAssociation`s over real UDP sockets on 127.0.0.1, in real time
//! (plan §6.1 "Loopback over real UDP sockets"). Each test runs our client
//! role against our server role, so both roles cross a real datagram path:
//! kernel socket buffers, `Instant::now()`, and the timers the association
//! hands to its driver.
//!
//! The driver is `common::drive`, written from the notes for QA in
//! impl-notes.md; stage 2's `DtlsDriver` has to do the same things.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use proto_dtls::{AssociationConfig, DtlsAssociation, DtlsCredentials, DtlsRole, FailureCause};
use proto_rtp::{RtpHeader, RtpPacket};
use proto_srtp::{SrtpDirection, SrtpProtect, SrtpUnprotect};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

struct Endpoint {
    socket: UdpSocket,
    addr: SocketAddr,
    id: DtlsCredentials,
}

async fn endpoint() -> Endpoint {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    Endpoint {
        socket,
        addr,
        id: identity(),
    }
}

fn config(role: DtlsRole, own: &Endpoint, peer: &Endpoint) -> AssociationConfig {
    AssociationConfig::new(role, own.id.clone(), vec![peer.id.fingerprint().clone()])
}

fn after(duration: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + duration
}

/// SRTP and SRTCP in both directions on the handshake's own sockets,
/// demultiplexed by the driver (RFC 7983 / RFC 5761).
async fn media_round_trip(
    c: &Endpoint,
    s: &Endpoint,
    client: &mut DtlsAssociation,
    server: &mut DtlsAssociation,
    ck: &proto_dtls::SrtpKeyingMaterial,
    sk: &proto_dtls::SrtpKeyingMaterial,
) {
    for (ssrc, from_client) in [(0x1111_2222u32, true), (0x3333_4444, false)] {
        let (tx_keys, tx_role, rx_keys, rx_role) = if from_client {
            (ck, DtlsRole::Client, sk, DtlsRole::Server)
        } else {
            (sk, DtlsRole::Server, ck, DtlsRole::Client)
        };
        let tx = srtp_context(
            tx_keys.local_key(tx_role),
            tx_keys.local_salt(tx_role),
            SrtpDirection::Outbound,
            ssrc,
        );
        let rx = srtp_context(
            rx_keys.remote_key(rx_role),
            rx_keys.remote_salt(rx_role),
            SrtpDirection::Inbound,
            ssrc,
        );
        let (from, to, to_addr) = if from_client {
            (&c.socket, &s.socket, s.addr)
        } else {
            (&s.socket, &c.socket, c.addr)
        };
        let from_addr = from.local_addr().unwrap();
        let payload = vec![0x5Au8; 160];
        for seq in 0..5u16 {
            let packet = RtpPacket::new(
                RtpHeader::new(0, seq, u32::from(seq) * 160, ssrc),
                payload.clone(),
            );
            let protected = SrtpProtect::new(&tx).protect_rtp(&packet).unwrap();
            from.send_to(&protected, to_addr).await.unwrap();
        }
        let report = rtcp_receiver_report(ssrc);
        let protected = SrtpProtect::new(&tx).protect_rtcp(&report).unwrap();
        from.send_to(&protected, to_addr).await.unwrap();

        let receiver = if from_client {
            &mut *server
        } else {
            &mut *client
        };
        let mut state = Driven::default();
        drive(
            receiver,
            to,
            from_addr,
            &mut state,
            after(Duration::from_secs(2)),
            |d| d.media.len() >= 6,
        )
        .await;
        assert_eq!(state.media.len(), 6);
        let (control, audio): (Vec<_>, Vec<_>) = state.media.iter().partition(|p| is_rtcp(p));
        assert_eq!((audio.len(), control.len()), (5, 1));
        for packet in audio {
            let opened = SrtpUnprotect::new(&rx).unprotect_rtp(packet).unwrap();
            assert_eq!(opened.payload.as_ref(), payload.as_slice());
        }
        let opened = SrtpUnprotect::new(&rx)
            .unprotect_rtcp_sync(control[0])
            .unwrap();
        assert_eq!(opened.as_ref(), report.as_slice());
    }
}

/// Handshake, then SRTP and SRTCP in both directions on the same two
/// sockets while the associations are still being serviced, then
/// `close_notify`.
#[tokio::test]
async fn handshake_srtp_and_close_over_udp() {
    let (c, s) = (endpoint().await, endpoint().await);
    let started = Instant::now();
    let mut client =
        DtlsAssociation::new(config(DtlsRole::Client, &c, &s), Instant::now()).unwrap();
    let mut server =
        DtlsAssociation::new(config(DtlsRole::Server, &s, &c), Instant::now()).unwrap();
    let (mut cs, mut ss) = (Driven::default(), Driven::default());

    let deadline = after(Duration::from_secs(8));
    tokio::join!(
        drive(
            &mut client,
            &c.socket,
            s.addr,
            &mut cs,
            deadline,
            Driven::settled
        ),
        drive(
            &mut server,
            &s.socket,
            c.addr,
            &mut ss,
            deadline,
            Driven::settled
        ),
    );
    assert_eq!(cs.failed, None);
    assert_eq!(ss.failed, None);
    let ck = cs.keys.take().expect("client keys");
    let sk = ss.keys.take().expect("server keys");
    assert_eq!(exported(&ck), exported(&sk));
    assert_eq!(exported(&ck).len(), 88);
    assert!(client.is_connected() && server.is_connected());
    // No loss on loopback: three datagrams each way, no retransmission, and
    // well inside the first retransmission interval.
    assert_eq!((cs.sent, cs.received), (3, 3));
    assert_eq!((ss.sent, ss.received), (3, 3));
    assert_eq!(client.stats().retransmits + server.stats().retransmits, 0);
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );

    media_round_trip(&c, &s, &mut client, &mut server, &ck, &sk).await;

    // close_notify from the client reaches the server over the socket.
    client.close();
    let mut closing = Driven::default();
    drive(
        &mut client,
        &c.socket,
        s.addr,
        &mut closing,
        after(Duration::from_millis(50)),
        |_| true,
    )
    .await;
    assert_eq!(closing.sent, 1);
    let mut state = Driven::default();
    drive(
        &mut server,
        &s.socket,
        c.addr,
        &mut state,
        after(Duration::from_secs(2)),
        |d| d.peer_closed,
    )
    .await;
    assert!(state.peer_closed);
    assert!(server.is_terminated());
}

/// The first two `ClientHello`s are lost for real (read off the server's
/// socket and thrown away before the server association exists). The client
/// retransmits on its own timer after 1 s and 3 s of wall-clock time, and
/// the handshake completes.
#[tokio::test]
async fn real_time_retransmission_recovers_from_loss_over_udp() {
    let (c, s) = (endpoint().await, endpoint().await);
    let started = Instant::now();
    let mut client =
        DtlsAssociation::new(config(DtlsRole::Client, &c, &s), Instant::now()).unwrap();
    let (mut cs, mut ss) = (Driven::default(), Driven::default());
    let deadline = after(Duration::from_secs(9));

    let server_side = async {
        let mut buf = [0u8; 2048];
        let mut lost_at = Vec::new();
        for _ in 0..2 {
            let (len, from) = s.socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(from, c.addr);
            assert_eq!(buf[0], 22, "a handshake record");
            assert!(len > 13);
            lost_at.push(started.elapsed());
        }
        let mut server =
            DtlsAssociation::new(config(DtlsRole::Server, &s, &c), Instant::now()).unwrap();
        drive(
            &mut server,
            &s.socket,
            c.addr,
            &mut ss,
            deadline,
            Driven::settled,
        )
        .await;
        (server, lost_at)
    };
    let ((server, lost_at), ()) = tokio::join!(
        server_side,
        drive(
            &mut client,
            &c.socket,
            s.addr,
            &mut cs,
            deadline,
            Driven::settled
        ),
    );

    assert_eq!(cs.failed, None);
    assert_eq!(ss.failed, None);
    assert_eq!(
        exported(cs.keys.as_ref().expect("client keys")),
        exported(ss.keys.as_ref().expect("server keys"))
    );
    assert!(server.is_connected());
    // RFC 6347 §4.2.4.1: retransmissions at 1 s and 3 s (1 s, then doubled).
    assert_eq!(client.stats().retransmits, 2);
    assert!(lost_at[0] < Duration::from_millis(900), "{lost_at:?}");
    assert!(
        lost_at[1] >= Duration::from_millis(950) && lost_at[1] < Duration::from_millis(2000),
        "{lost_at:?}"
    );
    let total = started.elapsed();
    assert!(
        total >= Duration::from_millis(2950) && total < Duration::from_millis(5000),
        "{total:?}"
    );
}

/// A peer whose socket is open but silent: the client retransmits in real
/// time and gives up at the configured budget. No keys.
#[tokio::test]
async fn silent_peer_times_out_in_real_time_over_udp() {
    for role in [DtlsRole::Client, DtlsRole::Server] {
        let (us, silent) = (endpoint().await, endpoint().await);
        let mut cfg = config(role, &us, &silent);
        cfg.initial_rto = Duration::from_millis(200);
        cfg.handshake_budget = Duration::from_millis(2000);
        let started = Instant::now();
        let mut assoc = DtlsAssociation::new(cfg, Instant::now()).unwrap();
        let mut state = Driven::default();
        drive(
            &mut assoc,
            &us.socket,
            silent.addr,
            &mut state,
            after(Duration::from_secs(6)),
            Driven::settled,
        )
        .await;
        let took = started.elapsed();
        assert_eq!(state.failed, Some(FailureCause::Timeout), "{role:?}");
        assert!(state.keys.is_none());
        assert!(assoc.is_terminated());
        assert!(
            took >= Duration::from_millis(2000) && took < Duration::from_millis(3000),
            "{role:?}: {took:?}"
        );
        // Client: hello at 0, then 200, 600 and 1400 ms; the next would be
        // at 3000 ms, a full second past the budget, so a late timer cannot
        // change the count. Server: nothing to send to a peer that never
        // spoke.
        let expected = if role == DtlsRole::Client { 4 } else { 0 };
        assert_eq!(state.sent, expected, "{role:?}");
        let mut waiting = 0;
        let mut buf = [0u8; 2048];
        while silent.socket.try_recv_from(&mut buf).is_ok() {
            waiting += 1;
        }
        assert_eq!(
            waiting, expected,
            "{role:?}: datagrams that reached the peer"
        );
    }
}

/// Fingerprint mismatch over UDP, each role in turn being the one that
/// refuses: the refusing side reports `FingerprintMismatch`, the other gets
/// the `bad_certificate` alert over the socket, neither has keys.
#[tokio::test]
async fn fingerprint_mismatch_over_udp_in_both_roles() {
    for refusing in [DtlsRole::Client, DtlsRole::Server] {
        let (c, s) = (endpoint().await, endpoint().await);
        let stranger = identity().fingerprint().clone();
        let mut client_cfg = config(DtlsRole::Client, &c, &s);
        let mut server_cfg = config(DtlsRole::Server, &s, &c);
        match refusing {
            DtlsRole::Client => client_cfg.peer_fingerprints = vec![stranger],
            DtlsRole::Server => server_cfg.peer_fingerprints = vec![stranger],
        }
        let mut client = DtlsAssociation::new(client_cfg, Instant::now()).unwrap();
        let mut server = DtlsAssociation::new(server_cfg, Instant::now()).unwrap();
        let (mut cs, mut ss) = (Driven::default(), Driven::default());
        let deadline = after(Duration::from_secs(5));
        tokio::join!(
            drive(
                &mut client,
                &c.socket,
                s.addr,
                &mut cs,
                deadline,
                Driven::settled
            ),
            drive(
                &mut server,
                &s.socket,
                c.addr,
                &mut ss,
                deadline,
                Driven::settled
            ),
        );
        let (refused, alerted) = match refusing {
            DtlsRole::Client => (&cs, &ss),
            DtlsRole::Server => (&ss, &cs),
        };
        assert_eq!(refused.failed, Some(FailureCause::FingerprintMismatch));
        assert_eq!(alerted.failed, Some(FailureCause::PeerAlert(42)));
        assert!(cs.keys.is_none() && ss.keys.is_none());
        assert!(client.is_terminated() && server.is_terminated());
    }
}

/// Datagrams from an address other than the peer never reach the
/// association (the driver's job, impl-notes), so a third party on the
/// loopback cannot inject a fatal alert during the handshake.
#[tokio::test]
async fn driver_ignores_datagrams_from_other_addresses() {
    let (c, s) = (endpoint().await, endpoint().await);
    let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut client =
        DtlsAssociation::new(config(DtlsRole::Client, &c, &s), Instant::now()).unwrap();
    let mut server =
        DtlsAssociation::new(config(DtlsRole::Server, &s, &c), Instant::now()).unwrap();
    for target in [c.addr, s.addr] {
        intruder
            .send_to(&plaintext_alert(0, 2, 40), target)
            .await
            .unwrap();
    }
    let (mut cs, mut ss) = (Driven::default(), Driven::default());
    let deadline = after(Duration::from_secs(5));
    tokio::join!(
        drive(
            &mut client,
            &c.socket,
            s.addr,
            &mut cs,
            deadline,
            Driven::settled
        ),
        drive(
            &mut server,
            &s.socket,
            c.addr,
            &mut ss,
            deadline,
            Driven::settled
        ),
    );
    assert_eq!((cs.strangers, ss.strangers), (1, 1));
    assert_eq!(
        exported(cs.keys.as_ref().expect("client keys")),
        exported(ss.keys.as_ref().expect("server keys"))
    );
}
