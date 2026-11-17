//! Interop: `DtlsAssociation` against pion/dtls, in both DTLS roles.
//!
//! The peer is `sidecar/srtp-test-peer`. It runs the handshake through the
//! same `dtlssession.Run` (same pion version, same `dtls.Config`) as the
//! SBC's DTLS sidecar, so it stands in for the SBC's DTLS endpoint; it then
//! sends SRTP and SRTCP with pion/srtp and counts what it can decrypt.
//!
//! What each success test proves:
//!
//! - the handshake completes against pion with our profile only (0xC02C,
//!   secp384r1, ECDSA P-384/SHA-384, `SRTP_AEAD_AES_256_GCM`, extended
//!   master secret), mutual authentication by SDP fingerprint both ways;
//! - **pion -> us**: every SRTP packet pion sends is authenticated and
//!   decrypted by `proto-srtp` under the keys *we* exported, and its payload
//!   is the one pion sent; the same for pion's SRTCP;
//! - **us -> pion**: pion authenticates and decrypts the SRTP and SRTCP we
//!   protect under our exported keys (its `RESULT received=` /
//!   `rtcp_received=` counters, which only count successful decryption);
//! - a receive context keyed for the wrong direction rejects pion's packets,
//!   so the checks above are not vacuous.
//!
//! Not proven here: anything about a non-pion peer, the SBC relay path
//! itself (`sbc-media-core` pumping records to the sidecar), and the client
//! crates (stage 2).
//!
//! These tests are `#[ignore]`d because they need the Go binary. To run:
//!
//! ```text
//! (cd sidecar/srtp-test-peer && go build -o /tmp/srtp-test-peer .)
//! PEER_BIN=/tmp/srtp-test-peer cargo test -p proto-dtls --test interop_pion -- --ignored --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use proto_dtls::{AssociationConfig, DtlsAssociation, DtlsRole, FailureCause, SrtpKeyingMaterial};
use proto_rtp::{RtpHeader, RtpPacket};
use proto_srtp::{SrtpDirection, SrtpProtect, SrtpUnprotect};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// SSRC the peer sends with (`-ssrc`), and the payload of its RTP packets
/// (`sidecar/srtp-test-peer/peer.go`).
const PEER_SSRC: u32 = 0x1234;
const PEER_PAYLOAD: &[u8] = b"SBC-DTLS-SRTP-terminate-audio-frame";
/// RTP packets the peer sends (`-count`); it adds one SRTCP report per ten.
const PEER_RTP: usize = 50;
const PEER_RTCP: usize = 5;
/// What we send to the peer.
const OUR_SSRC: u32 = 0x00C0_FFEE;
const OUR_RTP: u16 = 20;
const OUR_RTCP: usize = 2;

const fn opposite(role: DtlsRole) -> DtlsRole {
    match role {
        DtlsRole::Client => DtlsRole::Server,
        DtlsRole::Server => DtlsRole::Client,
    }
}

#[path = "common/pion_peer.rs"]
mod pion_peer;
use pion_peer::Peer;

struct Session {
    socket: UdpSocket,
    assoc: DtlsAssociation,
    state: Driven,
    peer: Peer,
}

/// Binds our socket, starts the peer in the opposite role and runs the
/// handshake until our side settles. The two flags give one side a
/// fingerprint that is not the other's (for the mismatch cases).
async fn handshake(
    ours: DtlsRole,
    wrong_fingerprint_for_us: bool,
    wrong_fingerprint_for_peer: bool,
) -> Session {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let id = identity();
    let stranger = identity().fingerprint().clone();
    let told_to_peer = if wrong_fingerprint_for_peer {
        &stranger
    } else {
        id.fingerprint()
    };
    let peer = Peer::spawn(
        opposite(ours),
        socket.local_addr().unwrap(),
        told_to_peer,
        PEER_RTP as u64,
        PEER_SSRC,
    )
    .await;
    let expected = if wrong_fingerprint_for_us {
        stranger
    } else {
        peer.fingerprint.clone()
    };
    let config = AssociationConfig::new(ours, id.clone(), vec![expected]);
    let mut assoc = DtlsAssociation::new(config, Instant::now()).unwrap();
    let mut state = Driven::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    drive(
        &mut assoc,
        &socket,
        peer.addr,
        &mut state,
        deadline,
        Driven::settled,
    )
    .await;
    Session {
        socket,
        assoc,
        state,
        peer,
    }
}

/// us -> pion: SRTP and SRTCP under our local (write) keys.
async fn send_media_to_peer(
    socket: &UdpSocket,
    to: SocketAddr,
    keys: &SrtpKeyingMaterial,
    ours: DtlsRole,
) {
    let tx = srtp_context(
        keys.local_key(ours),
        keys.local_salt(ours),
        SrtpDirection::Outbound,
        OUR_SSRC,
    );
    let payload = vec![0xA5u8; 160];
    for seq in 0..OUR_RTP {
        let packet = RtpPacket::new(
            RtpHeader::new(0, seq, u32::from(seq) * 160, OUR_SSRC),
            payload.clone(),
        );
        let protected = SrtpProtect::new(&tx).protect_rtp(&packet).unwrap();
        socket.send_to(&protected, to).await.unwrap();
    }
    for _ in 0..OUR_RTCP {
        let protected = SrtpProtect::new(&tx)
            .protect_rtcp(&rtcp_receiver_report(OUR_SSRC))
            .unwrap();
        socket.send_to(&protected, to).await.unwrap();
    }
}

/// Handshake against pion, then SRTP and SRTCP in both directions.
async fn interoperates(ours: DtlsRole) {
    let started = Instant::now();
    let Session {
        socket,
        mut assoc,
        mut state,
        peer,
    } = handshake(ours, false, false).await;
    assert_eq!(state.failed, None, "handshake with pion failed");
    let keys: SrtpKeyingMaterial = state.keys.take().expect("no keys exported");
    assert!(assoc.is_connected());
    assert_eq!(state.connected_events, 1);
    assert_eq!(exported(&keys).len(), 88);
    assert_eq!(
        assoc.presented_fingerprint(),
        Some(&peer.fingerprint),
        "pion presented the certificate it announced"
    );
    let handshake_time = started.elapsed();
    let stats = assoc.stats();

    send_media_to_peer(&socket, peer.addr, &keys, ours).await;

    // pion -> us: keep servicing the association (server role: pion may
    // retransmit its last flight) while its media arrives on the same socket.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    drive(&mut assoc, &socket, peer.addr, &mut state, deadline, |d| {
        d.media.len() >= PEER_RTP + PEER_RTCP
    })
    .await;
    assert_eq!(state.failed, None);
    assert!(!state.peer_closed);

    let rx = srtp_context(
        keys.remote_key(ours),
        keys.remote_salt(ours),
        SrtpDirection::Inbound,
        PEER_SSRC,
    );
    // Control: the same packets under our own write keys must not open.
    let wrong = srtp_context(
        keys.local_key(ours),
        keys.local_salt(ours),
        SrtpDirection::Inbound,
        PEER_SSRC,
    );
    let (mut media_ok, mut control_ok) = (0usize, 0usize);
    for packet in &state.media {
        if is_rtcp(packet) {
            assert!(
                SrtpUnprotect::new(&wrong)
                    .unprotect_rtcp_sync(packet)
                    .is_err()
            );
            let opened = SrtpUnprotect::new(&rx)
                .unprotect_rtcp_sync(packet)
                .expect("pion's SRTCP did not authenticate under our exported keys");
            // A receiver report from the peer's SSRC.
            assert_eq!(opened[1], 201);
            assert_eq!(&opened[4..8], &PEER_SSRC.to_be_bytes());
            control_ok += 1;
        } else {
            assert!(SrtpUnprotect::new(&wrong).unprotect_rtp(packet).is_err());
            let opened = SrtpUnprotect::new(&rx)
                .unprotect_rtp(packet)
                .expect("pion's SRTP did not authenticate under our exported keys");
            assert_eq!(opened.payload.as_ref(), PEER_PAYLOAD);
            assert_eq!(opened.header.ssrc, PEER_SSRC);
            media_ok += 1;
        }
    }

    let (exited_ok, result, stderr) = peer.finish().await;
    let result = result.unwrap_or_else(|| panic!("peer printed no RESULT; stderr: {stderr}"));
    eprintln!(
        "interop ours={ours:?}: handshake {handshake_time:?}, retransmits {}, discarded {}, \
         dtls datagrams sent/received {}/{}; pion->us SRTP {media_ok}/{PEER_RTP} SRTCP \
         {control_ok}/{PEER_RTCP}; us->pion {result:?}",
        stats.retransmits, stats.records_discarded, state.sent, state.received,
    );
    assert!(exited_ok, "peer exited non-zero; stderr: {stderr}");
    assert_eq!(result.profile, 8, "SRTP_AEAD_AES_256_GCM");
    assert_eq!(result.sent, PEER_RTP);
    assert_eq!(result.rtcp_sent, PEER_RTCP);
    // pion -> us. Loopback UDP does not lose packets in practice; allow a
    // little slack so a loaded runner cannot fail the gate on scheduling.
    assert!(
        media_ok >= PEER_RTP - 5,
        "decrypted {media_ok} of {PEER_RTP} SRTP packets"
    );
    assert!(control_ok >= 1, "decrypted no SRTCP from pion");
    // us -> pion.
    assert!(
        result.received >= usize::from(OUR_RTP) - 2,
        "pion decrypted {} of {OUR_RTP} SRTP packets",
        result.received
    );
    assert!(
        result.rtcp_received >= 1,
        "pion decrypted none of our SRTCP"
    );
    assert!(result.received <= usize::from(OUR_RTP) && result.rtcp_received <= OUR_RTCP);
}

/// The SBC-facing case: we are the DTLS client (`a=setup:active`), pion is
/// the server, as the SBC's sidecar is for an `actpass` offer.
#[tokio::test]
#[ignore = "needs the Go test peer: build sidecar/srtp-test-peer and set PEER_BIN (see file header)"]
async fn pion_as_server_we_are_client() {
    interoperates(DtlsRole::Client).await;
}

/// We are the DTLS server (`a=setup:passive`), pion is the client. Pion
/// takes its `CertificateVerify` scheme from our `CertificateRequest`.
#[tokio::test]
#[ignore = "needs the Go test peer: build sidecar/srtp-test-peer and set PEER_BIN (see file header)"]
async fn pion_as_client_we_are_server() {
    interoperates(DtlsRole::Server).await;
}

/// Pion is told to expect a certificate that is not ours: it refuses, we
/// end with its fatal alert, nobody has keys. Both roles.
#[tokio::test]
#[ignore = "needs the Go test peer: build sidecar/srtp-test-peer and set PEER_BIN (see file header)"]
async fn pion_refuses_our_certificate_when_told_another_fingerprint() {
    for ours in [DtlsRole::Client, DtlsRole::Server] {
        let Session {
            assoc, state, peer, ..
        } = handshake(ours, false, true).await;
        assert!(
            matches!(state.failed, Some(FailureCause::PeerAlert(_))),
            "{ours:?}: {:?}",
            state.failed
        );
        assert!(state.keys.is_none(), "{ours:?}: keys exported");
        assert!(assoc.is_terminated());
        // Known issue D3 (qa-report.md): when pion itself refuses the
        // certificate, the test peer never exits. Its `demuxConn.ReadFrom`
        // (sidecar/srtp-test-peer/peer.go) is already blocked when pion sets
        // the read deadline that should unblock it, so pion's handshake
        // waits for its read loop for ever. That is a fault of the test
        // tool, not of the association: our side has its alert and is done.
        // So: give it a moment, accept either a non-zero exit or a hang, and
        // never a success.
        let exited = peer.exit_within(Duration::from_secs(3)).await;
        eprintln!(
            "interop ours={ours:?}: pion refused us, we got {:?}; peer exit: {exited:?}",
            state.failed
        );
        assert_ne!(
            exited,
            Some(true),
            "{ours:?}: pion accepted the wrong certificate"
        );
    }
}

/// We are told to expect a certificate that is not pion's: we refuse with
/// `FingerprintMismatch` and `bad_certificate`, pion's handshake fails,
/// nobody has keys. Both roles.
#[tokio::test]
#[ignore = "needs the Go test peer: build sidecar/srtp-test-peer and set PEER_BIN (see file header)"]
async fn we_refuse_pion_when_its_fingerprint_does_not_match() {
    for ours in [DtlsRole::Client, DtlsRole::Server] {
        let Session {
            socket,
            mut assoc,
            mut state,
            peer,
        } = handshake(ours, true, false).await;
        assert_eq!(
            state.failed,
            Some(FailureCause::FingerprintMismatch),
            "{ours:?}"
        );
        assert!(state.keys.is_none(), "{ours:?}: keys exported");
        assert_eq!(assoc.presented_fingerprint(), Some(&peer.fingerprint));
        // Flush our alert so pion fails now instead of at its 30 s limit.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        drive(&mut assoc, &socket, peer.addr, &mut state, deadline, |_| {
            false
        })
        .await;
        let (exited_ok, result, stderr) = peer.finish().await;
        eprintln!("interop ours={ours:?}: we refused; pion: {}", stderr.trim());
        assert!(
            !exited_ok,
            "{ours:?}: pion completed a handshake we refused"
        );
        assert_eq!(result, None);
    }
}
