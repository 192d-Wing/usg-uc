//! Shared harness for the DTLS driver integration tests: a soft-client
//! `MediaSession` on a loopback socket, and an in-process DTLS peer.
//!
//! The peer side reuses the `proto-dtls` test harness (`dtls`): real
//! `DtlsAssociation`s, the hand-driven `Puppet` (which knows the session
//! keys and can therefore send authenticated records a real association
//! never would), and SRTP helpers.
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
pub mod peer;

pub use peer::{Peer, hex, opposite};

use client_sip_ua::dtls_driver::{DriverTimings, SecureProgress};
use client_sip_ua::sdp_dtls::{DtlsSdpParams, Setup};
use client_sip_ua::{DtlsIdentity, MediaSession, MediaSessionEvent};
use proto_dtls::{CertificateFingerprint, DtlsRole};
use proto_ice::IceConfig;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A soft-client media session on its own loopback socket.
pub struct Client {
    pub session: MediaSession,
    /// The call's original media socket (what the audio pipeline gets).
    pub socket: std::net::UdpSocket,
    pub addr: SocketAddr,
    pub identity: DtlsIdentity,
    /// Kept so that media-session events are not refused.
    pub events: mpsc::Receiver<MediaSessionEvent>,
}

impl Client {
    pub fn new(role: DtlsRole) -> Self {
        let (tx, events) = mpsc::channel(32);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let identity = DtlsIdentity::generate().unwrap();
        let mut session = MediaSession::new(
            addr,
            role == DtlsRole::Client,
            IceConfig::default(),
            socket.try_clone().unwrap(),
            &identity,
            tx,
        );
        session.set_dtls_role(role).unwrap();
        Self {
            session,
            socket,
            addr,
            identity,
            events,
        }
    }

    pub fn fingerprint(&self) -> CertificateFingerprint {
        self.identity.fingerprint().clone()
    }

    /// Starts the handshake towards `remote`, expecting `fingerprint`.
    pub async fn begin(
        &mut self,
        remote: SocketAddr,
        fingerprint: CertificateFingerprint,
        timings: DriverTimings,
    ) {
        self.session.set_remote_addr(remote);
        self.session
            .begin_secure("test-call", &params(fingerprint), timings)
            .await
            .unwrap();
    }

    /// Does what the audio pipeline does when it takes the socket: clears
    /// `O_NONBLOCK` and sets a read timeout. Only valid once the driver has
    /// given up its tokio view.
    pub fn take_socket_like_the_pipeline(&mut self, read_timeout: Duration) {
        self.session.release_socket();
        self.socket.set_nonblocking(false).unwrap();
        self.socket.set_read_timeout(Some(read_timeout)).unwrap();
    }

    /// Polls the session until the handshake has an outcome.
    pub async fn settle(&mut self, limit: Duration) -> SecureProgress {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            match self.session.poll_secure() {
                SecureProgress::Pending if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                other => return other,
            }
        }
    }
}

pub fn params(fingerprint: CertificateFingerprint) -> DtlsSdpParams {
    DtlsSdpParams {
        fingerprints: vec![fingerprint],
        setup: Setup::Active,
    }
}

/// Timings that keep failure tests short.
pub fn fast_timings() -> DriverTimings {
    DriverTimings {
        initial_rto: Duration::from_millis(200),
        handshake_budget: Duration::from_secs(5),
        ..DriverTimings::default()
    }
}

/// Runs the peer and polls the client until the client's handshake has an
/// outcome and the peer has settled (or `limit`).
pub async fn handshake(client: &mut Client, peer: &mut Peer, limit: Duration) -> SecureProgress {
    let client_addr = client.addr;
    let (progress, ()) = tokio::join!(
        client.settle(limit),
        peer.drive(client_addr, limit, Peer::settled, |_| true),
    );
    progress
}

/// A client and a peer that completed a handshake, the client in `role`.
pub async fn connected(role: DtlsRole) -> (Client, Peer) {
    let mut client = Client::new(role);
    let mut peer = Peer::new().await;
    peer.start(opposite(role), client.fingerprint());
    client
        .begin(peer.addr, peer.fingerprint(), fast_timings())
        .await;
    let progress = handshake(&mut client, &mut peer, Duration::from_secs(5)).await;
    assert_eq!(progress, SecureProgress::Ready, "client as {role:?}");
    assert_eq!(peer.failed, None);
    assert!(peer.keys.is_some(), "peer connected");
    (client, peer)
}

/// Reads one datagram from a std socket that may still be non-blocking.
pub async fn recv_std(socket: &std::net::UdpSocket, limit: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + limit;
    let mut buf = [0u8; 2048];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => return Some(buf[..len].to_vec()),
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(_) => return None,
        }
    }
}
