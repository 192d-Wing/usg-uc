//! An in-process DTLS peer for the soft-client DTLS tests: a real
//! `DtlsAssociation` on a loopback socket, driven by the test.
//!
//! Shared by the `client-sip-ua` and `client-core` integration tests (the
//! latter includes this file by path). It expects the `proto-dtls` test
//! harness as the sibling module `dtls`.
//!
//! Test-only code: panicking on an unexpected shape is the intended failure
//! mode.

use super::dtls;
use proto_dtls::{
    AssociationConfig, AssociationEvent, CertificateFingerprint, DtlsAssociation, DtlsCredentials,
    DtlsRole, FailureCause, SrtpKeyingMaterial,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// The role opposite to `role`.
pub const fn opposite(role: DtlsRole) -> DtlsRole {
    match role {
        DtlsRole::Client => DtlsRole::Server,
        DtlsRole::Server => DtlsRole::Client,
    }
}

/// An in-process DTLS peer: a real association on a loopback socket.
pub struct Peer {
    pub socket: UdpSocket,
    pub addr: SocketAddr,
    pub credentials: DtlsCredentials,
    pub assoc: Option<DtlsAssociation>,
    pub keys: Option<SrtpKeyingMaterial>,
    pub failed: Option<FailureCause>,
    pub saw_close: bool,
    /// Every DTLS datagram sent, in order.
    pub sent: Vec<Vec<u8>>,
    /// Every DTLS datagram received from the client (fed or not).
    pub received: Vec<Vec<u8>>,
    /// Datagrams from the client that are not DTLS.
    pub media: Vec<Vec<u8>>,
}

impl Peer {
    pub async fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        Self {
            socket,
            addr,
            credentials: dtls::identity(),
            assoc: None,
            keys: None,
            failed: None,
            saw_close: false,
            sent: Vec::new(),
            received: Vec::new(),
            media: Vec::new(),
        }
    }

    pub fn fingerprint(&self) -> CertificateFingerprint {
        self.credentials.fingerprint().clone()
    }

    /// Creates the association (its handshake budget starts now).
    pub fn start(&mut self, role: DtlsRole, expect: CertificateFingerprint) {
        self.start_with(role, expect, |_| {});
    }

    pub fn start_with(
        &mut self,
        role: DtlsRole,
        expect: CertificateFingerprint,
        configure: impl FnOnce(&mut AssociationConfig),
    ) {
        let mut config = AssociationConfig::new(role, self.credentials.clone(), vec![expect]);
        configure(&mut config);
        self.assoc = Some(DtlsAssociation::new(config, Instant::now()).unwrap());
    }

    pub const fn settled(&self) -> bool {
        self.keys.is_some() || self.failed.is_some() || self.saw_close
    }

    pub const fn association(&mut self) -> &mut DtlsAssociation {
        self.assoc.as_mut().expect("peer association started")
    }

    /// Sends what the association queued and takes its events.
    pub async fn flush(&mut self, client: SocketAddr) {
        while let Some(datagram) = self.association().poll_transmit() {
            if self.socket.send_to(&datagram, client).await.is_ok() {
                self.sent.push(datagram);
            }
        }
        while let Some(event) = self.association().poll_event() {
            match event {
                AssociationEvent::Connected { keys } => self.keys = Some(keys),
                AssociationEvent::Failed { cause } => self.failed = Some(cause),
                AssociationEvent::PeerClosed => self.saw_close = true,
            }
        }
    }

    /// Services the association in real time until `stop` or `limit`.
    /// `accept` decides whether a DTLS datagram from the client is fed to
    /// the association (`false` = lost on the way).
    pub async fn drive(
        &mut self,
        client: SocketAddr,
        limit: Duration,
        stop: impl Fn(&Self) -> bool,
        mut accept: impl FnMut(&[u8]) -> bool,
    ) {
        let deadline = tokio::time::Instant::now() + limit;
        let mut buf = vec![0u8; 4096];
        loop {
            self.flush(client).await;
            if stop(self) || tokio::time::Instant::now() >= deadline {
                return;
            }
            let wake = self.association().poll_timeout().map_or(deadline, |at| {
                deadline.min(tokio::time::Instant::from_std(at))
            });
            tokio::select! {
                received = self.socket.recv_from(&mut buf) => {
                    let Ok((len, from)) = received else { continue };
                    let datagram = buf[..len].to_vec();
                    if from != client {
                        continue;
                    }
                    if datagram.first().is_some_and(|b| (20..=63).contains(b)) {
                        let fed = accept(&datagram);
                        self.received.push(datagram.clone());
                        if fed {
                            self.association().handle_datagram(&datagram, Instant::now());
                        }
                    } else {
                        self.media.push(datagram);
                    }
                }
                () = tokio::time::sleep_until(wake) => {
                    self.association().handle_timeout(Instant::now());
                }
            }
        }
    }
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
