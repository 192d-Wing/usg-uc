//! The `sidecar/srtp-test-peer` process as a test peer: spawn it, read its
//! `FINGERPRINT` and `LOCAL` lines, and parse its `RESULT` line.
//!
//! Shared by `proto-dtls/tests/interop_pion.rs` and, through `#[path]`,
//! by `client-core/tests/dtls_interop_pion.rs`.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proto_dtls::{CertificateFingerprint, DtlsRole};
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};

/// A running `srtp-test-peer`.
pub struct Peer {
    pub child: Child,
    pub stdout: BufReader<ChildStdout>,
    pub fingerprint: CertificateFingerprint,
    pub addr: SocketAddr,
}

/// The peer's own summary line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PeerResult {
    pub sent: usize,
    pub received: usize,
    pub rtcp_sent: usize,
    pub rtcp_received: usize,
    pub profile: usize,
}

impl Peer {
    /// Starts the peer in `role`, pointed at `remote`, expecting a
    /// certificate with `expect` as fingerprint. Reads its `FINGERPRINT` and
    /// `LOCAL` lines.
    /// `count` is the number of RTP packets the peer sends (`-count`) and
    /// `ssrc` the SSRC it sends with (`-ssrc`).
    pub async fn spawn(
        role: DtlsRole,
        remote: SocketAddr,
        expect: &CertificateFingerprint,
        count: u64,
        ssrc: u32,
    ) -> Self {
        let bin = std::env::var("PEER_BIN").expect(
            "PEER_BIN must point at the built sidecar/srtp-test-peer binary \
             (cd sidecar/srtp-test-peer && go build -o /tmp/srtp-test-peer .)",
        );
        let mut child = Command::new(bin)
            .args([
                "-role",
                if role == DtlsRole::Client {
                    "client"
                } else {
                    "server"
                },
                "-remote",
                &remote.to_string(),
                "-peer-fp",
                &expect.to_sdp(),
                "-count",
                &count.to_string(),
                "-ssrc",
                &ssrc.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn PEER_BIN");
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let (mut fingerprint, mut addr) = (None, None);
        let read = async {
            let mut line = String::new();
            while fingerprint.is_none() || addr.is_none() {
                line.clear();
                assert_ne!(
                    stdout.read_line(&mut line).await.unwrap(),
                    0,
                    "peer exited early"
                );
                if let Some(value) = line.strip_prefix("FINGERPRINT ") {
                    fingerprint =
                        Some(CertificateFingerprint::from_sdp_strict(value.trim()).unwrap());
                } else if let Some(value) = line.strip_prefix("LOCAL ") {
                    addr = Some(value.trim().parse().unwrap());
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .expect("peer did not print FINGERPRINT and LOCAL");
        Self {
            child,
            stdout,
            fingerprint: fingerprint.unwrap(),
            addr: addr.unwrap(),
        }
    }

    /// Waits up to `limit` for the peer to exit, then kills it. `None` if
    /// it had to be killed, otherwise whether it exited 0.
    pub async fn exit_within(mut self, limit: Duration) -> Option<bool> {
        if let Ok(status) = tokio::time::timeout(limit, self.child.wait()).await {
            Some(status.unwrap().success())
        } else {
            self.child.kill().await.unwrap();
            None
        }
    }

    /// Waits for the peer to exit. Returns whether it exited 0, its `RESULT`
    /// line if it printed one, and its stderr.
    pub async fn finish(mut self) -> (bool, Option<PeerResult>, String) {
        let status = tokio::time::timeout(Duration::from_secs(40), self.child.wait())
            .await
            .expect("peer did not exit")
            .unwrap();
        let mut out = String::new();
        self.stdout.read_to_string(&mut out).await.unwrap();
        let mut err = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            stderr.read_to_string(&mut err).await.unwrap();
        }
        let result = out
            .lines()
            .find_map(|line| line.strip_prefix("RESULT "))
            .map(|fields| {
                let mut result = PeerResult::default();
                for field in fields.split_whitespace() {
                    let (name, value) = field.split_once('=').unwrap();
                    let value = value.parse().unwrap();
                    match name {
                        "sent" => result.sent = value,
                        "received" => result.received = value,
                        "rtcp_sent" => result.rtcp_sent = value,
                        "rtcp_received" => result.rtcp_received = value,
                        "profile" => result.profile = value,
                        other => panic!("unknown RESULT field {other}"),
                    }
                }
                result
            });
        (status.success(), result, err)
    }
}
