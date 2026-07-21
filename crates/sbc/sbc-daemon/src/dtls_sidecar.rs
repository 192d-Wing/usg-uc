//! IPC client for the Go DTLS-SRTP terminator sidecar.
//!
//! The relay opens one connection per terminated leg to the sidecar's Unix
//! socket and speaks the framed protocol: it reads the sidecar's `Hello`
//! (verifying the live fingerprint against the file-provisioned one), sends
//! `Start(role, peer fingerprint)`, pumps DTLS records both ways (`Dtls`
//! frames), and receives `Ready(profile, SRTP keys)`. The relay owns the media
//! socket and demuxes DTLS vs SRTP; this client only speaks the IPC side.
//!
//! Setup (`connect` → `start`) happens on [`SidecarClient`]; then
//! [`SidecarClient::into_split`] yields independent [`SidecarReader`] /
//! [`SidecarWriter`] halves so the relay can read sidecar events while
//! concurrently forwarding inbound DTLS records in a `select!` pump.
//!
//! Wire framing mirrors the sidecar: each message is a big-endian `u16` length
//! prefix over `[type:1][body]`. Frames are written in a single `write_all` so
//! a partial frame can never desync the stream.

use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// Max DTLS datagram carried over the channel (matches the sidecar).
const MAX_FRAME: usize = 4096;

/// Bounds connect + the sidecar's initial Hello so a hung sidecar can't wedge
/// the relay while it sets up a leg.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// Message types — must match the Go `service` protocol.
const MSG_HELLO: u8 = 1;
const MSG_START: u8 = 2;
const MSG_DTLS: u8 = 3;
const MSG_READY: u8 = 4;
const MSG_ERROR: u8 = 5;

/// The SBC's DTLS role for a leg. Byte values match the Go `dtlssession.Role`.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Role {
    /// SBC is the DTLS server (peer offered `a=setup:active`).
    Server = 0,
    /// SBC is the DTLS client (peer is `a=setup:passive`).
    Client = 1,
}

/// An event read from the sidecar during a session.
#[derive(Debug)]
pub enum SidecarEvent {
    /// A DTLS record the sidecar produced; send it on the media socket.
    Dtls(Vec<u8>),
    /// Handshake complete: negotiated SRTP profile + exported keying material.
    Ready {
        /// Negotiated SRTP protection profile (RFC 5764 value).
        profile: u16,
        /// Exported SRTP keying material for `proto-srtp`.
        srtp_keys: Vec<u8>,
    },
    /// The sidecar failed the handshake.
    Error(String),
}

/// Errors talking to the DTLS terminator sidecar.
#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    /// Transport I/O error.
    #[error("sidecar io: {0}")]
    Io(#[from] io::Error),
    /// Protocol violation (bad frame/type/length) or a timeout.
    #[error("sidecar protocol: {0}")]
    Protocol(String),
    /// The sidecar's live fingerprint differs from the file-provisioned one
    /// (e.g. it restarted with a rotated certificate) — the SDP would be stale.
    #[error("sidecar fingerprint mismatch: provisioned {file:?} vs live {live:?}")]
    FingerprintMismatch {
        /// The fingerprint the SBC advertised (from the file).
        file: String,
        /// The fingerprint the sidecar just reported over the socket.
        live: String,
    },
}

/// A per-leg connection to the DTLS terminator sidecar, during setup.
#[derive(Debug)]
pub struct SidecarClient {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
}

impl SidecarClient {
    /// Connects to the sidecar, reads its `Hello`, and verifies the live
    /// fingerprint matches the file-provisioned one advertised in SDP. Bounded
    /// by [`CONNECT_TIMEOUT`].
    ///
    /// # Errors
    /// Connection/IO failure, timeout, a non-Hello first frame, or a
    /// fingerprint mismatch.
    pub async fn connect(socket: &Path, expected_fingerprint: &str) -> Result<Self, SidecarError> {
        let setup = async {
            let (mut reader, writer) = UnixStream::connect(socket).await?.into_split();
            let hello = read_frame(&mut reader).await?;
            Ok::<_, SidecarError>((reader, writer, hello))
        };
        let (reader, writer, hello) = tokio::time::timeout(CONNECT_TIMEOUT, setup)
            .await
            .map_err(|_| {
                SidecarError::Protocol("timed out connecting to sidecar / awaiting Hello".into())
            })??;

        let (t, body) = split_frame(&hello)?;
        if t != MSG_HELLO {
            return Err(SidecarError::Protocol(format!(
                "expected Hello, got type {t}"
            )));
        }
        let live = String::from_utf8_lossy(body).trim().to_string();
        if !live.eq_ignore_ascii_case(expected_fingerprint.trim()) {
            return Err(SidecarError::FingerprintMismatch {
                file: expected_fingerprint.trim().to_string(),
                live,
            });
        }
        Ok(Self { reader, writer })
    }

    /// Sends `Start` to begin the DTLS handshake for this leg.
    ///
    /// # Errors
    /// Transport failure.
    pub async fn start(&mut self, role: Role, peer_fingerprint: &str) -> Result<(), SidecarError> {
        let mut body = Vec::with_capacity(1 + peer_fingerprint.len());
        body.push(role as u8);
        body.extend_from_slice(peer_fingerprint.as_bytes());
        write_frame(&mut self.writer, MSG_START, &body).await
    }

    /// Splits into independent read/write halves for the media-socket pump, so
    /// the relay can read sidecar events while concurrently forwarding inbound
    /// DTLS records (each half is `&mut`-borrowed separately in a `select!`).
    #[must_use]
    pub fn into_split(self) -> (SidecarReader, SidecarWriter) {
        (
            SidecarReader {
                reader: self.reader,
            },
            SidecarWriter {
                writer: self.writer,
            },
        )
    }
}

/// Read half of a sidecar session: sidecar → relay events.
#[derive(Debug)]
pub struct SidecarReader {
    reader: OwnedReadHalf,
}

impl SidecarReader {
    /// Reads the next event: a DTLS record to forward, or the final Ready/Error.
    ///
    /// # Errors
    /// Transport failure or a malformed frame.
    pub async fn read(&mut self) -> Result<SidecarEvent, SidecarError> {
        let frame = read_frame(&mut self.reader).await?;
        let (t, body) = split_frame(&frame)?;
        match t {
            MSG_DTLS => Ok(SidecarEvent::Dtls(body.to_vec())),
            MSG_READY => {
                if body.len() < 2 {
                    return Err(SidecarError::Protocol("short Ready message".into()));
                }
                let profile = u16::from_be_bytes([body[0], body[1]]);
                Ok(SidecarEvent::Ready {
                    profile,
                    srtp_keys: body[2..].to_vec(),
                })
            }
            MSG_ERROR => Ok(SidecarEvent::Error(
                String::from_utf8_lossy(body).into_owned(),
            )),
            other => Err(SidecarError::Protocol(format!(
                "unexpected message type {other}"
            ))),
        }
    }
}

/// Write half of a sidecar session: relay → sidecar DTLS records.
#[derive(Debug)]
pub struct SidecarWriter {
    writer: OwnedWriteHalf,
}

impl SidecarWriter {
    /// Sends one inbound DTLS record (demuxed from the media socket).
    ///
    /// # Errors
    /// Transport failure, or a record exceeding the frame limit.
    pub async fn send_dtls(&mut self, record: &[u8]) -> Result<(), SidecarError> {
        write_frame(&mut self.writer, MSG_DTLS, record).await
    }
}

async fn read_frame(reader: &mut OwnedReadHalf) -> Result<Vec<u8>, SidecarError> {
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr).await?;
    let n = usize::from(u16::from_be_bytes(hdr));
    if n == 0 || n > MAX_FRAME {
        return Err(SidecarError::Protocol(format!("invalid frame length {n}")));
    }
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(writer: &mut OwnedWriteHalf, t: u8, body: &[u8]) -> Result<(), SidecarError> {
    let n = 1 + body.len();
    if n > MAX_FRAME {
        return Err(SidecarError::Protocol(format!("frame too large: {n}")));
    }
    // Build the whole frame and issue a single write — a partial frame can never
    // appear on the wire (deadline-safe by construction).
    let mut frame = Vec::with_capacity(2 + n);
    #[allow(clippy::cast_possible_truncation)] // n <= MAX_FRAME (4096) fits u16
    frame.extend_from_slice(&(n as u16).to_be_bytes());
    frame.push(t);
    frame.extend_from_slice(body);
    writer.write_all(&frame).await?;
    Ok(())
}

fn split_frame(frame: &[u8]) -> Result<(u8, &[u8]), SidecarError> {
    frame
        .split_first()
        .map(|(t, rest)| (*t, rest))
        .ok_or_else(|| SidecarError::Protocol("empty frame".into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    // Framing helpers for the mock sidecar side: [len:2 BE][type:1][body].
    async fn write_typed<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
        let n = 1 + body.len();
        let mut f = Vec::with_capacity(2 + n);
        f.extend_from_slice(&(n as u16).to_be_bytes());
        f.push(t);
        f.extend_from_slice(body);
        w.write_all(&f).await.unwrap();
    }
    async fn read_typed<R: AsyncReadExt + Unpin>(r: &mut R) -> (u8, Vec<u8>) {
        let mut hdr = [0u8; 2];
        r.read_exact(&mut hdr).await.unwrap();
        let n = usize::from(u16::from_be_bytes(hdr));
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf).await.unwrap();
        (buf[0], buf[1..].to_vec())
    }

    // Exercises the client's framing + protocol flow against a scripted mock
    // sidecar (no real DTLS): Hello → Start → Dtls both ways → Ready.
    #[tokio::test]
    async fn client_protocol_roundtrip() {
        let dir = std::env::temp_dir();
        let sock = dir.join(format!("usg-dtls-client-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let fp = "sha-384 AB:CD:EF";

        let sock2 = sock.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            write_typed(&mut w, MSG_HELLO, fp.as_bytes()).await;
            let (t, body) = read_typed(&mut r).await; // Start
            assert_eq!(t, MSG_START);
            assert_eq!(body[0], Role::Client as u8);
            assert_eq!(&body[1..], b"sha-384 PEER");
            let (t, rec) = read_typed(&mut r).await; // client Dtls
            assert_eq!(t, MSG_DTLS);
            assert_eq!(rec, b"client-record");
            write_typed(&mut w, MSG_DTLS, b"server-record").await;
            let mut ready = vec![0u8, 8]; // profile = 8 (AEAD_AES_256_GCM)
            ready.extend_from_slice(&[7u8; 88]);
            write_typed(&mut w, MSG_READY, &ready).await;
            let _ = std::fs::remove_file(&sock2);
        });

        let mut client = SidecarClient::connect(&sock, fp).await.unwrap();
        client.start(Role::Client, "sha-384 PEER").await.unwrap();
        let (mut reader, mut writer) = client.into_split();
        writer.send_dtls(b"client-record").await.unwrap();

        match reader.read().await.unwrap() {
            SidecarEvent::Dtls(r) => assert_eq!(r, b"server-record"),
            other => panic!("want Dtls, got {other:?}"),
        }
        match reader.read().await.unwrap() {
            SidecarEvent::Ready { profile, srtp_keys } => {
                assert_eq!(profile, 8);
                assert_eq!(srtp_keys.len(), 88);
            }
            other => panic!("want Ready, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_rejects_fingerprint_mismatch() {
        let dir = std::env::temp_dir();
        let sock = dir.join(format!("usg-dtls-fpmm-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();

        let sock2 = sock.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_r, mut w) = stream.into_split();
            write_typed(&mut w, MSG_HELLO, b"sha-384 LIVE:FP").await;
            let _ = std::fs::remove_file(&sock2);
        });

        let err = SidecarClient::connect(&sock, "sha-384 FILE:FP")
            .await
            .unwrap_err();
        assert!(matches!(err, SidecarError::FingerprintMismatch { .. }));
    }
}
