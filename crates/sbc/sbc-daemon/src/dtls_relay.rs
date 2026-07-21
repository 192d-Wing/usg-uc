//! Media-side DTLS/SRTP demux + handshake record pump.
//!
//! For a terminated leg the relay owns the media UDP socket. Until the DTLS
//! handshake completes, incoming DTLS records (RFC 7983: first byte 20..=63) are
//! pumped to the sidecar and its responses sent back to the peer; SRTP/RTCP
//! (128..=191) does not flow yet. On the sidecar's `Ready` the exported SRTP
//! keys are returned and the caller switches to the SRTP relay (next phase).

use std::net::SocketAddr;

use proto_srtp::{SrtpKeyMaterial, SrtpProfile};
use tokio::net::UdpSocket;

use crate::dtls_sidecar::{SidecarError, SidecarEvent, SidecarReader, SidecarWriter};

// RFC 7714 §8.3 — AEAD_AES_256_GCM SRTP transform parameters.
const SRTP_MASTER_KEY_LEN: usize = 32;
const SRTP_MASTER_SALT_LEN: usize = 12;
/// Length of the DTLS-SRTP exported keying material for AEAD_AES_256_GCM:
/// `client_write_key || server_write_key || client_write_salt || server_write_salt`
/// (RFC 5764 §4.2). 32 + 32 + 12 + 12 = 88 bytes.
const EXPORTED_KEYING_LEN: usize = 2 * (SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN);

/// Classifies a demuxed media packet by its first byte (RFC 7983): DTLS records
/// are 20..=63; RTP/RTCP/SRTP are 128..=191; STUN is 0..=3.
#[must_use]
pub fn is_dtls_record(first_byte: u8) -> bool {
    (20..=63).contains(&first_byte)
}

/// Exported keying material from a completed handshake.
#[derive(Debug)]
pub struct HandshakeKeys {
    /// Negotiated SRTP protection profile (RFC 5764 value).
    pub profile: u16,
    /// Exported SRTP keying material for `proto-srtp`.
    pub srtp_keys: Vec<u8>,
}

/// Errors driving the media-side handshake pump.
#[derive(Debug, thiserror::Error)]
pub enum DtlsRelayError {
    /// Media-socket I/O error.
    #[error("media io: {0}")]
    Io(#[from] std::io::Error),
    /// IPC error talking to the sidecar.
    #[error("sidecar client: {0}")]
    Client(#[from] SidecarError),
    /// The sidecar failed the handshake.
    #[error("sidecar handshake failed: {0}")]
    Sidecar(String),
    /// The exported keying material was malformed or rejected by proto-srtp.
    #[error("srtp key material: {0}")]
    KeyMaterial(String),
}

/// Max inbound datagram we accept from the media socket. Matched to the
/// sidecar's IPC frame limit so a DTLS record the sidecar would accept is never
/// UDP-truncated on the way in.
const RECV_BUF: usize = 4096;

/// Pumps DTLS handshake records between the media socket and the sidecar until
/// the sidecar reports `Ready`, returning the exported SRTP keys.
///
/// - Inbound DTLS records from the media socket are forwarded to the sidecar;
///   non-DTLS packets (no SRTP flows before the handshake completes) are
///   dropped.
/// - The sidecar's outbound DTLS records are sent to the address the last DTLS
///   record was received from (symmetric latching, so replies reach a peer
///   behind NAT), falling back to `signaling_peer` before the first record —
///   needed when the SBC is the DTLS client and sends the first flight.
///
/// The caller should bound this with a timeout and own the socket's lifetime.
///
/// # Errors
/// Media/IPC I/O failure or a sidecar-reported handshake error.
pub async fn run_handshake_pump(
    media: &UdpSocket,
    signaling_peer: SocketAddr,
    reader: &mut SidecarReader,
    writer: &mut SidecarWriter,
) -> Result<HandshakeKeys, DtlsRelayError> {
    let mut buf = [0u8; RECV_BUF];
    // Where to send the sidecar's outbound records: the latched source of the
    // peer's DTLS, or the signaling address until we've seen one.
    let mut latched: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            // Media socket -> demux -> sidecar (inbound DTLS records).
            recv = media.recv_from(&mut buf) => {
                let (n, src) = recv?;
                if n > 0 && is_dtls_record(buf[0]) {
                    latched = Some(src);
                    writer.send_dtls(&buf[..n]).await?;
                }
                // Non-DTLS: no SRTP flows before the handshake; drop.
            }
            // Sidecar -> media socket (outbound DTLS records) / Ready / Error.
            event = reader.read() => {
                match event? {
                    SidecarEvent::Dtls(record) => {
                        media.send_to(&record, latched.unwrap_or(signaling_peer)).await?;
                    }
                    SidecarEvent::Ready { profile, srtp_keys } => {
                        return Ok(HandshakeKeys { profile, srtp_keys });
                    }
                    SidecarEvent::Error(msg) => {
                        return Err(DtlsRelayError::Sidecar(msg));
                    }
                }
            }
        }
    }
}

/// Splits the sidecar's exported DTLS-SRTP keying material into the SBC leg's
/// `(outbound, inbound)` SRTP master key material.
///
/// The `exported` blob is the RFC 5764 §4.2 layout for AEAD_AES_256_GCM:
/// `client_write_key(32) || server_write_key(32) || client_write_salt(12) ||
/// server_write_salt(12)`. Which half is the SBC's *outbound* (local) key
/// depends on the DTLS role: the client uses the `client_write_*` values to
/// protect its own traffic, the server uses `server_write_*`. `sbc_is_client`
/// is true when the SBC drove the handshake as DTLS client (peer offered
/// `a=setup:passive`, so the SBC is `active`).
///
/// # Errors
/// The blob is not exactly [`EXPORTED_KEYING_LEN`] bytes, or proto-srtp rejects
/// the derived key/salt.
pub fn srtp_key_material(
    exported: &[u8],
    sbc_is_client: bool,
) -> Result<(SrtpKeyMaterial, SrtpKeyMaterial), DtlsRelayError> {
    if exported.len() != EXPORTED_KEYING_LEN {
        return Err(DtlsRelayError::KeyMaterial(format!(
            "exported keying material is {} bytes, expected {EXPORTED_KEYING_LEN}",
            exported.len()
        )));
    }
    // RFC 5764 §4.2: keys first (both directions), then salts.
    let (keys, salts) = exported.split_at(2 * SRTP_MASTER_KEY_LEN);
    let (client_key, server_key) = keys.split_at(SRTP_MASTER_KEY_LEN);
    let (client_salt, server_salt) = salts.split_at(SRTP_MASTER_SALT_LEN);

    // Outbound = what the SBC uses to protect its own sent traffic (its
    // write key); inbound = the peer's write key, for unprotecting.
    let (out_key, out_salt, in_key, in_salt) = if sbc_is_client {
        (client_key, client_salt, server_key, server_salt)
    } else {
        (server_key, server_salt, client_key, client_salt)
    };

    let outbound = SrtpKeyMaterial::new(
        SrtpProfile::AeadAes256Gcm,
        out_key.to_vec(),
        out_salt.to_vec(),
    )
    .map_err(|e| DtlsRelayError::KeyMaterial(format!("outbound: {e}")))?;
    let inbound = SrtpKeyMaterial::new(
        SrtpProfile::AeadAes256Gcm,
        in_key.to_vec(),
        in_salt.to_vec(),
    )
    .map_err(|e| DtlsRelayError::KeyMaterial(format!("inbound: {e}")))?;
    Ok((outbound, inbound))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dtls_sidecar::{Role, SidecarClient};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[test]
    fn demux_classifies_dtls() {
        assert!(!is_dtls_record(0)); // STUN
        assert!(is_dtls_record(20)); // DTLS low
        assert!(is_dtls_record(22)); // DTLS handshake
        assert!(is_dtls_record(63)); // DTLS high
        assert!(!is_dtls_record(64)); // TURN channel
        assert!(!is_dtls_record(128)); // RTP/SRTP
    }

    // Distinct patterns per RFC 5764 field so the split is identifiable.
    fn sample_exported() -> Vec<u8> {
        let mut v = Vec::with_capacity(EXPORTED_KEYING_LEN);
        v.extend_from_slice(&[0x11u8; SRTP_MASTER_KEY_LEN]); // client_write_key
        v.extend_from_slice(&[0x22u8; SRTP_MASTER_KEY_LEN]); // server_write_key
        v.extend_from_slice(&[0x33u8; SRTP_MASTER_SALT_LEN]); // client_write_salt
        v.extend_from_slice(&[0x44u8; SRTP_MASTER_SALT_LEN]); // server_write_salt
        v
    }

    #[test]
    fn srtp_split_client_role() {
        // SBC is DTLS client: outbound = client_write_*, inbound = server_write_*.
        let (out, inb) = srtp_key_material(&sample_exported(), true).unwrap();
        assert_eq!(out.master_key(), [0x11u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(out.master_salt(), [0x33u8; SRTP_MASTER_SALT_LEN]);
        assert_eq!(inb.master_key(), [0x22u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(inb.master_salt(), [0x44u8; SRTP_MASTER_SALT_LEN]);
    }

    #[test]
    fn srtp_split_server_role() {
        // SBC is DTLS server: outbound = server_write_*, inbound = client_write_*.
        let (out, inb) = srtp_key_material(&sample_exported(), false).unwrap();
        assert_eq!(out.master_key(), [0x22u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(out.master_salt(), [0x44u8; SRTP_MASTER_SALT_LEN]);
        assert_eq!(inb.master_key(), [0x11u8; SRTP_MASTER_KEY_LEN]);
        assert_eq!(inb.master_salt(), [0x33u8; SRTP_MASTER_SALT_LEN]);
    }

    #[test]
    fn srtp_split_rejects_wrong_length() {
        assert!(matches!(
            srtp_key_material(&[0u8; EXPORTED_KEYING_LEN - 1], true),
            Err(DtlsRelayError::KeyMaterial(_))
        ));
        assert!(matches!(
            srtp_key_material(&[0u8; EXPORTED_KEYING_LEN + 1], false),
            Err(DtlsRelayError::KeyMaterial(_))
        ));
    }

    // Mock-sidecar framing (matches the Go service protocol).
    const MSG_HELLO: u8 = 1;
    const MSG_START: u8 = 2;
    const MSG_DTLS: u8 = 3;
    const MSG_READY: u8 = 4;

    async fn write_typed<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
        let n = 1 + body.len();
        let mut f = Vec::with_capacity(2 + n);
        f.extend_from_slice(&(u16::try_from(n).unwrap()).to_be_bytes());
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

    // A peer DTLS record is forwarded to the sidecar; the sidecar's response is
    // sent back to the peer; Ready yields the SRTP keys. Exercises the demux +
    // bidirectional pump (no real DTLS crypto).
    #[tokio::test]
    async fn pump_forwards_records_and_returns_keys() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let sock = std::env::temp_dir().join(format!("usg-dtls-relay-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let fp = "sha-384 SIDECAR";

        let sock2 = sock.clone();
        let sidecar = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            write_typed(&mut w, MSG_HELLO, fp.as_bytes()).await;
            let (t, _) = read_typed(&mut r).await; // Start
            assert_eq!(t, MSG_START);
            let (t, rec) = read_typed(&mut r).await; // forwarded peer DTLS record
            assert_eq!(t, MSG_DTLS);
            assert_eq!(rec, &[22u8, 1, 2, 3]);
            write_typed(&mut w, MSG_DTLS, b"sidecar-record").await;
            let mut ready = vec![0u8, 8];
            ready.extend_from_slice(&[9u8; 88]);
            write_typed(&mut w, MSG_READY, &ready).await;
            let _ = std::fs::remove_file(&sock2);
        });

        let mut client = SidecarClient::connect(&sock, fp).await.unwrap();
        client.start(Role::Server, "sha-384 PEER").await.unwrap();
        let (mut reader, mut writer) = client.into_split();

        // Peer sends a DTLS handshake record (first byte 22).
        peer.send_to(&[22u8, 1, 2, 3], relay_addr).await.unwrap();

        let keys = tokio::time::timeout(
            Duration::from_secs(5),
            run_handshake_pump(&relay, peer_addr, &mut reader, &mut writer),
        )
        .await
        .expect("pump timed out")
        .expect("pump failed");

        assert_eq!(keys.profile, 8);
        assert_eq!(keys.srtp_keys.len(), 88);

        // The sidecar's outbound record reached the peer.
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("peer recv timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"sidecar-record");

        sidecar.await.unwrap();
    }
}
