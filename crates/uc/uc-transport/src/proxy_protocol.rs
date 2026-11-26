//! PROXY protocol version 2 (haproxy.org `proxy-protocol.txt` §2.2).
//!
//! An L4 reverse proxy (`HAProxy` `send-proxy-v2`, Envoy with PROXY
//! protocol V2, cloud load balancers) sends this binary preamble before any application bytes to
//! convey the original client address. The parser is pure and bounded: the
//! declared length is capped from the 16-byte preamble before any body is
//! read, and [`read_v2`] reads exactly the header, never the payload behind
//! it.
//!
//! The preamble is only believed from a configured trusted proxy; the
//! caller decides that before calling [`read_v2`]. The text PROXY v1 form
//! (the only one nginx `stream` sends) is not accepted.
//!
//! ## NIST 800-53 Rev5: SC-5, SC-7, SI-10, AU-3

use crate::error::{TransportError, TransportResult};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// The 12-byte v2 signature (`\r\n\r\n\0\r\nQUIT\n`).
pub const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Fixed v2 preamble: signature, version/command, family/protocol, length.
pub const V2_HEADER_LEN: usize = 16;

/// Largest accepted address block (addresses plus TLVs). The spec's
/// recommended receive size is 536 bytes past the preamble (the 216-byte
/// `AF_UNIX` pair plus room for TLVs).
///
/// ## NIST 800-53 Rev5: SC-5
pub const MAX_V2_ADDR_LEN: usize = 536;

/// Address block length for `AF_INET` over `STREAM`.
const TCP4_ADDR_LEN: usize = 12;
/// Address block length for `AF_INET6` over `STREAM`.
const TCP6_ADDR_LEN: usize = 36;

/// Family/protocol byte values the parser accepts under `PROXY`.
const FAM_UNSPEC: u8 = 0x00;
const FAM_TCP4: u8 = 0x11;
const FAM_TCP6: u8 = 0x21;
/// Valid family/protocol pairs this receiver does not implement (UDP over
/// IPv4/IPv6, `AF_UNIX` stream/datagram). Spec §2.2: a receiver that does
/// not support a combination handles it like `AF_UNSPEC` (no address).
const FAM_UNIMPLEMENTED: [u8; 4] = [0x12, 0x22, 0x31, 0x32];

/// The v2 command nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Connection set up by the proxy itself (health check); addresses are
    /// ignored and the real connection endpoints apply.
    Local,
    /// Relayed connection; the address block names the original client.
    Proxy,
}

/// A parsed v2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyV2 {
    /// `LOCAL` or `PROXY`.
    pub command: Command,
    /// Original client address. `None` for `LOCAL`, for `AF_UNSPEC` and for
    /// the valid combinations not implemented here (UDP, `AF_UNIX`).
    pub source: Option<SocketAddr>,
    /// Address the client connected to at the proxy.
    pub destination: Option<SocketAddr>,
}

/// Why a v2 header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    /// The bytes do not start with the v2 signature (no PROXY header).
    #[error("no PROXY v2 signature")]
    BadSignature,
    /// Version other than 2, unknown command, or a family / protocol byte
    /// the spec does not define.
    #[error("unsupported PROXY v2 version, command or address family")]
    Unsupported,
    /// Declared length above [`MAX_V2_ADDR_LEN`].
    #[error("PROXY v2 header longer than {MAX_V2_ADDR_LEN} bytes")]
    TooLong,
    /// Declared length shorter than the address family requires.
    #[error("PROXY v2 address block shorter than its family requires")]
    Truncated,
    /// Structurally invalid header.
    #[error("malformed PROXY v2 header")]
    Malformed,
}

/// Validated preamble fields.
struct Preamble {
    command: Command,
    family: u8,
    len: usize,
}

/// Checks the 16-byte preamble: version, command, family and the length cap
/// are all enforced before any of the body is needed.
fn parse_preamble(pre: &[u8; V2_HEADER_LEN]) -> Result<Preamble, ProxyError> {
    let ver_cmd = pre[12];
    if ver_cmd >> 4 != 2 {
        return Err(ProxyError::Unsupported);
    }
    let command = match ver_cmd & 0x0F {
        0 => Command::Local,
        1 => Command::Proxy,
        _ => return Err(ProxyError::Unsupported),
    };
    let family = pre[13];
    let len = usize::from(u16::from_be_bytes([pre[14], pre[15]]));
    if len > MAX_V2_ADDR_LEN {
        return Err(ProxyError::TooLong);
    }
    // Spec §2.2: for LOCAL the receiver must ignore the address block, so
    // its family is not checked.
    if command == Command::Proxy {
        let need = match family {
            FAM_UNSPEC => 0,
            FAM_TCP4 => TCP4_ADDR_LEN,
            FAM_TCP6 => TCP6_ADDR_LEN,
            f if FAM_UNIMPLEMENTED.contains(&f) => 0,
            _ => return Err(ProxyError::Unsupported),
        };
        if len < need {
            return Err(ProxyError::Truncated);
        }
    }
    Ok(Preamble {
        command,
        family,
        len,
    })
}

/// Reads a fixed-size array out of `body` at `at`.
fn array_at<const N: usize>(body: &[u8], at: usize) -> Result<[u8; N], ProxyError> {
    body.get(at..at + N)
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(ProxyError::Truncated)
}

/// Whether a claimed client address can key per-client state: not port 0
/// and not an unspecified, multicast or broadcast IP (no TCP connection
/// comes from one).
///
/// ## NIST 800-53 Rev5: SI-10, SC-7
const fn usable_source(src: SocketAddr) -> bool {
    let ip = src.ip().to_canonical();
    let bad_ip = ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast());
    src.port() != 0 && !bad_ip
}

/// Decodes the address block of a `PROXY` header. TLVs after the addresses
/// are skipped, not interpreted. A source that cannot be a TCP client
/// (port 0, unspecified, multicast or broadcast) is
/// [`ProxyError::Malformed`].
// POAM: POA&M-456 - PROXY v2 TLVs (PP2_TYPE_SSL, PP2_TYPE_UNIQUE_ID, ...)
// are skipped and not validated; only the address block is used.
fn parse_addresses(
    family: u8,
    body: &[u8],
) -> Result<(Option<SocketAddr>, Option<SocketAddr>), ProxyError> {
    let (src, dst) = match family {
        FAM_TCP4 => {
            let src = Ipv4Addr::from(array_at::<4>(body, 0)?);
            let dst = Ipv4Addr::from(array_at::<4>(body, 4)?);
            let sport = u16::from_be_bytes(array_at::<2>(body, 8)?);
            let dport = u16::from_be_bytes(array_at::<2>(body, 10)?);
            (
                SocketAddr::from((src, sport)),
                SocketAddr::from((dst, dport)),
            )
        }
        FAM_TCP6 => {
            let src = Ipv6Addr::from(array_at::<16>(body, 0)?);
            let dst = Ipv6Addr::from(array_at::<16>(body, 16)?);
            let sport = u16::from_be_bytes(array_at::<2>(body, 32)?);
            let dport = u16::from_be_bytes(array_at::<2>(body, 34)?);
            (
                SocketAddr::from((src, sport)),
                SocketAddr::from((dst, dport)),
            )
        }
        f if f == FAM_UNSPEC || FAM_UNIMPLEMENTED.contains(&f) => return Ok((None, None)),
        _ => return Err(ProxyError::Unsupported),
    };
    if !usable_source(src) {
        return Err(ProxyError::Malformed);
    }
    Ok((Some(src), Some(dst)))
}

/// Parses a v2 header at the start of `buf`.
///
/// Returns `Ok(None)` while `buf` is a valid but incomplete prefix, and
/// `Ok(Some((header, consumed)))` once the whole header is present, where
/// `consumed = 16 + declared length`; bytes after that belong to the
/// application. The signature is checked on whatever bytes are present, so
/// a non-PROXY stream is refused from its first differing byte.
///
/// # Errors
///
/// [`ProxyError`] for a bad signature, unsupported version / command /
/// family, a declared length over [`MAX_V2_ADDR_LEN`] (detected from the
/// preamble alone), or an address block too short for its family.
///
/// ## NIST 800-53 Rev5: SI-10, SC-5
pub fn parse_v2(buf: &[u8]) -> Result<Option<(ProxyV2, usize)>, ProxyError> {
    let sig_len = buf.len().min(V2_SIGNATURE.len());
    if buf.get(..sig_len) != V2_SIGNATURE.get(..sig_len) {
        return Err(ProxyError::BadSignature);
    }
    let Some(pre) = buf
        .get(..V2_HEADER_LEN)
        .and_then(|s| <&[u8; V2_HEADER_LEN]>::try_from(s).ok())
    else {
        return Ok(None);
    };
    let pre = parse_preamble(pre)?;
    let total = V2_HEADER_LEN + pre.len;
    let Some(body) = buf.get(V2_HEADER_LEN..total) else {
        return Ok(None);
    };
    let (source, destination) = match pre.command {
        Command::Local => (None, None),
        Command::Proxy => parse_addresses(pre.family, body)?,
    };
    Ok(Some((
        ProxyV2 {
            command: pre.command,
            source,
            destination,
        },
        total,
    )))
}

/// Maps a parse error to the transport error the daemon counts: a missing
/// signature is "header missing", anything else "header invalid".
fn to_transport_error(e: ProxyError) -> TransportError {
    match e {
        ProxyError::BadSignature => TransportError::ProxyHeaderMissing {
            reason: e.to_string(),
        },
        _ => TransportError::ProxyHeaderInvalid {
            reason: e.to_string(),
        },
    }
}

/// Reads exactly one v2 header from `stream`, never past it.
///
/// Reads the 16-byte preamble, then its declared length (at most
/// [`MAX_V2_ADDR_LEN`]), so the HTTP upgrade that follows is left in the
/// socket. Fails as soon as the preamble is invalid, without waiting for the
/// body. Run it under the handshake deadline; a stalled sender is bounded by
/// that.
///
/// # Errors
///
/// [`TransportError::ProxyHeaderMissing`] when the stream does not start
/// with the v2 signature, [`TransportError::ProxyHeaderInvalid`] for any
/// other header error, and [`TransportError::Io`] on EOF or a socket error.
///
/// ## NIST 800-53 Rev5: SC-5, SI-10
pub async fn read_v2(stream: &mut TcpStream) -> TransportResult<ProxyV2> {
    // Stack buffer sized to the cap: no allocation, no over-read.
    let mut buf = [0u8; V2_HEADER_LEN + MAX_V2_ADDR_LEN];
    stream.read_exact(&mut buf[..V2_HEADER_LEN]).await?;
    if let Some((header, _)) = parse_v2(&buf[..V2_HEADER_LEN]).map_err(to_transport_error)? {
        return Ok(header);
    }
    // parse_v2 accepted the preamble, so the length is within the cap.
    let len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    let total = V2_HEADER_LEN + len.min(MAX_V2_ADDR_LEN);
    stream.read_exact(&mut buf[V2_HEADER_LEN..total]).await?;
    match parse_v2(&buf[..total]).map_err(to_transport_error)? {
        Some((header, _)) => Ok(header),
        None => Err(TransportError::ProxyHeaderInvalid {
            reason: ProxyError::Malformed.to_string(),
        }),
    }
}
