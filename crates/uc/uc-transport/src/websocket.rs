//! WebSocket transport for SIP-over-WebSocket (RFC 7118).
//!
//! This module provides WebSocket transport for SIP messages, enabling
//! browser-based WebRTC clients to communicate with the SBC.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-5**: Denial-of-Service Protection (bounded frames; send and close
//!   do not wait on a pending receive)
//! - **SC-5, SC-7, AU-3**: behind a configured trusted reverse proxy the
//!   client address comes from PROXY v2, `X-Forwarded-For` or `Forwarded`
//!   (RFC 7239), so per-source limits, flows and audit name the client
//!   ([`ClientAddressMode`], [`WebSocketListener::with_client_address`])
//!
//! This module carries plain WS only. It does not provide TLS, so SC-8 and
//! SC-23 are not met here. `transport.wss_listen` is rejected by
//! `validate_config`; TLS must be terminated by a reverse proxy in front of
//! `ws_listen`.
//!
//! ## RFC 7118 Compliance
//!
//! - SIP subprotocol negotiation ("sip")
//! - UTF-8 text frames for SIP messages
//! - Binary frames support for SDP bodies
//! - Ping/pong keepalive handling (pong sent by tungstenite, RFC 6455 §5.5.3)

// POAM: POA&M-459: `WebSocketListener::bind(addr, true)` only sets a flag (no
// TLS) and `WebSocketTransport::connect` reports a placeholder peer address.

use crate::error::{TransportError, TransportResult};
use crate::{MAX_STREAM_MESSAGE_SIZE, ReceivedMessage, StreamTransport, Transport};
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, accept_hdr_async_with_config, connect_async,
};
use tracing::{debug, info, warn};
use uc_types::address::{SbcSocketAddr, TransportType};

/// Stream type carried by [`WebSocketTransport`].
type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// SIP WebSocket subprotocol per RFC 7118.
pub const SIP_SUBPROTOCOL: &str = "sip";

/// Maximum WebSocket message and frame size. One WS message carries one SIP
/// message (RFC 7118 §5), so the SIP stream limit applies. tungstenite would
/// otherwise accept 64 MiB messages and 16 MiB frames.
///
/// ## NIST 800-53 Rev5: SC-5, SI-10; RFC 6455 §10.4
pub const MAX_WS_MESSAGE_SIZE: usize = MAX_STREAM_MESSAGE_SIZE;

/// Upper bound on writing the Close frame in [`Transport::close`]. A peer
/// that stops reading (zero receive window) cannot hold the caller, the
/// writer lock or the connection slot past this.
// NIST 800-53 Rev5: SC-5, SC-10 (bounded teardown)
const CLOSE_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// tungstenite read buffer per connection (default 128 KiB).
const WS_READ_BUFFER_SIZE: usize = 8 * 1024;

/// Bytes queued before tungstenite writes to the socket (default 128 KiB).
/// Must stay below [`WS_MAX_WRITE_BUFFER_SIZE`] by at least one full frame.
const WS_WRITE_BUFFER_SIZE: usize = 8 * 1024;

/// Hard cap on queued outbound bytes per connection (default unbounded): one
/// pending threshold plus one maximum-size message fits; a peer that stops
/// reading cannot grow it further.
const WS_MAX_WRITE_BUFFER_SIZE: usize = 2 * MAX_WS_MESSAGE_SIZE;

/// WebSocket protocol limits for SIP-over-WebSocket.
///
/// ## NIST 800-53 Rev5: SC-5, SC-6
fn sip_ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE))
        .read_buffer_size(WS_READ_BUFFER_SIZE)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
}

/// Whether a `Sec-WebSocket-Protocol` value offers the exact `sip` token
/// (comma-separated list, RFC 6455 §4.2.2; tokens are case-sensitive).
fn offers_sip(value: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|token| token.trim_ascii() == SIP_SUBPROTOCOL.as_bytes())
}

/// Builds an HTTP 400 handshake rejection.
fn reject_upgrade(reason: &str) -> ErrorResponse {
    let mut resp = ErrorResponse::new(Some(reason.to_string()));
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    resp
}

/// `Retry-After` seconds sent with a 503 upgrade refusal.
const BUSY_RETRY_AFTER: &str = "5";

/// Builds an HTTP 503 handshake refusal with `Retry-After` (RFC 9110
/// §15.6.4, §10.2.3): the client is over a per-client limit.
fn busy_upgrade() -> ErrorResponse {
    let mut resp = ErrorResponse::new(Some("client over its connection limits".to_string()));
    *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    resp.headers_mut()
        .insert("retry-after", HeaderValue::from_static(BUSY_RETRY_AFTER));
    resp
}

/// Upgrade-request check for RFC 7118 §4: the client MUST offer `sip`, and
/// the server MUST echo it or fail the handshake. With `require_sip` false
/// a request carrying no `Sec-WebSocket-Protocol` header is admitted without
/// a subprotocol (legacy gateways); one that offers only other protocols is
/// still refused.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
#[derive(Debug, Clone, Copy)]
struct SubprotocolCheck {
    require_sip: bool,
}

impl Callback for SubprotocolCheck {
    fn on_request(self, req: &Request, mut resp: Response) -> Result<Response, ErrorResponse> {
        let mut offered_any = false;
        let mut offered_sip = false;
        for value in req.headers().get_all("sec-websocket-protocol") {
            offered_any = true;
            if offers_sip(value.as_bytes()) {
                offered_sip = true;
            }
        }
        if offered_sip {
            resp.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static(SIP_SUBPROTOCOL),
            );
            return Ok(resp);
        }
        if !offered_any && !self.require_sip {
            return Ok(resp);
        }
        Err(reject_upgrade(
            "the 'sip' WebSocket subprotocol is required",
        ))
    }
}

/// Where a [`WebSocketListener`] takes the client address from when the TCP
/// peer is a trusted reverse proxy.
///
/// Whatever the mode, a header or preamble is believed only from a peer the
/// listener's trusted-proxy predicate accepts; from any other peer the TCP
/// source address is the client, as with [`ClientAddressMode::Peer`].
///
/// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAddressMode {
    /// The TCP peer is the client (no proxy).
    #[default]
    Peer,
    /// A PROXY protocol v2 preamble precedes the HTTP upgrade (L4 proxies:
    /// `HAProxy` `send-proxy-v2`, Envoy V2). The v1 text form, the only one
    /// nginx `stream` sends, is refused.
    ProxyV2,
    /// The `X-Forwarded-For` request header (HTTP ingress controllers).
    XForwardedFor,
    /// The RFC 7239 `Forwarded` request header, `for=` parameter.
    Forwarded,
}

/// A client address taken from a forwarding header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardedClient {
    /// Client IP (IPv4-mapped IPv6 reported as plain IPv4).
    pub ip: IpAddr,
    /// Client port, when the header carries one (`Forwarded` only).
    pub port: Option<u16>,
}

/// Why no client address could be taken from a forwarding header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ForwardedError {
    /// The header is absent or empty.
    #[error("forwarding header missing")]
    Missing,
    /// The hop that decides the client address does not parse.
    #[error("forwarding header malformed")]
    Malformed,
    /// The deciding hop is `unknown` or an obfuscated identifier
    /// (RFC 7239 §6.2, §6.3), so it cannot key per-client limits.
    #[error("forwarding header names an obfuscated or unknown client")]
    Obfuscated,
}

/// Predicate naming the reverse proxies whose forwarding information is
/// believed (`transport.ws_trusted_proxies` in the daemon).
pub type TrustedProxyFn = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Most hops examined in one forwarding header. A chain longer than this
/// with every hop trusted is refused rather than walked.
///
/// ## NIST 800-53 Rev5: SC-5
const MAX_FORWARDED_HOPS: usize = 64;

/// A non-zero decimal port of at most five digits.
fn parse_port(p: &[u8]) -> Option<u16> {
    if p.is_empty() || p.len() > 5 || !p.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(p)
        .ok()?
        .parse::<u16>()
        .ok()
        .filter(|&n| n != 0)
}

/// One `X-Forwarded-For` element: an IP literal, optionally bracketed (IPv6)
/// and optionally with a port, which is discarded.
fn parse_xff_node(element: &[u8]) -> Result<IpAddr, ForwardedError> {
    let s = std::str::from_utf8(element.trim_ascii()).map_err(|_| ForwardedError::Malformed)?;
    let ip = if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or(ForwardedError::Malformed)?;
        let ip = inner
            .parse::<Ipv6Addr>()
            .map_err(|_| ForwardedError::Malformed)?;
        if !after.is_empty() {
            let port = after.strip_prefix(':').ok_or(ForwardedError::Malformed)?;
            parse_port(port.as_bytes()).ok_or(ForwardedError::Malformed)?;
        }
        IpAddr::V6(ip)
    } else if let Ok(ip) = s.parse::<IpAddr>() {
        ip
    } else {
        let (host, port) = s.split_once(':').ok_or(ForwardedError::Malformed)?;
        parse_port(port.as_bytes()).ok_or(ForwardedError::Malformed)?;
        IpAddr::V4(
            host.parse::<Ipv4Addr>()
                .map_err(|_| ForwardedError::Malformed)?,
        )
    };
    Ok(ip.to_canonical())
}

/// Client address from `X-Forwarded-For` field lines (in arrival order;
/// RFC 9110 §5.3 combines them into one list, the last line rightmost).
///
/// Walks right to left: hops `is_trusted` accepts are proxies and skipped,
/// and the first untrusted hop is the client. Elements left of it were
/// supplied by the client and are never parsed. Empty elements (`a,,b`,
/// a trailing `,`) are list syntax, not hops, and are skipped (RFC 9110
/// §5.6.1.2). If every hop is trusted the leftmost is used. The port, if
/// any, is dropped.
///
/// # Errors
///
/// [`ForwardedError::Missing`] when there is no non-empty line,
/// [`ForwardedError::Malformed`] when a hop that must be examined is not an
/// IP literal, or the chain exceeds the hop limit.
///
/// ## NIST 800-53 Rev5: SC-7, SI-10; RFC 7239 §8.1 (trust only known proxies)
pub fn client_from_x_forwarded_for(
    values: &[&[u8]],
    is_trusted: impl Fn(IpAddr) -> bool,
) -> Result<ForwardedClient, ForwardedError> {
    let mut leftmost = None;
    let mut hops = 0usize;
    for line in values.iter().rev() {
        if line.trim_ascii().is_empty() {
            continue;
        }
        for element in line.rsplit(|&b| b == b',') {
            if element.trim_ascii().is_empty() {
                continue;
            }
            hops += 1;
            if hops > MAX_FORWARDED_HOPS {
                return Err(ForwardedError::Malformed);
            }
            let ip = parse_xff_node(element)?;
            if !is_trusted(ip) {
                return Ok(ForwardedClient { ip, port: None });
            }
            leftmost = Some(ip);
        }
    }
    leftmost
        .map(|ip| ForwardedClient { ip, port: None })
        .ok_or(ForwardedError::Missing)
}

/// RFC 9110 §5.6.2 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// RFC 9110 §5.6.4 `qdtext`.
const fn is_qdtext(b: u8) -> bool {
    matches!(b, b'\t' | b' ' | 0x21 | 0x23..=0x5B | 0x5D..=0x7E | 0x80..=0xFF)
}

/// RFC 9110 §5.6.4 `quoted-pair` octet: HTAB, SP, VCHAR or obs-text.
const fn is_quoted_pair_octet(b: u8) -> bool {
    matches!(b, b'\t' | b' '..=0x7E | 0x80..=0xFF)
}

/// Skips optional whitespace (SP / HTAB) from `i`.
fn skip_ows(line: &[u8], mut i: usize) -> usize {
    while matches!(line.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    i
}

/// Reads a `token` or `quoted-string` value at `i`; returns the value bytes
/// (quotes removed, escapes left in place) and the index after it.
fn forwarded_value(line: &[u8], mut i: usize) -> Result<(&[u8], usize), ForwardedError> {
    if line.get(i) != Some(&b'"') {
        let start = i;
        while line.get(i).copied().is_some_and(is_tchar) {
            i += 1;
        }
        let v = line.get(start..i).unwrap_or_default();
        return if v.is_empty() {
            Err(ForwardedError::Malformed)
        } else {
            Ok((v, i))
        };
    }
    i += 1;
    let start = i;
    loop {
        match line.get(i).copied() {
            Some(b'"') => break,
            Some(b'\\') if line.get(i + 1).copied().is_some_and(is_quoted_pair_octet) => i += 2,
            Some(b) if is_qdtext(b) => i += 1,
            _ => return Err(ForwardedError::Malformed),
        }
    }
    Ok((line.get(start..i).unwrap_or_default(), i + 1))
}

/// Splits `line` at commas outside quoted-strings (a `\` inside quotes
/// escapes the next octet), appending each element, empty ones included.
/// An unterminated quoted-string runs to the end of the line, so it lands
/// in the last element and fails there.
fn split_forwarded_elements<'a>(line: &'a [u8], out: &mut Vec<&'a [u8]>) {
    let mut start = 0;
    let mut quoted = false;
    let mut i = 0;
    while let Some(&b) = line.get(i) {
        match b {
            b'\\' if quoted => i += 1,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                out.push(line.get(start..i).unwrap_or_default());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(line.get(start..).unwrap_or_default());
}

/// One `forwarded-element` (RFC 7239 §4), already split from its list.
enum ForwardedElement<'a> {
    /// Only whitespace and `;`: list syntax, not a hop (RFC 9110 §5.6.1.2).
    Empty,
    /// Pairs but no `for=`.
    NoFor,
    /// The raw `for` value (quotes removed, escapes in place).
    For(&'a [u8]),
}

/// Parses one element: `forwarded-pair` separated by `;`, empty pairs
/// ignored. A parameter MUST NOT occur twice (RFC 7239 §4).
fn parse_forwarded_element(e: &[u8]) -> Result<ForwardedElement<'_>, ForwardedError> {
    let mut i = 0;
    let mut any_pair = false;
    let mut for_value = None;
    loop {
        i = skip_ows(e, i);
        match e.get(i) {
            None => break,
            Some(b';') => {
                i += 1;
                continue;
            }
            Some(_) => {}
        }
        let name_start = i;
        while e.get(i).copied().is_some_and(is_tchar) {
            i += 1;
        }
        let name = e.get(name_start..i).unwrap_or_default();
        if name.is_empty() || e.get(i) != Some(&b'=') {
            return Err(ForwardedError::Malformed);
        }
        let (value, next) = forwarded_value(e, i + 1)?;
        i = skip_ows(e, next);
        if !matches!(e.get(i), None | Some(b';')) {
            return Err(ForwardedError::Malformed);
        }
        any_pair = true;
        if name.eq_ignore_ascii_case(b"for") {
            if for_value.is_some() {
                return Err(ForwardedError::Malformed);
            }
            for_value = Some(value);
        }
    }
    Ok(match (any_pair, for_value) {
        (false, _) => ForwardedElement::Empty,
        (true, None) => ForwardedElement::NoFor,
        (true, Some(v)) => ForwardedElement::For(v),
    })
}

/// Longest unescaped `node` value examined (a bracketed IPv6 literal with
/// a port fits easily); longer values are refused.
const MAX_NODE_LEN: usize = 96;

/// Removes quoted-pair escapes (RFC 9110 §5.6.4) from a `for` value into
/// `out`.
fn unescape_node<'b>(
    v: &[u8],
    out: &'b mut [u8; MAX_NODE_LEN],
) -> Result<&'b [u8], ForwardedError> {
    let mut n = 0;
    let mut bytes = v.iter();
    while let Some(&b) = bytes.next() {
        let b = if b == b'\\' {
            *bytes.next().ok_or(ForwardedError::Malformed)?
        } else {
            b
        };
        *out.get_mut(n).ok_or(ForwardedError::Malformed)? = b;
        n += 1;
    }
    out.get(..n).ok_or(ForwardedError::Malformed)
}

/// RFC 7239 §6.3 `obfnode` / `obfport`: `_` followed by ALPHA / DIGIT / `.`
/// / `_` / `-`.
fn is_obfuscated(v: &[u8]) -> bool {
    v.split_first().is_some_and(|(&first, rest)| {
        first == b'_'
            && !rest.is_empty()
            && rest
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    })
}

/// RFC 7239 §6 `node-port`: a port, or an obfuscated port (`None`).
fn parse_node_port(p: &[u8]) -> Result<Option<u16>, ForwardedError> {
    if is_obfuscated(p) {
        return Ok(None);
    }
    parse_port(p).map(Some).ok_or(ForwardedError::Malformed)
}

/// RFC 7239 §6 `node`: `nodename [ ":" node-port ]`, where the nodename is
/// an IPv4 literal, a bracketed IPv6 literal, `unknown` or an `obfnode`.
fn parse_forwarded_node(v: &[u8]) -> Result<ForwardedClient, ForwardedError> {
    let (ip, port) = if let Some(rest) = v.strip_prefix(b"[") {
        let close = rest
            .iter()
            .position(|&b| b == b']')
            .ok_or(ForwardedError::Malformed)?;
        let (inner, after) = rest.split_at(close);
        let ip = std::str::from_utf8(inner)
            .ok()
            .and_then(|s| s.parse::<Ipv6Addr>().ok())
            .ok_or(ForwardedError::Malformed)?;
        let port = match after.get(1..).unwrap_or_default().split_first() {
            None => None,
            Some((b':', p)) => parse_node_port(p)?,
            Some(_) => return Err(ForwardedError::Malformed),
        };
        (IpAddr::V6(ip), port)
    } else {
        let mut parts = v.splitn(2, |&b| b == b':');
        let name = parts.next().unwrap_or_default();
        let port = parts.next();
        let port = port.map(parse_node_port).transpose()?.flatten();
        if name.eq_ignore_ascii_case(b"unknown") || is_obfuscated(name) {
            return Err(ForwardedError::Obfuscated);
        }
        let ip = std::str::from_utf8(name)
            .ok()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .ok_or(ForwardedError::Malformed)?;
        (IpAddr::V4(ip), port)
    };
    Ok(ForwardedClient {
        ip: ip.to_canonical(),
        port,
    })
}

/// Client address from RFC 7239 `Forwarded` field lines (in arrival order).
///
/// Parameter names are case-insensitive and values may be quoted-strings
/// (quoted-pair escapes removed), so `,` and `;` inside quotes do not
/// split; empty elements and empty pairs are ignored (RFC 7239 §4, RFC 9110
/// §5.6.1.2). Elements are parsed right to left only as far as the deciding
/// hop: hops `is_trusted` accepts are skipped, and the first untrusted hop
/// is the client (all trusted: the leftmost). Elements left of the deciding
/// hop were supplied by the client and are never parsed. A quoted
/// `"[v6]:port"` or `"v4:port"` keeps its port; an obfuscated port gives
/// `None`. Only `for=` is used: `proto=`, `by=` and `host=` are ignored.
///
/// # Errors
///
/// [`ForwardedError::Missing`] when no element has a `for=` hop,
/// [`ForwardedError::Obfuscated`] when the deciding hop is `unknown` or an
/// obfuscated identifier, [`ForwardedError::Malformed`] for a syntax error
/// in an examined element, an examined element without `for=`, or more
/// than the hop limit of trusted hops.
///
/// ## NIST 800-53 Rev5: SC-7, SI-10; RFC 7239 §4, §5.2, §6, §8.1
pub fn client_from_forwarded(
    values: &[&[u8]],
    is_trusted: impl Fn(IpAddr) -> bool,
) -> Result<ForwardedClient, ForwardedError> {
    // Element spans of one line; the line is bounded by the HTTP request
    // parser's limits.
    let mut elements = Vec::new();
    let mut node = [0u8; MAX_NODE_LEN];
    let mut leftmost = None;
    let mut hops = 0usize;
    for line in values.iter().rev() {
        elements.clear();
        split_forwarded_elements(line, &mut elements);
        for element in elements.iter().rev() {
            let value = match parse_forwarded_element(element)? {
                ForwardedElement::Empty => continue,
                ForwardedElement::NoFor => return Err(ForwardedError::Malformed),
                ForwardedElement::For(v) => v,
            };
            hops += 1;
            if hops > MAX_FORWARDED_HOPS {
                return Err(ForwardedError::Malformed);
            }
            let client = parse_forwarded_node(unescape_node(value, &mut node)?)?;
            if !is_trusted(client.ip) {
                return Ok(client);
            }
            leftmost = Some(client);
        }
    }
    leftmost.ok_or(ForwardedError::Missing)
}

/// What the trusted-proxy upgrade check decided, read by the listener
/// once the handshake returns.
enum ProxyCheckOutcome<A> {
    /// The forwarding header was missing or unusable (400 sent).
    Header(ForwardedError),
    /// The caller's admission refused the client (503 sent).
    Refused,
    /// The client was admitted; `A` is the caller's admission state.
    Admitted(SbcSocketAddr, A),
}

/// Upgrade-request check for a trusted proxy: takes the client address from
/// the configured forwarding header, refusing the upgrade with 400 when it
/// is missing or unusable (never a fallback to the proxy address), applies
/// the subprotocol check, then the caller's admission on the client address,
/// refusing with 503 + `Retry-After` when it says no. The outcome is left in
/// `outcome` for the listener.
///
/// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
struct ForwardedCheck<F, A> {
    subprotocol: SubprotocolCheck,
    forwarded: bool,
    trusted: TrustedProxyFn,
    admit: F,
    outcome: Arc<std::sync::Mutex<Option<ProxyCheckOutcome<A>>>>,
}

impl<F, A> ForwardedCheck<F, A> {
    fn set(&self, outcome: ProxyCheckOutcome<A>) {
        *self
            .outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome);
    }
}

impl<F, A> Callback for ForwardedCheck<F, A>
where
    F: FnOnce(SbcSocketAddr) -> Option<A>,
{
    fn on_request(self, req: &Request, resp: Response) -> Result<Response, ErrorResponse> {
        let header = if self.forwarded {
            "forwarded"
        } else {
            "x-forwarded-for"
        };
        // Bounded by the request parser's header limit.
        let lines: Vec<&[u8]> = req
            .headers()
            .get_all(header)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect();
        let trusted = |ip| (self.trusted)(ip);
        let parsed = if self.forwarded {
            client_from_forwarded(&lines, trusted)
        } else {
            client_from_x_forwarded_for(&lines, trusted)
        };
        let client = match parsed {
            Ok(client) => client,
            Err(e) => {
                self.set(ProxyCheckOutcome::Header(e));
                return Err(reject_upgrade("a valid client address header is required"));
            }
        };
        let resp = self.subprotocol.on_request(req, resp)?;
        // Port 0: the header carried no client port.
        let client = SbcSocketAddr::from(SocketAddr::new(client.ip, client.port.unwrap_or(0)));
        let Self { admit, outcome, .. } = self;
        let admitted = admit(client);
        let refused = admitted.is_none();
        *outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(admitted.map_or(ProxyCheckOutcome::Refused, |a| {
                ProxyCheckOutcome::Admitted(client, a)
            }));
        if refused {
            Err(busy_upgrade())
        } else {
            Ok(resp)
        }
    }
}

/// Options for [`WebSocketListener`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketListenerOptions {
    /// Refuse upgrades that do not offer the `sip` subprotocol (RFC 7118 §4).
    pub require_sip_subprotocol: bool,
}

impl Default for WebSocketListenerOptions {
    fn default() -> Self {
        Self {
            require_sip_subprotocol: true,
        }
    }
}

/// WebSocket transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketState {
    /// Connection is being established.
    Connecting,
    /// Connection is open and ready.
    Open,
    /// Connection is closing.
    Closing,
    /// Connection is closed.
    Closed,
}

/// WebSocket transport for SIP messages.
///
/// Implements RFC 7118 SIP-over-WebSocket over plain WS. The `secure` flag
/// only labels the transport; no TLS is applied (POA&M-459).
pub struct WebSocketTransport {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// Remote peer address.
    peer_addr: SbcSocketAddr,
    /// Read and write halves are locked separately so a send or close from
    /// another task never waits behind a pending `recv` on the reader task.
    // NIST 800-53 Rev5: SC-5 (no head-of-line blocking on the send path)
    reader: Mutex<SplitStream<WsStream>>,
    writer: Mutex<SplitSink<WsStream, Message>>,
    /// Connection state.
    connected: AtomicBool,
    /// Set by [`Transport::close`]; polled by the daemon reader.
    closed: AtomicBool,
    /// Ping and pong frames read since the last `take_control_frames`.
    control_frames: AtomicU64,
    /// WSS label only; no TLS is applied (POA&M-459).
    secure: bool,
    /// Client address learnt from a trusted proxy (SR-59); `peer_addr`
    /// stays the socket peer.
    client_addr: Option<SbcSocketAddr>,
}

impl WebSocketTransport {
    /// Creates a new WebSocket transport from an accepted connection.
    ///
    /// # Arguments
    ///
    /// * `stream` - The WebSocket stream from an accepted connection
    /// * `local_addr` - Local address
    /// * `peer_addr` - Remote peer address
    /// * `secure` - WSS label only; no TLS (POA&M-459)
    pub fn new(
        stream: WsStream,
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
        secure: bool,
    ) -> Self {
        let (writer, reader) = stream.split();
        Self {
            local_addr,
            peer_addr,
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            connected: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            control_frames: AtomicU64::new(0),
            secure,
            client_addr: None,
        }
    }

    /// Records the client address a trusted proxy reported (see
    /// [`Transport::client_addr`]).
    #[must_use]
    pub const fn with_client_addr(mut self, client: Option<SbcSocketAddr>) -> Self {
        self.client_addr = client;
        self
    }

    /// Connects to a WebSocket server.
    ///
    /// # Arguments
    ///
    /// * `url` - WebSocket URL (ws:// or wss://)
    /// * `local_addr` - Local bind address
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect(url: &str, local_addr: SbcSocketAddr) -> TransportResult<Self> {
        let secure = url.starts_with("wss://");

        info!(url = %url, "Connecting to WebSocket server");

        let (stream, _response) =
            connect_async(url)
                .await
                .map_err(|e| TransportError::ConnectFailed {
                    address: local_addr,
                    reason: format!("WebSocket connect failed: {e}"),
                })?;

        // POAM: POA&M-459: the peer address is a placeholder, not parsed from the URL.
        let peer_addr = local_addr;

        Ok(Self::new(stream, local_addr, peer_addr, secure))
    }

    /// Accepts a WebSocket connection from a TCP stream.
    ///
    /// # Arguments
    ///
    /// * `tcp_stream` - TCP stream to upgrade
    /// * `local_addr` - Local address
    /// * `peer_addr` - Remote peer address
    /// * `secure` - WSS label only; no TLS (POA&M-459)
    ///
    /// # Errors
    ///
    /// Returns an error if the WebSocket handshake fails.
    pub async fn accept(
        tcp_stream: TcpStream,
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
        secure: bool,
    ) -> TransportResult<Self> {
        Self::accept_with_options(
            tcp_stream,
            local_addr,
            peer_addr,
            secure,
            WebSocketListenerOptions::default(),
        )
        .await
    }

    /// Accepts a WebSocket connection with explicit options: negotiates the
    /// `sip` subprotocol and applies the SIP message/frame size limits.
    ///
    /// # Errors
    ///
    /// Returns an error if the WebSocket handshake fails or is refused.
    pub async fn accept_with_options(
        tcp_stream: TcpStream,
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
        secure: bool,
        options: WebSocketListenerOptions,
    ) -> TransportResult<Self> {
        let callback = SubprotocolCheck {
            require_sip: options.require_sip_subprotocol,
        };
        let stream = accept_hdr_async_with_config(
            MaybeTlsStream::Plain(tcp_stream),
            callback,
            Some(sip_ws_config()),
        )
        .await
        .map_err(|e| TransportError::ConnectFailed {
            address: peer_addr,
            reason: format!("WebSocket accept failed: {e}"),
        })?;

        info!(
            local = %local_addr,
            peer = %peer_addr,
            secure,
            "Accepted WebSocket connection"
        );

        Ok(Self::new(stream, local_addr, peer_addr, secure))
    }

    /// Returns the current connection state.
    #[must_use]
    pub fn state(&self) -> WebSocketState {
        if self.connected.load(Ordering::Relaxed) {
            WebSocketState::Open
        } else {
            WebSocketState::Closed
        }
    }

    /// Returns the `secure` flag. This is a label only; the stream is plain
    /// WS (POA&M-459).
    #[must_use]
    pub const fn is_wss(&self) -> bool {
        self.secure
    }

    /// Sends a ping frame for keepalive.
    ///
    /// # Errors
    ///
    /// Returns an error if the ping cannot be sent.
    pub async fn ping(&self, payload: &[u8]) -> TransportResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::AlreadyClosed);
        }
        let mut writer = self.writer.lock().await;
        writer
            .send(Message::Ping(payload.to_vec().into()))
            .await
            .map_err(|e| TransportError::Io {
                reason: format!("Ping failed: {e}"),
            })?;
        drop(writer);
        debug!("Sent WebSocket ping");
        Ok(())
    }
}

impl Transport for WebSocketTransport {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
        dest: &'a SbcSocketAddr,
    ) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(TransportError::AlreadyClosed);
            }
            if !self.connected.load(Ordering::Relaxed) {
                return Err(TransportError::NotConnected);
            }

            if data.len() > MAX_STREAM_MESSAGE_SIZE {
                return Err(TransportError::MessageTooLarge {
                    size: data.len(),
                    max_size: MAX_STREAM_MESSAGE_SIZE,
                });
            }

            // RFC 7118: SIP messages are sent as text frames
            let message = if data.is_ascii() {
                // Safe to use lossy here since we checked is_ascii
                Message::Text(String::from_utf8_lossy(data).into_owned().into())
            } else {
                // Binary data (e.g., SDP with binary content)
                Message::Binary(data.to_vec().into())
            };

            // Only the writer half is locked; a parked `recv` holds the reader.
            let mut writer = self.writer.lock().await;
            writer.send(message).await.map_err(|e| {
                self.connected.store(false, Ordering::Relaxed);
                TransportError::SendFailed {
                    address: *dest,
                    reason: format!("WebSocket send failed: {e}"),
                }
            })?;
            drop(writer);

            debug!(
                size = data.len(),
                peer = %self.peer_addr,
                "Sent WebSocket message"
            );

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(TransportError::AlreadyClosed);
            }

            // Cancel-safe: tokio-tungstenite keeps partial frames in the
            // shared WebSocket state, so dropping this future loses no data.
            let mut reader = self.reader.lock().await;
            loop {
                let Some(next) = reader.next().await else {
                    self.connected.store(false, Ordering::Relaxed);
                    return Err(TransportError::ConnectionClosed);
                };
                let message = match next {
                    Ok(message) => message,
                    Err(e) => {
                        warn!(error = %e, "WebSocket receive error");
                        self.connected.store(false, Ordering::Relaxed);
                        return Err(TransportError::ReceiveFailed {
                            reason: format!("WebSocket error: {e}"),
                        });
                    }
                };
                let data = match message {
                    // Zero-copy: both payloads are already `Bytes`.
                    Message::Text(text) => Bytes::from(text),
                    Message::Binary(data) => data,
                    // RFC 6455 §5.5.2/§5.5.3: tungstenite queues the Pong and
                    // flushes it on the next poll; only count the frame here.
                    Message::Ping(_) | Message::Pong(_) => {
                        self.control_frames.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Message::Close(_) => {
                        self.connected.store(false, Ordering::Relaxed);
                        info!(peer = %self.peer_addr, "WebSocket connection closed");
                        return Err(TransportError::ConnectionClosed);
                    }
                    Message::Frame(_) => continue,
                };
                drop(reader);

                debug!(
                    size = data.len(),
                    peer = %self.peer_addr,
                    "Received WebSocket message"
                );

                return Ok(ReceivedMessage {
                    data,
                    source: self.peer_addr,
                    transport: if self.secure {
                        TransportType::WebSocketSecure
                    } else {
                        TransportType::WebSocket
                    },
                });
            }
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    fn client_addr(&self) -> Option<SbcSocketAddr> {
        self.client_addr
    }

    fn transport_type(&self) -> TransportType {
        if self.secure {
            TransportType::WebSocketSecure
        } else {
            TransportType::WebSocket
        }
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + '_>> {
        Box::pin(async move {
            // The flag is set before the Close frame is written, so a
            // concurrent `send` after this point fails with AlreadyClosed.
            if self.closed.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            self.connected.store(false, Ordering::Relaxed);
            // The lock wait and the write share one deadline: a send stalled
            // on a non-reading peer holds the writer, and so does our own
            // Close write. On timeout the frame is dropped; the socket is
            // released when the transport is dropped.
            // NIST 800-53 Rev5: SC-5, SC-10 (bounded Close write)
            let flushed = tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, async {
                let mut writer = self.writer.lock().await;
                writer.send(Message::Close(None)).await
            })
            .await;
            if flushed.is_err() {
                info!(peer = %self.peer_addr, "WebSocket Close write timed out");
            }
            info!(peer = %self.peer_addr, "Closed WebSocket connection");
            Ok(())
        })
    }

    // NIST 800-53 Rev5: SC-10 (the daemon reader observes a local close on
    // its next tick)
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    // POAM: POA&M-458: counted here but not yet charged to the per-source
    // limiter by the daemon reader.
    fn take_control_frames(&self) -> u64 {
        self.control_frames.swap(0, Ordering::Relaxed)
    }
}

impl StreamTransport for WebSocketTransport {
    fn peer_addr(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for WebSocketTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketTransport")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("client_addr", &self.client_addr)
            .field("reader", &"<mutex>")
            .field("writer", &"<mutex>")
            .field("secure", &self.secure)
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field(
                "control_frames",
                &self.control_frames.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// WebSocket listener for accepting incoming connections.
pub struct WebSocketListener {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// TCP listener.
    listener: tokio::net::TcpListener,
    /// WSS label only; no TLS (POA&M-459).
    secure: bool,
    /// Handshake options.
    options: WebSocketListenerOptions,
    /// Where the client address comes from behind a trusted proxy.
    client_address: ClientAddressMode,
    /// Peers whose forwarding information is believed; `None` trusts nobody.
    trusted: Option<TrustedProxyFn>,
}

impl WebSocketListener {
    /// Creates a new WebSocket listener.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to bind to
    /// * `secure` - WSS label only; no TLS (POA&M-459)
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    pub async fn bind(addr: &SbcSocketAddr, secure: bool) -> TransportResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr.to_string())
            .await
            .map_err(|e| TransportError::BindFailed {
                address: *addr,
                reason: e.to_string(),
            })?;

        info!(
            address = %addr,
            secure,
            "WebSocket listener bound"
        );

        Ok(Self {
            local_addr: *addr,
            listener,
            secure,
            options: WebSocketListenerOptions::default(),
            client_address: ClientAddressMode::Peer,
            trusted: None,
        })
    }

    /// Replaces the handshake options.
    #[must_use]
    pub const fn with_options(mut self, options: WebSocketListenerOptions) -> Self {
        self.options = options;
        self
    }

    /// Takes the client address from `mode` when the TCP peer satisfies
    /// `trusted` (the configured reverse proxies). Other peers keep their
    /// socket address and their forwarding headers are ignored.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3; RFC 7239 §8.1
    #[must_use]
    pub fn with_client_address(mut self, mode: ClientAddressMode, trusted: TrustedProxyFn) -> Self {
        // POAM: POA&M-456 - forwarding information is trusted exactly as far
        // as `trusted`: a listed proxy can claim any client address.
        self.client_address = mode;
        self.trusted = Some(trusted);
        self
    }

    /// Whether `ip` is one of the configured trusted proxies (false when
    /// none are configured).
    #[must_use]
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted
            .as_ref()
            .is_some_and(|trusted| trusted(ip.to_canonical()))
    }

    /// Whether the client address of a connection from `peer` is learnt
    /// during the handshake (a trusted proxy and a mode other than
    /// [`ClientAddressMode::Peer`]) rather than being the peer itself.
    #[must_use]
    pub fn learns_client_address(&self, peer: IpAddr) -> bool {
        self.client_address != ClientAddressMode::Peer && self.is_trusted_proxy(peer)
    }

    /// Accepts the raw TCP connection only (no HTTP upgrade). Pair with
    /// [`Self::complete_handshake`] inside a spawned task under a timeout,
    /// so one slow client cannot stall the accept loop (SC-5).
    ///
    /// # Errors
    ///
    /// Returns an error if accepting fails.
    pub async fn accept_tcp(&self) -> TransportResult<(TcpStream, SbcSocketAddr)> {
        let (tcp_stream, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| crate::accept_error(&e))?;
        // NIST 800-53 Rev5: SI-10; supports SC-7, AC-4 - IPv4-mapped peers reported as plain IPv4.
        Ok((
            tcp_stream,
            SbcSocketAddr::from(crate::canonical_peer(peer_addr)),
        ))
    }

    /// Completes the WebSocket upgrade on a stream from [`Self::accept_tcp`]
    /// with no per-client admission (see [`Self::complete_handshake_with`]).
    ///
    /// # Errors
    ///
    /// As [`Self::complete_handshake_with`].
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
    pub async fn complete_handshake(
        &self,
        tcp_stream: TcpStream,
        peer: SbcSocketAddr,
    ) -> TransportResult<WebSocketTransport> {
        self.complete_handshake_with(tcp_stream, peer, |_| Some(()))
            .await
            .map(|(transport, _)| transport)
    }

    /// Completes the WebSocket upgrade on a stream from [`Self::accept_tcp`],
    /// admitting the client as early as its address is known.
    ///
    /// The transport's peer address is always the socket peer: it stays the
    /// flow, registration and response-routing key, unique per connection.
    /// From a trusted proxy (see [`Self::learns_client_address`]) the client
    /// address is learnt and exposed as [`Transport::client_addr`]: the
    /// PROXY v2 source, or the forwarding-header IP with its port when
    /// `Forwarded` carries one (port 0 otherwise). `admit` is called with
    /// it before the upgrade completes: right after the PROXY v2 preamble
    /// (a refusal closes the socket before any HTTP is read), or inside the
    /// upgrade-request check for the header modes (a refusal answers 503 +
    /// `Retry-After`). Its value is returned with the transport. PROXY v2
    /// `LOCAL` (health checks) is admitted under the proxy address and has
    /// no client address. A missing or invalid client address refuses the
    /// connection; it never falls back to the proxy address. From any other
    /// peer `admit` is not called and `None` is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake fails or is refused;
    /// [`TransportError::ProxyHeaderMissing`] /
    /// [`TransportError::ProxyHeaderInvalid`] when a trusted proxy sent no
    /// or an unusable client address; [`TransportError::ClientRefused`] when
    /// `admit` refused the client.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
    pub async fn complete_handshake_with<A, F>(
        &self,
        mut tcp_stream: TcpStream,
        peer: SbcSocketAddr,
        admit: F,
    ) -> TransportResult<(WebSocketTransport, Option<A>)>
    where
        F: FnOnce(SbcSocketAddr) -> Option<A> + Send + Unpin,
        A: Send,
    {
        let trusted = match &self.trusted {
            Some(trusted) if self.learns_client_address(peer.ip()) => Arc::clone(trusted),
            _ => {
                let transport = WebSocketTransport::accept_with_options(
                    tcp_stream,
                    self.local_addr,
                    peer,
                    self.secure,
                    self.options,
                )
                .await?;
                return Ok((transport, None));
            }
        };
        let forwarded = match self.client_address {
            ClientAddressMode::ProxyV2 => {
                let client = Self::proxy_v2_client(&mut tcp_stream).await?;
                let Some(admitted) = admit(client.unwrap_or(peer)) else {
                    return Err(TransportError::ClientRefused {
                        reason: "PROXY v2 client over its limits".to_string(),
                    });
                };
                let transport = WebSocketTransport::accept_with_options(
                    tcp_stream,
                    self.local_addr,
                    peer,
                    self.secure,
                    self.options,
                )
                .await?
                .with_client_addr(client);
                return Ok((transport, Some(admitted)));
            }
            ClientAddressMode::Forwarded => true,
            ClientAddressMode::XForwardedFor | ClientAddressMode::Peer => false,
        };
        let outcome = Arc::new(std::sync::Mutex::new(None));
        let callback = ForwardedCheck {
            subprotocol: SubprotocolCheck {
                require_sip: self.options.require_sip_subprotocol,
            },
            forwarded,
            trusted,
            admit,
            outcome: Arc::clone(&outcome),
        };
        let result = accept_hdr_async_with_config(
            MaybeTlsStream::Plain(tcp_stream),
            callback,
            Some(sip_ws_config()),
        )
        .await;
        let decided = outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let (client, admitted) = match decided {
            Some(ProxyCheckOutcome::Admitted(client, admitted)) => (client, admitted),
            Some(ProxyCheckOutcome::Header(ForwardedError::Missing)) => {
                return Err(TransportError::ProxyHeaderMissing {
                    reason: ForwardedError::Missing.to_string(),
                });
            }
            Some(ProxyCheckOutcome::Header(e)) => {
                return Err(TransportError::ProxyHeaderInvalid {
                    reason: e.to_string(),
                });
            }
            Some(ProxyCheckOutcome::Refused) => {
                return Err(TransportError::ClientRefused {
                    reason: "client over its limits".to_string(),
                });
            }
            // The request never reached the check (bad HTTP) or failed the
            // subprotocol check.
            None => {
                return Err(match result {
                    Err(e) => TransportError::ConnectFailed {
                        address: peer,
                        reason: format!("WebSocket accept failed: {e}"),
                    },
                    Ok(_) => TransportError::ProxyHeaderMissing {
                        reason: ForwardedError::Missing.to_string(),
                    },
                });
            }
        };
        let stream = result.map_err(|e| TransportError::ConnectFailed {
            address: peer,
            reason: format!("WebSocket accept failed: {e}"),
        })?;
        info!(
            local = %self.local_addr,
            proxy = %peer,
            client = %client,
            "Accepted WebSocket connection from trusted proxy"
        );
        let transport = WebSocketTransport::new(stream, self.local_addr, peer, self.secure)
            .with_client_addr(Some(client));
        Ok((transport, Some(admitted)))
    }

    /// Reads the PROXY v2 preamble from a trusted proxy and returns the
    /// client address: the header source for `PROXY`, `None` for `LOCAL`
    /// (health checks, keyed on the proxy itself).
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
    async fn proxy_v2_client(tcp_stream: &mut TcpStream) -> TransportResult<Option<SbcSocketAddr>> {
        use crate::proxy_protocol::{Command, read_v2};
        let header = read_v2(tcp_stream).await?;
        match (header.command, header.source) {
            (Command::Local, _) => Ok(None),
            (Command::Proxy, Some(source)) => {
                Ok(Some(SbcSocketAddr::from(crate::canonical_peer(source))))
            }
            // AF_UNSPEC (or a family not implemented here) under PROXY names
            // no client: refuse rather than key the client on the proxy.
            (Command::Proxy, None) => Err(TransportError::ProxyHeaderInvalid {
                reason: "PROXY v2 header carries no client address".to_string(),
            }),
        }
    }

    /// Accepts the next WebSocket connection (TCP accept and handshake
    /// inline; prefer [`Self::accept_tcp`] + [`Self::complete_handshake`]).
    ///
    /// # Errors
    ///
    /// Returns an error if accepting fails.
    pub async fn accept(&self) -> TransportResult<WebSocketTransport> {
        let (tcp_stream, peer) = self.accept_tcp().await?;
        self.complete_handshake(tcp_stream, peer).await
    }

    /// Returns the local address.
    #[must_use]
    pub const fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    /// Returns the address the socket is actually bound to (resolves a
    /// port-0 bind).
    ///
    /// # Errors
    ///
    /// Returns an error if the socket address cannot be read.
    pub fn bound_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_websocket_state() {
        assert_eq!(WebSocketState::Open, WebSocketState::Open);
        assert_ne!(WebSocketState::Open, WebSocketState::Closed);
    }

    #[test]
    fn test_sip_subprotocol() {
        assert_eq!(SIP_SUBPROTOCOL, "sip");
    }

    #[test]
    fn ws_message_limit_fits_sip_stream_limit() {
        const _: () = assert!(MAX_WS_MESSAGE_SIZE <= MAX_STREAM_MESSAGE_SIZE);
    }

    #[test]
    fn offers_sip_matches_exact_token_only() {
        assert!(offers_sip(b"sip"));
        assert!(offers_sip(b"chat, sip"));
        assert!(offers_sip(b" sip ,x"));
        assert!(!offers_sip(b"sips"));
        assert!(!offers_sip(b"SIP"));
        assert!(!offers_sip(b""));
    }

    async fn listener(require: bool) -> Arc<WebSocketListener> {
        let addr = SbcSocketAddr::from("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap());
        let l = WebSocketListener::bind(&addr, false)
            .await
            .unwrap()
            .with_options(WebSocketListenerOptions {
                require_sip_subprotocol: require,
            });
        Arc::new(l)
    }

    fn local(l: &WebSocketListener) -> std::net::SocketAddr {
        l.bound_addr().unwrap()
    }

    /// Spawns one accept + handshake; returns its result.
    fn serve_one(
        l: &Arc<WebSocketListener>,
    ) -> tokio::task::JoinHandle<TransportResult<WebSocketTransport>> {
        let l = Arc::clone(l);
        tokio::spawn(async move {
            let (tcp, peer) = l.accept_tcp().await?;
            l.complete_handshake(tcp, peer).await
        })
    }

    fn request(addr: std::net::SocketAddr, protocol: Option<&str>) -> Request {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = format!("ws://{addr}/").into_client_request().unwrap();
        if let Some(p) = protocol {
            req.headers_mut()
                .insert("sec-websocket-protocol", HeaderValue::from_str(p).unwrap());
        }
        req
    }

    #[tokio::test]
    async fn ws_handshake_accepts_sip_subprotocol_and_echoes_it() {
        let l = listener(true).await;
        let server = serve_one(&l);
        let (_ws, resp) = tokio_tungstenite::connect_async(request(local(&l), Some("sip")))
            .await
            .unwrap();
        assert_eq!(resp.headers().get("sec-websocket-protocol").unwrap(), "sip");
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn ws_handshake_rejects_missing_subprotocol() {
        let l = listener(true).await;
        let server = serve_one(&l);
        let err = tokio_tungstenite::connect_async(request(local(&l), None))
            .await
            .unwrap_err();
        let status = match err {
            tokio_tungstenite::tungstenite::Error::Http(resp) => Some(resp.status()),
            _ => None,
        };
        assert_eq!(status, Some(StatusCode::BAD_REQUEST));
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn ws_handshake_rejects_non_sip_subprotocol_even_when_not_required() {
        let l = listener(false).await;
        let server = serve_one(&l);
        assert!(
            tokio_tungstenite::connect_async(request(local(&l), Some("chat")))
                .await
                .is_err()
        );
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn ws_handshake_allows_missing_when_not_required() {
        let l = listener(false).await;
        let server = serve_one(&l);
        let (_ws, resp) = tokio_tungstenite::connect_async(request(local(&l), None))
            .await
            .unwrap();
        assert!(resp.headers().get("sec-websocket-protocol").is_none());
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn ws_rejects_message_over_64k() {
        use futures_util::SinkExt;
        let l = listener(true).await;
        let server = serve_one(&l);
        let (mut ws, _) = tokio_tungstenite::connect_async(request(local(&l), Some("sip")))
            .await
            .unwrap();
        let transport = server.await.unwrap().unwrap();
        let big = vec![b'a'; MAX_WS_MESSAGE_SIZE + 1];
        let _ = ws.send(Message::Binary(big.into())).await;
        assert!(transport.recv().await.is_err());
    }

    #[tokio::test]
    async fn ws_accept_tcp_does_not_block_on_handshake() {
        let l = listener(true).await;
        let addr = local(&l);
        // A silent client: TCP connected, never sends the upgrade.
        let _silent = TcpStream::connect(addr).await.unwrap();
        let (silent_tcp, _) = l.accept_tcp().await.unwrap();
        let l2 = Arc::clone(&l);
        let stalled = tokio::spawn(async move {
            let peer = SbcSocketAddr::from(addr);
            l2.complete_handshake(silent_tcp, peer).await
        });
        // A second client still completes its handshake.
        let server = serve_one(&l);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio_tungstenite::connect_async(request(addr, Some("sip"))),
        )
        .await
        .unwrap();
        assert!(res.is_ok());
        assert!(server.await.unwrap().is_ok());
        stalled.abort();
    }

    // QA: a message exactly at the 64 KiB SIP limit is still delivered.
    #[tokio::test]
    async fn qa_ws_message_at_limit_is_delivered() {
        use futures_util::SinkExt;
        let l = listener(true).await;
        let server = serve_one(&l);
        let (mut ws, _) = tokio_tungstenite::connect_async(request(local(&l), Some("sip")))
            .await
            .unwrap();
        let transport = server.await.unwrap().unwrap();
        let exact = vec![b'a'; MAX_WS_MESSAGE_SIZE];
        ws.send(Message::Binary(exact.into())).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), transport.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.data.len(), MAX_WS_MESSAGE_SIZE);
    }

    // QA: frames each under the cap but reassembling past the 64 KiB
    // message cap are refused (message cap, not only frame cap).
    #[tokio::test]
    async fn qa_ws_fragmented_message_over_limit_rejected() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::protocol::frame::Frame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
        let l = listener(true).await;
        let server = serve_one(&l);
        let (mut ws, _) = tokio_tungstenite::connect_async(request(local(&l), Some("sip")))
            .await
            .unwrap();
        let transport = server.await.unwrap().unwrap();
        let half = vec![b'a'; MAX_WS_MESSAGE_SIZE / 2 + 1];
        let _ = ws
            .send(Message::Frame(Frame::message(
                half.clone(),
                OpCode::Data(Data::Binary),
                false,
            )))
            .await;
        let _ = ws
            .send(Message::Frame(Frame::message(
                half.clone(),
                OpCode::Data(Data::Continue),
                false,
            )))
            .await;
        let _ = ws
            .send(Message::Frame(Frame::message(
                half,
                OpCode::Data(Data::Continue),
                true,
            )))
            .await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), transport.recv())
            .await
            .unwrap();
        assert!(r.is_err());
    }

    // QA: `sip` offered among other tokens is selected and echoed alone.
    #[tokio::test]
    async fn qa_ws_handshake_selects_sip_from_offer_list() {
        let l = listener(true).await;
        let server = serve_one(&l);
        let (_ws, resp) = tokio_tungstenite::connect_async(request(local(&l), Some("chat, sip")))
            .await
            .unwrap();
        assert_eq!(resp.headers().get("sec-websocket-protocol").unwrap(), "sip");
        assert!(server.await.unwrap().is_ok());
    }

    // QA: with the requirement on, an offer of only other protocols is a 400.
    #[tokio::test]
    async fn qa_ws_handshake_rejects_other_subprotocol_when_required() {
        let l = listener(true).await;
        let server = serve_one(&l);
        let err = tokio_tungstenite::connect_async(request(local(&l), Some("sips, chat")))
            .await
            .unwrap_err();
        let status = match err {
            tokio_tungstenite::tungstenite::Error::Http(resp) => Some(resp.status()),
            _ => None,
        };
        assert_eq!(status, Some(StatusCode::BAD_REQUEST));
        assert!(server.await.unwrap().is_err());
    }

    // NIST 800-53 Rev5: SC-7, SI-10
    // An IPv4 client on a dual-stack `[::]` listener is reported with its
    // plain IPv4 address (not `::ffff:a.b.c.d`), both from `accept_tcp` and
    // on the upgraded transport.
    #[tokio::test]
    async fn ws_dual_stack_accept_tcp_reports_plain_ipv4_peer() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let bind = SbcSocketAddr::new_v6(Ipv6Addr::UNSPECIFIED, 0);
        let Ok(l) = WebSocketListener::bind(&bind, false).await else {
            crate::skip_dual_stack("cannot bind [::]:0 (no IPv6)");
            return;
        };
        let l = Arc::new(l.with_options(WebSocketListenerOptions {
            require_sip_subprotocol: false,
        }));
        let port = local(&l).port();
        let accept = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                let (tcp, peer) = l.accept_tcp().await?;
                let ws = l.complete_handshake(tcp, peer).await?;
                Ok::<_, TransportError>((peer, ws))
            })
        };
        let v4 = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let probe =
            tokio::time::timeout(std::time::Duration::from_secs(2), TcpStream::connect(v4)).await;
        let Ok(Ok(tcp)) = probe else {
            crate::skip_dual_stack("127.0.0.1 cannot reach a [::] listener (no dual-stack)");
            accept.abort();
            return;
        };
        let (_ws, _resp) = tokio_tungstenite::client_async(request(v4, Some("sip")), tcp)
            .await
            .unwrap();
        let (peer, server) = accept.await.unwrap().unwrap();
        assert!(
            peer.is_ipv4(),
            "accept_tcp peer must be plain IPv4, got {peer}"
        );
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let transport_peer = *server.peer_addr();
        assert!(
            transport_peer.is_ipv4(),
            "transport peer_addr must be plain IPv4, got {transport_peer}"
        );
    }

    type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

    /// Upgraded server-side transport and its `sip` client.
    async fn ws_pair() -> (Arc<WebSocketTransport>, Client) {
        let l = listener(true).await;
        let server = serve_one(&l);
        let (ws, _) = tokio_tungstenite::connect_async(request(local(&l), Some("sip")))
            .await
            .unwrap();
        (Arc::new(server.await.unwrap().unwrap()), ws)
    }

    fn spawn_recv(
        t: &Arc<WebSocketTransport>,
    ) -> tokio::task::JoinHandle<TransportResult<ReceivedMessage>> {
        let t = Arc::clone(t);
        tokio::spawn(async move { t.recv().await })
    }

    const fn ms(v: u64) -> std::time::Duration {
        std::time::Duration::from_millis(v)
    }

    // NIST 800-53 Rev5: SC-5
    // Sends from other tasks complete while a recv is pending, and the
    // pending recv still gets its data. Twin of
    // `test_tcp_send_not_blocked_by_pending_recv`.
    #[tokio::test]
    async fn ws_send_not_blocked_by_pending_recv() {
        use futures_util::{SinkExt, StreamExt};
        let (server, mut client) = ws_pair().await;
        let dest = *server.peer_addr();
        let reader = spawn_recv(&server);
        tokio::time::sleep(ms(50)).await;
        assert!(!reader.is_finished(), "recv is pending");
        let mut senders = Vec::new();
        for i in 0..4u8 {
            let s = Arc::clone(&server);
            senders.push(tokio::spawn(async move {
                tokio::time::timeout(ms(500), s.send(&[b'A' + i], &dest)).await
            }));
        }
        for s in senders {
            s.await
                .unwrap()
                .expect("send must not wait on the pending recv")
                .unwrap();
        }
        let mut got = Vec::new();
        while got.len() < 4 {
            let m = tokio::time::timeout(ms(1000), client.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            got.extend_from_slice(&m.into_data());
        }
        got.sort_unstable();
        assert_eq!(got, b"ABCD");
        client.send(Message::text("200")).await.unwrap();
        let r = tokio::time::timeout(ms(1000), reader)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&r.data[..], b"200");
    }

    // NIST 800-53 Rev5: SC-5, SC-10
    // close() does not wait on a pending recv, marks the transport closed,
    // and the peer sees a Close frame.
    #[tokio::test]
    async fn ws_close_not_blocked_by_pending_recv() {
        use futures_util::StreamExt;
        let (server, mut client) = ws_pair().await;
        let _reader = spawn_recv(&server);
        tokio::time::sleep(ms(50)).await;
        tokio::time::timeout(ms(500), server.close())
            .await
            .expect("close must not wait on the pending recv")
            .unwrap();
        assert!(server.is_closed(), "is_closed after close()");
        let m = tokio::time::timeout(ms(1000), client.next())
            .await
            .expect("peer sees a frame")
            .unwrap()
            .unwrap();
        assert!(matches!(m, Message::Close(_)), "got {m:?}");
    }

    // RFC 6455 §5.5.2, §5.5.3: one Pong per Ping.
    #[tokio::test]
    async fn ws_ping_gets_exactly_one_pong() {
        use futures_util::{SinkExt, StreamExt};
        let (server, mut client) = ws_pair().await;
        let _reader = spawn_recv(&server);
        client
            .send(Message::Ping(b"x".to_vec().into()))
            .await
            .unwrap();
        let first = tokio::time::timeout(ms(300), client.next())
            .await
            .expect("pong within 300 ms")
            .unwrap()
            .unwrap();
        assert_eq!(first, Message::Pong(b"x".to_vec().into()));
        let second = tokio::time::timeout(ms(200), client.next()).await;
        assert!(second.is_err(), "second frame: {second:?}");
    }

    // A message split into fragments arriving across several cancelled
    // recv calls is delivered once and intact.
    #[tokio::test]
    async fn ws_recv_cancel_safe_across_ticks() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::protocol::frame::Frame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
        let (server, mut client) = ws_pair().await;
        let body: Vec<u8> = (0..60 * 1024u32).map(|i| b'a' + (i % 26) as u8).collect();
        let parts: Vec<Vec<u8>> = body.chunks(body.len() / 4).map(<[u8]>::to_vec).collect();
        assert_eq!(parts.len(), 4);
        let sender = tokio::spawn(async move {
            for (i, p) in parts.into_iter().enumerate() {
                let op = if i == 0 {
                    OpCode::Data(Data::Text)
                } else {
                    OpCode::Data(Data::Continue)
                };
                client
                    .send(Message::Frame(Frame::message(p, op, i == 3)))
                    .await
                    .unwrap();
                tokio::time::sleep(ms(30)).await;
            }
            client
        });
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + ms(1500);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(ms(20), server.recv()).await {
                Err(_) => {}
                Ok(r) => got.push(r.unwrap().data),
            }
        }
        let _client = sender.await.unwrap();
        assert_eq!(got.len(), 1, "messages delivered: {}", got.len());
        assert_eq!(&got[0][..], &body[..]);
    }

    // NIST 800-53 Rev5: SC-10
    // A peer close ends a pending recv with ConnectionClosed.
    #[tokio::test]
    async fn ws_pending_recv_ends_on_peer_close() {
        let (server, mut client) = ws_pair().await;
        let reader = spawn_recv(&server);
        tokio::time::sleep(ms(50)).await;
        client.close(None).await.unwrap();
        let r = tokio::time::timeout(ms(1000), reader)
            .await
            .expect("pending recv ends within 1 s")
            .unwrap();
        assert!(
            matches!(r, Err(TransportError::ConnectionClosed)),
            "got {r:?}"
        );
    }

    // NIST 800-53 Rev5: SC-10
    // is_closed reports a local close (the daemon reader polls it).
    #[tokio::test]
    async fn ws_is_closed_after_close() {
        let (server, _client) = ws_pair().await;
        assert!(!server.is_closed());
        tokio::time::timeout(ms(500), server.close())
            .await
            .unwrap()
            .unwrap();
        assert!(server.is_closed(), "is_closed after close()");
    }

    // A send after close() fails.
    #[tokio::test]
    async fn ws_send_after_close_fails() {
        let (server, _client) = ws_pair().await;
        let dest = *server.peer_addr();
        tokio::time::timeout(ms(500), server.close())
            .await
            .unwrap()
            .unwrap();
        let r = tokio::time::timeout(ms(500), server.send(b"x", &dest))
            .await
            .unwrap();
        assert!(matches!(r, Err(TransportError::AlreadyClosed)), "got {r:?}");
        let p = tokio::time::timeout(ms(500), server.ping(b"x"))
            .await
            .unwrap();
        assert!(matches!(p, Err(TransportError::AlreadyClosed)), "got {p:?}");
        let rx = tokio::time::timeout(ms(500), server.recv()).await.unwrap();
        assert!(
            matches!(rx, Err(TransportError::AlreadyClosed)),
            "got {rx:?}"
        );
    }

    // NIST 800-53 Rev5: SC-5, SC-10
    // close() returns within the Close-write bound when the peer never reads
    // and the server's send path is already full.
    #[tokio::test]
    async fn ws_close_bounded_when_peer_never_reads() {
        let (server, _client) = ws_pair().await;
        let dest = *server.peer_addr();
        let chunk = vec![b'a'; 60 * 1024];
        let mut stalled = false;
        for _ in 0..10_000 {
            if tokio::time::timeout(ms(200), server.send(&chunk, &dest))
                .await
                .is_err()
            {
                stalled = true;
                break;
            }
        }
        assert!(stalled, "send path never filled");
        tokio::time::timeout(ms(2000), server.close())
            .await
            .expect("close must return within the Close-write bound")
            .unwrap();
        assert!(server.is_closed());
    }

    // NIST 800-53 Rev5: SC-5, SC-10
    // close() returns within the Close-write bound while a spawned send,
    // stalled on a full send path, still holds the writer lock.
    #[tokio::test]
    async fn ws_close_bounded_while_send_holds_writer() {
        let (server, _client) = ws_pair().await;
        let dest = *server.peer_addr();
        let chunk = vec![b'a'; 60 * 1024];
        let mut stalled = None;
        for _ in 0..10_000 {
            let s = Arc::clone(&server);
            let c = chunk.clone();
            let h = tokio::spawn(async move { s.send(&c, &dest).await });
            tokio::time::sleep(ms(20)).await;
            if !h.is_finished() {
                stalled = Some(h);
                break;
            }
            h.await.unwrap().unwrap();
        }
        let pending = stalled.expect("send path never filled");
        tokio::time::sleep(ms(200)).await;
        assert!(!pending.is_finished(), "send still pending on the writer");
        tokio::time::timeout(ms(2000), server.close())
            .await
            .expect("close must return while a send holds the writer")
            .unwrap();
        assert!(server.is_closed());
        pending.abort();
    }

    // ---- SR-57: WebSocket buffers sized for many connections ----
    // NIST 800-53 Rev5: SC-5, SC-6

    /// Largest WebSocket frame header (RFC 6455 §5.2: 2 + 8 length + 4 mask).
    const QA_MAX_WS_FRAME_HEADER: usize = 14;

    #[test]
    fn ws_config_read_buffer_is_small() {
        let cfg = sip_ws_config();
        assert!(
            cfg.read_buffer_size <= 8 * 1024,
            "tungstenite read_buffer_size is {} bytes, want <= 8 KiB",
            cfg.read_buffer_size
        );
        assert!(
            cfg.max_write_buffer_size <= 2 * MAX_WS_MESSAGE_SIZE,
            "tungstenite max_write_buffer_size is {}, want <= {}",
            cfg.max_write_buffer_size,
            2 * MAX_WS_MESSAGE_SIZE
        );
        // tungstenite panics at accept unless max_write_buffer_size >
        // write_buffer_size, and one full message must fit past the
        // write threshold or a max-size send fails with WriteBufferFull.
        assert!(
            cfg.write_buffer_size + MAX_WS_MESSAGE_SIZE + QA_MAX_WS_FRAME_HEADER
                <= cfg.max_write_buffer_size,
            "write_buffer_size {} + one message does not fit max_write_buffer_size {}",
            cfg.write_buffer_size,
            cfg.max_write_buffer_size
        );
        // The message and frame caps are unchanged.
        assert_eq!(cfg.max_message_size, Some(MAX_WS_MESSAGE_SIZE));
        assert_eq!(cfg.max_frame_size, Some(MAX_WS_MESSAGE_SIZE));
    }

    // Regression guard: with the bounded write buffer the server still sends
    // back-to-back messages at the 64 KiB limit.
    #[tokio::test]
    async fn ws_server_sends_messages_at_limit() {
        use futures_util::StreamExt;
        let l = listener(true).await;
        let server = serve_one(&l);
        let (mut ws, _) = tokio_tungstenite::connect_async(request(local(&l), Some("sip")))
            .await
            .unwrap();
        let transport = server.await.unwrap().unwrap();
        let dest = *transport.peer_addr();
        let exact = vec![b'a'; MAX_WS_MESSAGE_SIZE];
        for _ in 0..3 {
            transport.send(&exact, &dest).await.unwrap();
        }
        for _ in 0..3 {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                .await
                .expect("client recv timed out")
                .expect("stream ended")
                .unwrap();
            assert_eq!(msg.into_data().len(), MAX_WS_MESSAGE_SIZE);
        }
    }
}
