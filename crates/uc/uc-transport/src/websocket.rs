//! WebSocket transport for SIP-over-WebSocket (RFC 7118).
//!
//! This module provides WebSocket transport for SIP messages, enabling
//! browser-based WebRTC clients to communicate with the SBC.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity (WSS encryption)
//! - **SC-23**: Session Authenticity (TLS client verification)
//! - **SC-5, SC-7, AU-3**: behind a configured trusted reverse proxy the
//!   client address comes from PROXY v2, `X-Forwarded-For` or `Forwarded`
//!   (RFC 7239), so per-source limits, flows and audit name the client
//!   ([`ClientAddressMode`], [`WebSocketListener::with_client_address`])
//!
//! ## RFC 7118 Compliance
//!
//! - SIP subprotocol negotiation ("sip")
//! - UTF-8 text frames for SIP messages
//! - Binary frames support for SDP bodies
//! - Ping/pong keepalive handling

use crate::error::{TransportError, TransportResult};
use crate::{MAX_STREAM_MESSAGE_SIZE, ReceivedMessage, StreamTransport, Transport};
use bytes::Bytes;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
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

/// SIP WebSocket subprotocol per RFC 7118.
pub const SIP_SUBPROTOCOL: &str = "sip";

/// Maximum WebSocket message and frame size. One WS message carries one SIP
/// message (RFC 7118 §5), so the SIP stream limit applies. tungstenite would
/// otherwise accept 64 MiB messages and 16 MiB frames.
///
/// ## NIST 800-53 Rev5: SC-5, SI-10; RFC 6455 §10.4
pub const MAX_WS_MESSAGE_SIZE: usize = MAX_STREAM_MESSAGE_SIZE;

/// WebSocket protocol limits for SIP-over-WebSocket.
fn sip_ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE))
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
    /// A PROXY protocol v2 preamble precedes the HTTP upgrade (L4 proxies).
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
/// supplied by the client and are never parsed. If every hop is trusted the
/// leftmost is used. The port, if any, is dropped.
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

/// Parses one `Forwarded` field line (RFC 7239 §4) into its elements' `for`
/// values (raw `node` bytes, quotes removed; `None` for an element without
/// `for`). Strict: any syntax error refuses the whole line.
fn parse_forwarded_line<'a>(
    line: &'a [u8],
    out: &mut Vec<Option<&'a [u8]>>,
) -> Result<(), ForwardedError> {
    let mut i = 0;
    loop {
        let mut for_value: Option<&'a [u8]> = None;
        loop {
            i = skip_ows(line, i);
            let name_start = i;
            while line.get(i).copied().is_some_and(is_tchar) {
                i += 1;
            }
            let name = line.get(name_start..i).unwrap_or_default();
            if name.is_empty() || line.get(i) != Some(&b'=') {
                return Err(ForwardedError::Malformed);
            }
            let (value, next) = forwarded_value(line, i + 1)?;
            i = next;
            // RFC 7239 §4: a parameter MUST NOT occur twice in one element.
            if name.eq_ignore_ascii_case(b"for") {
                if for_value.is_some() {
                    return Err(ForwardedError::Malformed);
                }
                for_value = Some(value);
            }
            i = skip_ows(line, i);
            if line.get(i) == Some(&b';') {
                i += 1;
            } else {
                break;
            }
        }
        if out.len() >= MAX_FORWARDED_HOPS {
            return Err(ForwardedError::Malformed);
        }
        out.push(for_value);
        match line.get(i) {
            None => return Ok(()),
            Some(b',') => i += 1,
            Some(_) => return Err(ForwardedError::Malformed),
        }
    }
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
/// Parameter names are case-insensitive and values may be quoted-strings,
/// so `,` and `;` inside quotes do not split. The header is parsed strictly
/// as a whole; then the `for=` hops are walked right to left, skipping hops
/// `is_trusted` accepts, and the first untrusted hop is the client (all
/// trusted: the leftmost). A quoted `"[v6]:port"` or `"v4:port"` keeps its
/// port; an obfuscated port gives `None`.
///
/// # Errors
///
/// [`ForwardedError::Missing`] when there is no non-empty line,
/// [`ForwardedError::Obfuscated`] when the deciding hop is `unknown` or an
/// obfuscated identifier, [`ForwardedError::Malformed`] for any syntax error,
/// an element without `for=` on the walked path, or too many elements.
///
/// ## NIST 800-53 Rev5: SC-7, SI-10; RFC 7239 §4, §5.2, §6, §8.1
pub fn client_from_forwarded(
    values: &[&[u8]],
    is_trusted: impl Fn(IpAddr) -> bool,
) -> Result<ForwardedClient, ForwardedError> {
    let mut elements = Vec::new();
    for line in values {
        if line.trim_ascii().is_empty() {
            continue;
        }
        parse_forwarded_line(line, &mut elements)?;
    }
    let mut leftmost = None;
    for value in elements.iter().rev() {
        let client = parse_forwarded_node(value.ok_or(ForwardedError::Malformed)?)?;
        if !is_trusted(client.ip) {
            return Ok(client);
        }
        leftmost = Some(client);
    }
    leftmost.ok_or(ForwardedError::Missing)
}

/// Upgrade-request check for a trusted proxy: takes the client address from
/// the configured forwarding header, refusing the upgrade with 400 when it
/// is missing or unusable (never a fallback to the proxy address), then
/// applies the subprotocol check. The outcome is left in `outcome` for the
/// listener.
///
/// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
struct ForwardedCheck {
    subprotocol: SubprotocolCheck,
    forwarded: bool,
    trusted: TrustedProxyFn,
    outcome: Arc<OnceLock<Result<ForwardedClient, ForwardedError>>>,
}

impl Callback for ForwardedCheck {
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
        let outcome = if self.forwarded {
            client_from_forwarded(&lines, trusted)
        } else {
            client_from_x_forwarded_for(&lines, trusted)
        };
        let _ = self.outcome.set(outcome);
        if outcome.is_err() {
            return Err(reject_upgrade("a valid client address header is required"));
        }
        self.subprotocol.on_request(req, resp)
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
/// Implements RFC 7118 SIP-over-WebSocket with support for both
/// secure (WSS) and insecure (WS) connections.
pub struct WebSocketTransport {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// Remote peer address.
    peer_addr: SbcSocketAddr,
    /// WebSocket stream (wrapped in mutex for interior mutability).
    stream: Arc<Mutex<Option<WebSocketStream<MaybeTlsStream<TcpStream>>>>>,
    /// Connection state.
    connected: AtomicBool,
    /// Whether this is a secure connection (WSS).
    secure: bool,
}

impl WebSocketTransport {
    /// Creates a new WebSocket transport from an accepted connection.
    ///
    /// # Arguments
    ///
    /// * `stream` - The WebSocket stream from an accepted connection
    /// * `local_addr` - Local address
    /// * `peer_addr` - Remote peer address
    /// * `secure` - Whether this is a WSS connection
    pub fn new(
        stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
        secure: bool,
    ) -> Self {
        Self {
            local_addr,
            peer_addr,
            stream: Arc::new(Mutex::new(Some(stream))),
            connected: AtomicBool::new(true),
            secure,
        }
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

        // Extract peer address from URL (simplified)
        let peer_addr = local_addr; // Placeholder - should parse from URL

        Ok(Self {
            local_addr,
            peer_addr,
            stream: Arc::new(Mutex::new(Some(stream))),
            connected: AtomicBool::new(true),
            secure,
        })
    }

    /// Accepts a WebSocket connection from a TCP stream.
    ///
    /// # Arguments
    ///
    /// * `tcp_stream` - TCP stream to upgrade
    /// * `local_addr` - Local address
    /// * `peer_addr` - Remote peer address
    /// * `secure` - Whether this is a WSS connection
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

    /// Returns true if this is a secure (WSS) connection.
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
        use futures_util::SinkExt;

        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.as_mut() {
            stream
                .send(Message::Ping(payload.to_vec().into()))
                .await
                .map_err(|e| TransportError::Io {
                    reason: format!("Ping failed: {e}"),
                })?;
            debug!("Sent WebSocket ping");
        }
        drop(guard);
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
            use futures_util::SinkExt;

            if !self.connected.load(Ordering::Relaxed) {
                return Err(TransportError::NotConnected);
            }

            if data.len() > MAX_STREAM_MESSAGE_SIZE {
                return Err(TransportError::MessageTooLarge {
                    size: data.len(),
                    max_size: MAX_STREAM_MESSAGE_SIZE,
                });
            }

            let mut guard = self.stream.lock().await;
            if let Some(stream) = guard.as_mut() {
                // RFC 7118: SIP messages are sent as text frames
                let message = if data.is_ascii() {
                    // Safe to use lossy here since we checked is_ascii
                    Message::Text(String::from_utf8_lossy(data).into_owned().into())
                } else {
                    // Binary data (e.g., SDP with binary content)
                    Message::Binary(data.to_vec().into())
                };

                stream.send(message).await.map_err(|e| {
                    self.connected.store(false, Ordering::Relaxed);
                    TransportError::SendFailed {
                        address: *dest,
                        reason: format!("WebSocket send failed: {e}"),
                    }
                })?;

                debug!(
                    size = data.len(),
                    peer = %self.peer_addr,
                    "Sent WebSocket message"
                );
            }
            drop(guard);

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            use futures_util::StreamExt;

            let mut guard = self.stream.lock().await;
            if let Some(stream) = guard.as_mut() {
                loop {
                    match stream.next().await {
                        Some(Ok(message)) => {
                            let data = match message {
                                Message::Text(text) => Bytes::from(text.as_bytes().to_vec()),
                                Message::Binary(data) => Bytes::from(data.to_vec()),
                                Message::Ping(payload) => {
                                    // Respond with pong
                                    use futures_util::SinkExt;
                                    let _ = stream.send(Message::Pong(payload)).await;
                                    continue;
                                }
                                Message::Pong(_) => {
                                    debug!("Received WebSocket pong");
                                    continue;
                                }
                                Message::Close(_) => {
                                    self.connected.store(false, Ordering::Relaxed);
                                    info!(peer = %self.peer_addr, "WebSocket connection closed");
                                    return Err(TransportError::ConnectionClosed);
                                }
                                Message::Frame(_) => continue,
                            };

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
                        Some(Err(e)) => {
                            warn!(error = %e, "WebSocket receive error");
                            self.connected.store(false, Ordering::Relaxed);
                            return Err(TransportError::ReceiveFailed {
                                reason: format!("WebSocket error: {e}"),
                            });
                        }
                        None => {
                            self.connected.store(false, Ordering::Relaxed);
                            return Err(TransportError::ConnectionClosed);
                        }
                    }
                }
            }
            drop(guard);

            Err(TransportError::NotConnected)
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
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
            use futures_util::SinkExt;

            let mut guard = self.stream.lock().await;
            if let Some(stream) = guard.as_mut() {
                let _ = stream.send(Message::Close(None)).await;
                self.connected.store(false, Ordering::Relaxed);
                info!(peer = %self.peer_addr, "Closed WebSocket connection");
            }
            drop(guard);
            Ok(())
        })
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
            .field("stream", &"<WebSocketStream>")
            .field("secure", &self.secure)
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .finish()
    }
}

/// WebSocket listener for accepting incoming connections.
pub struct WebSocketListener {
    /// Local address.
    local_addr: SbcSocketAddr,
    /// TCP listener.
    listener: tokio::net::TcpListener,
    /// Whether to use TLS (WSS).
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
    /// * `secure` - Whether to use WSS (TLS)
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

    /// Completes the WebSocket upgrade on a stream from [`Self::accept_tcp`].
    ///
    /// From a trusted proxy (see [`Self::learns_client_address`]) the
    /// transport's peer address is the client: the PROXY v2 source, or the
    /// forwarding-header IP with its port when `Forwarded` carries one and
    /// the proxy-side TCP source port otherwise (keeps flow keys unique). A
    /// missing or invalid client address refuses the connection; it never
    /// falls back to the proxy address. PROXY v2 `LOCAL` (health checks)
    /// keeps the proxy address.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake fails or is refused;
    /// [`TransportError::ProxyHeaderMissing`] /
    /// [`TransportError::ProxyHeaderInvalid`] when a trusted proxy sent no
    /// or an unusable client address.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
    pub async fn complete_handshake(
        &self,
        mut tcp_stream: TcpStream,
        peer: SbcSocketAddr,
    ) -> TransportResult<WebSocketTransport> {
        let trusted = match &self.trusted {
            Some(trusted) if self.learns_client_address(peer.ip()) => Arc::clone(trusted),
            _ => {
                return WebSocketTransport::accept_with_options(
                    tcp_stream,
                    self.local_addr,
                    peer,
                    self.secure,
                    self.options,
                )
                .await;
            }
        };
        let forwarded = match self.client_address {
            ClientAddressMode::ProxyV2 => {
                let client = Self::proxy_v2_client(&mut tcp_stream, peer).await?;
                return WebSocketTransport::accept_with_options(
                    tcp_stream,
                    self.local_addr,
                    client,
                    self.secure,
                    self.options,
                )
                .await;
            }
            ClientAddressMode::Forwarded => true,
            ClientAddressMode::XForwardedFor | ClientAddressMode::Peer => false,
        };
        let outcome = Arc::new(OnceLock::new());
        let callback = ForwardedCheck {
            subprotocol: SubprotocolCheck {
                require_sip: self.options.require_sip_subprotocol,
            },
            forwarded,
            trusted,
            outcome: Arc::clone(&outcome),
        };
        let result = accept_hdr_async_with_config(
            MaybeTlsStream::Plain(tcp_stream),
            callback,
            Some(sip_ws_config()),
        )
        .await;
        let client = match outcome.get().copied() {
            Some(Ok(client)) => Some(client),
            Some(Err(ForwardedError::Missing)) => {
                return Err(TransportError::ProxyHeaderMissing {
                    reason: ForwardedError::Missing.to_string(),
                });
            }
            Some(Err(e)) => {
                return Err(TransportError::ProxyHeaderInvalid {
                    reason: e.to_string(),
                });
            }
            None => None,
        };
        let stream = result.map_err(|e| TransportError::ConnectFailed {
            address: peer,
            reason: format!("WebSocket accept failed: {e}"),
        })?;
        // The callback ran (the upgrade succeeded), so `client` is set.
        let client = client.ok_or_else(|| TransportError::ProxyHeaderMissing {
            reason: ForwardedError::Missing.to_string(),
        })?;
        let client = SbcSocketAddr::from(SocketAddr::new(
            client.ip,
            client.port.unwrap_or_else(|| peer.port()),
        ));
        info!(
            local = %self.local_addr,
            proxy = %peer,
            client = %client,
            "Accepted WebSocket connection from trusted proxy"
        );
        Ok(WebSocketTransport::new(
            stream,
            self.local_addr,
            client,
            self.secure,
        ))
    }

    /// Reads the PROXY v2 preamble from a trusted proxy and returns the
    /// client address: the header source for `PROXY`, the proxy itself for
    /// `LOCAL` (health checks).
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7, AU-3
    async fn proxy_v2_client(
        tcp_stream: &mut TcpStream,
        peer: SbcSocketAddr,
    ) -> TransportResult<SbcSocketAddr> {
        use crate::proxy_protocol::{Command, read_v2};
        let header = read_v2(tcp_stream).await?;
        match (header.command, header.source) {
            (Command::Local, _) => Ok(peer),
            (Command::Proxy, Some(source)) => {
                Ok(SbcSocketAddr::from(crate::canonical_peer(source)))
            }
            // AF_UNSPEC under PROXY names no client: refuse rather than key
            // the client on the proxy address.
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
}
