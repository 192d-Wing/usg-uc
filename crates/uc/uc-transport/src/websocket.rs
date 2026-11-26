//! WebSocket transport for SIP-over-WebSocket (RFC 7118).
//!
//! This module provides WebSocket transport for SIP messages, enabling
//! browser-based WebRTC clients to communicate with the SBC.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-5**: Denial-of-Service Protection (bounded frames; send and close
//!   do not wait on a pending receive)
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
use std::pin::Pin;
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
        })
    }

    /// Replaces the handshake options.
    #[must_use]
    pub const fn with_options(mut self, options: WebSocketListenerOptions) -> Self {
        self.options = options;
        self
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
    /// # Errors
    ///
    /// Returns an error if the handshake fails or is refused.
    pub async fn complete_handshake(
        &self,
        tcp_stream: TcpStream,
        peer: SbcSocketAddr,
    ) -> TransportResult<WebSocketTransport> {
        WebSocketTransport::accept_with_options(
            tcp_stream,
            self.local_addr,
            peer,
            self.secure,
            self.options,
        )
        .await
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
