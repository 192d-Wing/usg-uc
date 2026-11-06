//! WebSocket transport for SIP-over-WebSocket (RFC 7118).
//!
//! This module provides WebSocket transport for SIP messages, enabling
//! browser-based WebRTC clients to communicate with the SBC.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity (WSS encryption)
//! - **SC-23**: Session Authenticity (TLS client verification)
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
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
        let (tcp_stream, peer_addr) =
            self.listener
                .accept()
                .await
                .map_err(|e| TransportError::Io {
                    reason: format!("Accept failed: {e}"),
                })?;
        Ok((tcp_stream, SbcSocketAddr::from(peer_addr)))
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
}
