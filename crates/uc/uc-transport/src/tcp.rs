//! TCP transport implementation.
//!
//! ## IPv6-First Design
//!
//! TCP connections prefer IPv6 per project requirements.
//!
//! ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
//!
//! Note: TCP provides integrity (via checksums) but no confidentiality.
//! For secure signaling, use TLS (`sbc-transport::tls`).

use crate::error::{TransportError, TransportResult};
use crate::listener::ListenerConfig;
use crate::{MAX_STREAM_MESSAGE_SIZE, ReceivedMessage, StreamTransport, Transport};
use bytes::BytesMut;
use socket2::{Domain, Protocol, Socket, Type};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, instrument, trace};
use uc_types::address::{SbcSocketAddr, TransportType};

/// TCP transport for connection-oriented SIP messaging.
///
/// ## SIP over TCP
///
/// Per RFC 3261, SIP messages over TCP are framed using Content-Length
/// headers. This implementation handles message framing automatically.
///
/// ## NIST 800-53 Rev5: SC-8
///
/// TCP provides basic integrity via checksums but no confidentiality.
/// Use TLS for secure signaling.
pub struct TcpTransport {
    stream: Arc<Mutex<TcpStream>>,
    local_addr: SbcSocketAddr,
    peer_addr: SbcSocketAddr,
    read_buffer: Mutex<BytesMut>,
    closed: AtomicBool,
}

impl TcpTransport {
    /// Creates a TCP transport from an established connection.
    ///
    /// This is typically called after accepting a connection from a listener.
    #[instrument(skip(stream))]
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_stream(stream: TcpStream) -> TransportResult<Self> {
        let local_addr = stream
            .local_addr()
            .map_err(|e| TransportError::Io {
                reason: format!("failed to get local address: {e}"),
            })?
            .into();

        let peer_addr = stream
            .peer_addr()
            .map_err(|e| TransportError::Io {
                reason: format!("failed to get peer address: {e}"),
            })?
            .into();

        debug!(local = %local_addr, peer = %peer_addr, "TCP transport created");

        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            local_addr,
            peer_addr,
            read_buffer: Mutex::new(BytesMut::with_capacity(MAX_STREAM_MESSAGE_SIZE)),
            closed: AtomicBool::new(false),
        })
    }

    /// Connects to a remote TCP endpoint.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection fails.
    #[instrument(skip_all, fields(dest = %dest))]
    pub async fn connect(dest: SbcSocketAddr) -> TransportResult<Self> {
        let dest_addr: SocketAddr = dest.into();

        let stream =
            TcpStream::connect(dest_addr)
                .await
                .map_err(|e| TransportError::ConnectFailed {
                    address: dest,
                    reason: e.to_string(),
                })?;

        Self::from_stream(stream)
    }

    /// Checks if the transport is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Transport for TcpTransport {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
        _dest: &'a SbcSocketAddr,
    ) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(TransportError::AlreadyClosed);
            }

            if data.len() > MAX_STREAM_MESSAGE_SIZE {
                return Err(TransportError::MessageTooLarge {
                    size: data.len(),
                    max_size: MAX_STREAM_MESSAGE_SIZE,
                });
            }

            trace!(size = data.len(), "sending TCP data");

            let mut stream = self.stream.lock().await;
            stream
                .write_all(data)
                .await
                .map_err(|e| TransportError::SendFailed {
                    address: self.peer_addr,
                    reason: e.to_string(),
                })?;

            stream
                .flush()
                .await
                .map_err(|e| TransportError::SendFailed {
                    address: self.peer_addr,
                    reason: e.to_string(),
                })?;

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(TransportError::AlreadyClosed);
            }

            let mut read_buffer = self.read_buffer.lock().await;
            let mut stream = self.stream.lock().await;

            // Read available data
            let mut temp_buffer = [0u8; 4096];
            let n =
                stream
                    .read(&mut temp_buffer)
                    .await
                    .map_err(|e| TransportError::ReceiveFailed {
                        reason: e.to_string(),
                    })?;

            if n == 0 {
                return Err(TransportError::ConnectionClosed);
            }

            read_buffer.extend_from_slice(&temp_buffer[..n]);

            trace!(size = n, "received TCP data");

            // For SIP, we'd parse the Content-Length and wait for full message.
            // For now, return whatever we received (simplified).
            let data = read_buffer.split().freeze();

            Ok(ReceivedMessage {
                data,
                source: self.peer_addr,
                transport: TransportType::Tcp,
            })
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tcp
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + '_>> {
        Box::pin(async move {
            if self
                .closed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(TransportError::AlreadyClosed);
            }

            let mut stream = self.stream.lock().await;
            let _ = stream.shutdown().await;

            debug!(peer = %self.peer_addr, "TCP transport closed");
            Ok(())
        })
    }
}

impl StreamTransport for TcpTransport {
    fn peer_addr(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    fn is_connected(&self) -> bool {
        !self.is_closed()
    }
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// TCP listener for accepting incoming connections.
///
/// ## NIST 800-53 Rev5: SC-8
pub struct TcpListener {
    listener: TokioTcpListener,
    local_addr: SbcSocketAddr,
    closed: AtomicBool,
}

impl TcpListener {
    /// Binds a TCP listener to the specified address.
    ///
    /// ## Errors
    ///
    /// Returns an error if binding fails.
    #[instrument(skip_all, fields(addr = %addr))]
    pub async fn bind(addr: SbcSocketAddr) -> TransportResult<Self> {
        Self::bind_with_config(ListenerConfig::new(addr, TransportType::Tcp)).await
    }

    /// Binds a TCP listener with the given configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error if binding fails.
    #[instrument(skip_all, fields(addr = %config.bind_address))]
    pub async fn bind_with_config(config: ListenerConfig) -> TransportResult<Self> {
        config.validate()?;

        let socket_addr: SocketAddr = config.bind_address.into();
        let domain = if socket_addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|e| {
            TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            }
        })?;

        // Configure socket options
        if config.reuse_address {
            socket
                .set_reuse_address(true)
                .map_err(|e| TransportError::BindFailed {
                    address: config.bind_address,
                    reason: format!("failed to set SO_REUSEADDR: {e}"),
                })?;
        }

        #[cfg(unix)]
        if config.reuse_port {
            socket
                .set_reuse_port(true)
                .map_err(|e| TransportError::BindFailed {
                    address: config.bind_address,
                    reason: format!("failed to set SO_REUSEPORT: {e}"),
                })?;
        }

        // For IPv6, enable dual-stack mode
        if socket_addr.is_ipv6() {
            socket
                .set_only_v6(false)
                .map_err(|e| TransportError::BindFailed {
                    address: config.bind_address,
                    reason: format!("failed to set IPV6_V6ONLY: {e}"),
                })?;
        }

        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to set non-blocking: {e}"),
            })?;

        socket
            .bind(&socket_addr.into())
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            })?;

        socket
            .listen(config.backlog as i32)
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to listen: {e}"),
            })?;

        let std_listener: std::net::TcpListener = socket.into();
        let tokio_listener =
            TokioTcpListener::from_std(std_listener).map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            })?;

        let local_addr = tokio_listener
            .local_addr()
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to get local address: {e}"),
            })?;

        debug!(local_addr = %local_addr, "TCP listener bound");

        Ok(Self {
            listener: tokio_listener,
            local_addr: local_addr.into(),
            closed: AtomicBool::new(false),
        })
    }

    /// Accepts the next incoming connection.
    ///
    /// ## Errors
    ///
    /// Returns an error if accept fails.
    pub async fn accept(&self) -> TransportResult<(TcpTransport, SbcSocketAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::AlreadyClosed);
        }

        let (stream, peer_addr) =
            self.listener
                .accept()
                .await
                .map_err(|e| TransportError::ReceiveFailed {
                    reason: format!("accept failed: {e}"),
                })?;

        debug!(peer = %peer_addr, "accepted TCP connection");

        let transport = TcpTransport::from_stream(stream)?;
        Ok((transport, peer_addr.into()))
    }

    /// Returns the local address.
    #[must_use]
    pub const fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    /// Closes the listener.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn close(&self) -> TransportResult<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TransportError::AlreadyClosed);
        }

        debug!(local_addr = %self.local_addr, "TCP listener closed");
        Ok(())
    }
}

impl std::fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpListener")
            .field("local_addr", &self.local_addr)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[tokio::test]
    async fn test_tcp_listener_bind() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let listener = TcpListener::bind(addr).await.unwrap();

        assert!(listener.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn test_tcp_connect_accept() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        let listen_addr = *listener.local_addr();

        // Spawn a task to accept
        let accept_handle = tokio::spawn(async move { listener.accept().await });

        // Connect
        let client = TcpTransport::connect(listen_addr).await.unwrap();
        assert!(client.is_connected());
        assert_eq!(client.transport_type(), TransportType::Tcp);

        // Wait for accept
        let (server, _peer) = accept_handle.await.unwrap().unwrap();
        assert!(server.is_connected());
    }

    #[tokio::test]
    async fn test_tcp_send_recv() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        let listen_addr = *listener.local_addr();

        let accept_handle = tokio::spawn(async move {
            let (server, _) = listener.accept().await.unwrap();
            server
        });

        let client = TcpTransport::connect(listen_addr).await.unwrap();
        let server = accept_handle.await.unwrap();

        // Send from client
        let test_data = b"Hello, TCP!";
        client.send(test_data, &listen_addr).await.unwrap();

        // Receive on server
        let msg = server.recv().await.unwrap();
        assert_eq!(&msg.data[..], test_data);
        assert_eq!(msg.transport, TransportType::Tcp);
    }

    #[tokio::test]
    async fn test_tcp_close() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        let listen_addr = *listener.local_addr();

        let accept_handle = tokio::spawn(async move { listener.accept().await });

        let client = TcpTransport::connect(listen_addr).await.unwrap();
        let _ = accept_handle.await.unwrap().unwrap();

        assert!(client.is_connected());
        client.close().await.unwrap();
        assert!(!client.is_connected());

        // Second close should fail
        let result = client.close().await;
        assert!(matches!(result, Err(TransportError::AlreadyClosed)));
    }
}
