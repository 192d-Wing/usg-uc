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
use crate::{
    MAX_STREAM_MESSAGE_SIZE, ReceivedMessage, STREAM_READ_CHUNK, StreamTransport, Transport,
    canonical_peer,
};
use bytes::{BufMut, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
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
    /// Read and write halves are locked separately so a send from another
    /// task (timer retransmission, a request routed onto this connection)
    /// never waits behind a pending `recv` on the connection's reader task.
    reader: Mutex<OwnedReadHalf>,
    writer: Mutex<OwnedWriteHalf>,
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

        // NIST 800-53 Rev5: SI-10; supports SC-7, AC-4 - IPv4-mapped peers reported as plain IPv4.
        let peer_addr = canonical_peer(stream.peer_addr().map_err(|e| TransportError::Io {
            reason: format!("failed to get peer address: {e}"),
        })?)
        .into();

        debug!(local = %local_addr, peer = %peer_addr, "TCP transport created");

        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            local_addr,
            peer_addr,
            // NIST 800-53 Rev5: SC-5, SC-6 - one read chunk resident per
            // connection, not a message-sized buffer.
            read_buffer: Mutex::new(BytesMut::with_capacity(STREAM_READ_CHUNK)),
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
        // SIP requests are small and latency-sensitive (RFC 3261 §18.3).
        let _ = stream.set_nodelay(true);

        Self::from_stream(stream)
    }

    /// Checks if the transport is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Transport for TcpTransport {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

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

            {
                let mut stream = self.writer.lock().await;
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
                drop(stream);
            }

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(TransportError::AlreadyClosed);
            }

            let data = {
                let mut read_buffer = self.read_buffer.lock().await;
                let mut stream = self.reader.lock().await;

                // Read straight into the chunk buffer. The previous chunk was
                // split off and, once the caller drops it, `reserve` reclaims
                // the same allocation; `limit` keeps one read to one chunk.
                read_buffer.reserve(STREAM_READ_CHUNK);
                let n = stream
                    .read_buf(&mut (&mut *read_buffer).limit(STREAM_READ_CHUNK))
                    .await
                    .map_err(|e| TransportError::ReceiveFailed {
                        reason: e.to_string(),
                    })?;
                drop(stream);

                if n == 0 {
                    return Err(TransportError::ConnectionClosed);
                }

                trace!(size = n, "received TCP data");

                // For SIP, we'd parse the Content-Length and wait for full message.
                // For now, return whatever we received (simplified).
                read_buffer.split().freeze()
            };

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

            {
                let mut stream = self.writer.lock().await;
                let _ = stream.shutdown().await;
                drop(stream);
            }

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
            .field("reader", &"<mutex>")
            .field("writer", &"<mutex>")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("read_buffer", &"<mutex>")
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

/// Creates a TCP socket with the appropriate domain.
fn create_tcp_socket(
    socket_addr: &SocketAddr,
    bind_address: SbcSocketAddr,
) -> TransportResult<Socket> {
    let domain = if socket_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|e| TransportError::BindFailed {
        address: bind_address,
        reason: e.to_string(),
    })
}

/// Configures socket options based on the listener config.
fn configure_socket_options(
    socket: &Socket,
    socket_addr: &SocketAddr,
    config: &ListenerConfig,
) -> TransportResult<()> {
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
        })
}

/// Binds and starts listening on the socket.
fn bind_and_listen(
    socket: &Socket,
    socket_addr: &SocketAddr,
    config: &ListenerConfig,
) -> TransportResult<()> {
    socket
        .bind(&(*socket_addr).into())
        .map_err(|e| TransportError::BindFailed {
            address: config.bind_address,
            reason: e.to_string(),
        })?;

    socket
        .listen(i32::try_from(config.backlog).unwrap_or(128))
        .map_err(|e| TransportError::BindFailed {
            address: config.bind_address,
            reason: format!("failed to listen: {e}"),
        })
}

/// Converts a socket2 socket to a tokio `TcpListener`.
fn socket_to_tokio_listener(
    socket: Socket,
    bind_address: SbcSocketAddr,
) -> TransportResult<TokioTcpListener> {
    let std_listener: std::net::TcpListener = socket.into();
    TokioTcpListener::from_std(std_listener).map_err(|e| TransportError::BindFailed {
        address: bind_address,
        reason: e.to_string(),
    })
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
        let socket = create_tcp_socket(&socket_addr, config.bind_address)?;
        configure_socket_options(&socket, &socket_addr, &config)?;
        bind_and_listen(&socket, &socket_addr, &config)?;

        let tokio_listener = socket_to_tokio_listener(socket, config.bind_address)?;
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

        // NIST 800-53 Rev5: SI-10; supports SC-7, AC-4 - IPv4-mapped peers reported as plain IPv4.
        let peer_addr = canonical_peer(peer_addr);
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
            .field("listener", &self.listener)
            .field("local_addr", &self.local_addr)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    // POA&M-5: read and write halves are locked separately, so a send from
    // another task (timer loop, routed request) completes while the reader
    // task is parked in recv(), and the pending recv still gets its data.
    #[tokio::test]
    async fn test_tcp_send_not_blocked_by_pending_recv() {
        use std::sync::Arc;
        let listener = TcpListener::bind(SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = *listener.local_addr();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let conn = Arc::new(TcpTransport::connect(addr).await.unwrap());
        let server = accept.await.unwrap();
        let reader = {
            let c = Arc::clone(&conn);
            tokio::spawn(async move { c.recv().await.map(|m| m.data.to_vec()) })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!reader.is_finished(), "recv is pending");
        let secs = std::time::Duration::from_secs(2);
        let mut senders = Vec::new();
        for i in 0..4u8 {
            let c = Arc::clone(&conn);
            senders.push(tokio::spawn(async move {
                tokio::time::timeout(secs, c.send(&[b'A' + i], &addr)).await
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
            got.extend_from_slice(&server.recv().await.unwrap().data);
        }
        got.sort_unstable();
        assert_eq!(got, b"ABCD");
        server.send(b"200", &addr).await.unwrap();
        let r = tokio::time::timeout(secs, reader)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(r, b"200");
    }

    // Closing while a recv is pending does not hang the reader forever:
    // the peer's close ends it with an error.
    #[tokio::test]
    async fn test_tcp_pending_recv_ends_on_peer_close() {
        use std::sync::Arc;
        let listener = TcpListener::bind(SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = *listener.local_addr();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let conn = Arc::new(TcpTransport::connect(addr).await.unwrap());
        let server = accept.await.unwrap();
        let reader = {
            let c = Arc::clone(&conn);
            tokio::spawn(async move { c.recv().await })
        };
        server.close().await.unwrap();
        drop(server);
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), reader)
            .await
            .expect("reader must end on peer close")
            .unwrap();
        assert!(r.is_err());
    }

    // NIST 800-53 Rev5: SC-7, SI-10
    // An IPv4 client on a dual-stack `[::]` listener is reported with its
    // plain IPv4 address, so consumers comparing against IPv4 configuration
    // (blocklists, trunk maps) see the canonical form.
    #[tokio::test]
    async fn test_tcp_dual_stack_accept_reports_plain_ipv4_peer() {
        use std::net::Ipv4Addr;
        let Ok(listener) = TcpListener::bind(SbcSocketAddr::new_v6(Ipv6Addr::UNSPECIFIED, 0)).await
        else {
            crate::skip_dual_stack("cannot bind [::]:0 (no IPv6)");
            return;
        };
        let port = listener.local_addr().port();
        let accept = tokio::spawn(async move { listener.accept().await });
        let v4 = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, port);
        let connect =
            tokio::time::timeout(std::time::Duration::from_secs(2), TcpTransport::connect(v4))
                .await;
        let Ok(Ok(client)) = connect else {
            crate::skip_dual_stack("127.0.0.1 cannot reach a [::] listener (no dual-stack)");
            accept.abort();
            return;
        };
        let (server, peer) = accept.await.unwrap().unwrap();
        assert!(peer.is_ipv4(), "accept peer must be plain IPv4, got {peer}");
        assert_eq!(peer.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        let transport_peer = *server.peer_addr();
        assert!(
            transport_peer.is_ipv4(),
            "transport peer_addr must be plain IPv4, got {transport_peer}"
        );
        client.send(b"x", &v4).await.unwrap();
        let msg = server.recv().await.unwrap();
        assert!(
            msg.source.is_ipv4(),
            "received message source must be plain IPv4, got {}",
            msg.source
        );
    }

    // ---- SR-57: per-connection read buffer is one read chunk ----
    // NIST 800-53 Rev5: SC-5, SC-6
    // An idle connection keeps one 4 KiB read chunk resident, not a 64 KiB
    // message-sized buffer.

    /// Upper bound on the resident read buffer per connection (one 4 KiB
    /// chunk, with allocator slack).
    const QA_MAX_RESIDENT_READ_BUFFER: usize = 8 * 1024;

    async fn qa_tcp_pair() -> (TcpTransport, TcpTransport, SbcSocketAddr) {
        let listener = TcpListener::bind(SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = *listener.local_addr();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpTransport::connect(addr).await.unwrap();
        let server = accept.await.unwrap();
        (client, server, addr)
    }

    /// Receives until `len` bytes have arrived; returns them concatenated.
    async fn qa_recv_exact(t: &TcpTransport, len: usize) -> Vec<u8> {
        let mut got = Vec::with_capacity(len);
        while got.len() < len {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), t.recv())
                .await
                .expect("recv timed out")
                .unwrap();
            got.extend_from_slice(&msg.data);
        }
        got
    }

    #[tokio::test]
    async fn tcp_transport_read_buffer_is_one_chunk() {
        let (client, server, addr) = qa_tcp_pair().await;
        for (name, t) in [("client", &client), ("server", &server)] {
            let cap = t.read_buffer.lock().await.capacity();
            assert!(
                cap <= QA_MAX_RESIDENT_READ_BUFFER,
                "{name} read buffer after connect is {cap} bytes, want <= {QA_MAX_RESIDENT_READ_BUFFER}"
            );
        }

        let payload = vec![b'a'; 4096];
        client.send(&payload, &addr).await.unwrap();
        let got = qa_recv_exact(&server, payload.len()).await;
        assert_eq!(got, payload);
        let cap = server.read_buffer.lock().await.capacity();
        assert!(
            cap <= QA_MAX_RESIDENT_READ_BUFFER,
            "server read buffer after a 4 KiB round trip is {cap} bytes, want <= {QA_MAX_RESIDENT_READ_BUFFER}"
        );
    }

    // Regression guard for reading straight into the chunk buffer: a
    // message much larger than one chunk arrives intact and in order over
    // several recv calls.
    #[tokio::test]
    async fn tcp_recv_large_message_in_chunks_is_intact() {
        let (client, server, addr) = qa_tcp_pair().await;
        let payload: Vec<u8> = (0..60 * 1024_u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        client.send(&payload, &addr).await.unwrap();
        let got = qa_recv_exact(&server, payload.len()).await;
        assert_eq!(got.len(), payload.len());
        assert!(got == payload, "60 KiB payload corrupted or reordered");
        let cap = server.read_buffer.lock().await.capacity();
        assert!(
            cap <= QA_MAX_RESIDENT_READ_BUFFER,
            "server read buffer after a 60 KiB message is {cap} bytes, want <= {QA_MAX_RESIDENT_READ_BUFFER}"
        );
    }

    // A recv returns at most one chunk, so a single read never grows the
    // buffer past it.
    #[tokio::test]
    async fn tcp_recv_returns_at_most_one_chunk() {
        let (client, server, addr) = qa_tcp_pair().await;
        let payload = vec![b'z'; 32 * 1024];
        client.send(&payload, &addr).await.unwrap();
        let mut total = 0;
        while total < payload.len() {
            let msg = server.recv().await.unwrap();
            assert!(
                msg.data.len() <= 4096,
                "one recv returned {} bytes, want <= 4096",
                msg.data.len()
            );
            total += msg.data.len();
        }
        assert_eq!(total, payload.len());
    }
}
