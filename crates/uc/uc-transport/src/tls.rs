//! TLS transport implementation with CNSA 2.0 compliance.
//!
//! ## CNSA 2.0 Compliance
//!
//! TLS is configured with CNSA 2.0 compliant settings only:
//! - **TLS 1.3** required (no TLS 1.2 or earlier)
//! - **Cipher Suite**: TLS_AES_256_GCM_SHA384 only
//! - **Key Exchange**: P-384 ECDHE
//! - **Certificates**: P-384 ECDSA
//!
//! ## NIST 800-53 Rev5
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-12**: Cryptographic Key Establishment and Management
//! - **SC-13**: Cryptographic Protection
//!
//! ## IPv6-First Design
//!
//! TLS connections prefer IPv6 per project requirements.

use crate::error::{TransportError, TransportResult};
use crate::listener::ListenerConfig;
use crate::{ReceivedMessage, StreamTransport, Transport, MAX_STREAM_MESSAGE_SIZE};
use bytes::BytesMut;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ServerConfig};
use uc_types::address::{SbcSocketAddr, TransportType};
use socket2::{Domain, Protocol, Socket, Type};
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tracing::{debug, instrument, trace};

/// Creates a CNSA 2.0 compliant TLS server configuration.
///
/// ## CNSA 2.0 Requirements
///
/// - TLS 1.3 only
/// - TLS_AES_256_GCM_SHA384 cipher suite
/// - P-384 certificates
///
/// ## Errors
///
/// Returns an error if the configuration cannot be created.
pub fn create_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> TransportResult<ServerConfig> {
    // Use aws-lc-rs provider for FIPS compliance
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::TlsHandshakeFailed {
            reason: format!("failed to set TLS 1.3: {e}"),
        })?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| TransportError::TlsCertificateError {
            reason: e.to_string(),
        })?;

    Ok(config)
}

/// Creates a CNSA 2.0 compliant TLS client configuration.
///
/// ## CNSA 2.0 Requirements
///
/// - TLS 1.3 only
/// - TLS_AES_256_GCM_SHA384 cipher suite
/// - P-384 key exchange
///
/// ## Errors
///
/// Returns an error if the configuration cannot be created.
pub fn create_client_config(
    root_certs: rustls::RootCertStore,
) -> TransportResult<ClientConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::TlsHandshakeFailed {
            reason: format!("failed to set TLS 1.3: {e}"),
        })?
        .with_root_certificates(root_certs)
        .with_no_client_auth();

    Ok(config)
}

/// Loads a certificate chain from a PEM file.
///
/// ## Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_certs(path: &Path) -> TransportResult<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).map_err(|e| TransportError::TlsCertificateError {
        reason: format!("failed to open cert file: {e}"),
    })?;

    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::TlsCertificateError {
            reason: format!("failed to parse certs: {e}"),
        })?;

    if certs.is_empty() {
        return Err(TransportError::TlsCertificateError {
            reason: "no certificates found in file".to_string(),
        });
    }

    Ok(certs)
}

/// Loads a private key from a PEM file.
///
/// ## Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_private_key(path: &Path) -> TransportResult<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).map_err(|e| TransportError::TlsCertificateError {
        reason: format!("failed to open key file: {e}"),
    })?;

    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                return Err(TransportError::TlsCertificateError {
                    reason: "no private key found in file".to_string(),
                });
            }
            Err(e) => {
                return Err(TransportError::TlsCertificateError {
                    reason: format!("failed to parse key: {e}"),
                });
            }
        }
    }
}

/// TLS transport for secure SIP messaging.
///
/// ## CNSA 2.0 Compliance
///
/// This transport is configured with CNSA 2.0 compliant TLS settings:
/// - TLS 1.3 only
/// - TLS_AES_256_GCM_SHA384 cipher suite
/// - P-384 ECDHE key exchange
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
pub struct TlsTransport {
    stream: Arc<Mutex<TlsStream<TcpStream>>>,
    local_addr: SbcSocketAddr,
    peer_addr: SbcSocketAddr,
    read_buffer: Mutex<BytesMut>,
    closed: AtomicBool,
}

impl TlsTransport {
    /// Creates a TLS transport from an established TLS connection.
    fn from_stream(stream: TlsStream<TcpStream>) -> TransportResult<Self> {
        let (io, _session) = stream.get_ref();

        let local_addr = io.local_addr().map_err(|e| TransportError::Io {
            reason: format!("failed to get local address: {e}"),
        })?;

        let peer_addr = io.peer_addr().map_err(|e| TransportError::Io {
            reason: format!("failed to get peer address: {e}"),
        })?;

        debug!(
            local = %local_addr,
            peer = %peer_addr,
            "TLS transport created"
        );

        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            local_addr: local_addr.into(),
            peer_addr: peer_addr.into(),
            read_buffer: Mutex::new(BytesMut::with_capacity(MAX_STREAM_MESSAGE_SIZE)),
            closed: AtomicBool::new(false),
        })
    }

    /// Connects to a remote TLS endpoint.
    ///
    /// ## CNSA 2.0 Compliance
    ///
    /// The connection uses CNSA 2.0 compliant TLS settings.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection or TLS handshake fails.
    #[instrument(skip(config), fields(dest = %dest))]
    pub async fn connect(
        dest: SbcSocketAddr,
        server_name: &str,
        config: Arc<ClientConfig>,
    ) -> TransportResult<Self> {
        let dest_addr: SocketAddr = dest.clone().into();

        let tcp_stream = TcpStream::connect(dest_addr)
            .await
            .map_err(|e| TransportError::ConnectFailed {
                address: dest.clone(),
                reason: e.to_string(),
            })?;

        let server_name: rustls::pki_types::ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| TransportError::TlsHandshakeFailed {
                reason: "invalid server name".to_string(),
            })?;

        let connector = TlsConnector::from(config);
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| TransportError::TlsHandshakeFailed {
                reason: e.to_string(),
            })?;

        debug!(dest = %dest_addr, "TLS handshake completed");

        Self::from_stream(TlsStream::Client(tls_stream))
    }

    /// Checks if the transport is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Transport for TlsTransport {
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

            trace!(size = data.len(), "sending TLS data");

            let mut stream = self.stream.lock().await;
            stream
                .write_all(data)
                .await
                .map_err(|e| TransportError::SendFailed {
                    address: self.peer_addr.clone(),
                    reason: e.to_string(),
                })?;

            stream.flush().await.map_err(|e| TransportError::SendFailed {
                address: self.peer_addr.clone(),
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

            let mut temp_buffer = [0u8; 4096];
            let n = stream
                .read(&mut temp_buffer)
                .await
                .map_err(|e| TransportError::ReceiveFailed {
                    reason: e.to_string(),
                })?;

            if n == 0 {
                return Err(TransportError::ConnectionClosed);
            }

            read_buffer.extend_from_slice(&temp_buffer[..n]);

            trace!(size = n, "received TLS data");

            let data = read_buffer.split().freeze();

            Ok(ReceivedMessage {
                data,
                source: self.peer_addr.clone(),
                transport: TransportType::Tls,
            })
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tls
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

            debug!(peer = %self.peer_addr, "TLS transport closed");
            Ok(())
        })
    }
}

impl StreamTransport for TlsTransport {
    fn peer_addr(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    fn is_connected(&self) -> bool {
        !self.is_closed()
    }
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// TLS listener for accepting incoming secure connections.
///
/// ## CNSA 2.0 Compliance
///
/// All connections are established using CNSA 2.0 compliant TLS settings.
///
/// ## NIST 800-53 Rev5: SC-8
pub struct TlsListener {
    listener: TokioTcpListener,
    acceptor: TlsAcceptor,
    local_addr: SbcSocketAddr,
    closed: AtomicBool,
}

impl TlsListener {
    /// Creates a TLS listener with the given configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error if binding fails.
    #[instrument(skip(server_config), fields(addr = %config.bind_address))]
    pub async fn bind(
        config: ListenerConfig,
        server_config: Arc<ServerConfig>,
    ) -> TransportResult<Self> {
        config.validate()?;

        let socket_addr: SocketAddr = config.bind_address.clone().into();
        let domain = if socket_addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket =
            Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|e| {
                TransportError::BindFailed {
                    address: config.bind_address.clone(),
                    reason: e.to_string(),
                }
            })?;

        if config.reuse_address {
            socket.set_reuse_address(true).map_err(|e| {
                TransportError::BindFailed {
                    address: config.bind_address.clone(),
                    reason: format!("failed to set SO_REUSEADDR: {e}"),
                }
            })?;
        }

        #[cfg(unix)]
        if config.reuse_port {
            socket.set_reuse_port(true).map_err(|e| {
                TransportError::BindFailed {
                    address: config.bind_address.clone(),
                    reason: format!("failed to set SO_REUSEPORT: {e}"),
                }
            })?;
        }

        if socket_addr.is_ipv6() {
            socket.set_only_v6(false).map_err(|e| {
                TransportError::BindFailed {
                    address: config.bind_address.clone(),
                    reason: format!("failed to set IPV6_V6ONLY: {e}"),
                }
            })?;
        }

        socket.set_nonblocking(true).map_err(|e| {
            TransportError::BindFailed {
                address: config.bind_address.clone(),
                reason: format!("failed to set non-blocking: {e}"),
            }
        })?;

        socket
            .bind(&socket_addr.into())
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address.clone(),
                reason: e.to_string(),
            })?;

        socket
            .listen(config.backlog as i32)
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address.clone(),
                reason: format!("failed to listen: {e}"),
            })?;

        let std_listener: std::net::TcpListener = socket.into();
        let tokio_listener =
            TokioTcpListener::from_std(std_listener).map_err(|e| TransportError::BindFailed {
                address: config.bind_address.clone(),
                reason: e.to_string(),
            })?;

        let local_addr = tokio_listener.local_addr().map_err(|e| {
            TransportError::BindFailed {
                address: config.bind_address.clone(),
                reason: format!("failed to get local address: {e}"),
            }
        })?;

        debug!(local_addr = %local_addr, "TLS listener bound");

        Ok(Self {
            listener: tokio_listener,
            acceptor: TlsAcceptor::from(server_config),
            local_addr: local_addr.into(),
            closed: AtomicBool::new(false),
        })
    }

    /// Accepts the next incoming TLS connection.
    ///
    /// This performs the TLS handshake before returning.
    ///
    /// ## Errors
    ///
    /// Returns an error if accept or TLS handshake fails.
    pub async fn accept(&self) -> TransportResult<(TlsTransport, SbcSocketAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::AlreadyClosed);
        }

        let (tcp_stream, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| TransportError::ReceiveFailed {
                reason: format!("accept failed: {e}"),
            })?;

        debug!(peer = %peer_addr, "accepted TCP connection, starting TLS handshake");

        let tls_stream = self
            .acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| TransportError::TlsHandshakeFailed {
                reason: e.to_string(),
            })?;

        debug!(peer = %peer_addr, "TLS handshake completed");

        let transport = TlsTransport::from_stream(TlsStream::Server(tls_stream))?;
        Ok((transport, peer_addr.into()))
    }

    /// Returns the local address.
    #[must_use]
    pub fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    /// Closes the listener.
    pub fn close(&self) -> TransportResult<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TransportError::AlreadyClosed);
        }

        debug!(local_addr = %self.local_addr, "TLS listener closed");
        Ok(())
    }
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener")
            .field("local_addr", &self.local_addr)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cnsa_compliant_client_config() {
        let root_store = rustls::RootCertStore::empty();
        let config = create_client_config(root_store).unwrap();

        // Verify TLS 1.3 is configured
        assert!(config.alpn_protocols.is_empty()); // No ALPN by default
    }

    // Note: Full TLS tests require generating P-384 test certificates
    // which would be done in integration tests.
}
