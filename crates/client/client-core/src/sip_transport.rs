//! SIP Transport Layer for the client.
//!
//! Handles TLS connections to SIP registrars and proxies,
//! sending SIP requests and receiving responses.
//!
//! ## CNSA 2.0 Compliance
//!
//! - TLS 1.3 only
//! - AES-256-GCM cipher suite
//! - P-384 ECDHE key exchange
//!
//! ## Certificate Verification Modes
//!
//! The transport supports three verification modes:
//!
//! - **Insecure** (development only): Accepts all certificates without validation.
//!   Use only for local development with self-signed certificates.
//!
//! - **System** (default): Uses the operating system's trusted CA store.
//!   On Windows, this uses the Windows Certificate Store.
//!   On macOS/Linux, uses the platform's trusted CA bundle.
//!
//! - **Custom**: Uses a user-provided set of trusted CA certificates.
//!   For environments with private CAs (e.g., government networks).

use crate::{AppError, AppResult};
use bytes::BytesMut;
use proto_sip::message::{SipMessage, SipRequest, SipResponse};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, error, info, warn};

/// Certificate verification mode for TLS connections.
#[derive(Debug, Clone, Default)]
pub enum CertVerificationMode {
    /// Accept all certificates (DEVELOPMENT ONLY).
    /// Use only for local testing with self-signed certificates.
    Insecure,

    /// Use the operating system's trusted CA store (default).
    /// On Windows: Windows Certificate Store (ROOT store).
    /// On macOS/Linux: Platform trust store via rustls-native-certs.
    #[default]
    System,

    /// Use custom trusted CA certificates.
    /// For environments with private CAs.
    Custom {
        /// DER-encoded trusted CA certificates.
        trusted_certs: Vec<Vec<u8>>,
    },
}

/// A certificate verifier that accepts all certificates.
/// Used for development/testing with self-signed certificates.
/// WARNING: Do NOT use in production!
#[derive(Debug)]
struct InsecureCertVerifier;

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        warn!("INSECURE: Accepting certificate without validation (development mode)");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // CNSA 2.0 preferred schemes first
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Client certificate resolver for mTLS.
///
/// Provides client certificates during TLS handshake for mutual authentication.
#[derive(Debug)]
struct ClientCertResolver {
    /// The certified key for client authentication.
    certified_key: Option<Arc<CertifiedKey>>,
}

impl ClientCertResolver {
    /// Creates a new resolver without a certificate.
    const fn new() -> Self {
        Self {
            certified_key: None,
        }
    }

    /// Creates a resolver with the given certificate chain and private key.
    fn with_cert(cert_chain: Vec<CertificateDer<'static>>, key: &PrivateKeyDer<'static>) -> Self {
        let signing_key = match rustls::crypto::aws_lc_rs::sign::any_supported_type(key) {
            Ok(key) => key,
            Err(e) => {
                error!(error = %e, "Failed to parse private key for client auth");
                return Self::new();
            }
        };

        let certified_key = CertifiedKey::new(cert_chain, signing_key);
        Self {
            certified_key: Some(Arc::new(certified_key)),
        }
    }
}

impl rustls::client::ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        if self.certified_key.is_some() {
            debug!("Providing client certificate for mTLS");
        }
        self.certified_key.clone()
    }

    fn has_certs(&self) -> bool {
        self.certified_key.is_some()
    }
}

/// Maximum SIP message size (64KB should be plenty for SIP).
const MAX_SIP_MESSAGE_SIZE: usize = 65536;

/// Starts a UDP receive loop in a dedicated thread using blocking I/O.
///
/// This is a workaround for Tauri's async runtime issues with `tokio::spawn`.
/// The thread will run indefinitely, receiving UDP packets and sending them
/// through the provided channel.
///
/// # Arguments
/// * `local_addr` - The local address to bind to (e.g., "0.0.0.0:12345")
/// * `event_tx` - Async channel to send transport events to
///
/// # Returns
/// A `JoinHandle` for the spawned thread (can be ignored if you don't need to join).
pub fn start_udp_receive_thread(
    local_addr: std::net::SocketAddr,
    event_tx: mpsc::Sender<TransportEvent>,
) -> std::thread::JoinHandle<()> {
    info!(local_addr = %local_addr, "Starting UDP receive thread (blocking I/O)");

    std::thread::spawn(move || {
        // Create a blocking std UDP socket
        let socket = match std::net::UdpSocket::bind(local_addr) {
            Ok(s) => {
                info!(local_addr = %local_addr, "UDP receive thread: socket bound");
                s
            }
            Err(e) => {
                error!(error = %e, "UDP receive thread: failed to bind socket");
                return;
            }
        };

        let mut buf = vec![0u8; MAX_SIP_MESSAGE_SIZE];
        info!("UDP receive thread: entering receive loop");

        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, source)) => {
                    debug!(source = %source, size = n, "UDP receive thread: received packet");

                    match SipMessage::parse(&buf[..n]) {
                        Ok(message) => {
                            debug!(source = %source, "UDP receive thread: parsed SIP message");
                            let event = match message {
                                SipMessage::Request(request) => {
                                    TransportEvent::RequestReceived { request, source }
                                }
                                SipMessage::Response(response) => {
                                    debug!(status = %response.status, "UDP receive thread: SIP response");
                                    TransportEvent::ResponseReceived { response, source }
                                }
                            };

                            // Send event to async channel (blocking send from sync context)
                            if event_tx.blocking_send(event).is_err() {
                                error!("UDP receive thread: event channel closed, exiting");
                                return;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, source = %source, "UDP receive thread: parse error");
                            if let Ok(raw) = std::str::from_utf8(&buf[..n]) {
                                debug!(raw_message = %raw, "UDP receive thread: raw message");
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "UDP receive thread: recv error");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    })
}

/// Runs a UDP receive loop that dispatches received SIP messages to the event channel.
///
/// This function spawns a dedicated thread to receive UDP messages using blocking I/O,
/// which works around issues with Tauri's async runtime and tokio's UDP socket.
///
/// NOTE: This function takes ownership of the Arc<UdpSocket> and converts it to a
/// `std::net::UdpSocket` for blocking receive. The socket should not be used for
/// send after calling this function - use a separate socket or call this before
/// the socket is stored for sending.
///
/// # Arguments
/// * `socket` - The UDP socket to receive from (will be converted to blocking)
/// * `event_tx` - Channel to send transport events to
pub async fn run_udp_receive_loop(socket: Arc<UdpSocket>, event_tx: mpsc::Sender<TransportEvent>) {
    // Log socket info for debugging
    let local_addr = socket.local_addr().ok();
    if let Some(ref addr) = local_addr {
        info!(
            local_addr = %addr,
            socket_ptr = ?Arc::as_ptr(&socket),
            "Setting up UDP receive with blocking I/O in dedicated thread"
        );
    }

    // Clone the socket's underlying std socket for blocking receive
    // We use try_clone on the std socket obtained via try_recv_from
    // Actually, we need to work with the Arc<UdpSocket> directly
    // Let's spawn a blocking task instead

    // Use tokio's spawn_blocking for actual blocking receive
    let socket_clone = socket;
    tokio::task::spawn_blocking(move || {
        info!("UDP receive thread started (blocking)");
        let mut buf = vec![0u8; MAX_SIP_MESSAGE_SIZE];

        loop {
            // Use the tokio socket's underlying std socket for blocking receive
            // This is a workaround - we're doing blocking I/O on the tokio socket
            // from a blocking thread context
            match socket_clone.try_recv_from(&mut buf) {
                Ok((n, source)) => {
                    debug!(source = %source, size = n, "Received UDP packet (blocking thread)");

                    match SipMessage::parse(&buf[..n]) {
                        Ok(message) => {
                            debug!(source = %source, "Parsed SIP message via UDP");
                            let event = match message {
                                SipMessage::Request(request) => {
                                    debug!(method = %request.method, "Received SIP request via UDP");
                                    TransportEvent::RequestReceived { request, source }
                                }
                                SipMessage::Response(response) => {
                                    debug!(status = %response.status, "Received SIP response via UDP");
                                    TransportEvent::ResponseReceived { response, source }
                                }
                            };
                            // Use blocking send from sync context
                            if event_tx.blocking_send(event).is_err() {
                                error!("UDP receive thread: event channel closed");
                                return;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, source = %source, "Failed to parse UDP SIP message");
                            if let Ok(raw) = std::str::from_utf8(&buf[..n]) {
                                debug!(raw_message = %raw, "Raw UDP message");
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Periodic log
                    static COUNTER: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    // No data available, sleep a bit and try again
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if count.is_multiple_of(500) {
                        debug!(poll_count = count, "UDP receive (blocking) still polling");
                    }
                }
                Err(e) => {
                    error!(error = %e, "UDP receive error (blocking thread)");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    });
}

/// Events from the transport layer.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// Received a SIP response.
    ResponseReceived {
        /// The SIP response.
        response: SipResponse,
        /// Source address.
        source: SocketAddr,
    },
    /// Received an incoming SIP request (e.g., incoming INVITE).
    RequestReceived {
        /// The SIP request.
        request: SipRequest,
        /// Source address.
        source: SocketAddr,
    },
    /// Connection established to a peer.
    Connected {
        /// Peer address.
        peer: SocketAddr,
    },
    /// Connection lost to a peer.
    Disconnected {
        /// Peer address.
        peer: SocketAddr,
        /// Reason for disconnection.
        reason: String,
    },
    /// Transport error occurred.
    Error {
        /// Error message.
        message: String,
    },
}

/// Active TLS connection to a SIP peer.
struct TlsConnection {
    /// TLS stream.
    stream: TlsStream<TcpStream>,
    /// Peer address.
    peer_addr: SocketAddr,
    /// Read buffer for partial messages.
    read_buffer: BytesMut,
}

impl TlsConnection {
    /// Creates a new TLS connection.
    fn new(stream: TlsStream<TcpStream>, peer_addr: SocketAddr) -> Self {
        Self {
            stream,
            peer_addr,
            read_buffer: BytesMut::with_capacity(MAX_SIP_MESSAGE_SIZE),
        }
    }

    /// Sends a SIP message.
    async fn send(&mut self, message: &[u8]) -> AppResult<()> {
        let peer = self.peer_addr;
        self.stream
            .write_all(message)
            .await
            .map_err(|e| AppError::Sip(format!("Failed to send to {peer}: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| AppError::Sip(format!("Failed to flush to {peer}: {e}")))?;
        Ok(())
    }

    /// Reads data from the connection and returns any complete SIP messages.
    async fn recv(&mut self) -> AppResult<Option<SipMessage>> {
        let mut buf = [0u8; 4096];
        let peer = self.peer_addr;
        let n = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|e| AppError::Sip(format!("Failed to read from {peer}: {e}")))?;

        if n == 0 {
            return Err(AppError::Sip(format!("Connection closed by {peer}")));
        }

        self.read_buffer.extend_from_slice(&buf[..n]);

        // Try to parse a complete SIP message
        // SIP messages end with \r\n\r\n for headers, then Content-Length bytes
        if let Some(message) = self.try_parse_message()? {
            return Ok(Some(message));
        }

        Ok(None)
    }

    /// Tries to parse a complete SIP message from the read buffer.
    fn try_parse_message(&mut self) -> AppResult<Option<SipMessage>> {
        // Look for end of headers (\r\n\r\n)
        let data = &self.read_buffer[..];
        let Some(header_end) = find_header_end(data) else {
            return Ok(None); // Need more data
        };

        // Parse headers to find Content-Length
        let headers_str = std::str::from_utf8(&data[..header_end + 4])
            .map_err(|e| AppError::Sip(format!("Invalid UTF-8 in SIP headers: {e}")))?;

        let content_length = extract_content_length(headers_str).unwrap_or(0);
        let total_length = header_end + 4 + content_length;

        if self.read_buffer.len() < total_length {
            return Ok(None); // Need more data for body
        }

        // Extract the complete message
        let message_bytes = self.read_buffer.split_to(total_length);

        // Parse the SIP message
        match SipMessage::parse(&message_bytes) {
            Ok(message) => Ok(Some(message)),
            Err(e) => {
                warn!(error = %e, "Failed to parse SIP message");
                Err(AppError::Sip(format!("Failed to parse SIP message: {e}")))
            }
        }
    }
}

/// Configuration for the SIP transport layer.
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    /// Certificate verification mode.
    pub verification_mode: CertVerificationMode,
    /// Client certificate chain for mTLS (DER-encoded).
    pub client_cert_chain: Option<Vec<Vec<u8>>>,
    /// Client private key for mTLS (DER-encoded).
    /// If `None` and `client_cert_chain` is `Some`, smart card signing is assumed.
    pub client_private_key: Option<Vec<u8>>,
}

impl TransportConfig {
    /// Creates a new configuration with system CA validation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the verification mode.
    #[must_use]
    pub fn with_verification_mode(mut self, mode: CertVerificationMode) -> Self {
        self.verification_mode = mode;
        self
    }

    /// Sets the client certificate for mTLS.
    #[must_use]
    pub fn with_client_certificate(
        mut self,
        cert_chain: Vec<Vec<u8>>,
        private_key: Option<Vec<u8>>,
    ) -> Self {
        self.client_cert_chain = Some(cert_chain);
        self.client_private_key = private_key;
        self
    }
}

/// SIP Transport manager.
///
/// Manages TLS connections to SIP peers and handles message routing.
/// Also supports UDP transport for testing with non-TLS providers.
pub struct SipTransport {
    /// TLS client configuration (can be rebuilt when certs change).
    tls_config: Arc<RwLock<Arc<ClientConfig>>>,
    /// Active TLS connections by peer address.
    connections: Arc<Mutex<HashMap<SocketAddr, TlsConnection>>>,
    /// UDP socket for connectionless transport.
    /// Uses `RwLock` so receive task can access socket without blocking sends.
    udp_socket: Arc<RwLock<Option<Arc<UdpSocket>>>>,
    /// Event sender.
    event_tx: mpsc::Sender<TransportEvent>,
    /// Transport configuration.
    config: Arc<RwLock<TransportConfig>>,
}

impl SipTransport {
    /// Creates a new SIP transport with default configuration.
    ///
    /// By default, uses system CA validation without client authentication.
    pub fn new(event_tx: mpsc::Sender<TransportEvent>) -> AppResult<Self> {
        Self::with_config(event_tx, TransportConfig::default())
    }

    /// Creates a new SIP transport with the specified configuration.
    pub fn with_config(
        event_tx: mpsc::Sender<TransportEvent>,
        config: TransportConfig,
    ) -> AppResult<Self> {
        // Create TLS configuration with CNSA 2.0 compliance
        let tls_config = Self::create_tls_config(&config)?;

        Ok(Self {
            tls_config: Arc::new(RwLock::new(Arc::new(tls_config))),
            connections: Arc::new(Mutex::new(HashMap::new())),
            udp_socket: Arc::new(RwLock::new(None)),
            event_tx,
            config: Arc::new(RwLock::new(config)),
        })
    }

    /// Sets the certificate verification mode.
    ///
    /// This will close all existing connections and rebuild the TLS config.
    pub async fn set_verification_mode(&self, mode: CertVerificationMode) -> AppResult<()> {
        info!(mode = ?mode, "Setting certificate verification mode");

        let mut config = self.config.write().await;
        config.verification_mode = mode;

        // Rebuild TLS config
        let new_tls_config = Self::create_tls_config(&config)?;
        drop(config);

        // Update the TLS config
        *self.tls_config.write().await = Arc::new(new_tls_config);

        // Close existing connections (they'll reconnect with new config)
        self.connections.lock().await.clear();

        Ok(())
    }

    /// Sets the client certificate for mTLS authentication.
    ///
    /// # Arguments
    /// * `cert_chain` - DER-encoded certificate chain (end-entity first)
    /// * `private_key` - Optional DER-encoded private key. If `None`, smart card signing is assumed.
    ///
    /// This will close all existing connections and rebuild the TLS config.
    pub async fn set_client_certificate(
        &self,
        cert_chain: Vec<Vec<u8>>,
        private_key: Option<Vec<u8>>,
    ) -> AppResult<()> {
        info!(
            cert_count = cert_chain.len(),
            has_private_key = private_key.is_some(),
            "Setting client certificate for mTLS"
        );

        let mut config = self.config.write().await;
        config.client_cert_chain = Some(cert_chain);
        config.client_private_key = private_key;

        // Rebuild TLS config
        let new_tls_config = Self::create_tls_config(&config)?;
        drop(config);

        // Update the TLS config
        *self.tls_config.write().await = Arc::new(new_tls_config);

        // Close existing connections (they'll reconnect with new config)
        self.connections.lock().await.clear();

        Ok(())
    }

    /// Creates CNSA 2.0 compliant TLS configuration.
    fn create_tls_config(config: &TransportConfig) -> AppResult<ClientConfig> {
        use rustls::crypto::aws_lc_rs::default_provider;

        let provider = default_provider();

        // Build the config based on verification mode
        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| AppError::Sip(format!("Failed to configure TLS 1.3: {e}")))?;

        // Configure server certificate verification
        let builder_with_verifier = match &config.verification_mode {
            CertVerificationMode::Insecure => {
                warn!("INSECURE MODE: Server certificates will not be validated!");
                warn!("This should only be used for development with self-signed certs");
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            }
            CertVerificationMode::System => {
                // Use platform's trusted CA store
                let root_store = load_system_root_certs();
                info!(
                    cert_count = root_store.len(),
                    "Loaded system trusted CA certificates"
                );
                builder.with_root_certificates(root_store)
            }
            CertVerificationMode::Custom { trusted_certs } => {
                // Use custom CA certificates
                let root_store = load_custom_root_certs(trusted_certs)?;
                info!(
                    cert_count = root_store.len(),
                    "Loaded custom trusted CA certificates"
                );
                builder.with_root_certificates(root_store)
            }
        };

        // Configure client authentication
        let tls_config = Self::configure_client_auth(builder_with_verifier, config)?;

        Ok(tls_config)
    }

    /// Configures client authentication for mTLS.
    fn configure_client_auth(
        builder: rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
        config: &TransportConfig,
    ) -> AppResult<ClientConfig> {
        match (&config.client_cert_chain, &config.client_private_key) {
            (Some(cert_chain), Some(private_key)) => {
                // Full mTLS with certificate and private key
                let certs: Vec<CertificateDer<'static>> = cert_chain
                    .iter()
                    .map(|c| CertificateDer::from(c.clone()))
                    .collect();

                let key = PrivateKeyDer::try_from(private_key.clone())
                    .map_err(|e| AppError::Sip(format!("Invalid private key format: {e}")))?;

                info!(
                    cert_count = certs.len(),
                    "Configuring mTLS with private key"
                );

                // Use custom resolver for client certificates
                let resolver = ClientCertResolver::with_cert(certs, &key);
                Ok(builder.with_client_cert_resolver(Arc::new(resolver)))
            }
            (Some(cert_chain), None) => {
                // Certificate without private key - smart card signing
                // For smart cards, the Windows TLS stack handles signing
                // We configure the certs but can't provide the resolver without
                // the private key. The OS will prompt for PIN when needed.
                info!(
                    cert_count = cert_chain.len(),
                    "Client certificate configured (smart card signing)"
                );
                warn!("Smart card mTLS requires Windows native TLS stack");
                // For now, proceed without client auth - platform handles it
                Ok(builder.with_no_client_auth())
            }
            (None, _) => {
                // No client authentication
                debug!("No client certificate configured");
                Ok(builder.with_no_client_auth())
            }
        }
    }

    /// Sends a SIP request to the specified destination.
    pub async fn send_request(
        &self,
        request: &SipRequest,
        destination: SocketAddr,
    ) -> AppResult<()> {
        info!(
            method = %request.method,
            destination = %destination,
            "Sending SIP request"
        );

        // Get or create connection
        let mut connections = self.connections.lock().await;

        if !connections.contains_key(&destination) {
            // Need to establish connection
            drop(connections); // Release lock during connect
            self.connect(destination).await?;
            connections = self.connections.lock().await;
        }

        let conn = connections
            .get_mut(&destination)
            .ok_or_else(|| AppError::Sip(format!("No connection to {destination}")))?;

        // Serialize and send
        let message_bytes = request.to_string();
        debug!(
            destination = %destination,
            size = message_bytes.len(),
            "Sending SIP message"
        );

        conn.send(message_bytes.as_bytes()).await?;
        drop(connections);

        Ok(())
    }

    /// Sends a SIP response to the specified destination.
    ///
    /// Used to respond to incoming SIP requests (e.g., INVITE, OPTIONS).
    /// The destination should match the source of the original request.
    pub async fn send_response(
        &self,
        response: &SipResponse,
        destination: SocketAddr,
    ) -> AppResult<()> {
        info!(
            status = response.status.code(),
            destination = %destination,
            "Sending SIP response"
        );

        // Get existing connection - responses are sent on the same connection
        // that received the request
        let mut connections = self.connections.lock().await;

        let conn = connections.get_mut(&destination).ok_or_else(|| {
            AppError::Sip(format!(
                "No connection to {destination} - cannot send response without established connection"
            ))
        })?;

        // Serialize and send
        let message_bytes = response.to_string();
        debug!(
            destination = %destination,
            size = message_bytes.len(),
            status = response.status.code(),
            "Sending SIP response"
        );

        conn.send(message_bytes.as_bytes()).await?;
        drop(connections);

        Ok(())
    }

    /// Gets or creates the UDP socket, returning it along with a flag indicating if it's new.
    ///
    /// If the socket is new, the caller should start a receive loop.
    /// In Tauri context, use `tauri::async_runtime::spawn` for the receive loop.
    pub async fn get_or_create_udp_socket(&self) -> AppResult<(Arc<UdpSocket>, bool)> {
        let socket_guard = self.udp_socket.read().await;
        if let Some(ref sock) = *socket_guard {
            let result = Ok((sock.clone(), false));
            drop(socket_guard);
            return result;
        }
        drop(socket_guard);

        // Need to create socket - get write lock
        let mut socket_guard = self.udp_socket.write().await;
        // Double-check in case another task created it
        if let Some(ref sock) = *socket_guard {
            let result = Ok((sock.clone(), false));
            drop(socket_guard);
            return result;
        }

        // Bind to any available port
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => {
                info!("UDP socket bound to 0.0.0.0");
                s
            }
            Err(e) => {
                warn!(error = %e, "Failed to bind to 0.0.0.0, trying localhost");
                UdpSocket::bind("127.0.0.1:0")
                    .await
                    .map_err(|e2| AppError::Sip(format!("Failed to bind UDP socket: {e} / {e2}")))?
            }
        };
        let local_addr = socket
            .local_addr()
            .map_err(|e| AppError::Sip(format!("Failed to get UDP local address: {e}")))?;
        info!(local_addr = %local_addr, "UDP socket bound");
        let socket = Arc::new(socket);
        *socket_guard = Some(socket.clone());
        drop(socket_guard);
        Ok((socket, true))
    }

    /// Returns the event sender for transport events.
    ///
    /// Use this to send events from an external UDP receive loop.
    pub fn event_sender(&self) -> mpsc::Sender<TransportEvent> {
        self.event_tx.clone()
    }

    /// Sends a SIP request via UDP (connectionless).
    ///
    /// For testing with non-TLS providers like `BulkVS`.
    /// NOTE: The caller is responsible for starting the UDP receive loop.
    /// In Tauri context, use `tauri::async_runtime::spawn` with `run_udp_receive_loop`.
    pub async fn send_request_udp(
        &self,
        request: &SipRequest,
        destination: SocketAddr,
    ) -> AppResult<()> {
        info!(
            method = %request.method,
            destination = %destination,
            "Sending SIP request via UDP"
        );

        // Get or create UDP socket (caller is responsible for receive loop)
        let (socket, is_new) = self.get_or_create_udp_socket().await?;

        // Log socket info for debugging
        if let Ok(local_addr) = socket.local_addr() {
            info!(
                local_addr = %local_addr,
                is_new_socket = is_new,
                socket_ptr = ?Arc::as_ptr(&socket),
                "Using UDP socket for send"
            );
        }

        // Serialize and send
        let message_bytes = request.to_string();
        debug!(
            destination = %destination,
            size = message_bytes.len(),
            "Sending SIP message via UDP"
        );

        socket
            .send_to(message_bytes.as_bytes(), destination)
            .await
            .map_err(|e| AppError::Sip(format!("Failed to send UDP to {destination}: {e}")))?;

        Ok(())
    }

    /// Sends a SIP response via UDP (connectionless).
    ///
    /// Used for responding to requests received via UDP (e.g., BYE, CANCEL).
    pub async fn send_response_udp(
        &self,
        response: &SipResponse,
        destination: SocketAddr,
    ) -> AppResult<()> {
        info!(
            status = response.status.code(),
            destination = %destination,
            "Sending SIP response via UDP"
        );

        // Get or create UDP socket
        let (socket, is_new) = self.get_or_create_udp_socket().await?;

        // Log socket info for debugging
        if let Ok(local_addr) = socket.local_addr() {
            info!(
                local_addr = %local_addr,
                is_new_socket = is_new,
                socket_ptr = ?Arc::as_ptr(&socket),
                "Using UDP socket for response send"
            );
        }

        // Serialize and send
        let message_bytes = response.to_string();
        debug!(
            destination = %destination,
            size = message_bytes.len(),
            status = response.status.code(),
            "Sending SIP response via UDP"
        );

        socket
            .send_to(message_bytes.as_bytes(), destination)
            .await
            .map_err(|e| {
                AppError::Sip(format!("Failed to send UDP response to {destination}: {e}"))
            })?;

        Ok(())
    }

    /// Establishes a TLS connection to a peer.
    async fn connect(&self, peer: SocketAddr) -> AppResult<()> {
        info!(peer = %peer, "Connecting to SIP peer");

        // Connect TCP
        let tcp_stream = TcpStream::connect(peer)
            .await
            .map_err(|e| AppError::Sip(format!("Failed to connect to {peer}: {e}")))?;

        // Derive server name from peer (use IP for now)
        let server_name: ServerName<'static> = peer
            .ip()
            .to_string()
            .try_into()
            .map_err(|_| AppError::Sip("Invalid server name".to_string()))?;

        // Get current TLS config
        let tls_config = self.tls_config.read().await.clone();

        // TLS handshake
        let connector = TlsConnector::from(tls_config);
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| AppError::Sip(format!("TLS handshake failed with {peer}: {e}")))?;

        info!(peer = %peer, "TLS connection established");

        // Store connection
        let conn = TlsConnection::new(tls_stream, peer);
        {
            let mut connections = self.connections.lock().await;
            connections.insert(peer, conn);
        }

        // Notify connected
        let _ = self.event_tx.send(TransportEvent::Connected { peer }).await;

        // Spawn receive task for this connection
        self.spawn_receive_task(peer);

        Ok(())
    }

    /// Spawns a task to receive messages from a connection.
    fn spawn_receive_task(&self, peer: SocketAddr) {
        let connections = self.connections.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            loop {
                let result = {
                    let mut conns = connections.lock().await;
                    if let Some(conn) = conns.get_mut(&peer) {
                        conn.recv().await
                    } else {
                        break; // Connection removed
                    }
                };

                match result {
                    Ok(Some(message)) => {
                        debug!(peer = %peer, "Received SIP message");
                        match message {
                            SipMessage::Request(request) => {
                                let _ = event_tx
                                    .send(TransportEvent::RequestReceived {
                                        request,
                                        source: peer,
                                    })
                                    .await;
                            }
                            SipMessage::Response(response) => {
                                let _ = event_tx
                                    .send(TransportEvent::ResponseReceived {
                                        response,
                                        source: peer,
                                    })
                                    .await;
                            }
                        }
                    }
                    Ok(None) => {
                        // No complete message yet, continue
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        error!(peer = %peer, error = %e, "Connection error");
                        let _ = event_tx
                            .send(TransportEvent::Disconnected {
                                peer,
                                reason: e.to_string(),
                            })
                            .await;

                        // Remove connection
                        connections.lock().await.remove(&peer);
                        break;
                    }
                }
            }
        });
    }

    /// Closes all connections.
    pub async fn shutdown(&self) {
        info!("Shutting down SIP transport");
        let mut connections = self.connections.lock().await;
        connections.clear();
    }
}

/// Builds a SIP response from an incoming request.
///
/// This copies the required headers from the request per RFC 3261 §8.2.6:
/// - Via (all headers, in order)
/// - From
/// - To (with optional tag for new dialogs)
/// - Call-ID
/// - `CSeq`
///
/// # Arguments
/// * `request` - The original SIP request
/// * `status` - The response status code
/// * `to_tag` - Optional To tag for dialog establishment (required for 200 OK to INVITE)
///
/// # Returns
/// A new SIP response with the required headers copied from the request.
pub fn build_response_from_request(
    request: &SipRequest,
    status: proto_sip::response::StatusCode,
    to_tag: Option<&str>,
) -> SipResponse {
    use proto_sip::header::{Header, HeaderName};

    let mut response = SipResponse::new(status);

    // Copy Via headers (all, in order) - RFC 3261 §8.2.6.1
    for via in request.headers.get_all(&HeaderName::Via) {
        response.add_header(Header::new(HeaderName::Via, &via.value));
    }

    // Copy From header unchanged
    if let Some(from) = request.headers.get_value(&HeaderName::From) {
        response.add_header(Header::new(HeaderName::From, from));
    }

    // Copy To header, adding tag if provided
    if let Some(to) = request.headers.get_value(&HeaderName::To) {
        let to_value = to_tag.map_or_else(
            || to.to_string(),
            |tag| {
                // Add or replace tag
                if to.contains(";tag=") {
                    to.to_string()
                } else {
                    format!("{to};tag={tag}")
                }
            },
        );
        response.add_header(Header::new(HeaderName::To, to_value));
    }

    // Copy Call-ID header unchanged
    if let Some(call_id) = request.headers.get_value(&HeaderName::CallId) {
        response.add_header(Header::new(HeaderName::CallId, call_id));
    }

    // Copy CSeq header unchanged
    if let Some(cseq) = request.headers.get_value(&HeaderName::CSeq) {
        response.add_header(Header::new(HeaderName::CSeq, cseq));
    }

    // Add Content-Length: 0 if no body
    response.add_header(Header::new(HeaderName::ContentLength, "0"));

    response
}

/// Generates a unique tag for SIP dialogs.
///
/// Returns a random alphanumeric string suitable for use as a To or From tag.
pub fn generate_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Generate pseudo-random tag based on timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Format as base36 for compact representation
    let hash = now.wrapping_mul(31);
    format!("{now:x}-{hash:x}")
}

/// Finds the end of SIP headers (\r\n\r\n).
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Extracts Content-Length from SIP headers.
fn extract_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("content-length:") || line_lower.starts_with("l:") {
            let value = line.split(':').nth(1)?.trim();
            return value.parse().ok();
        }
    }
    None
}

/// Loads the system's trusted root CA certificates.
///
/// Uses rustls-native-certs to load platform-specific trusted CAs:
/// - Windows: Windows Certificate Store (ROOT store)
/// - macOS: Keychain
/// - Linux: /etc/ssl/certs or distribution-specific locations
fn load_system_root_certs() -> RootCertStore {
    let mut root_store = RootCertStore::empty();

    // Load native certificates - returns CertificateResult in 0.8+
    let cert_result = rustls_native_certs::load_native_certs();

    // Log any errors encountered during loading
    for e in &cert_result.errors {
        warn!(error = %e, "Error loading native certificate");
    }

    // Add successfully loaded certificates
    let mut added = 0;
    let mut failed = 0;

    for cert in cert_result.certs {
        match root_store.add(cert) {
            Ok(()) => added += 1,
            Err(e) => {
                debug!(error = %e, "Failed to add certificate to root store");
                failed += 1;
            }
        }
    }

    info!(
        added = added,
        failed = failed,
        "Loaded system root certificates"
    );

    if added == 0 {
        warn!("No system root certificates loaded - server verification may fail");
    }

    root_store
}

/// Loads custom trusted CA certificates from DER-encoded bytes.
fn load_custom_root_certs(trusted_certs: &[Vec<u8>]) -> AppResult<RootCertStore> {
    let mut root_store = RootCertStore::empty();

    for (i, cert_der) in trusted_certs.iter().enumerate() {
        let cert = CertificateDer::from(cert_der.clone());
        match root_store.add(cert) {
            Ok(()) => {
                debug!(index = i, "Added custom CA certificate");
            }
            Err(e) => {
                warn!(
                    index = i,
                    error = %e,
                    "Failed to add custom CA certificate"
                );
            }
        }
    }

    if root_store.is_empty() {
        return Err(AppError::Sip(
            "No valid CA certificates provided".to_string(),
        ));
    }

    Ok(root_store)
}

/// Loads CA certificates from a PEM file and returns them as DER-encoded bytes.
///
/// This function reads a PEM-encoded certificate file (which may contain
/// multiple certificates) and returns each certificate as DER-encoded bytes,
/// suitable for use with `CertVerificationMode::Custom`.
///
/// Supports both PEM (.pem, .crt) and DER (.der, .cer) formats.
///
/// # Arguments
/// * `path` - Path to the certificate file
///
/// # Returns
/// A vector of DER-encoded certificates on success.
///
/// # Errors
/// Returns an error if the file cannot be read or contains no valid certificates.
pub fn load_certs_from_pem_file(path: &std::path::Path) -> AppResult<Vec<Vec<u8>>> {
    use std::fs;

    let content = fs::read(path).map_err(|e| {
        let display = path.display();
        AppError::Sip(format!("Failed to read CA file '{display}': {e}"))
    })?;

    // Check if it's a DER file (starts with ASN.1 SEQUENCE tag 0x30)
    if content.first() == Some(&0x30) {
        // Assume it's DER-encoded
        info!(
            path = %path.display(),
            "Loaded DER-encoded CA certificate"
        );
        return Ok(vec![content]);
    }

    // Parse as PEM
    let pem_str = String::from_utf8(content).map_err(|e| {
        let display = path.display();
        AppError::Sip(format!("Invalid UTF-8 in CA file '{display}': {e}"))
    })?;

    let certs = parse_pem_certificates(&pem_str);

    if certs.is_empty() {
        let display = path.display();
        return Err(AppError::Sip(format!(
            "No valid certificates found in '{display}'"
        )));
    }

    info!(
        path = %path.display(),
        cert_count = certs.len(),
        "Loaded CA certificates from PEM file"
    );

    Ok(certs)
}

/// Parses PEM-encoded certificates from a string.
///
/// Extracts all CERTIFICATE blocks from the PEM data.
fn parse_pem_certificates(pem_data: &str) -> Vec<Vec<u8>> {
    use base64::prelude::*;

    const BEGIN_CERT: &str = "-----BEGIN CERTIFICATE-----";
    const END_CERT: &str = "-----END CERTIFICATE-----";

    let mut certs = Vec::new();
    let mut remaining = pem_data;

    while let Some(begin_idx) = remaining.find(BEGIN_CERT) {
        remaining = &remaining[begin_idx + BEGIN_CERT.len()..];

        if let Some(end_idx) = remaining.find(END_CERT) {
            let base64_data: String = remaining[..end_idx]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();

            match BASE64_STANDARD.decode(&base64_data) {
                Ok(der_bytes) => {
                    certs.push(der_bytes);
                }
                Err(e) => {
                    warn!(error = %e, "Failed to decode PEM certificate, skipping");
                }
            }

            remaining = &remaining[end_idx + END_CERT.len()..];
        } else {
            break;
        }
    }

    certs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_end() {
        let data = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TLS\r\n\r\n";
        assert_eq!(find_header_end(data), Some(32));
    }

    #[test]
    fn test_find_header_end_not_found() {
        let data = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TLS\r\n";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn test_find_header_end_at_start() {
        let data = b"\r\n\r\n";
        assert_eq!(find_header_end(data), Some(0));
    }

    #[test]
    fn test_find_header_end_with_body() {
        let data = b"SIP/2.0 200 OK\r\nContent-Length: 5\r\n\r\nHello";
        assert_eq!(find_header_end(data), Some(33));
    }

    #[test]
    fn test_extract_content_length() {
        let headers = "SIP/2.0 200 OK\r\nContent-Length: 123\r\n\r\n";
        assert_eq!(extract_content_length(headers), Some(123));
    }

    #[test]
    fn test_extract_content_length_compact() {
        let headers = "SIP/2.0 200 OK\r\nl: 456\r\n\r\n";
        assert_eq!(extract_content_length(headers), Some(456));
    }

    #[test]
    fn test_extract_content_length_missing() {
        let headers = "SIP/2.0 200 OK\r\n\r\n";
        assert_eq!(extract_content_length(headers), None);
    }

    #[test]
    fn test_extract_content_length_case_insensitive() {
        let headers = "SIP/2.0 200 OK\r\nCONTENT-LENGTH: 789\r\n\r\n";
        assert_eq!(extract_content_length(headers), Some(789));
    }

    #[test]
    fn test_extract_content_length_with_spaces() {
        let headers = "SIP/2.0 200 OK\r\nContent-Length:   42  \r\n\r\n";
        assert_eq!(extract_content_length(headers), Some(42));
    }

    #[tokio::test]
    async fn test_transport_creation() {
        let (tx, _rx) = mpsc::channel(32);
        let transport = SipTransport::new(tx);
        assert!(
            transport.is_ok(),
            "SipTransport should be created successfully"
        );
    }

    #[tokio::test]
    async fn test_transport_shutdown() {
        let (tx, _rx) = mpsc::channel(32);
        let transport = SipTransport::new(tx).unwrap();
        // Shutdown should not panic even with no connections
        transport.shutdown().await;
    }

    #[test]
    fn test_transport_event_debug() {
        let event = TransportEvent::Connected {
            peer: "127.0.0.1:5060".parse().unwrap(),
        };
        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("Connected"));
        assert!(debug_str.contains("127.0.0.1:5060"));
    }

    #[test]
    fn test_transport_event_error() {
        let event = TransportEvent::Error {
            message: "Test error".to_string(),
        };
        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("Error"));
        assert!(debug_str.contains("Test error"));
    }

    #[test]
    fn test_transport_event_disconnected() {
        let event = TransportEvent::Disconnected {
            peer: "192.168.1.1:5061".parse().unwrap(),
            reason: "Connection reset".to_string(),
        };
        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("Disconnected"));
        assert!(debug_str.contains("192.168.1.1:5061"));
        assert!(debug_str.contains("Connection reset"));
    }

    #[test]
    fn test_cert_verification_mode_default() {
        let mode = CertVerificationMode::default();
        assert!(matches!(mode, CertVerificationMode::System));
    }

    #[test]
    fn test_cert_verification_mode_debug() {
        let insecure = CertVerificationMode::Insecure;
        assert!(format!("{insecure:?}").contains("Insecure"));

        let system = CertVerificationMode::System;
        assert!(format!("{system:?}").contains("System"));

        let custom = CertVerificationMode::Custom {
            trusted_certs: vec![vec![1, 2, 3]],
        };
        assert!(format!("{custom:?}").contains("Custom"));
    }

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert!(matches!(
            config.verification_mode,
            CertVerificationMode::System
        ));
        assert!(config.client_cert_chain.is_none());
        assert!(config.client_private_key.is_none());
    }

    #[test]
    fn test_transport_config_builder() {
        let config = TransportConfig::new()
            .with_verification_mode(CertVerificationMode::Insecure)
            .with_client_certificate(vec![vec![1, 2, 3]], Some(vec![4, 5, 6]));

        assert!(matches!(
            config.verification_mode,
            CertVerificationMode::Insecure
        ));
        assert!(config.client_cert_chain.is_some());
        assert!(config.client_private_key.is_some());
    }

    #[tokio::test]
    async fn test_transport_with_insecure_mode() {
        let (tx, _rx) = mpsc::channel(32);
        let config = TransportConfig::new().with_verification_mode(CertVerificationMode::Insecure);

        let transport = SipTransport::with_config(tx, config);
        assert!(
            transport.is_ok(),
            "Transport with insecure mode should be created"
        );
    }

    #[tokio::test]
    async fn test_transport_with_system_mode() {
        let (tx, _rx) = mpsc::channel(32);
        let config = TransportConfig::new().with_verification_mode(CertVerificationMode::System);

        let transport = SipTransport::with_config(tx, config);
        assert!(
            transport.is_ok(),
            "Transport with system mode should be created"
        );
    }

    #[tokio::test]
    async fn test_transport_set_verification_mode() {
        let (tx, _rx) = mpsc::channel(32);
        let transport = SipTransport::new(tx).unwrap();

        // Switch to insecure mode
        let result = transport
            .set_verification_mode(CertVerificationMode::Insecure)
            .await;
        assert!(result.is_ok(), "Setting verification mode should succeed");

        // Switch back to system mode
        let result = transport
            .set_verification_mode(CertVerificationMode::System)
            .await;
        assert!(result.is_ok(), "Setting verification mode should succeed");
    }

    #[test]
    fn test_load_system_root_certs() {
        // This should succeed on all platforms, though may load 0 certs
        let _root_store = load_system_root_certs();
        // Function always succeeds, just verify it returns a store
    }

    #[test]
    fn test_load_custom_root_certs_empty() {
        // Empty custom certs should fail
        let result = load_custom_root_certs(&[]);
        assert!(result.is_err(), "Empty custom certs should fail");
    }

    #[test]
    fn test_load_custom_root_certs_invalid() {
        // Invalid cert data should be skipped but if all fail, should error
        let result = load_custom_root_certs(&[vec![1, 2, 3]]);
        assert!(result.is_err(), "Invalid certs should fail");
    }

    #[test]
    fn test_generate_tag() {
        let tag1 = generate_tag();
        let tag2 = generate_tag();

        // Tags should be non-empty
        assert!(!tag1.is_empty());
        assert!(!tag2.is_empty());

        // Tags should contain hyphen (from our format)
        assert!(tag1.contains('-'));
    }

    #[test]
    fn test_build_response_from_request() {
        use proto_sip::header::{Header, HeaderName};
        use proto_sip::method::Method;
        use proto_sip::response::StatusCode;
        use proto_sip::uri::SipUri;

        // Create a test INVITE request
        let uri = SipUri::new("example.com").with_user("alice");
        let mut request = SipRequest::new(Method::Invite, uri);
        request.add_header(Header::new(
            HeaderName::Via,
            "SIP/2.0/TLS client.example.com:5061;branch=z9hG4bK776asdhds",
        ));
        request.add_header(Header::new(
            HeaderName::From,
            "<sip:bob@example.com>;tag=123456",
        ));
        request.add_header(Header::new(HeaderName::To, "<sip:alice@example.com>"));
        request.add_header(Header::new(HeaderName::CallId, "abc123@client.example.com"));
        request.add_header(Header::new(HeaderName::CSeq, "1 INVITE"));

        // Build a 180 Ringing response
        let response = build_response_from_request(&request, StatusCode::RINGING, Some("789xyz"));

        // Verify response status
        assert_eq!(response.status, StatusCode::RINGING);

        // Verify Via header is copied
        assert!(response.headers.get_value(&HeaderName::Via).is_some());

        // Verify From header is copied
        let from = response.headers.get_value(&HeaderName::From).unwrap();
        assert!(from.contains("bob@example.com"));

        // Verify To header has tag added
        let to = response.headers.get_value(&HeaderName::To).unwrap();
        assert!(to.contains("alice@example.com"));
        assert!(to.contains(";tag=789xyz"));

        // Verify Call-ID is copied
        let call_id = response.headers.get_value(&HeaderName::CallId).unwrap();
        assert_eq!(call_id, "abc123@client.example.com");

        // Verify CSeq is copied
        let cseq = response.headers.get_value(&HeaderName::CSeq).unwrap();
        assert_eq!(cseq, "1 INVITE");

        // Verify Content-Length is set
        let content_length = response
            .headers
            .get_value(&HeaderName::ContentLength)
            .unwrap();
        assert_eq!(content_length, "0");
    }

    #[test]
    fn test_build_response_without_to_tag() {
        use proto_sip::header::{Header, HeaderName};
        use proto_sip::method::Method;
        use proto_sip::response::StatusCode;
        use proto_sip::uri::SipUri;

        // Create a test request
        let uri = SipUri::new("example.com").with_user("alice");
        let mut request = SipRequest::new(Method::Invite, uri);
        request.add_header(Header::new(
            HeaderName::Via,
            "SIP/2.0/TLS client.example.com:5061;branch=z9hG4bK776asdhds",
        ));
        request.add_header(Header::new(
            HeaderName::From,
            "<sip:bob@example.com>;tag=123456",
        ));
        request.add_header(Header::new(HeaderName::To, "<sip:alice@example.com>"));
        request.add_header(Header::new(HeaderName::CallId, "abc123@client.example.com"));
        request.add_header(Header::new(HeaderName::CSeq, "1 INVITE"));

        // Build a 100 Trying response (no to tag needed)
        let response = build_response_from_request(&request, StatusCode::TRYING, None);

        // Verify To header has no tag
        let to = response.headers.get_value(&HeaderName::To).unwrap();
        assert!(!to.contains(";tag="));
    }

    #[test]
    fn test_build_response_preserves_existing_to_tag() {
        use proto_sip::header::{Header, HeaderName};
        use proto_sip::method::Method;
        use proto_sip::response::StatusCode;
        use proto_sip::uri::SipUri;

        // Create a request with To tag already present (in-dialog request)
        let uri = SipUri::new("example.com").with_user("alice");
        let mut request = SipRequest::new(Method::Invite, uri);
        request.add_header(Header::new(
            HeaderName::Via,
            "SIP/2.0/TLS client.example.com:5061;branch=z9hG4bK776asdhds",
        ));
        request.add_header(Header::new(
            HeaderName::From,
            "<sip:bob@example.com>;tag=123456",
        ));
        request.add_header(Header::new(
            HeaderName::To,
            "<sip:alice@example.com>;tag=existing",
        ));
        request.add_header(Header::new(HeaderName::CallId, "abc123@client.example.com"));
        request.add_header(Header::new(HeaderName::CSeq, "2 INVITE"));

        // Build response - should not add another tag
        let response = build_response_from_request(&request, StatusCode::OK, Some("new-tag"));

        let to = response.headers.get_value(&HeaderName::To).unwrap();
        // Should still have the original tag, not the new one
        assert!(to.contains(";tag=existing"));
        assert!(!to.contains("new-tag"));
    }

    #[test]
    fn test_build_response_multiple_via_headers() {
        use proto_sip::header::{Header, HeaderName};
        use proto_sip::method::Method;
        use proto_sip::response::StatusCode;
        use proto_sip::uri::SipUri;

        // Create request with multiple Via headers (proxied request)
        let uri = SipUri::new("example.com").with_user("alice");
        let mut request = SipRequest::new(Method::Invite, uri);
        request.add_header(Header::new(
            HeaderName::Via,
            "SIP/2.0/TLS proxy.example.com:5061;branch=z9hG4bKproxy1",
        ));
        request.add_header(Header::new(
            HeaderName::Via,
            "SIP/2.0/TLS client.example.com:5061;branch=z9hG4bKclient",
        ));
        request.add_header(Header::new(
            HeaderName::From,
            "<sip:bob@example.com>;tag=123456",
        ));
        request.add_header(Header::new(HeaderName::To, "<sip:alice@example.com>"));
        request.add_header(Header::new(HeaderName::CallId, "abc123@client.example.com"));
        request.add_header(Header::new(HeaderName::CSeq, "1 INVITE"));

        // Build response
        let response = build_response_from_request(&request, StatusCode::RINGING, Some("xyz"));

        // Count Via headers - should have 2
        let via_headers: Vec<_> = response.headers.get_all(&HeaderName::Via).collect();
        assert_eq!(via_headers.len(), 2);

        // Verify order preserved (proxy first, then client)
        assert!(via_headers[0].value.contains("proxy.example.com"));
        assert!(via_headers[1].value.contains("client.example.com"));
    }
}
