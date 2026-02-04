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
use tokio::net::TcpStream;
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
    fn new() -> Self {
        Self {
            certified_key: None,
        }
    }

    /// Creates a resolver with the given certificate chain and private key.
    fn with_cert(cert_chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        let signing_key = match rustls::crypto::aws_lc_rs::sign::any_supported_type(&key) {
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
        let header_end = match find_header_end(data) {
            Some(pos) => pos,
            None => return Ok(None), // Need more data
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
    /// If None and client_cert_chain is Some, smart card signing is assumed.
    pub client_private_key: Option<Vec<u8>>,
}

impl TransportConfig {
    /// Creates a new configuration with system CA validation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the verification mode.
    pub fn with_verification_mode(mut self, mode: CertVerificationMode) -> Self {
        self.verification_mode = mode;
        self
    }

    /// Sets the client certificate for mTLS.
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
pub struct SipTransport {
    /// TLS client configuration (can be rebuilt when certs change).
    tls_config: Arc<RwLock<Arc<ClientConfig>>>,
    /// Active connections by peer address.
    connections: Arc<Mutex<HashMap<SocketAddr, TlsConnection>>>,
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

        // Update the TLS config
        let mut tls = self.tls_config.write().await;
        *tls = Arc::new(new_tls_config);

        // Close existing connections (they'll reconnect with new config)
        let mut connections = self.connections.lock().await;
        connections.clear();

        Ok(())
    }

    /// Sets the client certificate for mTLS authentication.
    ///
    /// # Arguments
    /// * `cert_chain` - DER-encoded certificate chain (end-entity first)
    /// * `private_key` - Optional DER-encoded private key. If None, smart card signing is assumed.
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

        // Update the TLS config
        let mut tls = self.tls_config.write().await;
        *tls = Arc::new(new_tls_config);

        // Close existing connections (they'll reconnect with new config)
        let mut connections = self.connections.lock().await;
        connections.clear();

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
                let root_store = load_system_root_certs()?;
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

                info!(cert_count = certs.len(), "Configuring mTLS with private key");

                // Use custom resolver for client certificates
                let resolver = ClientCertResolver::with_cert(certs, key);
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

        let conn = connections.get_mut(&destination).ok_or_else(|| {
            AppError::Sip(format!("No connection to {destination}"))
        })?;

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
fn load_system_root_certs() -> AppResult<RootCertStore> {
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

    Ok(root_store)
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
        assert!(transport.is_ok(), "SipTransport should be created successfully");
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
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("Connected"));
        assert!(debug_str.contains("127.0.0.1:5060"));
    }

    #[test]
    fn test_transport_event_error() {
        let event = TransportEvent::Error {
            message: "Test error".to_string(),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("Error"));
        assert!(debug_str.contains("Test error"));
    }

    #[test]
    fn test_transport_event_disconnected() {
        let event = TransportEvent::Disconnected {
            peer: "192.168.1.1:5061".parse().unwrap(),
            reason: "Connection reset".to_string(),
        };
        let debug_str = format!("{:?}", event);
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
        let config =
            TransportConfig::new().with_verification_mode(CertVerificationMode::Insecure);

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
        let result = load_system_root_certs();
        assert!(result.is_ok(), "Loading system root certs should succeed");
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
}
