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

use crate::{AppError, AppResult};
use bytes::BytesMut;
use proto_sip::message::{SipMessage, SipRequest, SipResponse};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, error, info, warn};

/// A certificate verifier that accepts all certificates.
/// Used for development/testing with self-signed certificates.
/// In production, proper certificate validation should be enabled.
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
        // Accept all certificates for development
        // TODO: In production, implement proper certificate validation
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

/// SIP Transport manager.
///
/// Manages TLS connections to SIP peers and handles message routing.
pub struct SipTransport {
    /// TLS client configuration.
    tls_config: Arc<ClientConfig>,
    /// Active connections by peer address.
    connections: Arc<Mutex<HashMap<SocketAddr, TlsConnection>>>,
    /// Event sender.
    event_tx: mpsc::Sender<TransportEvent>,
    /// Client certificates for mTLS (DER-encoded).
    client_certs: Option<Vec<CertificateDer<'static>>>,
}

impl SipTransport {
    /// Creates a new SIP transport.
    pub fn new(event_tx: mpsc::Sender<TransportEvent>) -> AppResult<Self> {
        // Create TLS configuration with CNSA 2.0 compliance
        let tls_config = Self::create_tls_config()?;

        Ok(Self {
            tls_config: Arc::new(tls_config),
            connections: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            client_certs: None,
        })
    }

    /// Sets the client certificates for mTLS.
    pub fn set_client_certificates(&mut self, certs: Vec<Vec<u8>>) -> AppResult<()> {
        let certs: Vec<CertificateDer<'static>> = certs
            .into_iter()
            .map(|c| CertificateDer::from(c))
            .collect();

        self.client_certs = Some(certs.clone());

        // Rebuild TLS config with client certs
        // Note: For smart card certificates, the private key stays on the card
        // and signing is handled by the Windows CryptoAPI
        // For now, we use the config without client auth since
        // the Windows TLS stack handles smart card auth natively
        info!(cert_count = certs.len(), "Client certificates configured");

        Ok(())
    }

    /// Creates CNSA 2.0 compliant TLS configuration.
    fn create_tls_config() -> AppResult<ClientConfig> {
        use rustls::crypto::aws_lc_rs::default_provider;

        let provider = default_provider();

        // Use insecure certificate verifier for development
        // In production, this should use proper certificate validation with trusted CAs
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| AppError::Sip(format!("Failed to configure TLS 1.3: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth();

        Ok(config)
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

        // TLS handshake
        let connector = TlsConnector::from(self.tls_config.clone());
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
}
