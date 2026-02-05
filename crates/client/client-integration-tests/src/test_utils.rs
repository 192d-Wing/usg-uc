//! Test utilities and mock implementations for integration tests.

use client_types::{CertificateInfo, SipAccount};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::info;

/// Counter for generating unique test IDs.
#[allow(dead_code)]
static TEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a unique ID for test purposes.
#[allow(dead_code)]
fn generate_test_id() -> String {
    let id = TEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:016x}{:016x}", timestamp, id)
}

/// Initialize tracing for tests (call once per test module).
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("client=debug,client_integration_tests=debug")
        .with_test_writer()
        .try_init();
}

/// Creates a test SIP account for integration testing.
pub fn test_account() -> SipAccount {
    SipAccount::new(
        "test-account",
        "Test User",
        "sips:testuser@example.com",
        "sips:192.168.1.1:5061",
    )
}

/// Creates a test SIP account with a specific registrar address.
pub fn test_account_with_registrar(registrar_addr: SocketAddr) -> SipAccount {
    SipAccount::new(
        "test-account",
        "Test User",
        "sips:testuser@example.com",
        format!("sips:{}", registrar_addr),
    )
}

/// Creates a test certificate info matching the stub data.
pub fn test_certificate_info() -> CertificateInfo {
    CertificateInfo {
        thumbprint: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2".to_string(),
        subject_cn: "John Doe (CAC)".to_string(),
        subject_dn: "CN=John Doe, OU=Users, O=US Government, C=US".to_string(),
        issuer_cn: "DOD ID CA-59".to_string(),
        issuer_dn: "CN=DOD ID CA-59, OU=PKI, OU=DoD, O=U.S. Government, C=US".to_string(),
        not_before: "2024-01-01".to_string(),
        not_after: "2027-01-01".to_string(),
        is_valid: true,
        reader_name: Some("SCM Microsystems Inc. SCR331 0".to_string()),
        key_algorithm: "ECDSA P-384".to_string(),
        extended_key_usage: vec![
            "1.3.6.1.4.1.311.20.2.2".to_string(), // Smart Card Logon
            "1.3.6.1.5.5.7.3.2".to_string(),      // Client Auth
        ],
        has_smart_card_logon: true,
        has_client_auth: true,
    }
}

/// Allocates a random available port for testing.
pub async fn allocate_test_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap().port()
}

/// Allocates a test socket address.
pub async fn allocate_test_addr() -> SocketAddr {
    let port = allocate_test_port().await;
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Mock SIP server for integration testing.
///
/// Simulates basic SIP server responses for testing registration
/// and call flows without a real server.
#[allow(dead_code)]
pub struct MockSipServer {
    /// Server socket address.
    pub addr: SocketAddr,
    /// UDP socket for receiving/sending messages.
    socket: Arc<UdpSocket>,
    /// Channel for received messages.
    rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    /// Shutdown signal.
    shutdown_tx: mpsc::Sender<()>,
    /// Whether server is running.
    running: Arc<Mutex<bool>>,
}

#[allow(dead_code)]
impl MockSipServer {
    /// Creates and starts a new mock SIP server.
    pub async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let socket = Arc::new(socket);

        let (msg_tx, rx) = mpsc::channel(64);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let running = Arc::new(Mutex::new(true));

        // Spawn receiver task
        let recv_socket = socket.clone();
        let recv_running = running.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    result = recv_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                let data = buf[..len].to_vec();
                                let _ = msg_tx.send((data, src)).await;
                            }
                            Err(e) => {
                                if *recv_running.lock().await {
                                    info!("Mock server recv error: {}", e);
                                }
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        info!(addr = %addr, "Mock SIP server started");

        Self {
            addr,
            socket,
            rx,
            shutdown_tx,
            running,
        }
    }

    /// Receives the next SIP message.
    pub async fn recv(&mut self) -> Option<(String, SocketAddr)> {
        self.rx.recv().await.map(|(data, src)| {
            let msg = String::from_utf8_lossy(&data).to_string();
            (msg, src)
        })
    }

    /// Sends a SIP response.
    pub async fn send(&self, response: &str, dest: SocketAddr) {
        let _ = self.socket.send_to(response.as_bytes(), dest).await;
    }

    /// Creates a 200 OK response for REGISTER.
    pub fn register_200_ok(request: &str, contact: &str) -> String {
        // Extract Via, From, To, Call-ID, CSeq from request
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 200 OK\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to};tag=server-tag-123\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             Contact: {contact}\r\n\
             Expires: 3600\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Creates a 401 Unauthorized response.
    pub fn register_401_unauthorized(request: &str) -> String {
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 401 Unauthorized\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to};tag=server-tag-456\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", algorithm=SHA-256\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Creates a 180 Ringing response for INVITE.
    pub fn invite_180_ringing(request: &str) -> String {
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 180 Ringing\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to};tag=callee-tag-789\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Creates a 200 OK response for INVITE with SDP answer.
    pub fn invite_200_ok(request: &str, sdp_answer: &str) -> String {
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 200 OK\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to};tag=callee-tag-789\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             Contact: <sips:callee@192.168.1.200:5061>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            sdp_answer.len(),
            sdp_answer
        )
    }

    /// Creates a basic SDP answer for testing.
    pub fn basic_sdp_answer(media_port: u16, ice_ufrag: &str, ice_pwd: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 1234567890 1 IN IP4 192.168.1.200\r\n\
             s=USG SIP Server\r\n\
             c=IN IP4 192.168.1.200\r\n\
             t=0 0\r\n\
             m=audio {media_port} UDP/TLS/RTP/SAVPF 111 0 8\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=ice-ufrag:{ice_ufrag}\r\n\
             a=ice-pwd:{ice_pwd}\r\n\
             a=fingerprint:sha-384 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD\r\n\
             a=setup:active\r\n\
             a=mid:audio\r\n\
             a=sendrecv\r\n\
             a=rtcp-mux\r\n"
        )
    }

    /// Creates an INVITE request for simulating incoming calls.
    pub fn create_invite_request(
        caller_uri: &str,
        caller_display: &str,
        callee_uri: &str,
        target_addr: SocketAddr,
        call_id: &str,
        sdp_offer: &str,
    ) -> String {
        let branch = format!("z9hG4bK-{}", generate_test_id());
        let from_tag = format!("from-{}", generate_test_id());

        format!(
            "INVITE {callee_uri} SIP/2.0\r\n\
             Via: SIP/2.0/TLS {target_addr};branch={branch}\r\n\
             Max-Forwards: 70\r\n\
             From: \"{caller_display}\" <{caller_uri}>;tag={from_tag}\r\n\
             To: <{callee_uri}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <{caller_uri}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {sdp_offer}",
            sdp_offer.len()
        )
    }

    /// Creates a basic SDP offer for incoming call simulation.
    pub fn basic_sdp_offer(media_port: u16, ice_ufrag: &str, ice_pwd: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 9876543210 1 IN IP4 192.168.1.100\r\n\
             s=USG SIP Client\r\n\
             c=IN IP4 192.168.1.100\r\n\
             t=0 0\r\n\
             m=audio {media_port} UDP/TLS/RTP/SAVPF 111 0 8\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=ice-ufrag:{ice_ufrag}\r\n\
             a=ice-pwd:{ice_pwd}\r\n\
             a=fingerprint:sha-384 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55\r\n\
             a=setup:actpass\r\n\
             a=mid:audio\r\n\
             a=sendrecv\r\n\
             a=rtcp-mux\r\n"
        )
    }

    /// Creates a 100 Trying response for INVITE.
    pub fn invite_100_trying(request: &str) -> String {
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 100 Trying\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Creates a 486 Busy Here response for INVITE.
    pub fn invite_486_busy(request: &str) -> String {
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 486 Busy Here\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to};tag=reject-tag-123\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Creates a 603 Decline response for INVITE.
    pub fn invite_603_decline(request: &str) -> String {
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 603 Decline\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to};tag=decline-tag-456\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Creates a BYE request for call termination.
    pub fn create_bye_request(
        caller_uri: &str,
        callee_uri: &str,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        target_addr: SocketAddr,
    ) -> String {
        let branch = format!("z9hG4bK-{}", generate_test_id());

        format!(
            "BYE {callee_uri} SIP/2.0\r\n\
             Via: SIP/2.0/TLS {target_addr};branch={branch}\r\n\
             Max-Forwards: 70\r\n\
             From: <{caller_uri}>;tag={from_tag}\r\n\
             To: <{callee_uri}>;tag={to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 2 BYE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Creates a 200 OK response for BYE.
    pub fn bye_200_ok(request: &str) -> String {
        let via = extract_header(request, "Via:");
        let from = extract_header(request, "From:");
        let to = extract_header(request, "To:");
        let call_id = extract_header(request, "Call-ID:");
        let cseq = extract_header(request, "CSeq:");

        format!(
            "SIP/2.0 200 OK\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq}\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
    }

    /// Sends an INVITE to simulate an incoming call.
    pub async fn send_incoming_invite(
        &self,
        dest: SocketAddr,
        caller_uri: &str,
        caller_display: &str,
        callee_uri: &str,
        call_id: &str,
    ) {
        let sdp = Self::basic_sdp_offer(5004, "caller-ufrag", "caller-password-here");
        let invite = Self::create_invite_request(
            caller_uri,
            caller_display,
            callee_uri,
            self.addr,
            call_id,
            &sdp,
        );
        self.send(&invite, dest).await;
    }

    /// Stops the mock server.
    pub async fn stop(&mut self) {
        *self.running.lock().await = false;
        let _ = self.shutdown_tx.send(()).await;
    }
}

/// Extracts a header value from a SIP message.
fn extract_header(message: &str, header: &str) -> String {
    for line in message.lines() {
        if line.starts_with(header) {
            return line[header.len()..].trim().to_string();
        }
        // Handle case-insensitive match
        if line.to_lowercase().starts_with(&header.to_lowercase()) {
            return line[header.len()..].trim().to_string();
        }
    }
    String::new()
}

/// Waits for a condition with timeout.
#[allow(dead_code)]
pub async fn wait_for<F, Fut>(timeout_ms: u64, mut condition: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    while start.elapsed() < timeout {
        if condition().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_starts() {
        init_test_tracing();
        let mut server = MockSipServer::start().await;
        assert_ne!(server.addr.port(), 0);
        server.stop().await;
    }

    #[tokio::test]
    async fn test_extract_header() {
        let request = "REGISTER sips:example.com SIP/2.0\r\n\
                       Via: SIP/2.0/TLS 192.168.1.100:5061\r\n\
                       From: <sips:alice@example.com>;tag=abc123\r\n\
                       To: <sips:alice@example.com>\r\n\
                       Call-ID: 12345@192.168.1.100\r\n\
                       CSeq: 1 REGISTER\r\n";

        assert_eq!(extract_header(request, "Call-ID:"), "12345@192.168.1.100");
        assert_eq!(extract_header(request, "CSeq:"), "1 REGISTER");
    }

    #[tokio::test]
    async fn test_register_200_ok() {
        let request = "REGISTER sips:example.com SIP/2.0\r\n\
                       Via: SIP/2.0/TLS 192.168.1.100:5061\r\n\
                       From: <sips:alice@example.com>;tag=abc123\r\n\
                       To: <sips:alice@example.com>\r\n\
                       Call-ID: 12345@192.168.1.100\r\n\
                       CSeq: 1 REGISTER\r\n";

        let response = MockSipServer::register_200_ok(request, "<sips:alice@192.168.1.100:5061>");

        assert!(response.starts_with("SIP/2.0 200 OK"));
        assert!(response.contains("Call-ID: 12345@192.168.1.100"));
        assert!(response.contains("Expires: 3600"));
    }

    #[test]
    fn test_test_account() {
        let account = test_account();
        assert_eq!(account.id, "test-account");
        assert_eq!(account.domain(), Some("example.com"));
    }
}
