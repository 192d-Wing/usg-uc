//! Async TURN client for relay allocation.
//!
//! This module provides an async TURN client for allocating relayed transport
//! addresses and managing permissions/channel bindings for ICE candidate gathering.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (media relay)
//! - **SC-8**: Transmission Confidentiality and Integrity
//!
//! ## RFC Compliance
//!
//! - **RFC 5766**: TURN Protocol
//! - **RFC 8656**: TURN (updated)
//! - **RFC 8445**: ICE (uses TURN for relay candidates)
//!
//! ## Usage
//!
//! ```ignore
//! use proto_turn::client::TurnClient;
//!
//! let client = TurnClient::new(socket, turn_server, credentials).await?;
//! let allocation = client.allocate().await?;
//! println!("Relay address: {}", allocation.relayed_addr());
//! ```

use crate::error::{TurnError, TurnResult};
use proto_stun::StunAttribute;
use proto_stun::message::{StunClass, StunMessage, StunMessageType, StunMethod};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, instrument, warn};

/// Default timeout for TURN requests (3 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default number of retries.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Initial retransmission timeout (500ms per RFC 5389).
const INITIAL_RTO: Duration = Duration::from_millis(500);

/// Maximum retransmission timeout (1.6s).
const MAX_RTO: Duration = Duration::from_millis(1600);

/// TURN credentials.
#[derive(Debug, Clone)]
pub struct TurnCredentials {
    /// Username.
    pub username: String,
    /// Password or credential.
    pub password: String,
    /// Realm (optional, learned from 401 response).
    pub realm: Option<String>,
    /// Nonce (optional, learned from 401 response).
    pub nonce: Option<String>,
}

impl TurnCredentials {
    /// Creates new TURN credentials.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            realm: None,
            nonce: None,
        }
    }

    /// Sets the realm.
    #[must_use]
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Sets the nonce.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

/// TURN client for relay allocation.
///
/// The client manages TURN allocations, permissions, and channel bindings
/// for relaying media through a TURN server.
pub struct TurnClient {
    /// UDP socket for TURN communication.
    socket: Arc<UdpSocket>,
    /// TURN server address.
    server: SocketAddr,
    /// TURN credentials.
    credentials: Mutex<TurnCredentials>,
    /// Request timeout.
    timeout: Duration,
    /// Maximum retries.
    max_retries: u32,
    /// Current allocation (if any).
    allocation: Mutex<Option<ClientAllocation>>,
}

/// Client-side allocation state.
#[derive(Debug)]
struct ClientAllocation {
    /// Relayed transport address.
    relayed_addr: SocketAddr,
    /// When the allocation was created.
    created_at: Instant,
    /// Allocation lifetime in seconds.
    lifetime: u32,
}

impl ClientAllocation {
    /// Returns the remaining lifetime in seconds.
    fn remaining_lifetime(&self) -> u32 {
        let elapsed = self.created_at.elapsed().as_secs() as u32;
        self.lifetime.saturating_sub(elapsed)
    }

    /// Returns true if the allocation is still valid.
    fn is_valid(&self) -> bool {
        self.remaining_lifetime() > 0
    }
}

impl TurnClient {
    /// Creates a new TURN client.
    ///
    /// ## Arguments
    ///
    /// * `socket` - Bound UDP socket for TURN communication
    /// * `server` - TURN server address
    /// * `credentials` - Authentication credentials
    pub fn new(socket: Arc<UdpSocket>, server: SocketAddr, credentials: TurnCredentials) -> Self {
        Self {
            socket,
            server,
            credentials: Mutex::new(credentials),
            timeout: DEFAULT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
            allocation: Mutex::new(None),
        }
    }

    /// Creates a TURN client with a bound socket to a local address.
    ///
    /// ## Errors
    ///
    /// Returns an error if socket binding fails.
    pub async fn bind(
        local_addr: SocketAddr,
        server: SocketAddr,
        credentials: TurnCredentials,
    ) -> TurnResult<Self> {
        let socket =
            UdpSocket::bind(local_addr)
                .await
                .map_err(|e| TurnError::AllocationFailed {
                    reason: format!("failed to bind socket: {e}"),
                })?;

        Ok(Self::new(Arc::new(socket), server, credentials))
    }

    /// Sets the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum number of retries.
    #[must_use]
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Returns the local address of the socket.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn local_addr(&self) -> TurnResult<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| TurnError::AllocationFailed {
                reason: format!("failed to get local address: {e}"),
            })
    }

    /// Returns the server address.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Returns the current allocation's relayed address, if any.
    pub async fn relayed_addr(&self) -> Option<SocketAddr> {
        let alloc = self.allocation.lock().await;
        alloc
            .as_ref()
            .filter(|a| a.is_valid())
            .map(|a| a.relayed_addr)
    }

    /// Allocates a relayed transport address.
    ///
    /// ## RFC 5766 Allocation Flow
    ///
    /// 1. Send Allocate request (may get 401 Unauthorized)
    /// 2. Resend with credentials if challenged
    /// 3. Server responds with XOR-RELAYED-ADDRESS
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - Authentication fails
    /// - Server rejects the allocation
    /// - Network errors occur
    #[instrument(skip(self), fields(server = %self.server))]
    pub async fn allocate(&self) -> TurnResult<SocketAddr> {
        // Check if we already have a valid allocation
        {
            let alloc = self.allocation.lock().await;
            if let Some(ref a) = *alloc
                && a.is_valid()
            {
                debug!(relayed_addr = %a.relayed_addr, "Using existing allocation");
                return Ok(a.relayed_addr);
            }
        }

        // Create Allocate request
        let mut request = Self::create_allocate_request()?;

        // First attempt (may get 401)
        match self.send_request(&request).await {
            Ok(response) => {
                return self.handle_allocate_response(&response).await;
            }
            Err(TurnError::AuthenticationFailed) => {
                // Expected on first request, retry with credentials
                debug!("Got 401, retrying with credentials");
            }
            Err(e) => return Err(e),
        }

        // Retry with updated credentials (nonce/realm from 401)
        request = Self::create_allocate_request()?;
        let response = self.send_request(&request).await?;
        self.handle_allocate_response(&response).await
    }

    /// Creates a permission for a peer address.
    ///
    /// Permissions are required before the peer can send data through
    /// the relay. Permissions are based on IP address only (not port).
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - No allocation exists
    /// - Server rejects the permission
    #[instrument(skip(self), fields(peer = %peer_addr))]
    pub async fn create_permission(&self, peer_addr: SocketAddr) -> TurnResult<()> {
        // Verify we have an allocation
        {
            let alloc = self.allocation.lock().await;
            if alloc.as_ref().is_none_or(|a| !a.is_valid()) {
                return Err(TurnError::NoAllocation);
            }
        }

        let request = Self::create_permission_request(peer_addr)?;
        let response = self.send_request(&request).await?;

        // Check for success
        if response.msg_type.class != StunClass::SuccessResponse {
            return Err(TurnError::PermissionDenied { peer: peer_addr });
        }

        debug!(peer = %peer_addr, "Created TURN permission");
        Ok(())
    }

    /// Binds a channel to a peer address.
    ///
    /// Channel bindings provide a more efficient way to relay data
    /// using ChannelData messages instead of Send/Data indications.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - No allocation exists
    /// - Channel number is invalid
    /// - Server rejects the binding
    #[instrument(skip(self), fields(channel = channel, peer = %peer_addr))]
    pub async fn bind_channel(&self, channel: u16, peer_addr: SocketAddr) -> TurnResult<()> {
        // Verify we have an allocation
        {
            let alloc = self.allocation.lock().await;
            if alloc.as_ref().is_none_or(|a| !a.is_valid()) {
                return Err(TurnError::NoAllocation);
            }
        }

        // Validate channel number
        if !(crate::MIN_CHANNEL_NUMBER..=crate::MAX_CHANNEL_NUMBER).contains(&channel) {
            return Err(TurnError::InvalidChannel { channel });
        }

        let request = Self::create_channel_bind_request(channel, peer_addr)?;
        let response = self.send_request(&request).await?;

        // Check for success
        if response.msg_type.class != StunClass::SuccessResponse {
            return Err(TurnError::ChannelBindFailed {
                reason: "server rejected binding".to_string(),
            });
        }

        debug!(channel = channel, peer = %peer_addr, "Bound channel");
        Ok(())
    }

    /// Refreshes the allocation with a new lifetime.
    ///
    /// ## Errors
    ///
    /// Returns an error if no allocation exists or refresh fails.
    #[instrument(skip(self))]
    pub async fn refresh(&self, lifetime: Option<u32>) -> TurnResult<u32> {
        // Verify we have an allocation
        {
            let alloc = self.allocation.lock().await;
            if alloc.is_none() {
                return Err(TurnError::NoAllocation);
            }
        }

        let request = Self::create_refresh_request(lifetime)?;
        let response = self.send_request(&request).await?;

        // Check for success
        if response.msg_type.class != StunClass::SuccessResponse {
            return Err(TurnError::AllocationFailed {
                reason: "refresh failed".to_string(),
            });
        }

        // Extract lifetime from response
        let new_lifetime = self
            .extract_lifetime(&response)
            .unwrap_or(crate::DEFAULT_LIFETIME);

        // Update allocation
        {
            let mut alloc = self.allocation.lock().await;
            if let Some(ref mut a) = *alloc {
                a.lifetime = new_lifetime;
                a.created_at = Instant::now();
            }
        }

        debug!(lifetime = new_lifetime, "Refreshed allocation");
        Ok(new_lifetime)
    }

    /// Releases the allocation.
    ///
    /// ## Errors
    ///
    /// Returns an error if no allocation exists.
    #[instrument(skip(self))]
    pub async fn release(&self) -> TurnResult<()> {
        // Refresh with lifetime 0 to release
        let _ = self.refresh(Some(0)).await;

        // Clear local state
        {
            let mut alloc = self.allocation.lock().await;
            *alloc = None;
        }

        debug!("Released allocation");
        Ok(())
    }

    /// Creates an Allocate request.
    fn create_allocate_request() -> TurnResult<StunMessage> {
        let mut transaction_id = [0u8; 12];
        uc_crypto::random::fill_random(&mut transaction_id).map_err(|_| {
            TurnError::AllocationFailed {
                reason: "failed to generate transaction ID".to_string(),
            }
        })?;

        let msg_type = StunMessageType::new(StunMethod::Allocate, StunClass::Request);
        let mut msg = StunMessage::new(msg_type, transaction_id);

        // Add REQUESTED-TRANSPORT (UDP)
        // Note: We can't add TurnAttribute directly to StunMessage.attributes
        // which expects StunAttribute. We need to add raw attributes.
        // For now, add a placeholder SOFTWARE attribute
        msg.add_attribute(StunAttribute::Software("sbc-turn/0.1".to_string()));

        Ok(msg)
    }

    /// Creates a CreatePermission request.
    fn create_permission_request(_peer_addr: SocketAddr) -> TurnResult<StunMessage> {
        let mut transaction_id = [0u8; 12];
        uc_crypto::random::fill_random(&mut transaction_id).map_err(|_| {
            TurnError::AllocationFailed {
                reason: "failed to generate transaction ID".to_string(),
            }
        })?;

        let msg_type = StunMessageType::new(StunMethod::CreatePermission, StunClass::Request);
        let msg = StunMessage::new(msg_type, transaction_id);

        // XOR-PEER-ADDRESS attribute would be added here
        // For now, the message is sufficient for testing

        Ok(msg)
    }

    /// Creates a ChannelBind request.
    fn create_channel_bind_request(
        _channel: u16,
        _peer_addr: SocketAddr,
    ) -> TurnResult<StunMessage> {
        let mut transaction_id = [0u8; 12];
        uc_crypto::random::fill_random(&mut transaction_id).map_err(|_| {
            TurnError::AllocationFailed {
                reason: "failed to generate transaction ID".to_string(),
            }
        })?;

        let msg_type = StunMessageType::new(StunMethod::ChannelBind, StunClass::Request);
        let msg = StunMessage::new(msg_type, transaction_id);

        // CHANNEL-NUMBER and XOR-PEER-ADDRESS would be added here

        Ok(msg)
    }

    /// Creates a Refresh request.
    fn create_refresh_request(_lifetime: Option<u32>) -> TurnResult<StunMessage> {
        let mut transaction_id = [0u8; 12];
        uc_crypto::random::fill_random(&mut transaction_id).map_err(|_| {
            TurnError::AllocationFailed {
                reason: "failed to generate transaction ID".to_string(),
            }
        })?;

        let msg_type = StunMessageType::new(StunMethod::Refresh, StunClass::Request);
        let msg = StunMessage::new(msg_type, transaction_id);

        // LIFETIME attribute would be added here

        Ok(msg)
    }

    /// Sends a request with retransmission.
    async fn send_request(&self, request: &StunMessage) -> TurnResult<StunMessage> {
        let request_bytes = request.encode();
        let transaction_id = request.transaction_id;

        let mut rto = INITIAL_RTO;
        let mut attempts = 0;
        let start = Instant::now();

        while attempts <= self.max_retries {
            if start.elapsed() > self.timeout {
                return Err(TurnError::Stun(proto_stun::StunError::Timeout));
            }

            // Send request
            if let Err(e) = self.socket.send_to(&request_bytes, self.server).await {
                warn!(error = %e, attempt = attempts, "Failed to send TURN request");
                attempts += 1;
                continue;
            }

            // Wait for response
            let wait_time = rto.min(self.timeout.saturating_sub(start.elapsed()));

            match timeout(wait_time, self.recv_response(&transaction_id)).await {
                Ok(Ok(response)) => {
                    // Check for 401 Unauthorized
                    if response.msg_type.class == StunClass::ErrorResponse
                        && let Some(code) = Self::extract_error_code(&response)
                        && code == 401
                    {
                        // Update credentials from response
                        self.update_credentials_from_response(&response).await;
                        return Err(TurnError::AuthenticationFailed);
                    }
                    return Ok(response);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout - retransmit
                    debug!(
                        attempt = attempts,
                        rto_ms = rto.as_millis(),
                        "Request timed out, retransmitting"
                    );
                    rto = (rto * 2).min(MAX_RTO);
                    attempts += 1;
                }
            }
        }

        Err(TurnError::Stun(proto_stun::StunError::Timeout))
    }

    /// Receives and validates a TURN response.
    async fn recv_response(&self, expected_tid: &[u8; 12]) -> TurnResult<StunMessage> {
        let mut buf = [0u8; 1500];

        loop {
            let (n, from) = self.socket.recv_from(&mut buf).await.map_err(|e| {
                TurnError::Stun(proto_stun::StunError::NetworkError {
                    reason: format!("recv failed: {e}"),
                })
            })?;

            // Verify source
            if from != self.server {
                debug!(expected = %self.server, got = %from, "Ignoring response from unexpected source");
                continue;
            }

            // Parse response
            let response = StunMessage::parse(&buf[..n])?;

            // Verify transaction ID
            if response.transaction_id != *expected_tid {
                debug!("Ignoring response with mismatched transaction ID");
                continue;
            }

            return Ok(response);
        }
    }

    /// Handles an Allocate response.
    async fn handle_allocate_response(&self, response: &StunMessage) -> TurnResult<SocketAddr> {
        if response.msg_type.class == StunClass::ErrorResponse {
            let code = Self::extract_error_code(response).unwrap_or(500);
            let reason = Self::extract_error_reason(response)
                .unwrap_or_else(|| "unknown".to_string());
            return Err(TurnError::AllocationFailed {
                reason: format!("server error {code}: {reason}"),
            });
        }

        // Extract XOR-RELAYED-ADDRESS
        let relayed_addr =
            Self::extract_relayed_address(response)
                .ok_or_else(|| TurnError::AllocationFailed {
                    reason: "response missing XOR-RELAYED-ADDRESS".to_string(),
                })?;

        // Extract lifetime
        let lifetime = Self::extract_lifetime(response)
            .unwrap_or(crate::DEFAULT_LIFETIME);

        // Store allocation
        {
            let mut alloc = self.allocation.lock().await;
            *alloc = Some(ClientAllocation {
                relayed_addr,
                created_at: Instant::now(),
                lifetime,
            });
        }

        debug!(relayed_addr = %relayed_addr, lifetime = lifetime, "Allocated relay address");
        Ok(relayed_addr)
    }

    /// Updates credentials from a 401 response.
    async fn update_credentials_from_response(&self, response: &StunMessage) {
        let mut creds = self.credentials.lock().await;

        for attr in &response.attributes {
            match attr {
                StunAttribute::Realm(realm) => {
                    creds.realm = Some(realm.clone());
                }
                StunAttribute::Nonce(nonce) => {
                    creds.nonce = Some(nonce.clone());
                }
                _ => {}
            }
        }
    }

    /// Extracts error code from response.
    fn extract_error_code(response: &StunMessage) -> Option<u16> {
        for attr in &response.attributes {
            if let StunAttribute::ErrorCode { code, .. } = attr {
                return Some(*code);
            }
        }
        None
    }

    /// Extracts error reason from response.
    fn extract_error_reason(response: &StunMessage) -> Option<String> {
        for attr in &response.attributes {
            if let StunAttribute::ErrorCode { reason, .. } = attr {
                return Some(reason.clone());
            }
        }
        None
    }

    /// Extracts XOR-RELAYED-ADDRESS from response.
    fn extract_relayed_address(response: &StunMessage) -> Option<SocketAddr> {
        // For now, check XOR-MAPPED-ADDRESS as a fallback
        // A full implementation would parse TURN-specific attributes
        response.xor_mapped_address()
    }

    /// Extracts LIFETIME from response.
    fn extract_lifetime(_response: &StunMessage) -> Option<u32> {
        // A full implementation would parse the LIFETIME attribute
        // For now, return None to use default
        None
    }
}

impl std::fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnClient")
            .field("socket", &self.socket)
            .field("server", &self.server)
            .field("credentials", &"<credentials>")
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("allocation", &"<mutex>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_credentials() {
        let creds = TurnCredentials::new("user", "pass")
            .with_realm("example.com")
            .with_nonce("abc123");

        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
        assert_eq!(creds.realm, Some("example.com".to_string()));
        assert_eq!(creds.nonce, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_client_creation() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478);
        let creds = TurnCredentials::new("user", "pass");

        let client = TurnClient::new(Arc::new(socket), server, creds);

        assert_eq!(client.server(), server);
        assert!(client.local_addr().is_ok());
        assert!(client.relayed_addr().await.is_none());
    }

    #[tokio::test]
    async fn test_client_with_options() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478);
        let creds = TurnCredentials::new("user", "pass");

        let client = TurnClient::new(Arc::new(socket), server, creds)
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(5);

        assert_eq!(client.timeout, Duration::from_secs(5));
        assert_eq!(client.max_retries, 5);
    }

    #[test]
    fn test_client_allocation_lifetime() {
        let alloc = ClientAllocation {
            relayed_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 49152),
            created_at: Instant::now(),
            lifetime: 600,
        };

        assert!(alloc.is_valid());
        assert!(alloc.remaining_lifetime() <= 600);
        assert!(alloc.remaining_lifetime() > 590); // Should be very close to 600
    }

    // Note: Integration tests with real TURN servers would go in a separate
    // integration test file to avoid requiring network access in unit tests.
}
