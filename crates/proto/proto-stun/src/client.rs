//! Async STUN client for NAT discovery.
//!
//! This module provides an async STUN client for discovering server-reflexive
//! addresses (public IP addresses) for ICE candidate gathering.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (NAT discovery)
//!
//! ## RFC Compliance
//!
//! - **RFC 5389**: STUN Protocol
//! - **RFC 8489**: STUN (updated)
//! - **RFC 8445**: ICE (uses STUN for candidate gathering)
//!
//! ## Usage
//!
//! ```ignore
//! use proto_stun::client::StunClient;
//!
//! let client = StunClient::new(socket, stun_server).await?;
//! let public_addr = client.discover_srflx().await?;
//! println!("Public address: {}", public_addr);
//! ```

use crate::error::{StunError, StunResult};
use crate::message::StunMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};
use tracing::{debug, instrument, warn};

/// Default timeout for STUN requests (3 seconds per RFC 5389).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default number of retries (7 retries per RFC 5389 recommendation).
const DEFAULT_MAX_RETRIES: u32 = 7;

/// Initial retransmission timeout (500ms per RFC 5389).
const INITIAL_RTO: Duration = Duration::from_millis(500);

/// Maximum retransmission timeout (1.6s per RFC 5389 recommendation).
const MAX_RTO: Duration = Duration::from_millis(1600);

/// STUN client for NAT discovery.
///
/// The client sends STUN Binding requests to a STUN server and parses
/// the response to discover the server-reflexive (public) address.
pub struct StunClient {
    /// UDP socket for sending/receiving STUN messages.
    socket: Arc<UdpSocket>,
    /// STUN server address.
    server: SocketAddr,
    /// Request timeout.
    timeout: Duration,
    /// Maximum retries.
    max_retries: u32,
}

impl StunClient {
    /// Creates a new STUN client.
    ///
    /// ## Arguments
    ///
    /// * `socket` - Bound UDP socket for STUN communication
    /// * `server` - STUN server address (e.g., stun.l.google.com:19302)
    ///
    /// ## Example
    ///
    /// ```ignore
    /// let socket = UdpSocket::bind("0.0.0.0:0").await?;
    /// let client = StunClient::new(
    ///     Arc::new(socket),
    ///     "stun.l.google.com:19302".parse()?,
    /// );
    /// ```
    pub fn new(socket: Arc<UdpSocket>, server: SocketAddr) -> Self {
        Self {
            socket,
            server,
            timeout: DEFAULT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// Creates a STUN client with a bound socket to a local address.
    ///
    /// ## Errors
    ///
    /// Returns an error if socket binding fails.
    pub async fn bind(local_addr: SocketAddr, server: SocketAddr) -> StunResult<Self> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| StunError::NetworkError {
                reason: format!("failed to bind socket: {e}"),
            })?;

        Ok(Self::new(Arc::new(socket), server))
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
    pub fn local_addr(&self) -> StunResult<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| StunError::NetworkError {
                reason: format!("failed to get local address: {e}"),
            })
    }

    /// Returns the server address.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Discovers the server-reflexive address (public IP).
    ///
    /// Sends a STUN Binding request to the server and extracts the
    /// XOR-MAPPED-ADDRESS from the response.
    ///
    /// ## RFC 5389 Retransmission
    ///
    /// Implements the retransmission strategy from RFC 5389 Section 7.2.1:
    /// - Initial RTO: 500ms
    /// - Each retransmission doubles the RTO up to 1.6s max
    /// - Maximum 7 retransmissions
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - All retransmissions fail (timeout)
    /// - Server returns an error response
    /// - Response is malformed or missing XOR-MAPPED-ADDRESS
    #[instrument(skip(self), fields(server = %self.server))]
    pub async fn discover_srflx(&self) -> StunResult<SocketAddr> {
        let request = StunMessage::binding_request()?;
        let request_bytes = request.encode();
        let transaction_id = request.transaction_id;

        debug!(
            transaction_id = ?transaction_id,
            "Sending STUN Binding request"
        );

        let mut rto = INITIAL_RTO;
        let mut attempts = 0;
        let start = Instant::now();

        while attempts <= self.max_retries {
            if start.elapsed() > self.timeout {
                return Err(StunError::Timeout);
            }

            // Send request
            if let Err(e) = self.socket.send_to(&request_bytes, self.server).await {
                warn!(error = %e, attempt = attempts, "Failed to send STUN request");
                attempts += 1;
                continue;
            }

            // Wait for response with current RTO
            let wait_time = rto.min(self.timeout.saturating_sub(start.elapsed()));

            match timeout(wait_time, self.recv_response(&transaction_id)).await {
                Ok(Ok(addr)) => {
                    debug!(
                        srflx_addr = %addr,
                        attempts = attempts,
                        elapsed_ms = start.elapsed().as_millis(),
                        "Discovered server-reflexive address"
                    );
                    return Ok(addr);
                }
                Ok(Err(e)) => {
                    // Got a response but it was an error
                    return Err(e);
                }
                Err(_) => {
                    // Timeout - retransmit with doubled RTO
                    debug!(
                        attempt = attempts,
                        rto_ms = rto.as_millis(),
                        "STUN request timed out, retransmitting"
                    );
                    rto = (rto * 2).min(MAX_RTO);
                    attempts += 1;
                }
            }
        }

        Err(StunError::Timeout)
    }

    /// Receives and validates a STUN response.
    async fn recv_response(&self, expected_tid: &[u8; 12]) -> StunResult<SocketAddr> {
        let mut buf = [0u8; 1500];

        loop {
            let (n, from) =
                self.socket
                    .recv_from(&mut buf)
                    .await
                    .map_err(|e| StunError::NetworkError {
                        reason: format!("recv failed: {e}"),
                    })?;

            // Verify it's from the expected server
            if from != self.server {
                debug!(expected = %self.server, got = %from, "Ignoring response from unexpected source");
                continue;
            }

            let response = StunMessage::parse(&buf[..n])?;

            // Verify transaction ID matches
            if response.transaction_id != *expected_tid {
                debug!(expected = ?expected_tid, got = ?response.transaction_id, "Ignoring response with mismatched transaction ID");
                continue;
            }

            return Self::extract_mapped_address(&response);
        }
    }

    /// Extracts the mapped address from a STUN response, handling error responses.
    fn extract_mapped_address(response: &StunMessage) -> StunResult<SocketAddr> {
        // Check for error response
        if response.msg_type.class == crate::StunClass::ErrorResponse {
            return Err(Self::extract_error_code(response));
        }

        // Extract XOR-MAPPED-ADDRESS
        response
            .xor_mapped_address()
            .ok_or_else(|| StunError::InvalidMessage {
                reason: "response missing XOR-MAPPED-ADDRESS".to_string(),
            })
    }

    /// Extracts error code from an error response.
    fn extract_error_code(response: &StunMessage) -> StunError {
        let error_code = response.attributes.iter().find_map(|a| {
            if let crate::StunAttribute::ErrorCode { code, reason } = a {
                Some((*code, reason.clone()))
            } else {
                None
            }
        });

        if let Some((code, reason)) = error_code {
            StunError::ServerError { code, reason }
        } else {
            StunError::ServerError {
                code: 500,
                reason: "unknown error".to_string(),
            }
        }
    }
}

impl std::fmt::Debug for StunClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StunClient")
            .field("server", &self.server)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_default_values() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(3));
        assert_eq!(DEFAULT_MAX_RETRIES, 7);
        assert_eq!(INITIAL_RTO, Duration::from_millis(500));
        assert_eq!(MAX_RTO, Duration::from_millis(1600));
    }

    #[tokio::test]
    async fn test_client_creation() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478);
        let client = StunClient::new(Arc::new(socket), server);

        assert_eq!(client.server(), server);
        assert!(client.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_client_with_options() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478);

        let client = StunClient::new(Arc::new(socket), server)
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(3);

        assert_eq!(client.timeout, Duration::from_secs(5));
        assert_eq!(client.max_retries, 3);
    }

    // Note: Integration tests with real STUN servers would go in a separate
    // integration test file to avoid requiring network access in unit tests.

    #[tokio::test]
    async fn test_bind_creates_client() {
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478);
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

        let result = StunClient::bind(local_addr, server).await;
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.server(), server);
        assert!(client.local_addr().is_ok());
    }

    #[test]
    fn test_client_debug() {
        // Test Debug implementation (need to avoid async for direct struct inspection)
        let format = format!(
            "StunClient {{ server: {:?}, timeout: {:?}, max_retries: {:?} }}",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478),
            Duration::from_secs(3),
            7u32
        );
        assert!(format.contains("192.0.2.1"));
    }

    #[tokio::test]
    async fn test_client_debug_impl() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478);
        let client = StunClient::new(Arc::new(socket), server);

        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("StunClient"));
        assert!(debug_str.contains("192.0.2.1"));
    }

    #[test]
    fn test_extract_mapped_address_success() {
        use crate::{StunAttribute, StunClass, StunMethod};
        use crate::attribute::XorMappedAddress;
        use crate::message::StunMessageType;

        // Create a success response with XOR-MAPPED-ADDRESS
        let msg_type = StunMessageType::new(StunMethod::Binding, StunClass::SuccessResponse);
        let mut response = StunMessage::new(msg_type, [1u8; 12]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 12345);
        response.add_attribute(StunAttribute::XorMappedAddress(XorMappedAddress::new(addr)));

        let result = StunClient::extract_mapped_address(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), addr);
    }

    #[test]
    fn test_extract_mapped_address_missing() {
        use crate::{StunClass, StunMethod};
        use crate::message::StunMessageType;

        // Create a success response without XOR-MAPPED-ADDRESS
        let msg_type = StunMessageType::new(StunMethod::Binding, StunClass::SuccessResponse);
        let response = StunMessage::new(msg_type, [1u8; 12]);

        let result = StunClient::extract_mapped_address(&response);
        assert!(result.is_err());
        assert!(matches!(result, Err(StunError::InvalidMessage { .. })));
    }

    #[test]
    fn test_extract_mapped_address_error_response() {
        use crate::{StunAttribute, StunClass, StunMethod};
        use crate::message::StunMessageType;

        // Create an error response
        let msg_type = StunMessageType::new(StunMethod::Binding, StunClass::ErrorResponse);
        let mut response = StunMessage::new(msg_type, [1u8; 12]);
        response.add_attribute(StunAttribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".to_string(),
        });

        let result = StunClient::extract_mapped_address(&response);
        assert!(result.is_err());
        assert!(matches!(result, Err(StunError::ServerError { code: 401, .. })));
    }

    #[test]
    fn test_extract_error_code_with_error() {
        use crate::{StunAttribute, StunClass, StunMethod};
        use crate::message::StunMessageType;

        let msg_type = StunMessageType::new(StunMethod::Binding, StunClass::ErrorResponse);
        let mut response = StunMessage::new(msg_type, [1u8; 12]);
        response.add_attribute(StunAttribute::ErrorCode {
            code: 438,
            reason: "Stale Nonce".to_string(),
        });

        let error = StunClient::extract_error_code(&response);
        assert!(matches!(error, StunError::ServerError { code: 438, .. }));
    }

    #[test]
    fn test_extract_error_code_missing() {
        use crate::{StunClass, StunMethod};
        use crate::message::StunMessageType;

        // Error response without error code attribute
        let msg_type = StunMessageType::new(StunMethod::Binding, StunClass::ErrorResponse);
        let response = StunMessage::new(msg_type, [1u8; 12]);

        let error = StunClient::extract_error_code(&response);
        assert!(matches!(
            error,
            StunError::ServerError { code: 500, .. }
        ));
    }

    #[tokio::test]
    async fn test_discover_srflx_timeout() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Use a non-routable address to ensure timeout
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3478);

        let client = StunClient::new(Arc::new(socket), server)
            .with_timeout(Duration::from_millis(100))
            .with_max_retries(0);

        let result = client.discover_srflx().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(StunError::Timeout)));
    }
}
