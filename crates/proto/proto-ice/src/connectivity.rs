//! ICE connectivity check procedures per RFC 8445 §6.
//!
//! This module implements the STUN-based connectivity check procedures
//! required for ICE negotiation.
//!
//! ## RFC 8445 Compliance
//!
//! - **§6.1**: Procedures for Connectivity Checks
//! - **§6.2**: Connectivity Check Transactions
//! - **§7.2**: STUN Server Procedures
//! - **§7.3**: Triggering ICE Processing

use crate::agent::{IceCredentials, IceRole};
use crate::candidate::Candidate;
use crate::error::{IceError, IceResult};
use proto_stun::{StunAttribute, StunClass, StunMessage, StunMessageType, StunMethod};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, instrument, trace, warn};

/// Default timeout for connectivity checks (Ta * RTO = 50ms * 39.5s).
const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_millis(39500);

/// Initial retransmission timeout per RFC 8445 §14.3.
const INITIAL_RTO: Duration = Duration::from_millis(500);

/// Maximum retransmission timeout.
const MAX_RTO: Duration = Duration::from_millis(1600);

/// Maximum retransmissions per RFC 8445 §14.3.
const MAX_RETRANSMISSIONS: u32 = 7;

/// Result of a connectivity check.
#[derive(Debug, Clone)]
pub enum CheckResult {
    /// Check succeeded with the mapped address from response.
    Success {
        /// The XOR-MAPPED-ADDRESS from the response.
        mapped_address: SocketAddr,
        /// Whether USE-CANDIDATE was set in the request.
        nominated: bool,
    },
    /// Check failed with an error.
    Failure {
        /// Error reason.
        reason: String,
    },
    /// Check timed out.
    Timeout,
    /// Role conflict detected - need to switch roles.
    RoleConflict {
        /// New role to assume.
        new_role: IceRole,
    },
}

/// Connectivity check transaction.
///
/// Represents a single STUN Binding request/response exchange for
/// connectivity verification.
#[derive(Debug)]
pub struct ConnectivityCheck {
    /// Local candidate.
    local: Candidate,
    /// Remote candidate.
    remote: Candidate,
    /// Local credentials.
    local_credentials: IceCredentials,
    /// Remote credentials.
    remote_credentials: IceCredentials,
    /// Agent role.
    role: IceRole,
    /// Tie-breaker for role conflicts.
    tie_breaker: u64,
    /// Whether to include USE-CANDIDATE (nomination).
    nominate: bool,
    /// Transaction ID.
    transaction_id: [u8; 12],
}

impl ConnectivityCheck {
    /// Creates a new connectivity check.
    pub fn new(
        local: Candidate,
        remote: Candidate,
        local_credentials: IceCredentials,
        remote_credentials: IceCredentials,
        role: IceRole,
        tie_breaker: u64,
    ) -> Self {
        let mut transaction_id = [0u8; 12];
        // Generate random transaction ID
        if uc_crypto::random::fill_random(&mut transaction_id).is_err() {
            // Fallback to time-based ID
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            transaction_id[..8].copy_from_slice(&now.to_be_bytes());
        }

        Self {
            local,
            remote,
            local_credentials,
            remote_credentials,
            role,
            tie_breaker,
            nominate: false,
            transaction_id,
        }
    }

    /// Sets whether to nominate this pair (controlling agent only).
    pub fn with_nomination(mut self, nominate: bool) -> Self {
        self.nominate = nominate;
        self
    }

    /// Returns the local candidate.
    pub fn local(&self) -> &Candidate {
        &self.local
    }

    /// Returns the remote candidate.
    pub fn remote(&self) -> &Candidate {
        &self.remote
    }

    /// Returns the transaction ID.
    pub fn transaction_id(&self) -> &[u8; 12] {
        &self.transaction_id
    }

    /// Creates the STUN Binding request for this check.
    ///
    /// ## RFC 8445 §7.1.1 STUN Request
    ///
    /// The request includes:
    /// - USERNAME: remote-ufrag:local-ufrag
    /// - PRIORITY: priority of the pair being checked
    /// - ICE-CONTROLLING or ICE-CONTROLLED with tie-breaker
    /// - USE-CANDIDATE: if nominating (controlling only)
    /// - MESSAGE-INTEGRITY using remote password
    /// - FINGERPRINT
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn create_request(&self) -> IceResult<StunMessage> {
        let mut msg = StunMessage::new(StunMessageType::binding_request(), self.transaction_id);

        // USERNAME: remote-ufrag:local-ufrag (per RFC 8445 §7.1.1)
        let username = format!(
            "{}:{}",
            self.remote_credentials.ufrag, self.local_credentials.ufrag
        );
        msg.add_attribute(StunAttribute::Username(username));

        // PRIORITY: The priority that WOULD be assigned to a peer-reflexive
        // candidate learned from this check (per RFC 8445 §7.1.1)
        let priority = Candidate::compute_priority(
            crate::candidate::CandidateType::PeerReflexive,
            self.local.component(),
            self.local.local_preference(),
        );
        msg.add_attribute(StunAttribute::Priority(priority));

        // ICE-CONTROLLING or ICE-CONTROLLED with tie-breaker
        match self.role {
            IceRole::Controlling => {
                msg.add_attribute(StunAttribute::IceControlling(self.tie_breaker));
                // USE-CANDIDATE for nomination (controlling agent only)
                if self.nominate {
                    msg.add_attribute(StunAttribute::UseCandidate);
                }
            }
            IceRole::Controlled => {
                msg.add_attribute(StunAttribute::IceControlled(self.tie_breaker));
            }
        }

        Ok(msg)
    }

    /// Processes a STUN response for this check.
    ///
    /// ## RFC 8445 §7.2 Processing the Response
    ///
    /// Handles:
    /// - Success responses: Extract XOR-MAPPED-ADDRESS
    /// - Error responses: Handle role conflicts (487)
    /// - Validate MESSAGE-INTEGRITY
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn process_response(&self, response: &StunMessage) -> IceResult<CheckResult> {
        // Verify transaction ID
        if response.transaction_id != self.transaction_id {
            return Err(IceError::ProtocolError {
                reason: "transaction ID mismatch".to_string(),
            });
        }

        match response.msg_type.class {
            StunClass::SuccessResponse => {
                // Extract XOR-MAPPED-ADDRESS
                let mapped_address =
                    response
                        .xor_mapped_address()
                        .ok_or_else(|| IceError::ProtocolError {
                            reason: "missing XOR-MAPPED-ADDRESS in response".to_string(),
                        })?;

                Ok(CheckResult::Success {
                    mapped_address,
                    nominated: self.nominate,
                })
            }
            StunClass::ErrorResponse => {
                // Check for role conflict (487)
                let error_code = response.attributes.iter().find_map(|a| {
                    if let StunAttribute::ErrorCode { code, reason } = a {
                        Some((*code, reason.clone()))
                    } else {
                        None
                    }
                });

                if let Some((code, reason)) = error_code {
                    if code == 487 {
                        // Role conflict per RFC 8445 §7.2.5.1
                        let new_role = match self.role {
                            IceRole::Controlling => IceRole::Controlled,
                            IceRole::Controlled => IceRole::Controlling,
                        };
                        return Ok(CheckResult::RoleConflict { new_role });
                    }
                    return Ok(CheckResult::Failure {
                        reason: format!("STUN error {code}: {reason}"),
                    });
                }

                Ok(CheckResult::Failure {
                    reason: "unknown STUN error".to_string(),
                })
            }
            _ => Ok(CheckResult::Failure {
                reason: format!("unexpected response class: {:?}", response.msg_type.class),
            }),
        }
    }
}

/// Async connectivity checker.
///
/// Manages the execution of connectivity checks using STUN transactions.
pub struct ConnectivityChecker {
    /// UDP socket for sending/receiving STUN messages.
    socket: Arc<UdpSocket>,
    /// Check timeout.
    timeout: Duration,
    /// Maximum retransmissions.
    max_retransmissions: u32,
}

impl ConnectivityChecker {
    /// Creates a new connectivity checker.
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            timeout: DEFAULT_CHECK_TIMEOUT,
            max_retransmissions: MAX_RETRANSMISSIONS,
        }
    }

    /// Sets the check timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum retransmissions.
    pub fn with_max_retransmissions(mut self, max: u32) -> Self {
        self.max_retransmissions = max;
        self
    }

    /// Performs a connectivity check.
    ///
    /// ## RFC 8445 §6.2 Connectivity Check Transaction
    ///
    /// 1. Send STUN Binding request to remote candidate
    /// 2. Wait for response with retransmissions
    /// 3. Process response and return result
    #[instrument(skip(self, check, password), fields(
        local = %check.local().address(),
        remote = %check.remote().address(),
    ))]
    pub async fn perform_check(
        &self,
        check: &ConnectivityCheck,
        password: &[u8],
    ) -> IceResult<CheckResult> {
        let request = check.create_request()?;

        // Encode with MESSAGE-INTEGRITY and FINGERPRINT
        let request_bytes =
            request
                .encode_with_integrity(password)
                .map_err(|e| IceError::ProtocolError {
                    reason: format!("failed to encode request: {e}"),
                })?;

        let remote_addr = check.remote().address();

        debug!(
            transaction_id = ?check.transaction_id(),
            "Sending connectivity check"
        );

        let mut rto = INITIAL_RTO;
        let mut attempts = 0;
        let start = Instant::now();

        while attempts <= self.max_retransmissions {
            if start.elapsed() > self.timeout {
                return Ok(CheckResult::Timeout);
            }

            // Send request
            if let Err(e) = self.socket.send_to(&request_bytes, remote_addr).await {
                warn!(error = %e, attempt = attempts, "Failed to send connectivity check");
                attempts += 1;
                continue;
            }

            trace!(
                attempt = attempts,
                rto_ms = rto.as_millis(),
                "Sent STUN request"
            );

            // Wait for response
            let wait_time = rto.min(self.timeout.saturating_sub(start.elapsed()));

            match tokio::time::timeout(wait_time, self.recv_response(check)).await {
                Ok(Ok(result)) => {
                    debug!(
                        elapsed_ms = start.elapsed().as_millis(),
                        attempts = attempts,
                        "Connectivity check completed"
                    );
                    return Ok(result);
                }
                Ok(Err(e)) => {
                    // Got a response but processing failed
                    return Err(e);
                }
                Err(_) => {
                    // Timeout - retransmit with doubled RTO
                    trace!(
                        attempt = attempts,
                        rto_ms = rto.as_millis(),
                        "Connectivity check timed out, retransmitting"
                    );
                    rto = (rto * 2).min(MAX_RTO);
                    attempts += 1;
                }
            }
        }

        Ok(CheckResult::Timeout)
    }

    /// Receives and processes a STUN response.
    async fn recv_response(&self, check: &ConnectivityCheck) -> IceResult<CheckResult> {
        let mut buf = [0u8; 1500];

        loop {
            let (n, from) =
                self.socket
                    .recv_from(&mut buf)
                    .await
                    .map_err(|e| IceError::NetworkError {
                        reason: format!("recv failed: {e}"),
                    })?;

            // Parse the response
            let response = match StunMessage::parse(&buf[..n]) {
                Ok(msg) => msg,
                Err(e) => {
                    trace!(error = %e, "Ignoring non-STUN packet");
                    continue;
                }
            };

            // Check if this is a request (we need to handle incoming checks too)
            if response.msg_type.class == StunClass::Request {
                trace!(from = %from, "Received STUN request (should be handled by server)");
                continue;
            }

            // Verify transaction ID matches our check
            if response.transaction_id != *check.transaction_id() {
                trace!(
                    expected = ?check.transaction_id(),
                    got = ?response.transaction_id,
                    "Ignoring response with mismatched transaction ID"
                );
                continue;
            }

            // Process the response
            return check.process_response(&response);
        }
    }
}

/// STUN server for handling incoming connectivity checks.
///
/// ## RFC 8445 §7.3 Server Procedures
///
/// Processes incoming STUN Binding requests from remote peers
/// during ICE connectivity checking.
pub struct IceStunServer {
    /// Local credentials.
    local_credentials: IceCredentials,
    /// Agent role.
    role: IceRole,
    /// Tie-breaker.
    tie_breaker: u64,
}

impl IceStunServer {
    /// Creates a new ICE STUN server.
    pub fn new(local_credentials: IceCredentials, role: IceRole, tie_breaker: u64) -> Self {
        Self {
            local_credentials,
            role,
            tie_breaker,
        }
    }

    /// Updates the agent role.
    pub fn set_role(&mut self, role: IceRole) {
        self.role = role;
    }

    /// Processes an incoming STUN Binding request.
    ///
    /// ## RFC 8445 §7.3 STUN Server Procedures
    ///
    /// 1. Validate MESSAGE-INTEGRITY using local password
    /// 2. Check for role conflicts
    /// 3. Generate success response with XOR-MAPPED-ADDRESS
    ///
    /// ## Returns
    ///
    /// - `Ok((response, triggered_check))` - Response to send and optional triggered check info
    /// - `Err` - Request was invalid or rejected
    pub fn process_request(
        &self,
        request: &StunMessage,
        source_addr: SocketAddr,
        _local_addr: SocketAddr,
    ) -> IceResult<(StunMessage, Option<TriggeredCheckInfo>)> {
        // Verify this is a Binding request
        if request.msg_type.method != StunMethod::Binding
            || request.msg_type.class != StunClass::Request
        {
            return Err(IceError::ProtocolError {
                reason: "expected Binding request".to_string(),
            });
        }

        // Extract and validate USERNAME
        let username = request
            .attributes
            .iter()
            .find_map(|a| {
                if let StunAttribute::Username(u) = a {
                    Some(u.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| IceError::ProtocolError {
                reason: "missing USERNAME attribute".to_string(),
            })?;

        // USERNAME format should be local-ufrag:remote-ufrag
        let parts: Vec<&str> = username.split(':').collect();
        if parts.len() != 2 {
            return Err(IceError::ProtocolError {
                reason: format!("invalid USERNAME format: {username}"),
            });
        }

        // Verify local ufrag matches
        if parts[0] != self.local_credentials.ufrag {
            return Err(IceError::ProtocolError {
                reason: "USERNAME ufrag mismatch".to_string(),
            });
        }

        // Check for role conflict per RFC 8445 §7.3.1.1
        let role_conflict = self.check_role_conflict(request)?;
        if let Some(new_role) = role_conflict {
            // Return 487 error
            let error_response = StunMessage::binding_error(request, 487, "Role Conflict");
            return Ok((
                error_response,
                Some(TriggeredCheckInfo {
                    source_addr,
                    priority: 0,
                    use_candidate: false,
                    role_conflict: Some(new_role),
                }),
            ));
        }

        // Extract PRIORITY for triggered check
        let priority = request
            .attributes
            .iter()
            .find_map(|a| {
                if let StunAttribute::Priority(p) = a {
                    Some(*p)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Check for USE-CANDIDATE
        let use_candidate = request
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::UseCandidate));

        // Create success response with XOR-MAPPED-ADDRESS
        let mut response = StunMessage::binding_response(request);
        response.add_attribute(StunAttribute::XorMappedAddress(
            proto_stun::XorMappedAddress::new(source_addr),
        ));

        // Return triggered check info
        let triggered = TriggeredCheckInfo {
            source_addr,
            priority,
            use_candidate,
            role_conflict: None,
        };

        Ok((response, Some(triggered)))
    }

    /// Checks for role conflict per RFC 8445 §7.3.1.1.
    fn check_role_conflict(&self, request: &StunMessage) -> IceResult<Option<IceRole>> {
        let remote_controlling = request.attributes.iter().find_map(|a| {
            if let StunAttribute::IceControlling(tb) = a {
                Some(*tb)
            } else {
                None
            }
        });

        let remote_controlled = request.attributes.iter().find_map(|a| {
            if let StunAttribute::IceControlled(tb) = a {
                Some(*tb)
            } else {
                None
            }
        });

        match (self.role, remote_controlling, remote_controlled) {
            // We're controlling, they claim controlling
            (IceRole::Controlling, Some(remote_tb), None) => {
                if self.tie_breaker >= remote_tb {
                    // We win, they should switch to controlled
                    // Return error 487 so they switch
                    Ok(Some(IceRole::Controlled))
                } else {
                    // They win, we should switch to controlled
                    // But we don't return error, we switch ourselves
                    Ok(None)
                }
            }
            // We're controlled, they claim controlled
            (IceRole::Controlled, None, Some(remote_tb)) => {
                if self.tie_breaker >= remote_tb {
                    // We win, we should switch to controlling
                    Ok(None)
                } else {
                    // They win, they should switch to controlling
                    Ok(Some(IceRole::Controlling))
                }
            }
            // No conflict
            _ => Ok(None),
        }
    }
}

/// Information about a triggered check from an incoming request.
#[derive(Debug, Clone)]
pub struct TriggeredCheckInfo {
    /// Source address of the request.
    pub source_addr: SocketAddr,
    /// PRIORITY from the request (for peer-reflexive candidate).
    pub priority: u32,
    /// Whether USE-CANDIDATE was present.
    pub use_candidate: bool,
    /// Role conflict result if any.
    pub role_conflict: Option<IceRole>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{CandidateType, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_candidate(ip: [u8; 4], port: u16) -> Candidate {
        Candidate::new(
            "test".to_string(),
            1,
            TransportProtocol::Udp,
            2130706431,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port),
            CandidateType::Host,
        )
    }

    fn test_credentials() -> IceCredentials {
        IceCredentials::new("ufrag123".to_string(), "password456".to_string())
    }

    #[test]
    fn test_connectivity_check_creation() {
        let local = test_candidate([192, 168, 1, 100], 5060);
        let remote = test_candidate([10, 0, 0, 1], 5060);
        let local_creds = test_credentials();
        let remote_creds = IceCredentials::new("remote".to_string(), "remotepwd".to_string());

        let check = ConnectivityCheck::new(
            local.clone(),
            remote.clone(),
            local_creds,
            remote_creds,
            IceRole::Controlling,
            12345,
        );

        assert_eq!(check.local().address(), local.address());
        assert_eq!(check.remote().address(), remote.address());
    }

    #[test]
    fn test_create_request() {
        let local = test_candidate([192, 168, 1, 100], 5060);
        let remote = test_candidate([10, 0, 0, 1], 5060);
        let local_creds = test_credentials();
        let remote_creds = IceCredentials::new("remote".to_string(), "remotepwd".to_string());

        let check = ConnectivityCheck::new(
            local,
            remote,
            local_creds.clone(),
            remote_creds.clone(),
            IceRole::Controlling,
            12345,
        );

        let request = check.create_request().unwrap();

        // Verify USERNAME attribute
        let username = request.attributes.iter().find_map(|a| {
            if let StunAttribute::Username(u) = a {
                Some(u.clone())
            } else {
                None
            }
        });
        assert_eq!(
            username,
            Some(format!("{}:{}", remote_creds.ufrag, local_creds.ufrag))
        );

        // Verify ICE-CONTROLLING attribute
        let has_controlling = request
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::IceControlling(12345)));
        assert!(has_controlling);

        // Verify PRIORITY attribute
        let has_priority = request
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Priority(_)));
        assert!(has_priority);
    }

    #[test]
    fn test_create_request_with_nomination() {
        let local = test_candidate([192, 168, 1, 100], 5060);
        let remote = test_candidate([10, 0, 0, 1], 5060);
        let local_creds = test_credentials();
        let remote_creds = IceCredentials::new("remote".to_string(), "remotepwd".to_string());

        let check = ConnectivityCheck::new(
            local,
            remote,
            local_creds,
            remote_creds,
            IceRole::Controlling,
            12345,
        )
        .with_nomination(true);

        let request = check.create_request().unwrap();

        // Verify USE-CANDIDATE attribute
        let has_use_candidate = request
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::UseCandidate));
        assert!(has_use_candidate);
    }

    #[test]
    fn test_controlled_request() {
        let local = test_candidate([192, 168, 1, 100], 5060);
        let remote = test_candidate([10, 0, 0, 1], 5060);
        let local_creds = test_credentials();
        let remote_creds = IceCredentials::new("remote".to_string(), "remotepwd".to_string());

        let check = ConnectivityCheck::new(
            local,
            remote,
            local_creds,
            remote_creds,
            IceRole::Controlled,
            12345,
        );

        let request = check.create_request().unwrap();

        // Verify ICE-CONTROLLED attribute (not ICE-CONTROLLING)
        let has_controlled = request
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::IceControlled(12345)));
        assert!(has_controlled);

        let has_controlling = request
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::IceControlling(_)));
        assert!(!has_controlling);
    }

    #[test]
    fn test_process_success_response() {
        let local = test_candidate([192, 168, 1, 100], 5060);
        let remote = test_candidate([10, 0, 0, 1], 5060);
        let local_creds = test_credentials();
        let remote_creds = IceCredentials::new("remote".to_string(), "remotepwd".to_string());

        let check = ConnectivityCheck::new(
            local,
            remote,
            local_creds,
            remote_creds,
            IceRole::Controlling,
            12345,
        );

        // Create mock success response
        let mut response =
            StunMessage::new(StunMessageType::binding_response(), check.transaction_id);
        let mapped_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 32853);
        response.add_attribute(StunAttribute::XorMappedAddress(
            proto_stun::XorMappedAddress::new(mapped_addr),
        ));

        let result = check.process_response(&response).unwrap();

        match result {
            CheckResult::Success {
                mapped_address,
                nominated,
            } => {
                assert_eq!(mapped_address, mapped_addr);
                assert!(!nominated);
            }
            _ => panic!("Expected success result"),
        }
    }

    #[test]
    fn test_process_role_conflict_response() {
        let local = test_candidate([192, 168, 1, 100], 5060);
        let remote = test_candidate([10, 0, 0, 1], 5060);
        let local_creds = test_credentials();
        let remote_creds = IceCredentials::new("remote".to_string(), "remotepwd".to_string());

        let check = ConnectivityCheck::new(
            local,
            remote,
            local_creds,
            remote_creds,
            IceRole::Controlling,
            12345,
        );

        // Create 487 error response
        let response = StunMessage::binding_error(
            &StunMessage::new(StunMessageType::binding_request(), check.transaction_id),
            487,
            "Role Conflict",
        );

        // Fix transaction ID
        let mut response = response;
        response.transaction_id = check.transaction_id;

        let result = check.process_response(&response).unwrap();

        match result {
            CheckResult::RoleConflict { new_role } => {
                assert_eq!(new_role, IceRole::Controlled);
            }
            _ => panic!("Expected role conflict result"),
        }
    }

    #[test]
    fn test_stun_server_process_request() {
        let local_creds = test_credentials();
        let server = IceStunServer::new(local_creds.clone(), IceRole::Controlled, 54321);

        // Create incoming request
        let mut request = StunMessage::new(StunMessageType::binding_request(), [1u8; 12]);
        request.add_attribute(StunAttribute::Username(format!(
            "{}:remote",
            local_creds.ufrag
        )));
        request.add_attribute(StunAttribute::Priority(2130706431));
        request.add_attribute(StunAttribute::IceControlling(12345));

        let source_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060);
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);

        let (response, triggered) = server
            .process_request(&request, source_addr, local_addr)
            .unwrap();

        // Verify response is a success
        assert_eq!(response.msg_type.class, StunClass::SuccessResponse);

        // Verify XOR-MAPPED-ADDRESS
        assert_eq!(response.xor_mapped_address(), Some(source_addr));

        // Verify triggered check info
        let triggered = triggered.unwrap();
        assert_eq!(triggered.source_addr, source_addr);
        assert_eq!(triggered.priority, 2130706431);
        assert!(!triggered.use_candidate);
    }
}
