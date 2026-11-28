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
use bytes::Bytes;
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
        // RFC 8489 §6: the transaction ID is uniformly random.
        #[allow(clippy::expect_used)]
        let transaction_id: [u8; 12] = uc_crypto::random::generate_random()
            .expect("DRBG failure generating STUN transaction ID");

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

    /// Creates the request and encodes it with MESSAGE-INTEGRITY (keyed
    /// with the remote password, RFC 8445 §7.2.2) and FINGERPRINT
    /// (RFC 8445 §7.1).
    ///
    /// # Errors
    /// Returns an error if the request cannot be encoded.
    pub fn encode_request(&self) -> IceResult<Bytes> {
        self.create_request()?
            .encode_with_integrity_and_fingerprint(self.remote_credentials.pwd.as_bytes())
            .map_err(IceError::from)
    }

    /// Returns the role this check was sent in.
    pub fn role(&self) -> IceRole {
        self.role
    }

    /// Sets whether to nominate this pair (controlling agent only).
    #[must_use]
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
    /// ## RFC 8445 §7.2.5, RFC 8489 §9.1.4
    ///
    /// `raw` is the datagram as received and `from` its source. Before any
    /// state is touched the response must carry a valid FINGERPRINT and a
    /// MESSAGE-INTEGRITY keyed with the remote password; otherwise
    /// [`IceError::Unauthenticated`] is returned and the caller must keep
    /// waiting (the response is discarded). An authenticated response from
    /// an address other than the check's target fails the check
    /// (§7.2.5.2.1, non-symmetric transport addresses).
    ///
    /// ## NIST 800-53 Rev5: IA-3, SC-8, SI-10
    ///
    /// # Errors
    /// [`IceError::Unauthenticated`] for a response to discard;
    /// [`IceError::ProtocolError`] for a transaction ID mismatch.
    pub fn process_response(
        &self,
        response: &StunMessage,
        raw: &[u8],
        from: SocketAddr,
    ) -> IceResult<CheckResult> {
        // Verify transaction ID
        if response.transaction_id != self.transaction_id {
            return Err(IceError::ProtocolError {
                reason: "transaction ID mismatch".to_string(),
            });
        }
        if !StunMessage::has_valid_fingerprint(raw) {
            return Err(IceError::Unauthenticated {
                reason: "missing or invalid FINGERPRINT".to_string(),
            });
        }
        if !StunMessage::verify_integrity(raw, self.remote_credentials.pwd.as_bytes()) {
            return Err(IceError::Unauthenticated {
                reason: "missing or invalid MESSAGE-INTEGRITY".to_string(),
            });
        }
        if from != self.remote.address() {
            return Ok(CheckResult::Failure {
                reason: "response source does not match check target".to_string(),
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
                let error_code = response.attributes.iter().find_map(|a| {
                    if let StunAttribute::ErrorCode { code, reason } = a {
                        Some((*code, reason.clone()))
                    } else {
                        None
                    }
                });

                if let Some((code, reason)) = error_code {
                    if code == 487 {
                        // RFC 8445 §7.2.5.1: switch to the role opposite
                        // the one the request was sent in.
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
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum retransmissions.
    #[must_use]
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
    ///
    /// The request is signed with the check's remote password; responses
    /// that fail authentication are discarded while waiting.
    #[instrument(skip(self, check), fields(
        local = %check.local().address(),
        remote = %check.remote().address(),
    ))]
    pub async fn perform_check(&self, check: &ConnectivityCheck) -> IceResult<CheckResult> {
        // Encode with MESSAGE-INTEGRITY and FINGERPRINT
        let request_bytes = check.encode_request()?;

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

            // Process the response; unauthenticated ones are discarded.
            match check.process_response(&response, &buf[..n], from) {
                Err(IceError::Unauthenticated { reason }) => {
                    debug!(from = %from, %reason, "Discarding unauthenticated STUN response");
                }
                other => return other,
            }
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
    /// ## RFC 8445 §7.3, RFC 8489 §9.1.3
    ///
    /// `raw` is the datagram as received. In order:
    /// 1. A request without a valid FINGERPRINT is discarded
    ///    ([`IceError::Unauthenticated`], no response).
    /// 2. Without both USERNAME and MESSAGE-INTEGRITY: 400, unsigned.
    /// 3. USERNAME not `<local ufrag>:<remote ufrag>`, or MESSAGE-INTEGRITY
    ///    not valid under the local password: 401, unsigned.
    /// 4. Role conflicts are resolved per §7.3.1.1 (487 or a role switch).
    /// 5. Success response with XOR-MAPPED-ADDRESS, signed.
    ///
    /// Only an authenticated request yields [`TriggeredCheckInfo`]; the
    /// caller must not change any state for any other outcome. Encode the
    /// response with [`Self::encode_response`].
    ///
    /// ## NIST 800-53 Rev5: IA-3, SC-8, SI-10
    ///
    /// # Errors
    /// [`IceError::ProtocolError`] for a message that is not a Binding
    /// request; [`IceError::Unauthenticated`] for one to drop silently.
    pub fn process_request(
        &self,
        request: &StunMessage,
        raw: &[u8],
        source_addr: SocketAddr,
        _local_addr: SocketAddr,
    ) -> IceResult<RequestOutcome> {
        // Verify this is a Binding request
        if request.msg_type.method != StunMethod::Binding
            || request.msg_type.class != StunClass::Request
        {
            return Err(IceError::ProtocolError {
                reason: "expected Binding request".to_string(),
            });
        }

        if !StunMessage::has_valid_fingerprint(raw) {
            return Err(IceError::Unauthenticated {
                reason: "missing or invalid FINGERPRINT".to_string(),
            });
        }

        let username = request.attributes.iter().find_map(|a| {
            if let StunAttribute::Username(u) = a {
                Some(u.as_str())
            } else {
                None
            }
        });
        let has_integrity = request
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::MessageIntegrity(_)));
        let Some(username) = username.filter(|_| has_integrity) else {
            return Ok(RequestOutcome::unsigned(StunMessage::binding_error(
                request,
                400,
                "Bad Request",
            )));
        };

        // USERNAME is <our ufrag>:<their ufrag> (RFC 8445 §7.2.2).
        let ufrag_ok = username.split_once(':').is_some_and(|(local, remote)| {
            local == self.local_credentials.ufrag && !remote.is_empty()
        });
        if !ufrag_ok || !StunMessage::verify_integrity(raw, self.local_credentials.pwd.as_bytes()) {
            return Ok(RequestOutcome::unsigned(StunMessage::binding_error(
                request,
                401,
                "Unauthorized",
            )));
        }

        // Role conflict per RFC 8445 §7.3.1.1.
        let role_switch = match self.check_role_conflict(request) {
            RoleCheck::NoConflict => None,
            RoleCheck::Reject => {
                return Ok(RequestOutcome {
                    response: StunMessage::binding_error(request, 487, "Role Conflict"),
                    signed: true,
                    triggered: None,
                });
            }
            RoleCheck::SwitchTo(role) => Some(role),
        };
        let role = role_switch.unwrap_or(self.role);

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

        // USE-CANDIDATE only means something to a controlled agent
        // (RFC 8445 §7.3.1.5).
        let use_candidate = role == IceRole::Controlled
            && request
                .attributes
                .iter()
                .any(|a| matches!(a, StunAttribute::UseCandidate));

        // Create success response with XOR-MAPPED-ADDRESS
        let mut response = StunMessage::binding_response(request);
        response.add_attribute(StunAttribute::XorMappedAddress(
            proto_stun::XorMappedAddress::new(source_addr),
        ));

        Ok(RequestOutcome {
            response,
            signed: true,
            triggered: Some(TriggeredCheckInfo {
                source_addr,
                priority,
                use_candidate,
                role_conflict: role_switch,
            }),
        })
    }

    /// Encodes a response from [`Self::process_request`]: signed with the
    /// local password and FINGERPRINT for an authenticated request (RFC
    /// 8445 §7.3), FINGERPRINT only for a 400/401 (RFC 8489 §9.1.3).
    ///
    /// # Errors
    /// Returns an error if the response cannot be encoded.
    pub fn encode_response(&self, outcome: &RequestOutcome) -> IceResult<Bytes> {
        if outcome.signed {
            outcome
                .response
                .encode_with_integrity_and_fingerprint(self.local_credentials.pwd.as_bytes())
                .map_err(IceError::from)
        } else {
            Ok(outcome.response.encode_with_fingerprint())
        }
    }

    /// Resolves a role conflict per RFC 8445 §7.3.1.1.
    ///
    /// - Both controlling: if our tie-breaker is >= theirs we keep the
    ///   role and answer 487; otherwise we switch to controlled.
    /// - Both controlled: if our tie-breaker is >= theirs we switch to
    ///   controlling; otherwise we keep the role and answer 487.
    fn check_role_conflict(&self, request: &StunMessage) -> RoleCheck {
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
            (IceRole::Controlling, Some(remote_tb), _) => {
                if self.tie_breaker >= remote_tb {
                    RoleCheck::Reject
                } else {
                    RoleCheck::SwitchTo(IceRole::Controlled)
                }
            }
            (IceRole::Controlled, None, Some(remote_tb)) => {
                if self.tie_breaker >= remote_tb {
                    RoleCheck::SwitchTo(IceRole::Controlling)
                } else {
                    RoleCheck::Reject
                }
            }
            _ => RoleCheck::NoConflict,
        }
    }
}

/// Outcome of [`IceStunServer::check_role_conflict`].
enum RoleCheck {
    NoConflict,
    /// Keep our role and answer 487.
    Reject,
    /// Switch to this role and process the request.
    SwitchTo(IceRole),
}

/// Result of [`IceStunServer::process_request`].
#[derive(Debug, Clone)]
pub struct RequestOutcome {
    /// Response to send back to the request's source.
    pub response: StunMessage,
    /// Whether the response is signed (the request authenticated).
    pub signed: bool,
    /// Present only for an authenticated, accepted request.
    pub triggered: Option<TriggeredCheckInfo>,
}

impl RequestOutcome {
    fn unsigned(response: StunMessage) -> Self {
        Self {
            response,
            signed: false,
            triggered: None,
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
    /// Role the agent must switch to before acting on this request
    /// (RFC 8445 §7.3.1.1); the request was otherwise accepted.
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

    fn remote_creds() -> IceCredentials {
        IceCredentials::new("remote".to_string(), "remotepwd-remotepwd-rem".to_string())
    }

    fn check_for(role: IceRole) -> ConnectivityCheck {
        ConnectivityCheck::new(
            test_candidate([192, 168, 1, 100], 5060),
            test_candidate([10, 0, 0, 1], 5060),
            test_credentials(),
            remote_creds(),
            role,
            12345,
        )
    }

    fn success_for(check: &ConnectivityCheck) -> StunMessage {
        let mut response =
            StunMessage::new(StunMessageType::binding_response(), check.transaction_id);
        response.add_attribute(StunAttribute::XorMappedAddress(
            proto_stun::XorMappedAddress::new(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
                32853,
            )),
        ));
        response
    }

    fn signed(msg: &StunMessage, pwd: &str) -> Vec<u8> {
        msg.encode_with_integrity_and_fingerprint(pwd.as_bytes())
            .unwrap()
            .to_vec()
    }

    fn deliver(check: &ConnectivityCheck, raw: &[u8], from: SocketAddr) -> IceResult<CheckResult> {
        check.process_response(&StunMessage::parse(raw).unwrap(), raw, from)
    }

    #[test]
    fn test_process_success_response() {
        let check = check_for(IceRole::Controlling);
        let raw = signed(&success_for(&check), &remote_creds().pwd);
        match deliver(&check, &raw, check.remote().address()).unwrap() {
            CheckResult::Success {
                mapped_address,
                nominated,
            } => {
                assert_eq!(mapped_address.port(), 32853);
                assert!(!nominated);
            }
            other => panic!("Expected success result, got {other:?}"),
        }
    }

    #[test]
    fn encoded_request_is_signed_with_the_remote_password() {
        let check = check_for(IceRole::Controlling);
        let raw = check.encode_request().unwrap();
        assert!(StunMessage::has_valid_fingerprint(&raw));
        assert!(StunMessage::verify_integrity(
            &raw,
            remote_creds().pwd.as_bytes()
        ));
        assert!(!StunMessage::verify_integrity(
            &raw,
            test_credentials().pwd.as_bytes()
        ));
    }

    #[test]
    fn unauthenticated_responses_are_discarded() {
        let check = check_for(IceRole::Controlling);
        let to = check.remote().address();
        let resp = success_for(&check);
        // Unsigned, FINGERPRINT only.
        let raw = resp.encode_with_fingerprint();
        assert!(matches!(
            deliver(&check, &raw, to),
            Err(IceError::Unauthenticated { .. })
        ));
        // Signed with the wrong password.
        let raw = signed(&resp, "not-the-remote-password");
        assert!(matches!(
            deliver(&check, &raw, to),
            Err(IceError::Unauthenticated { .. })
        ));
        // Signed but no FINGERPRINT.
        let raw = resp
            .encode_with_integrity(remote_creds().pwd.as_bytes())
            .unwrap();
        assert!(matches!(
            deliver(&check, &raw, to),
            Err(IceError::Unauthenticated { .. })
        ));
        // An unsigned 487 does not switch roles.
        let conflict = StunMessage::binding_error(
            &StunMessage::new(StunMessageType::binding_request(), check.transaction_id),
            487,
            "Role Conflict",
        );
        let raw = conflict.encode_with_fingerprint();
        assert!(matches!(
            deliver(&check, &raw, to),
            Err(IceError::Unauthenticated { .. })
        ));
    }

    #[test]
    fn authenticated_response_from_another_source_fails_the_check() {
        let check = check_for(IceRole::Controlling);
        let raw = signed(&success_for(&check), &remote_creds().pwd);
        let elsewhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5060);
        assert!(matches!(
            deliver(&check, &raw, elsewhere).unwrap(),
            CheckResult::Failure { .. }
        ));
    }

    #[test]
    fn test_process_role_conflict_response() {
        for (role, expected) in [
            (IceRole::Controlling, IceRole::Controlled),
            (IceRole::Controlled, IceRole::Controlling),
        ] {
            let check = check_for(role);
            let response = StunMessage::binding_error(
                &StunMessage::new(StunMessageType::binding_request(), check.transaction_id),
                487,
                "Role Conflict",
            );
            let raw = signed(&response, &remote_creds().pwd);
            match deliver(&check, &raw, check.remote().address()).unwrap() {
                CheckResult::RoleConflict { new_role } => assert_eq!(new_role, expected),
                other => panic!("Expected role conflict result, got {other:?}"),
            }
        }
    }

    fn peer_request(local_ufrag: &str, role_attr: StunAttribute) -> StunMessage {
        let mut request = StunMessage::new(StunMessageType::binding_request(), [1u8; 12]);
        request.add_attribute(StunAttribute::Username(format!("{local_ufrag}:remote")));
        request.add_attribute(StunAttribute::Priority(2130706431));
        request.add_attribute(role_attr);
        request
    }

    fn src() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060)
    }

    fn local() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060)
    }

    fn serve(server: &IceStunServer, raw: &[u8]) -> IceResult<RequestOutcome> {
        server.process_request(&StunMessage::parse(raw).unwrap(), raw, src(), local())
    }

    fn error_code(msg: &StunMessage) -> Option<u16> {
        msg.attributes.iter().find_map(|a| match a {
            StunAttribute::ErrorCode { code, .. } => Some(*code),
            _ => None,
        })
    }

    #[test]
    fn test_stun_server_process_request() {
        let local_creds = test_credentials();
        let server = IceStunServer::new(local_creds.clone(), IceRole::Controlled, 54321);
        let request = peer_request(&local_creds.ufrag, StunAttribute::IceControlling(12345));
        let raw = signed(&request, &local_creds.pwd);

        let outcome = serve(&server, &raw).unwrap();
        assert!(outcome.signed);
        assert_eq!(outcome.response.msg_type.class, StunClass::SuccessResponse);
        assert_eq!(outcome.response.xor_mapped_address(), Some(src()));

        // The encoded response is signed with our password.
        let bytes = server.encode_response(&outcome).unwrap();
        assert!(StunMessage::verify_integrity(
            &bytes,
            local_creds.pwd.as_bytes()
        ));
        assert!(StunMessage::has_valid_fingerprint(&bytes));

        let triggered = outcome.triggered.unwrap();
        assert_eq!(triggered.source_addr, src());
        assert_eq!(triggered.priority, 2130706431);
        assert!(!triggered.use_candidate);
        assert!(triggered.role_conflict.is_none());
    }

    #[test]
    fn unauthenticated_requests_change_nothing() {
        let creds = test_credentials();
        let server = IceStunServer::new(creds.clone(), IceRole::Controlling, 54321);
        // A forged request: right ufrag (it is in the SDP), ICE-CONTROLLING
        // with a larger tie-breaker, USE-CANDIDATE, no valid integrity.
        let mut request = peer_request(&creds.ufrag, StunAttribute::IceControlling(u64::MAX));
        request.add_attribute(StunAttribute::UseCandidate);

        // No MESSAGE-INTEGRITY: 400, unsigned, no triggered check.
        let raw = request.encode_with_fingerprint();
        let out = serve(&server, &raw).unwrap();
        assert_eq!(error_code(&out.response), Some(400));
        assert!(!out.signed && out.triggered.is_none());
        let bytes = server.encode_response(&out).unwrap();
        assert!(!StunMessage::verify_integrity(&bytes, creds.pwd.as_bytes()));

        // Wrong password: 401, unsigned, no triggered check.
        let raw = signed(&request, "guessed-password-guessed");
        let out = serve(&server, &raw).unwrap();
        assert_eq!(error_code(&out.response), Some(401));
        assert!(!out.signed && out.triggered.is_none());

        // Wrong ufrag, right password: 401.
        let other = peer_request("someone-else", StunAttribute::IceControlled(1));
        let out = serve(&server, &signed(&other, &creds.pwd)).unwrap();
        assert_eq!(error_code(&out.response), Some(401));

        // No FINGERPRINT: dropped without a response.
        let raw = request.encode_with_integrity(creds.pwd.as_bytes()).unwrap();
        assert!(matches!(
            serve(&server, &raw),
            Err(IceError::Unauthenticated { .. })
        ));
    }

    /// RFC 8445 §7.3.1.1, all four tie-breaker cases.
    #[test]
    fn role_conflict_follows_rfc8445_7_3_1_1() {
        let creds = test_credentials();
        let ours = 1_000u64;

        // Both controlling, ours >= theirs: 487, keep controlling.
        let server = IceStunServer::new(creds.clone(), IceRole::Controlling, ours);
        let req = peer_request(&creds.ufrag, StunAttribute::IceControlling(ours));
        let out = serve(&server, &signed(&req, &creds.pwd)).unwrap();
        assert_eq!(error_code(&out.response), Some(487));
        assert!(out.signed && out.triggered.is_none());

        // Both controlling, ours < theirs: switch to controlled, accept,
        // and honour USE-CANDIDATE under the new role.
        let mut req = peer_request(&creds.ufrag, StunAttribute::IceControlling(ours + 1));
        req.add_attribute(StunAttribute::UseCandidate);
        let out = serve(&server, &signed(&req, &creds.pwd)).unwrap();
        assert_eq!(out.response.msg_type.class, StunClass::SuccessResponse);
        let t = out.triggered.unwrap();
        assert_eq!(t.role_conflict, Some(IceRole::Controlled));
        assert!(t.use_candidate);

        // Both controlled, ours >= theirs: switch to controlling, accept.
        let server = IceStunServer::new(creds.clone(), IceRole::Controlled, ours);
        let req = peer_request(&creds.ufrag, StunAttribute::IceControlled(ours));
        let out = serve(&server, &signed(&req, &creds.pwd)).unwrap();
        assert_eq!(out.response.msg_type.class, StunClass::SuccessResponse);
        assert_eq!(
            out.triggered.unwrap().role_conflict,
            Some(IceRole::Controlling)
        );

        // Both controlled, ours < theirs: 487, keep controlled.
        let req = peer_request(&creds.ufrag, StunAttribute::IceControlled(ours + 1));
        let out = serve(&server, &signed(&req, &creds.pwd)).unwrap();
        assert_eq!(error_code(&out.response), Some(487));
        assert!(out.triggered.is_none());
    }

    #[test]
    fn use_candidate_is_ignored_by_a_controlling_agent() {
        let creds = test_credentials();
        let server = IceStunServer::new(creds.clone(), IceRole::Controlling, 5);
        let mut req = peer_request(&creds.ufrag, StunAttribute::IceControlled(9));
        req.add_attribute(StunAttribute::UseCandidate);
        let out = serve(&server, &signed(&req, &creds.pwd)).unwrap();
        assert!(!out.triggered.unwrap().use_candidate);
    }
}
