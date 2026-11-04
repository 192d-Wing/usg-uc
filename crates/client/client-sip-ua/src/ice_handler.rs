//! ICE Handler for NAT traversal.
//!
//! Manages ICE candidate gathering, connectivity checks, and selected pair
//! for establishing media connectivity through NATs and firewalls.

use crate::{SipUaError, SipUaResult};
use proto_ice::agent::{GatheringState, IceState};
use proto_ice::{
    Candidate, CandidateType, CheckResult, ConnectivityCheck, IceAgent, IceConfig, IceCredentials,
    IceRole, IceStunServer, PairState, component,
};
use proto_stun::{StunClass, StunMessage};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// Upper bound for the whole connectivity-check phase.
///
/// After it ICE is declared failed and the caller falls back to the SDP
/// `c=`/`m=` address. RFC 8445 leaves this to the application; a softphone
/// wants audio within a few seconds of answer, so this is short.
pub const DEFAULT_CHECK_PHASE_TIMEOUT: Duration = Duration::from_secs(3);

/// Initial STUN retransmission timeout for connectivity checks (RFC 8445
/// §14.3 recommends RTO = max(500 ms, Ta * N); the pair count is small).
const INITIAL_RTO: Duration = Duration::from_millis(500);
/// Upper bound for the doubled retransmission timeout.
const MAX_RTO: Duration = Duration::from_millis(1600);

/// ICE handler for managing connectivity establishment.
pub struct IceHandler {
    /// The underlying ICE agent.
    agent: IceAgent,
    /// Event sender for ICE state changes.
    event_tx: mpsc::Sender<IceEvent>,
    /// Local address for host candidates.
    local_addr: SocketAddr,
    /// The media socket connectivity checks are sent and answered on. ICE
    /// checks must share the RTP socket (RFC 8445 §2.2): the peer learns our
    /// transport address from the check's source.
    socket: Option<Arc<UdpSocket>>,
    /// Upper bound for the check phase; see [`DEFAULT_CHECK_PHASE_TIMEOUT`].
    check_phase_timeout: Duration,
}

/// A connectivity check that has been sent and awaits its response.
struct OutstandingCheck {
    pair_index: usize,
    check: ConnectivityCheck,
    sent_at: Instant,
    rto: Duration,
    attempts: u32,
}

/// Events emitted by the ICE handler.
#[derive(Debug, Clone)]
pub enum IceEvent {
    /// ICE state changed.
    StateChanged {
        /// New state.
        state: IceState,
    },
    /// Gathering state changed.
    GatheringStateChanged {
        /// New gathering state.
        state: GatheringState,
    },
    /// New local candidate discovered.
    LocalCandidate {
        /// The candidate.
        candidate: Candidate,
    },
    /// ICE connectivity established.
    Connected {
        /// Local address of selected pair.
        local_addr: SocketAddr,
        /// Remote address of selected pair.
        remote_addr: SocketAddr,
    },
    /// ICE failed to establish connectivity.
    Failed {
        /// Reason for failure.
        reason: String,
    },
}

impl IceHandler {
    /// Creates a new ICE handler.
    ///
    /// # Arguments
    /// * `local_addr` - Local address for host candidates
    /// * `role` - ICE role (Controlling for outbound, Controlled for inbound)
    /// * `config` - ICE configuration with STUN/TURN servers
    /// * `event_tx` - Channel for sending ICE events
    pub fn new(
        local_addr: SocketAddr,
        role: IceRole,
        config: IceConfig,
        event_tx: mpsc::Sender<IceEvent>,
    ) -> Self {
        let agent = IceAgent::new(role, config);
        Self {
            agent,
            event_tx,
            local_addr,
            socket: None,
            check_phase_timeout: DEFAULT_CHECK_PHASE_TIMEOUT,
        }
    }

    /// Sets the media socket used for connectivity checks (both sending
    /// ours and answering the peer's). Must be called before
    /// [`Self::start_checks`].
    pub fn set_socket(&mut self, socket: Arc<UdpSocket>) {
        self.socket = Some(socket);
    }

    /// Overrides the connectivity-check phase timeout.
    pub const fn set_check_phase_timeout(&mut self, timeout: Duration) {
        self.check_phase_timeout = timeout;
    }

    /// Remote candidates learned from the peer's SDP.
    pub fn remote_candidates(&self) -> Vec<Candidate> {
        self.agent.remote_candidates().to_vec()
    }

    /// Creates an ICE handler for outbound calls (Controlling role).
    pub fn for_outbound(
        local_addr: SocketAddr,
        config: IceConfig,
        event_tx: mpsc::Sender<IceEvent>,
    ) -> Self {
        Self::new(local_addr, IceRole::Controlling, config, event_tx)
    }

    /// Creates an ICE handler for inbound calls (Controlled role).
    pub fn for_inbound(
        local_addr: SocketAddr,
        config: IceConfig,
        event_tx: mpsc::Sender<IceEvent>,
    ) -> Self {
        Self::new(local_addr, IceRole::Controlled, config, event_tx)
    }

    /// Gets the local ICE credentials (ufrag and password).
    pub fn local_credentials(&self) -> IceCredentials {
        self.agent.local_credentials().clone()
    }

    /// Sets the remote ICE credentials from SDP.
    pub fn set_remote_credentials(&mut self, credentials: IceCredentials) {
        self.agent.set_remote_credentials(credentials);
    }

    /// Gets the current ICE state.
    #[allow(clippy::missing_const_for_fn)]
    pub fn state(&self) -> IceState {
        self.agent.state()
    }

    /// Gets the current gathering state.
    #[allow(clippy::missing_const_for_fn)]
    pub fn gathering_state(&self) -> GatheringState {
        self.agent.gathering_state()
    }

    /// Gets the ICE role.
    #[allow(clippy::missing_const_for_fn)]
    pub fn role(&self) -> IceRole {
        self.agent.role()
    }

    /// Gets all local candidates.
    pub fn local_candidates(&self) -> Vec<Candidate> {
        self.agent.local_candidates().to_vec()
    }

    /// Starts gathering ICE candidates.
    ///
    /// This will discover host candidates from local interfaces,
    /// and optionally server-reflexive candidates via STUN
    /// and relay candidates via TURN.
    pub async fn gather_candidates(&mut self) -> SipUaResult<()> {
        info!(local_addr = %self.local_addr, "Starting ICE candidate gathering");

        // Gather host candidates
        let _ = self.agent.gather_candidates(&[self.local_addr]);

        // Notify gathering started
        let _ = self
            .event_tx
            .send(IceEvent::GatheringStateChanged {
                state: GatheringState::Gathering,
            })
            .await;

        // Add host candidate
        let host_candidate = Candidate::host(self.local_addr, proto_ice::component::RTP);
        self.agent.add_local_candidate(host_candidate.clone());

        let _ = self
            .event_tx
            .send(IceEvent::LocalCandidate {
                candidate: host_candidate,
            })
            .await;

        // Gather STUN/TURN candidates asynchronously
        if let Err(e) = self.agent.gather_async_candidates().await {
            warn!("Failed to gather STUN/TURN candidates: {}", e);
            // Continue with host candidates only
        }

        // Send any additional candidates discovered
        for candidate in self.agent.local_candidates() {
            if candidate.candidate_type() != CandidateType::Host {
                let _ = self
                    .event_tx
                    .send(IceEvent::LocalCandidate {
                        candidate: candidate.clone(),
                    })
                    .await;
            }
        }

        // Notify gathering complete
        let _ = self
            .event_tx
            .send(IceEvent::GatheringStateChanged {
                state: GatheringState::Complete,
            })
            .await;

        info!(
            candidate_count = self.agent.local_candidates().len(),
            "ICE candidate gathering complete"
        );

        Ok(())
    }

    /// Adds a remote candidate from SDP.
    pub fn add_remote_candidate(&mut self, candidate: &Candidate) {
        debug!(
            candidate_type = ?candidate.candidate_type(),
            address = %candidate.address(),
            "Adding remote ICE candidate"
        );
        // Ignore result - we just log if pairing fails
        let _ = self.agent.add_remote_candidate(candidate);
    }

    /// Runs the connectivity-check phase (RFC 8445 §6–§8) on the media socket
    /// and returns the selected pair's `(local, remote)` addresses.
    ///
    /// Pairs are checked in priority order, paced by `Ta`; incoming checks
    /// from the peer are answered from the same socket (§7.3) so the far end
    /// can complete too. The controlling agent nominates the first pair that
    /// succeeds (aggressive nomination sends USE-CANDIDATE on every check,
    /// regular nomination sends one nominating check after the first
    /// success); the controlled agent selects the pair the peer nominated.
    /// Returns `Ok(None)` when every pair failed or the check phase timed out
    /// — the caller then falls back to the SDP default destination.
    pub async fn start_checks(&mut self) -> SipUaResult<Option<(SocketAddr, SocketAddr)>> {
        let socket = self
            .socket
            .clone()
            .ok_or_else(|| SipUaError::IceError("media socket not set".to_string()))?;
        let remote_creds =
            self.agent.remote_credentials().cloned().ok_or_else(|| {
                SipUaError::IceError("remote ICE credentials not set".to_string())
            })?;
        self.agent
            .start_checks()
            .map_err(|e| SipUaError::IceError(e.to_string()))?;
        info!(
            pairs = self.agent.checklist().len(),
            role = %self.agent.role(),
            "Starting ICE connectivity checks"
        );
        let _ = self
            .event_tx
            .send(IceEvent::StateChanged {
                state: IceState::Checking,
            })
            .await;

        let ta = Duration::from_millis(self.agent.config().ta_interval.max(1));
        let max_retransmissions = self.agent.config().max_retransmissions;
        let deadline = Instant::now() + self.check_phase_timeout;
        let mut outstanding: HashMap<[u8; 12], OutstandingCheck> = HashMap::new();
        let mut nominated_sent = false;
        let mut buf = vec![0u8; 1500];

        loop {
            if let Some(pair) = self.selected_pair()
                && self.nomination_done()
            {
                self.notify_connected(pair.0, pair.1).await?;
                return Ok(Some(pair));
            }
            if self.agent.state() == IceState::Failed {
                self.notify_failed("all candidate pairs failed").await?;
                return Ok(None);
            }
            if Instant::now() >= deadline {
                // A pair may have succeeded without nomination completing;
                // use it rather than nothing (§8.1.1 lets the controlling
                // agent pick any valid pair).
                if let Some(pair) = self.selected_pair() {
                    self.notify_connected(pair.0, pair.1).await?;
                    return Ok(Some(pair));
                }
                self.notify_failed("connectivity checks timed out").await?;
                return Ok(None);
            }

            // Regular nomination: once a pair succeeded, send one nominating
            // check for it (§8.1.1). Aggressive nomination already set
            // USE-CANDIDATE on the ordinary checks.
            if self.agent.role() == IceRole::Controlling
                && !self.agent.aggressive_nomination()
                && !nominated_sent
                && let Some(idx) = self.best_succeeded_pair()
                && let Some(check) = self.build_check(idx, true)
            {
                nominated_sent = true;
                Self::send_check(&socket, &remote_creds, &check).await;
                Self::track(&mut outstanding, idx, check);
            }

            self.send_next_check(&socket, &remote_creds, &mut outstanding)
                .await;

            for idx in Self::retransmit_expired(
                &socket,
                &remote_creds,
                &mut outstanding,
                max_retransmissions,
            )
            .await
            {
                debug!(pair = idx, "Connectivity check timed out");
                let _ = self.agent.check_failed(idx);
            }

            // Read the socket for one Ta slot: answer the peer's checks,
            // match responses to our outstanding checks.
            match tokio::time::timeout(ta, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    let Ok(msg) = StunMessage::parse(&buf[..n]) else {
                        trace!(from = %from, "Non-STUN packet during ICE checks, ignored");
                        continue;
                    };
                    match msg.msg_type.class {
                        StunClass::Request => {
                            self.answer_peer_check(&socket, &msg, from).await;
                        }
                        StunClass::SuccessResponse | StunClass::ErrorResponse => {
                            let Some(oc) = outstanding.remove(&msg.transaction_id) else {
                                trace!("STUN response for unknown transaction, ignored");
                                continue;
                            };
                            self.handle_check_response(&oc, &msg);
                        }
                        StunClass::Indication => {}
                    }
                }
                Ok(Err(e)) => {
                    return Err(SipUaError::TransportError(e.to_string()));
                }
                Err(_) => {} // Ta elapsed with nothing to read
            }
        }
    }

    /// Sends the next ordinary check in priority order, if any (one per Ta
    /// slot, §6.1.4.2).
    async fn send_next_check(
        &mut self,
        socket: &UdpSocket,
        remote_creds: &IceCredentials,
        outstanding: &mut HashMap<[u8; 12], OutstandingCheck>,
    ) {
        if let Some(idx) = self.agent.next_check()
            && let Some(check) = self.build_check(idx, self.agent.should_nominate_check())
        {
            let _ = self.agent.start_check(idx);
            Self::send_check(socket, remote_creds, &check).await;
            Self::track(outstanding, idx, check);
        }
    }

    /// Records a sent check so its response can be matched and it can be
    /// retransmitted.
    fn track(
        outstanding: &mut HashMap<[u8; 12], OutstandingCheck>,
        pair_index: usize,
        check: ConnectivityCheck,
    ) {
        outstanding.insert(
            *check.transaction_id(),
            OutstandingCheck {
                pair_index,
                check,
                sent_at: Instant::now(),
                rto: INITIAL_RTO,
                attempts: 1,
            },
        );
    }

    /// Retransmits checks whose RTO expired (RFC 8445 §14.3, doubling up to
    /// [`MAX_RTO`]) and drops those past `max_retransmissions`, returning the
    /// pair indices that gave up.
    async fn retransmit_expired(
        socket: &UdpSocket,
        remote_creds: &IceCredentials,
        outstanding: &mut HashMap<[u8; 12], OutstandingCheck>,
        max_retransmissions: u32,
    ) -> Vec<usize> {
        let now = Instant::now();
        let mut gave_up = Vec::new();
        for oc in outstanding.values_mut() {
            if now.duration_since(oc.sent_at) < oc.rto {
                continue;
            }
            if oc.attempts > max_retransmissions {
                gave_up.push(*oc.check.transaction_id());
                continue;
            }
            oc.attempts += 1;
            oc.sent_at = now;
            oc.rto = (oc.rto * 2).min(MAX_RTO);
            Self::send_check(socket, remote_creds, &oc.check).await;
        }
        gave_up
            .iter()
            .filter_map(|tid| outstanding.remove(tid).map(|oc| oc.pair_index))
            .collect()
    }

    /// True when the selected pair is final: the controlling agent has
    /// nominated it, or the controlled agent was told so via USE-CANDIDATE.
    fn nomination_done(&self) -> bool {
        self.agent
            .selected_pair(component::RTP)
            .is_some_and(proto_ice::CandidatePair::is_nominated)
    }

    /// Highest-priority pair that has succeeded.
    fn best_succeeded_pair(&self) -> Option<usize> {
        self.agent
            .checklist()
            .pairs()
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state() == PairState::Succeeded)
            .max_by_key(|(_, p)| p.priority())
            .map(|(i, _)| i)
    }

    fn build_check(&self, pair_index: usize, nominate: bool) -> Option<ConnectivityCheck> {
        let pair = self.agent.checklist().get(pair_index)?;
        self.agent
            .create_connectivity_check_with_nomination(pair.local(), pair.remote(), nominate)
    }

    /// Sends a check signed with the peer's password (§7.2.2: the request's
    /// MESSAGE-INTEGRITY uses the remote agent's password).
    async fn send_check(
        socket: &UdpSocket,
        remote_creds: &IceCredentials,
        check: &ConnectivityCheck,
    ) {
        let Ok(request) = check.create_request() else {
            return;
        };
        match request.encode_with_integrity(remote_creds.pwd.as_bytes()) {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, check.remote().address()).await {
                    warn!(error = %e, remote = %check.remote().address(), "Failed to send connectivity check");
                }
            }
            Err(e) => warn!(error = %e, "Failed to encode connectivity check"),
        }
    }

    /// Answers a Binding request from the peer (§7.3): the response carries
    /// XOR-MAPPED-ADDRESS and is signed with our password. A USE-CANDIDATE
    /// from the controlling peer nominates the matching pair on our side.
    async fn answer_peer_check(
        &mut self,
        socket: &UdpSocket,
        request: &StunMessage,
        from: SocketAddr,
    ) {
        let server = IceStunServer::new(
            self.agent.local_credentials().clone(),
            self.agent.role(),
            self.agent.tie_breaker(),
        );
        let (response, triggered) = match server.process_request(request, from, self.local_addr) {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, from = %from, "Rejected peer connectivity check");
                return;
            }
        };
        let pwd = self.agent.local_credentials().pwd.clone();
        match response.encode_with_integrity(pwd.as_bytes()) {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, from).await {
                    warn!(error = %e, "Failed to answer connectivity check");
                }
            }
            Err(e) => warn!(error = %e, "Failed to encode check response"),
        }
        let Some(info) = triggered else {
            return;
        };
        if let Some(new_role) = info.role_conflict {
            info!(?new_role, "ICE role conflict; switching role");
            self.agent.set_role(new_role);
            return;
        }
        // The peer reached us on this pair, so it is valid from its side; if
        // it nominated it and the pair already succeeded for us, select it.
        if info.use_candidate && self.agent.role() == IceRole::Controlled {
            let idx =
                self.agent.checklist().pairs().iter().position(|p| {
                    p.remote().address() == from && p.state() == PairState::Succeeded
                });
            if let Some(idx) = idx {
                self.select_nominated(idx);
            }
        }
    }

    /// Applies the peer's response to one of our checks.
    fn handle_check_response(&mut self, oc: &OutstandingCheck, response: &StunMessage) {
        match oc.check.process_response(response) {
            Ok(CheckResult::Success { nominated, .. }) => {
                let _ = self.agent.check_succeeded(oc.pair_index);
                if nominated {
                    self.select_nominated(oc.pair_index);
                }
            }
            Ok(CheckResult::RoleConflict { new_role }) => {
                info!(
                    ?new_role,
                    "ICE role conflict reported by peer; switching role"
                );
                self.agent.set_role(new_role);
                // The pair goes back to Waiting so it is re-checked under the new role.
                if let Some(p) = self.agent.checklist_mut().get_mut(oc.pair_index) {
                    p.set_state(PairState::Waiting);
                }
            }
            Ok(CheckResult::Failure { reason })
            | Err(proto_ice::IceError::ProtocolError { reason }) => {
                debug!(pair = oc.pair_index, %reason, "Connectivity check failed");
                let _ = self.agent.check_failed(oc.pair_index);
            }
            Ok(CheckResult::Timeout) | Err(_) => {
                let _ = self.agent.check_failed(oc.pair_index);
            }
        }
    }

    /// Marks a succeeded pair as nominated and selected for its component.
    fn select_nominated(&mut self, idx: usize) {
        let comp = match self.agent.checklist().get(idx) {
            Some(p) => p.local().component(),
            None => return,
        };
        if let Some(p) = self.agent.checklist_mut().get_mut(idx) {
            p.nominate();
        }
        let _ = self.agent.checklist_mut().select_pair(comp, idx);
    }

    /// The selected candidate pair's `(local, remote)` addresses, once a pair
    /// has been selected for the RTP component.
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.agent
            .selected_pair(component::RTP)
            .map(|p| (p.local().address(), p.remote().address()))
    }

    /// Notifies that ICE connectivity has been established.
    pub async fn notify_connected(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> SipUaResult<()> {
        info!(
            local_addr = %local_addr,
            remote_addr = %remote_addr,
            "ICE connectivity established"
        );

        self.event_tx
            .send(IceEvent::Connected {
                local_addr,
                remote_addr,
            })
            .await
            .map_err(|e| SipUaError::IceError(e.to_string()))?;

        Ok(())
    }

    /// Notifies that ICE has failed.
    pub async fn notify_failed(&self, reason: &str) -> SipUaResult<()> {
        warn!(reason = %reason, "ICE connectivity failed");

        self.event_tx
            .send(IceEvent::Failed {
                reason: reason.to_string(),
            })
            .await
            .map_err(|e| SipUaError::IceError(e.to_string()))?;

        Ok(())
    }

    /// Formats local candidates as SDP `a=candidate:` lines.
    pub fn format_sdp_candidates(&self) -> Vec<String> {
        self.agent
            .local_candidates()
            .iter()
            .map(Candidate::to_sdp)
            .collect()
    }

    /// Parses an SDP `a=candidate:` line into a Candidate.
    pub fn parse_sdp_candidate(sdp_line: &str) -> SipUaResult<Candidate> {
        // Remove "a=" prefix if present
        let line = sdp_line.trim().strip_prefix("a=").unwrap_or(sdp_line);

        Candidate::from_sdp(line).map_err(|e| SipUaError::IceError(e.to_string()))
    }
}

/// True when the SDP default destination (`c=`/`m=`) is not one of the peer's
/// candidates (RFC 8445 §5.1.1, RFC 5245 §5.1).
///
/// That happens when a B2BUA re-anchored `c=`/`m=` at itself while relaying
/// the far party's ICE attributes. ICE then does not apply to this media path
/// (an "ICE mismatch") and
/// media goes to the default destination directly.
pub fn is_ice_mismatch(default_destination: SocketAddr, remote_candidates: &[Candidate]) -> bool {
    !remote_candidates
        .iter()
        .any(|c| c.address() == default_destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ice_handler_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:10000".parse().unwrap();
        let config = IceConfig::default();

        let handler = IceHandler::for_outbound(local_addr, config, tx);

        assert_eq!(handler.role(), IceRole::Controlling);
        assert_eq!(handler.state(), IceState::New);
    }

    #[tokio::test]
    async fn test_ice_handler_inbound() {
        let (tx, _rx) = mpsc::channel(10);
        let local_addr: SocketAddr = "192.168.1.100:10000".parse().unwrap();
        let config = IceConfig::default();

        let handler = IceHandler::for_inbound(local_addr, config, tx);

        assert_eq!(handler.role(), IceRole::Controlled);
    }

    #[test]
    fn test_parse_host_candidate() {
        let sdp = "candidate:1 1 UDP 2130706431 192.168.1.100 10000 typ host";
        let candidate = IceHandler::parse_sdp_candidate(sdp).unwrap();

        assert_eq!(candidate.candidate_type(), CandidateType::Host);
        assert_eq!(candidate.address().ip().to_string(), "192.168.1.100");
        assert_eq!(candidate.address().port(), 10000);
        assert_eq!(candidate.component(), 1);
    }

    #[test]
    fn test_parse_srflx_candidate() {
        let sdp = "candidate:2 1 UDP 1694498815 203.0.113.5 54321 typ srflx raddr 192.168.1.100 rport 10000";
        let candidate = IceHandler::parse_sdp_candidate(sdp).unwrap();

        assert_eq!(candidate.candidate_type(), CandidateType::ServerReflexive);
        assert_eq!(candidate.address().ip().to_string(), "203.0.113.5");
        assert_eq!(candidate.address().port(), 54321);
    }

    #[test]
    fn ice_mismatch_when_default_destination_is_not_a_candidate() {
        let cand = Candidate::host("192.168.1.100:10000".parse().unwrap(), 1);
        // A B2BUA re-anchored c=/m= at itself: not among the peer's candidates.
        assert!(is_ice_mismatch(
            "203.0.113.9:20000".parse().unwrap(),
            std::slice::from_ref(&cand)
        ));
        // Peer-to-peer: the default destination is the peer's host candidate.
        assert!(!is_ice_mismatch(
            "192.168.1.100:10000".parse().unwrap(),
            &[cand]
        ));
        // No candidates at all is also a mismatch.
        assert!(is_ice_mismatch("192.168.1.100:10000".parse().unwrap(), &[]));
    }

    /// Two agents on loopback run real connectivity checks against each
    /// other: the controlling side nominates, the controlled side selects the
    /// nominated pair, and both report the same pair (mirrored).
    async fn run_loopback_checks(aggressive: bool) {
        let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a_addr = a_sock.local_addr().unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        let config = IceConfig {
            aggressive_nomination: aggressive,
            ..IceConfig::default()
        };

        let (a_tx, mut a_rx) = mpsc::channel(32);
        let (b_tx, _b_rx) = mpsc::channel(32);
        let mut a = IceHandler::for_outbound(a_addr, config.clone(), a_tx);
        let mut b = IceHandler::for_inbound(b_addr, config, b_tx);
        a.set_socket(a_sock);
        b.set_socket(b_sock);

        // Exchange what SDP would carry: credentials and host candidates.
        a.gather_candidates().await.unwrap();
        b.gather_candidates().await.unwrap();
        a.set_remote_credentials(b.local_credentials());
        b.set_remote_credentials(a.local_credentials());
        for c in b.local_candidates() {
            a.add_remote_candidate(&c);
        }
        for c in a.local_candidates() {
            b.add_remote_candidate(&c);
        }

        let (ra, rb) = tokio::join!(a.start_checks(), b.start_checks());
        // Both sides must have selected a pair.
        let (a_local, a_remote) = ra.unwrap().unwrap();
        let (b_local, b_remote) = rb.unwrap().unwrap();
        assert_eq!((a_local, a_remote), (a_addr, b_addr));
        assert_eq!((b_local, b_remote), (b_addr, a_addr));
        assert_eq!(a.state(), IceState::Completed);
        assert!(a.nomination_done(), "controlling agent nominated the pair");

        // The event stream saw Checking then Connected.
        let mut saw_connected = false;
        while let Ok(ev) = a_rx.try_recv() {
            if let IceEvent::Connected { remote_addr, .. } = ev {
                assert_eq!(remote_addr, b_addr);
                saw_connected = true;
            }
        }
        assert!(saw_connected);
    }

    #[tokio::test]
    async fn loopback_checks_with_regular_nomination() {
        run_loopback_checks(false).await;
    }

    #[tokio::test]
    async fn loopback_checks_with_aggressive_nomination() {
        run_loopback_checks(true).await;
    }

    /// A peer that never answers (e.g. a B2BUA that does not run ICE): the
    /// check phase gives up at the configured timeout and reports no pair, so
    /// the caller can fall back to the SDP address.
    #[tokio::test]
    async fn unanswered_checks_time_out_without_a_pair() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = sock.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(32);
        let mut h = IceHandler::for_outbound(local, IceConfig::default(), tx);
        h.set_socket(sock);
        h.set_check_phase_timeout(Duration::from_millis(300));
        h.gather_candidates().await.unwrap();
        h.set_remote_credentials(IceCredentials::generate());
        h.add_remote_candidate(&Candidate::host(
            silent.local_addr().unwrap(),
            component::RTP,
        ));

        let started = Instant::now();
        let result = h.start_checks().await.unwrap();
        assert!(result.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "bounded by the phase timeout"
        );
        assert!(h.selected_pair().is_none());
    }

    #[test]
    fn test_format_candidate_sdp() {
        let candidate = Candidate::host("192.168.1.100:10000".parse().unwrap(), 1);
        let sdp = candidate.to_sdp();

        assert!(sdp.contains("192.168.1.100"));
        assert!(sdp.contains("10000"));
        assert!(sdp.contains("typ host"));
    }
}
