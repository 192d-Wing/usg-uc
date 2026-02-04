//! ICE Handler for NAT traversal.
//!
//! Manages ICE candidate gathering, connectivity checks, and selected pair
//! for establishing media connectivity through NATs and firewalls.

use crate::{SipUaError, SipUaResult};
use proto_ice::agent::{GatheringState, IceState};
use proto_ice::{Candidate, CandidateType, IceAgent, IceConfig, IceCredentials, IceRole};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// ICE handler for managing connectivity establishment.
pub struct IceHandler {
    /// The underlying ICE agent.
    agent: IceAgent,
    /// Event sender for ICE state changes.
    event_tx: mpsc::Sender<IceEvent>,
    /// Local address for host candidates.
    local_addr: SocketAddr,
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
        }
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
    pub fn state(&self) -> IceState {
        self.agent.state()
    }

    /// Gets the current gathering state.
    pub fn gathering_state(&self) -> GatheringState {
        self.agent.gathering_state()
    }

    /// Gets the ICE role.
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

    /// Starts connectivity checks.
    ///
    /// Call this after gathering is complete and remote candidates are added.
    pub async fn start_checks(&mut self) -> SipUaResult<()> {
        info!("Starting ICE connectivity checks");

        let _ = self
            .event_tx
            .send(IceEvent::StateChanged {
                state: IceState::Checking,
            })
            .await;

        // The agent will perform connectivity checks
        // In a full implementation, this would drive the check process

        Ok(())
    }

    /// Gets the selected candidate pair addresses if connectivity is established.
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        // Return selected pair if connected
        if self.agent.state() == IceState::Connected || self.agent.state() == IceState::Completed {
            // In a full implementation, get from checklist
            // For now, return the local/remote addresses
            let local_candidates = self.agent.local_candidates();
            let remote_candidates = self.agent.remote_candidates();

            if let (Some(local), Some(remote)) =
                (local_candidates.first(), remote_candidates.first())
            {
                return Some((local.address(), remote.address()));
            }
        }
        None
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
            .map(|c| c.to_sdp())
            .collect()
    }

    /// Parses an SDP `a=candidate:` line into a Candidate.
    pub fn parse_sdp_candidate(sdp_line: &str) -> SipUaResult<Candidate> {
        // Remove "a=" prefix if present
        let line = sdp_line.trim().strip_prefix("a=").unwrap_or(sdp_line);

        Candidate::from_sdp(line).map_err(|e| SipUaError::IceError(e.to_string()))
    }
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
    fn test_format_candidate_sdp() {
        let candidate = Candidate::host("192.168.1.100:10000".parse().unwrap(), 1);
        let sdp = candidate.to_sdp();

        assert!(sdp.contains("192.168.1.100"));
        assert!(sdp.contains("10000"));
        assert!(sdp.contains("typ host"));
    }
}
