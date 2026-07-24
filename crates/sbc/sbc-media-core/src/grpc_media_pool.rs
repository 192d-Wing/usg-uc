//! Client-side media-node **pool** (Phase 3b of the signaling↔media split).
//!
//! [`MediaPool`] is a [`MediaController`] that fans calls across N standalone
//! media nodes (each a [`GrpcMediaController`]). Because it implements the same
//! trait as a single node, the SIP stack holds `Arc<dyn MediaController>`
//! unchanged — it never learns there's a pool.
//!
//! Per call: `create_session` selects the least-loaded node, records a
//! `call_id → node` affinity, and returns that node's [`AllocatedPorts`] — which,
//! since Phase 3a, carries the node's advertised media IP + fingerprint, so the
//! SIP stack steers SDP to the chosen node. Every subsequent op for the call
//! (`set_remote_address`, `start_relay*`, `stop_relay`, `remove_session`) follows
//! the affinity to the SAME node — a call's media lives on one node.
//!
//! Health and failover (routing away from down nodes, tearing down a dead node's
//! calls) are Phase 3c and layer on top of this.

use crate::grpc_media_controller::GrpcMediaController;
use crate::media_pipeline::{AllocatedPorts, LegDtlsParams, MediaController, MediaPipelineError};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tracing::warn;
use uc_media_engine::MediaMode;
use uc_types::address::SbcSocketAddr;

/// How often the health-reset task optimistically re-enables nodes marked
/// unhealthy, so a recovered node rejoins selection (and a still-down one is
/// simply re-marked on its next failed use).
const HEALTH_RESET_INTERVAL: Duration = Duration::from_secs(30);

/// One media node in the pool: its gRPC client, an approximate active-session
/// count (least-loaded selection), and a health flag (route-away on failure).
struct PoolNode {
    client: GrpcMediaController,
    /// Active sessions assigned to this node. Approximate (updated with `Relaxed`
    /// ordering, and selection races are tolerated) — good enough to balance.
    active: AtomicUsize,
    /// Cleared when a control RPC to this node fails at the transport layer
    /// (node down); selection skips unhealthy nodes. Optimistically re-set every
    /// [`HEALTH_RESET_INTERVAL`] so a recovered node rejoins.
    healthy: AtomicBool,
}

/// A [`MediaController`] over a pool of media nodes with `call_id`-affinity,
/// least-loaded selection, and route-away from unhealthy nodes.
pub struct MediaPool {
    nodes: Arc<Vec<PoolNode>>,
    /// `call_id → node index`. The authoritative record of which node owns a call.
    affinity: RwLock<HashMap<String, usize>>,
    /// Emits a call's id when the node hosting it is detected down, so the SIP
    /// layer tears the call down (BYE both legs — the endpoints redial onto a
    /// healthy node). Same channel shape as the in-process `media_failure_tx`.
    media_failure_tx: Option<mpsc::UnboundedSender<String>>,
}

impl MediaPool {
    /// Builds a pool over `clients` (one per media node) and spawns its
    /// health-reset task. `media_failure_tx` receives the call ids whose node
    /// went down (for signaling-side teardown); `None` disables that.
    ///
    /// # Errors
    /// Returns an error if `clients` is empty — a pool needs at least one node.
    pub fn new(
        clients: Vec<GrpcMediaController>,
        media_failure_tx: Option<mpsc::UnboundedSender<String>>,
    ) -> Result<Self, MediaPipelineError> {
        if clients.is_empty() {
            return Err(MediaPipelineError::Rpc(
                "media pool requires at least one node".to_string(),
            ));
        }
        let nodes: Arc<Vec<PoolNode>> = Arc::new(
            clients
                .into_iter()
                .map(|client| PoolNode {
                    client,
                    active: AtomicUsize::new(0),
                    healthy: AtomicBool::new(true),
                })
                .collect(),
        );
        // Optimistic recovery: periodically re-enable unhealthy nodes so a node
        // that came back rejoins selection. A still-down node just gets re-marked
        // on its next failed use (create_session routes away), so this needs no
        // active health RPC.
        let monitored = Arc::clone(&nodes);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HEALTH_RESET_INTERVAL);
            ticker.tick().await; // consume the immediate first tick
            loop {
                ticker.tick().await;
                for node in monitored.iter() {
                    node.healthy.store(true, Ordering::Relaxed);
                }
            }
        });
        Ok(Self {
            nodes,
            affinity: RwLock::new(HashMap::new()),
            media_failure_tx,
        })
    }

    /// Marks node `idx` down and tears down every in-flight call hosted on it:
    /// drops each from the affinity map and emits its id on `media_failure_tx`
    /// so the SIP layer BYEs it (their media is gone with the node). New calls
    /// route away via [`Self::select`].
    async fn fail_node(&self, idx: usize) {
        self.nodes[idx].healthy.store(false, Ordering::Relaxed);
        let doomed: Vec<String> = {
            let mut affinity = self.affinity.write().await;
            let doomed: Vec<String> = affinity
                .iter()
                .filter(|&(_, &node)| node == idx)
                .map(|(call, _)| call.clone())
                .collect();
            for call in &doomed {
                affinity.remove(call);
            }
            doomed
        };
        // The node holds no sessions from our view now.
        self.nodes[idx].active.store(0, Ordering::Relaxed);
        if !doomed.is_empty() {
            warn!(
                node = idx,
                calls = doomed.len(),
                "media node down; tearing down its in-flight calls"
            );
            if let Some(tx) = &self.media_failure_tx {
                for call in doomed {
                    let _ = tx.send(call);
                }
            }
        }
    }

    /// Number of nodes in the pool.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Picks the least-loaded **healthy** node (lowest active-session count; ties
    /// → lowest index), or `None` if every node is currently marked unhealthy.
    /// Reads atomics without a lock, so a burst of concurrent selects may pick
    /// the same node — a bounded, self-correcting imbalance, not a correctness
    /// issue.
    fn select(&self) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None; // (idx, load)
        for (idx, node) in self.nodes.iter().enumerate() {
            if !node.healthy.load(Ordering::Relaxed) {
                continue;
            }
            let load = node.active.load(Ordering::Relaxed);
            if best.is_none_or(|(_, best_load)| load < best_load) {
                best = Some((idx, load));
            }
        }
        best.map(|(idx, _)| idx)
    }

    /// The node owning `call_id`, or [`MediaPipelineError::SessionNotFound`].
    async fn node_for(&self, call_id: &str) -> Result<usize, MediaPipelineError> {
        self.affinity
            .read()
            .await
            .get(call_id)
            .copied()
            .ok_or(MediaPipelineError::SessionNotFound)
    }
}

#[async_trait::async_trait]
impl MediaController for MediaPool {
    async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
        a_leg_media_ip: Option<IpAddr>,
        b_leg_media_ip: Option<IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        // Idempotent on retransmit: if the call already has a node, reuse it
        // rather than double-allocating on a second node.
        if let Some(idx) = self.affinity.read().await.get(call_id).copied() {
            return self.nodes[idx]
                .client
                .create_session_with_zones(call_id, mode, a_leg_media_ip, b_leg_media_ip)
                .await;
        }

        // Try the least-loaded healthy node; on a TRANSPORT failure (node down,
        // surfaced as MediaPipelineError::Rpc) mark it unhealthy and route the
        // call to another node. Each failure removes one node from selection, so
        // the loop ends when a node succeeds or all are unhealthy. Non-transport
        // errors (bad request, exhausted, etc.) are the node's real answer and
        // are returned as-is.
        loop {
            let Some(idx) = self.select() else {
                return Err(MediaPipelineError::Rpc(
                    "no healthy media node available".to_string(),
                ));
            };
            // Reserve the slot before the RPC so concurrent selects see the load;
            // release it if this node fails.
            self.nodes[idx].active.fetch_add(1, Ordering::Relaxed);
            match self.nodes[idx]
                .client
                .create_session_with_zones(call_id, mode, a_leg_media_ip, b_leg_media_ip)
                .await
            {
                Ok(ports) => {
                    self.affinity.write().await.insert(call_id.to_string(), idx);
                    return Ok(ports);
                }
                Err(MediaPipelineError::Rpc(e)) => {
                    warn!(node = idx, error = %e, "media node unreachable; routing away");
                    // Mark down + BYE any in-flight calls it was hosting, then
                    // retry this call on another node (loop).
                    self.fail_node(idx).await;
                }
                Err(other) => {
                    self.nodes[idx].active.fetch_sub(1, Ordering::Relaxed);
                    return Err(other);
                }
            }
        }
    }

    async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        let idx = self.node_for(call_id).await?;
        self.nodes[idx]
            .client
            .set_remote_address(call_id, is_a_leg, address)
            .await
    }

    async fn start_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let idx = self.node_for(call_id).await?;
        self.nodes[idx].client.start_relay(call_id).await
    }

    async fn start_relay_terminate(
        &self,
        call_id: &str,
        a_leg: LegDtlsParams,
        b_leg: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        let idx = self.node_for(call_id).await?;
        self.nodes[idx]
            .client
            .start_relay_terminate(call_id, a_leg, b_leg)
            .await
    }

    async fn stop_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let idx = self.node_for(call_id).await?;
        self.nodes[idx].client.stop_relay(call_id).await
    }

    async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let idx = self.node_for(call_id).await?;
        let result = self.nodes[idx].client.remove_session(call_id).await;
        // Drop the affinity + release the slot regardless of the node's result
        // (best-effort cleanup — the call is going away either way).
        if self.affinity.write().await.remove(call_id).is_some() {
            self.nodes[idx].active.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError> {
        // Announcement playback is not a call, so it carries no affinity; just
        // place it on the least-loaded healthy node.
        let idx = self.select().ok_or_else(|| {
            MediaPipelineError::Rpc("no healthy media node available".to_string())
        })?;
        self.nodes[idx].client.allocate_ports().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc_media_server::MediaControllerServer;
    use crate::media_pipeline::{MediaPipeline, MediaPipelineConfig};
    use sbc_grpc_api::sbc::media_controller_service_server::MediaControllerServiceServer;
    use std::sync::Arc;

    /// Brings up a real MediaControllerServer over a default pipeline whose
    /// `advertised_media_ip` is `ip`, so a session created on it is identifiable
    /// by the `media_ip` it returns. Returns a client connected to it.
    async fn spawn_node(ip: &str) -> GrpcMediaController {
        // A random high port range per node so start_relay's socket binds don't
        // collide with parallel tests that use the default 16384-32768 range.
        let base = 40_000u16.wrapping_add((rand::random::<u16>() % 20_000) & !1);
        let pipeline = Arc::new(MediaPipeline::new(MediaPipelineConfig {
            advertised_media_ip: Some(ip.parse().unwrap()),
            rtp_port_min: base,
            rtp_port_max: base + 400,
            ..Default::default()
        }));
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let server = MediaControllerServer::new(pipeline, None, rx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(MediaControllerServiceServer::new(server))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        GrpcMediaController::connect(format!("http://{addr}"))
            .await
            .unwrap()
    }

    async fn two_node_pool() -> MediaPool {
        // Distinct loopback IPs (127.0.0.0/8 is all local): identify which node
        // served a call by the media IP it returns, AND remain bindable — the
        // node binds its advertised_media_ip for the relay (see grpc_media_server).
        let a = spawn_node("127.0.0.1").await;
        let b = spawn_node("127.0.0.2").await;
        MediaPool::new(vec![a, b], None).unwrap()
    }

    #[tokio::test]
    async fn empty_pool_rejected() {
        assert!(MediaPool::new(vec![], None).is_err());
    }

    #[tokio::test]
    async fn least_loaded_balances_across_nodes() {
        let pool = two_node_pool().await;
        // Two sessions land on the two different nodes (least-loaded alternates),
        // identifiable by the advertised media IP each node returns.
        let s1 = pool
            .create_session_with_zones("c1", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();
        let s2 = pool
            .create_session_with_zones("c2", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();
        let ip1 = s1.media_ip.unwrap();
        let ip2 = s2.media_ip.unwrap();
        assert_ne!(ip1, ip2, "two calls should spread across both nodes");
    }

    #[tokio::test]
    async fn ops_follow_call_affinity() {
        let pool = two_node_pool().await;
        let s1 = pool
            .create_session_with_zones("call", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();
        let node_ip = s1.media_ip.unwrap();
        // set_remote_address + start_relay must reach the SAME node (a wrong node
        // answers SessionNotFound). Both legs' remotes are needed before
        // start_relay binds its sockets.
        pool.set_remote_address(
            "call",
            true,
            SbcSocketAddr::new("1.2.3.4".parse().unwrap(), 5000),
        )
        .await
        .unwrap();
        pool.set_remote_address(
            "call",
            false,
            SbcSocketAddr::new("5.6.7.8".parse().unwrap(), 6000),
        )
        .await
        .unwrap();
        pool.start_relay("call").await.unwrap();

        // A retransmitted create_session reuses the same node (same media IP).
        let again = pool
            .create_session_with_zones("call", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();
        assert_eq!(
            again.media_ip.unwrap(),
            node_ip,
            "retransmit must reuse the node"
        );
    }

    #[tokio::test]
    async fn unknown_call_is_session_not_found() {
        let pool = two_node_pool().await;
        let err = pool.start_relay("nope").await.unwrap_err();
        assert!(matches!(err, MediaPipelineError::SessionNotFound));
    }

    #[tokio::test]
    async fn remove_session_frees_affinity_and_load() {
        let pool = two_node_pool().await;
        // Fill both nodes, then a 3rd call: with c1→node0, c2→node1 (1 each), the
        // 3rd goes to node0 (tie → lowest index). Remove c1 (node0 → 0 active),
        // so the 4th call must land on node0 again.
        pool.create_session_with_zones("c1", None, None, None)
            .await
            .unwrap();
        pool.create_session_with_zones("c2", None, None, None)
            .await
            .unwrap();
        let c1_ip = pool.affinity.read().await.get("c1").copied().unwrap();
        pool.remove_session("c1").await.unwrap();
        // Affinity cleared.
        assert!(pool.node_for("c1").await.is_err());
        // The freed node (c1's) is now least-loaded → next call lands there.
        pool.create_session_with_zones("c3", None, None, None)
            .await
            .unwrap();
        assert_eq!(
            pool.affinity.read().await.get("c3").copied().unwrap(),
            c1_ip
        );
    }

    #[tokio::test]
    async fn routes_away_from_unhealthy_node() {
        let pool = two_node_pool().await;
        // Mark node 0 unhealthy (as create_session would on a transport failure);
        // every new session must now land on node 1 (127.0.0.2).
        pool.nodes[0].healthy.store(false, Ordering::Relaxed);
        for call in ["c1", "c2", "c3"] {
            let s = pool
                .create_session_with_zones(call, None, None, None)
                .await
                .unwrap();
            assert_eq!(s.media_ip.unwrap().to_string(), "127.0.0.2");
            assert_eq!(pool.affinity.read().await.get(call).copied().unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn all_unhealthy_yields_no_node_error() {
        let pool = two_node_pool().await;
        for node in pool.nodes.iter() {
            node.healthy.store(false, Ordering::Relaxed);
        }
        let err = pool
            .create_session_with_zones("c", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, MediaPipelineError::Rpc(_)));
        // allocate_ports likewise has nowhere to go.
        assert!(pool.allocate_ports().await.is_err());
    }

    #[tokio::test]
    async fn node_down_byes_its_in_flight_calls() {
        let a = spawn_node("127.0.0.1").await;
        let b = spawn_node("127.0.0.2").await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let pool = MediaPool::new(vec![a, b], Some(tx)).unwrap();

        pool.create_session_with_zones("c1", None, None, None)
            .await
            .unwrap();
        let node = pool.affinity.read().await.get("c1").copied().unwrap();

        // The node hosting c1 goes down: c1 is dropped from affinity, its slot
        // released, and its id emitted so the SIP layer BYEs it.
        pool.fail_node(node).await;
        assert!(pool.node_for("c1").await.is_err());
        assert!(!pool.nodes[node].healthy.load(Ordering::Relaxed));
        assert_eq!(pool.nodes[node].active.load(Ordering::Relaxed), 0);
        assert_eq!(rx.recv().await.unwrap(), "c1");
    }
}
