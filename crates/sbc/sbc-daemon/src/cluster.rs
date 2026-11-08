//! Cluster integration module.
//!
//! This module coordinates clustering components:
//! - Storage backends (in-memory, `Redis`, `PostgreSQL`)
//! - Service discovery (static, DNS, `Kubernetes`)
//! - Cluster membership and failover
//! - State synchronization
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-24**: Fail in Known State - Graceful failover
//! - **CP-7**: Alternate Processing Site - Multi-node clustering
//! - **CP-10**: System Recovery - Automatic failover and rejoin

use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[cfg(feature = "cluster")]
use proto_registrar::AsyncLocationService;
#[cfg(feature = "cluster")]
use sbc_config::SbcConfig;
#[cfg(feature = "cluster")]
use sbc_config::schema::ClusterAuthConfig;
#[cfg(feature = "cluster")]
use uc_cluster::{ClusterAuthKey, ClusterMembership, ClusterNode, NodeId, PeerAuthenticator};
#[cfg(feature = "cluster")]
use uc_discovery::{DiscoveryConfig, DiscoveryManager};
#[cfg(feature = "cluster")]
use uc_storage::StorageManager;

/// Cluster manager coordinates all clustering components.
#[cfg(feature = "cluster")]
pub struct ClusterManager {
    /// Storage backend manager.
    storage: Arc<StorageManager>,
    /// Discovery manager for finding peers.
    discovery: Arc<DiscoveryManager>,
    /// Cluster membership tracker.
    membership: Arc<ClusterMembership>,
    /// Async location service (storage-backed registrar).
    location_service: Arc<AsyncLocationService>,
    /// Local node ID.
    node_id: NodeId,
    /// Peer message authenticator (`[cluster.auth]`); `None` only when the
    /// cluster is configured but disabled without a key.
    authenticator: Option<Arc<PeerAuthenticator>>,
}

#[cfg(feature = "cluster")]
impl ClusterManager {
    /// Creates a new cluster manager from configuration.
    ///
    /// # Errors
    /// Returns an error if any component fails to initialize.
    pub async fn new(config: &SbcConfig) -> Result<Self, ClusterError> {
        let cluster_config =
            config
                .cluster
                .as_ref()
                .ok_or_else(|| ClusterError::NotConfigured {
                    reason: "Cluster configuration is required when cluster feature is enabled"
                        .to_string(),
                })?;

        let storage_config =
            config
                .storage
                .as_ref()
                .ok_or_else(|| ClusterError::NotConfigured {
                    reason: "Storage configuration is required when cluster feature is enabled"
                        .to_string(),
                })?;

        // Initialize storage backend
        info!(
            backend = %storage_config.backend,
            "Initializing storage backend"
        );
        let storage = StorageManager::new(storage_config.clone())
            .await
            .map_err(|e| ClusterError::StorageInitFailed {
                reason: e.to_string(),
            })?;
        let storage = Arc::new(storage);

        // Verify storage health
        if !storage.health_check().await {
            return Err(ClusterError::StorageInitFailed {
                reason: "Storage health check failed".to_string(),
            });
        }
        info!("Storage backend health check passed");

        // Initialize discovery manager with default static discovery
        // In a production deployment, this would come from extended cluster config
        let discovery_config = DiscoveryConfig::default();
        info!(
            method = ?discovery_config.method,
            "Initializing service discovery"
        );
        let discovery = DiscoveryManager::new(discovery_config).map_err(|e| {
            ClusterError::DiscoveryInitFailed {
                reason: e.to_string(),
            }
        })?;
        let discovery = Arc::new(discovery);

        // Initialize cluster membership
        let node_id = cluster_config.effective_node_id();
        info!(
            node_id = %node_id,
            role = ?cluster_config.role,
            "Initializing cluster membership"
        );
        let membership = ClusterMembership::new(cluster_config.inner.clone());
        let membership = Arc::new(membership);

        // NIST 800-53 Rev5: CM-6 — peer authentication key (IA-3, SC-23:
        // prerequisite only, no peer transport, POA&M-241). Validation
        // already requires `[cluster.auth]` when `cluster.enabled`; re-checked
        // here so a programmatic config cannot bypass it (fail closed).
        let authenticator = match &cluster_config.auth {
            Some(auth) => {
                let peers: Vec<NodeId> = membership
                    .all_members()
                    .await
                    .into_iter()
                    .map(|m| NodeId::new(m.node_id))
                    .filter(|id| *id != node_id)
                    .collect();
                Some(Arc::new(build_authenticator(auth, &node_id, peers)?))
            }
            None if cluster_config.enabled => {
                return Err(ClusterError::NotConfigured {
                    reason: "cluster.auth is required when cluster.enabled (POA&M-241)".to_string(),
                });
            }
            None => {
                warn!("cluster.auth not configured; cluster peer messages cannot be authenticated");
                None
            }
        };

        // Create async location service with storage backend
        let location_service = AsyncLocationService::new(Arc::clone(&storage));
        let location_service = Arc::new(location_service);

        // Perform initial cache sync from storage
        let synced = location_service.sync_cache().await;
        info!(synced_bindings = synced, "Initial cache sync completed");

        Ok(Self {
            storage,
            discovery,
            membership,
            location_service,
            node_id,
            authenticator,
        })
    }

    /// Returns the peer message authenticator, if `[cluster.auth]` is set.
    ///
    /// A future peer transport must verify inbound heartbeats with
    /// `ClusterMembership::handle_authenticated_heartbeat` using this
    /// authenticator, never `handle_heartbeat` (POA&M-241).
    pub const fn authenticator(&self) -> Option<&Arc<PeerAuthenticator>> {
        self.authenticator.as_ref()
    }

    /// Adds a member and authorises it as an envelope sender.
    ///
    /// This is the single mutation path for membership growth: the
    /// authenticator peer table and the membership view stay in step.
    ///
    /// # Errors
    /// Returns an error if the peer table is full or the node already exists.
    pub async fn add_member(&self, node: ClusterNode) -> Result<(), ClusterError> {
        add_member(&self.membership, self.authenticator.as_deref(), node).await
    }

    /// Removes a member and revokes it as an envelope sender.
    ///
    /// # Errors
    /// Returns an error if the node is not a member.
    pub async fn remove_member(&self, node_id: &NodeId) -> Result<(), ClusterError> {
        remove_member(&self.membership, self.authenticator.as_deref(), node_id).await
    }

    /// Returns the storage manager.
    pub const fn storage(&self) -> &Arc<StorageManager> {
        &self.storage
    }

    /// Returns the discovery manager.
    pub const fn discovery(&self) -> &Arc<DiscoveryManager> {
        &self.discovery
    }

    /// Returns the cluster membership tracker.
    pub const fn membership(&self) -> &Arc<ClusterMembership> {
        &self.membership
    }

    /// Returns the async location service for SIP registrations.
    pub const fn location_service(&self) -> &Arc<AsyncLocationService> {
        &self.location_service
    }

    /// Returns the local node ID.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Starts cluster services (discovery, heartbeat, etc.).
    ///
    /// # Errors
    /// Returns an error if cluster services fail to start.
    pub async fn start(&self) -> Result<(), ClusterError> {
        info!(node_id = %self.node_id, "Starting cluster services");

        // Discover initial peers
        match self.discovery.discover().await {
            Ok(peers) => {
                info!(peer_count = peers.len(), "Discovered cluster peers");
                for peer in &peers {
                    debug!(
                        peer_id = peer.node_id.as_ref().map_or("unknown", |n| n.as_str()),
                        address = %peer.address,
                        "Found peer"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to discover peers, continuing as standalone");
            }
        }

        // Start heartbeat sender
        // POAM: POA&M-241 — no cluster peer transport exists: discovered peers
        // are only logged, nothing sends or receives sealed heartbeats, and
        // `add_member` is not yet called from discovery. When a transport is
        // added it must seal with `self.authenticator` and feed inbound
        // envelopes to `membership.handle_authenticated_heartbeat`.

        info!("Cluster services started");
        Ok(())
    }

    /// Stops cluster services gracefully.
    pub async fn stop(&self) {
        info!(node_id = %self.node_id, "Stopping cluster services");

        // Mark the local node as failed/draining
        // The membership manager will handle the state transition
        if let Err(e) = self.membership.mark_failed(&self.node_id).await {
            warn!(error = %e, "Failed to mark node as draining");
        }

        // Flush any pending storage operations
        // (Storage manager handles this internally)

        info!("Cluster services stopped");
    }

    /// Performs health check on all cluster components.
    pub async fn health_check(&self) -> ClusterHealth {
        let storage_healthy = self.storage.health_check().await;
        let discovery_healthy = self.discovery.health_check().await;
        let location_healthy = self.location_service.health_check().await;

        let all_healthy = storage_healthy && discovery_healthy && location_healthy;

        ClusterHealth {
            healthy: all_healthy,
            storage_healthy,
            discovery_healthy,
            location_healthy,
            node_id: self.node_id.to_string(),
        }
    }

    /// Returns cluster status for API/monitoring.
    pub async fn status(&self) -> ClusterStatus {
        let health = self.health_check().await;
        let members = self.membership.all_members().await;
        let local_node = self.membership.get_node(&self.node_id).await;

        ClusterStatus {
            node_id: self.node_id.to_string(),
            role: local_node
                .as_ref()
                .map(|n| format!("{:?}", n.role))
                .unwrap_or_default(),
            state: local_node
                .as_ref()
                .map(|n| format!("{:?}", n.state))
                .unwrap_or_default(),
            health,
            member_count: members.len(),
            storage_backend: self.storage.backend_type().to_string(),
        }
    }
}

/// Builds the peer authenticator from `[cluster.auth]`.
///
/// The per-boot generation is the wall clock in nanoseconds since the Unix
/// epoch, so it increases across restarts as long as the clock does not
/// step backwards (NTP required; NIST 800-53 Rev5: AU-8).
// POAM: POA&M-241 — the generation is clock-derived, not persisted; a clock
// rollback across a restart yields a lower generation and peers reject this
// node's envelopes as replays until the clock passes the previous boot.
///
/// # Errors
/// Returns [`ClusterError::NotConfigured`] if the key file cannot be read,
/// is too short, or the peer set is invalid. Key material is never logged.
#[cfg(feature = "cluster")]
fn build_authenticator(
    auth: &ClusterAuthConfig,
    node_id: &NodeId,
    peers: impl IntoIterator<Item = NodeId>,
) -> Result<PeerAuthenticator, ClusterError> {
    let fail = |kind: &str, detail: String| {
        // NIST 800-53 Rev5: AU-2, AU-3 — key-load failure event; never the key.
        error!(
            event = "cluster.auth.load_failed",
            key_id = auth.key_id,
            node_id = %node_id,
            error_kind = kind,
            "Cluster peer authentication key load failed"
        );
        ClusterError::NotConfigured { reason: detail }
    };
    check_key_file_permissions(&auth.key_file)
        .map_err(|e| fail("permissions", format!("cluster.auth.key_file: {e}")))?;
    // NIST 800-53 Rev5: SC-12 — key is zeroized on drop by ClusterAuthKey.
    let key = ClusterAuthKey::from_file(&auth.key_file)
        .map_err(|e| fail("read", format!("cluster.auth.key_file: {e}")))?;
    let generation =
        boot_generation().map_err(|e| fail("generation", format!("cluster.auth: {e}")))?;
    let authenticator =
        PeerAuthenticator::new(key, auth.key_id, node_id.clone(), generation, peers)
            .map_err(|e| fail("authenticator", format!("cluster.auth: {e}")))?;
    info!(
        event = "cluster.auth.loaded",
        key_id = auth.key_id,
        node_id = %node_id,
        generation,
        "Cluster peer authentication key loaded"
    );
    Ok(authenticator)
}

/// Per-boot generation: Unix time in nanoseconds (saturating).
///
/// # Errors
/// A clock before the Unix epoch is rejected rather than mapped to 0, which
/// would collide with every other mis-set boot (replay window reuse).
#[cfg(feature = "cluster")]
fn boot_generation() -> Result<u64, String> {
    generation_since_epoch(std::time::SystemTime::now())
}

#[cfg(feature = "cluster")]
fn generation_since_epoch(now: std::time::SystemTime) -> Result<u64, String> {
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .map_err(|_| "system clock is before the Unix epoch".to_string())
}

/// Refuses a key file readable or writable by group/other.
///
/// ## NIST 800-53 Rev5: SC-12, AC-3
// POAM: POA&M-260 — the owner == effective uid check is not implemented:
// sbc-daemon has no libc/nix/rustix dependency to query geteuid().
#[cfg(all(feature = "cluster", unix))]
fn check_key_file_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{}: mode {mode:o} grants group/other access; require 0600 or 0400",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(all(feature = "cluster", not(unix)))]
fn check_key_file_permissions(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

/// Authorises `node` as a sender, then adds it to `membership`. The peer is
/// revoked again if the insert fails for any reason other than the node
/// already being a member. Membership is never mutated while the
/// authenticator's internal lock is held.
#[cfg(feature = "cluster")]
async fn add_member(
    membership: &ClusterMembership,
    auth: Option<&PeerAuthenticator>,
    node: ClusterNode,
) -> Result<(), ClusterError> {
    let id = node.id.clone();
    if let Some(a) = auth {
        a.add_peer(id.clone())
            .map_err(|e| ClusterError::MembershipError {
                reason: e.to_string(),
            })?;
    }
    match membership.add_node(node).await {
        Ok(()) => Ok(()),
        // Already a member: it was (and stays) an authorised sender.
        Err(e @ uc_cluster::ClusterError::NodeAlreadyExists { .. }) => {
            Err(ClusterError::MembershipError {
                reason: e.to_string(),
            })
        }
        Err(e) => {
            if let Some(a) = auth {
                a.remove_peer(&id);
            }
            Err(ClusterError::MembershipError {
                reason: e.to_string(),
            })
        }
    }
}

/// Removes `node_id` from `membership` and revokes it as a sender. The peer
/// is revoked even if the membership removal fails, so a partially-known
/// node can never keep sending authenticated envelopes.
#[cfg(feature = "cluster")]
async fn remove_member(
    membership: &ClusterMembership,
    auth: Option<&PeerAuthenticator>,
    node_id: &NodeId,
) -> Result<(), ClusterError> {
    let result = membership.remove_node(node_id).await;
    if let Some(a) = auth {
        a.remove_peer(node_id);
    }
    result
        .map(|_| ())
        .map_err(|e| ClusterError::MembershipError {
            reason: e.to_string(),
        })
}

/// Cluster health status.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ClusterHealth {
    /// Overall health status.
    pub healthy: bool,
    /// Storage backend health.
    pub storage_healthy: bool,
    /// Discovery service health.
    pub discovery_healthy: bool,
    /// Location service health.
    pub location_healthy: bool,
    /// Node ID.
    pub node_id: String,
}

/// Cluster status for API/monitoring.
#[derive(Debug, Clone)]
pub struct ClusterStatus {
    /// Local node ID.
    pub node_id: String,
    /// Local node role.
    pub role: String,
    /// Local node state.
    pub state: String,
    /// Health status.
    pub health: ClusterHealth,
    /// Number of cluster members.
    pub member_count: usize,
    /// Storage backend type.
    pub storage_backend: String,
}

/// Cluster-related errors.
#[derive(Debug)]
pub enum ClusterError {
    /// Cluster not configured.
    NotConfigured {
        /// Reason.
        reason: String,
    },
    /// Storage initialization failed.
    StorageInitFailed {
        /// Reason.
        reason: String,
    },
    /// Discovery initialization failed.
    DiscoveryInitFailed {
        /// Reason.
        reason: String,
    },
    /// Membership error.
    MembershipError {
        /// Reason.
        reason: String,
    },
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured { reason } => write!(f, "Cluster not configured: {reason}"),
            Self::StorageInitFailed { reason } => {
                write!(f, "Storage initialization failed: {reason}")
            }
            Self::DiscoveryInitFailed { reason } => {
                write!(f, "Discovery initialization failed: {reason}")
            }
            Self::MembershipError { reason } => write!(f, "Membership error: {reason}"),
        }
    }
}

impl std::error::Error for ClusterError {}

/// Stub implementation when cluster feature is disabled.
#[cfg(not(feature = "cluster"))]
pub struct ClusterManager;

#[cfg(not(feature = "cluster"))]
impl ClusterManager {
    /// Cluster feature is disabled.
    pub async fn new(_config: &sbc_config::SbcConfig) -> Result<Self, ClusterError> {
        Err(ClusterError::NotConfigured {
            reason: "Cluster feature is not enabled. Rebuild with --features cluster".to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_error_display() {
        let err = ClusterError::NotConfigured {
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("test"));

        let err = ClusterError::StorageInitFailed {
            reason: "connection failed".to_string(),
        };
        assert!(err.to_string().contains("connection failed"));
    }

    #[cfg(feature = "cluster")]
    mod auth {
        use super::super::*;
        use bytes::Bytes;
        use std::io::Write;
        use uc_cluster::{ClusterConfig, NodeEndpoints, NodeRole};

        fn key_file(len: usize) -> tempfile::NamedTempFile {
            let mut f = tempfile::NamedTempFile::new().expect("tempfile");
            f.write_all(&vec![0x5a; len]).expect("write key");
            f
        }

        fn auth_cfg(f: &tempfile::NamedTempFile) -> ClusterAuthConfig {
            ClusterAuthConfig {
                key_file: f.path().to_path_buf(),
                key_id: 9,
            }
        }

        fn node(id: &str) -> ClusterNode {
            let a: std::net::SocketAddr = "192.0.2.1:5060".parse().expect("addr");
            ClusterNode::new(
                NodeId::new(id),
                NodeRole::Secondary,
                "r".to_string(),
                "z".to_string(),
                NodeEndpoints::new(a.into(), a, a, a),
            )
        }

        #[test]
        fn missing_key_file_rejected() {
            let cfg = ClusterAuthConfig {
                key_file: "/nonexistent/usg-sbc/cluster.key".into(),
                key_id: 1,
            };
            let msg = build_authenticator(&cfg, &NodeId::new("a"), [])
                .map(|_| ())
                .expect_err("missing key file accepted")
                .to_string();
            assert!(msg.contains("cluster.auth.key_file"));
        }

        #[test]
        fn short_key_rejected() {
            let f = key_file(uc_cluster::auth::MIN_KEY_LEN - 1);
            assert!(build_authenticator(&auth_cfg(&f), &NodeId::new("a"), []).is_err());
        }

        #[test]
        fn generation_is_nonzero() {
            assert!(boot_generation().expect("clock") > 0);
        }

        #[test]
        fn pre_epoch_generation_rejected() {
            let t = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
            assert!(generation_since_epoch(t).is_err());
        }

        #[cfg(unix)]
        #[test]
        fn group_readable_key_file_rejected() {
            use std::os::unix::fs::PermissionsExt;
            let f = key_file(uc_cluster::auth::MIN_KEY_LEN);
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o640))
                .expect("chmod");
            let msg = build_authenticator(&auth_cfg(&f), &NodeId::new("a"), [])
                .map(|_| ())
                .expect_err("0640 key accepted")
                .to_string();
            assert!(msg.contains("group/other"));
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
            assert!(build_authenticator(&auth_cfg(&f), &NodeId::new("a"), []).is_ok());
        }

        #[tokio::test]
        async fn remove_unknown_member_still_revokes_peer() {
            let f = key_file(uc_cluster::auth::MIN_KEY_LEN);
            let local = build_authenticator(&auth_cfg(&f), &NodeId::new("a"), [NodeId::new("b")])
                .expect("a");
            let peer = build_authenticator(&auth_cfg(&f), &NodeId::new("b"), []).expect("b");
            let membership = ClusterMembership::new(ClusterConfig::default());
            let env = peer.seal(Bytes::from_static(b"hb")).expect("seal");
            assert!(local.verify(&env).is_ok());
            assert!(
                remove_member(&membership, Some(&local), &NodeId::new("b"))
                    .await
                    .is_err()
            );
            let env = peer.seal(Bytes::from_static(b"hb2")).expect("seal");
            assert!(local.verify(&env).is_err(), "revoked peer still accepted");
        }

        #[tokio::test]
        async fn add_and_remove_member_track_authenticator() {
            let f = key_file(uc_cluster::auth::MIN_KEY_LEN);
            let local = build_authenticator(&auth_cfg(&f), &NodeId::new("a"), []).expect("a");
            let peer = build_authenticator(&auth_cfg(&f), &NodeId::new("b"), []).expect("b");
            let membership = ClusterMembership::new(ClusterConfig::default());

            let env = peer.seal(Bytes::from_static(b"hb")).expect("seal");
            assert!(local.verify(&env).is_err(), "unknown sender accepted");

            add_member(&membership, Some(&local), node("b"))
                .await
                .expect("add");
            assert!(local.verify(&env).is_ok(), "member rejected");

            // Duplicate add fails but keeps the member authorised.
            assert!(
                add_member(&membership, Some(&local), node("b"))
                    .await
                    .is_err()
            );
            let env = peer.seal(Bytes::from_static(b"hb")).expect("seal");
            assert!(local.verify(&env).is_ok(), "duplicate add revoked member");

            remove_member(&membership, Some(&local), &NodeId::new("b"))
                .await
                .expect("remove");
            let env = peer.seal(Bytes::from_static(b"hb")).expect("seal");
            assert!(local.verify(&env).is_err(), "removed member accepted");
            assert!(
                remove_member(&membership, Some(&local), &NodeId::new("b"))
                    .await
                    .is_err()
            );
        }
    }

    #[test]
    fn test_cluster_health() {
        let health = ClusterHealth {
            healthy: true,
            storage_healthy: true,
            discovery_healthy: true,
            location_healthy: true,
            node_id: "test-node".to_string(),
        };
        assert!(health.healthy);
    }
}
