//! Cluster integration module.
//!
//! This module coordinates clustering components:
//! - Storage backends (in-memory, Redis, PostgreSQL)
//! - Service discovery (static, DNS, Kubernetes)
//! - Cluster membership and failover
//! - State synchronization
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-24**: Fail in Known State - Graceful failover
//! - **CP-7**: Alternate Processing Site - Multi-node clustering
//! - **CP-10**: System Recovery - Automatic failover and rejoin

use std::sync::Arc;
use tracing::{debug, info, warn};

#[cfg(feature = "cluster")]
use proto_registrar::AsyncLocationService;
#[cfg(feature = "cluster")]
use sbc_config::SbcConfig;
#[cfg(feature = "cluster")]
use uc_cluster::{ClusterMembership, NodeId};
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
        let membership = ClusterMembership::new(cluster_config.clone());
        let membership = Arc::new(membership);

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
        })
    }

    /// Returns the storage manager.
    pub fn storage(&self) -> &Arc<StorageManager> {
        &self.storage
    }

    /// Returns the discovery manager.
    pub fn discovery(&self) -> &Arc<DiscoveryManager> {
        &self.discovery
    }

    /// Returns the cluster membership tracker.
    pub fn membership(&self) -> &Arc<ClusterMembership> {
        &self.membership
    }

    /// Returns the async location service for SIP registrations.
    pub fn location_service(&self) -> &Arc<AsyncLocationService> {
        &self.location_service
    }

    /// Returns the local node ID.
    pub fn node_id(&self) -> &NodeId {
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
                        peer_id = peer.node_id.as_ref().map(|n| n.as_str()).unwrap_or("unknown"),
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
        // (In a full implementation, this would spawn background tasks)

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

/// Cluster health status.
#[derive(Debug, Clone)]
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
