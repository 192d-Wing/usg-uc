//! # High Availability Clustering for USG SBC
//!
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::match_same_arms)]
//!
//! This crate provides core clustering primitives for the USG Session Border Controller,
//! enabling carrier-grade reliability through:
//!
//! - **Node Management**: Cluster membership and node lifecycle
//! - **Failure Detection**: Heartbeat-based health monitoring
//! - **Failover Coordination**: Automatic session takeover on node failure
//! - **Quorum Management**: Split-brain prevention
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-24**: Fail in Known State
//! - **CP-7**: Alternate Processing Site
//! - **CP-10**: System Recovery and Reconstitution
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Cluster Manager                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Membership   │   Heartbeat    │   Failover    │  Quorum   │
//! │  Tracking     │   Protocol     │   Coordinator │  Policy   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use uc_cluster::{ClusterConfig, ClusterManager, NodeRole};
//!
//! let config = ClusterConfig::builder()
//!     .cluster_id("production-sbc")
//!     .node_id("node-01")
//!     .role(NodeRole::Primary)
//!     .build();
//!
//! let manager = ClusterManager::new(config).await?;
//! manager.start().await?;
//! ```

pub mod config;
pub mod error;
pub mod failover;
pub mod health;
pub mod membership;
pub mod node;

pub use config::{
    ClusterConfig, FailoverConfig, FailoverStrategy, HeartbeatConfig, ReplicationConfig,
};
pub use error::{ClusterError, ClusterResult};
pub use failover::{FailoverCoordinator, TakeoverResult};
pub use health::{HealthChecker, Heartbeat};
pub use membership::{ClusterMembership, QuorumPolicy};
pub use node::{ClusterNode, NodeEndpoints, NodeId, NodeRole, NodeState};
