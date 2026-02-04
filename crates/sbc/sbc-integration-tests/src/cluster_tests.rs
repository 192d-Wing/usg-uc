//! Cluster integration tests.
//!
//! Tests for the clustering infrastructure including:
//! - Storage backends (in-memory, Redis, PostgreSQL)
//! - Service discovery (static, DNS, Kubernetes)
//! - Cluster membership and failover
//! - Storage-backed registrar (AsyncLocationService)
//!
//! ## Running Tests
//!
//! ```bash
//! # In-memory storage tests (no external dependencies)
//! cargo test -p sbc-integration-tests --features cluster
//!
//! # Redis tests (requires Redis on localhost:6379)
//! cargo test -p sbc-integration-tests --features redis -- --ignored
//!
//! # PostgreSQL tests (requires PostgreSQL on localhost:5432)
//! cargo test -p sbc-integration-tests --features postgres -- --ignored
//! ```

#![cfg(feature = "cluster")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use uc_cluster::{ClusterConfig, ClusterMembership, ClusterNode, NodeEndpoints, NodeId, NodeRole};
use uc_discovery::{DiscoveredPeer, DiscoveryConfig, DiscoveryManager, DiscoveryMethod};
use uc_storage::{StorageConfig, StorageManager};
use uc_types::SbcSocketAddr;

// ============================================================================
// Storage Backend Tests
// ============================================================================

mod storage_tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_storage_basic_operations() {
        let config = StorageConfig::in_memory();
        let storage = StorageManager::new(config).await.unwrap();

        // Test set and get
        storage
            .set("test:key1", b"value1", None)
            .await
            .expect("set should succeed");

        let result = storage.get("test:key1").await.expect("get should succeed");
        assert_eq!(result.as_deref(), Some(b"value1".as_slice()));

        // Test delete
        let deleted = storage
            .delete("test:key1")
            .await
            .expect("delete should succeed");
        assert!(deleted);

        // Verify deletion
        let result = storage.get("test:key1").await.expect("get should succeed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_storage_ttl() {
        let config = StorageConfig::in_memory();
        let storage = StorageManager::new(config).await.unwrap();

        // Set with short TTL
        storage
            .set("test:ttl", b"expires", Some(Duration::from_millis(100)))
            .await
            .expect("set should succeed");

        // Should exist immediately
        let result = storage.get("test:ttl").await.expect("get should succeed");
        assert!(result.is_some());

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be gone
        let result = storage.get("test:ttl").await.expect("get should succeed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_storage_keys_pattern() {
        let config = StorageConfig::in_memory();
        let storage = StorageManager::new(config).await.unwrap();

        // Set multiple keys
        storage
            .set("sip:binding:alice@example.com", b"1", None)
            .await
            .unwrap();
        storage
            .set("sip:binding:bob@example.com", b"2", None)
            .await
            .unwrap();
        storage
            .set("sip:session:call-123", b"3", None)
            .await
            .unwrap();

        // Query bindings only
        let keys = storage
            .keys("sip:binding:*")
            .await
            .expect("keys should succeed");
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k.contains("alice")));
        assert!(keys.iter().any(|k| k.contains("bob")));
    }

    #[tokio::test]
    async fn test_in_memory_storage_increment() {
        let config = StorageConfig::in_memory();
        let storage = StorageManager::new(config).await.unwrap();

        // Increment non-existent key (should start at 0)
        let val = storage
            .increment("test:counter", 1)
            .await
            .expect("increment should succeed");
        assert_eq!(val, 1);

        // Increment existing key
        let val = storage
            .increment("test:counter", 5)
            .await
            .expect("increment should succeed");
        assert_eq!(val, 6);

        // Decrement
        let val = storage
            .increment("test:counter", -2)
            .await
            .expect("increment should succeed");
        assert_eq!(val, 4);
    }

    #[tokio::test]
    async fn test_in_memory_storage_health_check() {
        let config = StorageConfig::in_memory();
        let storage = StorageManager::new(config).await.unwrap();

        assert!(storage.health_check().await);
    }

    #[tokio::test]
    #[ignore = "Requires Redis on localhost:6379"]
    #[cfg(feature = "redis")]
    async fn test_redis_storage_basic_operations() {
        let config = StorageConfig::redis("redis://localhost:6379");
        let storage = StorageManager::new(config)
            .await
            .expect("Redis connection should succeed");

        // Clean up first
        let _ = storage.delete("test:redis:key1").await;

        // Test set and get
        storage
            .set("test:redis:key1", b"redis_value", None)
            .await
            .expect("set should succeed");

        let result = storage
            .get("test:redis:key1")
            .await
            .expect("get should succeed");
        assert_eq!(result.as_deref(), Some(b"redis_value".as_slice()));

        // Cleanup
        storage.delete("test:redis:key1").await.unwrap();
    }

    #[tokio::test]
    #[ignore = "Requires PostgreSQL on localhost:5432"]
    #[cfg(feature = "postgres")]
    async fn test_postgres_storage_basic_operations() {
        let config = StorageConfig::postgres("postgres://localhost/sbc_test");
        let storage = StorageManager::new(config)
            .await
            .expect("PostgreSQL connection should succeed");

        // Clean up first
        let _ = storage.delete("test:pg:key1").await;

        // Test set and get
        storage
            .set("test:pg:key1", b"pg_value", None)
            .await
            .expect("set should succeed");

        let result = storage
            .get("test:pg:key1")
            .await
            .expect("get should succeed");
        assert_eq!(result.as_deref(), Some(b"pg_value".as_slice()));

        // Cleanup
        storage.delete("test:pg:key1").await.unwrap();
    }
}

// ============================================================================
// Discovery Tests
// ============================================================================

mod discovery_tests {
    use super::*;

    #[tokio::test]
    async fn test_static_discovery() {
        let peer1: SocketAddr = "[::1]:5070".parse().unwrap();
        let peer2: SocketAddr = "[::1]:5071".parse().unwrap();

        let config = DiscoveryConfig::builder()
            .method(DiscoveryMethod::Static)
            .add_static_peer(peer1)
            .add_static_peer(peer2)
            .build();

        let manager = DiscoveryManager::new(config).expect("discovery manager should create");

        let peers = manager.discover().await.expect("discovery should succeed");

        assert_eq!(peers.len(), 2);
        assert!(peers.iter().any(|p| p.address == peer1));
        assert!(peers.iter().any(|p| p.address == peer2));
    }

    #[tokio::test]
    async fn test_static_discovery_empty() {
        let config = DiscoveryConfig::builder()
            .method(DiscoveryMethod::Static)
            .build();

        let manager = DiscoveryManager::new(config).expect("discovery manager should create");

        let peers = manager.discover().await.expect("discovery should succeed");
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_discovery_health_check() {
        let config = DiscoveryConfig::default();
        let manager = DiscoveryManager::new(config).expect("discovery manager should create");

        assert!(manager.health_check().await);
    }

    #[test]
    fn test_discovered_peer_metadata() {
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();
        let peer = DiscoveredPeer::new(addr)
            .with_priority(10)
            .with_weight(50)
            .with_metadata(
                uc_discovery::PeerMetadata::new()
                    .with_region("us-east-1")
                    .with_zone("us-east-1a")
                    .with_label("env", "prod"),
            );

        assert_eq!(peer.address, addr);
        assert_eq!(peer.priority, 10);
        assert_eq!(peer.weight, 50);
        assert!(peer.metadata.is_some());

        let meta = peer.metadata.unwrap();
        assert_eq!(meta.region.as_deref(), Some("us-east-1"));
        assert_eq!(meta.zone.as_deref(), Some("us-east-1a"));
        assert_eq!(meta.labels.get("env"), Some(&"prod".to_string()));
    }
}

// ============================================================================
// Cluster Membership Tests
// ============================================================================

mod membership_tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    fn create_test_endpoints() -> NodeEndpoints {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060);
        NodeEndpoints::new(
            SbcSocketAddr::from(addr),
            addr,
            addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
        )
    }

    #[tokio::test]
    async fn test_cluster_membership_creation() {
        let config = ClusterConfig::builder()
            .node_id("node-01")
            .cluster_id("test-cluster")
            .role(NodeRole::Primary)
            .build();

        let membership = ClusterMembership::new(config);

        // Initially no members (local node not auto-added)
        let members = membership.all_members().await;
        assert_eq!(members.len(), 0);
    }

    #[tokio::test]
    async fn test_cluster_membership_add_node() {
        let config = ClusterConfig::builder()
            .node_id("node-01")
            .cluster_id("test-cluster")
            .role(NodeRole::Primary)
            .build();

        let membership = ClusterMembership::new(config);

        // Add a node
        let node = ClusterNode::new(
            NodeId::new("node-02"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            create_test_endpoints(),
        );

        membership
            .add_node(node)
            .await
            .expect("add_node should succeed");

        let members = membership.all_members().await;
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].node_id.as_str(), "node-02");
    }

    #[tokio::test]
    async fn test_cluster_membership_remove_node() {
        let config = ClusterConfig::builder()
            .node_id("node-01")
            .cluster_id("test-cluster")
            .role(NodeRole::Primary)
            .build();

        let membership = ClusterMembership::new(config);

        // Add and then remove a node
        let node = ClusterNode::new(
            NodeId::new("node-03"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            create_test_endpoints(),
        );

        membership.add_node(node).await.unwrap();
        assert_eq!(membership.member_count().await, 1);

        membership
            .remove_node(&NodeId::new("node-03"))
            .await
            .expect("remove_node should succeed");

        assert_eq!(membership.member_count().await, 0);
    }

    #[tokio::test]
    async fn test_cluster_membership_get_node() {
        let config = ClusterConfig::builder()
            .node_id("node-01")
            .cluster_id("test-cluster")
            .role(NodeRole::Primary)
            .build();

        let membership = ClusterMembership::new(config);

        let node = ClusterNode::new(
            NodeId::new("node-04"),
            NodeRole::Secondary,
            "us-west-2".to_string(),
            "us-west-2a".to_string(),
            create_test_endpoints(),
        );

        membership.add_node(node).await.unwrap();

        let found = membership.get_node(&NodeId::new("node-04")).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().region, "us-west-2");

        // Non-existent node
        let not_found = membership.get_node(&NodeId::new("nonexistent")).await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_cluster_view_version_increments() {
        let config = ClusterConfig::builder()
            .node_id("node-01")
            .cluster_id("test-cluster")
            .role(NodeRole::Primary)
            .build();

        let membership = ClusterMembership::new(config);
        let initial = membership.view_version();

        let node = ClusterNode::new(
            NodeId::new("node-05"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            create_test_endpoints(),
        );

        membership.add_node(node).await.unwrap();
        assert!(membership.view_version() > initial);
    }
}

// ============================================================================
// AsyncLocationService Tests (Storage-Backed Registrar)
// ============================================================================

mod registrar_tests {
    use super::*;
    use proto_registrar::{AsyncLocationService, Binding};

    fn create_test_binding(aor: &str, contact: &str, call_id: &str, cseq: u32) -> Binding {
        let mut binding = Binding::new(aor, contact, call_id, cseq);
        binding.set_user_agent("Test UA/1.0");
        binding
    }

    #[tokio::test]
    async fn test_async_location_service_add_binding() {
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());
        let service = AsyncLocationService::new(storage);

        let binding = create_test_binding(
            "sip:alice@example.com",
            "sip:alice@192.168.1.100:5060",
            "abc123",
            1,
        );

        service
            .add_binding(binding)
            .await
            .expect("add_binding should succeed");

        // Lookup should find the binding
        let bindings = service.lookup("sip:alice@example.com").await;
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].contact_uri(), "sip:alice@192.168.1.100:5060");
    }

    #[tokio::test]
    async fn test_async_location_service_multiple_bindings() {
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());
        let service = AsyncLocationService::new(storage);

        // Add two bindings for same AOR
        let binding1 = create_test_binding(
            "sip:bob@example.com",
            "sip:bob@192.168.1.100:5060",
            "call1",
            1,
        );

        let binding2 = create_test_binding(
            "sip:bob@example.com",
            "sip:bob@192.168.1.101:5060",
            "call2",
            1,
        );

        service.add_binding(binding1).await.unwrap();
        service.add_binding(binding2).await.unwrap();

        let bindings = service.lookup("sip:bob@example.com").await;
        assert_eq!(bindings.len(), 2);
    }

    #[tokio::test]
    async fn test_async_location_service_remove_binding() {
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());
        let service = AsyncLocationService::new(storage);

        let binding = create_test_binding(
            "sip:charlie@example.com",
            "sip:charlie@192.168.1.100:5060",
            "call3",
            1,
        );

        service.add_binding(binding).await.unwrap();

        // Verify it exists
        let bindings = service.lookup("sip:charlie@example.com").await;
        assert_eq!(bindings.len(), 1);

        // Remove it
        service
            .remove_binding("sip:charlie@example.com", "sip:charlie@192.168.1.100:5060")
            .await
            .unwrap();

        // Should be gone
        let bindings = service.lookup("sip:charlie@example.com").await;
        assert!(bindings.is_empty());
    }

    #[tokio::test]
    async fn test_async_location_service_remove_all_bindings() {
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());
        let service = AsyncLocationService::new(storage);

        // Add multiple bindings
        for i in 0..5 {
            let binding = create_test_binding(
                "sip:dave@example.com",
                &format!("sip:dave@192.168.1.{}:5060", 100 + i),
                &format!("call{i}"),
                1,
            );
            service.add_binding(binding).await.unwrap();
        }

        let bindings = service.lookup("sip:dave@example.com").await;
        assert_eq!(bindings.len(), 5);

        // Remove all
        let removed = service
            .remove_all_bindings("sip:dave@example.com")
            .await
            .unwrap();
        assert_eq!(removed, 5);

        // Should all be gone
        let bindings = service.lookup("sip:dave@example.com").await;
        assert!(bindings.is_empty());
    }

    #[tokio::test]
    async fn test_async_location_service_health_check() {
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());
        let service = AsyncLocationService::new(storage);

        assert!(service.health_check().await);
    }

    #[tokio::test]
    async fn test_async_location_service_cache_reload() {
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());
        let service = AsyncLocationService::new(Arc::clone(&storage));

        // Add a binding
        let binding = create_test_binding(
            "sip:eve@example.com",
            "sip:eve@192.168.1.100:5060",
            "sync-test",
            1,
        );

        service.add_binding(binding).await.unwrap();

        // Create a new service instance with same storage (simulates another node)
        let service2 = AsyncLocationService::new(storage);

        // Cache is empty, but storage has the binding
        // lookup() will load from storage on cache miss
        let bindings = service2.lookup("sip:eve@example.com").await;
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].contact_uri(), "sip:eve@192.168.1.100:5060");

        // Now cache should be populated
        let stats = service2.stats().await;
        assert_eq!(stats.cached_bindings, 1);
    }
}

// ============================================================================
// End-to-End Cluster Integration Tests
// ============================================================================

mod e2e_tests {
    use super::*;
    use proto_registrar::{AsyncLocationService, Binding};
    use std::net::{IpAddr, Ipv6Addr};

    fn create_test_endpoints() -> NodeEndpoints {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060);
        NodeEndpoints::new(
            SbcSocketAddr::from(addr),
            addr,
            addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
        )
    }

    #[tokio::test]
    async fn test_cluster_formation_with_discovery() {
        // Create cluster config
        let config = ClusterConfig::builder()
            .node_id("node-e2e-1")
            .cluster_id("e2e-cluster")
            .role(NodeRole::Primary)
            .build();

        let membership = ClusterMembership::new(config);

        // Add secondary nodes
        let node2 = ClusterNode::new(
            NodeId::new("node-e2e-2"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1a".to_string(),
            create_test_endpoints(),
        );

        let node3 = ClusterNode::new(
            NodeId::new("node-e2e-3"),
            NodeRole::Secondary,
            "us-east-1".to_string(),
            "us-east-1b".to_string(),
            create_test_endpoints(),
        );

        membership.add_node(node2).await.unwrap();
        membership.add_node(node3).await.unwrap();

        assert_eq!(membership.member_count().await, 2);
    }

    #[tokio::test]
    async fn test_storage_backed_registration_flow() {
        // Setup storage
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());

        // Create location service
        let location_service = AsyncLocationService::new(Arc::clone(&storage));

        // Simulate REGISTER processing
        let aor = "sip:frank@example.com";
        let contact = "sip:frank@10.0.0.50:5060";

        // Initial REGISTER
        let mut binding = Binding::new(aor, contact, "reg-flow-1", 1);
        binding.set_instance_id("<urn:uuid:abc123>");
        binding.set_reg_id(1);
        binding.set_user_agent("TestPhone/1.0");

        location_service.add_binding(binding).await.unwrap();

        // Verify registration
        let bindings = location_service.lookup(aor).await;
        assert_eq!(bindings.len(), 1);

        // Re-REGISTER (refresh)
        let mut binding2 = Binding::new(aor, contact, "reg-flow-2", 2);
        binding2.set_instance_id("<urn:uuid:abc123>");
        binding2.set_reg_id(1);
        binding2.set_user_agent("TestPhone/1.0");

        location_service.add_binding(binding2).await.unwrap();

        // Should still have 1 binding (updated)
        let bindings = location_service.lookup(aor).await;
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].cseq(), 2);

        // Unregister (expires=0)
        location_service.remove_binding(aor, contact).await.unwrap();

        // Should be gone
        let bindings = location_service.lookup(aor).await;
        assert!(bindings.is_empty());
    }

    #[tokio::test]
    async fn test_cluster_with_shared_storage() {
        // Simulates two nodes sharing the same storage backend
        let config = StorageConfig::in_memory();
        let storage = Arc::new(StorageManager::new(config).await.unwrap());

        // Node 1 location service
        let service1 = AsyncLocationService::new(Arc::clone(&storage));

        // Node 2 location service (same storage)
        let service2 = AsyncLocationService::new(Arc::clone(&storage));

        // Node 1 registers a user
        let binding = Binding::new(
            "sip:grace@example.com",
            "sip:grace@10.0.0.100:5060",
            "shared-1",
            1,
        );

        service1.add_binding(binding).await.unwrap();

        // Node 2 syncs cache
        service2.sync_cache().await;

        // Node 2 should see the registration
        let bindings = service2.lookup("sip:grace@example.com").await;
        assert_eq!(bindings.len(), 1);

        // Node 2 can route to the user
        assert_eq!(bindings[0].contact_uri(), "sip:grace@10.0.0.100:5060");
    }
}
