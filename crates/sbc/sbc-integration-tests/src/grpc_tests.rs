//! gRPC API integration tests.
//!
//! Tests for the gRPC management API including:
//! - Health check protocol compliance
//! - ConfigService operations
//! - SystemService operations
//! - CallService operations
//! - RegistrationService operations
//! - ClusterService operations (feature-gated)
//!
//! ## Running Tests
//!
//! ```bash
//! # Basic gRPC tests
//! cargo test -p sbc-integration-tests --features grpc
//!
//! # With reflection service tests
//! cargo test -p sbc-integration-tests --features grpc-reflection
//!
//! # With cluster service tests
//! cargo test -p sbc-integration-tests --features "grpc,cluster"
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CA-8**: Penetration Testing
//! - **SA-11**: Developer Testing and Evaluation

#![cfg(feature = "grpc")]

// ============================================================================
// Proto Message Tests
// ============================================================================

mod proto_message_tests {
    use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus};
    use sbc_grpc_api::sbc::{
        // Config service
        GetConfigRequest, GetConfigResponse,
        ValidateConfigRequest, ValidateConfigResponse,
        ReloadConfigRequest, ReloadConfigResponse,
        // System service
        GetVersionRequest, GetVersionResponse,
        GetStatsRequest, GetStatsResponse,
        GetMetricsRequest, GetMetricsResponse,
        GetTlsStatusRequest, GetTlsStatusResponse,
        // Call service
        ListCallsRequest, ListCallsResponse,
        GetCallRequest, GetCallResponse,
        GetCallStatsRequest, GetCallStatsResponse,
        TerminateCallRequest, TerminateCallResponse,
        CallState, CallInfo, CallLegInfo,
        // Registration service
        ListRegistrationsRequest, ListRegistrationsResponse,
        GetRegistrationRequest, GetRegistrationResponse,
        GetRegistrationStatsRequest, GetRegistrationStatsResponse,
        DeleteRegistrationRequest, DeleteRegistrationResponse,
        RegistrationInfo, ContactInfo,
    };

    #[test]
    fn test_health_check_request_default() {
        let req = HealthCheckRequest::default();
        assert!(req.service.is_empty());
    }

    #[test]
    fn test_health_check_request_with_service() {
        let req = HealthCheckRequest {
            service: "sbc".to_string(),
        };
        assert_eq!(req.service, "sbc");
    }

    #[test]
    fn test_health_check_response_serving_status() {
        let resp = HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        };
        assert_eq!(resp.status, 1);
    }

    #[test]
    fn test_serving_status_enum_values() {
        assert_eq!(ServingStatus::Unknown as i32, 0);
        assert_eq!(ServingStatus::Serving as i32, 1);
        assert_eq!(ServingStatus::NotServing as i32, 2);
        assert_eq!(ServingStatus::ServiceUnknown as i32, 3);
    }

    #[test]
    fn test_config_service_messages() {
        // GetConfig
        let get_req = GetConfigRequest {
            sections: vec![],
            format: "json".to_string(),
        };
        assert_eq!(get_req.format, "json");

        let get_resp = GetConfigResponse {
            config: "{}".to_string(),
            format: "json".to_string(),
            version: "1.0.0".to_string(),
            last_modified: 1700000000,
        };
        assert_eq!(get_resp.config, "{}");
        assert_eq!(get_resp.version, "1.0.0");

        // ValidateConfig
        let validate_req = ValidateConfigRequest {
            config: "test".to_string(),
            format: "toml".to_string(),
        };
        assert_eq!(validate_req.config, "test");

        let validate_resp = ValidateConfigResponse {
            valid: true,
            errors: vec![],
            warnings: vec![],
        };
        assert!(validate_resp.valid);
        assert!(validate_resp.errors.is_empty());

        // ReloadConfig
        let reload_req = ReloadConfigRequest {
            path: String::new(),
        };
        assert!(reload_req.path.is_empty());

        let reload_resp = ReloadConfigResponse {
            success: true,
            message: "Reloaded".to_string(),
            changed_sections: vec!["general".to_string()],
            new_version: "2.0.0".to_string(),
        };
        assert!(reload_resp.success);
    }

    #[test]
    fn test_system_service_messages() {
        // GetVersion
        let ver_req = GetVersionRequest::default();
        let _ = ver_req;

        let ver_resp = GetVersionResponse {
            version: "1.0.0".to_string(),
            name: "sbc-daemon".to_string(),
            build_time: "2024-01-01".to_string(),
            rust_version: "1.75.0".to_string(),
            git_commit: "abc123".to_string(),
            git_branch: "main".to_string(),
            release_build: true,
            target: "x86_64-unknown-linux-gnu".to_string(),
            features: vec!["grpc".to_string()],
        };
        assert_eq!(ver_resp.version, "1.0.0");
        assert_eq!(ver_resp.git_commit, "abc123");

        // GetStats
        let stats_req = GetStatsRequest::default();
        let _ = stats_req;

        let stats_resp = GetStatsResponse {
            calls_total: 1000,
            calls_active: 10,
            registrations_total: 500,
            registrations_active: 50,
            messages_received: 5000,
            messages_sent: 4500,
            rate_limited: 5,
            uptime_secs: 3600,
            start_time: None,
            memory_usage_bytes: 100_000_000,
            peak_memory_bytes: 150_000_000,
            active_connections: 20,
            active_transactions: 15,
            active_dialogs: 10,
        };
        assert_eq!(stats_resp.uptime_secs, 3600);
        assert_eq!(stats_resp.calls_active, 10);

        // GetMetrics
        let metrics_req = GetMetricsRequest {
            prefix: String::new(),
            include_histograms: true,
        };
        assert!(metrics_req.include_histograms);

        let metrics_resp = GetMetricsResponse {
            metrics: "# HELP test".to_string(),
            content_type: "text/plain".to_string(),
        };
        assert!(!metrics_resp.metrics.is_empty());

        // GetTlsStatus
        let tls_req = GetTlsStatusRequest::default();
        let _ = tls_req;

        let tls_resp = GetTlsStatusResponse {
            enabled: true,
            status: None, // Optional TlsStatus
        };
        assert!(tls_resp.enabled);
    }

    #[test]
    fn test_call_service_messages() {
        // ListCalls
        let list_req = ListCallsRequest {
            limit: 10,
            offset: 0,
            state_filter: CallState::Unspecified as i32,
            from_filter: String::new(),
            to_filter: String::new(),
            direction_filter: String::new(),
        };
        assert_eq!(list_req.limit, 10);

        let list_resp = ListCallsResponse {
            calls: vec![],
            total: 0,
            active: 0,
        };
        assert!(list_resp.calls.is_empty());

        // GetCall
        let get_req = GetCallRequest {
            call_id: "call-123".to_string(),
        };
        assert_eq!(get_req.call_id, "call-123");

        let get_resp = GetCallResponse { call: None };
        assert!(get_resp.call.is_none());

        // GetCallStats
        let stats_req = GetCallStatsRequest {
            time_range_secs: 0,
        };
        assert_eq!(stats_req.time_range_secs, 0);

        let stats_resp = GetCallStatsResponse {
            calls_total: 100,
            calls_active: 5,
            calls_completed: 90,
            calls_failed: 5,
            average_duration_secs: 120.5,
            peak_concurrent: 50,
            calls_per_second: 1.5,
            window_start: None,
            window_end: None,
        };
        assert_eq!(stats_resp.calls_active, 5);

        // TerminateCall
        let term_req = TerminateCallRequest {
            call_id: "call-456".to_string(),
            reason: "admin".to_string(),
            cause_code: 200,
        };
        assert_eq!(term_req.call_id, "call-456");

        let term_resp = TerminateCallResponse {
            success: true,
            message: "Terminated".to_string(),
        };
        assert!(term_resp.success);
    }

    #[test]
    fn test_call_state_enum() {
        assert_eq!(CallState::Unspecified as i32, 0);
        assert_eq!(CallState::Initial as i32, 1);
        assert_eq!(CallState::Early as i32, 2);
        assert_eq!(CallState::Confirmed as i32, 3);
        assert_eq!(CallState::Terminated as i32, 4);
    }

    #[test]
    fn test_call_info_structure() {
        let call = CallInfo {
            call_id: "call-789".to_string(),
            state: CallState::Confirmed as i32,
            from_uri: "sip:alice@example.com".to_string(),
            to_uri: "sip:bob@example.com".to_string(),
            from_tag: "tag123".to_string(),
            to_tag: "tag456".to_string(),
            start_time: Some(prost_types::Timestamp {
                seconds: 1700000000,
                nanos: 0,
            }),
            duration_secs: 60,
            media_mode: "relay".to_string(),
            transport: "UDP".to_string(),
            a_leg: Some(CallLegInfo {
                local_addr: "192.168.1.1:5060".to_string(),
                remote_addr: "192.168.1.100:5060".to_string(),
                rtp_local: "192.168.1.1:10000".to_string(),
                rtp_remote: "192.168.1.100:10000".to_string(),
                codec: "PCMU".to_string(),
                srtp_enabled: true,
                dtls_state: "connected".to_string(),
                ice_state: "completed".to_string(),
                packets_sent: 1000,
                packets_received: 1000,
                bytes_sent: 80000,
                bytes_received: 80000,
            }),
            b_leg: Some(CallLegInfo {
                local_addr: "192.168.1.1:5060".to_string(),
                remote_addr: "192.168.1.101:5060".to_string(),
                rtp_local: "192.168.1.1:10002".to_string(),
                rtp_remote: "192.168.1.101:10000".to_string(),
                codec: "PCMU".to_string(),
                srtp_enabled: true,
                dtls_state: "connected".to_string(),
                ice_state: "completed".to_string(),
                packets_sent: 1000,
                packets_received: 1000,
                bytes_sent: 80000,
                bytes_received: 80000,
            }),
            attestation: "A".to_string(),
            direction: "inbound".to_string(),
        };

        assert_eq!(call.call_id, "call-789");
        assert_eq!(call.state, CallState::Confirmed as i32);
        assert!(call.a_leg.is_some());
        assert!(call.b_leg.is_some());
    }

    #[test]
    fn test_registration_service_messages() {
        // ListRegistrations
        let list_req = ListRegistrationsRequest {
            limit: 20,
            offset: 0,
            aor_filter: String::new(),
            realm_filter: String::new(),
            user_agent_filter: String::new(),
            expiring_within_secs: 0,
        };
        assert_eq!(list_req.limit, 20);

        let list_resp = ListRegistrationsResponse {
            registrations: vec![],
            total: 0,
            active: 0,
        };
        assert!(list_resp.registrations.is_empty());

        // GetRegistration
        let get_req = GetRegistrationRequest {
            aor: "sip:alice@example.com".to_string(),
        };
        assert_eq!(get_req.aor, "sip:alice@example.com");

        let get_resp = GetRegistrationResponse {
            registration: None,
        };
        assert!(get_resp.registration.is_none());

        // GetRegistrationStats
        let stats_req = GetRegistrationStatsRequest {
            realm: String::new(),
        };
        assert!(stats_req.realm.is_empty());

        let stats_resp = GetRegistrationStatsResponse {
            registrations_total: 1000,
            registrations_active: 100,
            unique_aors: 80,
            total_contacts: 150,
            expiring_soon: 5,
            avg_contacts_per_aor: 1.5,
            registrations_per_minute: 10.0,
            reregistrations_per_minute: 5.0,
            auth_failures_per_minute: 0.1,
        };
        assert_eq!(stats_resp.registrations_total, 1000);

        // DeleteRegistration
        let del_req = DeleteRegistrationRequest {
            aor: "sip:bob@example.com".to_string(),
            contact_uri: String::new(),
            reason: "test".to_string(),
        };
        assert_eq!(del_req.aor, "sip:bob@example.com");

        let del_resp = DeleteRegistrationResponse {
            success: true,
            message: "Deleted".to_string(),
            contacts_removed: 2,
        };
        assert!(del_resp.success);
        assert_eq!(del_resp.contacts_removed, 2);
    }

    #[test]
    fn test_registration_info_structure() {
        let reg = RegistrationInfo {
            aor: "sip:charlie@example.com".to_string(),
            contacts: vec![
                ContactInfo {
                    uri: "sip:charlie@192.168.1.50:5060".to_string(),
                    expires: 3600,
                    q_value: 1.0,
                    instance_id: "<urn:uuid:abc123>".to_string(),
                    pub_gruu: String::new(),
                    temp_gruu: String::new(),
                    registered_at: Some(prost_types::Timestamp {
                        seconds: 1700000000,
                        nanos: 0,
                    }),
                    source_addr: "192.168.1.50:5060".to_string(),
                    transport: "UDP".to_string(),
                    secure: false,
                    call_id: "reg-call-1".to_string(),
                    cseq: 1,
                },
            ],
            registered_at: Some(prost_types::Timestamp {
                seconds: 1700000000,
                nanos: 0,
            }),
            min_expires_secs: 3600,
            user_agent: "TestPhone/1.0".to_string(),
            realm: "example.com".to_string(),
            instance_id: "<urn:uuid:abc123>".to_string(),
            display_name: "Charlie".to_string(),
        };

        assert_eq!(reg.aor, "sip:charlie@example.com");
        assert_eq!(reg.contacts.len(), 1);
        assert_eq!(reg.contacts[0].uri, "sip:charlie@192.168.1.50:5060");
        assert_eq!(reg.contacts[0].q_value, 1.0);
    }
}

// ============================================================================
// Cluster Service Proto Tests (feature-gated)
// ============================================================================

#[cfg(feature = "grpc-cluster")]
mod cluster_proto_tests {
    use sbc_grpc_api::sbc::{
        GetClusterStatusRequest, GetClusterStatusResponse,
        ListNodesRequest, ListNodesResponse,
        GetNodeStatusRequest, GetNodeStatusResponse,
        DrainNodeRequest, DrainNodeResponse,
        InitiateFailoverRequest, InitiateFailoverResponse,
        UndoFailoverRequest, UndoFailoverResponse,
        NodeInfo, NodeMetrics, ClusterHealth, HealthCheckDetail,
        NodeRole, NodeState,
    };

    #[test]
    fn test_node_role_enum() {
        assert_eq!(NodeRole::Unspecified as i32, 0);
        assert_eq!(NodeRole::Primary as i32, 1);
        assert_eq!(NodeRole::Secondary as i32, 2);
        assert_eq!(NodeRole::Standby as i32, 3);
        assert_eq!(NodeRole::Witness as i32, 4);
    }

    #[test]
    fn test_node_state_enum() {
        assert_eq!(NodeState::Unspecified as i32, 0);
        assert_eq!(NodeState::Initializing as i32, 1);
        assert_eq!(NodeState::Active as i32, 2);
        assert_eq!(NodeState::Draining as i32, 3);
        assert_eq!(NodeState::Standby as i32, 4);
        assert_eq!(NodeState::Failed as i32, 5);
        assert_eq!(NodeState::Maintenance as i32, 6);
    }

    #[test]
    fn test_cluster_status_messages() {
        // GetClusterStatus
        let req = GetClusterStatusRequest::default();
        let _ = req;

        let resp = GetClusterStatusResponse {
            node_id: "node-01".to_string(),
            role: NodeRole::Primary as i32,
            state: NodeState::Active as i32,
            health: None,
            member_count: 3,
            storage_backend: "memory".to_string(),
            cluster_id: "test-cluster".to_string(),
            leader_id: "node-01".to_string(),
            last_sync: None,
            replication_lag_ms: 0,
        };
        assert_eq!(resp.cluster_id, "test-cluster");
        assert_eq!(resp.member_count, 3);
        assert_eq!(resp.node_id, "node-01");
    }

    #[test]
    fn test_list_nodes_messages() {
        let req = ListNodesRequest {
            role_filter: NodeRole::Unspecified as i32,
            state_filter: NodeState::Unspecified as i32,
            include_offline: false,
        };
        assert_eq!(req.include_offline, false);

        let resp = ListNodesResponse {
            nodes: vec![
                NodeInfo {
                    node_id: "node-01".to_string(),
                    role: NodeRole::Primary as i32,
                    state: NodeState::Active as i32,
                    address: "[::1]:5070".to_string(),
                    sip_address: "[::1]:5060".to_string(),
                    api_address: "[::1]:8080".to_string(),
                    last_seen: None,
                    uptime_secs: 86400,
                    metrics: None,
                    version: "1.0.0".to_string(),
                    region: "us-east-1".to_string(),
                    zone: "us-east-1a".to_string(),
                    labels: std::collections::HashMap::new(),
                },
            ],
            total: 1,
        };
        assert_eq!(resp.nodes.len(), 1);
        assert_eq!(resp.nodes[0].node_id, "node-01");
        assert_eq!(resp.nodes[0].role, NodeRole::Primary as i32);
    }

    #[test]
    fn test_node_status_messages() {
        let req = GetNodeStatusRequest {
            node_id: "node-02".to_string(),
        };
        assert_eq!(req.node_id, "node-02");

        let resp = GetNodeStatusResponse {
            node: Some(NodeInfo {
                node_id: "node-02".to_string(),
                role: NodeRole::Secondary as i32,
                state: NodeState::Active as i32,
                address: "[::1]:5071".to_string(),
                sip_address: "[::1]:5061".to_string(),
                api_address: "[::1]:8081".to_string(),
                last_seen: None,
                uptime_secs: 86400,
                metrics: Some(NodeMetrics {
                    active_calls: 50,
                    active_registrations: 200,
                    cpu_usage: 25.5,
                    memory_usage: 45.0,
                    network_in_bps: 1000000,
                    network_out_bps: 800000,
                    disk_usage: 30.0,
                    load_score: 0.5,
                    calls_per_second: 10.0,
                    messages_per_second: 100.0,
                }),
                version: "1.0.0".to_string(),
                region: "us-west-2".to_string(),
                zone: "us-west-2a".to_string(),
                labels: std::collections::HashMap::new(),
            }),
        };
        assert!(resp.node.is_some());
        let node = resp.node.unwrap();
        assert_eq!(node.node_id, "node-02");
        assert!(node.metrics.is_some());
        let metrics = node.metrics.unwrap();
        assert_eq!(metrics.active_calls, 50);
    }

    #[test]
    fn test_drain_node_messages() {
        let req = DrainNodeRequest {
            node_id: "node-03".to_string(),
            timeout_secs: 60,
            reason: "maintenance".to_string(),
        };
        assert_eq!(req.node_id, "node-03");
        assert_eq!(req.timeout_secs, 60);

        let resp = DrainNodeResponse {
            success: true,
            message: "Node draining".to_string(),
            calls_draining: 5,
            registrations_migrating: 10,
        };
        assert!(resp.success);
        assert_eq!(resp.calls_draining, 5);
    }

    #[test]
    fn test_failover_messages() {
        // InitiateFailover
        let init_req = InitiateFailoverRequest {
            target_node_id: "node-02".to_string(),
            reason: "Manual failover".to_string(),
            force: false,
        };
        assert_eq!(init_req.target_node_id, "node-02");

        let init_resp = InitiateFailoverResponse {
            success: true,
            message: "Failover complete".to_string(),
            new_primary_id: "node-02".to_string(),
            operation_id: "op-123".to_string(),
        };
        assert!(init_resp.success);
        assert_eq!(init_resp.new_primary_id, "node-02");

        // UndoFailover
        let undo_req = UndoFailoverRequest {
            operation_id: "op-123".to_string(),
            reason: "Test rollback".to_string(),
        };
        assert_eq!(undo_req.reason, "Test rollback");

        let undo_resp = UndoFailoverResponse {
            success: true,
            message: "Rollback complete".to_string(),
        };
        assert!(undo_resp.success);
    }

    #[test]
    fn test_cluster_health_structure() {
        let health = ClusterHealth {
            healthy: true,
            storage_healthy: true,
            discovery_healthy: true,
            location_healthy: true,
            sync_healthy: true,
            healthy_nodes: 3,
            quorum_size: 2,
            quorum_met: true,
            checks: vec![
                HealthCheckDetail {
                    name: "quorum".to_string(),
                    passed: true,
                    message: "Quorum achieved".to_string(),
                    timestamp: None,
                    duration_ms: 10,
                },
                HealthCheckDetail {
                    name: "replication".to_string(),
                    passed: true,
                    message: "Replication active".to_string(),
                    timestamp: None,
                    duration_ms: 5,
                },
            ],
        };

        assert!(health.healthy);
        assert_eq!(health.checks.len(), 2);
        assert!(health.checks.iter().all(|c| c.passed));
    }
}

// ============================================================================
// Reflection Service Tests
// ============================================================================

#[cfg(feature = "grpc-reflection")]
mod reflection_tests {
    use sbc_grpc_api::FILE_DESCRIPTOR_SET;

    #[test]
    fn test_file_descriptor_set_exists() {
        assert!(!FILE_DESCRIPTOR_SET.is_empty());
    }

    #[test]
    fn test_file_descriptor_set_is_valid_protobuf() {
        // The file descriptor set should be valid protobuf bytes
        // A minimal check is that it starts with valid protobuf field markers
        assert!(FILE_DESCRIPTOR_SET.len() > 100);

        // First byte should be a valid protobuf field marker (field 1, wire type 2 = length-delimited)
        // 0x0a = (1 << 3) | 2 = field 1, wire type 2
        assert_eq!(FILE_DESCRIPTOR_SET[0], 0x0a);
    }

    #[test]
    fn test_file_descriptor_set_contains_sbc_services() {
        // Convert to string and check for service names
        // This is a basic check - the actual parsing would require prost
        let descriptor_str = String::from_utf8_lossy(FILE_DESCRIPTOR_SET);

        // Check that our service names appear in the descriptor
        assert!(descriptor_str.contains("ConfigService") || descriptor_str.contains("config_service"));
        assert!(descriptor_str.contains("SystemService") || descriptor_str.contains("system_service"));
        assert!(descriptor_str.contains("CallService") || descriptor_str.contains("call_service"));
        assert!(descriptor_str.contains("RegistrationService") || descriptor_str.contains("registration_service"));
    }
}

// ============================================================================
// Prelude Export Tests
// ============================================================================

mod prelude_tests {
    use sbc_grpc_api::prelude::*;

    #[test]
    fn test_config_service_types_exported() {
        let _ = GetConfigRequest::default();
        let _ = GetConfigResponse::default();
        let _ = UpdateConfigRequest::default();
        let _ = UpdateConfigResponse::default();
        let _ = ValidateConfigRequest::default();
        let _ = ValidateConfigResponse::default();
        let _ = ReloadConfigRequest::default();
        let _ = ReloadConfigResponse::default();
    }

    #[test]
    fn test_call_service_types_exported() {
        let _ = ListCallsRequest::default();
        let _ = ListCallsResponse::default();
        let _ = GetCallRequest::default();
        let _ = GetCallResponse::default();
        let _ = TerminateCallRequest::default();
        let _ = TerminateCallResponse::default();
        let _ = GetCallStatsRequest::default();
        let _ = GetCallStatsResponse::default();
    }

    #[test]
    fn test_registration_service_types_exported() {
        let _ = ListRegistrationsRequest::default();
        let _ = ListRegistrationsResponse::default();
        let _ = GetRegistrationRequest::default();
        let _ = GetRegistrationResponse::default();
        let _ = DeleteRegistrationRequest::default();
        let _ = DeleteRegistrationResponse::default();
        let _ = GetRegistrationStatsRequest::default();
        let _ = GetRegistrationStatsResponse::default();
    }

    #[test]
    fn test_system_service_types_exported() {
        let _ = GetVersionRequest::default();
        let _ = GetVersionResponse::default();
        let _ = GetStatsRequest::default();
        let _ = GetStatsResponse::default();
        let _ = GetMetricsRequest::default();
        let _ = GetMetricsResponse::default();
        let _ = GetTlsStatusRequest::default();
        let _ = GetTlsStatusResponse::default();
        let _ = ReloadTlsRequest::default();
        let _ = ReloadTlsResponse::default();
        let _ = ShutdownRequest::default();
        let _ = ShutdownResponse::default();
    }

    #[test]
    fn test_health_service_types_exported() {
        let _ = HealthCheckRequest::default();
        let _ = HealthCheckResponse::default();
        assert_eq!(ServingStatus::Serving as i32, 1);
    }

    #[cfg(feature = "grpc-cluster")]
    #[test]
    fn test_cluster_service_types_exported() {
        let _ = GetClusterStatusRequest::default();
        let _ = GetClusterStatusResponse::default();
        let _ = ListNodesRequest::default();
        let _ = ListNodesResponse::default();
        let _ = GetNodeStatusRequest::default();
        let _ = GetNodeStatusResponse::default();
        let _ = DrainNodeRequest::default();
        let _ = DrainNodeResponse::default();
        let _ = InitiateFailoverRequest::default();
        let _ = InitiateFailoverResponse::default();
        let _ = UndoFailoverRequest::default();
        let _ = UndoFailoverResponse::default();
    }
}

// ============================================================================
// Service Trait Tests
// ============================================================================

mod service_trait_tests {
    // These tests verify that the generated service traits have the expected methods
    // by implementing mock services

    use sbc_grpc_api::health::health_server::Health;
    use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus};
    use tonic::{Request, Response, Status};

    #[derive(Debug, Default)]
    struct MockHealthService;

    #[tonic::async_trait]
    impl Health for MockHealthService {
        async fn check(
            &self,
            request: Request<HealthCheckRequest>,
        ) -> Result<Response<HealthCheckResponse>, Status> {
            let service = request.into_inner().service;
            Ok(Response::new(HealthCheckResponse {
                status: if service.is_empty() || service == "sbc" {
                    ServingStatus::Serving as i32
                } else {
                    ServingStatus::ServiceUnknown as i32
                },
            }))
        }

        type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<HealthCheckResponse, Status>>;

        async fn watch(
            &self,
            _request: Request<HealthCheckRequest>,
        ) -> Result<Response<Self::WatchStream>, Status> {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let _ = tx.send(Ok(HealthCheckResponse {
                status: ServingStatus::Serving as i32,
            })).await;
            Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
        }
    }

    #[tokio::test]
    async fn test_health_service_impl() {
        let service = MockHealthService;

        // Test check for empty service (overall health)
        let req = Request::new(HealthCheckRequest { service: String::new() });
        let resp = service.check(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ServingStatus::Serving as i32);

        // Test check for specific service
        let req = Request::new(HealthCheckRequest { service: "sbc".to_string() });
        let resp = service.check(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ServingStatus::Serving as i32);

        // Test check for unknown service
        let req = Request::new(HealthCheckRequest { service: "unknown".to_string() });
        let resp = service.check(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ServingStatus::ServiceUnknown as i32);
    }
}

// ============================================================================
// Message Serialization Tests
// ============================================================================

mod serialization_tests {
    use prost::Message;
    use sbc_grpc_api::sbc::{GetVersionResponse, CallState, CallInfo};
    use sbc_grpc_api::health::{HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus};

    #[test]
    fn test_health_check_request_encode_decode() {
        let original = HealthCheckRequest {
            service: "sbc.api.v1.ConfigService".to_string(),
        };

        let encoded = original.encode_to_vec();
        let decoded = HealthCheckRequest::decode(encoded.as_slice()).unwrap();

        assert_eq!(original.service, decoded.service);
    }

    #[test]
    fn test_health_check_response_encode_decode() {
        let original = HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        };

        let encoded = original.encode_to_vec();
        let decoded = HealthCheckResponse::decode(encoded.as_slice()).unwrap();

        assert_eq!(original.status, decoded.status);
    }

    #[test]
    fn test_version_response_encode_decode() {
        let original = GetVersionResponse {
            version: "1.2.3".to_string(),
            name: "sbc-daemon".to_string(),
            build_time: "2024-01-15T10:30:00Z".to_string(),
            rust_version: "1.75.0".to_string(),
            git_commit: "abc123def456".to_string(),
            git_branch: "main".to_string(),
            release_build: true,
            target: "x86_64-unknown-linux-gnu".to_string(),
            features: vec!["grpc".to_string(), "cluster".to_string()],
        };

        let encoded = original.encode_to_vec();
        let decoded = GetVersionResponse::decode(encoded.as_slice()).unwrap();

        assert_eq!(original.version, decoded.version);
        assert_eq!(original.build_time, decoded.build_time);
        assert_eq!(original.git_commit, decoded.git_commit);
        assert_eq!(original.features, decoded.features);
    }

    #[test]
    fn test_call_info_encode_decode() {
        let original = CallInfo {
            call_id: "call-test-123".to_string(),
            state: CallState::Confirmed as i32,
            from_uri: "sip:alice@example.com".to_string(),
            to_uri: "sip:bob@example.com".to_string(),
            from_tag: "tag123".to_string(),
            to_tag: "tag456".to_string(),
            start_time: Some(prost_types::Timestamp {
                seconds: 1705318200,
                nanos: 0,
            }),
            duration_secs: 300,
            media_mode: "relay".to_string(),
            transport: "TLS".to_string(),
            a_leg: None,
            b_leg: None,
            attestation: "A".to_string(),
            direction: "inbound".to_string(),
        };

        let encoded = original.encode_to_vec();
        let decoded = CallInfo::decode(encoded.as_slice()).unwrap();

        assert_eq!(original.call_id, decoded.call_id);
        assert_eq!(original.state, decoded.state);
        assert_eq!(original.from_uri, decoded.from_uri);
        assert_eq!(original.duration_secs, 300);
    }

    #[test]
    fn test_empty_message_encode() {
        use sbc_grpc_api::sbc::GetVersionRequest;

        let msg = GetVersionRequest::default();
        let encoded = msg.encode_to_vec();

        // Empty message should encode to empty bytes
        assert!(encoded.is_empty());
    }
}
