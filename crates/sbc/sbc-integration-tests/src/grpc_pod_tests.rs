//! Smoke tests for the two optional gRPC pods introduced by the container
//! split: `sbc-announcement-server` (AnnouncementService) and
//! `sbc-trunk-agent` (TrunkStatusPublishService).
//!
//! Each module has two layers:
//!
//! 1. **Proto message tests** — field defaults, enum values, encode/decode
//!    round trips. These run entirely in-memory.
//! 2. **Service smoke tests** — in-process gRPC server + tonic client over a
//!    loopback TCP connection. No external services, Postgres, or carrier
//!    network required.
//!
//! Run with:
//! ```bash
//! cargo test -p sbc-integration-tests --features grpc
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CA-8**: Penetration Testing
//! - **SA-11**: Developer Testing and Evaluation

#![cfg(feature = "grpc")]

// ============================================================================
// AnnouncementService
// ============================================================================

mod announcement_proto_tests {
    use prost::Message;
    use sbc_grpc_api::sbc::{
        AnnouncementBound, AnnouncementCompleted, AnnouncementKind, PlayAnnouncementEvent,
        PlayAnnouncementRequest, play_announcement_event,
    };

    #[test]
    fn test_announcement_kind_enum_values() {
        assert_eq!(AnnouncementKind::Unspecified as i32, 0);
        assert_eq!(AnnouncementKind::NumberNotInService as i32, 1);
        assert_eq!(AnnouncementKind::AllCircuitsBusy as i32, 2);
        assert_eq!(AnnouncementKind::Silence as i32, 3);
    }

    #[test]
    fn test_play_announcement_request_fields() {
        let req = PlayAnnouncementRequest {
            kind: AnnouncementKind::NumberNotInService as i32,
            rtp_destination: "203.0.113.5:16384".to_string(),
            ssrc: 0xDEAD_BEEF,
            initial_delay_ms: 200,
            call_id: "test-call-1@sbc".to_string(),
        };
        assert_eq!(req.kind, AnnouncementKind::NumberNotInService as i32);
        assert_eq!(req.rtp_destination, "203.0.113.5:16384");
        assert_eq!(req.ssrc, 0xDEAD_BEEF);
        assert_eq!(req.initial_delay_ms, 200);
        assert_eq!(req.call_id, "test-call-1@sbc");
    }

    #[test]
    fn test_announcement_bound_fields() {
        let bound = AnnouncementBound {
            advertised_ip: "198.51.100.1".to_string(),
            rtp_port: 20000,
        };
        assert_eq!(bound.advertised_ip, "198.51.100.1");
        assert_eq!(bound.rtp_port, 20000);
    }

    #[test]
    fn test_announcement_completed_fields() {
        let completed = AnnouncementCompleted { packets_sent: 750 };
        assert_eq!(completed.packets_sent, 750);
    }

    #[test]
    fn test_play_event_bound_variant() {
        let event = PlayAnnouncementEvent {
            event: Some(play_announcement_event::Event::Bound(AnnouncementBound {
                advertised_ip: "198.51.100.1".to_string(),
                rtp_port: 20000,
            })),
        };
        match event.event.unwrap() {
            play_announcement_event::Event::Bound(b) => {
                assert_eq!(b.advertised_ip, "198.51.100.1");
                assert_eq!(b.rtp_port, 20000);
            }
            play_announcement_event::Event::Completed(_) => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_play_event_completed_variant() {
        let event = PlayAnnouncementEvent {
            event: Some(play_announcement_event::Event::Completed(
                AnnouncementCompleted { packets_sent: 42 },
            )),
        };
        match event.event.unwrap() {
            play_announcement_event::Event::Completed(c) => assert_eq!(c.packets_sent, 42),
            play_announcement_event::Event::Bound(_) => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_play_request_encode_decode() {
        let original = PlayAnnouncementRequest {
            kind: AnnouncementKind::AllCircuitsBusy as i32,
            rtp_destination: "192.0.2.1:20000".to_string(),
            ssrc: 12345,
            initial_delay_ms: 0,
            call_id: "abc@example.com".to_string(),
        };
        let encoded = original.encode_to_vec();
        let decoded = PlayAnnouncementRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.kind, original.kind);
        assert_eq!(decoded.rtp_destination, original.rtp_destination);
        assert_eq!(decoded.ssrc, original.ssrc);
        assert_eq!(decoded.call_id, original.call_id);
    }

    #[test]
    fn test_play_event_bound_encode_decode() {
        let original = PlayAnnouncementEvent {
            event: Some(play_announcement_event::Event::Bound(AnnouncementBound {
                advertised_ip: "10.0.0.1".to_string(),
                rtp_port: 16384,
            })),
        };
        let encoded = original.encode_to_vec();
        let decoded = PlayAnnouncementEvent::decode(encoded.as_slice()).unwrap();
        match decoded.event.unwrap() {
            play_announcement_event::Event::Bound(b) => {
                assert_eq!(b.advertised_ip, "10.0.0.1");
                assert_eq!(b.rtp_port, 16384);
            }
            _ => panic!("wrong variant after round-trip"),
        }
    }

    #[test]
    fn test_play_event_completed_encode_decode() {
        let original = PlayAnnouncementEvent {
            event: Some(play_announcement_event::Event::Completed(
                AnnouncementCompleted { packets_sent: 999 },
            )),
        };
        let encoded = original.encode_to_vec();
        let decoded = PlayAnnouncementEvent::decode(encoded.as_slice()).unwrap();
        match decoded.event.unwrap() {
            play_announcement_event::Event::Completed(c) => assert_eq!(c.packets_sent, 999),
            _ => panic!("wrong variant after round-trip"),
        }
    }
}

mod announcement_service_smoke {
    use sbc_grpc_api::sbc::{
        AnnouncementBound, AnnouncementCompleted, AnnouncementKind, PlayAnnouncementEvent,
        PlayAnnouncementRequest, announcement_service_client::AnnouncementServiceClient,
        announcement_service_server::{AnnouncementService, AnnouncementServiceServer},
        play_announcement_event,
    };
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::{Request, Response, Status};

    #[derive(Debug, Default)]
    struct MockAnnouncementService;

    #[tonic::async_trait]
    impl AnnouncementService for MockAnnouncementService {
        type PlayStream = ReceiverStream<Result<PlayAnnouncementEvent, Status>>;

        async fn play(
            &self,
            request: Request<PlayAnnouncementRequest>,
        ) -> Result<Response<Self::PlayStream>, Status> {
            let req = request.into_inner();
            if req.kind == AnnouncementKind::Unspecified as i32 {
                return Err(Status::invalid_argument("kind must not be Unspecified"));
            }
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            tokio::spawn(async move {
                let _ = tx
                    .send(Ok(PlayAnnouncementEvent {
                        event: Some(play_announcement_event::Event::Bound(AnnouncementBound {
                            advertised_ip: "127.0.0.1".to_string(),
                            rtp_port: 16384,
                        })),
                    }))
                    .await;
                let _ = tx
                    .send(Ok(PlayAnnouncementEvent {
                        event: Some(play_announcement_event::Event::Completed(
                            AnnouncementCompleted { packets_sent: 42 },
                        )),
                    }))
                    .await;
                // Dropping tx closes the stream.
            });
            Ok(Response::new(ReceiverStream::new(rx)))
        }
    }

    async fn spawn_server() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(AnnouncementServiceServer::new(MockAnnouncementService))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        addr
    }

    #[tokio::test]
    async fn test_play_streams_bound_then_completed() {
        let addr = spawn_server().await;
        let mut client = AnnouncementServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let mut stream = client
            .play(PlayAnnouncementRequest {
                kind: AnnouncementKind::NumberNotInService as i32,
                rtp_destination: "127.0.0.1:30000".to_string(),
                ssrc: 1,
                initial_delay_ms: 0,
                call_id: "smoke@sbc".to_string(),
            })
            .await
            .unwrap()
            .into_inner();

        // First event: Bound.
        let ev1 = stream.message().await.unwrap().expect("expected Bound event");
        match ev1.event.unwrap() {
            play_announcement_event::Event::Bound(b) => {
                assert_eq!(b.advertised_ip, "127.0.0.1");
                assert_eq!(b.rtp_port, 16384);
            }
            play_announcement_event::Event::Completed(_) => panic!("expected Bound first"),
        }

        // Second event: Completed.
        let ev2 = stream
            .message()
            .await
            .unwrap()
            .expect("expected Completed event");
        match ev2.event.unwrap() {
            play_announcement_event::Event::Completed(c) => assert_eq!(c.packets_sent, 42),
            play_announcement_event::Event::Bound(_) => panic!("expected Completed"),
        }

        // Stream closes after Completed.
        assert!(stream.message().await.unwrap().is_none(), "stream should be closed");
    }

    #[tokio::test]
    async fn test_play_silence_kind_accepted() {
        let addr = spawn_server().await;
        let mut client = AnnouncementServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let mut stream = client
            .play(PlayAnnouncementRequest {
                kind: AnnouncementKind::Silence as i32,
                rtp_destination: "127.0.0.1:30002".to_string(),
                ssrc: 2,
                initial_delay_ms: 0,
                call_id: "silence@sbc".to_string(),
            })
            .await
            .unwrap()
            .into_inner();

        // The mock accepts all non-Unspecified kinds; Silence is valid.
        let ev = stream.message().await.unwrap().expect("expected Bound event");
        assert!(matches!(
            ev.event.unwrap(),
            play_announcement_event::Event::Bound(_)
        ));
    }

    #[tokio::test]
    async fn test_play_rejects_unspecified_kind() {
        let addr = spawn_server().await;
        let mut client = AnnouncementServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let result = client
            .play(PlayAnnouncementRequest {
                kind: AnnouncementKind::Unspecified as i32,
                rtp_destination: "127.0.0.1:30004".to_string(),
                ssrc: 0,
                initial_delay_ms: 0,
                call_id: "bad@sbc".to_string(),
            })
            .await;

        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }
}

// ============================================================================
// TrunkStatusPublishService
// ============================================================================

mod trunk_status_proto_tests {
    use prost::Message;
    use sbc_grpc_api::sbc::{
        PublishTrunkStatusRequest, PublishTrunkStatusResponse, TrunkHealthInfo,
        TrunkRegistrationInfo,
    };

    #[test]
    fn test_publish_request_defaults() {
        let req = PublishTrunkStatusRequest::default();
        assert!(req.agent_id.is_empty());
        assert!(req.health.is_empty());
        assert!(req.registrations.is_empty());
    }

    #[test]
    fn test_publish_request_with_data() {
        let req = PublishTrunkStatusRequest {
            agent_id: "trunk-agent-0".to_string(),
            health: vec![TrunkHealthInfo {
                trunk_id: "bulkvs-1".to_string(),
                reachable: true,
                last_response_ms: 12,
                consecutive_success: 5,
                uptime_pct: 99.9,
                ..Default::default()
            }],
            registrations: vec![TrunkRegistrationInfo {
                trunk_id: "bulkvs-1".to_string(),
                registered: true,
                state: "registered".to_string(),
                registrar: "sip.bulkvs.com".to_string(),
                username: "15551234567".to_string(),
                expires_secs: 3600,
                attempts: 3,
                successes: 3,
                ..Default::default()
            }],
        };
        assert_eq!(req.agent_id, "trunk-agent-0");
        assert_eq!(req.health.len(), 1);
        assert!(req.health[0].reachable);
        assert_eq!(req.registrations[0].expires_secs, 3600);
    }

    #[test]
    fn test_publish_response_accepted() {
        let resp = PublishTrunkStatusResponse {
            accepted: true,
            message: String::new(),
        };
        assert!(resp.accepted);
        assert!(resp.message.is_empty());
    }

    #[test]
    fn test_publish_response_rejected() {
        let resp = PublishTrunkStatusResponse {
            accepted: false,
            message: "daemon runs local trunk services".to_string(),
        };
        assert!(!resp.accepted);
        assert!(!resp.message.is_empty());
    }

    #[test]
    fn test_trunk_health_info_fields() {
        let info = TrunkHealthInfo {
            trunk_id: "carrier-1".to_string(),
            reachable: true,
            last_response_ms: 15,
            consecutive_success: 10,
            total_pings: 1000,
            total_success: 998,
            uptime_pct: 99.8,
            ..Default::default()
        };
        assert_eq!(info.trunk_id, "carrier-1");
        assert!(info.reachable);
        assert_eq!(info.total_pings, 1000);
        assert_eq!(info.total_success, 998);
    }

    #[test]
    fn test_trunk_registration_info_fields() {
        let info = TrunkRegistrationInfo {
            trunk_id: "carrier-1".to_string(),
            registered: true,
            state: "registered".to_string(),
            registrar: "sip.carrier.net".to_string(),
            username: "did-pool".to_string(),
            expires_secs: 1800,
            attempts: 5,
            successes: 5,
            ..Default::default()
        };
        assert_eq!(info.trunk_id, "carrier-1");
        assert!(info.registered);
        assert_eq!(info.expires_secs, 1800);
        assert_eq!(info.attempts, info.successes);
    }

    #[test]
    fn test_publish_request_encode_decode() {
        let original = PublishTrunkStatusRequest {
            agent_id: "pod-abc123".to_string(),
            health: vec![TrunkHealthInfo {
                trunk_id: "carrier-1".to_string(),
                reachable: true,
                total_pings: 100,
                total_success: 98,
                uptime_pct: 98.0,
                ..Default::default()
            }],
            registrations: vec![],
        };
        let encoded = original.encode_to_vec();
        let decoded = PublishTrunkStatusRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.agent_id, original.agent_id);
        assert_eq!(decoded.health.len(), 1);
        assert_eq!(decoded.health[0].trunk_id, "carrier-1");
        assert_eq!(decoded.health[0].total_pings, 100);
    }

    #[test]
    fn test_publish_response_encode_decode() {
        let original = PublishTrunkStatusResponse {
            accepted: true,
            message: String::new(),
        };
        let encoded = original.encode_to_vec();
        let decoded = PublishTrunkStatusResponse::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.accepted, original.accepted);
    }
}

mod trunk_status_service_smoke {
    use sbc_grpc_api::sbc::{
        PublishTrunkStatusRequest, PublishTrunkStatusResponse, TrunkHealthInfo,
        TrunkRegistrationInfo,
        trunk_status_publish_service_client::TrunkStatusPublishServiceClient,
        trunk_status_publish_service_server::{
            TrunkStatusPublishService, TrunkStatusPublishServiceServer,
        },
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    struct MockPublishService {
        /// When true the service simulates the daemon running its own loops
        /// and rejects external publishes — mirrors `TrunkStatusPublishServiceImpl`
        /// behaviour when `state.trunk_monitor.is_some()`.
        reject: bool,
    }

    #[tonic::async_trait]
    impl TrunkStatusPublishService for MockPublishService {
        async fn publish_trunk_status(
            &self,
            _request: Request<PublishTrunkStatusRequest>,
        ) -> Result<Response<PublishTrunkStatusResponse>, Status> {
            if self.reject {
                return Ok(Response::new(PublishTrunkStatusResponse {
                    accepted: false,
                    message: "daemon runs local trunk services".to_string(),
                }));
            }
            Ok(Response::new(PublishTrunkStatusResponse {
                accepted: true,
                message: String::new(),
            }))
        }
    }

    async fn spawn_server(reject: bool) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(TrunkStatusPublishServiceServer::new(MockPublishService {
                    reject,
                }))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        addr
    }

    #[tokio::test]
    async fn test_publish_with_trunk_data_accepted() {
        let addr = spawn_server(false).await;
        let mut client = TrunkStatusPublishServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .publish_trunk_status(PublishTrunkStatusRequest {
                agent_id: "trunk-agent-0".to_string(),
                health: vec![TrunkHealthInfo {
                    trunk_id: "bulkvs-1".to_string(),
                    reachable: true,
                    last_response_ms: 8,
                    ..Default::default()
                }],
                registrations: vec![TrunkRegistrationInfo {
                    trunk_id: "bulkvs-1".to_string(),
                    registered: true,
                    state: "registered".to_string(),
                    ..Default::default()
                }],
            })
            .await
            .unwrap()
            .into_inner();

        assert!(resp.accepted);
        assert!(resp.message.is_empty());
    }

    #[tokio::test]
    async fn test_publish_empty_snapshot_accepted() {
        let addr = spawn_server(false).await;
        let mut client = TrunkStatusPublishServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .publish_trunk_status(PublishTrunkStatusRequest {
                agent_id: "trunk-agent-0".to_string(),
                health: vec![],
                registrations: vec![],
            })
            .await
            .unwrap()
            .into_inner();

        // Empty snapshot is valid — all trunks may be down or none configured yet.
        assert!(resp.accepted);
    }

    #[tokio::test]
    async fn test_publish_rejected_when_daemon_runs_local_loops() {
        let addr = spawn_server(true).await;
        let mut client = TrunkStatusPublishServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .publish_trunk_status(PublishTrunkStatusRequest {
                agent_id: "rogue-agent".to_string(),
                health: vec![],
                registrations: vec![],
            })
            .await
            .unwrap()
            .into_inner();

        assert!(!resp.accepted);
        assert!(!resp.message.is_empty());
    }

    #[tokio::test]
    async fn test_publish_multiple_trunks() {
        let addr = spawn_server(false).await;
        let mut client = TrunkStatusPublishServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .publish_trunk_status(PublishTrunkStatusRequest {
                agent_id: "trunk-agent-0".to_string(),
                health: vec![
                    TrunkHealthInfo {
                        trunk_id: "bulkvs-1".to_string(),
                        reachable: true,
                        ..Default::default()
                    },
                    TrunkHealthInfo {
                        trunk_id: "bulkvs-2".to_string(),
                        reachable: false,
                        consecutive_failures: 3,
                        ..Default::default()
                    },
                ],
                registrations: vec![
                    TrunkRegistrationInfo {
                        trunk_id: "bulkvs-1".to_string(),
                        registered: true,
                        ..Default::default()
                    },
                    TrunkRegistrationInfo {
                        trunk_id: "bulkvs-2".to_string(),
                        registered: false,
                        last_error: "401 Unauthorized".to_string(),
                        ..Default::default()
                    },
                ],
            })
            .await
            .unwrap()
            .into_inner();

        assert!(resp.accepted);
    }
}

// ============================================================================
// TrunkHealthService — snapshot staleness fields
// ============================================================================

mod trunk_health_response_proto_tests {
    use prost::Message;
    use sbc_grpc_api::sbc::{
        ListTrunkHealthResponse, ListTrunkRegistrationsResponse, TrunkHealthInfo,
        TrunkRegistrationInfo,
    };

    #[test]
    fn test_list_trunk_health_response_defaults() {
        let resp = ListTrunkHealthResponse::default();
        assert!(resp.trunks.is_empty());
        assert!(!resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 0);
    }

    #[test]
    fn test_list_trunk_health_response_external_with_age() {
        let resp = ListTrunkHealthResponse {
            trunks: vec![TrunkHealthInfo {
                trunk_id: "bulkvs-1".to_string(),
                reachable: true,
                uptime_pct: 99.5,
                ..Default::default()
            }],
            trunk_services_external: true,
            snapshot_age_secs: 45,
        };
        assert!(resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 45);
        assert_eq!(resp.trunks[0].trunk_id, "bulkvs-1");
    }

    #[test]
    fn test_list_trunk_health_response_no_snapshot_yet() {
        let resp = ListTrunkHealthResponse {
            trunks: vec![],
            trunk_services_external: true,
            snapshot_age_secs: 0,
        };
        // age=0 + external=true means no snapshot received yet.
        assert!(resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 0);
    }

    #[test]
    fn test_list_trunk_health_response_in_process() {
        // In-process mode: external=false, age is meaningless (always 0).
        let resp = ListTrunkHealthResponse {
            trunks: vec![],
            trunk_services_external: false,
            snapshot_age_secs: 0,
        };
        assert!(!resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 0);
    }

    #[test]
    fn test_list_trunk_health_response_encode_decode() {
        let original = ListTrunkHealthResponse {
            trunks: vec![TrunkHealthInfo {
                trunk_id: "carrier-1".to_string(),
                reachable: false,
                consecutive_failures: 7,
                uptime_pct: 88.0,
                ..Default::default()
            }],
            trunk_services_external: true,
            snapshot_age_secs: 200,
        };
        let encoded = original.encode_to_vec();
        let decoded = ListTrunkHealthResponse::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.trunk_services_external, original.trunk_services_external);
        assert_eq!(decoded.snapshot_age_secs, original.snapshot_age_secs);
        assert_eq!(decoded.trunks[0].trunk_id, "carrier-1");
        assert_eq!(decoded.trunks[0].consecutive_failures, 7);
    }

    #[test]
    fn test_list_trunk_registrations_response_defaults() {
        let resp = ListTrunkRegistrationsResponse::default();
        assert!(resp.trunks.is_empty());
        assert!(!resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 0);
    }

    #[test]
    fn test_list_trunk_registrations_response_external_with_age() {
        let resp = ListTrunkRegistrationsResponse {
            trunks: vec![TrunkRegistrationInfo {
                trunk_id: "bulkvs-1".to_string(),
                registered: true,
                state: "registered".to_string(),
                expires_secs: 3600,
                ..Default::default()
            }],
            trunk_services_external: true,
            snapshot_age_secs: 25,
        };
        assert!(resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 25);
        assert!(resp.trunks[0].registered);
    }

    #[test]
    fn test_list_trunk_registrations_response_encode_decode() {
        let original = ListTrunkRegistrationsResponse {
            trunks: vec![TrunkRegistrationInfo {
                trunk_id: "carrier-2".to_string(),
                registered: false,
                last_error: "503 Service Unavailable".to_string(),
                attempts: 12,
                ..Default::default()
            }],
            trunk_services_external: true,
            snapshot_age_secs: 130,
        };
        let encoded = original.encode_to_vec();
        let decoded = ListTrunkRegistrationsResponse::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.trunk_services_external, original.trunk_services_external);
        assert_eq!(decoded.snapshot_age_secs, original.snapshot_age_secs);
        assert_eq!(decoded.trunks[0].last_error, "503 Service Unavailable");
        assert_eq!(decoded.trunks[0].attempts, 12);
    }
}

mod trunk_health_service_smoke {
    use sbc_grpc_api::sbc::{
        ListTrunkHealthRequest, ListTrunkHealthResponse, ListTrunkRegistrationsRequest,
        ListTrunkRegistrationsResponse, RegisterTrunkRequest, RegisterTrunkResponse,
        TrunkHealthInfo, TrunkRegistrationInfo,
        trunk_health_service_client::TrunkHealthServiceClient,
        trunk_health_service_server::{TrunkHealthService, TrunkHealthServiceServer},
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    /// Mock that can simulate both in-process and external-agent scenarios.
    struct MockTrunkHealthService {
        external: bool,
        snapshot_age_secs: u32,
    }

    #[tonic::async_trait]
    impl TrunkHealthService for MockTrunkHealthService {
        async fn list_trunk_health(
            &self,
            _request: Request<ListTrunkHealthRequest>,
        ) -> Result<Response<ListTrunkHealthResponse>, Status> {
            Ok(Response::new(ListTrunkHealthResponse {
                trunks: vec![TrunkHealthInfo {
                    trunk_id: "bulkvs-1".to_string(),
                    reachable: true,
                    uptime_pct: 99.9,
                    total_pings: 500,
                    total_success: 499,
                    ..Default::default()
                }],
                trunk_services_external: self.external,
                snapshot_age_secs: self.snapshot_age_secs,
            }))
        }

        async fn list_trunk_registrations(
            &self,
            _request: Request<ListTrunkRegistrationsRequest>,
        ) -> Result<Response<ListTrunkRegistrationsResponse>, Status> {
            Ok(Response::new(ListTrunkRegistrationsResponse {
                trunks: vec![TrunkRegistrationInfo {
                    trunk_id: "bulkvs-1".to_string(),
                    registered: true,
                    state: "registered".to_string(),
                    expires_secs: 3600,
                    attempts: 3,
                    successes: 3,
                    ..Default::default()
                }],
                trunk_services_external: self.external,
                snapshot_age_secs: self.snapshot_age_secs,
            }))
        }

        async fn register_trunk(
            &self,
            _request: Request<RegisterTrunkRequest>,
        ) -> Result<Response<RegisterTrunkResponse>, Status> {
            Ok(Response::new(RegisterTrunkResponse {
                success: true,
                message: "ok".to_string(),
            }))
        }
    }

    async fn spawn_server(external: bool, snapshot_age_secs: u32) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(TrunkHealthServiceServer::new(MockTrunkHealthService {
                    external,
                    snapshot_age_secs,
                }))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        addr
    }

    #[tokio::test]
    async fn test_list_health_in_process_mode() {
        let addr = spawn_server(false, 0).await;
        let mut client = TrunkHealthServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .list_trunk_health(ListTrunkHealthRequest {})
            .await
            .unwrap()
            .into_inner();

        // In-process: no external flag, age is always 0.
        assert!(!resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 0);
        assert_eq!(resp.trunks.len(), 1);
        assert!(resp.trunks[0].reachable);
    }

    #[tokio::test]
    async fn test_list_health_external_fresh_snapshot() {
        let addr = spawn_server(true, 20).await;
        let mut client = TrunkHealthServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .list_trunk_health(ListTrunkHealthRequest {})
            .await
            .unwrap()
            .into_inner();

        assert!(resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 20);
    }

    #[tokio::test]
    async fn test_list_health_external_stale_snapshot() {
        let addr = spawn_server(true, 300).await;
        let mut client = TrunkHealthServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .list_trunk_health(ListTrunkHealthRequest {})
            .await
            .unwrap()
            .into_inner();

        assert!(resp.trunk_services_external);
        // 300 s > 120 s threshold — caller should flag as STALE.
        assert!(resp.snapshot_age_secs > 120);
    }

    #[tokio::test]
    async fn test_list_health_external_no_snapshot_yet() {
        // age=0 + external=true → agent not yet connected.
        let addr = spawn_server(true, 0).await;
        let mut client = TrunkHealthServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .list_trunk_health(ListTrunkHealthRequest {})
            .await
            .unwrap()
            .into_inner();

        assert!(resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 0);
    }

    #[tokio::test]
    async fn test_list_registrations_external_mode() {
        let addr = spawn_server(true, 45).await;
        let mut client = TrunkHealthServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .list_trunk_registrations(ListTrunkRegistrationsRequest {})
            .await
            .unwrap()
            .into_inner();

        assert!(resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 45);
        assert_eq!(resp.trunks.len(), 1);
        assert!(resp.trunks[0].registered);
    }

    #[tokio::test]
    async fn test_list_registrations_in_process_mode() {
        let addr = spawn_server(false, 0).await;
        let mut client = TrunkHealthServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let resp = client
            .list_trunk_registrations(ListTrunkRegistrationsRequest {})
            .await
            .unwrap()
            .into_inner();

        assert!(!resp.trunk_services_external);
        assert_eq!(resp.snapshot_age_secs, 0);
        assert_eq!(resp.trunks[0].expires_secs, 3600);
    }
}
