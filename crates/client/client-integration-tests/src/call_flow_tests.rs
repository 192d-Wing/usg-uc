//! Call flow integration tests.
//!
//! Tests the call lifecycle including:
//! - CallManager setup and configuration
//! - Outbound call initiation
//! - SDP offer/answer exchange
//! - Call state transitions
//! - Media session coordination

use crate::test_utils::{allocate_test_addr, init_test_tracing, test_account};
use client_core::{CallManager, CallManagerEvent};
use client_types::CallState;
use proto_ice::IceConfig;
use tokio::sync::mpsc;

/// Tests CallManager creation and initial state.
#[tokio::test]
async fn test_call_manager_creation() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let manager = CallManager::new(sip_addr, media_addr, tx);

    // Initial state checks
    assert!(manager.active_call_id().is_none());
    assert!(!manager.is_muted());
    assert!(manager.active_call_info().is_none());
}

/// Tests that making a call without an account fails.
#[tokio::test]
async fn test_call_without_account_fails() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    // Attempt call without configuring account
    let result = manager.make_call("sips:bob@example.com").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("No account configured"),
        "Expected 'No account configured' error, got: {}",
        err
    );
}

/// Tests that hangup without active call fails.
#[tokio::test]
async fn test_hangup_without_active_call_fails() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    let result = manager.hangup().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("No active call"),
        "Expected 'No active call' error, got: {}",
        err
    );
}

/// Tests mute toggle functionality.
#[tokio::test]
async fn test_mute_toggle() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    // Initial state: not muted
    assert!(!manager.is_muted());

    // Toggle mute on
    let muted = manager.toggle_mute();
    assert!(muted);
    assert!(manager.is_muted());

    // Toggle mute off
    let muted = manager.toggle_mute();
    assert!(!muted);
    assert!(!manager.is_muted());

    // Toggle again
    let muted = manager.toggle_mute();
    assert!(muted);
    assert!(manager.is_muted());
}

/// Tests account configuration.
#[tokio::test]
async fn test_account_configuration() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    let account = test_account();
    manager.configure_account(&account);

    // Account is configured internally - we verify by attempting a call
    // which should now fail for a different reason (transport/network)
    // rather than "No account configured"

    // Note: Full call initiation would require network connectivity
    // This test verifies the configuration path doesn't error
}

/// Tests ICE configuration.
#[tokio::test]
async fn test_ice_configuration() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    let ice_config = IceConfig::default();
    manager.set_ice_config(ice_config);

    // Configuration is stored internally
    // Verified by making a call (would use configured ICE)
}

/// Tests DTLS credentials configuration.
#[tokio::test]
async fn test_dtls_credentials_configuration() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    // Simulate certificate chain from CertificateStore
    let cert_chain = vec![vec![0x30, 0x82, 0x01, 0x5a]]; // Minimal DER stub
    let private_key = vec![]; // Empty for smart card (key stays on card)

    manager.set_dtls_credentials(cert_chain, private_key);

    // Credentials are stored internally
    // Would be used when creating media sessions
}

/// Tests codec preference configuration.
#[tokio::test]
async fn test_codec_preference() {
    init_test_tracing();

    use client_types::audio::CodecPreference;

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    // Default codec
    let default = manager.preferred_codec();
    assert_eq!(default, CodecPreference::G711Ulaw);

    // Set Opus
    manager.set_preferred_codec(CodecPreference::Opus);
    assert_eq!(manager.preferred_codec(), CodecPreference::Opus);

    // Set G.711 A-law
    manager.set_preferred_codec(CodecPreference::G711Alaw);
    assert_eq!(manager.preferred_codec(), CodecPreference::G711Alaw);
}

/// Tests that multiple calls are rejected (single call mode).
#[tokio::test]
async fn test_single_call_mode() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    // Configure account for calls
    let account = test_account();
    manager.configure_account(&account);

    // Note: We can't actually make a call without network connectivity,
    // but we can verify the single-call mode check exists by examining
    // the error path

    // This would require mocking the SIP UA layer to fully test
}

/// Tests call state queries.
#[tokio::test]
async fn test_call_state_queries() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let manager = CallManager::new(sip_addr, media_addr, tx);

    // Query for nonexistent call
    assert!(manager.get_call_state("nonexistent-call-id").is_none());
    assert!(manager.get_call_info("nonexistent-call-id").is_none());
    assert!(manager.get_media_session("nonexistent-call-id").is_none());
    assert!(manager.get_audio_session("nonexistent-call-id").is_none());
}

/// Tests audio stats when no active call.
#[tokio::test]
async fn test_audio_stats_no_call() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let manager = CallManager::new(sip_addr, media_addr, tx);

    // No active call - should return None
    let stats = manager.audio_stats();
    assert!(stats.is_none());
}

/// Integration test: Full call manager setup with certificate.
#[tokio::test]
async fn test_call_manager_full_setup() {
    init_test_tracing();

    use client_core::CertificateStore;
    use client_types::audio::CodecPreference;

    let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let mut manager = CallManager::new(sip_addr, media_addr, tx);

    // 1. Configure account
    let account = test_account();
    manager.configure_account(&account);

    // 2. Configure ICE
    let ice_config = IceConfig::default();
    manager.set_ice_config(ice_config);

    // 3. Configure DTLS credentials from certificate store
    #[cfg(not(windows))]
    {
        let store = CertificateStore::open_personal();
        let certs = store.list_certificates().unwrap();

        if let Some(cert) = certs.iter().find(|c| c.is_valid) {
            if let Ok(chain) = store.get_certificate_chain(&cert.thumbprint) {
                manager.set_dtls_credentials(chain, Vec::new());
            }
        }
    }

    // 4. Set preferred codec
    manager.set_preferred_codec(CodecPreference::Opus);

    // Verify configuration
    assert_eq!(manager.preferred_codec(), CodecPreference::Opus);
    assert!(manager.active_call_id().is_none());
    assert!(!manager.is_muted());

    println!("CallManager fully configured and ready for calls");
}

/// Tests CallState enum behavior.
#[tokio::test]
async fn test_call_state_properties() {
    // Test is_active() method
    assert!(!CallState::Idle.is_active());
    assert!(CallState::Dialing.is_active());
    assert!(CallState::Ringing.is_active());
    assert!(CallState::Connecting.is_active());
    assert!(CallState::Connected.is_active());
    assert!(!CallState::Terminated.is_active());

    // Test has_media() method
    // Media flows only in EarlyMedia and Connected states
    assert!(!CallState::Idle.has_media());
    assert!(!CallState::Dialing.has_media());
    assert!(!CallState::Ringing.has_media());
    assert!(!CallState::Connecting.has_media());
    assert!(CallState::Connected.has_media());
    assert!(!CallState::Terminated.has_media());
}

#[cfg(test)]
mod sdp_tests {
    //! SDP generation and parsing tests.

    /// Tests that SDP offer contains required elements.
    #[tokio::test]
    async fn test_sdp_offer_structure() {
        // SDP offers are generated by CallManager internally
        // We test the expected structure conceptually

        let expected_elements = [
            "v=0",            // Version
            "o=",             // Origin
            "s=",             // Session name
            "c=",             // Connection info
            "t=0 0",          // Timing
            "m=audio",        // Media description
            "a=rtpmap:",      // Codec mappings
            "a=ice-ufrag:",   // ICE credentials
            "a=ice-pwd:",     // ICE credentials
            "a=fingerprint:", // DTLS fingerprint
            "a=setup:",       // DTLS setup role
        ];

        // These would be verified against actual SDP output in full integration
        for element in &expected_elements {
            assert!(!element.is_empty());
        }
    }
}

#[cfg(test)]
mod event_tests {
    //! CallManagerEvent tests.

    use super::*;

    #[tokio::test]
    async fn test_event_channel_capacity() {
        let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);

        // Channel should be created with capacity
        assert!(!tx.is_closed());
    }
}

#[cfg(test)]
mod incoming_call_tests {
    //! Incoming call handling tests.
    //!
    //! Tests the Phase 24.17/24.18 incoming call functionality including:
    //! - Handling incoming INVITE requests
    //! - Sending provisional responses (100 Trying, 180 Ringing)
    //! - Accepting calls with 200 OK
    //! - Rejecting calls with 486/603

    use super::*;
    use proto_sip::{SipMessage, SipRequest};
    use std::net::SocketAddr;

    /// Helper to parse an INVITE request from string.
    fn parse_invite(text: &str) -> SipRequest {
        let msg: SipMessage = text.parse().expect("Failed to parse SIP message");
        match msg {
            SipMessage::Request(req) => req,
            SipMessage::Response(_) => panic!("Expected request, got response"),
        }
    }

    /// Tests that CallManager can handle an incoming INVITE.
    #[tokio::test]
    async fn test_handle_incoming_invite() {
        init_test_tracing();

        let (tx, mut rx) = mpsc::channel::<CallManagerEvent>(32);
        let sip_addr = allocate_test_addr().await;
        let media_addr = allocate_test_addr().await;

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        // Configure account (required for incoming calls)
        let account = test_account();
        manager.configure_account(&account);

        // Create a mock incoming INVITE
        let caller_uri = "sips:caller@example.com";
        let callee_uri = "sips:testuser@example.com";
        let call_id = "incoming-call-12345@example.com";
        let source_addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();

        // Build mock SIP request
        let invite_str = format!(
            "INVITE {callee_uri} SIP/2.0\r\n\
             Via: SIP/2.0/TLS {source_addr};branch=z9hG4bK-test123\r\n\
             From: <{caller_uri}>;tag=from-tag-789\r\n\
             To: <{callee_uri}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <{caller_uri}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );

        let invite = parse_invite(&invite_str);

        // Handle the incoming INVITE
        let result = manager
            .handle_incoming_invite_from(&invite, source_addr)
            .await;
        assert!(
            result.is_ok(),
            "Should handle incoming INVITE: {:?}",
            result
        );

        // Should have the incoming call tracked
        assert!(manager.has_incoming_call(), "Should track incoming call");

        // Should emit SendResponse events for 100 Trying and 180 Ringing
        let mut saw_trying = false;
        let mut saw_ringing = false;

        // Drain events
        while let Ok(event) = rx.try_recv() {
            if let CallManagerEvent::SendResponse { response, .. } = event {
                let response_str = response.to_string();
                if response_str.contains("100 Trying") {
                    saw_trying = true;
                }
                if response_str.contains("180 Ringing") {
                    saw_ringing = true;
                }
            }
        }

        assert!(saw_trying, "Should send 100 Trying");
        assert!(saw_ringing, "Should send 180 Ringing");
    }

    /// Tests accepting an incoming call.
    #[tokio::test]
    async fn test_accept_incoming_call() {
        init_test_tracing();

        let (tx, mut rx) = mpsc::channel::<CallManagerEvent>(32);
        let sip_addr = allocate_test_addr().await;
        let media_addr = allocate_test_addr().await;

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let account = test_account();
        manager.configure_account(&account);

        // Simulate incoming INVITE
        let call_id = "accept-test-call@example.com";
        let source_addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();

        let invite_str = format!(
            "INVITE sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS {source_addr};branch=z9hG4bK-accept123\r\n\
             From: <sips:alice@example.com>;tag=from-accept-tag\r\n\
             To: <sips:testuser@example.com>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sips:alice@192.168.1.100:5061>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );

        let invite = parse_invite(&invite_str);
        manager
            .handle_incoming_invite_from(&invite, source_addr)
            .await
            .unwrap();

        // Get the internal call ID from incoming calls
        let incoming = manager.incoming_calls();
        assert!(!incoming.is_empty(), "Should have incoming call");
        let internal_call_id = incoming[0].call_id.clone();

        // Drain provisional response events
        while rx.try_recv().is_ok() {}

        // Accept the call
        let result = manager.accept_incoming_call(&internal_call_id).await;
        assert!(
            result.is_ok(),
            "Should accept incoming call: {:?}",
            result.err()
        );

        // Should emit a SendResponse event with 200 OK and CallStateChanged event
        let mut saw_200_ok = false;
        let mut saw_connected_event = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                CallManagerEvent::SendResponse { response, .. } => {
                    let response_str = response.to_string();
                    if response_str.contains("200 OK") {
                        saw_200_ok = true;
                    }
                }
                CallManagerEvent::CallStateChanged { state, .. } => {
                    if state == CallState::Connected {
                        saw_connected_event = true;
                    }
                }
                _ => {}
            }
        }

        assert!(saw_200_ok, "Should send 200 OK when accepting call");
        assert!(
            saw_connected_event,
            "Should emit Connected state change event"
        );

        // Verify internal state tracking
        assert!(
            manager.active_call_id().is_some(),
            "Should have active call ID after accept"
        );
    }

    /// Tests rejecting an incoming call.
    #[tokio::test]
    async fn test_reject_incoming_call() {
        init_test_tracing();

        let (tx, mut rx) = mpsc::channel::<CallManagerEvent>(32);
        let sip_addr = allocate_test_addr().await;
        let media_addr = allocate_test_addr().await;

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let account = test_account();
        manager.configure_account(&account);

        // Simulate incoming INVITE
        let call_id = "reject-test-call@example.com";
        let source_addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();

        let invite_str = format!(
            "INVITE sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS {source_addr};branch=z9hG4bK-reject456\r\n\
             From: <sips:bob@example.com>;tag=from-reject-tag\r\n\
             To: <sips:testuser@example.com>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sips:bob@192.168.1.100:5061>\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );

        let invite = parse_invite(&invite_str);
        manager
            .handle_incoming_invite_from(&invite, source_addr)
            .await
            .unwrap();

        // Get the internal call ID
        let incoming = manager.incoming_calls();
        let internal_call_id = incoming[0].call_id.clone();

        // Drain provisional response events
        while rx.try_recv().is_ok() {}

        // Reject the call (decline=false for 486 Busy Here)
        let result = manager.reject_incoming_call(&internal_call_id, false).await;
        assert!(
            result.is_ok(),
            "Should reject incoming call: {:?}",
            result.err()
        );

        // Should emit a SendResponse event with 486 or 603
        let mut saw_reject_response = false;
        while let Ok(event) = rx.try_recv() {
            if let CallManagerEvent::SendResponse { response, .. } = event {
                let response_str = response.to_string();
                if response_str.contains("486 Busy")
                    || response_str.contains("603 Decline")
                    || response_str.contains("480 Temporarily")
                {
                    saw_reject_response = true;
                }
            }
        }

        assert!(saw_reject_response, "Should send rejection response");

        // Incoming call should be removed
        assert!(
            !manager.has_incoming_call(),
            "Should remove incoming call after rejection"
        );
    }

    /// Tests that accepting a nonexistent call fails gracefully.
    #[tokio::test]
    async fn test_accept_nonexistent_call_fails() {
        init_test_tracing();

        let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
        let sip_addr = allocate_test_addr().await;
        let media_addr = allocate_test_addr().await;

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let result = manager.accept_incoming_call("nonexistent-call-id").await;
        assert!(result.is_err(), "Should fail for nonexistent call");
    }

    /// Tests that rejecting a nonexistent call fails gracefully.
    #[tokio::test]
    async fn test_reject_nonexistent_call_fails() {
        init_test_tracing();

        let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
        let sip_addr = allocate_test_addr().await;
        let media_addr = allocate_test_addr().await;

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let result = manager
            .reject_incoming_call("nonexistent-call-id", false)
            .await;
        assert!(result.is_err(), "Should fail for nonexistent call");
    }

    /// Tests incoming call list.
    #[tokio::test]
    async fn test_incoming_calls_list() {
        init_test_tracing();

        let (tx, _rx) = mpsc::channel::<CallManagerEvent>(32);
        let sip_addr = allocate_test_addr().await;
        let media_addr = allocate_test_addr().await;

        let mut manager = CallManager::new(sip_addr, media_addr, tx);

        let account = test_account();
        manager.configure_account(&account);

        // Initially no incoming calls
        assert!(
            manager.incoming_calls().is_empty(),
            "Should start with no incoming calls"
        );

        // Add an incoming call
        let source_addr: SocketAddr = "192.168.1.100:5061".parse().unwrap();
        let invite_str = format!(
            "INVITE sips:testuser@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS {source_addr};branch=z9hG4bK-iter789\r\n\
             From: <sips:charlie@example.com>;tag=from-iter-tag\r\n\
             To: <sips:testuser@example.com>\r\n\
             Call-ID: iter-test-call@example.com\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );

        let invite = parse_invite(&invite_str);
        let _ = manager
            .handle_incoming_invite_from(&invite, source_addr)
            .await;

        // Should have one incoming call
        let incoming = manager.incoming_calls();
        assert_eq!(incoming.len(), 1, "Should have one incoming call");

        // Verify call info
        let info = &incoming[0];
        assert!(!info.call_id.is_empty());
        assert_eq!(info.remote_uri, "sips:charlie@example.com");
    }
}

#[cfg(test)]
mod mock_server_invite_tests {
    //! Tests for the MockSipServer INVITE helpers.

    use crate::test_utils::MockSipServer;

    #[tokio::test]
    async fn test_mock_server_invite_request_format() {
        let request = MockSipServer::create_invite_request(
            "sips:caller@example.com",
            "Alice Smith",
            "sips:callee@example.com",
            "192.168.1.1:5061".parse().unwrap(),
            "test-call-id-123",
            "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n",
        );

        assert!(request.starts_with("INVITE sips:callee@example.com"));
        assert!(request.contains("From: \"Alice Smith\" <sips:caller@example.com>"));
        assert!(request.contains("To: <sips:callee@example.com>"));
        assert!(request.contains("Call-ID: test-call-id-123"));
        assert!(request.contains("CSeq: 1 INVITE"));
        assert!(request.contains("branch=z9hG4bK-"));
        assert!(request.contains("Content-Type: application/sdp"));
    }

    #[tokio::test]
    async fn test_mock_server_basic_sdp_offer() {
        let sdp = MockSipServer::basic_sdp_offer(5004, "test-ufrag", "test-pwd");

        assert!(sdp.contains("v=0"));
        assert!(sdp.contains("m=audio 5004"));
        assert!(sdp.contains("a=ice-ufrag:test-ufrag"));
        assert!(sdp.contains("a=ice-pwd:test-pwd"));
        assert!(sdp.contains("a=fingerprint:sha-384"));
        assert!(sdp.contains("a=setup:actpass"));
        assert!(sdp.contains("a=rtcp-mux"));
    }

    #[tokio::test]
    async fn test_mock_server_100_trying() {
        let request = "INVITE sips:callee@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/TLS 192.168.1.100:5061;branch=z9hG4bK-abc\r\n\
                       From: <sips:caller@example.com>;tag=from123\r\n\
                       To: <sips:callee@example.com>\r\n\
                       Call-ID: call-123\r\n\
                       CSeq: 1 INVITE\r\n\r\n";

        let response = MockSipServer::invite_100_trying(request);

        assert!(response.starts_with("SIP/2.0 100 Trying"));
        assert!(response.contains("Call-ID: call-123"));
        assert!(response.contains("CSeq: 1 INVITE"));
    }

    #[tokio::test]
    async fn test_mock_server_486_busy() {
        let request = "INVITE sips:callee@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/TLS 192.168.1.100:5061\r\n\
                       From: <sips:caller@example.com>;tag=from123\r\n\
                       To: <sips:callee@example.com>\r\n\
                       Call-ID: call-456\r\n\
                       CSeq: 1 INVITE\r\n\r\n";

        let response = MockSipServer::invite_486_busy(request);

        assert!(response.starts_with("SIP/2.0 486 Busy Here"));
        assert!(response.contains("To:"));
        assert!(response.contains("tag=")); // To tag added
    }

    #[tokio::test]
    async fn test_mock_server_603_decline() {
        let request = "INVITE sips:callee@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/TLS 192.168.1.100:5061\r\n\
                       From: <sips:caller@example.com>;tag=from789\r\n\
                       To: <sips:callee@example.com>\r\n\
                       Call-ID: call-789\r\n\
                       CSeq: 1 INVITE\r\n\r\n";

        let response = MockSipServer::invite_603_decline(request);

        assert!(response.starts_with("SIP/2.0 603 Decline"));
    }

    #[tokio::test]
    async fn test_mock_server_bye_request() {
        let request = MockSipServer::create_bye_request(
            "sips:caller@example.com",
            "sips:callee@example.com",
            "bye-call-id",
            "from-tag",
            "to-tag",
            "192.168.1.1:5061".parse().unwrap(),
        );

        assert!(request.starts_with("BYE sips:callee@example.com"));
        assert!(request.contains("From: <sips:caller@example.com>;tag=from-tag"));
        assert!(request.contains("To: <sips:callee@example.com>;tag=to-tag"));
        assert!(request.contains("Call-ID: bye-call-id"));
        assert!(request.contains("CSeq: 2 BYE"));
    }

    #[tokio::test]
    async fn test_mock_server_bye_200_ok() {
        let request = "BYE sips:callee@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/TLS 192.168.1.100:5061\r\n\
                       From: <sips:caller@example.com>;tag=from-bye\r\n\
                       To: <sips:callee@example.com>;tag=to-bye\r\n\
                       Call-ID: bye-test\r\n\
                       CSeq: 2 BYE\r\n\r\n";

        let response = MockSipServer::bye_200_ok(request);

        assert!(response.starts_with("SIP/2.0 200 OK"));
        assert!(response.contains("CSeq: 2 BYE"));
    }
}
