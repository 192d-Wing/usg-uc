//! Registration flow integration tests.
//!
//! Tests the SIP REGISTER flow including:
//! - RegistrationAgent request generation
//! - Response handling (200 OK, 401, 403)
//! - State transitions
//! - ClientApp integration

use crate::test_utils::{
    MockSipServer, allocate_test_addr, init_test_tracing, test_account_with_registrar,
};
use client_sip_ua::{RegistrationAgent, RegistrationEvent};
use client_types::RegistrationState;
use tokio::sync::mpsc;

/// Tests that RegistrationAgent sends REGISTER request.
#[tokio::test]
async fn test_registration_agent_sends_register() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    // Start mock server
    let server = MockSipServer::start().await;
    let account = test_account_with_registrar(server.addr);

    // Register
    agent.register(&account).await.unwrap();

    // Should receive state change to Registering
    let event = rx.recv().await.unwrap();
    assert!(
        matches!(event, RegistrationEvent::StateChanged { state, .. } if state == RegistrationState::Registering),
        "Expected StateChanged to Registering, got: {:?}",
        event
    );

    // Should receive SendRequest event
    let event = rx.recv().await.unwrap();
    if let RegistrationEvent::SendRequest {
        request,
        destination,
    } = event
    {
        // Verify request is a REGISTER
        assert_eq!(request.method.to_string(), "REGISTER");

        // Verify destination matches server
        assert_eq!(destination, server.addr);

        // Verify required headers are present
        let request_str = request.to_string();
        assert!(request_str.contains("Via:"), "Missing Via header");
        assert!(request_str.contains("From:"), "Missing From header");
        assert!(request_str.contains("To:"), "Missing To header");
        assert!(request_str.contains("Call-ID:"), "Missing Call-ID header");
        assert!(request_str.contains("CSeq:"), "Missing CSeq header");
        assert!(request_str.contains("Contact:"), "Missing Contact header");
        assert!(request_str.contains("Expires:"), "Missing Expires header");
    } else {
        panic!("Expected SendRequest event, got: {:?}", event);
    }

    // Verify agent state
    assert_eq!(
        agent.get_state("test-account"),
        Some(RegistrationState::Registering)
    );
}

/// Tests that RegistrationAgent increments CSeq on retry.
#[tokio::test]
async fn test_registration_cseq_increment() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    let server = MockSipServer::start().await;
    let account = test_account_with_registrar(server.addr);

    // First registration
    agent.register(&account).await.unwrap();

    // Drain events
    let _ = rx.recv().await; // StateChanged
    let first_request =
        if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
            request.to_string()
        } else {
            panic!("Expected SendRequest");
        };

    // Extract CSeq from first request
    let first_cseq = extract_cseq(&first_request);

    // Register again (simulating refresh)
    agent.register(&account).await.unwrap();

    // Drain state change
    let _ = rx.recv().await;

    let second_request =
        if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
            request.to_string()
        } else {
            panic!("Expected SendRequest");
        };

    let second_cseq = extract_cseq(&second_request);

    // CSeq should be incremented
    assert!(
        second_cseq > first_cseq,
        "CSeq should increment: {} -> {}",
        first_cseq,
        second_cseq
    );
}

/// Tests that RegistrationAgent reuses Call-ID (RFC 3261).
#[tokio::test]
async fn test_registration_reuses_call_id() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    let server = MockSipServer::start().await;
    let account = test_account_with_registrar(server.addr);

    // First registration
    agent.register(&account).await.unwrap();
    let _ = rx.recv().await;
    let first_request =
        if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
            request.to_string()
        } else {
            panic!("Expected SendRequest");
        };

    let first_call_id = extract_call_id(&first_request);

    // Second registration
    agent.register(&account).await.unwrap();
    let _ = rx.recv().await;
    let second_request =
        if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
            request.to_string()
        } else {
            panic!("Expected SendRequest");
        };

    let second_call_id = extract_call_id(&second_request);

    // Call-ID should be the same (RFC 3261)
    assert_eq!(
        first_call_id, second_call_id,
        "Call-ID should be reused across registrations"
    );
}

/// Tests that RegistrationAgent reuses From tag (RFC 3261).
#[tokio::test]
async fn test_registration_reuses_from_tag() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    let server = MockSipServer::start().await;
    let account = test_account_with_registrar(server.addr);

    // First registration
    agent.register(&account).await.unwrap();
    let _ = rx.recv().await;
    let first_request =
        if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
            request.to_string()
        } else {
            panic!("Expected SendRequest");
        };

    let first_from_tag = extract_from_tag(&first_request);

    // Second registration
    agent.register(&account).await.unwrap();
    let _ = rx.recv().await;
    let second_request =
        if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
            request.to_string()
        } else {
            panic!("Expected SendRequest");
        };

    let second_from_tag = extract_from_tag(&second_request);

    // From tag should be the same
    assert_eq!(
        first_from_tag, second_from_tag,
        "From tag should be reused across registrations"
    );
}

/// Tests Via header includes branch parameter.
#[tokio::test]
async fn test_registration_via_has_branch() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    let server = MockSipServer::start().await;
    let account = test_account_with_registrar(server.addr);

    agent.register(&account).await.unwrap();
    let _ = rx.recv().await;

    let request = if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
        request.to_string()
    } else {
        panic!("Expected SendRequest");
    };

    // Extract Via header
    let via = extract_header(&request, "Via:");

    // Via must have branch parameter starting with z9hG4bK (magic cookie per RFC 3261)
    assert!(
        via.contains("branch=z9hG4bK"),
        "Via branch must start with magic cookie z9hG4bK"
    );
}

/// Tests Contact header includes transport parameter.
#[tokio::test]
async fn test_registration_contact_has_transport() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    let server = MockSipServer::start().await;
    let account = test_account_with_registrar(server.addr);

    agent.register(&account).await.unwrap();
    let _ = rx.recv().await;

    let request = if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
        request.to_string()
    } else {
        panic!("Expected SendRequest");
    };

    // Contact should include transport=tls
    let contact = extract_header(&request, "Contact:");
    assert!(
        contact.to_lowercase().contains("transport=tls"),
        "Contact should specify TLS transport: {}",
        contact
    );
}

/// Tests User-Agent header is present and indicates CNSA compliance.
#[tokio::test]
async fn test_registration_user_agent_cnsa() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    let server = MockSipServer::start().await;
    let account = test_account_with_registrar(server.addr);

    agent.register(&account).await.unwrap();
    let _ = rx.recv().await;

    let request = if let RegistrationEvent::SendRequest { request, .. } = rx.recv().await.unwrap() {
        request.to_string()
    } else {
        panic!("Expected SendRequest");
    };

    let user_agent = extract_header(&request, "User-Agent:");
    assert!(
        user_agent.contains("CNSA"),
        "User-Agent should indicate CNSA compliance: {}",
        user_agent
    );
}

/// Tests unknown account returns None state.
#[tokio::test]
async fn test_registration_unknown_account_state() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let agent = RegistrationAgent::new(local_addr, tx);

    assert!(
        agent.get_state("nonexistent").is_none(),
        "Unknown account should return None state"
    );
}

/// Tests that registrar address parsing handles port correctly.
#[tokio::test]
async fn test_registration_registrar_addr_parsing() {
    init_test_tracing();

    let (tx, mut rx) = mpsc::channel::<RegistrationEvent>(32);
    let local_addr = allocate_test_addr().await;
    let mut agent = RegistrationAgent::new(local_addr, tx);

    // Create server on specific port
    let server = MockSipServer::start().await;
    let expected_port = server.addr.port();

    let account = test_account_with_registrar(server.addr);
    agent.register(&account).await.unwrap();

    // Skip state change
    let _ = rx.recv().await;

    // Get SendRequest event
    let event = rx.recv().await.unwrap();
    if let RegistrationEvent::SendRequest { destination, .. } = event {
        assert_eq!(destination.port(), expected_port);
    } else {
        panic!("Expected SendRequest");
    }
}

// --- Helper functions ---

fn extract_header(message: &str, header: &str) -> String {
    for line in message.lines() {
        let line_lower = line.to_lowercase();
        let header_lower = header.to_lowercase();
        if line_lower.starts_with(&header_lower) {
            return line[header.len()..].trim().to_string();
        }
    }
    String::new()
}

fn extract_cseq(message: &str) -> u32 {
    let cseq_line = extract_header(message, "CSeq:");
    // CSeq format: "1 REGISTER"
    cseq_line
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn extract_call_id(message: &str) -> String {
    extract_header(message, "Call-ID:")
}

fn extract_from_tag(message: &str) -> String {
    let from = extract_header(message, "From:");
    // Extract tag parameter
    if let Some(tag_start) = from.find("tag=") {
        let rest = &from[tag_start + 4..];
        let tag_end = rest.find([';', '>', ' ']).unwrap_or(rest.len());
        return rest[..tag_end].to_string();
    }
    String::new()
}

#[cfg(test)]
mod response_handling_tests {
    //! Response handling is tested separately since it requires
    //! constructing SipResponse objects which depends on proto-sip internals.
    //! These tests verify the state machine behavior conceptually.

    use super::*;

    /// Tests that agent transitions to Registering state on register().
    #[tokio::test]
    async fn test_register_transitions_to_registering() {
        init_test_tracing();

        let (tx, _rx) = mpsc::channel::<RegistrationEvent>(32);
        let local_addr = allocate_test_addr().await;
        let mut agent = RegistrationAgent::new(local_addr, tx);

        let server = MockSipServer::start().await;
        let account = test_account_with_registrar(server.addr);

        // Before registration
        assert!(agent.get_state("test-account").is_none());

        // After registration
        agent.register(&account).await.unwrap();
        assert_eq!(
            agent.get_state("test-account"),
            Some(RegistrationState::Registering)
        );
    }
}
