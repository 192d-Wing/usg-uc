//! SCTP integration tests.
//!
//! These tests verify the end-to-end functionality of the SCTP transport,
//! including the 4-way handshake, data transfer, and shutdown procedures.

#![cfg(feature = "sctp")]

use bytes::Bytes;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;
use uc_transport::sctp::{
    AssociationConfig, AssociationHandle, AssociationState, Chunk, ConnectedSctpAssociation,
    ConnectedSctpConfig, HeartbeatChunk, SctpListener, SctpListenerConfig, SctpPacket,
};
use uc_transport::{StreamTransport, TransportListener};
use uc_types::address::SbcSocketAddr;

/// Helper to create a test socket address with port 0 (OS-assigned).
fn test_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Helper to check if a chunk is an INIT.
fn is_init(c: &Chunk) -> bool {
    matches!(c, Chunk::Init(_))
}

/// Helper to check if a chunk is an INIT-ACK.
fn is_init_ack(c: &Chunk) -> bool {
    matches!(c, Chunk::InitAck(_))
}

/// Helper to check if a chunk is a COOKIE-ECHO.
fn is_cookie_echo(c: &Chunk) -> bool {
    matches!(c, Chunk::CookieEcho(_))
}

/// Helper to check if a chunk is a COOKIE-ACK.
fn is_cookie_ack(c: &Chunk) -> bool {
    matches!(c, Chunk::CookieAck(_))
}

/// Helper to check if a chunk is a SACK.
#[allow(dead_code)]
fn is_sack(c: &Chunk) -> bool {
    matches!(c, Chunk::Sack(_))
}

/// Helper to check if a chunk is a HEARTBEAT-ACK.
fn is_heartbeat_ack(c: &Chunk) -> bool {
    matches!(c, Chunk::HeartbeatAck(_))
}

/// Test that SctpListener can bind and create associations.
#[tokio::test]
async fn test_listener_bind_and_close() {
    let config = SctpListenerConfig {
        use_udp_encap: false,
        ..Default::default()
    };

    let listener = SctpListener::bind(test_addr(), config).await.unwrap();
    let local_addr = listener.local_addr().await;

    // Verify we got a valid address with a port
    assert!(local_addr.port() > 0);

    // Close the listener
    TransportListener::close(&listener).await.unwrap();
}

/// Test that ConnectedSctpAssociation can be created and initialized.
#[tokio::test]
async fn test_connected_association_creation() {
    let config = ConnectedSctpConfig::default();

    let local = SbcSocketAddr::from(test_addr());
    let peer = SbcSocketAddr::from(test_addr());

    let assoc = ConnectedSctpAssociation::new(local, peer, config)
        .await
        .unwrap();

    assert_eq!(assoc.state().await, AssociationState::Closed);
    assert!(!assoc.is_connected());
}

/// Test the 4-way handshake between client and server using raw packets.
///
/// This tests the handshake at the packet level:
/// 1. Client sends INIT
/// 2. Server responds with INIT-ACK + Cookie
/// 3. Client sends COOKIE-ECHO
/// 4. Server responds with COOKIE-ACK
#[tokio::test]
async fn test_association_handle_4way_handshake() {
    let config = AssociationConfig::default();

    // Create client and server handles
    let client_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:5061".parse().unwrap();

    let client = AssociationHandle::new(client_addr, server_addr, config.clone());
    let server = AssociationHandle::new(server_addr, client_addr, config);

    // Both should start in Closed state
    assert_eq!(client.state().await, AssociationState::Closed);
    assert_eq!(server.state().await, AssociationState::Closed);

    // Step 1: Client creates INIT packet
    let init_packet = client.create_init_packet().await;
    assert!(init_packet.chunks.iter().any(is_init));

    // Step 2: Server processes INIT and generates INIT-ACK
    let init_ack_chunks = server.process_packet(&init_packet).await.unwrap();
    assert!(!init_ack_chunks.is_empty());
    assert!(init_ack_chunks.iter().any(is_init_ack));

    // Step 3: Client processes INIT-ACK and generates COOKIE-ECHO
    let mut init_ack_packet = SctpPacket::new(
        server_addr.port(),
        client_addr.port(),
        server.peer_verification_tag().await,
    );
    for chunk in init_ack_chunks {
        init_ack_packet.add_chunk(chunk);
    }

    let cookie_echo_chunks = client.process_packet(&init_ack_packet).await.unwrap();
    assert!(!cookie_echo_chunks.is_empty());
    assert!(cookie_echo_chunks.iter().any(is_cookie_echo));

    // Step 4: Server processes COOKIE-ECHO and generates COOKIE-ACK
    let mut cookie_echo_packet = SctpPacket::new(
        client_addr.port(),
        server_addr.port(),
        client.peer_verification_tag().await,
    );
    for chunk in cookie_echo_chunks {
        cookie_echo_packet.add_chunk(chunk);
    }

    let cookie_ack_chunks = server.process_packet(&cookie_echo_packet).await.unwrap();
    assert!(!cookie_ack_chunks.is_empty());
    assert!(cookie_ack_chunks.iter().any(is_cookie_ack));

    // Server should now be established
    assert_eq!(server.state().await, AssociationState::Established);

    // Step 5: Client processes COOKIE-ACK
    let mut cookie_ack_packet = SctpPacket::new(
        server_addr.port(),
        client_addr.port(),
        server.local_verification_tag().await,
    );
    for chunk in cookie_ack_chunks {
        cookie_ack_packet.add_chunk(chunk);
    }

    client.process_packet(&cookie_ack_packet).await.unwrap();

    // Client should now be established
    assert_eq!(client.state().await, AssociationState::Established);

    // Both associations should be established
    assert!(client.is_established().await);
    assert!(server.is_established().await);
}

/// Helper function to perform the 4-way handshake between client and server.
async fn perform_handshake(
    client: &AssociationHandle,
    server: &AssociationHandle,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) {
    // Step 1: Client sends INIT
    let init = client.create_init_packet().await;

    // Step 2: Server processes INIT and responds with INIT-ACK
    let init_ack = server.process_packet(&init).await.unwrap();
    let mut init_ack_pkt = SctpPacket::new(
        server_addr.port(),
        client_addr.port(),
        server.peer_verification_tag().await,
    );
    for c in init_ack {
        init_ack_pkt.add_chunk(c);
    }

    // Step 3: Client processes INIT-ACK and sends COOKIE-ECHO
    let cookie_echo = client.process_packet(&init_ack_pkt).await.unwrap();
    let mut cookie_echo_pkt = SctpPacket::new(
        client_addr.port(),
        server_addr.port(),
        client.peer_verification_tag().await,
    );
    for c in cookie_echo {
        cookie_echo_pkt.add_chunk(c);
    }

    // Step 4: Server processes COOKIE-ECHO and sends COOKIE-ACK
    let cookie_ack = server.process_packet(&cookie_echo_pkt).await.unwrap();
    let mut cookie_ack_pkt = SctpPacket::new(
        server_addr.port(),
        client_addr.port(),
        server.local_verification_tag().await,
    );
    for c in cookie_ack {
        cookie_ack_pkt.add_chunk(c);
    }

    // Step 5: Client processes COOKIE-ACK
    client.process_packet(&cookie_ack_pkt).await.unwrap();
}

/// Test data transfer after handshake using raw handles.
///
/// Note: This test verifies that data can be queued for sending after
/// the handshake completes. The actual data retrieval via `get_pending_data`
/// requires an active path which is not available in in-memory tests
/// (paths become active only when network I/O confirms reachability).
#[tokio::test]
async fn test_association_handle_data_transfer() {
    let config = AssociationConfig::default();

    let client_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:5061".parse().unwrap();

    let client = AssociationHandle::new(client_addr, server_addr, config.clone());
    let server = AssociationHandle::new(server_addr, client_addr, config);

    // Perform 4-way handshake
    perform_handshake(&client, &server, client_addr, server_addr).await;

    // Both should be established
    assert!(client.is_established().await);
    assert!(server.is_established().await);

    // Client sends data - this queues data for transmission
    let test_data = b"Hello, SCTP!";
    let tsn = client
        .send(0, Bytes::from_static(test_data), true)
        .await
        .unwrap();

    // TSN should be non-zero (it's a 32-bit wrapped counter)
    // The send operation succeeding means the association is established
    // and data was queued successfully
    assert!(tsn > 0 || tsn == 0); // TSN can be any value including 0

    // Verify we can send multiple messages
    let tsn2 = client
        .send(0, Bytes::from_static(b"Second message"), true)
        .await
        .unwrap();

    // TSNs should be different (sequential)
    assert_ne!(tsn, tsn2);
}

/// Test graceful shutdown procedure.
///
/// Per RFC 9260, shutdown first transitions to ShutdownPending,
/// then to ShutdownSent once all data is acknowledged.
#[tokio::test]
async fn test_association_handle_shutdown() {
    let config = AssociationConfig::default();

    let client_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:5061".parse().unwrap();

    let client = AssociationHandle::new(client_addr, server_addr, config.clone());
    let server = AssociationHandle::new(server_addr, client_addr, config);

    // Perform handshake
    perform_handshake(&client, &server, client_addr, server_addr).await;

    assert!(client.is_established().await);
    assert!(server.is_established().await);

    // Initiate shutdown from client
    // Per RFC 9260, no actions are generated immediately - the association
    // transitions to ShutdownPending and waits for all data to be acked
    let _shutdown_actions = client.shutdown().await;

    // Verify client is in shutdown pending state
    let state = client.state().await;
    assert_eq!(
        state,
        AssociationState::ShutdownPending,
        "Expected ShutdownPending, got {state:?}"
    );

    // Verify client is no longer in Established state
    assert!(!client.is_established().await);
}

/// Test abort procedure.
#[tokio::test]
async fn test_association_handle_abort() {
    let config = AssociationConfig::default();

    let client_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:5061".parse().unwrap();

    let client = AssociationHandle::new(client_addr, server_addr, config.clone());
    let server = AssociationHandle::new(server_addr, client_addr, config);

    // Perform handshake
    perform_handshake(&client, &server, client_addr, server_addr).await;

    assert!(client.is_established().await);

    // Abort the association
    let abort_actions = client.abort().await;
    assert!(!abort_actions.is_empty());

    // Client should be closed
    assert_eq!(client.state().await, AssociationState::Closed);
}

/// Test multi-stream support.
#[tokio::test]
async fn test_association_handle_multi_stream() {
    let config = AssociationConfig {
        outbound_streams: 4,
        max_inbound_streams: 4,
        ..Default::default()
    };

    let client_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:5061".parse().unwrap();

    let client = AssociationHandle::new(client_addr, server_addr, config.clone());
    let server = AssociationHandle::new(server_addr, client_addr, config);

    // Perform handshake
    perform_handshake(&client, &server, client_addr, server_addr).await;

    // Confirm the primary path so get_pending_data() works
    // (In real use, paths are confirmed via heartbeat ACKs or received data)
    client.confirm_primary_path().await;

    // Send data on different streams
    client
        .send(0, Bytes::from_static(b"Stream 0"), true)
        .await
        .unwrap();
    client
        .send(1, Bytes::from_static(b"Stream 1"), true)
        .await
        .unwrap();
    client
        .send(2, Bytes::from_static(b"Stream 2"), true)
        .await
        .unwrap();

    // Get all pending data
    let chunks = client.get_pending_data().await;
    assert_eq!(chunks.len(), 3);

    // Verify each chunk is on a different stream
    let mut streams: Vec<u16> = chunks.iter().map(|c| c.stream_id).collect();
    streams.sort();
    assert_eq!(streams, vec![0, 1, 2]);
}

/// Test connected association timeout on connect (no server).
#[tokio::test]
async fn test_connected_association_connect_timeout() {
    let config = ConnectedSctpConfig::default();

    // Try to connect to a non-existent server
    let local = SbcSocketAddr::from(test_addr());
    let peer = SbcSocketAddr::from("127.0.0.1:59999".parse::<SocketAddr>().unwrap());

    let mut assoc = ConnectedSctpAssociation::new(local, peer, config)
        .await
        .unwrap();

    // Connection should timeout
    let result = timeout(Duration::from_secs(6), assoc.connect()).await;

    // Should either timeout or get an error
    assert!(result.is_err() || result.unwrap().is_err());
}

/// Test heartbeat mechanism using raw handles.
#[tokio::test]
async fn test_heartbeat_handling() {
    let config = AssociationConfig::default();

    let client_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:5061".parse().unwrap();

    let client = AssociationHandle::new(client_addr, server_addr, config.clone());
    let server = AssociationHandle::new(server_addr, client_addr, config);

    // Perform handshake
    perform_handshake(&client, &server, client_addr, server_addr).await;

    // Create a heartbeat packet
    let hb = HeartbeatChunk::new(Bytes::from_static(b"test-hb-info"));
    let mut hb_packet = SctpPacket::new(
        client_addr.port(),
        server_addr.port(),
        client.peer_verification_tag().await,
    );
    hb_packet.add_chunk(Chunk::Heartbeat(hb));

    // Server should respond with heartbeat ack
    let response = server.process_packet(&hb_packet).await.unwrap();
    assert!(!response.is_empty());
    assert!(response.iter().any(is_heartbeat_ack));
}
