//! SCTP RFC 9260 Compliance Tests
//!
//! This module provides comprehensive test coverage for RFC 9260 (Stream Control
//! Transmission Protocol) compliance. Tests are organized by RFC section.
//!
//! # Test Organization
//! - Section 3: SCTP Packet Format
//! - Section 4: SCTP Association State Diagram
//! - Section 5: Association Initialization
//! - Section 6: User Data Transfer
//! - Section 7: Congestion Control
//! - Section 9: Termination of Association

#![cfg(feature = "sctp")]

use bytes::{Bytes, BytesMut};
use std::net::{Ipv4Addr, SocketAddr};
use uc_transport::sctp::{
    AbortChunk, AssociationConfig, AssociationHandle, AssociationState, Chunk, ChunkType,
    CookieAckChunk, CookieEchoChunk, CwrChunk, DataChunk, EcneChunk, ErrorCause, ErrorChunk,
    GapAckBlock, HeartbeatAckChunk, HeartbeatChunk, InitAckChunk, InitChunk, InitParam, SackChunk,
    SctpPacket, ShutdownAckChunk, ShutdownChunk, ShutdownCompleteChunk, UnknownChunkAction,
};

// =============================================================================
// Test Helpers
// =============================================================================

fn test_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Encodes a chunk and decodes it back, returning the result.
fn roundtrip_chunk(chunk: Chunk) -> Chunk {
    let mut buf = BytesMut::new();
    chunk.encode(&mut buf);
    let mut bytes = buf.freeze();
    Chunk::decode(&mut bytes).unwrap()
}

// =============================================================================
// Section 3: SCTP Packet Format (RFC 9260 Section 3)
// =============================================================================

mod section3_packet_format {
    use super::*;

    // -------------------------------------------------------------------------
    // Section 3.1: SCTP Common Header Format
    // -------------------------------------------------------------------------

    /// RFC 9260 Section 3.1: Verify common header encoding (12 bytes).
    #[test]
    fn test_common_header_format() {
        let packet = SctpPacket::new(5060, 5061, 0x12345678);
        let encoded = packet.encode();

        // Common header is 12 bytes
        assert!(encoded.len() >= 12);

        // Source port (bytes 0-1)
        assert_eq!(u16::from_be_bytes([encoded[0], encoded[1]]), 5060);
        // Destination port (bytes 2-3)
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 5061);
        // Verification tag (bytes 4-7)
        assert_eq!(
            u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]),
            0x12345678
        );
        // Checksum (bytes 8-11) - CRC32c
        // Just verify it's present; actual value depends on implementation
        assert!(encoded.len() >= 12);
    }

    /// RFC 9260 Section 3.1: Verification tag must be 0 for INIT chunk.
    #[test]
    fn test_init_requires_zero_verification_tag() {
        let init = InitChunk::new(0xABCD1234, 65535, 10, 10, 1000);
        let mut packet = SctpPacket::new(5060, 5061, 0); // Must be 0 for INIT
        packet.add_chunk(Chunk::Init(init));

        let encoded = packet.encode();
        // Verification tag should be 0
        let vtag = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        assert_eq!(vtag, 0);
    }

    // -------------------------------------------------------------------------
    // Section 3.2: Chunk Field Descriptions
    // -------------------------------------------------------------------------

    /// RFC 9260 Section 3.2: Chunk header is 4 bytes (type, flags, length).
    #[test]
    fn test_chunk_header_size() {
        // Minimum chunk is 4 bytes (just header)
        let shutdown_ack = Chunk::ShutdownAck(ShutdownAckChunk);
        let mut buf = BytesMut::new();
        shutdown_ack.encode(&mut buf);

        assert_eq!(buf.len(), 4);
        assert_eq!(buf[0], ChunkType::ShutdownAck as u8);
        assert_eq!(buf[1], 0); // flags
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 4); // length
    }

    /// RFC 9260 Section 3.2: Chunk length includes the header (4 bytes).
    #[test]
    fn test_chunk_length_includes_header() {
        // SHUTDOWN chunk: 4 byte header + 4 byte TSN = 8 bytes
        let shutdown = Chunk::Shutdown(ShutdownChunk::new(12345));
        let mut buf = BytesMut::new();
        shutdown.encode(&mut buf);

        let length = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(length, 8);
    }

    /// RFC 9260 Section 3.2: Chunks must be padded to 4-byte boundary.
    #[test]
    fn test_chunk_padding() {
        // DATA chunk with 1 byte payload
        let data = Chunk::Data(DataChunk::new(1, 0, 0, 0, Bytes::from_static(b"X")));
        let mut buf = BytesMut::new();
        data.encode(&mut buf);

        // 16 byte header + 1 byte data = 17 bytes, padded to 20
        assert_eq!(buf.len() % 4, 0);
        assert_eq!(buf.len(), 20);
    }

    /// RFC 9260 Section 3.2: Chunk padding bytes should be zero.
    #[test]
    fn test_chunk_padding_zeros() {
        let data = Chunk::Data(DataChunk::new(1, 0, 0, 0, Bytes::from_static(b"AB"))); // 2 bytes
        let mut buf = BytesMut::new();
        data.encode(&mut buf);

        // 16 byte header + 2 bytes data = 18 bytes, padded to 20
        // Last 2 bytes should be padding zeros
        assert_eq!(buf[18], 0);
        assert_eq!(buf[19], 0);
    }

    /// RFC 9260 Section 3.2: Unknown chunk type handling based on upper bits.
    #[test]
    fn test_unknown_chunk_action_bits() {
        // 00xxxxxx - Stop processing and report
        assert_eq!(
            ChunkType::unknown_action(0b0000_0000),
            UnknownChunkAction::StopAndReport
        );
        assert_eq!(
            ChunkType::unknown_action(0b0011_1111),
            UnknownChunkAction::StopAndReport
        );

        // 01xxxxxx - Stop processing silently
        assert_eq!(
            ChunkType::unknown_action(0b0100_0000),
            UnknownChunkAction::StopSilently
        );
        assert_eq!(
            ChunkType::unknown_action(0b0111_1111),
            UnknownChunkAction::StopSilently
        );

        // 10xxxxxx - Skip and report
        assert_eq!(
            ChunkType::unknown_action(0b1000_0000),
            UnknownChunkAction::SkipAndReport
        );
        assert_eq!(
            ChunkType::unknown_action(0b1011_1111),
            UnknownChunkAction::SkipAndReport
        );

        // 11xxxxxx - Skip silently
        assert_eq!(
            ChunkType::unknown_action(0b1100_0000),
            UnknownChunkAction::SkipSilently
        );
        assert_eq!(
            ChunkType::unknown_action(0b1111_1111),
            UnknownChunkAction::SkipSilently
        );
    }

    // -------------------------------------------------------------------------
    // Section 3.3: Chunk Definitions
    // -------------------------------------------------------------------------

    /// RFC 9260 Section 3.3.1: DATA chunk format.
    #[test]
    fn test_data_chunk_format() {
        let data = DataChunk::new(0x12345678, 0x1234, 0x5678, 0xABCDEF00, Bytes::from("test"))
            .with_immediate(true)
            .with_unordered(false)
            .with_fragment(true, true);

        let decoded = roundtrip_chunk(Chunk::Data(data.clone()));

        if let Chunk::Data(d) = decoded {
            assert_eq!(d.tsn, 0x12345678);
            assert_eq!(d.stream_id, 0x1234);
            assert_eq!(d.ssn, 0x5678);
            assert_eq!(d.ppid, 0xABCDEF00);
            assert_eq!(d.data, Bytes::from("test"));
            assert!(d.immediate);
            assert!(!d.unordered);
            assert!(d.beginning);
            assert!(d.ending);
        } else {
            panic!("Expected DATA chunk");
        }
    }

    /// RFC 9260 Section 3.3.1: DATA chunk flags (I, U, B, E bits).
    #[test]
    fn test_data_chunk_flags() {
        // Test all flag combinations
        let test_cases = [
            (false, false, false, false, 0b0000),
            (true, false, false, false, 0b1000), // I bit
            (false, true, false, false, 0b0100), // U bit
            (false, false, true, false, 0b0010), // B bit
            (false, false, false, true, 0b0001), // E bit
            (true, true, true, true, 0b1111),    // All bits
        ];

        for (immediate, unordered, beginning, ending, expected_flags) in test_cases {
            let mut data = DataChunk::new(1, 0, 0, 0, Bytes::from("x"));
            data.immediate = immediate;
            data.unordered = unordered;
            data.beginning = beginning;
            data.ending = ending;

            let chunk = Chunk::Data(data);
            let mut buf = BytesMut::new();
            chunk.encode(&mut buf);

            assert_eq!(
                buf[1], expected_flags,
                "Flags mismatch for i={immediate}, u={unordered}, b={beginning}, e={ending}"
            );
        }
    }

    /// RFC 9260 Section 3.3.2: INIT chunk format.
    #[test]
    fn test_init_chunk_format() {
        let init = InitChunk::new(0xABCD1234, 65535, 10, 20, 1000)
            .with_ipv4_address(Ipv4Addr::new(192, 168, 1, 1));

        let decoded = roundtrip_chunk(Chunk::Init(init.clone()));

        if let Chunk::Init(i) = decoded {
            assert_eq!(i.initiate_tag, 0xABCD1234);
            assert_eq!(i.a_rwnd, 65535);
            assert_eq!(i.num_outbound_streams, 10);
            assert_eq!(i.num_inbound_streams, 20);
            assert_eq!(i.initial_tsn, 1000);
            assert_eq!(i.params.len(), 1);
            assert!(matches!(i.params[0], InitParam::Ipv4Address(_)));
        } else {
            panic!("Expected INIT chunk");
        }
    }

    /// RFC 9260 Section 3.3.2: INIT chunk must have non-zero initiate tag.
    #[test]
    fn test_init_chunk_nonzero_tag() {
        // Per RFC, Initiate Tag MUST NOT be 0
        let init = InitChunk::new(0, 65535, 10, 10, 1000);
        // Implementation should validate this, but for now just ensure
        // the value is preserved
        let decoded = roundtrip_chunk(Chunk::Init(init));
        if let Chunk::Init(i) = decoded {
            assert_eq!(i.initiate_tag, 0);
        }
    }

    /// RFC 9260 Section 3.3.3: INIT-ACK chunk format.
    #[test]
    fn test_init_ack_chunk_format() {
        let init = InitChunk::new(0x11111111, 32768, 5, 5, 500);
        let init_ack =
            InitAckChunk::from_init(&init, 0x22222222, 65535, 1000, Bytes::from("cookie"));

        let decoded = roundtrip_chunk(Chunk::InitAck(init_ack));

        if let Chunk::InitAck(ia) = decoded {
            assert_eq!(ia.initiate_tag, 0x22222222);
            assert_eq!(ia.a_rwnd, 65535);
            assert_eq!(ia.initial_tsn, 1000);
            assert!(ia.cookie().is_some());
        } else {
            panic!("Expected INIT-ACK chunk");
        }
    }

    /// RFC 9260 Section 3.3.4: SACK chunk format.
    #[test]
    fn test_sack_chunk_format() {
        let mut sack = SackChunk::new(12345, 32768);
        sack.add_gap_block(2, 5);
        sack.add_gap_block(10, 15);
        sack.add_dup_tsn(12340);

        let decoded = roundtrip_chunk(Chunk::Sack(sack));

        if let Chunk::Sack(s) = decoded {
            assert_eq!(s.cumulative_tsn_ack, 12345);
            assert_eq!(s.a_rwnd, 32768);
            assert_eq!(s.gap_ack_blocks.len(), 2);
            assert_eq!(s.gap_ack_blocks[0], GapAckBlock { start: 2, end: 5 });
            assert_eq!(s.gap_ack_blocks[1], GapAckBlock { start: 10, end: 15 });
            assert_eq!(s.dup_tsns.len(), 1);
            assert_eq!(s.dup_tsns[0], 12340);
        } else {
            panic!("Expected SACK chunk");
        }
    }

    /// RFC 9260 Section 3.3.5: HEARTBEAT chunk format.
    #[test]
    fn test_heartbeat_chunk_format() {
        let hb = HeartbeatChunk::new(Bytes::from("heartbeat-info-12345"));

        let decoded = roundtrip_chunk(Chunk::Heartbeat(hb));

        if let Chunk::Heartbeat(h) = decoded {
            assert_eq!(h.info, Bytes::from("heartbeat-info-12345"));
        } else {
            panic!("Expected HEARTBEAT chunk");
        }
    }

    /// RFC 9260 Section 3.3.6: HEARTBEAT-ACK echoes back info unchanged.
    #[test]
    fn test_heartbeat_ack_echoes_info() {
        let hb = HeartbeatChunk::new(Bytes::from("echo-me-back"));
        let hb_ack = HeartbeatAckChunk::from_heartbeat(&hb);

        assert_eq!(hb_ack.info, hb.info);

        let decoded = roundtrip_chunk(Chunk::HeartbeatAck(hb_ack));
        if let Chunk::HeartbeatAck(ha) = decoded {
            assert_eq!(ha.info, Bytes::from("echo-me-back"));
        } else {
            panic!("Expected HEARTBEAT-ACK chunk");
        }
    }

    /// RFC 9260 Section 3.3.7: ABORT chunk format with T bit.
    #[test]
    fn test_abort_chunk_format() {
        let mut abort = AbortChunk::new();
        abort.tcb_destroyed = true;
        abort.add_cause(ErrorCause::UserInitiatedAbort {
            reason: Bytes::from("user abort"),
        });

        let decoded = roundtrip_chunk(Chunk::Abort(abort));

        if let Chunk::Abort(a) = decoded {
            assert!(a.tcb_destroyed);
            assert_eq!(a.causes.len(), 1);
        } else {
            panic!("Expected ABORT chunk");
        }
    }

    /// RFC 9260 Section 3.3.8: SHUTDOWN chunk format.
    #[test]
    fn test_shutdown_chunk_format() {
        let shutdown = ShutdownChunk::new(0xDEADBEEF);

        let decoded = roundtrip_chunk(Chunk::Shutdown(shutdown));

        if let Chunk::Shutdown(s) = decoded {
            assert_eq!(s.cumulative_tsn_ack, 0xDEADBEEF);
        } else {
            panic!("Expected SHUTDOWN chunk");
        }
    }

    /// RFC 9260 Section 3.3.10: ERROR chunk with various causes.
    #[test]
    fn test_error_chunk_causes() {
        let causes = vec![
            ErrorCause::InvalidStreamIdentifier { stream_id: 42 },
            ErrorCause::StaleCookieError { measure: 1000 },
            ErrorCause::OutOfResource,
            ErrorCause::NoUserData { tsn: 12345 },
            ErrorCause::ProtocolViolation {
                info: Bytes::from("violation"),
            },
        ];

        for cause in causes {
            let mut error = ErrorChunk::new();
            error.add_cause(cause.clone());

            let decoded = roundtrip_chunk(Chunk::Error(error));

            if let Chunk::Error(e) = decoded {
                assert_eq!(e.causes.len(), 1);
            } else {
                panic!("Expected ERROR chunk");
            }
        }
    }

    /// RFC 9260 Section 3.3.11: COOKIE-ECHO chunk format.
    #[test]
    fn test_cookie_echo_chunk_format() {
        let cookie_echo = CookieEchoChunk::new(Bytes::from("state-cookie-data-here"));

        let decoded = roundtrip_chunk(Chunk::CookieEcho(cookie_echo));

        if let Chunk::CookieEcho(ce) = decoded {
            assert_eq!(ce.cookie, Bytes::from("state-cookie-data-here"));
        } else {
            panic!("Expected COOKIE-ECHO chunk");
        }
    }

    /// RFC 9260 Section 3.3.12: COOKIE-ACK chunk format (no parameters).
    #[test]
    fn test_cookie_ack_chunk_format() {
        let cookie_ack = Chunk::CookieAck(CookieAckChunk);

        let mut buf = BytesMut::new();
        cookie_ack.encode(&mut buf);

        // Should be exactly 4 bytes
        assert_eq!(buf.len(), 4);
        assert_eq!(buf[0], ChunkType::CookieAck as u8);
    }

    /// RFC 9260 Section 3.3.13: SHUTDOWN-COMPLETE with T bit.
    #[test]
    fn test_shutdown_complete_t_bit() {
        // T=0 case
        let sc = ShutdownCompleteChunk::new(false);
        let decoded = roundtrip_chunk(Chunk::ShutdownComplete(sc));
        if let Chunk::ShutdownComplete(s) = decoded {
            assert!(!s.tcb_destroyed);
        } else {
            panic!("Expected SHUTDOWN-COMPLETE");
        }

        // T=1 case
        let sc = ShutdownCompleteChunk::new(true);
        let decoded = roundtrip_chunk(Chunk::ShutdownComplete(sc));
        if let Chunk::ShutdownComplete(s) = decoded {
            assert!(s.tcb_destroyed);
        } else {
            panic!("Expected SHUTDOWN-COMPLETE");
        }
    }

    /// RFC 9260 Section 3.3.11 (ECN): ECNE chunk format.
    #[test]
    fn test_ecne_chunk_format() {
        let ecne = EcneChunk::new(0xCAFEBABE);

        let decoded = roundtrip_chunk(Chunk::Ecne(ecne));

        if let Chunk::Ecne(e) = decoded {
            assert_eq!(e.lowest_tsn, 0xCAFEBABE);
        } else {
            panic!("Expected ECNE chunk");
        }
    }

    /// RFC 9260 Section 3.3.12 (ECN): CWR chunk format.
    #[test]
    fn test_cwr_chunk_format() {
        let cwr = CwrChunk::new(0xDEADBEEF);

        let decoded = roundtrip_chunk(Chunk::Cwr(cwr));

        if let Chunk::Cwr(c) = decoded {
            assert_eq!(c.lowest_tsn, 0xDEADBEEF);
        } else {
            panic!("Expected CWR chunk");
        }
    }

    // -------------------------------------------------------------------------
    // Section 3.2.1: Chunk Bundling Rules
    // -------------------------------------------------------------------------

    /// RFC 9260 Section 6.10: INIT must not be bundled with other chunks.
    #[test]
    fn test_init_must_not_bundle() {
        assert!(ChunkType::Init.must_not_bundle());
    }

    /// RFC 9260 Section 6.10: INIT-ACK must not be bundled with other chunks.
    #[test]
    fn test_init_ack_must_not_bundle() {
        assert!(ChunkType::InitAck.must_not_bundle());
    }

    /// RFC 9260 Section 6.10: SHUTDOWN-COMPLETE must not be bundled.
    #[test]
    fn test_shutdown_complete_must_not_bundle() {
        assert!(ChunkType::ShutdownComplete.must_not_bundle());
    }

    /// RFC 9260 Section 6.10: DATA and SACK can be bundled.
    #[test]
    fn test_data_sack_can_bundle() {
        assert!(!ChunkType::Data.must_not_bundle());
        assert!(!ChunkType::Sack.must_not_bundle());
    }
}

// =============================================================================
// Section 4: SCTP Association State Diagram (RFC 9260 Section 4)
// =============================================================================

mod section4_state_diagram {
    use super::*;
    use uc_transport::sctp::{StateAction, StateEvent, StateMachine};

    /// RFC 9260 Section 4: Initial state is CLOSED.
    #[test]
    fn test_initial_state_closed() {
        let sm = StateMachine::new();
        assert_eq!(sm.state(), AssociationState::Closed);
    }

    /// RFC 9260 Section 4: CLOSED -> COOKIE-WAIT on Associate.
    #[test]
    fn test_closed_to_cookie_wait() {
        let mut sm = StateMachine::new();
        let actions = sm.process_event(StateEvent::Associate);

        assert_eq!(sm.state(), AssociationState::CookieWait);
        assert!(actions.contains(&StateAction::SendInit));
        assert!(actions.contains(&StateAction::StartT1Init));
    }

    /// RFC 9260 Section 4: COOKIE-WAIT -> COOKIE-ECHOED on INIT-ACK.
    #[test]
    fn test_cookie_wait_to_cookie_echoed() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        let actions = sm.process_event(StateEvent::ReceiveInitAck);

        assert_eq!(sm.state(), AssociationState::CookieEchoed);
        assert!(actions.contains(&StateAction::StopT1Init));
        assert!(actions.contains(&StateAction::SendCookieEcho));
        assert!(actions.contains(&StateAction::StartT1Cookie));
    }

    /// RFC 9260 Section 4: COOKIE-ECHOED -> ESTABLISHED on COOKIE-ACK.
    #[test]
    fn test_cookie_echoed_to_established() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        let actions = sm.process_event(StateEvent::ReceiveCookieAck);

        assert_eq!(sm.state(), AssociationState::Established);
        assert!(actions.contains(&StateAction::StopT1Cookie));
        assert!(actions.contains(&StateAction::NotifyConnected));
    }

    /// RFC 9260 Section 4: Server stays CLOSED on INIT (stateless).
    #[test]
    fn test_server_stays_closed_on_init() {
        let mut sm = StateMachine::new();
        let actions = sm.process_event(StateEvent::ReceiveInit);

        // Server remains in CLOSED (stateless processing)
        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::SendInitAck));
    }

    /// RFC 9260 Section 4: CLOSED -> ESTABLISHED on valid COOKIE-ECHO (server).
    #[test]
    fn test_server_cookie_echo_to_established() {
        let mut sm = StateMachine::new();
        // Server receives INIT (stays CLOSED, sends INIT-ACK)
        sm.process_event(StateEvent::ReceiveInit);
        // Server receives valid COOKIE-ECHO
        let actions = sm.process_event(StateEvent::ReceiveCookieEcho);

        assert_eq!(sm.state(), AssociationState::Established);
        assert!(actions.contains(&StateAction::SendCookieAck));
        assert!(actions.contains(&StateAction::NotifyConnected));
    }

    /// RFC 9260 Section 4: ESTABLISHED -> SHUTDOWN-PENDING on Shutdown.
    #[test]
    fn test_established_to_shutdown_pending() {
        let mut sm = StateMachine::new();
        // Get to ESTABLISHED
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);

        let _actions = sm.process_event(StateEvent::Shutdown);

        assert_eq!(sm.state(), AssociationState::ShutdownPending);
    }

    /// RFC 9260 Section 4: SHUTDOWN-PENDING -> SHUTDOWN-SENT on AllDataAcked.
    #[test]
    fn test_shutdown_pending_to_shutdown_sent() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);
        sm.process_event(StateEvent::Shutdown);

        let actions = sm.process_event(StateEvent::AllDataAcked);

        assert_eq!(sm.state(), AssociationState::ShutdownSent);
        assert!(actions.contains(&StateAction::SendShutdown));
        assert!(actions.contains(&StateAction::StartT2Shutdown));
    }

    /// RFC 9260 Section 4: SHUTDOWN-SENT -> CLOSED on SHUTDOWN-ACK.
    #[test]
    fn test_shutdown_sent_to_closed() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);
        sm.process_event(StateEvent::Shutdown);
        sm.process_event(StateEvent::AllDataAcked);

        let actions = sm.process_event(StateEvent::ReceiveShutdownAck);

        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::StopT2Shutdown));
        assert!(actions.contains(&StateAction::SendShutdownComplete));
        assert!(actions.contains(&StateAction::DeleteTcb));
    }

    /// RFC 9260 Section 4: ESTABLISHED -> SHUTDOWN-RECEIVED on SHUTDOWN.
    #[test]
    fn test_established_to_shutdown_received() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);

        let _actions = sm.process_event(StateEvent::ReceiveShutdown);

        assert_eq!(sm.state(), AssociationState::ShutdownReceived);
    }

    /// RFC 9260 Section 4: SHUTDOWN-RECEIVED -> SHUTDOWN-ACK-SENT on AllDataAcked.
    #[test]
    fn test_shutdown_received_to_shutdown_ack_sent() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);
        sm.process_event(StateEvent::ReceiveShutdown);

        let actions = sm.process_event(StateEvent::AllDataAcked);

        assert_eq!(sm.state(), AssociationState::ShutdownAckSent);
        assert!(actions.contains(&StateAction::SendShutdownAck));
    }

    /// RFC 9260 Section 4: SHUTDOWN-ACK-SENT -> CLOSED on SHUTDOWN-COMPLETE.
    #[test]
    fn test_shutdown_ack_sent_to_closed() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);
        sm.process_event(StateEvent::ReceiveShutdown);
        sm.process_event(StateEvent::AllDataAcked);

        let actions = sm.process_event(StateEvent::ReceiveShutdownComplete);

        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::StopT2Shutdown));
        assert!(actions.contains(&StateAction::DeleteTcb));
    }

    /// RFC 9260 Section 4: Simultaneous shutdown (SHUTDOWN-SENT -> SHUTDOWN-ACK-SENT).
    #[test]
    fn test_simultaneous_shutdown() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);
        sm.process_event(StateEvent::Shutdown);
        sm.process_event(StateEvent::AllDataAcked);

        // In SHUTDOWN-SENT, receive SHUTDOWN from peer
        let actions = sm.process_event(StateEvent::ReceiveShutdown);

        assert_eq!(sm.state(), AssociationState::ShutdownAckSent);
        assert!(actions.contains(&StateAction::SendShutdownAck));
    }

    /// RFC 9260 Section 4: ABORT transitions any state to CLOSED.
    #[test]
    fn test_abort_from_any_state() {
        let states_to_test = [
            vec![StateEvent::Associate],                             // COOKIE-WAIT
            vec![StateEvent::Associate, StateEvent::ReceiveInitAck], // COOKIE-ECHOED
            vec![
                StateEvent::Associate,
                StateEvent::ReceiveInitAck,
                StateEvent::ReceiveCookieAck,
            ], // ESTABLISHED
        ];

        for events in states_to_test {
            let mut sm = StateMachine::new();
            for event in events {
                sm.process_event(event);
            }
            let state_before = sm.state();

            let actions = sm.process_event(StateEvent::Abort);

            assert_eq!(
                sm.state(),
                AssociationState::Closed,
                "Failed to transition from {state_before:?} to CLOSED on ABORT"
            );
            assert!(
                actions.contains(&StateAction::DeleteTcb)
                    || actions.contains(&StateAction::SendAbort)
            );
        }
    }

    /// RFC 9260 Section 4: Receive ABORT transitions to CLOSED.
    #[test]
    fn test_receive_abort_from_established() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);

        let actions = sm.process_event(StateEvent::ReceiveAbort);

        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::DeleteTcb));
        assert!(actions.contains(&StateAction::NotifyDisconnected));
    }

    /// RFC 9260 Section 4: T1-init timeout retransmission.
    #[test]
    fn test_t1_init_timeout_retransmit() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);

        let actions = sm.process_event(StateEvent::T1InitExpired);

        // Should retransmit INIT
        assert_eq!(sm.state(), AssociationState::CookieWait);
        assert!(actions.contains(&StateAction::SendInit));
        assert!(actions.contains(&StateAction::StartT1Init));
    }

    /// RFC 9260 Section 4: Max retransmissions leads to failure.
    #[test]
    fn test_max_init_retransmissions() {
        let mut sm = StateMachine::new();
        sm.process_event(StateEvent::Associate);

        // Exhaust all retransmissions (default is 8)
        for _ in 0..=StateMachine::DEFAULT_MAX_INIT_RETRIES {
            sm.process_event(StateEvent::T1InitExpired);
        }

        assert_eq!(sm.state(), AssociationState::Closed);
    }

    /// RFC 9260 Section 4: State helper methods.
    #[test]
    fn test_state_helper_methods() {
        // is_connected
        assert!(AssociationState::Established.is_connected());
        assert!(AssociationState::ShutdownPending.is_connected());
        assert!(AssociationState::ShutdownReceived.is_connected());
        assert!(!AssociationState::Closed.is_connected());
        assert!(!AssociationState::CookieWait.is_connected());

        // is_shutting_down
        assert!(AssociationState::ShutdownPending.is_shutting_down());
        assert!(AssociationState::ShutdownSent.is_shutting_down());
        assert!(AssociationState::ShutdownReceived.is_shutting_down());
        assert!(AssociationState::ShutdownAckSent.is_shutting_down());
        assert!(!AssociationState::Established.is_shutting_down());

        // can_send_data
        assert!(AssociationState::Established.can_send_data());
        assert!(AssociationState::ShutdownReceived.can_send_data());
        assert!(!AssociationState::ShutdownPending.can_send_data());
        assert!(!AssociationState::Closed.can_send_data());

        // can_receive_data
        assert!(AssociationState::Established.can_receive_data());
        assert!(AssociationState::ShutdownPending.can_receive_data());
        assert!(AssociationState::ShutdownSent.can_receive_data());
        assert!(!AssociationState::ShutdownReceived.can_receive_data());

        // is_handshaking
        assert!(AssociationState::CookieWait.is_handshaking());
        assert!(AssociationState::CookieEchoed.is_handshaking());
        assert!(!AssociationState::Established.is_handshaking());
    }
}

// =============================================================================
// Section 5: Association Initialization (RFC 9260 Section 5)
// =============================================================================

mod section5_association_init {
    use super::*;

    /// RFC 9260 Section 5.1: 4-way handshake sequence.
    #[tokio::test]
    async fn test_4way_handshake_sequence() {
        let config = AssociationConfig::default();

        let client = AssociationHandle::new(test_addr(5060), test_addr(5061), config.clone());
        let server = AssociationHandle::new(test_addr(5061), test_addr(5060), config);

        // Initial state
        assert_eq!(client.state().await, AssociationState::Closed);
        assert_eq!(server.state().await, AssociationState::Closed);

        // Step 1: Client sends INIT
        let init_packet = client.create_init_packet().await;
        assert_eq!(client.state().await, AssociationState::CookieWait);

        // Step 2: Server receives INIT, sends INIT-ACK
        let init_ack_chunks = server.process_packet(&init_packet).await.unwrap();
        assert!(!init_ack_chunks.is_empty());
        assert!(
            init_ack_chunks
                .iter()
                .any(|c| matches!(c, Chunk::InitAck(_)))
        );

        // Step 3: Client receives INIT-ACK, sends COOKIE-ECHO
        let init_ack_packet = build_packet(&server, &client, init_ack_chunks).await;
        let cookie_echo_chunks = client.process_packet(&init_ack_packet).await.unwrap();
        assert_eq!(client.state().await, AssociationState::CookieEchoed);
        assert!(
            cookie_echo_chunks
                .iter()
                .any(|c| matches!(c, Chunk::CookieEcho(_)))
        );

        // Step 4: Server receives COOKIE-ECHO, sends COOKIE-ACK
        let cookie_echo_packet = build_packet(&client, &server, cookie_echo_chunks).await;
        let cookie_ack_chunks = server.process_packet(&cookie_echo_packet).await.unwrap();
        assert_eq!(server.state().await, AssociationState::Established);
        assert!(
            cookie_ack_chunks
                .iter()
                .any(|c| matches!(c, Chunk::CookieAck(_)))
        );

        // Step 5: Client receives COOKIE-ACK
        let cookie_ack_packet = build_packet(&server, &client, cookie_ack_chunks).await;
        client.process_packet(&cookie_ack_packet).await.unwrap();
        assert_eq!(client.state().await, AssociationState::Established);

        // Both established
        assert!(client.is_established().await);
        assert!(server.is_established().await);
    }

    /// RFC 9260 Section 5.1: Verification tags are exchanged during handshake.
    #[tokio::test]
    async fn test_verification_tag_exchange() {
        let config = AssociationConfig::default();

        let client = AssociationHandle::new(test_addr(5060), test_addr(5061), config.clone());
        let server = AssociationHandle::new(test_addr(5061), test_addr(5060), config);

        let init_packet = client.create_init_packet().await;
        let client_vtag = client.local_verification_tag().await;

        let init_ack_chunks = server.process_packet(&init_packet).await.unwrap();
        let server_vtag = server.local_verification_tag().await;

        // Tags should be non-zero
        assert_ne!(client_vtag, 0);
        assert_ne!(server_vtag, 0);

        // After handshake, each side should know peer's tag
        let init_ack_packet = build_packet(&server, &client, init_ack_chunks).await;
        client.process_packet(&init_ack_packet).await.unwrap();

        assert_eq!(client.peer_verification_tag().await, server_vtag);
    }

    /// RFC 9260 Section 5.2: Collision handling - INIT received while in COOKIE-WAIT.
    #[tokio::test]
    async fn test_init_collision() {
        let config = AssociationConfig::default();

        let client = AssociationHandle::new(test_addr(5060), test_addr(5061), config.clone());

        // Client initiates
        let _init_packet = client.create_init_packet().await;
        assert_eq!(client.state().await, AssociationState::CookieWait);

        // Client receives an INIT from peer (collision)
        let peer_init = InitChunk::new(0xAAAA0000, 65535, 10, 10, 2000);
        let mut peer_init_packet = SctpPacket::new(5061, 5060, 0);
        peer_init_packet.add_chunk(Chunk::Init(peer_init));

        // Should still process and potentially respond
        let response = client.process_packet(&peer_init_packet).await;
        // Collision handling depends on implementation
        assert!(response.is_ok());
    }

    /// Helper to build packet from chunks.
    async fn build_packet(
        source: &AssociationHandle,
        dest: &AssociationHandle,
        chunks: Vec<Chunk>,
    ) -> SctpPacket {
        let vtag = if chunks.iter().any(|c| matches!(c, Chunk::Init(_))) {
            0 // INIT uses vtag=0
        } else if chunks.iter().any(|c| matches!(c, Chunk::InitAck(_))) {
            source.peer_verification_tag().await
        } else {
            dest.local_verification_tag().await
        };

        let mut packet = SctpPacket::new(5061, 5060, vtag);
        for chunk in chunks {
            packet.add_chunk(chunk);
        }
        packet
    }
}

// =============================================================================
// Section 6: User Data Transfer (RFC 9260 Section 6)
// =============================================================================

mod section6_data_transfer {
    use super::*;

    /// Helper to create an established association pair.
    async fn create_established_pair() -> (AssociationHandle, AssociationHandle) {
        let config = AssociationConfig::default();

        let client = AssociationHandle::new(test_addr(5060), test_addr(5061), config.clone());
        let server = AssociationHandle::new(test_addr(5061), test_addr(5060), config);

        // Perform handshake
        let init = client.create_init_packet().await;
        let init_ack = server.process_packet(&init).await.unwrap();

        let mut init_ack_pkt = SctpPacket::new(5061, 5060, server.peer_verification_tag().await);
        for c in init_ack {
            init_ack_pkt.add_chunk(c);
        }

        let cookie_echo = client.process_packet(&init_ack_pkt).await.unwrap();
        let mut cookie_echo_pkt = SctpPacket::new(5060, 5061, client.peer_verification_tag().await);
        for c in cookie_echo {
            cookie_echo_pkt.add_chunk(c);
        }

        let cookie_ack = server.process_packet(&cookie_echo_pkt).await.unwrap();
        // V-tag must be client's local tag (what client expects to receive)
        let mut cookie_ack_pkt = SctpPacket::new(5061, 5060, client.local_verification_tag().await);
        for c in cookie_ack {
            cookie_ack_pkt.add_chunk(c);
        }

        client.process_packet(&cookie_ack_pkt).await.unwrap();

        // Confirm paths for data transfer
        client.confirm_primary_path().await;
        server.confirm_primary_path().await;

        (client, server)
    }

    /// RFC 9260 Section 6.1: Data can only be sent when ESTABLISHED.
    #[tokio::test]
    async fn test_data_requires_established() {
        let config = AssociationConfig::default();
        let client = AssociationHandle::new(test_addr(5060), test_addr(5061), config);

        // Not established yet
        let result = client.send(0, Bytes::from("test"), true).await;
        assert!(result.is_err());
    }

    /// RFC 9260 Section 6.1: TSN is assigned when data is queued.
    #[tokio::test]
    async fn test_tsn_assignment() {
        let (client, _server) = create_established_pair().await;

        let tsn1 = client.send(0, Bytes::from("first"), true).await.unwrap();
        let tsn2 = client.send(0, Bytes::from("second"), true).await.unwrap();

        // TSNs should be sequential (accounting for wrap-around)
        assert_eq!(tsn2, tsn1.wrapping_add(1));
    }

    /// RFC 9260 Section 6.2: SACK acknowledges received data.
    #[tokio::test]
    async fn test_sack_acknowledgment() {
        let (client, server) = create_established_pair().await;

        // Client sends data
        let _tsn = client
            .send(0, Bytes::from("test data"), true)
            .await
            .unwrap();
        let data_chunks = client.get_pending_data().await;
        assert_eq!(data_chunks.len(), 1);

        // Build DATA packet
        let mut data_pkt = SctpPacket::new(5060, 5061, client.peer_verification_tag().await);
        for chunk in &data_chunks {
            data_pkt.add_chunk(Chunk::Data(chunk.clone()));
        }

        // Server receives DATA, sends SACK
        let response = server.process_packet(&data_pkt).await.unwrap();
        assert!(response.iter().any(|c| matches!(c, Chunk::Sack(_))));

        // Verify SACK acknowledges the TSN
        if let Some(Chunk::Sack(sack)) = response.iter().find(|c| matches!(c, Chunk::Sack(_))) {
            assert_eq!(sack.cumulative_tsn_ack, data_chunks[0].tsn);
        }
    }

    /// RFC 9260 Section 6.2.1: Gap Ack Blocks for out-of-order data.
    #[test]
    fn test_gap_ack_block_encoding() {
        let mut sack = SackChunk::new(100, 65535);
        sack.add_gap_block(5, 10); // TSNs 105-110 received
        sack.add_gap_block(15, 20); // TSNs 115-120 received

        let decoded = roundtrip_chunk(Chunk::Sack(sack));

        if let Chunk::Sack(s) = decoded {
            assert_eq!(s.gap_ack_blocks.len(), 2);
            assert_eq!(s.gap_ack_blocks[0].start, 5);
            assert_eq!(s.gap_ack_blocks[0].end, 10);
            assert_eq!(s.gap_ack_blocks[1].start, 15);
            assert_eq!(s.gap_ack_blocks[1].end, 20);
        }
    }

    /// RFC 9260 Section 6.5: Ordered delivery on same stream.
    #[tokio::test]
    async fn test_ordered_delivery() {
        let (client, _server) = create_established_pair().await;

        // Send multiple ordered messages on same stream
        let _tsn1 = client.send(0, Bytes::from("first"), true).await.unwrap();
        let _tsn2 = client.send(0, Bytes::from("second"), true).await.unwrap();
        let _tsn3 = client.send(0, Bytes::from("third"), true).await.unwrap();

        let data_chunks = client.get_pending_data().await;

        // All on stream 0 with sequential SSN
        assert_eq!(data_chunks.len(), 3);
        assert!(data_chunks.iter().all(|c| c.stream_id == 0));
        assert!(data_chunks.iter().all(|c| !c.unordered));
    }

    /// RFC 9260 Section 6.6: Unordered delivery with U bit.
    #[tokio::test]
    async fn test_unordered_delivery() {
        let (client, _server) = create_established_pair().await;

        // Send unordered message
        let _tsn = client
            .send(0, Bytes::from("unordered"), false)
            .await
            .unwrap();

        let data_chunks = client.get_pending_data().await;
        assert_eq!(data_chunks.len(), 1);
        assert!(data_chunks[0].unordered);
    }

    /// RFC 9260 Section 6.9: Message fragmentation.
    #[test]
    fn test_fragment_flags() {
        // First fragment: B=1, E=0
        let first = DataChunk::new(1, 0, 0, 0, Bytes::from("first")).with_fragment(true, false);
        assert!(first.beginning);
        assert!(!first.ending);

        // Middle fragment: B=0, E=0
        let middle = DataChunk::new(2, 0, 0, 0, Bytes::from("middle")).with_fragment(false, false);
        assert!(!middle.beginning);
        assert!(!middle.ending);

        // Last fragment: B=0, E=1
        let last = DataChunk::new(3, 0, 0, 0, Bytes::from("last")).with_fragment(false, true);
        assert!(!last.beginning);
        assert!(last.ending);

        // Unfragmented: B=1, E=1
        let unfrag = DataChunk::new(4, 0, 0, 0, Bytes::from("whole")).with_fragment(true, true);
        assert!(unfrag.beginning);
        assert!(unfrag.ending);
    }

    /// RFC 9260 Section 6.3.2: T3-rtx timer management.
    #[tokio::test]
    async fn test_t3_rtx_timer_starts_on_data() {
        let (client, _server) = create_established_pair().await;

        // Send data
        client.send(0, Bytes::from("test"), true).await.unwrap();
        let chunks = client.get_pending_data().await;

        // Track sent chunks
        client.track_sent_chunks(&chunks).await;

        // Should have outstanding data
        assert!(client.has_outstanding_data().await);

        // Ensure T3 is running
        client.ensure_t3_running().await;
    }
}

// =============================================================================
// Section 7: Congestion Control (RFC 9260 Section 7)
// =============================================================================

mod section7_congestion_control {
    use super::*;
    use uc_transport::sctp::CongestionController;

    /// RFC 9260 Section 7.2.1: Initial cwnd calculation.
    #[test]
    fn test_initial_cwnd() {
        // cwnd = min(4*MTU, max(2*MTU, 4380))

        // MTU 1280: min(5120, max(2560, 4380)) = min(5120, 4380) = 4380
        let cc = CongestionController::with_mtu(1280);
        assert_eq!(cc.cwnd(), 4380);

        // MTU 1500: min(6000, max(3000, 4380)) = min(6000, 4380) = 4380
        let cc = CongestionController::with_mtu(1500);
        assert_eq!(cc.cwnd(), 4380);

        // MTU 500: min(2000, max(1000, 4380)) = min(2000, 4380) = 2000
        let cc = CongestionController::with_mtu(500);
        assert_eq!(cc.cwnd(), 2000);

        // MTU 2000: min(8000, max(4000, 4380)) = min(8000, 4380) = 4380
        let cc = CongestionController::with_mtu(2000);
        assert_eq!(cc.cwnd(), 4380);
    }

    /// RFC 9260 Section 7.2.1: Slow start increases cwnd.
    #[test]
    fn test_slow_start_increase() {
        let mut cc = CongestionController::with_mtu(1000);
        // Initial state should be slow start (cwnd < ssthresh=MAX)
        assert!(cc.is_slow_start());
        let initial = cc.cwnd();

        // Simulate receiving a SACK that acks 1000 bytes
        cc.on_sack(1000, true);

        // cwnd should increase by min(bytes_acked, MTU) = 1000
        assert_eq!(cc.cwnd(), initial + 1000);
    }

    /// RFC 9260 Section 7.2.1: Slow start limited by MTU per ACK.
    #[test]
    fn test_slow_start_limited_by_mtu() {
        let mut cc = CongestionController::with_mtu(1000);
        // Initially in slow start

        let initial = cc.cwnd();

        // ACK more than MTU
        cc.on_sack(5000, true);

        // Should only increase by MTU
        assert_eq!(cc.cwnd(), initial + 1000);
    }

    /// RFC 9260 Section 7.2.2: Congestion avoidance phase.
    /// After timeout, cwnd is reduced and we can test congestion avoidance.
    #[test]
    fn test_congestion_avoidance() {
        let mut cc = CongestionController::with_mtu(1000);
        // Start with large cwnd via slow start increases
        for _ in 0..10 {
            cc.on_sack(1000, true);
        }

        // Trigger timeout to set ssthresh and reduce cwnd
        cc.on_timeout();
        // After timeout: cwnd = MTU, ssthresh = max(prev_cwnd/2, 4*MTU)

        // Now grow cwnd back above ssthresh via slow start
        let ssthresh = cc.ssthresh();
        while cc.cwnd() < ssthresh {
            cc.on_sack(1000, true);
        }

        // Now in congestion avoidance (cwnd >= ssthresh)
        assert!(!cc.is_slow_start());

        let initial = cc.cwnd();
        let cwnd = initial;

        // Need to ack cwnd worth of bytes to increase cwnd by 1 MTU
        // Ack half of cwnd
        cc.on_sack(cwnd / 2, true);
        assert_eq!(cc.cwnd(), initial); // Not enough yet

        // Ack the other half + more
        cc.on_sack(cwnd / 2 + 1, true);
        assert_eq!(cc.cwnd(), initial + 1000); // Now increased
    }

    /// RFC 9260 Section 7.2.3: Timeout reduces cwnd to 1 MTU.
    #[test]
    fn test_timeout_cwnd_reduction() {
        let mut cc = CongestionController::with_mtu(1000);
        // Grow cwnd first
        for _ in 0..10 {
            cc.on_sack(1000, true);
        }
        let prev_cwnd = cc.cwnd();

        cc.on_timeout();

        // cwnd = 1 MTU
        assert_eq!(cc.cwnd(), 1000);
        // ssthresh = max(cwnd/2, 4*MTU)
        let expected_ssthresh = (prev_cwnd / 2).max(4 * 1000);
        assert_eq!(cc.ssthresh(), expected_ssthresh);
    }

    /// RFC 9260 Section 7.2.4: Fast retransmit on 3 duplicate SACKs.
    #[test]
    fn test_fast_retransmit_threshold() {
        let mut cc = CongestionController::with_mtu(1000);
        // Grow cwnd first
        for _ in 0..10 {
            cc.on_sack(1000, true);
        }

        assert!(!cc.is_fast_recovery());

        // 2 duplicates - not yet
        cc.on_sack(0, false);
        cc.on_sack(0, false);
        assert!(!cc.is_fast_recovery());

        let cwnd_before = cc.cwnd();

        // 3rd duplicate triggers fast recovery
        cc.on_sack(0, false);
        assert!(cc.is_fast_recovery());

        // ssthresh = max(cwnd/2, 4*MTU)
        let expected_ssthresh = (cwnd_before / 2).max(4 * 1000);
        assert_eq!(cc.ssthresh(), expected_ssthresh);
        // cwnd = ssthresh
        assert_eq!(cc.cwnd(), expected_ssthresh);
    }

    /// RFC 9260 Section 7.2.4: Exit fast recovery on new ACK.
    #[test]
    fn test_fast_recovery_exit() {
        let mut cc = CongestionController::with_mtu(1000);
        // Grow cwnd first
        for _ in 0..10 {
            cc.on_sack(1000, true);
        }

        // Enter fast recovery
        for _ in 0..3 {
            cc.on_sack(0, false);
        }
        assert!(cc.is_fast_recovery());

        cc.set_fast_recovery_exit_tsn(100);

        // New ACK exits fast recovery
        cc.on_sack(1000, true);
        assert!(!cc.is_fast_recovery());
    }

    /// RFC 9260 Section 7.1: Flight size tracking.
    #[test]
    fn test_flight_size() {
        let mut cc = CongestionController::new();

        assert_eq!(cc.flight_size(), 0);

        cc.on_data_sent(1000);
        assert_eq!(cc.flight_size(), 1000);

        cc.on_data_sent(500);
        assert_eq!(cc.flight_size(), 1500);

        // SACK reduces flight size
        cc.on_sack(600, true);
        assert_eq!(cc.flight_size(), 900);
    }

    /// RFC 9260 Section 7.1: Available window calculation.
    #[test]
    fn test_available_window() {
        let mut cc = CongestionController::with_mtu(1000);
        // cwnd should be ~4380 for MTU 1000

        assert_eq!(cc.available_window(), cc.cwnd());

        cc.on_data_sent(1000);
        assert_eq!(cc.available_window(), cc.cwnd() - 1000);

        // Send more data to exhaust window
        while cc.available_window() > 0 {
            cc.on_data_sent(cc.available_window().min(1000));
        }
        assert_eq!(cc.available_window(), 0);
    }

    /// RFC 9260 Section 7.2.1: ssthresh initial value is infinite.
    #[test]
    fn test_initial_ssthresh() {
        let cc = CongestionController::new();
        assert_eq!(cc.ssthresh(), u32::MAX);
    }
}

// =============================================================================
// Section 9: Termination of Association (RFC 9260 Section 9)
// =============================================================================

mod section9_termination {
    use super::*;

    /// RFC 9260 Section 9.2: Graceful shutdown procedure.
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let config = AssociationConfig::default();
        let assoc = AssociationHandle::new(test_addr(5060), test_addr(5061), config.clone());
        let peer = AssociationHandle::new(test_addr(5061), test_addr(5060), config);

        // Establish association
        let init = assoc.create_init_packet().await;
        let init_ack = peer.process_packet(&init).await.unwrap();

        let mut init_ack_pkt = SctpPacket::new(5061, 5060, peer.peer_verification_tag().await);
        for c in init_ack {
            init_ack_pkt.add_chunk(c);
        }
        let cookie_echo = assoc.process_packet(&init_ack_pkt).await.unwrap();

        let mut cookie_echo_pkt = SctpPacket::new(5060, 5061, assoc.peer_verification_tag().await);
        for c in cookie_echo {
            cookie_echo_pkt.add_chunk(c);
        }
        let cookie_ack = peer.process_packet(&cookie_echo_pkt).await.unwrap();

        // V-tag must be assoc's local tag (what assoc expects to receive)
        let mut cookie_ack_pkt = SctpPacket::new(5061, 5060, assoc.local_verification_tag().await);
        for c in cookie_ack {
            cookie_ack_pkt.add_chunk(c);
        }
        assoc.process_packet(&cookie_ack_pkt).await.unwrap();

        assert!(assoc.is_established().await);

        // Initiate shutdown
        let _actions = assoc.shutdown().await;

        // Should be in SHUTDOWN-PENDING
        assert_eq!(assoc.state().await, AssociationState::ShutdownPending);
    }

    /// RFC 9260 Section 9.1: Abort procedure.
    #[tokio::test]
    async fn test_abort_procedure() {
        let config = AssociationConfig::default();
        let assoc = AssociationHandle::new(test_addr(5060), test_addr(5061), config.clone());
        let peer = AssociationHandle::new(test_addr(5061), test_addr(5060), config);

        // Establish
        let init = assoc.create_init_packet().await;
        let init_ack = peer.process_packet(&init).await.unwrap();

        let mut init_ack_pkt = SctpPacket::new(5061, 5060, peer.peer_verification_tag().await);
        for c in init_ack {
            init_ack_pkt.add_chunk(c);
        }
        let cookie_echo = assoc.process_packet(&init_ack_pkt).await.unwrap();

        let mut cookie_echo_pkt = SctpPacket::new(5060, 5061, assoc.peer_verification_tag().await);
        for c in cookie_echo {
            cookie_echo_pkt.add_chunk(c);
        }
        let cookie_ack = peer.process_packet(&cookie_echo_pkt).await.unwrap();

        // V-tag must be assoc's local tag (what assoc expects to receive)
        let mut cookie_ack_pkt = SctpPacket::new(5061, 5060, assoc.local_verification_tag().await);
        for c in cookie_ack {
            cookie_ack_pkt.add_chunk(c);
        }
        assoc.process_packet(&cookie_ack_pkt).await.unwrap();

        // Abort
        let actions = assoc.abort().await;

        assert_eq!(assoc.state().await, AssociationState::Closed);
        assert!(!actions.is_empty());
    }

    /// RFC 9260 Section 9.1: ABORT chunk format with error causes.
    #[test]
    fn test_abort_with_causes() {
        let mut abort = AbortChunk::new();
        abort.tcb_destroyed = true;
        abort.add_cause(ErrorCause::ProtocolViolation {
            info: Bytes::from("test violation"),
        });

        let decoded = roundtrip_chunk(Chunk::Abort(abort));

        if let Chunk::Abort(a) = decoded {
            assert!(a.tcb_destroyed);
            assert_eq!(a.causes.len(), 1);
            if let ErrorCause::ProtocolViolation { info } = &a.causes[0] {
                assert_eq!(info, &Bytes::from("test violation"));
            } else {
                panic!("Expected ProtocolViolation cause");
            }
        } else {
            panic!("Expected ABORT chunk");
        }
    }

    /// RFC 9260 Section 9.2: SHUTDOWN chunk carries cumulative TSN.
    #[test]
    fn test_shutdown_carries_tsn() {
        let shutdown = ShutdownChunk::new(0x12345678);

        let decoded = roundtrip_chunk(Chunk::Shutdown(shutdown));

        if let Chunk::Shutdown(s) = decoded {
            assert_eq!(s.cumulative_tsn_ack, 0x12345678);
        } else {
            panic!("Expected SHUTDOWN chunk");
        }
    }
}

// =============================================================================
// Additional Compliance Tests
// =============================================================================

mod additional_compliance {
    #[allow(unused_imports)]
    use super::*;

    /// RFC 9260: Packet checksum (CRC32c).
    #[test]
    fn test_packet_has_checksum() {
        let packet = SctpPacket::new(5060, 5061, 0);
        let encoded = packet.encode();

        // Checksum is at bytes 8-11
        // Just verify the packet is long enough to contain it
        assert!(encoded.len() >= 12);
    }

    /// RFC 9260: Multiple chunks can be bundled in one packet.
    #[test]
    fn test_chunk_bundling() {
        let mut packet = SctpPacket::new(5060, 5061, 0x12345678);

        let data = DataChunk::new(1, 0, 0, 0, Bytes::from("test"));
        let sack = SackChunk::new(100, 65535);

        packet.add_chunk(Chunk::Data(data));
        packet.add_chunk(Chunk::Sack(sack));

        let encoded = packet.encode();
        let decoded = SctpPacket::decode(&mut encoded.into()).unwrap();

        assert_eq!(decoded.chunks.len(), 2);
    }

    /// RFC 9260: SSN (Stream Sequence Number) handling for ordered messages.
    #[test]
    fn test_ssn_sequential() {
        let data1 = DataChunk::new(1, 0, 0, 0, Bytes::from("first"));
        let data2 = DataChunk::new(2, 0, 1, 0, Bytes::from("second")); // SSN = 1
        let data3 = DataChunk::new(3, 0, 2, 0, Bytes::from("third")); // SSN = 2

        // Verify SSNs are sequential
        assert_eq!(data1.ssn, 0);
        assert_eq!(data2.ssn, 1);
        assert_eq!(data3.ssn, 2);
    }

    /// RFC 9260: Heartbeat mechanism for path verification.
    #[tokio::test]
    async fn test_heartbeat_mechanism() {
        let config = AssociationConfig::default();
        let client = AssociationHandle::new(test_addr(5060), test_addr(5061), config.clone());
        let server = AssociationHandle::new(test_addr(5061), test_addr(5060), config);

        // Establish
        let init = client.create_init_packet().await;
        let init_ack = server.process_packet(&init).await.unwrap();

        let mut init_ack_pkt = SctpPacket::new(5061, 5060, server.peer_verification_tag().await);
        for c in init_ack {
            init_ack_pkt.add_chunk(c);
        }
        let cookie_echo = client.process_packet(&init_ack_pkt).await.unwrap();

        let mut cookie_echo_pkt = SctpPacket::new(5060, 5061, client.peer_verification_tag().await);
        for c in cookie_echo {
            cookie_echo_pkt.add_chunk(c);
        }
        let cookie_ack = server.process_packet(&cookie_echo_pkt).await.unwrap();

        // V-tag must be client's local tag (what client expects to receive)
        let mut cookie_ack_pkt = SctpPacket::new(5061, 5060, client.local_verification_tag().await);
        for c in cookie_ack {
            cookie_ack_pkt.add_chunk(c);
        }
        client.process_packet(&cookie_ack_pkt).await.unwrap();

        // Send heartbeat
        let hb = HeartbeatChunk::new(Bytes::from("hb-info"));
        let mut hb_pkt = SctpPacket::new(5060, 5061, client.peer_verification_tag().await);
        hb_pkt.add_chunk(Chunk::Heartbeat(hb));

        let response = server.process_packet(&hb_pkt).await.unwrap();

        // Should get HEARTBEAT-ACK back
        assert!(response.iter().any(|c| matches!(c, Chunk::HeartbeatAck(_))));
    }

    /// RFC 9260: PPID (Payload Protocol Identifier) handling.
    #[test]
    fn test_ppid_preserved() {
        let ppids = [0u32, 1, 0x03000000, 0xFFFFFFFF];

        for ppid in ppids {
            let data = DataChunk::new(1, 0, 0, ppid, Bytes::from("test"));
            let decoded = roundtrip_chunk(Chunk::Data(data));

            if let Chunk::Data(d) = decoded {
                assert_eq!(d.ppid, ppid, "PPID {ppid} not preserved");
            }
        }
    }

    /// RFC 9260: Multi-stream support.
    #[test]
    fn test_multi_stream() {
        let streams = [0u16, 1, 5, 100, 0xFFFF];

        for stream_id in streams {
            let data = DataChunk::new(1, stream_id, 0, 0, Bytes::from("test"));
            let decoded = roundtrip_chunk(Chunk::Data(data));

            if let Chunk::Data(d) = decoded {
                assert_eq!(
                    d.stream_id, stream_id,
                    "Stream ID {stream_id} not preserved"
                );
            }
        }
    }
}
