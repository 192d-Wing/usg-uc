//! SCTP packet encoding and decoding (RFC 9260 Section 3).
//!
//! This module implements the SCTP common header and packet structure.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32c::crc32c;

use super::chunk::Chunk;
use crate::error::{TransportError, TransportResult};

/// SCTP common header size.
pub const HEADER_SIZE: usize = 12;

/// Maximum SCTP packet size (limited by UDP encapsulation).
pub const MAX_PACKET_SIZE: usize = 65535;

// =============================================================================
// SCTP Packet
// =============================================================================

/// SCTP Packet structure (RFC 9260 Section 3).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Source Port Number        |     Destination Port Number   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Verification Tag                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Checksum                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                            Chunks                             /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SctpPacket {
    /// Source port number.
    pub source_port: u16,
    /// Destination port number.
    pub dest_port: u16,
    /// Verification tag for association identification.
    pub verification_tag: u32,
    /// SCTP chunks.
    pub chunks: Vec<Chunk>,
}

impl SctpPacket {
    /// Creates a new SCTP packet.
    #[must_use]
    pub fn new(source_port: u16, dest_port: u16, verification_tag: u32) -> Self {
        Self {
            source_port,
            dest_port,
            verification_tag,
            chunks: Vec::new(),
        }
    }

    /// Adds a chunk to the packet.
    pub fn add_chunk(&mut self, chunk: Chunk) {
        self.chunks.push(chunk);
    }

    /// Returns the number of chunks.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Checks if the packet is empty (no chunks).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Encodes the packet to bytes.
    ///
    /// The checksum is calculated over the entire packet with the checksum
    /// field set to zero, then inserted into the appropriate position.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(1500);

        // Write header with zero checksum
        buf.put_u16(self.source_port);
        buf.put_u16(self.dest_port);
        buf.put_u32(self.verification_tag);
        buf.put_u32(0); // Checksum placeholder

        // Write chunks
        for chunk in &self.chunks {
            chunk.encode(&mut buf);
        }

        // Calculate CRC32c checksum
        let checksum = crc32c(&buf);

        // Insert checksum at offset 8
        let checksum_bytes = checksum.to_le_bytes();
        buf[8] = checksum_bytes[0];
        buf[9] = checksum_bytes[1];
        buf[10] = checksum_bytes[2];
        buf[11] = checksum_bytes[3];

        buf
    }

    /// Decodes a packet from bytes.
    ///
    /// Verifies the CRC32c checksum before parsing chunks.
    pub fn decode(data: &[u8]) -> TransportResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: format!(
                    "Packet too short: {} bytes (minimum {})",
                    data.len(),
                    HEADER_SIZE
                ),
            });
        }

        // Verify checksum
        let received_checksum = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        // Calculate checksum with checksum field zeroed
        let mut verify_data = data.to_vec();
        verify_data[8] = 0;
        verify_data[9] = 0;
        verify_data[10] = 0;
        verify_data[11] = 0;
        let calculated_checksum = crc32c(&verify_data);

        if received_checksum != calculated_checksum {
            return Err(TransportError::ReceiveFailed {
                reason: format!(
                    "Checksum mismatch: received 0x{:08x}, calculated 0x{:08x}",
                    received_checksum, calculated_checksum
                ),
            });
        }

        // Parse header
        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let dest_port = u16::from_be_bytes([data[2], data[3]]);
        let verification_tag = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Parse chunks
        let mut chunks = Vec::new();
        let mut chunk_data = Bytes::copy_from_slice(&data[HEADER_SIZE..]);

        while chunk_data.has_remaining() {
            match Chunk::decode(&mut chunk_data) {
                Ok(chunk) => chunks.push(chunk),
                Err(e) => {
                    // Log partial parse and return what we have
                    tracing::warn!("Error parsing chunk: {e}");
                    break;
                }
            }
        }

        Ok(Self {
            source_port,
            dest_port,
            verification_tag,
            chunks,
        })
    }

    /// Validates that chunks can be bundled together.
    ///
    /// Per RFC 9260 Section 6.10:
    /// - INIT, INIT ACK, and SHUTDOWN COMPLETE MUST NOT be bundled.
    ///
    /// Returns the chunk type that cannot be bundled, or None if valid.
    pub fn validate_bundling(&self) -> Option<super::chunk::ChunkType> {
        for chunk in &self.chunks {
            if chunk.chunk_type().must_not_bundle() && self.chunks.len() > 1 {
                return Some(chunk.chunk_type());
            }
        }
        None
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sctp::chunk::{DataChunk, InitChunk, SackChunk};

    #[test]
    fn test_empty_packet_roundtrip() {
        let packet = SctpPacket::new(5060, 5061, 0x12345678);

        let encoded = packet.encode();
        let decoded = SctpPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.source_port, 5060);
        assert_eq!(decoded.dest_port, 5061);
        assert_eq!(decoded.verification_tag, 0x12345678);
        assert!(decoded.chunks.is_empty());
    }

    #[test]
    fn test_data_packet_roundtrip() {
        let mut packet = SctpPacket::new(5060, 5061, 0xABCDEF00);
        packet.add_chunk(Chunk::Data(DataChunk::new(
            1,
            0,
            1,
            0,
            Bytes::from("Hello"),
        )));

        let encoded = packet.encode();
        let decoded = SctpPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.source_port, 5060);
        assert_eq!(decoded.dest_port, 5061);
        assert_eq!(decoded.verification_tag, 0xABCDEF00);
        assert_eq!(decoded.chunks.len(), 1);
    }

    #[test]
    fn test_multiple_chunks_roundtrip() {
        let mut packet = SctpPacket::new(5060, 5061, 0x11223344);

        // Add multiple DATA chunks
        packet.add_chunk(Chunk::Data(DataChunk::new(1, 0, 1, 0, Bytes::from("First"))));
        packet.add_chunk(Chunk::Data(DataChunk::new(2, 0, 2, 0, Bytes::from("Second"))));

        // Add a SACK chunk
        packet.add_chunk(Chunk::Sack(SackChunk::new(100, 65535)));

        let encoded = packet.encode();
        let decoded = SctpPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.chunks.len(), 3);
    }

    #[test]
    fn test_checksum_verification() {
        let packet = SctpPacket::new(5060, 5061, 0x12345678);
        let mut encoded = packet.encode();

        // Corrupt the checksum
        encoded[8] ^= 0xFF;

        let result = SctpPacket::decode(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Checksum mismatch"));
    }

    #[test]
    fn test_packet_too_short() {
        let short_data = vec![0u8; 8];
        let result = SctpPacket::decode(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_bundling_validation() {
        // Normal bundling should pass
        let mut packet = SctpPacket::new(5060, 5061, 0);
        packet.add_chunk(Chunk::Data(DataChunk::new(1, 0, 1, 0, Bytes::new())));
        packet.add_chunk(Chunk::Sack(SackChunk::new(0, 65535)));
        assert!(packet.validate_bundling().is_none());

        // INIT with other chunks should fail
        let mut packet = SctpPacket::new(5060, 5061, 0);
        packet.add_chunk(Chunk::Init(InitChunk::new(1, 65535, 10, 10, 1)));
        packet.add_chunk(Chunk::Data(DataChunk::new(1, 0, 1, 0, Bytes::new())));
        assert!(packet.validate_bundling().is_some());

        // Lone INIT should pass
        let mut packet = SctpPacket::new(5060, 5061, 0);
        packet.add_chunk(Chunk::Init(InitChunk::new(1, 65535, 10, 10, 1)));
        assert!(packet.validate_bundling().is_none());
    }

    #[test]
    fn test_crc32c_known_value() {
        // Test CRC32c with known value
        let data = b"Hello, SCTP!";
        let checksum = crc32c(data);
        // CRC32c of "Hello, SCTP!" should be consistent
        assert_ne!(checksum, 0);
    }
}
