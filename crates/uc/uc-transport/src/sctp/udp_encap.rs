//! SCTP UDP encapsulation (RFC 6951).
//!
//! This module implements UDP encapsulation for SCTP to enable NAT traversal.
//! SCTP packets are encapsulated within UDP datagrams for transport through
//! NAT devices that don't understand native SCTP.
//!
//! ## Format
//!
//! ```text
//! UDP Header (8 bytes) | SCTP Common Header (12 bytes) | SCTP Chunks
//! ```
//!
//! ## Default Ports
//!
//! - IANA registered port for SCTP/UDP: 9899
//! - Can use any port for NAT traversal purposes

use super::packet::SctpPacket;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;

// =============================================================================
// Constants
// =============================================================================

/// IANA registered port for SCTP over UDP (RFC 6951).
pub const SCTP_UDP_PORT: u16 = 9899;

/// UDP header size in bytes.
pub const UDP_HEADER_SIZE: usize = 8;

/// Minimum SCTP packet size (common header only).
pub const MIN_SCTP_PACKET_SIZE: usize = super::packet::HEADER_SIZE;

/// Minimum encapsulated packet size.
pub const MIN_ENCAP_SIZE: usize = UDP_HEADER_SIZE + MIN_SCTP_PACKET_SIZE;

// =============================================================================
// UDP Encapsulation Configuration
// =============================================================================

/// Configuration for UDP encapsulation.
#[derive(Debug, Clone)]
pub struct UdpEncapConfig {
    /// Local UDP port for encapsulation.
    pub local_port: u16,
    /// Remote UDP port for encapsulation.
    pub remote_port: u16,
    /// Whether to use checksum covering the UDP pseudo-header.
    pub enable_checksum: bool,
}

impl Default for UdpEncapConfig {
    fn default() -> Self {
        Self {
            local_port: SCTP_UDP_PORT,
            remote_port: SCTP_UDP_PORT,
            enable_checksum: true,
        }
    }
}

impl UdpEncapConfig {
    /// Creates a new configuration with the specified ports.
    #[must_use]
    pub const fn new(local_port: u16, remote_port: u16) -> Self {
        Self {
            local_port,
            remote_port,
            enable_checksum: true,
        }
    }

    /// Creates a configuration using the default SCTP/UDP port.
    #[must_use]
    pub const fn default_port() -> Self {
        Self {
            local_port: SCTP_UDP_PORT,
            remote_port: SCTP_UDP_PORT,
            enable_checksum: true,
        }
    }
}

// =============================================================================
// UDP Header
// =============================================================================

/// UDP header for encapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub dest_port: u16,
    /// Length (header + data).
    pub length: u16,
    /// Checksum (0 if disabled).
    pub checksum: u16,
}

impl UdpHeader {
    /// Creates a new UDP header.
    #[must_use]
    pub const fn new(source_port: u16, dest_port: u16, payload_len: usize) -> Self {
        let length = (UDP_HEADER_SIZE + payload_len) as u16;
        Self {
            source_port,
            dest_port,
            length,
            checksum: 0, // Will be calculated if needed
        }
    }

    /// Encodes the header into bytes.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_port);
        buf.put_u16(self.dest_port);
        buf.put_u16(self.length);
        buf.put_u16(self.checksum);
    }

    /// Decodes a header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short.
    pub fn decode(buf: &mut Bytes) -> Result<Self, UdpEncapError> {
        if buf.remaining() < UDP_HEADER_SIZE {
            return Err(UdpEncapError::BufferTooShort {
                expected: UDP_HEADER_SIZE,
                actual: buf.remaining(),
            });
        }

        let source_port = buf.get_u16();
        let dest_port = buf.get_u16();
        let length = buf.get_u16();
        let checksum = buf.get_u16();

        Ok(Self {
            source_port,
            dest_port,
            length,
            checksum,
        })
    }

    /// Calculates the UDP checksum.
    ///
    /// Per RFC 768, the checksum covers a pseudo-header plus the UDP header and data.
    /// For UDP over IPv4, checksum is optional (can be 0).
    /// For UDP over IPv6, checksum is mandatory.
    #[must_use]
    pub fn calculate_checksum(
        &self,
        source_addr: &SocketAddr,
        dest_addr: &SocketAddr,
        payload: &[u8],
    ) -> u16 {
        let mut sum: u32 = 0;

        // Add pseudo-header
        match (source_addr, dest_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                // IPv4 pseudo-header
                let src_octets = src.ip().octets();
                let dst_octets = dst.ip().octets();

                sum += u32::from(u16::from_be_bytes([src_octets[0], src_octets[1]]));
                sum += u32::from(u16::from_be_bytes([src_octets[2], src_octets[3]]));
                sum += u32::from(u16::from_be_bytes([dst_octets[0], dst_octets[1]]));
                sum += u32::from(u16::from_be_bytes([dst_octets[2], dst_octets[3]]));
                sum += 17u32; // UDP protocol number
                sum += u32::from(self.length);
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                // IPv6 pseudo-header
                let src_octets = src.ip().octets();
                let dst_octets = dst.ip().octets();

                for chunk in src_octets.chunks(2) {
                    sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
                }
                for chunk in dst_octets.chunks(2) {
                    sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
                }
                sum += u32::from(self.length);
                sum += 17u32; // UDP protocol number (next header)
            }
            _ => {
                // Mixed addressing not supported
                return 0;
            }
        }

        // Add UDP header (excluding checksum field)
        sum += u32::from(self.source_port);
        sum += u32::from(self.dest_port);
        sum += u32::from(self.length);

        // Add payload
        let mut chunks = payload.chunks_exact(2);
        for chunk in chunks.by_ref() {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }

        // Handle odd byte
        if let Some(&last_byte) = chunks.remainder().first() {
            sum += u32::from(u16::from_be_bytes([last_byte, 0]));
        }

        // Fold 32-bit sum into 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        let checksum = !sum as u16;

        // If checksum is 0, use 0xFFFF (RFC 768)
        if checksum == 0 { 0xFFFF } else { checksum }
    }
}

// =============================================================================
// Encapsulated Packet
// =============================================================================

/// An SCTP packet encapsulated in UDP.
#[derive(Debug, Clone)]
pub struct EncapsulatedPacket {
    /// UDP header.
    pub udp_header: UdpHeader,
    /// SCTP packet.
    pub sctp_packet: SctpPacket,
}

impl EncapsulatedPacket {
    /// Creates a new encapsulated packet.
    #[must_use]
    pub fn new(sctp_packet: SctpPacket, source_port: u16, dest_port: u16) -> Self {
        // Estimate SCTP packet size
        let sctp_size = super::packet::HEADER_SIZE + sctp_packet.estimated_chunks_size();
        let udp_header = UdpHeader::new(source_port, dest_port, sctp_size);

        Self {
            udp_header,
            sctp_packet,
        }
    }

    /// Creates an encapsulated packet from configuration.
    #[must_use]
    pub fn from_config(sctp_packet: SctpPacket, config: &UdpEncapConfig) -> Self {
        Self::new(sctp_packet, config.local_port, config.remote_port)
    }

    /// Encodes the encapsulated packet into bytes.
    ///
    /// Optionally calculates the UDP checksum if addresses are provided.
    pub fn encode(
        &self,
        source_addr: Option<&SocketAddr>,
        dest_addr: Option<&SocketAddr>,
    ) -> Bytes {
        // First encode the SCTP packet
        let sctp_bytes = self.sctp_packet.encode();

        // Update UDP header with actual length
        let mut udp_header = self.udp_header;
        udp_header.length = (UDP_HEADER_SIZE + sctp_bytes.len()) as u16;

        // Calculate checksum if addresses provided
        if let (Some(src), Some(dst)) = (source_addr, dest_addr) {
            udp_header.checksum = udp_header.calculate_checksum(src, dst, &sctp_bytes);
        }

        // Encode the full packet
        let mut buf = BytesMut::with_capacity(UDP_HEADER_SIZE + sctp_bytes.len());
        udp_header.encode(&mut buf);
        buf.extend_from_slice(&sctp_bytes);

        buf.freeze()
    }

    /// Decodes an encapsulated packet from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn decode(mut buf: Bytes) -> Result<Self, UdpEncapError> {
        if buf.remaining() < MIN_ENCAP_SIZE {
            return Err(UdpEncapError::BufferTooShort {
                expected: MIN_ENCAP_SIZE,
                actual: buf.remaining(),
            });
        }

        let udp_header = UdpHeader::decode(&mut buf)?;

        // Validate length
        let expected_sctp_len = udp_header.length as usize - UDP_HEADER_SIZE;
        if buf.remaining() < expected_sctp_len {
            return Err(UdpEncapError::InvalidLength {
                header_length: udp_header.length,
                actual_remaining: buf.remaining(),
            });
        }

        // Take only the SCTP portion
        let sctp_bytes = buf.slice(..expected_sctp_len);
        let sctp_packet = SctpPacket::decode(&sctp_bytes)
            .map_err(|e| UdpEncapError::SctpDecodeError(e.to_string()))?;

        Ok(Self {
            udp_header,
            sctp_packet,
        })
    }

    /// Verifies the UDP checksum.
    ///
    /// Returns true if the checksum is valid or zero (disabled).
    #[must_use]
    pub fn verify_checksum(
        &self,
        source_addr: &SocketAddr,
        dest_addr: &SocketAddr,
        original_data: &[u8],
    ) -> bool {
        // Zero checksum means it was disabled
        if self.udp_header.checksum == 0 {
            return true;
        }

        // Extract the SCTP payload from original data (skip UDP header)
        if original_data.len() < UDP_HEADER_SIZE {
            return false;
        }
        let sctp_payload = &original_data[UDP_HEADER_SIZE..];

        // Calculate expected checksum
        let mut header_for_calc = self.udp_header;
        header_for_calc.checksum = 0;
        let calculated = header_for_calc.calculate_checksum(source_addr, dest_addr, sctp_payload);

        // Verify
        calculated == self.udp_header.checksum || self.udp_header.checksum == 0xFFFF
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during UDP encapsulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpEncapError {
    /// Buffer is too short.
    BufferTooShort {
        /// Expected minimum size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },
    /// Invalid length field in UDP header.
    InvalidLength {
        /// Length from header.
        header_length: u16,
        /// Actual remaining bytes.
        actual_remaining: usize,
    },
    /// Failed to decode SCTP packet.
    SctpDecodeError(String),
}

impl std::fmt::Display for UdpEncapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort { expected, actual } => {
                write!(f, "buffer too short: expected {expected}, got {actual}")
            }
            Self::InvalidLength {
                header_length,
                actual_remaining,
            } => {
                write!(
                    f,
                    "invalid length: header says {header_length}, but only {actual_remaining} bytes remain"
                )
            }
            Self::SctpDecodeError(e) => write!(f, "SCTP decode error: {e}"),
        }
    }
}

impl std::error::Error for UdpEncapError {}

// =============================================================================
// Helper Functions
// =============================================================================

/// Encapsulates an SCTP packet for UDP transmission.
#[must_use]
pub fn encapsulate(sctp_packet: SctpPacket, config: &UdpEncapConfig) -> EncapsulatedPacket {
    EncapsulatedPacket::from_config(sctp_packet, config)
}

/// Decapsulates an SCTP packet from a UDP datagram.
///
/// # Errors
///
/// Returns an error if the packet is malformed.
pub fn decapsulate(data: Bytes) -> Result<EncapsulatedPacket, UdpEncapError> {
    EncapsulatedPacket::decode(data)
}

/// Checks if a UDP port is the standard SCTP/UDP port.
#[must_use]
pub const fn is_sctp_udp_port(port: u16) -> bool {
    port == SCTP_UDP_PORT
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sctp::chunk::{Chunk, DataChunk};

    fn create_test_sctp_packet() -> SctpPacket {
        let data_chunk = DataChunk::new(1, 0, 0, 0, Bytes::from_static(b"test data"));
        let mut packet = SctpPacket::new(5060, 5061, 0x12345678);
        packet.add_chunk(Chunk::Data(data_chunk));
        packet
    }

    #[test]
    fn test_udp_header_encode_decode() {
        let header = UdpHeader::new(9899, 9899, 100);

        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = UdpHeader::decode(&mut bytes).unwrap();

        assert_eq!(decoded.source_port, 9899);
        assert_eq!(decoded.dest_port, 9899);
        assert_eq!(decoded.length, 108); // 8 + 100
    }

    #[test]
    fn test_encapsulated_packet_roundtrip() {
        let sctp_packet = create_test_sctp_packet();
        let encap = EncapsulatedPacket::new(sctp_packet, 9899, 9899);

        let encoded = encap.encode(None, None);
        let decoded = EncapsulatedPacket::decode(encoded).unwrap();

        assert_eq!(decoded.udp_header.source_port, 9899);
        assert_eq!(decoded.udp_header.dest_port, 9899);
        assert_eq!(decoded.sctp_packet.source_port, 5060);
        assert_eq!(decoded.sctp_packet.dest_port, 5061);
        assert_eq!(decoded.sctp_packet.verification_tag, 0x12345678);
    }

    #[test]
    fn test_encapsulate_helper() {
        let sctp_packet = create_test_sctp_packet();
        let config = UdpEncapConfig::default();

        let encap = encapsulate(sctp_packet, &config);

        assert_eq!(encap.udp_header.source_port, SCTP_UDP_PORT);
        assert_eq!(encap.udp_header.dest_port, SCTP_UDP_PORT);
    }

    #[test]
    fn test_decapsulate_helper() {
        let sctp_packet = create_test_sctp_packet();
        let config = UdpEncapConfig::default();

        let encap = encapsulate(sctp_packet, &config);
        let encoded = encap.encode(None, None);

        let decap = decapsulate(encoded).unwrap();
        assert_eq!(decap.sctp_packet.chunks.len(), 1);
    }

    #[test]
    fn test_buffer_too_short() {
        let data = Bytes::from_static(&[0u8; 10]);
        let result = decapsulate(data);

        assert!(matches!(result, Err(UdpEncapError::BufferTooShort { .. })));
    }

    #[test]
    fn test_default_config() {
        let config = UdpEncapConfig::default();

        assert_eq!(config.local_port, SCTP_UDP_PORT);
        assert_eq!(config.remote_port, SCTP_UDP_PORT);
        assert!(config.enable_checksum);
    }

    #[test]
    fn test_custom_config() {
        let config = UdpEncapConfig::new(12345, 54321);

        assert_eq!(config.local_port, 12345);
        assert_eq!(config.remote_port, 54321);
    }

    #[test]
    fn test_is_sctp_udp_port() {
        assert!(is_sctp_udp_port(9899));
        assert!(!is_sctp_udp_port(5060));
    }

    #[test]
    fn test_udp_checksum_ipv4() {
        let header = UdpHeader::new(9899, 9899, 10);
        let src: SocketAddr = "192.168.1.1:9899".parse().unwrap();
        let dst: SocketAddr = "192.168.1.2:9899".parse().unwrap();
        let payload = b"0123456789";

        let checksum = header.calculate_checksum(&src, &dst, payload);

        // Checksum should be non-zero
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_encapsulated_with_checksum() {
        let sctp_packet = create_test_sctp_packet();
        let encap = EncapsulatedPacket::new(sctp_packet, 9899, 9899);

        let src: SocketAddr = "192.168.1.1:9899".parse().unwrap();
        let dst: SocketAddr = "192.168.1.2:9899".parse().unwrap();

        let encoded = encap.encode(Some(&src), Some(&dst));

        // Verify the encoded packet has a non-zero checksum in the UDP header
        let mut buf = encoded.clone();
        let _ = buf.get_u16(); // source port
        let _ = buf.get_u16(); // dest port
        let _ = buf.get_u16(); // length
        let checksum = buf.get_u16();

        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_udp_encap_error_display() {
        let err = UdpEncapError::BufferTooShort {
            expected: 20,
            actual: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains("20"));
        assert!(msg.contains("10"));

        let err = UdpEncapError::SctpDecodeError("test error".to_string());
        let msg = err.to_string();
        assert!(msg.contains("test error"));
    }
}
