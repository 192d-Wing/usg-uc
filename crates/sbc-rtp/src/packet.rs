//! RTP packet handling per RFC 3550.

use crate::error::{RtpError, RtpResult};
use crate::{RTP_HEADER_MIN_SIZE, RTP_VERSION};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

/// RTP header per RFC 3550.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           synchronization source (SSRC) identifier            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// |            contributing source (CSRC) identifiers             |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    /// Padding flag.
    pub padding: bool,
    /// Extension flag.
    pub extension: bool,
    /// Marker bit.
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Synchronization source identifier.
    pub ssrc: u32,
    /// Contributing source identifiers.
    pub csrc: Vec<u32>,
    /// Extension header (if present).
    pub extension_header: Option<ExtensionHeader>,
}

impl RtpHeader {
    /// Creates a new RTP header with required fields.
    #[must_use]
    pub fn new(payload_type: u8, sequence_number: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            padding: false,
            extension: false,
            marker: false,
            payload_type: payload_type & 0x7F,
            sequence_number,
            timestamp,
            ssrc,
            csrc: Vec::new(),
            extension_header: None,
        }
    }

    /// Sets the marker bit.
    #[must_use]
    pub fn with_marker(mut self, marker: bool) -> Self {
        self.marker = marker;
        self
    }

    /// Adds a CSRC.
    #[must_use]
    pub fn with_csrc(mut self, csrc: u32) -> Self {
        if self.csrc.len() < 15 {
            self.csrc.push(csrc);
        }
        self
    }

    /// Returns the header size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        let mut size = RTP_HEADER_MIN_SIZE + self.csrc.len() * 4;
        if let Some(ref ext) = self.extension_header {
            size += 4 + ext.data.len();
        }
        size
    }

    /// Parses an RTP header from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the data is too short or invalid.
    pub fn parse(data: &[u8]) -> RtpResult<(Self, usize)> {
        if data.len() < RTP_HEADER_MIN_SIZE {
            return Err(RtpError::PacketTooShort {
                need: RTP_HEADER_MIN_SIZE,
                got: data.len(),
            });
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;

        if version != RTP_VERSION {
            return Err(RtpError::InvalidVersion { version });
        }

        let padding = (first_byte & 0x20) != 0;
        let extension = (first_byte & 0x10) != 0;
        let csrc_count = (first_byte & 0x0F) as usize;

        let second_byte = data[1];
        let marker = (second_byte & 0x80) != 0;
        let payload_type = second_byte & 0x7F;

        let mut cursor = &data[2..];
        let sequence_number = cursor.get_u16();
        let timestamp = cursor.get_u32();
        let ssrc = cursor.get_u32();

        // Parse CSRCs
        let header_size = RTP_HEADER_MIN_SIZE + csrc_count * 4;
        if data.len() < header_size {
            return Err(RtpError::PacketTooShort {
                need: header_size,
                got: data.len(),
            });
        }

        let mut csrc = Vec::with_capacity(csrc_count);
        for _ in 0..csrc_count {
            csrc.push(cursor.get_u32());
        }

        // Parse extension header
        let mut total_header_size = header_size;
        let extension_header = if extension {
            if data.len() < total_header_size + 4 {
                return Err(RtpError::InvalidExtension {
                    reason: "extension header too short".to_string(),
                });
            }

            let ext_data = &data[total_header_size..];
            let profile = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            let length = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize * 4;

            if data.len() < total_header_size + 4 + length {
                return Err(RtpError::InvalidExtension {
                    reason: "extension data too short".to_string(),
                });
            }

            total_header_size += 4 + length;
            Some(ExtensionHeader {
                profile,
                data: Bytes::copy_from_slice(&ext_data[4..4 + length]),
            })
        } else {
            None
        };

        Ok((
            Self {
                padding,
                extension,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
                csrc,
                extension_header,
            },
            total_header_size,
        ))
    }

    /// Serializes the header to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.size());

        // First byte: V=2, P, X, CC
        let first_byte = (RTP_VERSION << 6)
            | (if self.padding { 0x20 } else { 0 })
            | (if self.extension { 0x10 } else { 0 })
            | ((self.csrc.len() as u8) & 0x0F);
        buf.put_u8(first_byte);

        // Second byte: M, PT
        let second_byte = (if self.marker { 0x80 } else { 0 }) | (self.payload_type & 0x7F);
        buf.put_u8(second_byte);

        buf.put_u16(self.sequence_number);
        buf.put_u32(self.timestamp);
        buf.put_u32(self.ssrc);

        for &csrc in &self.csrc {
            buf.put_u32(csrc);
        }

        if let Some(ref ext) = self.extension_header {
            buf.put_u16(ext.profile);
            buf.put_u16((ext.data.len() / 4) as u16);
            buf.put_slice(&ext.data);
        }

        buf.freeze()
    }
}

/// RTP extension header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHeader {
    /// Profile-specific identifier.
    pub profile: u16,
    /// Extension data (must be multiple of 4 bytes).
    pub data: Bytes,
}

/// Complete RTP packet (header + payload).
#[derive(Debug, Clone)]
pub struct RtpPacket {
    /// RTP header.
    pub header: RtpHeader,
    /// Payload data.
    pub payload: Bytes,
    /// Padding bytes (if any).
    pub padding_size: usize,
}

impl RtpPacket {
    /// Creates a new RTP packet.
    #[must_use]
    pub fn new(header: RtpHeader, payload: impl Into<Bytes>) -> Self {
        Self {
            header,
            payload: payload.into(),
            padding_size: 0,
        }
    }

    /// Parses an RTP packet from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the packet is invalid.
    pub fn parse(data: &[u8]) -> RtpResult<Self> {
        let (header, header_size) = RtpHeader::parse(data)?;

        let mut payload_end = data.len();
        let mut padding_size = 0;

        // Handle padding
        if header.padding {
            if data.is_empty() {
                return Err(RtpError::InvalidPadding {
                    reason: "padding flag set but no padding length".to_string(),
                });
            }

            padding_size = data[data.len() - 1] as usize;
            if padding_size == 0 || padding_size > data.len() - header_size {
                return Err(RtpError::InvalidPadding {
                    reason: format!("invalid padding size: {padding_size}"),
                });
            }

            payload_end -= padding_size;
        }

        let payload = Bytes::copy_from_slice(&data[header_size..payload_end]);

        Ok(Self {
            header,
            payload,
            padding_size,
        })
    }

    /// Serializes the packet to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.header.size() + self.payload.len() + self.padding_size);

        buf.put(self.header.to_bytes());
        buf.put(self.payload.clone());

        if self.padding_size > 0 {
            buf.put_bytes(0, self.padding_size - 1);
            buf.put_u8(self.padding_size as u8);
        }

        buf.freeze()
    }

    /// Returns the total packet size.
    #[must_use]
    pub fn size(&self) -> usize {
        self.header.size() + self.payload.len() + self.padding_size
    }
}

impl fmt::Display for RtpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RTP[PT={}, seq={}, ts={}, ssrc={:#010x}, len={}]",
            self.header.payload_type,
            self.header.sequence_number,
            self.header.timestamp,
            self.header.ssrc,
            self.payload.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_new() {
        let header = RtpHeader::new(0, 1234, 5678, 0x12345678);
        assert_eq!(header.payload_type, 0);
        assert_eq!(header.sequence_number, 1234);
        assert_eq!(header.timestamp, 5678);
        assert_eq!(header.ssrc, 0x12345678);
        assert!(!header.marker);
    }

    #[test]
    fn test_header_serialize_parse() {
        let header = RtpHeader::new(96, 1000, 160000, 0xDEADBEEF)
            .with_marker(true)
            .with_csrc(0x11111111);

        let bytes = header.to_bytes();
        let (parsed, _) = RtpHeader::parse(&bytes).unwrap();

        assert_eq!(parsed.payload_type, 96);
        assert_eq!(parsed.sequence_number, 1000);
        assert_eq!(parsed.timestamp, 160000);
        assert_eq!(parsed.ssrc, 0xDEADBEEF);
        assert!(parsed.marker);
        assert_eq!(parsed.csrc, vec![0x11111111]);
    }

    #[test]
    fn test_packet_roundtrip() {
        let header = RtpHeader::new(0, 100, 1600, 0xABCDEF01);
        let payload = vec![0u8; 160]; // 20ms G.711

        let packet = RtpPacket::new(header, payload.clone());
        let bytes = packet.to_bytes();
        let parsed = RtpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.header.sequence_number, 100);
        assert_eq!(parsed.payload.len(), 160);
    }

    #[test]
    fn test_invalid_version() {
        let mut data = vec![0u8; 12];
        data[0] = 0xC0; // Version 3

        let result = RtpHeader::parse(&data);
        assert!(matches!(result, Err(RtpError::InvalidVersion { version: 3 })));
    }

    #[test]
    fn test_packet_too_short() {
        let data = vec![0u8; 8]; // Less than 12 bytes

        let result = RtpHeader::parse(&data);
        assert!(matches!(result, Err(RtpError::PacketTooShort { .. })));
    }

    #[test]
    fn test_packet_display() {
        let header = RtpHeader::new(0, 1234, 5678, 0x12345678);
        let packet = RtpPacket::new(header, vec![0u8; 160]);

        let display = format!("{packet}");
        assert!(display.contains("PT=0"));
        assert!(display.contains("seq=1234"));
        assert!(display.contains("0x12345678"));
    }
}
