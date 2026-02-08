//! RTP packet handling per RFC 3550.

use crate::error::{RtpError, RtpResult};
use crate::{RTP_HEADER_MIN_SIZE, RTP_VERSION};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

/// Parses the first byte of an RTP header.
/// Returns (padding, extension, `csrc_count`).
fn parse_first_byte(byte: u8) -> RtpResult<(bool, bool, usize)> {
    let version = (byte >> 6) & 0x03;
    if version != RTP_VERSION {
        return Err(RtpError::InvalidVersion { version });
    }

    let padding = (byte & 0x20) != 0;
    let extension = (byte & 0x10) != 0;
    let csrc_count = (byte & 0x0F) as usize;

    Ok((padding, extension, csrc_count))
}

/// Parses the second byte of an RTP header.
/// Returns (marker, `payload_type`).
fn parse_second_byte(byte: u8) -> (bool, u8) {
    let marker = (byte & 0x80) != 0;
    let payload_type = byte & 0x7F;
    (marker, payload_type)
}

/// Parses the CSRC list from the RTP header.
fn parse_csrc_list(cursor: &mut &[u8], count: usize) -> Vec<u32> {
    let mut csrc = Vec::with_capacity(count);
    for _ in 0..count {
        csrc.push(cursor.get_u32());
    }
    csrc
}

/// Parses the extension header if present.
/// Returns (`extension_header`, `total_header_size`).
fn parse_extension_header(
    data: &[u8],
    header_size: usize,
    has_extension: bool,
) -> RtpResult<(Option<ExtensionHeader>, usize)> {
    if !has_extension {
        return Ok((None, header_size));
    }

    if data.len() < header_size + 4 {
        return Err(RtpError::InvalidExtension {
            reason: "extension header too short",
        });
    }

    let ext_data = &data[header_size..];
    let profile = u16::from_be_bytes([ext_data[0], ext_data[1]]);
    let length = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize * 4;

    if data.len() < header_size + 4 + length {
        return Err(RtpError::InvalidExtension {
            reason: "extension data too short",
        });
    }

    let total_header_size = header_size + 4 + length;
    let extension_header = ExtensionHeader {
        profile,
        data: Bytes::copy_from_slice(&ext_data[4..4 + length]),
    };

    Ok((Some(extension_header), total_header_size))
}

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

    /// Serializes the header directly into `buf`, returning the number of
    /// bytes written.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`Self::size()`].
    #[must_use]
    pub fn write_into(&self, buf: &mut [u8]) -> usize {
        let size = self.size();
        debug_assert!(buf.len() >= size, "buffer too small for RTP header");

        // First byte: V=2, P, X, CC
        buf[0] = (RTP_VERSION << 6)
            | (if self.padding { 0x20 } else { 0 })
            | (if self.extension { 0x10 } else { 0 })
            | ((self.csrc.len() as u8) & 0x0F);

        // Second byte: M, PT
        buf[1] = (if self.marker { 0x80 } else { 0 }) | (self.payload_type & 0x7F);

        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut pos = 12;
        for &csrc in &self.csrc {
            buf[pos..pos + 4].copy_from_slice(&csrc.to_be_bytes());
            pos += 4;
        }

        if let Some(ref ext) = self.extension_header {
            buf[pos..pos + 2].copy_from_slice(&ext.profile.to_be_bytes());
            #[allow(clippy::cast_possible_truncation)]
            let ext_len = (ext.data.len() / 4) as u16;
            buf[pos + 2..pos + 4].copy_from_slice(&ext_len.to_be_bytes());
            pos += 4;
            buf[pos..pos + ext.data.len()].copy_from_slice(&ext.data);
            pos += ext.data.len();
        }

        pos
    }

    /// Parses an RTP header from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the data is too short or invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> RtpResult<(Self, usize)> {
        if data.len() < RTP_HEADER_MIN_SIZE {
            return Err(RtpError::PacketTooShort {
                need: RTP_HEADER_MIN_SIZE,
                got: data.len(),
            });
        }

        let (padding, extension, csrc_count) = parse_first_byte(data[0])?;
        let (marker, payload_type) = parse_second_byte(data[1]);

        let mut cursor = &data[2..];
        let sequence_number = cursor.get_u16();
        let timestamp = cursor.get_u32();
        let ssrc = cursor.get_u32();

        let header_size = RTP_HEADER_MIN_SIZE + csrc_count * 4;
        if data.len() < header_size {
            return Err(RtpError::PacketTooShort {
                need: header_size,
                got: data.len(),
            });
        }

        let csrc = parse_csrc_list(&mut cursor, csrc_count);
        let (extension_header, total_header_size) =
            parse_extension_header(data, header_size, extension)?;

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
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> RtpResult<Self> {
        let (header, header_size) = RtpHeader::parse(data)?;

        let mut payload_end = data.len();
        let mut padding_size = 0;

        // Handle padding
        if header.padding {
            if data.is_empty() {
                return Err(RtpError::InvalidPadding {
                    reason: "padding flag set but no padding length",
                });
            }

            padding_size = data[data.len() - 1] as usize;
            if padding_size == 0 || padding_size > data.len() - header_size {
                return Err(RtpError::InvalidPaddingSize { padding_size });
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
        let mut buf =
            BytesMut::with_capacity(self.header.size() + self.payload.len() + self.padding_size);

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
#[allow(clippy::unreadable_literal, clippy::unwrap_used)]
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

        let packet = RtpPacket::new(header, payload);
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
        assert!(matches!(
            result,
            Err(RtpError::InvalidVersion { version: 3 })
        ));
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

    #[test]
    fn test_header_write_into_matches_to_bytes() {
        let header = RtpHeader::new(96, 1000, 160000, 0xDEADBEEF)
            .with_marker(true)
            .with_csrc(0x11111111);

        let expected = header.to_bytes();

        let mut buf = [0u8; 128];
        let written = header.write_into(&mut buf);

        assert_eq!(written, expected.len());
        assert_eq!(&buf[..written], &expected[..]);
    }

    #[test]
    fn test_header_write_into_minimal() {
        let header = RtpHeader::new(0, 100, 1600, 0xABCDEF01);

        let expected = header.to_bytes();

        let mut buf = [0u8; 12];
        let written = header.write_into(&mut buf);

        assert_eq!(written, 12);
        assert_eq!(&buf[..], &expected[..]);
    }
}
