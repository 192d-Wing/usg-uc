//! RTCP packet handling per RFC 3550.

use crate::RTP_VERSION;
use crate::error::{RtpError, RtpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

/// RTCP packet types per RFC 3550.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtcpType {
    /// Sender Report.
    SenderReport,
    /// Receiver Report.
    ReceiverReport,
    /// Source Description.
    SourceDescription,
    /// Goodbye.
    Goodbye,
    /// Application-defined.
    ApplicationDefined,
    /// Unknown type.
    Unknown(u8),
}

impl RtcpType {
    /// Returns the numeric packet type.
    #[must_use]
    pub fn packet_type(&self) -> u8 {
        match self {
            Self::SenderReport => 200,
            Self::ReceiverReport => 201,
            Self::SourceDescription => 202,
            Self::Goodbye => 203,
            Self::ApplicationDefined => 204,
            Self::Unknown(pt) => *pt,
        }
    }

    /// Creates from a numeric packet type.
    #[must_use]
    pub fn from_u8(pt: u8) -> Self {
        match pt {
            200 => Self::SenderReport,
            201 => Self::ReceiverReport,
            202 => Self::SourceDescription,
            203 => Self::Goodbye,
            204 => Self::ApplicationDefined,
            _ => Self::Unknown(pt),
        }
    }
}

impl fmt::Display for RtcpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SenderReport => write!(f, "SR"),
            Self::ReceiverReport => write!(f, "RR"),
            Self::SourceDescription => write!(f, "SDES"),
            Self::Goodbye => write!(f, "BYE"),
            Self::ApplicationDefined => write!(f, "APP"),
            Self::Unknown(pt) => write!(f, "RTCP({pt})"),
        }
    }
}

/// RTCP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpHeader {
    /// Padding flag.
    pub padding: bool,
    /// Report count or subtype.
    pub count: u8,
    /// Packet type.
    pub packet_type: RtcpType,
    /// Length in 32-bit words minus one.
    pub length: u16,
}

impl RtcpHeader {
    /// Creates a new RTCP header.
    #[must_use]
    pub fn new(packet_type: RtcpType, count: u8) -> Self {
        Self {
            padding: false,
            count: count & 0x1F,
            packet_type,
            length: 0,
        }
    }

    /// Parses an RTCP header from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the data is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> RtpResult<Self> {
        if data.len() < 4 {
            return Err(RtpError::InvalidRtcp {
                reason: "header too short".to_string(),
            });
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;

        if version != RTP_VERSION {
            return Err(RtpError::InvalidRtcp {
                reason: format!("invalid RTCP version: {version}"),
            });
        }

        let padding = (first_byte & 0x20) != 0;
        let count = first_byte & 0x1F;
        let packet_type = RtcpType::from_u8(data[1]);

        let mut cursor = &data[2..];
        let length = cursor.get_u16();

        Ok(Self {
            padding,
            count,
            packet_type,
            length,
        })
    }

    /// Returns the packet length in bytes (excluding header).
    #[must_use]
    pub fn payload_length(&self) -> usize {
        (self.length as usize + 1) * 4 - 4
    }

    /// Serializes the header to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4);

        let first_byte =
            (RTP_VERSION << 6) | (if self.padding { 0x20 } else { 0 }) | (self.count & 0x1F);
        buf.put_u8(first_byte);
        buf.put_u8(self.packet_type.packet_type());
        buf.put_u16(self.length);

        buf.freeze()
    }
}

/// RTCP packet.
#[derive(Debug, Clone)]
pub struct RtcpPacket {
    /// RTCP header.
    pub header: RtcpHeader,
    /// Packet payload.
    pub payload: Bytes,
}

impl RtcpPacket {
    /// Creates a new RTCP packet.
    #[must_use]
    pub fn new(header: RtcpHeader, payload: impl Into<Bytes>) -> Self {
        Self {
            header,
            payload: payload.into(),
        }
    }

    /// Parses an RTCP packet from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the packet is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> RtpResult<Self> {
        let header = RtcpHeader::parse(data)?;
        let payload_len = header.payload_length();

        if data.len() < 4 + payload_len {
            return Err(RtpError::InvalidRtcp {
                reason: "packet too short for declared length".to_string(),
            });
        }

        let payload = Bytes::copy_from_slice(&data[4..4 + payload_len]);

        Ok(Self { header, payload })
    }

    /// Parses a compound RTCP packet (multiple RTCP packets concatenated).
    ///
    /// ## Errors
    ///
    /// Returns an error if any packet is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_compound(data: &[u8]) -> RtpResult<Vec<Self>> {
        let mut packets = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            if data.len() - offset < 4 {
                break;
            }

            let header = RtcpHeader::parse(&data[offset..])?;
            let packet_len = (header.length as usize + 1) * 4;

            if offset + packet_len > data.len() {
                return Err(RtpError::InvalidRtcp {
                    reason: "compound packet too short".to_string(),
                });
            }

            let packet = Self::parse(&data[offset..offset + packet_len])?;
            packets.push(packet);
            offset += packet_len;
        }

        Ok(packets)
    }

    /// Returns the packet type.
    #[must_use]
    pub fn packet_type(&self) -> RtcpType {
        self.header.packet_type
    }

    /// Serializes the packet to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4 + self.payload.len());
        buf.put(self.header.to_bytes());
        buf.put(self.payload.clone());
        buf.freeze()
    }
}

impl fmt::Display for RtcpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RTCP[{}, count={}, len={}]",
            self.header.packet_type,
            self.header.count,
            self.payload.len()
        )
    }
}

/// Sender Report (SR) specific fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderInfo {
    /// SSRC of sender.
    pub ssrc: u32,
    /// NTP timestamp (most significant word).
    pub ntp_timestamp_msw: u32,
    /// NTP timestamp (least significant word).
    pub ntp_timestamp_lsw: u32,
    /// RTP timestamp.
    pub rtp_timestamp: u32,
    /// Sender's packet count.
    pub sender_packet_count: u32,
    /// Sender's octet count.
    pub sender_octet_count: u32,
}

impl SenderInfo {
    /// Parses sender info from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the data is too short.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> RtpResult<Self> {
        if data.len() < 24 {
            return Err(RtpError::InvalidRtcp {
                reason: "sender info too short".to_string(),
            });
        }

        let mut cursor = data;
        Ok(Self {
            ssrc: cursor.get_u32(),
            ntp_timestamp_msw: cursor.get_u32(),
            ntp_timestamp_lsw: cursor.get_u32(),
            rtp_timestamp: cursor.get_u32(),
            sender_packet_count: cursor.get_u32(),
            sender_octet_count: cursor.get_u32(),
        })
    }
}

/// Reception report block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceptionReport {
    /// SSRC of source.
    pub ssrc: u32,
    /// Fraction lost.
    pub fraction_lost: u8,
    /// Cumulative packets lost (24-bit signed).
    pub cumulative_lost: i32,
    /// Extended highest sequence number.
    pub extended_highest_seq: u32,
    /// Interarrival jitter.
    pub jitter: u32,
    /// Last SR timestamp.
    pub last_sr: u32,
    /// Delay since last SR.
    pub delay_since_last_sr: u32,
}

impl ReceptionReport {
    /// Parses a reception report from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the data is too short.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> RtpResult<Self> {
        if data.len() < 24 {
            return Err(RtpError::InvalidRtcp {
                reason: "reception report too short".to_string(),
            });
        }

        let mut cursor = data;
        let ssrc = cursor.get_u32();
        let fraction_lost = cursor.get_u8();

        // 24-bit signed cumulative lost
        let lost_bytes = [0, cursor.get_u8(), cursor.get_u8(), cursor.get_u8()];
        let cumulative_lost = i32::from_be_bytes(lost_bytes) >> 8;

        let extended_highest_seq = cursor.get_u32();
        let jitter = cursor.get_u32();
        let last_sr = cursor.get_u32();
        let delay_since_last_sr = cursor.get_u32();

        Ok(Self {
            ssrc,
            fraction_lost,
            cumulative_lost,
            extended_highest_seq,
            jitter,
            last_sr,
            delay_since_last_sr,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_rtcp_type() {
        assert_eq!(RtcpType::SenderReport.packet_type(), 200);
        assert_eq!(RtcpType::from_u8(200), RtcpType::SenderReport);
        assert_eq!(RtcpType::from_u8(201), RtcpType::ReceiverReport);
        assert_eq!(format!("{}", RtcpType::SenderReport), "SR");
    }

    #[test]
    fn test_header_roundtrip() {
        let header = RtcpHeader::new(RtcpType::SenderReport, 1);
        let bytes = header.to_bytes();
        let parsed = RtcpHeader::parse(&bytes).unwrap();

        assert_eq!(parsed.packet_type, RtcpType::SenderReport);
        assert_eq!(parsed.count, 1);
    }

    #[test]
    fn test_packet_display() {
        let header = RtcpHeader::new(RtcpType::ReceiverReport, 2);
        let packet = RtcpPacket::new(header, vec![0u8; 24]);

        let display = format!("{packet}");
        assert!(display.contains("RR"));
        assert!(display.contains("count=2"));
    }
}
