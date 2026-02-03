//! TURN ChannelData message handling.

use crate::error::{TurnError, TurnResult};
use crate::{MAX_CHANNEL_NUMBER, MIN_CHANNEL_NUMBER};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// ChannelData message header size (4 bytes).
pub const CHANNEL_DATA_HEADER_SIZE: usize = 4;

/// Maximum ChannelData payload size.
/// Per RFC 5766, the maximum is 65535 - 4 = 65531 bytes.
pub const MAX_CHANNEL_DATA_SIZE: usize = 65531;

/// ChannelData message for efficient data relay.
///
/// ChannelData messages provide a more efficient way to send data
/// through the TURN relay compared to Send/Data indications.
///
/// Format (RFC 5766):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Channel Number        |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                       Application Data                        /
/// /                                                               /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelData {
    /// Channel number (0x4000-0x7FFE).
    channel: u16,
    /// Application data payload.
    data: Bytes,
}

impl ChannelData {
    /// Creates a new ChannelData message.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - Channel number is out of valid range
    /// - Data exceeds maximum size
    pub fn new(channel: u16, data: Bytes) -> TurnResult<Self> {
        if channel < MIN_CHANNEL_NUMBER || channel > MAX_CHANNEL_NUMBER {
            return Err(TurnError::InvalidChannel { channel });
        }

        if data.len() > MAX_CHANNEL_DATA_SIZE {
            return Err(TurnError::DataTooLarge {
                size: data.len(),
                max: MAX_CHANNEL_DATA_SIZE,
            });
        }

        Ok(Self { channel, data })
    }

    /// Returns the channel number.
    pub fn channel(&self) -> u16 {
        self.channel
    }

    /// Returns the application data.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Consumes self and returns the application data.
    pub fn into_data(self) -> Bytes {
        self.data
    }

    /// Checks if a buffer starts with a ChannelData message.
    ///
    /// ChannelData messages have first two bits as 01, meaning
    /// the first byte is in range 0x40-0x7F.
    pub fn is_channel_data(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        // Channel numbers are 0x4000-0x7FFE
        // First byte should be 0x40-0x7F
        let first_byte = data[0];
        (0x40..=0x7F).contains(&first_byte)
    }

    /// Decodes a ChannelData message from bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - Buffer is too small
    /// - Channel number is invalid
    /// - Length field exceeds buffer
    pub fn decode(data: &[u8]) -> TurnResult<Self> {
        if data.len() < CHANNEL_DATA_HEADER_SIZE {
            return Err(TurnError::BufferTooSmall {
                needed: CHANNEL_DATA_HEADER_SIZE,
                available: data.len(),
            });
        }

        let mut buf = data;
        let channel = buf.get_u16();
        let length = buf.get_u16() as usize;

        // Validate channel number
        if channel < MIN_CHANNEL_NUMBER || channel > MAX_CHANNEL_NUMBER {
            return Err(TurnError::InvalidChannel { channel });
        }

        // Check we have enough data
        if buf.len() < length {
            return Err(TurnError::BufferTooSmall {
                needed: CHANNEL_DATA_HEADER_SIZE + length,
                available: data.len(),
            });
        }

        let payload = Bytes::copy_from_slice(&buf[..length]);

        Ok(Self {
            channel,
            data: payload,
        })
    }

    /// Encodes the ChannelData message to bytes.
    pub fn encode(&self) -> Bytes {
        // Calculate padded length (must be multiple of 4)
        let data_len = self.data.len();
        let padded_len = (data_len + 3) & !3;

        let mut buf = BytesMut::with_capacity(CHANNEL_DATA_HEADER_SIZE + padded_len);

        buf.put_u16(self.channel);
        buf.put_u16(data_len as u16);
        buf.put_slice(&self.data);

        // Add padding if needed
        let padding = padded_len - data_len;
        for _ in 0..padding {
            buf.put_u8(0);
        }

        buf.freeze()
    }

    /// Returns the total encoded size including padding.
    pub fn encoded_size(&self) -> usize {
        let padded_len = (self.data.len() + 3) & !3;
        CHANNEL_DATA_HEADER_SIZE + padded_len
    }
}

/// Distinguishes between STUN messages and ChannelData.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// STUN message (first two bits are 00).
    Stun,
    /// ChannelData message (first two bits are 01).
    ChannelData,
    /// Unknown message type.
    Unknown,
}

impl MessageType {
    /// Determines the message type from the first byte.
    pub fn from_first_byte(byte: u8) -> Self {
        match byte >> 6 {
            0b00 => Self::Stun,
            0b01 => Self::ChannelData,
            _ => Self::Unknown,
        }
    }

    /// Determines the message type from a buffer.
    pub fn detect(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::Unknown;
        }
        Self::from_first_byte(data[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_data_creation() {
        let data = Bytes::from_static(b"Hello, World!");
        let msg = ChannelData::new(0x4000, data.clone()).unwrap();
        assert_eq!(msg.channel(), 0x4000);
        assert_eq!(msg.data(), &data);
    }

    #[test]
    fn test_channel_data_invalid_channel_low() {
        let data = Bytes::from_static(b"test");
        let result = ChannelData::new(0x3FFF, data);
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_data_invalid_channel_high() {
        let data = Bytes::from_static(b"test");
        let result = ChannelData::new(0x7FFF, data);
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_data_encode_decode() {
        let original_data = Bytes::from_static(b"Test payload data");
        let msg = ChannelData::new(0x4001, original_data.clone()).unwrap();

        let encoded = msg.encode();
        let decoded = ChannelData::decode(&encoded).unwrap();

        assert_eq!(decoded.channel(), 0x4001);
        assert_eq!(decoded.data(), &original_data);
    }

    #[test]
    fn test_channel_data_padding() {
        // Data length 5 should pad to 8
        let data = Bytes::from_static(b"12345");
        let msg = ChannelData::new(0x4000, data).unwrap();

        let encoded = msg.encode();
        // 4 header + 8 padded data
        assert_eq!(encoded.len(), 12);
    }

    #[test]
    fn test_is_channel_data() {
        // Valid ChannelData (0x40xx)
        assert!(ChannelData::is_channel_data(&[0x40, 0x00]));
        assert!(ChannelData::is_channel_data(&[0x7F, 0xFE]));

        // STUN message (0x00 or 0x01 start)
        assert!(!ChannelData::is_channel_data(&[0x00, 0x01]));
        assert!(!ChannelData::is_channel_data(&[0x01, 0x01]));

        // Empty
        assert!(!ChannelData::is_channel_data(&[]));
    }

    #[test]
    fn test_message_type_detection() {
        // STUN (00xxxxxx)
        assert_eq!(MessageType::detect(&[0x00, 0x01]), MessageType::Stun);
        assert_eq!(MessageType::detect(&[0x01, 0x01]), MessageType::Stun);

        // ChannelData (01xxxxxx)
        assert_eq!(MessageType::detect(&[0x40, 0x00]), MessageType::ChannelData);
        assert_eq!(MessageType::detect(&[0x7F, 0x00]), MessageType::ChannelData);

        // Unknown (10xxxxxx or 11xxxxxx)
        assert_eq!(MessageType::detect(&[0x80, 0x00]), MessageType::Unknown);
        assert_eq!(MessageType::detect(&[0xC0, 0x00]), MessageType::Unknown);

        // Empty
        assert_eq!(MessageType::detect(&[]), MessageType::Unknown);
    }

    #[test]
    fn test_decode_too_small() {
        let result = ChannelData::decode(&[0x40, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_length() {
        // Header says 100 bytes, but only 4 available
        let data = [0x40, 0x00, 0x00, 0x64];
        let result = ChannelData::decode(&data);
        assert!(result.is_err());
    }
}
