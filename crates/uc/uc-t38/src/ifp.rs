//! IFP (Internet Fax Protocol) packet handling per ITU-T T.38.
//!
//! IFP packets encapsulate T.30 fax data for transmission over IP networks.

use crate::error::{T38Error, T38Result};
use crate::signal::T30Signal;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

/// IFP packet data types per ITU-T T.38.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DataType {
    /// V.21 low-speed modulation (300 bps).
    V21 = 0,
    /// V.27ter fallback mode (2400 bps).
    V27Ter2400 = 1,
    /// V.27ter normal mode (4800 bps).
    V27Ter4800 = 2,
    /// V.29 mode (7200 bps).
    V29_7200 = 3,
    /// V.29 mode (9600 bps).
    V29_9600 = 4,
    /// V.17 mode (7200 bps).
    V17_7200 = 5,
    /// V.17 mode (9600 bps).
    V17_9600 = 6,
    /// V.17 mode (12000 bps).
    V17_12000 = 7,
    /// V.17 mode (14400 bps).
    V17_14400 = 8,
    /// V.8 announcement message.
    V8Am = 9,
    /// V.8 call menu.
    V8Cm = 10,
    /// V.8 joint menu.
    V8Jm = 11,
    /// V.34 HDX control channel.
    V34HdxCc = 12,
    /// V.34 primary channel.
    V34Primary = 13,
    /// T.30 indications.
    T30Ind = 14,
    /// No signal.
    NoSignal = 15,
}

impl DataType {
    /// Returns the bit rate for this data type.
    #[must_use]
    pub const fn bit_rate(&self) -> u32 {
        match self {
            Self::V21 => 300,
            Self::V27Ter2400 => 2400,
            Self::V27Ter4800 => 4800,
            Self::V29_7200 | Self::V17_7200 => 7200,
            Self::V29_9600 | Self::V17_9600 => 9600,
            Self::V17_12000 => 12000,
            Self::V17_14400 => 14400,
            _ => 0,
        }
    }

    /// Returns true if this is a high-speed data type.
    #[must_use]
    pub const fn is_high_speed(&self) -> bool {
        matches!(
            self,
            Self::V29_7200
                | Self::V29_9600
                | Self::V17_7200
                | Self::V17_9600
                | Self::V17_12000
                | Self::V17_14400
                | Self::V34Primary
        )
    }

    /// Returns true if this is a control channel type.
    #[must_use]
    pub const fn is_control(&self) -> bool {
        matches!(
            self,
            Self::V21 | Self::V8Am | Self::V8Cm | Self::V8Jm | Self::V34HdxCc | Self::T30Ind
        )
    }
}

impl TryFrom<u8> for DataType {
    type Error = T38Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::V21),
            1 => Ok(Self::V27Ter2400),
            2 => Ok(Self::V27Ter4800),
            3 => Ok(Self::V29_7200),
            4 => Ok(Self::V29_9600),
            5 => Ok(Self::V17_7200),
            6 => Ok(Self::V17_9600),
            7 => Ok(Self::V17_12000),
            8 => Ok(Self::V17_14400),
            9 => Ok(Self::V8Am),
            10 => Ok(Self::V8Cm),
            11 => Ok(Self::V8Jm),
            12 => Ok(Self::V34HdxCc),
            13 => Ok(Self::V34Primary),
            14 => Ok(Self::T30Ind),
            15 => Ok(Self::NoSignal),
            _ => Err(T38Error::InvalidIfpPacket {
                reason: format!("unknown data type: {value}"),
            }),
        }
    }
}

/// T.30 indication type for IFP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum T30Indication {
    /// No signal.
    NoSignal = 0,
    /// CNG tone.
    Cng = 1,
    /// CED tone.
    Ced = 2,
    /// V.21 preamble.
    V21Preamble = 3,
    /// V.27 training.
    V27Training = 4,
    /// V.29 training.
    V29Training = 5,
    /// V.17 short training.
    V17ShortTraining = 6,
    /// V.17 long training.
    V17LongTraining = 7,
    /// V.8 announcement.
    V8Announce = 8,
    /// V.34 control channel retrain.
    V34CcRetrain = 9,
    /// V.34 primary channel retrain.
    V34PrimaryRetrain = 10,
    /// Page start marker.
    PageMarker = 11,
}

impl TryFrom<u8> for T30Indication {
    type Error = T38Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoSignal),
            1 => Ok(Self::Cng),
            2 => Ok(Self::Ced),
            3 => Ok(Self::V21Preamble),
            4 => Ok(Self::V27Training),
            5 => Ok(Self::V29Training),
            6 => Ok(Self::V17ShortTraining),
            7 => Ok(Self::V17LongTraining),
            8 => Ok(Self::V8Announce),
            9 => Ok(Self::V34CcRetrain),
            10 => Ok(Self::V34PrimaryRetrain),
            11 => Ok(Self::PageMarker),
            _ => Err(T38Error::InvalidIfpPacket {
                reason: format!("unknown T.30 indication: {value}"),
            }),
        }
    }
}

impl From<T30Signal> for T30Indication {
    fn from(signal: T30Signal) -> Self {
        match signal {
            T30Signal::Cng => Self::Cng,
            T30Signal::Ced => Self::Ced,
            T30Signal::V21Preamble => Self::V21Preamble,
            _ => Self::NoSignal,
        }
    }
}

/// IFP packet per ITU-T T.38.
#[derive(Debug, Clone)]
pub struct IfpPacket {
    /// Packet sequence number.
    pub seq_num: u16,
    /// Data type.
    pub data_type: DataType,
    /// T.30 indication (if data_type is T30Ind).
    pub indication: Option<T30Indication>,
    /// Data payload.
    pub data: Bytes,
}

impl IfpPacket {
    /// Creates a new IFP packet with data.
    #[must_use]
    pub fn new(seq_num: u16, data_type: DataType, data: impl Into<Bytes>) -> Self {
        Self {
            seq_num,
            data_type,
            indication: None,
            data: data.into(),
        }
    }

    /// Creates a new T.30 indication packet.
    #[must_use]
    pub fn indication(seq_num: u16, indication: T30Indication) -> Self {
        Self {
            seq_num,
            data_type: DataType::T30Ind,
            indication: Some(indication),
            data: Bytes::new(),
        }
    }

    /// Encodes the IFP packet to bytes.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4 + self.data.len());

        // Sequence number (16 bits)
        buf.put_u16(self.seq_num);

        // Type field (8 bits)
        buf.put_u8(self.data_type as u8);

        // Indication or data length
        if let Some(ind) = self.indication {
            buf.put_u8(ind as u8);
        } else if !self.data.is_empty() {
            buf.put_u8(self.data.len() as u8);
            buf.put_slice(&self.data);
        } else {
            buf.put_u8(0);
        }

        buf.freeze()
    }

    /// Decodes an IFP packet from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn decode(mut data: Bytes) -> T38Result<Self> {
        if data.len() < 4 {
            return Err(T38Error::InvalidIfpPacket {
                reason: "packet too short".to_string(),
            });
        }

        let seq_num = data.get_u16();
        let type_byte = data.get_u8();
        let data_type = DataType::try_from(type_byte)?;

        if data_type == DataType::T30Ind {
            let ind_byte = data.get_u8();
            let indication = T30Indication::try_from(ind_byte)?;
            Ok(Self {
                seq_num,
                data_type,
                indication: Some(indication),
                data: Bytes::new(),
            })
        } else {
            let len = data.get_u8() as usize;
            if data.len() < len {
                return Err(T38Error::InvalidIfpPacket {
                    reason: format!("data length mismatch: expected {len}, got {}", data.len()),
                });
            }
            let payload = data.split_to(len);
            Ok(Self {
                seq_num,
                data_type,
                indication: None,
                data: payload,
            })
        }
    }

    /// Returns true if this is a control packet.
    #[must_use]
    pub fn is_control(&self) -> bool {
        self.data_type.is_control()
    }

    /// Returns true if this is a high-speed data packet.
    #[must_use]
    pub fn is_high_speed(&self) -> bool {
        self.data_type.is_high_speed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_bit_rate() {
        assert_eq!(DataType::V21.bit_rate(), 300);
        assert_eq!(DataType::V17_14400.bit_rate(), 14400);
        assert_eq!(DataType::NoSignal.bit_rate(), 0);
    }

    #[test]
    fn test_data_type_classification() {
        assert!(DataType::V21.is_control());
        assert!(!DataType::V21.is_high_speed());
        assert!(DataType::V17_14400.is_high_speed());
        assert!(!DataType::T30Ind.is_high_speed());
    }

    #[test]
    fn test_ifp_packet_encode_decode() {
        let packet = IfpPacket::new(42, DataType::V21, vec![0x01, 0x02, 0x03]);
        let encoded = packet.encode();
        let decoded = IfpPacket::decode(encoded).expect("decode failed");

        assert_eq!(decoded.seq_num, 42);
        assert_eq!(decoded.data_type, DataType::V21);
        assert_eq!(decoded.data.as_ref(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_ifp_indication_packet() {
        let packet = IfpPacket::indication(1, T30Indication::Cng);
        let encoded = packet.encode();
        let decoded = IfpPacket::decode(encoded).expect("decode failed");

        assert_eq!(decoded.seq_num, 1);
        assert_eq!(decoded.data_type, DataType::T30Ind);
        assert_eq!(decoded.indication, Some(T30Indication::Cng));
    }

    #[test]
    fn test_t30_signal_to_indication() {
        assert_eq!(T30Indication::from(T30Signal::Cng), T30Indication::Cng);
        assert_eq!(T30Indication::from(T30Signal::Ced), T30Indication::Ced);
        assert_eq!(
            T30Indication::from(T30Signal::Unknown),
            T30Indication::NoSignal
        );
    }
}
