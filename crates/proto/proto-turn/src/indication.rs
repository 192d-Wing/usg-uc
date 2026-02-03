//! TURN Send and Data indications per RFC 5766 §9, §12.
//!
//! This module implements Send and Data indications for relaying data
//! through a TURN server without channel bindings.
//!
//! ## RFC 5766 Compliance
//!
//! - **§9**: Send Indication (client to server)
//! - **§12**: Data Indication (server to client)
//!
//! ## Message Format
//!
//! Send and Data indications use the STUN message format with:
//! - XOR-PEER-ADDRESS: The peer's address
//! - DATA: The application data
//!
//! ## Usage
//!
//! Send indications are sent by the client when no channel binding exists.
//! Data indications are received from the server for incoming peer data.

use crate::attribute::TurnAttribute;
use crate::error::{TurnError, TurnResult};
use bytes::{BufMut, Bytes, BytesMut};
use proto_stun::message::{StunClass, StunMessage, StunMessageType, StunMethod};
use std::net::SocketAddr;

/// Maximum data size in a Send/Data indication.
///
/// Per RFC 5766, the maximum UDP datagram size minus headers.
/// Using a conservative limit that fits in a single UDP packet.
pub const MAX_INDICATION_DATA_SIZE: usize = 1200;

/// Send indication for relaying data to a peer.
///
/// ## RFC 5766 §9
///
/// A Send indication is used by the client to send data to a peer
/// when no channel binding exists for that peer.
///
/// Required attributes:
/// - XOR-PEER-ADDRESS: Address of the peer to send to
/// - DATA: Application data to relay
///
/// Optional attributes:
/// - DONT-FRAGMENT: Request that the server set the DF bit
#[derive(Debug, Clone)]
pub struct SendIndication {
    /// Peer address to send to.
    peer_address: SocketAddr,
    /// Application data to relay.
    data: Bytes,
    /// Whether to request the DF bit be set.
    dont_fragment: bool,
}

impl SendIndication {
    /// Creates a new Send indication.
    ///
    /// ## Arguments
    ///
    /// * `peer_address` - Address of the peer to send data to
    /// * `data` - Application data to relay
    ///
    /// ## Errors
    ///
    /// Returns an error if data exceeds maximum size.
    ///
    /// ## RFC 5766 §9
    ///
    /// The client sends a Send indication to the server when it
    /// wants to send data to a peer but does not have a channel
    /// binding for that peer.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(peer_address: SocketAddr, data: Bytes) -> TurnResult<Self> {
        if data.len() > MAX_INDICATION_DATA_SIZE {
            return Err(TurnError::DataTooLarge {
                size: data.len(),
                max: MAX_INDICATION_DATA_SIZE,
            });
        }

        Ok(Self {
            peer_address,
            data,
            dont_fragment: false,
        })
    }

    /// Sets the DONT-FRAGMENT flag.
    ///
    /// ## RFC 5766 §9
    ///
    /// If the DONT-FRAGMENT attribute is present, the server sets
    /// the DF bit in the IP header when relaying the data.
    #[must_use]
    pub fn with_dont_fragment(mut self, dont_fragment: bool) -> Self {
        self.dont_fragment = dont_fragment;
        self
    }

    /// Returns the peer address.
    #[must_use]
    pub fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    /// Returns the application data.
    #[must_use]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Returns whether DONT-FRAGMENT is set.
    #[must_use]
    pub fn dont_fragment(&self) -> bool {
        self.dont_fragment
    }

    /// Encodes the Send indication to a STUN message.
    ///
    /// ## RFC 5766 §9
    ///
    /// The Send indication uses method 0x0006 with class Indication (0x10).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn encode(&self) -> TurnResult<Bytes> {
        let mut transaction_id = [0u8; 12];
        uc_crypto::random::fill_random(&mut transaction_id).map_err(|_| {
            TurnError::InvalidRequest {
                reason: "failed to generate transaction ID".to_string(),
            }
        })?;

        let msg_type = StunMessageType::new(StunMethod::Send, StunClass::Indication);

        // Encode XOR-PEER-ADDRESS
        let peer_attr = TurnAttribute::XorPeerAddress(self.peer_address);
        let peer_bytes = peer_attr.encode(&transaction_id);

        // Encode DATA
        let data_attr = TurnAttribute::Data(self.data.clone());
        let data_bytes = data_attr.encode(&transaction_id);

        // Build the message manually since we need TURN attributes
        let mut buf = BytesMut::new();

        // STUN header
        buf.put_u16(msg_type.to_u16());
        // Length placeholder (will be filled in later)
        let length_pos = buf.len();
        buf.put_u16(0);
        buf.put_u32(proto_stun::MAGIC_COOKIE);
        buf.put_slice(&transaction_id);

        // Attributes
        buf.put_slice(&peer_bytes);
        buf.put_slice(&data_bytes);

        // Add DONT-FRAGMENT if requested
        if self.dont_fragment {
            let df_attr = TurnAttribute::DontFragment;
            let df_bytes = df_attr.encode(&transaction_id);
            buf.put_slice(&df_bytes);
        }

        // Update length
        let length = (buf.len() - 20) as u16;
        buf[length_pos] = (length >> 8) as u8;
        buf[length_pos + 1] = length as u8;

        Ok(buf.freeze())
    }

    /// Parses a Send indication from a STUN message.
    ///
    /// ## Errors
    ///
    /// Returns an error if required attributes are missing.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(msg: &StunMessage, raw_data: &[u8]) -> TurnResult<Self> {
        if msg.msg_type.method != StunMethod::Send {
            return Err(TurnError::InvalidRequest {
                reason: "not a Send indication".to_string(),
            });
        }

        if msg.msg_type.class != StunClass::Indication {
            return Err(TurnError::InvalidRequest {
                reason: "not an indication class".to_string(),
            });
        }

        // Parse TURN attributes from raw data
        let mut peer_address: Option<SocketAddr> = None;
        let mut data: Option<Bytes> = None;
        let mut dont_fragment = false;

        // Skip STUN header (20 bytes) and parse attributes
        let attrs_data = &raw_data[20..];
        let mut offset = 0;

        while offset + 4 <= attrs_data.len() {
            let attr_type = u16::from_be_bytes([attrs_data[offset], attrs_data[offset + 1]]);
            let attr_len =
                u16::from_be_bytes([attrs_data[offset + 2], attrs_data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > attrs_data.len() {
                break;
            }

            let attr_value = &attrs_data[offset..offset + attr_len];

            if let Some(turn_attr) =
                TurnAttribute::parse(attr_type, attr_value, &msg.transaction_id)?
            {
                match turn_attr {
                    TurnAttribute::XorPeerAddress(addr) => peer_address = Some(addr),
                    TurnAttribute::Data(d) => data = Some(d),
                    TurnAttribute::DontFragment => dont_fragment = true,
                    _ => {}
                }
            }

            // Move to next attribute (with padding)
            offset += (attr_len + 3) & !3;
        }

        let peer_address = peer_address.ok_or_else(|| TurnError::InvalidRequest {
            reason: "missing XOR-PEER-ADDRESS".to_string(),
        })?;

        let data = data.ok_or_else(|| TurnError::InvalidRequest {
            reason: "missing DATA attribute".to_string(),
        })?;

        Ok(Self {
            peer_address,
            data,
            dont_fragment,
        })
    }
}

/// Data indication received from the server.
///
/// ## RFC 5766 §12
///
/// A Data indication is sent by the server to the client when
/// data arrives from a peer for which no channel binding exists.
///
/// Required attributes:
/// - XOR-PEER-ADDRESS: Address of the peer that sent the data
/// - DATA: The application data from the peer
#[derive(Debug, Clone)]
pub struct DataIndication {
    /// Peer address the data came from.
    peer_address: SocketAddr,
    /// Application data from the peer.
    data: Bytes,
}

impl DataIndication {
    /// Creates a new Data indication (typically on server side).
    ///
    /// ## Arguments
    ///
    /// * `peer_address` - Address of the peer that sent the data
    /// * `data` - Application data from the peer
    ///
    /// ## Errors
    ///
    /// Returns an error if data exceeds maximum size.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(peer_address: SocketAddr, data: Bytes) -> TurnResult<Self> {
        if data.len() > MAX_INDICATION_DATA_SIZE {
            return Err(TurnError::DataTooLarge {
                size: data.len(),
                max: MAX_INDICATION_DATA_SIZE,
            });
        }

        Ok(Self { peer_address, data })
    }

    /// Returns the peer address.
    #[must_use]
    pub fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    /// Returns the application data.
    #[must_use]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Consumes self and returns the application data.
    #[must_use]
    pub fn into_data(self) -> Bytes {
        self.data
    }

    /// Encodes the Data indication to bytes.
    ///
    /// ## RFC 5766 §12
    ///
    /// The Data indication uses method 0x0007 with class Indication (0x10).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn encode(&self) -> TurnResult<Bytes> {
        let mut transaction_id = [0u8; 12];
        uc_crypto::random::fill_random(&mut transaction_id).map_err(|_| {
            TurnError::InvalidRequest {
                reason: "failed to generate transaction ID".to_string(),
            }
        })?;

        let msg_type = StunMessageType::new(StunMethod::Data, StunClass::Indication);

        // Encode XOR-PEER-ADDRESS
        let peer_attr = TurnAttribute::XorPeerAddress(self.peer_address);
        let peer_bytes = peer_attr.encode(&transaction_id);

        // Encode DATA
        let data_attr = TurnAttribute::Data(self.data.clone());
        let data_bytes = data_attr.encode(&transaction_id);

        // Build message
        let mut buf = BytesMut::new();

        // STUN header
        buf.put_u16(msg_type.to_u16());
        let length_pos = buf.len();
        buf.put_u16(0);
        buf.put_u32(proto_stun::MAGIC_COOKIE);
        buf.put_slice(&transaction_id);

        // Attributes
        buf.put_slice(&peer_bytes);
        buf.put_slice(&data_bytes);

        // Update length
        let length = (buf.len() - 20) as u16;
        buf[length_pos] = (length >> 8) as u8;
        buf[length_pos + 1] = length as u8;

        Ok(buf.freeze())
    }

    /// Parses a Data indication from a STUN message.
    ///
    /// ## Errors
    ///
    /// Returns an error if required attributes are missing.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(msg: &StunMessage, raw_data: &[u8]) -> TurnResult<Self> {
        if msg.msg_type.method != StunMethod::Data {
            return Err(TurnError::InvalidRequest {
                reason: "not a Data indication".to_string(),
            });
        }

        if msg.msg_type.class != StunClass::Indication {
            return Err(TurnError::InvalidRequest {
                reason: "not an indication class".to_string(),
            });
        }

        // Parse TURN attributes from raw data
        let mut peer_address: Option<SocketAddr> = None;
        let mut data: Option<Bytes> = None;

        // Skip STUN header (20 bytes) and parse attributes
        let attrs_data = &raw_data[20..];
        let mut offset = 0;

        while offset + 4 <= attrs_data.len() {
            let attr_type = u16::from_be_bytes([attrs_data[offset], attrs_data[offset + 1]]);
            let attr_len =
                u16::from_be_bytes([attrs_data[offset + 2], attrs_data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > attrs_data.len() {
                break;
            }

            let attr_value = &attrs_data[offset..offset + attr_len];

            if let Some(turn_attr) =
                TurnAttribute::parse(attr_type, attr_value, &msg.transaction_id)?
            {
                match turn_attr {
                    TurnAttribute::XorPeerAddress(addr) => peer_address = Some(addr),
                    TurnAttribute::Data(d) => data = Some(d),
                    _ => {}
                }
            }

            // Move to next attribute (with padding)
            offset += (attr_len + 3) & !3;
        }

        let peer_address = peer_address.ok_or_else(|| TurnError::InvalidRequest {
            reason: "missing XOR-PEER-ADDRESS".to_string(),
        })?;

        let data = data.ok_or_else(|| TurnError::InvalidRequest {
            reason: "missing DATA attribute".to_string(),
        })?;

        Ok(Self { peer_address, data })
    }
}

/// Detects if a STUN message is a Send or Data indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicationType {
    /// Send indication (client to server).
    Send,
    /// Data indication (server to client).
    Data,
    /// Not an indication.
    None,
}

impl IndicationType {
    /// Detects the indication type from a STUN message.
    pub fn detect(msg: &StunMessage) -> Self {
        if msg.msg_type.class != StunClass::Indication {
            return Self::None;
        }

        match msg.msg_type.method {
            StunMethod::Send => Self::Send,
            StunMethod::Data => Self::Data,
            _ => Self::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_send_indication_creation() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let data = Bytes::from_static(b"Hello, peer!");

        let send = SendIndication::new(peer, data.clone()).unwrap();
        assert_eq!(send.peer_address(), peer);
        assert_eq!(send.data(), &data);
        assert!(!send.dont_fragment());
    }

    #[test]
    fn test_send_indication_with_dont_fragment() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let data = Bytes::from_static(b"Hello!");

        let send = SendIndication::new(peer, data)
            .unwrap()
            .with_dont_fragment(true);
        assert!(send.dont_fragment());
    }

    #[test]
    fn test_send_indication_data_too_large() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let data = Bytes::from(vec![0u8; MAX_INDICATION_DATA_SIZE + 1]);

        let result = SendIndication::new(peer, data);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_indication_encode() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let data = Bytes::from_static(b"Test data");

        let send = SendIndication::new(peer, data).unwrap();
        let encoded = send.encode().unwrap();

        // Verify it's a STUN message with Send method
        assert_eq!(encoded[0] & 0xC0, 0x00); // STUN message
        // Method = Send (0x0006), Class = Indication (0x10)
        // Type = 0x0016
        let msg_type = u16::from_be_bytes([encoded[0], encoded[1]]);
        assert_eq!(msg_type, 0x0016); // Send indication
    }

    #[test]
    fn test_data_indication_creation() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 49152);
        let data = Bytes::from_static(b"Response from peer");

        let data_ind = DataIndication::new(peer, data.clone()).unwrap();
        assert_eq!(data_ind.peer_address(), peer);
        assert_eq!(data_ind.data(), &data);
    }

    #[test]
    fn test_data_indication_encode() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 49152);
        let data = Bytes::from_static(b"Peer data");

        let data_ind = DataIndication::new(peer, data).unwrap();
        let encoded = data_ind.encode().unwrap();

        // Verify it's a STUN message with Data method
        let msg_type = u16::from_be_bytes([encoded[0], encoded[1]]);
        assert_eq!(msg_type, 0x0017); // Data indication
    }

    #[test]
    fn test_indication_type_detection() {
        let transaction_id = [0u8; 12];

        // Send indication
        let send_type = StunMessageType::new(StunMethod::Send, StunClass::Indication);
        let send_msg = StunMessage::new(send_type, transaction_id);
        assert_eq!(IndicationType::detect(&send_msg), IndicationType::Send);

        // Data indication
        let data_type = StunMessageType::new(StunMethod::Data, StunClass::Indication);
        let data_msg = StunMessage::new(data_type, transaction_id);
        assert_eq!(IndicationType::detect(&data_msg), IndicationType::Data);

        // Not an indication (request)
        let req_type = StunMessageType::new(StunMethod::Binding, StunClass::Request);
        let req_msg = StunMessage::new(req_type, transaction_id);
        assert_eq!(IndicationType::detect(&req_msg), IndicationType::None);
    }
}
