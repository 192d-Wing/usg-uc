//! TURN-specific STUN attributes per RFC 5766.

use crate::error::{TurnError, TurnResult};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// TURN attribute types per RFC 5766/8656.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TurnAttributeType {
    /// CHANNEL-NUMBER.
    ChannelNumber = 0x000C,
    /// LIFETIME.
    Lifetime = 0x000D,
    /// XOR-PEER-ADDRESS.
    XorPeerAddress = 0x0012,
    /// DATA.
    Data = 0x0013,
    /// XOR-RELAYED-ADDRESS.
    XorRelayedAddress = 0x0016,
    /// REQUESTED-ADDRESS-FAMILY (RFC 6156).
    RequestedAddressFamily = 0x0017,
    /// EVEN-PORT.
    EvenPort = 0x0018,
    /// REQUESTED-TRANSPORT.
    RequestedTransport = 0x0019,
    /// DONT-FRAGMENT.
    DontFragment = 0x001A,
    /// RESERVATION-TOKEN.
    ReservationToken = 0x0022,
    /// ADDITIONAL-ADDRESS-FAMILY (RFC 8656).
    AdditionalAddressFamily = 0x8000,
}

impl TurnAttributeType {
    /// Creates from u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x000C => Some(Self::ChannelNumber),
            0x000D => Some(Self::Lifetime),
            0x0012 => Some(Self::XorPeerAddress),
            0x0013 => Some(Self::Data),
            0x0016 => Some(Self::XorRelayedAddress),
            0x0017 => Some(Self::RequestedAddressFamily),
            0x0018 => Some(Self::EvenPort),
            0x0019 => Some(Self::RequestedTransport),
            0x001A => Some(Self::DontFragment),
            0x0022 => Some(Self::ReservationToken),
            0x8000 => Some(Self::AdditionalAddressFamily),
            _ => None,
        }
    }
}

/// Address family for TURN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4.
    IPv4 = 0x01,
    /// IPv6.
    IPv6 = 0x02,
}

impl AddressFamily {
    /// Creates from byte value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::IPv4),
            0x02 => Some(Self::IPv6),
            _ => None,
        }
    }
}

/// Transport protocol for TURN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// UDP (17).
    Udp = 17,
    /// TCP (6).
    Tcp = 6,
}

impl TransportProtocol {
    /// Creates from IANA protocol number.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            17 => Some(Self::Udp),
            6 => Some(Self::Tcp),
            _ => None,
        }
    }
}

/// TURN-specific STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnAttribute {
    /// CHANNEL-NUMBER attribute.
    ChannelNumber(u16),
    /// LIFETIME attribute (seconds).
    Lifetime(u32),
    /// XOR-PEER-ADDRESS attribute.
    XorPeerAddress(SocketAddr),
    /// DATA attribute.
    Data(Bytes),
    /// XOR-RELAYED-ADDRESS attribute.
    XorRelayedAddress(SocketAddr),
    /// REQUESTED-ADDRESS-FAMILY attribute.
    RequestedAddressFamily(AddressFamily),
    /// EVEN-PORT attribute.
    EvenPort {
        /// Reserve next higher port.
        reserve_pair: bool,
    },
    /// REQUESTED-TRANSPORT attribute.
    RequestedTransport(TransportProtocol),
    /// DONT-FRAGMENT attribute.
    DontFragment,
    /// RESERVATION-TOKEN attribute.
    ReservationToken([u8; 8]),
}

impl TurnAttribute {
    /// Returns the attribute type.
    pub fn attr_type(&self) -> u16 {
        match self {
            Self::ChannelNumber(_) => TurnAttributeType::ChannelNumber as u16,
            Self::Lifetime(_) => TurnAttributeType::Lifetime as u16,
            Self::XorPeerAddress(_) => TurnAttributeType::XorPeerAddress as u16,
            Self::Data(_) => TurnAttributeType::Data as u16,
            Self::XorRelayedAddress(_) => TurnAttributeType::XorRelayedAddress as u16,
            Self::RequestedAddressFamily(_) => TurnAttributeType::RequestedAddressFamily as u16,
            Self::EvenPort { .. } => TurnAttributeType::EvenPort as u16,
            Self::RequestedTransport(_) => TurnAttributeType::RequestedTransport as u16,
            Self::DontFragment => TurnAttributeType::DontFragment as u16,
            Self::ReservationToken(_) => TurnAttributeType::ReservationToken as u16,
        }
    }

    /// Parses a TURN attribute from bytes.
    pub fn parse(
        attr_type: u16,
        value: &[u8],
        transaction_id: &[u8; 12],
    ) -> TurnResult<Option<Self>> {
        let Some(turn_type) = TurnAttributeType::from_u16(attr_type) else {
            return Ok(None); // Not a TURN attribute
        };

        let attr = match turn_type {
            TurnAttributeType::ChannelNumber => {
                if value.len() < 4 {
                    return Err(TurnError::InvalidRequest {
                        reason: "CHANNEL-NUMBER too short".to_string(),
                    });
                }
                let channel = u16::from_be_bytes([value[0], value[1]]);
                Self::ChannelNumber(channel)
            }
            TurnAttributeType::Lifetime => {
                if value.len() < 4 {
                    return Err(TurnError::InvalidRequest {
                        reason: "LIFETIME too short".to_string(),
                    });
                }
                let lifetime = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                Self::Lifetime(lifetime)
            }
            TurnAttributeType::XorPeerAddress | TurnAttributeType::XorRelayedAddress => {
                let addr = parse_xor_address(value, transaction_id)?;
                if turn_type == TurnAttributeType::XorPeerAddress {
                    Self::XorPeerAddress(addr)
                } else {
                    Self::XorRelayedAddress(addr)
                }
            }
            TurnAttributeType::Data => Self::Data(Bytes::copy_from_slice(value)),
            TurnAttributeType::RequestedAddressFamily => {
                if value.is_empty() {
                    return Err(TurnError::InvalidRequest {
                        reason: "REQUESTED-ADDRESS-FAMILY too short".to_string(),
                    });
                }
                let family =
                    AddressFamily::from_u8(value[0]).ok_or_else(|| TurnError::InvalidRequest {
                        reason: format!("unknown address family: {}", value[0]),
                    })?;
                Self::RequestedAddressFamily(family)
            }
            TurnAttributeType::EvenPort => {
                let reserve_pair = !value.is_empty() && (value[0] & 0x80) != 0;
                Self::EvenPort { reserve_pair }
            }
            TurnAttributeType::RequestedTransport => {
                if value.is_empty() {
                    return Err(TurnError::InvalidRequest {
                        reason: "REQUESTED-TRANSPORT too short".to_string(),
                    });
                }
                let proto = TransportProtocol::from_u8(value[0]).ok_or_else(|| {
                    TurnError::InvalidRequest {
                        reason: format!("unsupported transport: {}", value[0]),
                    }
                })?;
                Self::RequestedTransport(proto)
            }
            TurnAttributeType::DontFragment => Self::DontFragment,
            TurnAttributeType::ReservationToken => {
                if value.len() < 8 {
                    return Err(TurnError::InvalidRequest {
                        reason: "RESERVATION-TOKEN too short".to_string(),
                    });
                }
                let mut token = [0u8; 8];
                token.copy_from_slice(&value[..8]);
                Self::ReservationToken(token)
            }
            TurnAttributeType::AdditionalAddressFamily => {
                return Ok(None); // Skip for now
            }
        };

        Ok(Some(attr))
    }

    /// Encodes the attribute to bytes.
    pub fn encode(&self, transaction_id: &[u8; 12]) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u16(self.attr_type());

        let value = self.encode_value(transaction_id);
        buf.put_u16(value.len() as u16);
        buf.put(value.as_ref());

        // Pad to 4-byte boundary
        let padding = (4 - (value.len() % 4)) % 4;
        for _ in 0..padding {
            buf.put_u8(0);
        }

        buf.freeze()
    }

    fn encode_value(&self, transaction_id: &[u8; 12]) -> Bytes {
        let mut buf = BytesMut::new();

        match self {
            Self::ChannelNumber(channel) => {
                buf.put_u16(*channel);
                buf.put_u16(0); // RFFU
            }
            Self::Lifetime(lifetime) => {
                buf.put_u32(*lifetime);
            }
            Self::XorPeerAddress(addr) | Self::XorRelayedAddress(addr) => {
                return encode_xor_address(addr, transaction_id);
            }
            Self::Data(data) => {
                buf.put(data.clone());
            }
            Self::RequestedAddressFamily(family) => {
                buf.put_u8(*family as u8);
                buf.put_u8(0); // RFFU
                buf.put_u16(0); // RFFU
            }
            Self::EvenPort { reserve_pair } => {
                let byte = if *reserve_pair { 0x80 } else { 0x00 };
                buf.put_u8(byte);
                buf.put_u8(0);
                buf.put_u16(0);
            }
            Self::RequestedTransport(proto) => {
                buf.put_u8(*proto as u8);
                buf.put_u8(0);
                buf.put_u16(0);
            }
            Self::DontFragment => {
                // No value
            }
            Self::ReservationToken(token) => {
                buf.put_slice(token);
            }
        }

        buf.freeze()
    }
}

/// Parses a XOR-encoded address.
fn parse_xor_address(data: &[u8], transaction_id: &[u8; 12]) -> TurnResult<SocketAddr> {
    if data.len() < 4 {
        return Err(TurnError::InvalidRequest {
            reason: "XOR address too short".to_string(),
        });
    }

    let family = data[1];
    let x_port = u16::from_be_bytes([data[2], data[3]]);
    let port = x_port ^ ((proto_stun::MAGIC_COOKIE >> 16) as u16);

    let addr = match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return Err(TurnError::InvalidRequest {
                    reason: "XOR IPv4 address too short".to_string(),
                });
            }
            let x_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let addr = x_addr ^ proto_stun::MAGIC_COOKIE;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port)
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(TurnError::InvalidRequest {
                    reason: "XOR IPv6 address too short".to_string(),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);

            // XOR with magic cookie + transaction ID
            let cookie_bytes = proto_stun::MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                octets[i] ^= cookie_bytes[i];
            }
            for i in 0..12 {
                octets[4 + i] ^= transaction_id[i];
            }

            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
        _ => {
            return Err(TurnError::InvalidRequest {
                reason: format!("unknown address family: {family}"),
            });
        }
    };

    Ok(addr)
}

/// Encodes a XOR-encoded address.
fn encode_xor_address(addr: &SocketAddr, transaction_id: &[u8; 12]) -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u8(0); // Reserved

    let x_port = addr.port() ^ ((proto_stun::MAGIC_COOKIE >> 16) as u16);

    match addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(0x01); // IPv4 family
            buf.put_u16(x_port);
            let x_addr = u32::from_be_bytes(v4.ip().octets()) ^ proto_stun::MAGIC_COOKIE;
            buf.put_u32(x_addr);
        }
        SocketAddr::V6(v6) => {
            buf.put_u8(0x02); // IPv6 family
            buf.put_u16(x_port);

            let mut octets = v6.ip().octets();
            let cookie_bytes = proto_stun::MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                octets[i] ^= cookie_bytes[i];
            }
            for i in 0..12 {
                octets[4 + i] ^= transaction_id[i];
            }
            buf.put_slice(&octets);
        }
    }

    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_number_roundtrip() {
        let transaction_id = [0u8; 12];
        let attr = TurnAttribute::ChannelNumber(0x4000);

        let encoded = attr.encode(&transaction_id);
        // Skip type and length (4 bytes), parse value
        let value = &encoded[4..];
        let parsed = TurnAttribute::parse(
            TurnAttributeType::ChannelNumber as u16,
            value,
            &transaction_id,
        )
        .unwrap()
        .unwrap();

        if let TurnAttribute::ChannelNumber(ch) = parsed {
            assert_eq!(ch, 0x4000);
        } else {
            panic!("Expected ChannelNumber");
        }
    }

    #[test]
    fn test_lifetime_attribute() {
        let transaction_id = [0u8; 12];
        let attr = TurnAttribute::Lifetime(600);

        let encoded = attr.encode(&transaction_id);
        let value = &encoded[4..];
        let parsed =
            TurnAttribute::parse(TurnAttributeType::Lifetime as u16, value, &transaction_id)
                .unwrap()
                .unwrap();

        if let TurnAttribute::Lifetime(lt) = parsed {
            assert_eq!(lt, 600);
        } else {
            panic!("Expected Lifetime");
        }
    }

    #[test]
    fn test_xor_peer_address_ipv4() {
        let transaction_id = [0u8; 12];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let attr = TurnAttribute::XorPeerAddress(addr);

        let encoded = attr.encode(&transaction_id);
        let value = &encoded[4..];
        let parsed = TurnAttribute::parse(
            TurnAttributeType::XorPeerAddress as u16,
            value,
            &transaction_id,
        )
        .unwrap()
        .unwrap();

        if let TurnAttribute::XorPeerAddress(parsed_addr) = parsed {
            assert_eq!(parsed_addr, addr);
        } else {
            panic!("Expected XorPeerAddress");
        }
    }

    #[test]
    fn test_requested_transport() {
        let transaction_id = [0u8; 12];
        let attr = TurnAttribute::RequestedTransport(TransportProtocol::Udp);

        let encoded = attr.encode(&transaction_id);
        let value = &encoded[4..];
        let parsed = TurnAttribute::parse(
            TurnAttributeType::RequestedTransport as u16,
            value,
            &transaction_id,
        )
        .unwrap()
        .unwrap();

        if let TurnAttribute::RequestedTransport(proto) = parsed {
            assert_eq!(proto, TransportProtocol::Udp);
        } else {
            panic!("Expected RequestedTransport");
        }
    }
}
