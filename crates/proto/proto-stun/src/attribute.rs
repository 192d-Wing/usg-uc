//! STUN attributes per RFC 5389/8489.

use crate::error::{StunError, StunResult};
use crate::MAGIC_COOKIE;
use bytes::{BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// STUN attribute types per RFC 5389/8489.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AttributeType {
    // Comprehension-required (0x0000-0x7FFF)
    /// MAPPED-ADDRESS (deprecated, use XOR-MAPPED-ADDRESS).
    MappedAddress = 0x0001,
    /// USERNAME.
    Username = 0x0006,
    /// MESSAGE-INTEGRITY.
    MessageIntegrity = 0x0008,
    /// ERROR-CODE.
    ErrorCode = 0x0009,
    /// UNKNOWN-ATTRIBUTES.
    UnknownAttributes = 0x000A,
    /// REALM.
    Realm = 0x0014,
    /// NONCE.
    Nonce = 0x0015,
    /// XOR-MAPPED-ADDRESS.
    XorMappedAddress = 0x0020,

    // Comprehension-optional (0x8000-0xFFFF)
    /// SOFTWARE.
    Software = 0x8022,
    /// ALTERNATE-SERVER.
    AlternateServer = 0x8023,
    /// FINGERPRINT.
    Fingerprint = 0x8028,

    // ICE attributes (RFC 5245/8445)
    /// PRIORITY.
    Priority = 0x0024,
    /// USE-CANDIDATE.
    UseCandidate = 0x0025,
    /// ICE-CONTROLLED.
    IceControlled = 0x8029,
    /// ICE-CONTROLLING.
    IceControlling = 0x802A,
}

impl AttributeType {
    /// Creates from u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::MappedAddress),
            0x0006 => Some(Self::Username),
            0x0008 => Some(Self::MessageIntegrity),
            0x0009 => Some(Self::ErrorCode),
            0x000A => Some(Self::UnknownAttributes),
            0x0014 => Some(Self::Realm),
            0x0015 => Some(Self::Nonce),
            0x0020 => Some(Self::XorMappedAddress),
            0x0024 => Some(Self::Priority),
            0x0025 => Some(Self::UseCandidate),
            0x8022 => Some(Self::Software),
            0x8023 => Some(Self::AlternateServer),
            0x8028 => Some(Self::Fingerprint),
            0x8029 => Some(Self::IceControlled),
            0x802A => Some(Self::IceControlling),
            _ => None,
        }
    }

    /// Returns true if this is a comprehension-required attribute.
    pub fn is_comprehension_required(&self) -> bool {
        (*self as u16) < 0x8000
    }
}

/// STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttribute {
    /// XOR-MAPPED-ADDRESS attribute.
    XorMappedAddress(XorMappedAddress),
    /// MAPPED-ADDRESS attribute (legacy).
    MappedAddress(SocketAddr),
    /// USERNAME attribute.
    Username(String),
    /// MESSAGE-INTEGRITY attribute (20 bytes for HMAC-SHA1, 32 for SHA256).
    MessageIntegrity(Vec<u8>),
    /// ERROR-CODE attribute.
    ErrorCode {
        /// Error code (100-699).
        code: u16,
        /// Reason phrase.
        reason: String,
    },
    /// REALM attribute.
    Realm(String),
    /// NONCE attribute.
    Nonce(String),
    /// SOFTWARE attribute.
    Software(String),
    /// FINGERPRINT attribute (CRC32).
    Fingerprint(u32),
    /// PRIORITY attribute (ICE).
    Priority(u32),
    /// USE-CANDIDATE attribute (ICE, no value).
    UseCandidate,
    /// ICE-CONTROLLED attribute.
    IceControlled(u64),
    /// ICE-CONTROLLING attribute.
    IceControlling(u64),
    /// Unknown attribute (type + raw bytes).
    Unknown {
        /// Attribute type.
        attr_type: u16,
        /// Raw value bytes.
        value: Bytes,
    },
}

impl StunAttribute {
    /// Returns the attribute type.
    pub fn attr_type(&self) -> u16 {
        match self {
            Self::XorMappedAddress(_) => AttributeType::XorMappedAddress as u16,
            Self::MappedAddress(_) => AttributeType::MappedAddress as u16,
            Self::Username(_) => AttributeType::Username as u16,
            Self::MessageIntegrity(_) => AttributeType::MessageIntegrity as u16,
            Self::ErrorCode { .. } => AttributeType::ErrorCode as u16,
            Self::Realm(_) => AttributeType::Realm as u16,
            Self::Nonce(_) => AttributeType::Nonce as u16,
            Self::Software(_) => AttributeType::Software as u16,
            Self::Fingerprint(_) => AttributeType::Fingerprint as u16,
            Self::Priority(_) => AttributeType::Priority as u16,
            Self::UseCandidate => AttributeType::UseCandidate as u16,
            Self::IceControlled(_) => AttributeType::IceControlled as u16,
            Self::IceControlling(_) => AttributeType::IceControlling as u16,
            Self::Unknown { attr_type, .. } => *attr_type,
        }
    }

    /// Parses an attribute from bytes.
    ///
    /// The `transaction_id` is needed for XOR operations.
    pub fn parse(data: &[u8], transaction_id: &[u8; 12]) -> StunResult<(Self, usize)> {
        if data.len() < 4 {
            return Err(StunError::InvalidAttribute {
                reason: "attribute header too short".to_string(),
            });
        }

        let attr_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Padded length (4-byte aligned)
        let padded_len = (length + 3) & !3;

        if data.len() < 4 + padded_len {
            return Err(StunError::InvalidAttribute {
                reason: format!("attribute value truncated: need {}, got {}", padded_len, data.len() - 4),
            });
        }

        let value = &data[4..4 + length];
        let attr = Self::parse_value(attr_type, value, transaction_id)?;

        Ok((attr, 4 + padded_len))
    }

    fn parse_value(attr_type: u16, value: &[u8], transaction_id: &[u8; 12]) -> StunResult<Self> {
        match AttributeType::from_u16(attr_type) {
            Some(AttributeType::XorMappedAddress) => {
                let addr = XorMappedAddress::parse(value, transaction_id)?;
                Ok(Self::XorMappedAddress(addr))
            }
            Some(AttributeType::MappedAddress) => {
                let addr = parse_mapped_address(value)?;
                Ok(Self::MappedAddress(addr))
            }
            Some(AttributeType::Username) => {
                let s = String::from_utf8(value.to_vec()).map_err(|_| StunError::InvalidAttribute {
                    reason: "invalid UTF-8 in USERNAME".to_string(),
                })?;
                Ok(Self::Username(s))
            }
            Some(AttributeType::MessageIntegrity) => {
                Ok(Self::MessageIntegrity(value.to_vec()))
            }
            Some(AttributeType::ErrorCode) => {
                if value.len() < 4 {
                    return Err(StunError::InvalidAttribute {
                        reason: "ERROR-CODE too short".to_string(),
                    });
                }
                let class = (value[2] & 0x07) as u16;
                let number = value[3] as u16;
                let code = class * 100 + number;
                let reason = String::from_utf8(value[4..].to_vec()).unwrap_or_default();
                Ok(Self::ErrorCode { code, reason })
            }
            Some(AttributeType::Realm) => {
                let s = String::from_utf8(value.to_vec()).map_err(|_| StunError::InvalidAttribute {
                    reason: "invalid UTF-8 in REALM".to_string(),
                })?;
                Ok(Self::Realm(s))
            }
            Some(AttributeType::Nonce) => {
                let s = String::from_utf8(value.to_vec()).map_err(|_| StunError::InvalidAttribute {
                    reason: "invalid UTF-8 in NONCE".to_string(),
                })?;
                Ok(Self::Nonce(s))
            }
            Some(AttributeType::Software) => {
                let s = String::from_utf8(value.to_vec()).map_err(|_| StunError::InvalidAttribute {
                    reason: "invalid UTF-8 in SOFTWARE".to_string(),
                })?;
                Ok(Self::Software(s))
            }
            Some(AttributeType::Fingerprint) => {
                if value.len() != 4 {
                    return Err(StunError::InvalidAttribute {
                        reason: "FINGERPRINT must be 4 bytes".to_string(),
                    });
                }
                let fp = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                Ok(Self::Fingerprint(fp))
            }
            Some(AttributeType::Priority) => {
                if value.len() != 4 {
                    return Err(StunError::InvalidAttribute {
                        reason: "PRIORITY must be 4 bytes".to_string(),
                    });
                }
                let priority = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                Ok(Self::Priority(priority))
            }
            Some(AttributeType::UseCandidate) => {
                Ok(Self::UseCandidate)
            }
            Some(AttributeType::IceControlled) => {
                if value.len() != 8 {
                    return Err(StunError::InvalidAttribute {
                        reason: "ICE-CONTROLLED must be 8 bytes".to_string(),
                    });
                }
                let tie_breaker = u64::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                ]);
                Ok(Self::IceControlled(tie_breaker))
            }
            Some(AttributeType::IceControlling) => {
                if value.len() != 8 {
                    return Err(StunError::InvalidAttribute {
                        reason: "ICE-CONTROLLING must be 8 bytes".to_string(),
                    });
                }
                let tie_breaker = u64::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                ]);
                Ok(Self::IceControlling(tie_breaker))
            }
            _ => {
                // Unknown attribute - check if comprehension-required
                if attr_type < 0x8000 {
                    return Err(StunError::UnknownRequiredAttribute { attr_type });
                }
                Ok(Self::Unknown {
                    attr_type,
                    value: Bytes::copy_from_slice(value),
                })
            }
        }
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
            Self::XorMappedAddress(addr) => {
                return addr.encode(transaction_id);
            }
            Self::MappedAddress(addr) => {
                buf.put_u8(0); // Reserved
                match addr {
                    SocketAddr::V4(v4) => {
                        buf.put_u8(0x01); // IPv4 family
                        buf.put_u16(v4.port());
                        buf.put_slice(&v4.ip().octets());
                    }
                    SocketAddr::V6(v6) => {
                        buf.put_u8(0x02); // IPv6 family
                        buf.put_u16(v6.port());
                        buf.put_slice(&v6.ip().octets());
                    }
                }
            }
            Self::Username(s) => {
                buf.put_slice(s.as_bytes());
            }
            Self::MessageIntegrity(hmac) => {
                buf.put_slice(hmac);
            }
            Self::ErrorCode { code, reason } => {
                buf.put_u16(0); // Reserved
                buf.put_u8((code / 100) as u8);
                buf.put_u8((code % 100) as u8);
                buf.put_slice(reason.as_bytes());
            }
            Self::Realm(s) | Self::Nonce(s) | Self::Software(s) => {
                buf.put_slice(s.as_bytes());
            }
            Self::Fingerprint(fp) => {
                buf.put_u32(*fp);
            }
            Self::Priority(p) => {
                buf.put_u32(*p);
            }
            Self::UseCandidate => {
                // No value
            }
            Self::IceControlled(tb) | Self::IceControlling(tb) => {
                buf.put_u64(*tb);
            }
            Self::Unknown { value, .. } => {
                buf.put(value.clone());
            }
        }

        buf.freeze()
    }
}

/// XOR-MAPPED-ADDRESS attribute.
///
/// Contains the reflexive transport address XORed with the magic cookie
/// and transaction ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XorMappedAddress {
    /// The address (after XOR decode).
    pub addr: SocketAddr,
}

impl XorMappedAddress {
    /// Creates a new XOR-MAPPED-ADDRESS.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Parses from raw bytes.
    pub fn parse(data: &[u8], transaction_id: &[u8; 12]) -> StunResult<Self> {
        if data.len() < 4 {
            return Err(StunError::InvalidAttribute {
                reason: "XOR-MAPPED-ADDRESS too short".to_string(),
            });
        }

        let family = data[1];
        let x_port = u16::from_be_bytes([data[2], data[3]]);
        let port = x_port ^ ((MAGIC_COOKIE >> 16) as u16);

        let addr = match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return Err(StunError::InvalidAttribute {
                        reason: "XOR-MAPPED-ADDRESS IPv4 too short".to_string(),
                    });
                }
                let x_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let addr = x_addr ^ MAGIC_COOKIE;
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port)
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(StunError::InvalidAttribute {
                        reason: "XOR-MAPPED-ADDRESS IPv6 too short".to_string(),
                    });
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);

                // XOR with magic cookie + transaction ID
                let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    octets[i] ^= cookie_bytes[i];
                }
                for i in 0..12 {
                    octets[4 + i] ^= transaction_id[i];
                }

                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
            }
            _ => {
                return Err(StunError::InvalidAttribute {
                    reason: format!("unknown address family: {family}"),
                });
            }
        };

        Ok(Self { addr })
    }

    /// Encodes to bytes.
    pub fn encode(&self, transaction_id: &[u8; 12]) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(0); // Reserved

        let x_port = self.addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);

        match self.addr {
            SocketAddr::V4(v4) => {
                buf.put_u8(0x01); // IPv4 family
                buf.put_u16(x_port);
                let x_addr = u32::from_be_bytes(v4.ip().octets()) ^ MAGIC_COOKIE;
                buf.put_u32(x_addr);
            }
            SocketAddr::V6(v6) => {
                buf.put_u8(0x02); // IPv6 family
                buf.put_u16(x_port);

                let mut octets = v6.ip().octets();
                let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
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
}

/// Parses a MAPPED-ADDRESS attribute (non-XOR).
fn parse_mapped_address(data: &[u8]) -> StunResult<SocketAddr> {
    if data.len() < 4 {
        return Err(StunError::InvalidAttribute {
            reason: "MAPPED-ADDRESS too short".to_string(),
        });
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            if data.len() < 8 {
                return Err(StunError::InvalidAttribute {
                    reason: "MAPPED-ADDRESS IPv4 too short".to_string(),
                });
            }
            let addr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(IpAddr::V4(addr), port))
        }
        0x02 => {
            if data.len() < 20 {
                return Err(StunError::InvalidAttribute {
                    reason: "MAPPED-ADDRESS IPv6 too short".to_string(),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(StunError::InvalidAttribute {
            reason: format!("unknown address family: {family}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_mapped_address_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let xma = XorMappedAddress::new(addr);
        let transaction_id = [0u8; 12];

        let encoded = xma.encode(&transaction_id);
        let parsed = XorMappedAddress::parse(&encoded, &transaction_id).unwrap();

        assert_eq!(parsed.addr, addr);
    }

    #[test]
    fn test_xor_mapped_address_ipv6() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            5060,
        );
        let xma = XorMappedAddress::new(addr);
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let encoded = xma.encode(&transaction_id);
        let parsed = XorMappedAddress::parse(&encoded, &transaction_id).unwrap();

        assert_eq!(parsed.addr, addr);
    }

    #[test]
    fn test_attribute_roundtrip() {
        let transaction_id = [0u8; 12];
        let attr = StunAttribute::Username("alice:bob".to_string());

        let encoded = attr.encode(&transaction_id);
        let (parsed, _) = StunAttribute::parse(&encoded, &transaction_id).unwrap();

        assert_eq!(parsed, attr);
    }

    #[test]
    fn test_priority_attribute() {
        let transaction_id = [0u8; 12];
        let attr = StunAttribute::Priority(0x6E0001FF);

        let encoded = attr.encode(&transaction_id);
        let (parsed, _) = StunAttribute::parse(&encoded, &transaction_id).unwrap();

        if let StunAttribute::Priority(p) = parsed {
            assert_eq!(p, 0x6E0001FF);
        } else {
            panic!("Expected Priority attribute");
        }
    }

    #[test]
    fn test_error_code_attribute() {
        let transaction_id = [0u8; 12];
        let attr = StunAttribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".to_string(),
        };

        let encoded = attr.encode(&transaction_id);
        let (parsed, _) = StunAttribute::parse(&encoded, &transaction_id).unwrap();

        if let StunAttribute::ErrorCode { code, reason } = parsed {
            assert_eq!(code, 401);
            assert_eq!(reason, "Unauthorized");
        } else {
            panic!("Expected ErrorCode attribute");
        }
    }
}
