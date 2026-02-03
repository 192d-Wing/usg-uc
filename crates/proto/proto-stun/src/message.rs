//! STUN message parsing and generation.

use crate::attribute::StunAttribute;
use crate::error::{StunError, StunResult};
use crate::{FINGERPRINT_XOR, HEADER_SIZE, MAGIC_COOKIE};
use bytes::{BufMut, Bytes, BytesMut};

/// STUN method types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StunMethod {
    /// Binding method (RFC 5389).
    Binding = 0x0001,
    /// Allocate (TURN, RFC 5766).
    Allocate = 0x0003,
    /// Refresh (TURN).
    Refresh = 0x0004,
    /// Send (TURN).
    Send = 0x0006,
    /// Data (TURN).
    Data = 0x0007,
    /// CreatePermission (TURN).
    CreatePermission = 0x0008,
    /// ChannelBind (TURN).
    ChannelBind = 0x0009,
}

impl StunMethod {
    /// Creates from the method bits of the message type.
    pub fn from_u16(value: u16) -> Option<Self> {
        // Extract method bits: M0-M3 from bits 0-3, M4-M11 from bits 5-8 and 9-11
        let m = (value & 0x000F) | ((value >> 1) & 0x0070) | ((value >> 2) & 0x0F80);
        match m {
            0x0001 => Some(Self::Binding),
            0x0003 => Some(Self::Allocate),
            0x0004 => Some(Self::Refresh),
            0x0006 => Some(Self::Send),
            0x0007 => Some(Self::Data),
            0x0008 => Some(Self::CreatePermission),
            0x0009 => Some(Self::ChannelBind),
            _ => None,
        }
    }
}

/// STUN message class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StunClass {
    /// Request (0b00).
    Request,
    /// Indication (0b01).
    Indication,
    /// Success Response (0b10).
    SuccessResponse,
    /// Error Response (0b11).
    ErrorResponse,
}

impl StunClass {
    /// Creates from the class bits of the message type.
    fn from_bits(c0: bool, c1: bool) -> Self {
        match (c1, c0) {
            (false, false) => Self::Request,
            (false, true) => Self::Indication,
            (true, false) => Self::SuccessResponse,
            (true, true) => Self::ErrorResponse,
        }
    }

    /// Returns the class bits.
    fn to_bits(self) -> (bool, bool) {
        match self {
            Self::Request => (false, false),
            Self::Indication => (false, true),
            Self::SuccessResponse => (true, false),
            Self::ErrorResponse => (true, true),
        }
    }
}

/// STUN message type (method + class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StunMessageType {
    /// Method.
    pub method: StunMethod,
    /// Class.
    pub class: StunClass,
}

impl StunMessageType {
    /// Creates a new message type.
    pub fn new(method: StunMethod, class: StunClass) -> Self {
        Self { method, class }
    }

    /// Binding Request.
    pub fn binding_request() -> Self {
        Self::new(StunMethod::Binding, StunClass::Request)
    }

    /// Binding Response (success).
    pub fn binding_response() -> Self {
        Self::new(StunMethod::Binding, StunClass::SuccessResponse)
    }

    /// Binding Error Response.
    pub fn binding_error() -> Self {
        Self::new(StunMethod::Binding, StunClass::ErrorResponse)
    }

    /// Parses from the 16-bit message type field.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_u16(value: u16) -> StunResult<Self> {
        // Class bits: C0 at bit 4, C1 at bit 8
        let c0 = (value & 0x0010) != 0;
        let c1 = (value & 0x0100) != 0;
        let class = StunClass::from_bits(c0, c1);

        let method = StunMethod::from_u16(value).ok_or_else(|| StunError::InvalidMessage {
            reason: format!("unknown method in message type: {value:#06x}"),
        })?;

        Ok(Self { method, class })
    }

    /// Encodes to the 16-bit message type field.
    pub fn to_u16(self) -> u16 {
        let method = self.method as u16;
        let (c1, c0) = self.class.to_bits();

        // Encode method bits: M0-M3 at bits 0-3, M4-M6 at bits 5-7, M7-M11 at bits 9-13
        let m0_3 = method & 0x000F;
        let m4_6 = (method & 0x0070) << 1;
        let m7_11 = (method & 0x0F80) << 2;

        let c0_bit = if c0 { 0x0010 } else { 0 };
        let c1_bit = if c1 { 0x0100 } else { 0 };

        m0_3 | m4_6 | m7_11 | c0_bit | c1_bit
    }
}

/// STUN message.
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message type (method + class).
    pub msg_type: StunMessageType,
    /// 96-bit transaction ID.
    pub transaction_id: [u8; 12],
    /// Message attributes.
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    /// Creates a new STUN message.
    pub fn new(msg_type: StunMessageType, transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Creates a Binding Request with a random transaction ID.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn binding_request() -> StunResult<Self> {
        let mut transaction_id = [0u8; 12];
        uc_crypto::random::fill_random(&mut transaction_id).map_err(|_| {
            StunError::InvalidMessage {
                reason: "failed to generate transaction ID".to_string(),
            }
        })?;

        Ok(Self::new(
            StunMessageType::binding_request(),
            transaction_id,
        ))
    }

    /// Creates a Binding Response for a request.
    pub fn binding_response(request: &StunMessage) -> Self {
        Self::new(StunMessageType::binding_response(), request.transaction_id)
    }

    /// Creates a Binding Error Response.
    pub fn binding_error(request: &StunMessage, code: u16, reason: &str) -> Self {
        let mut msg = Self::new(StunMessageType::binding_error(), request.transaction_id);
        msg.attributes.push(StunAttribute::ErrorCode {
            code,
            reason: reason.to_string(),
        });
        msg
    }

    /// Adds an attribute.
    pub fn add_attribute(&mut self, attr: StunAttribute) {
        self.attributes.push(attr);
    }

    /// Gets an attribute by type.
    pub fn get_attribute(&self, attr_type: u16) -> Option<&StunAttribute> {
        self.attributes.iter().find(|a| a.attr_type() == attr_type)
    }

    /// Returns the XOR-MAPPED-ADDRESS if present.
    pub fn xor_mapped_address(&self) -> Option<std::net::SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::XorMappedAddress(xma) = attr {
                return Some(xma.addr);
            }
        }
        None
    }

    /// Parses a STUN message from bytes.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> StunResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(StunError::MessageTooShort {
                need: HEADER_SIZE,
                got: data.len(),
            });
        }

        // Check first two bits are 00 (distinguishes from RTP/RTCP)
        if (data[0] & 0xC0) != 0 {
            return Err(StunError::InvalidMessage {
                reason: "first two bits must be 00".to_string(),
            });
        }

        let msg_type_value = u16::from_be_bytes([data[0], data[1]]);
        let msg_type = StunMessageType::from_u16(msg_type_value)?;

        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if cookie != MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie { got: cookie });
        }

        // Length must be multiple of 4
        if !length.is_multiple_of(4) {
            return Err(StunError::InvalidMessage {
                reason: "message length not multiple of 4".to_string(),
            });
        }

        if data.len() < HEADER_SIZE + length {
            return Err(StunError::MessageTooShort {
                need: HEADER_SIZE + length,
                got: data.len(),
            });
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = HEADER_SIZE;
        let end = HEADER_SIZE + length;

        while offset < end {
            let (attr, consumed) = StunAttribute::parse(&data[offset..end], &transaction_id)?;
            attributes.push(attr);
            offset += consumed;
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
        })
    }

    /// Encodes the message to bytes.
    pub fn encode(&self) -> Bytes {
        let mut attrs = BytesMut::new();
        for attr in &self.attributes {
            attrs.put(attr.encode(&self.transaction_id));
        }

        let mut buf = BytesMut::with_capacity(HEADER_SIZE + attrs.len());

        // Message type
        buf.put_u16(self.msg_type.to_u16());

        // Message length (excludes 20-byte header)
        buf.put_u16(attrs.len() as u16);

        // Magic cookie
        buf.put_u32(MAGIC_COOKIE);

        // Transaction ID
        buf.put_slice(&self.transaction_id);

        // Attributes
        buf.put(attrs);

        buf.freeze()
    }

    /// Encodes with MESSAGE-INTEGRITY attribute.
    ///
    /// The key should be derived from the password per RFC 5389.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn encode_with_integrity(&self, key: &[u8]) -> StunResult<Bytes> {
        let mut msg = self.clone();

        // Encode without integrity to compute HMAC
        let partial = msg.encode();

        // Compute HMAC-SHA1 (RFC 5389 uses SHA1, but we could use SHA256 for ICE)
        // For now, use SHA384 for CNSA compliance in long-term credentials
        let hmac = compute_hmac_sha384(key, &partial);

        // Truncate to 20 bytes for compatibility (HMAC-SHA1 length)
        msg.attributes
            .push(StunAttribute::MessageIntegrity(hmac[..20].to_vec()));

        Ok(msg.encode())
    }

    /// Encodes with FINGERPRINT attribute.
    ///
    /// Per RFC 5389, the FINGERPRINT is computed over the entire message
    /// including the header, but with the length field adjusted to include
    /// the FINGERPRINT attribute (8 bytes).
    pub fn encode_with_fingerprint(&self) -> Bytes {
        // First encode without fingerprint
        let partial = self.encode();

        // Create buffer with adjusted length for fingerprint (add 8 bytes)
        let mut adjusted = BytesMut::from(partial.as_ref());
        // Adjust the length field at bytes 2-3
        let old_len = u16::from_be_bytes([adjusted[2], adjusted[3]]);
        let new_len = old_len + 8; // FINGERPRINT attribute is 8 bytes
        adjusted[2] = (new_len >> 8) as u8;
        adjusted[3] = new_len as u8;

        // Compute CRC32 over the adjusted message
        let crc = compute_crc32(&adjusted);
        let fingerprint = crc ^ FINGERPRINT_XOR;

        // Now encode with the fingerprint attribute
        let mut msg = self.clone();
        msg.attributes.push(StunAttribute::Fingerprint(fingerprint));
        msg.encode()
    }

    /// Verifies the FINGERPRINT attribute if present.
    ///
    /// Per RFC 5389, the FINGERPRINT is computed over the message
    /// up to (but not including) the FINGERPRINT attribute, with
    /// the length field as it appears in the actual message.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn verify_fingerprint(&self, raw_data: &[u8]) -> StunResult<bool> {
        // Find fingerprint attribute
        let fp_attr = self
            .attributes
            .iter()
            .find(|a| matches!(a, StunAttribute::Fingerprint(_)));

        let Some(StunAttribute::Fingerprint(received_fp)) = fp_attr else {
            return Ok(true); // No fingerprint to verify
        };

        if raw_data.len() < HEADER_SIZE + 8 {
            return Ok(false);
        }

        // FINGERPRINT attribute is 8 bytes (4 header + 4 value)
        let fp_offset = raw_data.len() - 8;

        // Compute CRC32 over message up to (but not including) FINGERPRINT
        let crc = compute_crc32(&raw_data[..fp_offset]);
        let expected_fp = crc ^ FINGERPRINT_XOR;

        Ok(*received_fp == expected_fp)
    }
}

/// Computes HMAC-SHA384 (CNSA 2.0 compliant).
fn compute_hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    uc_crypto::hash::hmac_sha384(key, data)
}

/// Computes CRC32 for fingerprint.
fn compute_crc32(data: &[u8]) -> u32 {
    // CRC32 per RFC 5389 (ISO 3309 polynomial)
    const CRC_TABLE: [u32; 256] = generate_crc_table();
    let mut crc: u32 = 0xFFFFFFFF;

    for byte in data {
        let index = ((crc ^ (*byte as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[index];
    }

    !crc
}

/// Generates CRC32 lookup table at compile time.
const fn generate_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::XorMappedAddress;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_message_type_encoding() {
        let mt = StunMessageType::binding_request();
        assert_eq!(mt.to_u16(), 0x0001);

        let mt = StunMessageType::binding_response();
        assert_eq!(mt.to_u16(), 0x0101);

        let mt = StunMessageType::binding_error();
        assert_eq!(mt.to_u16(), 0x0111);
    }

    #[test]
    fn test_message_type_parsing() {
        let mt = StunMessageType::from_u16(0x0001).unwrap();
        assert_eq!(mt.method, StunMethod::Binding);
        assert_eq!(mt.class, StunClass::Request);

        let mt = StunMessageType::from_u16(0x0101).unwrap();
        assert_eq!(mt.method, StunMethod::Binding);
        assert_eq!(mt.class, StunClass::SuccessResponse);
    }

    #[test]
    fn test_binding_request_roundtrip() {
        let mut msg = StunMessage::binding_request().unwrap();
        msg.add_attribute(StunAttribute::Software("test-agent/1.0".to_string()));

        let encoded = msg.encode();
        let parsed = StunMessage::parse(&encoded).unwrap();

        assert_eq!(parsed.msg_type, msg.msg_type);
        assert_eq!(parsed.transaction_id, msg.transaction_id);
        assert_eq!(parsed.attributes.len(), 1);
    }

    #[test]
    fn test_binding_response_with_xor_mapped_address() {
        let request = StunMessage::binding_request().unwrap();
        let mut response = StunMessage::binding_response(&request);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 32853);
        response.add_attribute(StunAttribute::XorMappedAddress(XorMappedAddress::new(addr)));

        let encoded = response.encode();
        let parsed = StunMessage::parse(&encoded).unwrap();

        assert_eq!(parsed.xor_mapped_address(), Some(addr));
    }

    #[test]
    fn test_fingerprint() {
        let mut msg = StunMessage::binding_request().unwrap();
        msg.add_attribute(StunAttribute::Software("test".to_string()));

        let encoded = msg.encode_with_fingerprint();
        let parsed = StunMessage::parse(&encoded).unwrap();

        assert!(parsed.verify_fingerprint(&encoded).unwrap());
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut data = vec![0u8; 20];
        data[0] = 0x00;
        data[1] = 0x01; // Binding request
        // Wrong magic cookie
        data[4] = 0x12;
        data[5] = 0x34;
        data[6] = 0x56;
        data[7] = 0x78;

        let result = StunMessage::parse(&data);
        assert!(matches!(result, Err(StunError::InvalidMagicCookie { .. })));
    }

    #[test]
    fn test_crc32() {
        // Test vector
        let data = b"123456789";
        let crc = compute_crc32(data);
        assert_eq!(crc, 0xCBF43926);
    }
}
