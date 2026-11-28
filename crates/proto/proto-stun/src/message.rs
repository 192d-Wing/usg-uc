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

        // RFC 8489 §14.5/§14.7: attributes after MESSAGE-INTEGRITY other
        // than FINGERPRINT, and anything after FINGERPRINT, are not covered
        // by the integrity check and MUST be ignored.
        let mut seen_integrity = false;
        let mut seen_fingerprint = false;
        while offset < end {
            let (attr, consumed) = StunAttribute::parse(&data[offset..end], &transaction_id)?;
            offset += consumed;
            if seen_fingerprint {
                continue;
            }
            match attr {
                StunAttribute::Fingerprint(_) => seen_fingerprint = true,
                StunAttribute::MessageIntegrity(_) if !seen_integrity => seen_integrity = true,
                _ if seen_integrity => continue,
                _ => {}
            }
            attributes.push(attr);
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

    /// Encodes with a MESSAGE-INTEGRITY attribute (RFC 8489 §14.5).
    ///
    /// The HMAC-SHA1 is computed over the header and every attribute
    /// before MESSAGE-INTEGRITY, with the header length field already
    /// counting the 24-byte MESSAGE-INTEGRITY attribute. For ICE
    /// short-term credentials `key` is the password itself (§9.1.1). Any
    /// MESSAGE-INTEGRITY or FINGERPRINT already in `attributes` is dropped
    /// first.
    ///
    /// CNSA-EXCEPTION: HMAC-SHA1 is mandated by RFC 8489 §14.5 (POA&M-500);
    /// it authenticates the message only.
    ///
    /// ## NIST 800-53 Rev5: SC-8 (Transmission Integrity), SC-13
    ///
    /// # Errors
    /// Returns an error if the message is too large to encode.
    pub fn encode_with_integrity(&self, key: &[u8]) -> StunResult<Bytes> {
        let msg = self.with_integrity(key)?;
        Ok(msg.encode())
    }

    /// Encodes with MESSAGE-INTEGRITY followed by FINGERPRINT, the form
    /// RFC 8445 §7.1/§7.3 requires for ICE connectivity checks and their
    /// responses.
    ///
    /// # Errors
    /// Returns an error if the message is too large to encode.
    pub fn encode_with_integrity_and_fingerprint(&self, key: &[u8]) -> StunResult<Bytes> {
        let msg = self.with_integrity(key)?;
        Ok(msg.encode_with_fingerprint())
    }

    /// Returns a copy with MESSAGE-INTEGRITY appended (see
    /// [`Self::encode_with_integrity`]).
    fn with_integrity(&self, key: &[u8]) -> StunResult<Self> {
        let mut msg = self.clone();
        msg.attributes.retain(|a| {
            !matches!(
                a,
                StunAttribute::MessageIntegrity(_) | StunAttribute::Fingerprint(_)
            )
        });
        let partial = msg.encode();
        let new_len =
            u16::try_from(partial.len() - HEADER_SIZE + INTEGRITY_ATTR_LEN).map_err(|_| {
                StunError::InvalidMessage {
                    reason: "message too large for MESSAGE-INTEGRITY".to_string(),
                }
            })?;
        let mut covered = BytesMut::from(partial.as_ref());
        covered[2..4].copy_from_slice(&new_len.to_be_bytes());
        // CNSA-EXCEPTION: RFC 8489 §14.5 HMAC-SHA1 (POA&M-500).
        let tag = uc_crypto::interop::hmac_sha1(key, &covered);
        msg.attributes
            .push(StunAttribute::MessageIntegrity(tag.to_vec()));
        Ok(msg)
    }

    /// Verifies the MESSAGE-INTEGRITY attribute of a received message
    /// (RFC 8489 §14.5, §9.1.3).
    ///
    /// `raw` is the datagram as received. The HMAC-SHA1 is recomputed over
    /// the bytes before the first MESSAGE-INTEGRITY attribute with the
    /// length field adjusted to end at that attribute, and compared in
    /// constant time. Returns `false` when the message has no
    /// MESSAGE-INTEGRITY, when it is not 20 bytes, or when it does not
    /// match.
    ///
    /// ## NIST 800-53 Rev5: SC-8, IA-3 (Device Authentication), SC-13
    #[must_use]
    pub fn verify_integrity(raw: &[u8], key: &[u8]) -> bool {
        let Some(off) = find_attribute(raw, ATTR_MESSAGE_INTEGRITY) else {
            return false;
        };
        let Some(value) = raw.get(off + 4..off + INTEGRITY_ATTR_LEN) else {
            return false;
        };
        if u16::from_be_bytes([raw[off + 2], raw[off + 3]]) != 20 {
            return false;
        }
        let Ok(new_len) = u16::try_from(off - HEADER_SIZE + INTEGRITY_ATTR_LEN) else {
            return false;
        };
        let mut covered = raw[..off].to_vec();
        covered[2..4].copy_from_slice(&new_len.to_be_bytes());
        // CNSA-EXCEPTION: RFC 8489 §14.5 HMAC-SHA1 (POA&M-500).
        uc_crypto::interop::verify_hmac_sha1(key, &covered, value)
    }

    /// True when `raw` ends with a FINGERPRINT attribute whose CRC-32
    /// matches (RFC 8489 §14.7). A message without FINGERPRINT fails.
    #[must_use]
    pub fn has_valid_fingerprint(raw: &[u8]) -> bool {
        let Some(total) = message_len(raw) else {
            return false;
        };
        if total < HEADER_SIZE + FINGERPRINT_ATTR_LEN {
            return false;
        }
        let fp_off = total - FINGERPRINT_ATTR_LEN;
        if find_attribute(raw, ATTR_FINGERPRINT) != Some(fp_off)
            || raw[fp_off + 2..fp_off + 4] != [0, 4]
        {
            return false;
        }
        let received = u32::from_be_bytes([
            raw[fp_off + 4],
            raw[fp_off + 5],
            raw[fp_off + 6],
            raw[fp_off + 7],
        ]);
        compute_crc32(&raw[..fp_off]) ^ FINGERPRINT_XOR == received
    }

    /// Encodes with FINGERPRINT attribute.
    ///
    /// Per RFC 5389, the FINGERPRINT is computed over the entire message
    /// including the header, but with the length field adjusted to include
    /// the FINGERPRINT attribute (8 bytes).
    pub fn encode_with_fingerprint(&self) -> Bytes {
        let mut msg = self.clone();
        msg.attributes
            .retain(|a| !matches!(a, StunAttribute::Fingerprint(_)));
        // First encode without fingerprint
        let partial = msg.encode();

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
        msg.attributes.push(StunAttribute::Fingerprint(fingerprint));
        msg.encode()
    }

    /// Verifies the FINGERPRINT attribute if present.
    ///
    /// Returns `Ok(true)` when the message has no FINGERPRINT; use
    /// [`Self::has_valid_fingerprint`] where FINGERPRINT is mandatory.
    ///
    /// # Errors
    /// Never fails; the `Result` is kept for API compatibility.
    pub fn verify_fingerprint(&self, raw_data: &[u8]) -> StunResult<bool> {
        if !self
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Fingerprint(_)))
        {
            return Ok(true);
        }
        Ok(Self::has_valid_fingerprint(raw_data))
    }
}

/// MESSAGE-INTEGRITY attribute type.
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
/// FINGERPRINT attribute type.
const ATTR_FINGERPRINT: u16 = 0x8028;
/// MESSAGE-INTEGRITY attribute size on the wire (4-byte header + 20).
const INTEGRITY_ATTR_LEN: usize = 24;
/// FINGERPRINT attribute size on the wire (4-byte header + 4).
const FINGERPRINT_ATTR_LEN: usize = 8;

/// Header-declared message size (header + attributes), if `raw` holds it.
fn message_len(raw: &[u8]) -> Option<usize> {
    let header = raw.get(..HEADER_SIZE)?;
    let total = HEADER_SIZE + usize::from(u16::from_be_bytes([header[2], header[3]]));
    (raw.len() >= total).then_some(total)
}

/// Offset of the first attribute of `attr_type` in `raw`, walking the
/// attribute TLVs within the header-declared length.
fn find_attribute(raw: &[u8], attr_type: u16) -> Option<usize> {
    let total = message_len(raw)?;
    let mut off = HEADER_SIZE;
    while off + 4 <= total {
        let t = u16::from_be_bytes([raw[off], raw[off + 1]]);
        let len = usize::from(u16::from_be_bytes([raw[off + 2], raw[off + 3]]));
        if t == attr_type {
            return (off + 4 + len <= total).then_some(off);
        }
        off += 4 + ((len + 3) & !3);
    }
    None
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

    /// RFC 5769 §2.1 sample request (short-term credentials).
    const RFC5769_REQUEST: [u8; 108] = [
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74,
        0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e,
        0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20,
        0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
        0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5,
        0x7a, 0x3b, 0xcf,
    ];

    /// RFC 5769 §2.2 sample IPv4 response.
    const RFC5769_RESPONSE_V4: [u8; 80] = [
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76,
        0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1,
        0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00,
        0x04, 0xc0, 0x7d, 0x4c, 0x96,
    ];

    /// RFC 5769 §2.3 sample IPv6 response.
    const RFC5769_RESPONSE_V6: [u8; 92] = [
        0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76,
        0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01,
        0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9,
        0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41, 0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb,
        0x0b, 0x4c,
    ];

    /// RFC 5769 §2 short-term password.
    const RFC5769_PASSWORD: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";

    #[test]
    fn rfc5769_request_integrity_and_fingerprint() {
        assert!(StunMessage::verify_integrity(
            &RFC5769_REQUEST,
            RFC5769_PASSWORD
        ));
        assert!(StunMessage::has_valid_fingerprint(&RFC5769_REQUEST));
        assert!(!StunMessage::verify_integrity(&RFC5769_REQUEST, b"wrong"));
        let msg = StunMessage::parse(&RFC5769_REQUEST).unwrap();
        assert_eq!(
            msg.get_attribute(0x0006),
            Some(&StunAttribute::Username("evtj:h6vY".to_string()))
        );
        assert_eq!(
            msg.get_attribute(0x8029),
            Some(&StunAttribute::IceControlled(0x932f_f9b1_5126_3b36))
        );
        assert_eq!(
            msg.get_attribute(0x0024),
            Some(&StunAttribute::Priority(0x6e00_01ff))
        );
    }

    #[test]
    fn rfc5769_responses_integrity_fingerprint_and_address() {
        let v4: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let v6: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
            .parse()
            .unwrap();
        for (raw, addr) in [
            (&RFC5769_RESPONSE_V4[..], v4),
            (&RFC5769_RESPONSE_V6[..], v6),
        ] {
            assert!(StunMessage::verify_integrity(raw, RFC5769_PASSWORD));
            assert!(StunMessage::has_valid_fingerprint(raw));
            let msg = StunMessage::parse(raw).unwrap();
            assert_eq!(msg.xor_mapped_address(), Some(addr));
            assert!(msg.verify_fingerprint(raw).unwrap());
        }
    }

    #[test]
    fn rfc5769_any_flipped_bit_fails_integrity() {
        // Every byte covered by MESSAGE-INTEGRITY (header, attributes and
        // the tag itself), except the length field and the magic cookie
        // (which break parsing first), is authenticated.
        let mi_end = RFC5769_REQUEST.len() - 8;
        for i in (0..mi_end).filter(|i| !(2..8).contains(i)) {
            let mut raw = RFC5769_REQUEST;
            raw[i] ^= 0x01;
            assert!(
                !StunMessage::verify_integrity(&raw, RFC5769_PASSWORD),
                "byte {i} not covered"
            );
        }
    }

    #[test]
    fn encoder_output_verifies_and_round_trips() {
        let mut msg = StunMessage::new(StunMessageType::binding_request(), [7u8; 12]);
        msg.add_attribute(StunAttribute::Username("evtj:h6vY".to_string()));
        msg.add_attribute(StunAttribute::Priority(0x6e00_01ff));
        msg.add_attribute(StunAttribute::IceControlled(0x932f_f9b1_5126_3b36));
        let raw = msg
            .encode_with_integrity_and_fingerprint(RFC5769_PASSWORD)
            .unwrap();
        assert!(StunMessage::verify_integrity(&raw, RFC5769_PASSWORD));
        assert!(StunMessage::has_valid_fingerprint(&raw));
        // MI is 24 bytes and FP is 8; the header length counts both.
        assert_eq!(
            usize::from(u16::from_be_bytes([raw[2], raw[3]])),
            raw.len() - 20
        );
        // Without FINGERPRINT the integrity still verifies (length ends at MI).
        let raw = msg.encode_with_integrity(RFC5769_PASSWORD).unwrap();
        assert!(StunMessage::verify_integrity(&raw, RFC5769_PASSWORD));
        assert!(!StunMessage::has_valid_fingerprint(&raw));
        // Re-signing a parsed message drops the old MI/FP first.
        let parsed = StunMessage::parse(&raw).unwrap();
        let again = parsed.encode_with_integrity(RFC5769_PASSWORD).unwrap();
        assert_eq!(again, raw);
    }

    #[test]
    fn message_without_integrity_does_not_verify() {
        let msg = StunMessage::new(StunMessageType::binding_request(), [1u8; 12]);
        let raw = msg.encode_with_fingerprint();
        assert!(!StunMessage::verify_integrity(&raw, RFC5769_PASSWORD));
        assert!(StunMessage::has_valid_fingerprint(&raw));
    }

    #[test]
    fn attributes_after_integrity_are_ignored() {
        let mut msg = StunMessage::new(StunMessageType::binding_request(), [1u8; 12]);
        msg.add_attribute(StunAttribute::Username("a:b".to_string()));
        let mut raw = BytesMut::from(msg.encode_with_integrity(b"pw").unwrap().as_ref());
        // Append an unauthenticated USE-CANDIDATE after MESSAGE-INTEGRITY.
        raw.put_slice(&[0x00, 0x25, 0x00, 0x00]);
        let len = u16::from_be_bytes([raw[2], raw[3]]) + 4;
        raw[2..4].copy_from_slice(&len.to_be_bytes());
        let parsed = StunMessage::parse(&raw).unwrap();
        assert!(parsed.get_attribute(0x0025).is_none());
        assert!(StunMessage::verify_integrity(&raw, b"pw"));
    }
}
