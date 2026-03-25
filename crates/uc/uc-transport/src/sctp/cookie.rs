//! SCTP state cookie generation and validation (RFC 9260 Section 5.1.3).
//!
//! This module implements secure state cookies for the SCTP 4-way handshake:
//! - Cookie generation with association state
//! - Cookie authentication with HMAC-SHA384 (CNSA 2.0 compliant)
//! - Cookie validation with timestamp checking
//! - Replay protection via cookie expiration

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uc_crypto::hash::{hmac_sha384, verify_hmac_sha384};

// =============================================================================
// Constants
// =============================================================================

/// Cookie magic value for validation.
const COOKIE_MAGIC: u32 = 0x5343_5450; // "SCTP" in ASCII

/// Default cookie lifetime (60 seconds per RFC 9260).
pub const DEFAULT_COOKIE_LIFETIME: Duration = Duration::from_secs(60);

/// Cookie version for format compatibility.
const COOKIE_VERSION: u8 = 1;

/// Minimum cookie size (header only, unencrypted).
const MIN_COOKIE_SIZE: usize = 4 + 1 + 8 + 4 + 4 + 2 + 2 + 4 + 4; // 33 bytes

// =============================================================================
// Cookie Data
// =============================================================================

/// State cookie data structure.
///
/// Contains all information needed to recreate the association state
/// after receiving a COOKIE ECHO chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieData {
    /// Cookie creation timestamp (Unix timestamp in milliseconds).
    pub timestamp_ms: u64,
    /// Local verification tag.
    pub local_verification_tag: u32,
    /// Peer verification tag.
    pub peer_verification_tag: u32,
    /// Local initial TSN.
    pub local_initial_tsn: u32,
    /// Peer initial TSN.
    pub peer_initial_tsn: u32,
    /// Number of outbound streams.
    pub outbound_streams: u16,
    /// Number of inbound streams.
    pub inbound_streams: u16,
    /// Peer address (for multi-homing).
    pub peer_addr: SocketAddr,
    /// Local address.
    pub local_addr: SocketAddr,
}

impl CookieData {
    /// Creates a new cookie data structure.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        local_verification_tag: u32,
        peer_verification_tag: u32,
        local_initial_tsn: u32,
        peer_initial_tsn: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            timestamp_ms,
            local_verification_tag,
            peer_verification_tag,
            local_initial_tsn,
            peer_initial_tsn,
            outbound_streams,
            inbound_streams,
            peer_addr,
            local_addr,
        }
    }

    /// Returns the age of the cookie.
    #[must_use]
    pub fn age(&self) -> Duration {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Duration::from_millis(now_ms.saturating_sub(self.timestamp_ms))
    }

    /// Returns true if the cookie has expired.
    #[must_use]
    pub fn is_expired(&self, lifetime: Duration) -> bool {
        self.age() > lifetime
    }

    /// Encodes the cookie data to bytes.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(64);

        // Header
        buf.put_u32(COOKIE_MAGIC);
        buf.put_u8(COOKIE_VERSION);

        // Timestamp
        buf.put_u64(self.timestamp_ms);

        // Verification tags
        buf.put_u32(self.local_verification_tag);
        buf.put_u32(self.peer_verification_tag);

        // TSNs
        buf.put_u32(self.local_initial_tsn);
        buf.put_u32(self.peer_initial_tsn);

        // Streams
        buf.put_u16(self.outbound_streams);
        buf.put_u16(self.inbound_streams);

        // Addresses
        encode_socket_addr(&mut buf, &self.peer_addr);
        encode_socket_addr(&mut buf, &self.local_addr);

        buf
    }

    /// Decodes cookie data from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the cookie is malformed.
    pub fn decode(mut buf: Bytes) -> Result<Self, CookieError> {
        if buf.remaining() < MIN_COOKIE_SIZE {
            return Err(CookieError::TooShort {
                expected: MIN_COOKIE_SIZE,
                actual: buf.remaining(),
            });
        }

        // Verify magic
        let magic = buf.get_u32();
        if magic != COOKIE_MAGIC {
            return Err(CookieError::InvalidMagic { found: magic });
        }

        // Verify version
        let version = buf.get_u8();
        if version != COOKIE_VERSION {
            return Err(CookieError::UnsupportedVersion { version });
        }

        // Parse fields
        let timestamp_ms = buf.get_u64();
        let local_verification_tag = buf.get_u32();
        let peer_verification_tag = buf.get_u32();
        let local_initial_tsn = buf.get_u32();
        let peer_initial_tsn = buf.get_u32();
        let outbound_streams = buf.get_u16();
        let inbound_streams = buf.get_u16();

        let peer_addr = decode_socket_addr(&mut buf)?;
        let local_addr = decode_socket_addr(&mut buf)?;

        Ok(Self {
            timestamp_ms,
            local_verification_tag,
            peer_verification_tag,
            local_initial_tsn,
            peer_initial_tsn,
            outbound_streams,
            inbound_streams,
            peer_addr,
            local_addr,
        })
    }
}

// =============================================================================
// Constants
// =============================================================================

/// HMAC-SHA384 output size in bytes (per CNSA 2.0 compliance).
const HMAC_SIZE: usize = 48;

// =============================================================================
// Cookie Generator
// =============================================================================

/// Cookie generator with HMAC-SHA384 protection (RFC 9260 Section 5.1.3).
///
/// Uses HMAC-SHA384 for cookie authentication, which is CNSA 2.0 compliant.
/// The secret key should be cryptographically random and rotated periodically.
#[derive(Debug, Clone)]
pub struct CookieGenerator {
    /// Secret key for HMAC-SHA384 (48 bytes for SHA384 security level).
    secret_key: [u8; 48],
    /// Cookie lifetime.
    lifetime: Duration,
    /// Whether to use HMAC protection.
    use_hmac: bool,
}

impl CookieGenerator {
    /// Creates a new cookie generator with a cryptographically random secret.
    #[must_use]
    pub fn new() -> Self {
        use rand::RngCore;

        // Generate a cryptographically secure random key
        let mut key = [0u8; 48];
        rand::rng().fill_bytes(&mut key);

        Self {
            secret_key: key,
            lifetime: DEFAULT_COOKIE_LIFETIME,
            use_hmac: true,
        }
    }

    /// Creates a cookie generator with a specific secret key.
    ///
    /// The key should be 48 bytes for HMAC-SHA384 security level.
    #[must_use]
    pub const fn with_secret(secret_key: [u8; 48]) -> Self {
        Self {
            secret_key,
            lifetime: DEFAULT_COOKIE_LIFETIME,
            use_hmac: true,
        }
    }

    /// Creates a cookie generator without HMAC (for testing only).
    ///
    /// # Security Warning
    ///
    /// This method creates an insecure cookie generator that does NOT
    /// authenticate cookies. Use only for testing purposes.
    #[must_use]
    pub fn insecure() -> Self {
        Self {
            secret_key: [0u8; 48],
            lifetime: DEFAULT_COOKIE_LIFETIME,
            use_hmac: false,
        }
    }

    /// Sets the cookie lifetime.
    pub fn set_lifetime(&mut self, lifetime: Duration) {
        self.lifetime = lifetime;
    }

    /// Returns the cookie lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> Duration {
        self.lifetime
    }

    /// Generates a state cookie from the given data.
    ///
    /// The cookie contains the encoded association state followed by
    /// an HMAC-SHA384 authentication tag for integrity protection.
    #[must_use]
    pub fn generate(&self, data: &CookieData) -> Bytes {
        let encoded = data.encode();

        if self.use_hmac {
            // Compute HMAC-SHA384 over the encoded data
            let hmac = hmac_sha384(&self.secret_key, &encoded);
            let mut result = BytesMut::with_capacity(encoded.len() + HMAC_SIZE);
            result.extend_from_slice(&encoded);
            result.extend_from_slice(&hmac);
            result.freeze()
        } else {
            encoded.freeze()
        }
    }

    /// Validates and decodes a state cookie.
    ///
    /// Verifies the HMAC-SHA384 authentication tag and checks expiration.
    ///
    /// # Errors
    ///
    /// Returns an error if the cookie is invalid, tampered, or expired.
    pub fn validate(&self, cookie: &Bytes) -> Result<CookieData, CookieError> {
        if self.use_hmac {
            if cookie.len() < HMAC_SIZE {
                return Err(CookieError::TooShort {
                    expected: HMAC_SIZE,
                    actual: cookie.len(),
                });
            }

            // Split cookie data and HMAC tag
            let data_len = cookie.len() - HMAC_SIZE;
            let data_bytes = cookie.slice(..data_len);
            let received_hmac = &cookie[data_len..];

            // Verify HMAC-SHA384 using constant-time comparison
            if !verify_hmac_sha384(&self.secret_key, &data_bytes, received_hmac) {
                return Err(CookieError::HmacMismatch);
            }

            // Decode and check expiration
            let data = CookieData::decode(data_bytes)?;
            if data.is_expired(self.lifetime) {
                return Err(CookieError::Expired {
                    age: data.age(),
                    lifetime: self.lifetime,
                });
            }

            Ok(data)
        } else {
            // No HMAC (insecure mode for testing only)
            let data = CookieData::decode(cookie.clone())?;
            if data.is_expired(self.lifetime) {
                return Err(CookieError::Expired {
                    age: data.age(),
                    lifetime: self.lifetime,
                });
            }

            Ok(data)
        }
    }
}

impl Default for CookieGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during cookie operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieError {
    /// Cookie is too short.
    TooShort {
        /// Expected minimum size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },
    /// Invalid magic value.
    InvalidMagic {
        /// Found magic value.
        found: u32,
    },
    /// Unsupported cookie version.
    UnsupportedVersion {
        /// Found version.
        version: u8,
    },
    /// HMAC verification failed.
    HmacMismatch,
    /// Cookie has expired.
    Expired {
        /// Cookie age.
        age: Duration,
        /// Maximum lifetime.
        lifetime: Duration,
    },
    /// Invalid address encoding.
    InvalidAddress,
}

impl std::fmt::Display for CookieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { expected, actual } => {
                write!(f, "cookie too short: expected {expected}, got {actual}")
            }
            Self::InvalidMagic { found } => {
                write!(f, "invalid cookie magic: 0x{found:08x}")
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported cookie version: {version}")
            }
            Self::HmacMismatch => write!(f, "cookie HMAC verification failed"),
            Self::Expired { age, lifetime } => {
                write!(
                    f,
                    "cookie expired: age {:?} exceeds lifetime {:?}",
                    age, lifetime
                )
            }
            Self::InvalidAddress => write!(f, "invalid address encoding in cookie"),
        }
    }
}

impl std::error::Error for CookieError {}

// =============================================================================
// Helper Functions
// =============================================================================

/// Encodes a socket address to bytes.
fn encode_socket_addr(buf: &mut BytesMut, addr: &SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(4); // IPv4
            buf.put_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        SocketAddr::V6(v6) => {
            buf.put_u8(6); // IPv6
            buf.put_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
    }
}

/// Decodes a socket address from bytes.
fn decode_socket_addr(buf: &mut Bytes) -> Result<SocketAddr, CookieError> {
    if buf.remaining() < 1 {
        return Err(CookieError::InvalidAddress);
    }

    let addr_type = buf.get_u8();

    match addr_type {
        4 => {
            if buf.remaining() < 6 {
                return Err(CookieError::InvalidAddress);
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            let port = buf.get_u16();
            Ok(SocketAddr::new(octets.into(), port))
        }
        6 => {
            if buf.remaining() < 18 {
                return Err(CookieError::InvalidAddress);
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            let port = buf.get_u16();
            Ok(SocketAddr::new(octets.into(), port))
        }
        _ => Err(CookieError::InvalidAddress),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_addr_v4() -> SocketAddr {
        "192.168.1.100:5060".parse().unwrap()
    }

    fn test_addr_v6() -> SocketAddr {
        "[::1]:5060".parse().unwrap()
    }

    #[test]
    fn test_cookie_data_creation() {
        let data = CookieData::new(
            0x12345678,
            0xABCDEF00,
            1000,
            2000,
            10,
            10,
            test_addr_v4(),
            test_addr_v4(),
        );

        assert_eq!(data.local_verification_tag, 0x12345678);
        assert_eq!(data.peer_verification_tag, 0xABCDEF00);
        assert_eq!(data.local_initial_tsn, 1000);
        assert_eq!(data.peer_initial_tsn, 2000);
        assert_eq!(data.outbound_streams, 10);
        assert_eq!(data.inbound_streams, 10);
    }

    #[test]
    fn test_cookie_data_encode_decode_v4() {
        let original = CookieData::new(
            0x12345678,
            0xABCDEF00,
            1000,
            2000,
            10,
            10,
            test_addr_v4(),
            test_addr_v4(),
        );

        let encoded = original.encode();
        let decoded = CookieData::decode(encoded.freeze()).unwrap();

        assert_eq!(
            decoded.local_verification_tag,
            original.local_verification_tag
        );
        assert_eq!(
            decoded.peer_verification_tag,
            original.peer_verification_tag
        );
        assert_eq!(decoded.local_initial_tsn, original.local_initial_tsn);
        assert_eq!(decoded.peer_initial_tsn, original.peer_initial_tsn);
        assert_eq!(decoded.outbound_streams, original.outbound_streams);
        assert_eq!(decoded.inbound_streams, original.inbound_streams);
        assert_eq!(decoded.peer_addr, original.peer_addr);
        assert_eq!(decoded.local_addr, original.local_addr);
    }

    #[test]
    fn test_cookie_data_encode_decode_v6() {
        let original = CookieData::new(
            0x12345678,
            0xABCDEF00,
            1000,
            2000,
            10,
            10,
            test_addr_v6(),
            test_addr_v6(),
        );

        let encoded = original.encode();
        let decoded = CookieData::decode(encoded.freeze()).unwrap();

        assert_eq!(decoded.peer_addr, original.peer_addr);
        assert_eq!(decoded.local_addr, original.local_addr);
    }

    #[test]
    fn test_cookie_age() {
        let data = CookieData::new(0, 0, 0, 0, 10, 10, test_addr_v4(), test_addr_v4());

        let age = data.age();
        assert!(age < Duration::from_secs(1));
    }

    #[test]
    fn test_cookie_expiration() {
        let mut data = CookieData::new(0, 0, 0, 0, 10, 10, test_addr_v4(), test_addr_v4());

        // Not expired with default lifetime
        assert!(!data.is_expired(DEFAULT_COOKIE_LIFETIME));

        // Force expiration
        data.timestamp_ms = 0;
        assert!(data.is_expired(DEFAULT_COOKIE_LIFETIME));
    }

    #[test]
    fn test_cookie_generator_insecure() {
        let generator = CookieGenerator::insecure();
        let data = CookieData::new(
            0x12345678,
            0xABCDEF00,
            1000,
            2000,
            10,
            10,
            test_addr_v4(),
            test_addr_v4(),
        );

        let cookie = generator.generate(&data);
        let validated = generator.validate(&cookie).unwrap();

        assert_eq!(
            validated.local_verification_tag,
            data.local_verification_tag
        );
    }

    #[test]
    fn test_cookie_generator_with_hmac() {
        let generator = CookieGenerator::new();
        let data = CookieData::new(
            0x12345678,
            0xABCDEF00,
            1000,
            2000,
            10,
            10,
            test_addr_v4(),
            test_addr_v4(),
        );

        let cookie = generator.generate(&data);

        // Cookie should be larger due to HMAC
        assert!(cookie.len() > data.encode().len());

        let validated = generator.validate(&cookie).unwrap();
        assert_eq!(
            validated.local_verification_tag,
            data.local_verification_tag
        );
    }

    #[test]
    fn test_cookie_hmac_tampering() {
        let generator = CookieGenerator::new();
        let data = CookieData::new(
            0x12345678,
            0xABCDEF00,
            1000,
            2000,
            10,
            10,
            test_addr_v4(),
            test_addr_v4(),
        );

        let cookie = generator.generate(&data);

        // Tamper with the cookie
        let mut tampered = BytesMut::from(&cookie[..]);
        tampered[10] ^= 0xFF;
        let tampered = tampered.freeze();

        let result = generator.validate(&tampered);
        assert!(matches!(result, Err(CookieError::HmacMismatch)));
    }

    #[test]
    fn test_cookie_expired() {
        let mut generator = CookieGenerator::insecure();
        generator.set_lifetime(Duration::from_millis(1));

        let mut data = CookieData::new(
            0x12345678,
            0xABCDEF00,
            1000,
            2000,
            10,
            10,
            test_addr_v4(),
            test_addr_v4(),
        );

        // Force old timestamp
        data.timestamp_ms = 0;

        let cookie = data.encode().freeze();
        let result = generator.validate(&cookie);

        assert!(matches!(result, Err(CookieError::Expired { .. })));
    }

    #[test]
    fn test_cookie_invalid_magic() {
        let mut buf = BytesMut::new();
        buf.put_u32(0xDEADBEEF); // Wrong magic
        buf.put_u8(1);
        buf.resize(MIN_COOKIE_SIZE, 0);

        let result = CookieData::decode(buf.freeze());
        assert!(matches!(result, Err(CookieError::InvalidMagic { .. })));
    }

    #[test]
    fn test_cookie_error_display() {
        let err = CookieError::HmacMismatch;
        assert!(err.to_string().contains("HMAC"));

        let err = CookieError::Expired {
            age: Duration::from_secs(120),
            lifetime: Duration::from_secs(60),
        };
        assert!(err.to_string().contains("expired"));
    }
}
