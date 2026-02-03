//! RFC 3264 §6.2 Multicast Stream Negotiation.
//!
//! This module implements multicast-specific offer/answer rules per RFC 3264.
//!
//! ## RFC 3264 §6.2 Compliance
//!
//! Multicast streams differ from unicast in several key ways:
//!
//! 1. **Multicast Addresses**: Connection addresses in the 224.0.0.0/4 (IPv4)
//!    or `ff00::/8` (IPv6) ranges indicate multicast sessions.
//!
//! 2. **TTL Specification**: Multicast addresses may include TTL values
//!    in the format "address/ttl" (e.g., "224.2.1.1/127").
//!
//! 3. **Direction Semantics**: In multicast, "sendonly" means the endpoint
//!    will send to the multicast group, "recvonly" means it will receive.
//!
//! 4. **Many-to-Many**: Multiple senders and receivers can participate
//!    in the same multicast session.
//!
//! ## Connection Address Format (RFC 4566 §5.7)
//!
//! For multicast IPv4:
//! ```text
//! c=IN IP4 <base multicast address>/<ttl>/<number of addresses>
//! ```
//!
//! For multicast IPv6:
//! ```text
//! c=IN IP6 <base multicast address>/<number of addresses>
//! ```
//!
//! ## Example
//!
//! ```text
//! c=IN IP4 224.2.1.1/127/3
//! ```
//! This specifies 3 multicast addresses (224.2.1.1, 224.2.1.2, 224.2.1.3)
//! with a TTL of 127.

use crate::attribute::Direction;
use crate::error::{SdpError, SdpResult};
use crate::media::{ConnectionData, MediaDescription};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Multicast address with TTL and address count.
///
/// Per RFC 4566 §5.7, multicast connection data may include:
/// - TTL (IPv4 only): Time-to-live for multicast packets
/// - Number of addresses: For hierarchical encoding (deprecated)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastAddress {
    /// Base multicast address.
    address: String,
    /// Time-to-live (IPv4 only, 0-255).
    ttl: Option<u8>,
    /// Number of contiguous addresses (deprecated, usually 1).
    num_addresses: u16,
    /// Whether this is an IPv6 address.
    is_ipv6: bool,
}

impl MulticastAddress {
    /// Creates a new IPv4 multicast address with TTL.
    ///
    /// # Arguments
    ///
    /// * `address` - IPv4 multicast address (224.0.0.0 - 239.255.255.255)
    /// * `ttl` - Time-to-live (0-255)
    ///
    /// # Errors
    ///
    /// Returns error if address is not a valid IPv4 multicast address.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new_ipv4(address: &str, ttl: u8) -> SdpResult<Self> {
        let addr: Ipv4Addr = address.parse().map_err(|_| SdpError::InvalidConnection {
            reason: format!("invalid IPv4 address: {address}"),
        })?;

        if !addr.is_multicast() {
            return Err(SdpError::InvalidConnection {
                reason: format!("not a multicast address: {address} (must be 224.0.0.0/4)"),
            });
        }

        Ok(Self {
            address: address.to_string(),
            ttl: Some(ttl),
            num_addresses: 1,
            is_ipv6: false,
        })
    }

    /// Creates a new IPv6 multicast address.
    ///
    /// # Arguments
    ///
    /// * `address` - IPv6 multicast address (`ff00::/8`)
    ///
    /// # Errors
    ///
    /// Returns error if address is not a valid IPv6 multicast address.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new_ipv6(address: &str) -> SdpResult<Self> {
        let addr: Ipv6Addr = address.parse().map_err(|_| SdpError::InvalidConnection {
            reason: format!("invalid IPv6 address: {address}"),
        })?;

        if !addr.is_multicast() {
            return Err(SdpError::InvalidConnection {
                reason: format!("not a multicast address: {address} (must be ff00::/8)"),
            });
        }

        Ok(Self {
            address: address.to_string(),
            ttl: None, // IPv6 multicast doesn't use TTL in SDP
            num_addresses: 1,
            is_ipv6: true,
        })
    }

    /// Parses a multicast address from connection data address field.
    ///
    /// Handles formats:
    /// - IPv4: `<address>/<ttl>` or `<address>/<ttl>/<num>`
    /// - IPv6: `<address>` or `<address>/<num>`
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(addr_field: &str, is_ipv6: bool) -> SdpResult<Self> {
        let parts: Vec<&str> = addr_field.split('/').collect();

        if is_ipv6 {
            Self::parse_ipv6(&parts)
        } else {
            Self::parse_ipv4(&parts)
        }
    }

    fn parse_ipv4(parts: &[&str]) -> SdpResult<Self> {
        if parts.is_empty() {
            return Err(SdpError::InvalidConnection {
                reason: "empty address field".to_string(),
            });
        }

        let address = parts[0];
        let addr: Ipv4Addr = address.parse().map_err(|_| SdpError::InvalidConnection {
            reason: format!("invalid IPv4 address: {address}"),
        })?;

        if !addr.is_multicast() {
            return Err(SdpError::InvalidConnection {
                reason: format!("not a multicast address: {address}"),
            });
        }

        let ttl = if parts.len() > 1 {
            Some(parts[1].parse().map_err(|_| SdpError::InvalidConnection {
                reason: format!("invalid TTL: {}", parts[1]),
            })?)
        } else {
            None
        };

        let num_addresses = if parts.len() > 2 {
            parts[2].parse().map_err(|_| SdpError::InvalidConnection {
                reason: format!("invalid address count: {}", parts[2]),
            })?
        } else {
            1
        };

        Ok(Self {
            address: address.to_string(),
            ttl,
            num_addresses,
            is_ipv6: false,
        })
    }

    fn parse_ipv6(parts: &[&str]) -> SdpResult<Self> {
        if parts.is_empty() {
            return Err(SdpError::InvalidConnection {
                reason: "empty address field".to_string(),
            });
        }

        let address = parts[0];
        let addr: Ipv6Addr = address.parse().map_err(|_| SdpError::InvalidConnection {
            reason: format!("invalid IPv6 address: {address}"),
        })?;

        if !addr.is_multicast() {
            return Err(SdpError::InvalidConnection {
                reason: format!("not a multicast address: {address}"),
            });
        }

        let num_addresses = if parts.len() > 1 {
            parts[1].parse().map_err(|_| SdpError::InvalidConnection {
                reason: format!("invalid address count: {}", parts[1]),
            })?
        } else {
            1
        };

        Ok(Self {
            address: address.to_string(),
            ttl: None,
            num_addresses,
            is_ipv6: true,
        })
    }

    /// Returns the base multicast address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the TTL (IPv4 only).
    #[must_use]
    pub const fn ttl(&self) -> Option<u8> {
        self.ttl
    }

    /// Returns the number of addresses.
    #[must_use]
    pub const fn num_addresses(&self) -> u16 {
        self.num_addresses
    }

    /// Returns true if this is an IPv6 multicast address.
    #[must_use]
    pub const fn is_ipv6(&self) -> bool {
        self.is_ipv6
    }

    /// Converts to connection data format string.
    #[must_use]
    pub fn to_connection_address(&self) -> String {
        if self.is_ipv6 {
            if self.num_addresses > 1 {
                format!("{}/{}", self.address, self.num_addresses)
            } else {
                self.address.clone()
            }
        } else {
            match (self.ttl, self.num_addresses) {
                (Some(ttl), 1) => format!("{}/{}", self.address, ttl),
                (Some(ttl), n) => format!("{}/{}/{}", self.address, ttl, n),
                (None, 1) => self.address.clone(),
                (None, n) => format!("{}/{}", self.address, n),
            }
        }
    }

    /// Creates `ConnectionData` from this multicast address.
    #[must_use]
    pub fn to_connection_data(&self) -> ConnectionData {
        ConnectionData {
            net_type: "IN".to_string(),
            addr_type: if self.is_ipv6 {
                "IP6".to_string()
            } else {
                "IP4".to_string()
            },
            address: self.to_connection_address(),
        }
    }
}

/// Checks if a connection address is multicast.
///
/// Per RFC 4566, multicast addresses are:
/// - IPv4: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
/// - IPv6: `ff00::/8`
#[must_use]
pub fn is_multicast_address(connection: &ConnectionData) -> bool {
    // Extract the base address (before any /)
    let addr_part = connection
        .address
        .split('/')
        .next()
        .unwrap_or(&connection.address);

    if connection.addr_type == "IP4" {
        if let Ok(addr) = Ipv4Addr::from_str(addr_part) {
            return addr.is_multicast();
        }
    } else if connection.addr_type == "IP6"
        && let Ok(addr) = Ipv6Addr::from_str(addr_part)
    {
        return addr.is_multicast();
    }

    false
}

/// Checks if a media description uses multicast.
#[must_use]
pub fn is_multicast_media(
    media: &MediaDescription,
    session_connection: Option<&ConnectionData>,
) -> bool {
    // Check media-level connection first
    if let Some(ref conn) = media.connection {
        return is_multicast_address(conn);
    }

    // Fall back to session-level connection
    if let Some(conn) = session_connection {
        return is_multicast_address(conn);
    }

    false
}

/// RFC 3264 §6.2 Multicast stream negotiation rules.
///
/// Implements the specific rules for negotiating multicast streams
/// in the offer/answer model.
#[derive(Debug, Clone)]
pub struct MulticastNegotiator {
    /// Local multicast address (if we want to send).
    local_address: Option<MulticastAddress>,
    /// Preferred TTL for sending.
    preferred_ttl: u8,
    /// Whether we can receive multicast.
    can_receive: bool,
    /// Whether we can send multicast.
    can_send: bool,
}

impl Default for MulticastNegotiator {
    fn default() -> Self {
        Self {
            local_address: None,
            preferred_ttl: 127, // Default site-local scope
            can_receive: true,
            can_send: false,
        }
    }
}

impl MulticastNegotiator {
    /// Creates a new multicast negotiator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the local multicast address for sending.
    #[must_use]
    pub fn with_send_address(mut self, address: MulticastAddress) -> Self {
        self.local_address = Some(address);
        self.can_send = true;
        self
    }

    /// Sets whether we can receive multicast.
    #[must_use]
    pub const fn with_receive(mut self, can_receive: bool) -> Self {
        self.can_receive = can_receive;
        self
    }

    /// Sets the preferred TTL.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: u8) -> Self {
        self.preferred_ttl = ttl;
        self
    }

    /// Validates a multicast offer per RFC 3264 §6.2.
    ///
    /// ## RFC 3264 §6.2 Rules
    ///
    /// 1. The answerer MUST NOT change the multicast address
    /// 2. The answerer MUST NOT change the TTL (for IPv4)
    /// 3. Direction indicates sender/receiver role in multicast group
    ///
    /// # Errors
    ///
    /// Returns an error if the offer violates multicast validation rules.
    pub fn validate_offer(
        &self,
        media: &MediaDescription,
        session_conn: Option<&ConnectionData>,
    ) -> SdpResult<MulticastValidation> {
        let connection = media.connection.as_ref().or(session_conn).ok_or_else(|| {
            SdpError::InvalidConnection {
                reason: "multicast media requires connection data".to_string(),
            }
        })?;

        if !is_multicast_address(connection) {
            return Err(SdpError::InvalidConnection {
                reason: "expected multicast address".to_string(),
            });
        }

        let mcast_addr = MulticastAddress::parse(&connection.address, connection.is_ipv6())?;

        // Validate TTL is present for IPv4
        if !mcast_addr.is_ipv6 && mcast_addr.ttl.is_none() {
            return Err(SdpError::InvalidConnection {
                reason: "IPv4 multicast requires TTL specification".to_string(),
            });
        }

        let offer_direction = media.direction();

        // Determine our role based on offer direction and capabilities
        let (can_participate, answer_direction) = self.compute_answer_direction(offer_direction);

        Ok(MulticastValidation {
            multicast_address: mcast_addr,
            offer_direction,
            answer_direction,
            can_participate,
        })
    }

    /// Computes the answer direction for multicast.
    ///
    /// ## RFC 3264 §6.2 Direction Rules for Multicast
    ///
    /// Unlike unicast, multicast direction indicates participation role:
    /// - sendrecv: Both send to and receive from multicast group
    /// - sendonly: Only send to multicast group
    /// - recvonly: Only receive from multicast group
    /// - inactive: Do not participate
    const fn compute_answer_direction(&self, offer_direction: Direction) -> (bool, Direction) {
        match offer_direction {
            Direction::Sendrecv => {
                // Offer wants both directions in multicast group
                match (self.can_send, self.can_receive) {
                    (true, true) => (true, Direction::Sendrecv),
                    (true, false) => (true, Direction::Sendonly),
                    (false, true) => (true, Direction::Recvonly),
                    (false, false) => (false, Direction::Inactive),
                }
            }
            Direction::Sendonly => {
                // Offerer will send to group, expects us to receive
                if self.can_receive {
                    (true, Direction::Recvonly)
                } else {
                    (false, Direction::Inactive)
                }
            }
            Direction::Recvonly => {
                // Offerer will receive from group, expects us to send
                if self.can_send {
                    (true, Direction::Sendonly)
                } else {
                    (false, Direction::Inactive)
                }
            }
            Direction::Inactive => (false, Direction::Inactive),
        }
    }

    /// Generates a multicast media answer.
    ///
    /// Per RFC 3264 §6.2, the answer:
    /// 1. MUST use the same multicast address
    /// 2. MUST use the same TTL
    /// 3. Sets direction based on local capabilities
    ///
    /// # Errors
    ///
    /// Returns an error if the offer is invalid or answer generation fails.
    pub fn generate_answer(
        &self,
        offer_media: &MediaDescription,
        session_conn: Option<&ConnectionData>,
    ) -> SdpResult<MediaDescription> {
        let validation = self.validate_offer(offer_media, session_conn)?;

        let mut answer = MediaDescription::new(
            offer_media.media_type,
            if validation.can_participate {
                offer_media.port
            } else {
                0 // Reject by setting port to 0
            },
            offer_media.protocol,
        );

        if validation.can_participate {
            // Copy the multicast connection data exactly (RFC 3264 §6.2 requirement)
            answer.connection = offer_media
                .connection
                .clone()
                .or_else(|| session_conn.cloned());

            // Copy formats (intersection would be done by caller)
            answer.formats.clone_from(&offer_media.formats);

            // Set our direction
            answer.add_attribute(validation.answer_direction.to_attribute());
        }

        Ok(answer)
    }
}

/// Result of validating a multicast offer.
#[derive(Debug, Clone)]
pub struct MulticastValidation {
    /// The multicast address from the offer.
    pub multicast_address: MulticastAddress,
    /// Direction in the offer.
    pub offer_direction: Direction,
    /// Computed answer direction.
    pub answer_direction: Direction,
    /// Whether we can participate in this multicast session.
    pub can_participate: bool,
}

/// Multicast scope based on IPv4 TTL or IPv6 address prefix.
///
/// Per RFC 2365 (Administratively Scoped IP Multicast).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastScope {
    /// Node-local (TTL=0 or `ff01::/16`).
    NodeLocal,
    /// Link-local (TTL=1 or `ff02::/16`).
    LinkLocal,
    /// Site-local (TTL=32 or less, or `ff05::/16`).
    SiteLocal,
    /// Organization-local (TTL=64 or less, or `ff08::/16`).
    OrganizationLocal,
    /// Global (TTL>64 or `ff0e::/16`).
    Global,
}

impl MulticastScope {
    /// Determines scope from TTL value (IPv4).
    #[must_use]
    pub const fn from_ttl(ttl: u8) -> Self {
        match ttl {
            0 => Self::NodeLocal,
            1 => Self::LinkLocal,
            2..=32 => Self::SiteLocal,
            33..=64 => Self::OrganizationLocal,
            _ => Self::Global,
        }
    }

    /// Determines scope from IPv6 multicast address.
    #[must_use]
    pub const fn from_ipv6(addr: &Ipv6Addr) -> Option<Self> {
        if !addr.is_multicast() {
            return None;
        }

        let octets = addr.octets();
        // Scope is in bits 4-7 of the second byte (after ff)
        let scope = octets[1] & 0x0f;

        Some(match scope {
            0x01 => Self::NodeLocal,
            0x02 => Self::LinkLocal,
            0x05 => Self::SiteLocal,
            0x08 => Self::OrganizationLocal,
            0x0e | _ => Self::Global, // Unknown scope treated as global
        })
    }

    /// Returns the recommended TTL for this scope.
    #[must_use]
    pub const fn recommended_ttl(&self) -> u8 {
        match self {
            Self::NodeLocal => 0,
            Self::LinkLocal => 1,
            Self::SiteLocal => 32,
            Self::OrganizationLocal => 64,
            Self::Global => 255,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicast_address_ipv4() {
        let mcast = MulticastAddress::new_ipv4("224.2.1.1", 127).unwrap();
        assert_eq!(mcast.address(), "224.2.1.1");
        assert_eq!(mcast.ttl(), Some(127));
        assert!(!mcast.is_ipv6());
    }

    #[test]
    fn test_multicast_address_ipv4_invalid() {
        // Not a multicast address
        let result = MulticastAddress::new_ipv4("192.168.1.1", 127);
        assert!(result.is_err());
    }

    #[test]
    fn test_multicast_address_ipv6() {
        let mcast = MulticastAddress::new_ipv6("ff02::1").unwrap();
        assert_eq!(mcast.address(), "ff02::1");
        assert!(mcast.ttl().is_none());
        assert!(mcast.is_ipv6());
    }

    #[test]
    fn test_multicast_address_ipv6_invalid() {
        // Not a multicast address
        let result = MulticastAddress::new_ipv6("2001:db8::1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv4_with_ttl() {
        let mcast = MulticastAddress::parse("224.2.1.1/127", false).unwrap();
        assert_eq!(mcast.address(), "224.2.1.1");
        assert_eq!(mcast.ttl(), Some(127));
        assert_eq!(mcast.num_addresses(), 1);
    }

    #[test]
    fn test_parse_ipv4_with_ttl_and_count() {
        let mcast = MulticastAddress::parse("224.2.1.1/127/3", false).unwrap();
        assert_eq!(mcast.address(), "224.2.1.1");
        assert_eq!(mcast.ttl(), Some(127));
        assert_eq!(mcast.num_addresses(), 3);
    }

    #[test]
    fn test_parse_ipv6_with_count() {
        let mcast = MulticastAddress::parse("ff02::1/2", true).unwrap();
        assert_eq!(mcast.address(), "ff02::1");
        assert_eq!(mcast.num_addresses(), 2);
    }

    #[test]
    fn test_to_connection_address() {
        let mcast = MulticastAddress::new_ipv4("224.2.1.1", 127).unwrap();
        assert_eq!(mcast.to_connection_address(), "224.2.1.1/127");

        let mcast6 = MulticastAddress::new_ipv6("ff02::1").unwrap();
        assert_eq!(mcast6.to_connection_address(), "ff02::1");
    }

    #[test]
    fn test_is_multicast_address() {
        let mcast_conn = ConnectionData {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "224.2.1.1/127".to_string(),
        };
        assert!(is_multicast_address(&mcast_conn));

        let unicast_conn = ConnectionData {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "192.168.1.1".to_string(),
        };
        assert!(!is_multicast_address(&unicast_conn));
    }

    #[test]
    fn test_multicast_negotiator_recvonly() {
        let negotiator = MulticastNegotiator::new().with_receive(true);

        let mut media = MediaDescription::new(
            crate::media::MediaType::Audio,
            5000,
            crate::media::TransportProtocol::RtpSavp,
        );
        media.connection = Some(ConnectionData {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "224.2.1.1/127".to_string(),
        });
        media.add_attribute(crate::attribute::Attribute::flag(
            crate::attribute::AttributeName::Sendonly,
        ));

        let validation = negotiator.validate_offer(&media, None).unwrap();
        assert!(validation.can_participate);
        assert_eq!(validation.answer_direction, Direction::Recvonly);
    }

    #[test]
    fn test_multicast_negotiator_cannot_participate() {
        let negotiator = MulticastNegotiator::new()
            .with_receive(false)
            .with_send_address(MulticastAddress::new_ipv4("224.2.1.1", 127).unwrap());

        let mut media = MediaDescription::new(
            crate::media::MediaType::Audio,
            5000,
            crate::media::TransportProtocol::RtpSavp,
        );
        media.connection = Some(ConnectionData {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "224.2.1.1/127".to_string(),
        });
        // Offer is sendonly, so they send and expect us to receive
        media.add_attribute(crate::attribute::Attribute::flag(
            crate::attribute::AttributeName::Sendonly,
        ));

        let validation = negotiator.validate_offer(&media, None).unwrap();
        // We can't receive, so we can't participate
        assert!(!validation.can_participate);
        assert_eq!(validation.answer_direction, Direction::Inactive);
    }

    #[test]
    fn test_multicast_scope_from_ttl() {
        assert_eq!(MulticastScope::from_ttl(0), MulticastScope::NodeLocal);
        assert_eq!(MulticastScope::from_ttl(1), MulticastScope::LinkLocal);
        assert_eq!(MulticastScope::from_ttl(32), MulticastScope::SiteLocal);
        assert_eq!(
            MulticastScope::from_ttl(64),
            MulticastScope::OrganizationLocal
        );
        assert_eq!(MulticastScope::from_ttl(128), MulticastScope::Global);
    }

    #[test]
    fn test_multicast_scope_from_ipv6() {
        let link_local: Ipv6Addr = "ff02::1".parse().unwrap();
        assert_eq!(
            MulticastScope::from_ipv6(&link_local),
            Some(MulticastScope::LinkLocal)
        );

        let site_local: Ipv6Addr = "ff05::1".parse().unwrap();
        assert_eq!(
            MulticastScope::from_ipv6(&site_local),
            Some(MulticastScope::SiteLocal)
        );

        let global: Ipv6Addr = "ff0e::1".parse().unwrap();
        assert_eq!(
            MulticastScope::from_ipv6(&global),
            Some(MulticastScope::Global)
        );

        // Non-multicast returns None
        let unicast: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(MulticastScope::from_ipv6(&unicast), None);
    }

    #[test]
    fn test_generate_multicast_answer() {
        let negotiator = MulticastNegotiator::new().with_receive(true);

        let mut offer_media = MediaDescription::new(
            crate::media::MediaType::Audio,
            5000,
            crate::media::TransportProtocol::RtpSavp,
        );
        offer_media.connection = Some(ConnectionData {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "224.2.1.1/127".to_string(),
        });
        offer_media.formats = vec!["0".to_string(), "8".to_string()];
        offer_media.add_attribute(crate::attribute::Attribute::flag(
            crate::attribute::AttributeName::Sendrecv,
        ));

        let answer = negotiator.generate_answer(&offer_media, None).unwrap();

        // Should copy the multicast address exactly
        assert_eq!(
            answer.connection.as_ref().map(|c| c.address.as_str()),
            Some("224.2.1.1/127")
        );
        // Should have recvonly since we can only receive
        assert_eq!(answer.direction(), Direction::Recvonly);
        // Port should be preserved (can participate)
        assert_eq!(answer.port, 5000);
    }
}
