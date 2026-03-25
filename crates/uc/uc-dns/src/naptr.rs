//! NAPTR record handling for SIP DNS (RFC 3263).
//!
//! NAPTR (Naming Authority Pointer) records provide service and protocol
//! selection for SIP routing.

use crate::config::TransportPref;
use crate::error::{DnsError, DnsResult};
use std::cmp::Ordering;
use tracing::debug;

/// NAPTR record per RFC 3403.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaptrRecord {
    /// Domain name.
    pub name: String,
    /// Order (lower is processed first).
    pub order: u16,
    /// Preference (lower is preferred within same order).
    pub preference: u16,
    /// Flags (e.g., "s" for SRV, "a" for A record).
    pub flags: String,
    /// Service (e.g., "SIP+D2T" for SIP over TCP).
    pub service: String,
    /// Regular expression for URI transformation.
    pub regexp: String,
    /// Replacement domain (for SRV lookup).
    pub replacement: String,
    /// TTL in seconds.
    pub ttl: u32,
}

impl NaptrRecord {
    /// Creates a new NAPTR record.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        order: u16,
        preference: u16,
        flags: impl Into<String>,
        service: impl Into<String>,
        regexp: impl Into<String>,
        replacement: impl Into<String>,
        ttl: u32,
    ) -> Self {
        Self {
            name: name.into(),
            order,
            preference,
            flags: flags.into(),
            service: service.into(),
            regexp: regexp.into(),
            replacement: replacement.into(),
            ttl,
        }
    }

    /// Returns the parsed service type.
    #[must_use]
    pub fn service_type(&self) -> Option<NaptrService> {
        NaptrService::from_service_field(&self.service)
    }

    /// Returns the transport preference for this record.
    #[must_use]
    pub fn transport(&self) -> Option<TransportPref> {
        self.service_type().map(|s| s.transport())
    }

    /// Returns true if this record points to an SRV lookup.
    #[must_use]
    pub fn is_srv_lookup(&self) -> bool {
        self.flags.eq_ignore_ascii_case("s")
    }

    /// Returns true if this record points to an A/AAAA lookup.
    #[must_use]
    pub fn is_address_lookup(&self) -> bool {
        self.flags.eq_ignore_ascii_case("a")
    }

    /// Returns true if this record uses a regexp transformation.
    #[must_use]
    pub fn is_regexp(&self) -> bool {
        self.flags.eq_ignore_ascii_case("u") && !self.regexp.is_empty()
    }

    /// Returns the target for the next lookup.
    #[must_use]
    pub fn next_lookup_target(&self) -> Option<&str> {
        if self.is_srv_lookup() || self.is_address_lookup() {
            if self.replacement.is_empty() || self.replacement == "." {
                None
            } else {
                Some(&self.replacement)
            }
        } else {
            None
        }
    }
}

impl Ord for NaptrRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.order.cmp(&other.order) {
            Ordering::Equal => self.preference.cmp(&other.preference),
            other => other,
        }
    }
}

impl PartialOrd for NaptrRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// NAPTR service types for SIP (RFC 3263).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NaptrService {
    /// SIP over UDP (SIP+D2U).
    SipUdp,
    /// SIP over TCP (SIP+D2T).
    SipTcp,
    /// SIPS over TCP (SIPS+D2T) - TLS.
    SipsTcp,
    /// SIP over SCTP (SIP+D2S).
    SipSctp,
    /// SIP over WebSocket (SIP+D2W).
    SipWs,
    /// SIPS over WebSocket (SIPS+D2W) - WSS.
    SipsWs,
}

impl NaptrService {
    /// Parses from a NAPTR service field.
    #[must_use]
    pub fn from_service_field(service: &str) -> Option<Self> {
        // Service format: "protocol+resolution" e.g., "SIP+D2T"
        let upper = service.to_uppercase();
        match upper.as_str() {
            "SIP+D2U" => Some(Self::SipUdp),
            "SIP+D2T" => Some(Self::SipTcp),
            "SIPS+D2T" => Some(Self::SipsTcp),
            "SIP+D2S" => Some(Self::SipSctp),
            "SIP+D2W" => Some(Self::SipWs),
            "SIPS+D2W" => Some(Self::SipsWs),
            _ => None,
        }
    }

    /// Returns the transport preference for this service.
    #[must_use]
    pub const fn transport(&self) -> TransportPref {
        match self {
            Self::SipUdp => TransportPref::Udp,
            Self::SipTcp => TransportPref::Tcp,
            Self::SipsTcp => TransportPref::Tls,
            Self::SipSctp => TransportPref::Sctp,
            Self::SipWs => TransportPref::WebSocket,
            Self::SipsWs => TransportPref::WebSocketSecure,
        }
    }

    /// Returns the service string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SipUdp => "SIP+D2U",
            Self::SipTcp => "SIP+D2T",
            Self::SipsTcp => "SIPS+D2T",
            Self::SipSctp => "SIP+D2S",
            Self::SipWs => "SIP+D2W",
            Self::SipsWs => "SIPS+D2W",
        }
    }

    /// Returns true if this is a secure transport.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(self, Self::SipsTcp | Self::SipsWs)
    }
}

impl std::fmt::Display for NaptrService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// NAPTR resolver for SIP domains.
#[derive(Debug)]
pub struct NaptrResolver {
    /// Cached NAPTR records.
    records: Vec<NaptrRecord>,
}

impl NaptrResolver {
    /// Creates a new NAPTR resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Adds NAPTR records from a lookup result.
    pub fn add_records(&mut self, records: Vec<NaptrRecord>) {
        self.records.extend(records);
        self.records.sort();
    }

    /// Clears all cached records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns the number of cached records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true if no records are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Selects records for a specific transport.
    #[must_use]
    pub fn select_for_transport(&self, transport: TransportPref) -> Vec<&NaptrRecord> {
        self.records
            .iter()
            .filter(|r| r.transport() == Some(transport))
            .collect()
    }

    /// Selects the best record based on order/preference.
    #[must_use]
    pub fn select_best(&self) -> Option<&NaptrRecord> {
        self.records.first()
    }

    /// Selects the best record for SIP services.
    #[must_use]
    pub fn select_best_sip(&self) -> Option<&NaptrRecord> {
        self.records.iter().find(|r| r.service_type().is_some())
    }

    /// Returns all SRV-pointing records in order.
    #[must_use]
    pub fn srv_records(&self) -> Vec<&NaptrRecord> {
        self.records.iter().filter(|r| r.is_srv_lookup()).collect()
    }

    /// Parses a NAPTR record from a DNS response string.
    ///
    /// Format: "order preference flags service regexp replacement"
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid.
    pub fn parse_record(name: &str, data: &str, ttl: u32) -> DnsResult<NaptrRecord> {
        // NAPTR format: order preference "flags" "service" "regexp" replacement
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut was_quoted = false;

        for ch in data.chars() {
            match ch {
                '"' => {
                    if in_quotes {
                        // End of quoted string - push even if empty
                        parts.push(current.clone());
                        current.clear();
                        was_quoted = true;
                    }
                    in_quotes = !in_quotes;
                }
                ' ' | '\t' if !in_quotes => {
                    if !current.is_empty() {
                        parts.push(current.clone());
                        current.clear();
                    }
                    was_quoted = false;
                }
                _ => current.push(ch),
            }
        }
        if !current.is_empty() {
            parts.push(current);
        }
        let _ = was_quoted; // Suppress unused variable warning

        if parts.len() < 6 {
            return Err(DnsError::InvalidNaptr {
                reason: format!("expected 6 parts, got {}", parts.len()),
            });
        }

        let order = parts[0]
            .parse::<u16>()
            .map_err(|e| DnsError::InvalidNaptr {
                reason: format!("invalid order: {e}"),
            })?;

        let preference = parts[1]
            .parse::<u16>()
            .map_err(|e| DnsError::InvalidNaptr {
                reason: format!("invalid preference: {e}"),
            })?;

        let flags = parts[2].clone();
        let service = parts[3].clone();
        let regexp = parts[4].clone();
        let replacement = parts[5].trim_end_matches('.').to_string();

        debug!(
            name = %name,
            order,
            preference,
            flags = %flags,
            service = %service,
            "Parsed NAPTR record"
        );

        Ok(NaptrRecord::new(
            name,
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
            ttl,
        ))
    }
}

impl Default for NaptrResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_naptr_record_creation() {
        let record = NaptrRecord::new(
            "example.com",
            10,
            20,
            "s",
            "SIP+D2T",
            "",
            "_sip._tcp.example.com",
            300,
        );

        assert_eq!(record.order, 10);
        assert_eq!(record.preference, 20);
        assert!(record.is_srv_lookup());
        assert_eq!(record.service_type(), Some(NaptrService::SipTcp));
        assert_eq!(record.transport(), Some(TransportPref::Tcp));
    }

    #[test]
    fn test_naptr_ordering() {
        let r1 = NaptrRecord::new("", 10, 20, "s", "SIP+D2T", "", "", 300);
        let r2 = NaptrRecord::new("", 20, 10, "s", "SIP+D2U", "", "", 300);
        let r3 = NaptrRecord::new("", 10, 30, "s", "SIP+D2S", "", "", 300);

        // r1 < r2 (lower order)
        assert!(r1 < r2);
        // r1 < r3 (same order, lower preference)
        assert!(r1 < r3);
    }

    #[test]
    fn test_naptr_service_parsing() {
        assert_eq!(
            NaptrService::from_service_field("SIP+D2U"),
            Some(NaptrService::SipUdp)
        );
        assert_eq!(
            NaptrService::from_service_field("SIPS+D2T"),
            Some(NaptrService::SipsTcp)
        );
        assert_eq!(
            NaptrService::from_service_field("sip+d2w"),
            Some(NaptrService::SipWs)
        );
        assert_eq!(NaptrService::from_service_field("invalid"), None);
    }

    #[test]
    fn test_naptr_service_secure() {
        assert!(!NaptrService::SipUdp.is_secure());
        assert!(!NaptrService::SipTcp.is_secure());
        assert!(NaptrService::SipsTcp.is_secure());
        assert!(NaptrService::SipsWs.is_secure());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_naptr_resolver() {
        let mut resolver = NaptrResolver::new();
        resolver.add_records(vec![
            NaptrRecord::new("", 20, 10, "s", "SIP+D2U", "", "_sip._udp.example.com", 300),
            NaptrRecord::new("", 10, 10, "s", "SIP+D2T", "", "_sip._tcp.example.com", 300),
        ]);

        let best = resolver.select_best();
        assert!(best.is_some());
        assert_eq!(best.unwrap().service, "SIP+D2T");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_parse_record() {
        let record = NaptrResolver::parse_record(
            "example.com",
            "10 20 \"s\" \"SIP+D2T\" \"\" _sip._tcp.example.com.",
            300,
        )
        .unwrap();

        assert_eq!(record.order, 10);
        assert_eq!(record.preference, 20);
        assert_eq!(record.flags, "s");
        assert_eq!(record.service, "SIP+D2T");
    }
}
