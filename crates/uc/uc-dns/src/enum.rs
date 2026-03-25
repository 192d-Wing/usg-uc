//! ENUM (E.164 to URI) lookup per RFC 6116.
//!
//! ENUM allows mapping E.164 telephone numbers to URIs (SIP, H.323, etc.)
//! using DNS NAPTR records.

use crate::config::EnumConfig;
use crate::error::{DnsError, DnsResult};
use crate::naptr::NaptrRecord;
use tracing::{debug, info};

/// Result of an ENUM lookup.
#[derive(Debug, Clone)]
pub struct EnumResult {
    /// The original E.164 number.
    pub number: String,
    /// The resolved URI.
    pub uri: String,
    /// The service type (e.g., "E2U+sip").
    pub service: String,
    /// Order from NAPTR record.
    pub order: u16,
    /// Preference from NAPTR record.
    pub preference: u16,
    /// TTL in seconds.
    pub ttl: u32,
}

impl EnumResult {
    /// Creates a new ENUM result.
    #[must_use]
    pub fn new(
        number: impl Into<String>,
        uri: impl Into<String>,
        service: impl Into<String>,
        order: u16,
        preference: u16,
        ttl: u32,
    ) -> Self {
        Self {
            number: number.into(),
            uri: uri.into(),
            service: service.into(),
            order,
            preference,
            ttl,
        }
    }

    /// Returns true if this is a SIP URI.
    #[must_use]
    pub fn is_sip(&self) -> bool {
        self.service.to_uppercase().contains("SIP")
            || self.uri.starts_with("sip:")
            || self.uri.starts_with("sips:")
    }

    /// Returns true if this is an H.323 URI.
    #[must_use]
    pub fn is_h323(&self) -> bool {
        self.service.to_uppercase().contains("H323") || self.uri.starts_with("h323:")
    }

    /// Returns true if this is an email/mailto URI.
    #[must_use]
    pub fn is_email(&self) -> bool {
        self.service.to_uppercase().contains("MAILTO") || self.uri.starts_with("mailto:")
    }
}

/// ENUM resolver for E.164 to URI mapping.
#[derive(Debug)]
pub struct EnumResolver {
    /// Configuration.
    config: EnumConfig,
}

impl EnumResolver {
    /// Creates a new ENUM resolver.
    #[must_use]
    pub fn new(config: EnumConfig) -> Self {
        Self { config }
    }

    /// Converts an E.164 number to an ENUM domain name.
    ///
    /// E.164: +1-555-123-4567
    /// ENUM:  7.6.5.4.3.2.1.5.5.5.1.e164.arpa
    ///
    /// # Errors
    ///
    /// Returns an error if the number format is invalid.
    pub fn number_to_domain(&self, number: &str, enum_domain: &str) -> DnsResult<String> {
        // Remove non-digit characters except leading +
        let digits: String = number.chars().filter(char::is_ascii_digit).collect();

        if digits.is_empty() {
            return Err(DnsError::InvalidEnum {
                number: number.to_string(),
                reason: "no digits found".to_string(),
            });
        }

        if digits.len() < 3 || digits.len() > 15 {
            return Err(DnsError::InvalidEnum {
                number: number.to_string(),
                reason: format!("invalid length: {} (expected 3-15)", digits.len()),
            });
        }

        // Reverse digits and join with dots
        let reversed: String = digits
            .chars()
            .rev()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(".");

        let domain = format!("{reversed}.{enum_domain}");
        debug!(number = %number, domain = %domain, "Converted number to ENUM domain");

        Ok(domain)
    }

    /// Returns the list of ENUM domains to query.
    #[must_use]
    pub fn enum_domains(&self) -> &[String] {
        &self.config.domains
    }

    /// Returns the preferred services in order.
    #[must_use]
    pub fn preferred_services(&self) -> &[String] {
        &self.config.preferred_services
    }

    /// Checks if a service matches the preferred services.
    #[must_use]
    pub fn is_preferred_service(&self, service: &str) -> bool {
        let upper = service.to_uppercase();
        self.config
            .preferred_services
            .iter()
            .any(|s| s.to_uppercase() == upper)
    }

    /// Applies the NAPTR regexp to transform a number to a URI.
    ///
    /// ENUM NAPTR regexp format: !pattern!replacement!
    ///
    /// # Errors
    ///
    /// Returns an error if the regexp is invalid.
    pub fn apply_regexp(&self, number: &str, regexp: &str) -> DnsResult<String> {
        if regexp.is_empty() {
            return Err(DnsError::InvalidEnum {
                number: number.to_string(),
                reason: "empty regexp".to_string(),
            });
        }

        // Parse regexp: !pattern!replacement![flags]
        let delim = regexp.chars().next().unwrap_or('!');
        let parts: Vec<&str> = regexp.split(delim).collect();

        if parts.len() < 3 {
            return Err(DnsError::InvalidEnum {
                number: number.to_string(),
                reason: format!("invalid regexp format: {regexp}"),
            });
        }

        let pattern = parts[1];
        let replacement = parts[2];

        // Simple pattern matching (real implementation would use regex crate)
        // For now, just use the replacement with number substitution
        let uri = if pattern == "^.*$" {
            // Match entire string, replace completely
            replacement.replace("\\1", number)
        } else if pattern.starts_with("^\\+") {
            // Match E.164 format
            replacement.replace("\\1", number)
        } else {
            // Generic replacement
            replacement.to_string()
        };

        debug!(
            number = %number,
            regexp = %regexp,
            uri = %uri,
            "Applied ENUM regexp"
        );

        Ok(uri)
    }

    /// Processes NAPTR records to extract ENUM results.
    pub fn process_naptr_records(&self, number: &str, records: &[NaptrRecord]) -> Vec<EnumResult> {
        let mut results = Vec::new();

        for record in records {
            // Check if this is an ENUM service (E2U+*)
            if !record.service.to_uppercase().starts_with("E2U+") {
                continue;
            }

            // Try to apply the regexp
            if !record.regexp.is_empty()
                && let Ok(uri) = self.apply_regexp(number, &record.regexp)
            {
                results.push(EnumResult::new(
                    number,
                    uri,
                    &record.service,
                    record.order,
                    record.preference,
                    record.ttl,
                ));
            }
        }

        // Sort by order, then preference
        results.sort_by(|a, b| match a.order.cmp(&b.order) {
            std::cmp::Ordering::Equal => a.preference.cmp(&b.preference),
            other => other,
        });

        if !results.is_empty() {
            info!(
                number = %number,
                count = results.len(),
                "Found ENUM results"
            );
        }

        results
    }

    /// Selects the best SIP result from ENUM results.
    #[must_use]
    pub fn select_best_sip<'a>(&self, results: &'a [EnumResult]) -> Option<&'a EnumResult> {
        results.iter().find(|r| r.is_sip())
    }
}

impl Default for EnumResolver {
    fn default() -> Self {
        Self::new(EnumConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_number_to_domain() {
        let resolver = EnumResolver::default();

        let domain = resolver
            .number_to_domain("+1-555-123-4567", "e164.arpa")
            .unwrap();
        assert_eq!(domain, "7.6.5.4.3.2.1.5.5.5.1.e164.arpa");

        let domain2 = resolver
            .number_to_domain("15551234567", "e164.arpa")
            .unwrap();
        assert_eq!(domain2, "7.6.5.4.3.2.1.5.5.5.1.e164.arpa");
    }

    #[test]
    fn test_number_to_domain_invalid() {
        let resolver = EnumResolver::default();

        // Too short
        assert!(resolver.number_to_domain("12", "e164.arpa").is_err());

        // No digits
        assert!(resolver.number_to_domain("abc", "e164.arpa").is_err());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_apply_regexp() {
        let resolver = EnumResolver::default();

        // Simple replacement
        let uri = resolver
            .apply_regexp("+15551234567", "!^.*$!sip:user@example.com!")
            .unwrap();
        assert_eq!(uri, "sip:user@example.com");
    }

    #[test]
    fn test_enum_result_types() {
        let sip_result = EnumResult::new(
            "+15551234567",
            "sip:user@example.com",
            "E2U+sip",
            10,
            10,
            300,
        );
        assert!(sip_result.is_sip());
        assert!(!sip_result.is_h323());

        let h323_result = EnumResult::new(
            "+15551234567",
            "h323:user@example.com",
            "E2U+h323",
            20,
            10,
            300,
        );
        assert!(h323_result.is_h323());
        assert!(!h323_result.is_sip());
    }

    #[test]
    fn test_process_naptr_records() {
        let resolver = EnumResolver::default();

        let records = vec![
            NaptrRecord::new(
                "7.6.5.4.3.2.1.5.5.5.1.e164.arpa",
                10,
                10,
                "u",
                "E2U+sip",
                "!^.*$!sip:user@example.com!",
                ".",
                300,
            ),
            NaptrRecord::new(
                "7.6.5.4.3.2.1.5.5.5.1.e164.arpa",
                20,
                10,
                "u",
                "E2U+h323",
                "!^.*$!h323:user@example.com!",
                ".",
                300,
            ),
        ];

        let results = resolver.process_naptr_records("+15551234567", &records);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_sip()); // Lower order first
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_select_best_sip() {
        let resolver = EnumResolver::default();

        let results = vec![
            EnumResult::new("+1", "h323:a@example.com", "E2U+h323", 10, 10, 300),
            EnumResult::new("+1", "sip:b@example.com", "E2U+sip", 20, 10, 300),
        ];

        let best = resolver.select_best_sip(&results);
        assert!(best.is_some());
        assert!(best.unwrap().is_sip());
    }
}
