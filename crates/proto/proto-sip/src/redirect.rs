//! SIP redirect handling per RFC 3261 Section 13.2.2.4.
//!
//! This module implements redirect response (3xx) handling for UACs,
//! including Contact header parsing with q-value ordering.
//!
//! ## RFC 3261 Section 13.2.2.4 Compliance
//!
//! When a UAC receives a 3xx response:
//! 1. Extract Contact header field values
//! 2. Order contacts by q-value (highest first)
//! 3. Re-attempt request to alternate locations
//!
//! ## Security Considerations
//!
//! Per RFC 3261 Section 26.4.4:
//! - UACs SHOULD limit redirect recursion depth
//! - UACs MAY require user confirmation for redirects
//! - Redirects to different domains should be treated carefully

use crate::error::{SipError, SipResult};
use crate::header::HeaderName;
use crate::header_params::NameAddr;
use crate::uri::SipUri;
use std::cmp::Ordering;

/// Default maximum redirect depth to prevent loops.
pub const DEFAULT_MAX_REDIRECT_DEPTH: u8 = 5;

/// Default q-value when not specified (RFC 3261 Section 20.10).
const DEFAULT_Q_VALUE: f32 = 1.0;

/// A contact from a 3xx redirect response.
///
/// ## RFC 3261 Section 20.10
///
/// Contact headers in 3xx responses contain alternative locations
/// where the request may be retried, optionally with q-values
/// indicating preference.
#[derive(Debug, Clone)]
pub struct RedirectContact {
    /// The contact URI.
    uri: SipUri,
    /// Display name if present.
    display_name: Option<String>,
    /// Q-value (0.0-1.0) indicating preference. Higher is preferred.
    q_value: f32,
    /// Expires value if present (seconds).
    expires: Option<u32>,
}

impl RedirectContact {
    /// Creates a new redirect contact.
    #[must_use]
    pub fn new(uri: SipUri) -> Self {
        Self {
            uri,
            display_name: None,
            q_value: DEFAULT_Q_VALUE,
            expires: None,
        }
    }

    /// Creates from a `NameAddr` with q-value parsing.
    ///
    /// ## RFC 3261 Section 20.10
    ///
    /// The q parameter indicates relative preference (0.0-1.0).
    #[must_use]
    pub fn from_name_addr(name_addr: &NameAddr, raw_value: &str) -> Self {
        let mut q_value = DEFAULT_Q_VALUE;
        let mut expires = None;

        // Parse q-value and expires from the raw header value
        // These appear after the URI as ;q=x.x and ;expires=xxx
        for param in raw_value.split(';') {
            let param = param.trim();
            if let Some(q_str) = param.strip_prefix("q=") {
                if let Ok(q) = q_str.parse::<f32>() {
                    // Clamp to valid range
                    q_value = q.clamp(0.0, 1.0);
                }
            } else if let Some(exp_str) = param.strip_prefix("expires=") {
                expires = exp_str.parse().ok();
            }
        }

        Self {
            uri: name_addr.uri.clone(),
            display_name: name_addr.display_name.clone(),
            q_value,
            expires,
        }
    }

    /// Returns the contact URI.
    #[must_use]
    pub fn uri(&self) -> &SipUri {
        &self.uri
    }

    /// Returns the display name if present.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Returns the q-value preference (0.0-1.0).
    #[must_use]
    pub fn q_value(&self) -> f32 {
        self.q_value
    }

    /// Returns the expires value if present.
    #[must_use]
    pub fn expires(&self) -> Option<u32> {
        self.expires
    }

    /// Consumes self and returns the URI.
    #[must_use]
    pub fn into_uri(self) -> SipUri {
        self.uri
    }
}

impl PartialEq for RedirectContact {
    fn eq(&self, other: &Self) -> bool {
        self.uri == other.uri
    }
}

impl Eq for RedirectContact {}

impl PartialOrd for RedirectContact {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RedirectContact {
    /// Orders by q-value descending (higher q-value first).
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order: higher q-value should come first
        other
            .q_value
            .partial_cmp(&self.q_value)
            .unwrap_or(Ordering::Equal)
    }
}

/// Result of processing a redirect response.
///
/// ## RFC 3261 Section 13.2.2.4
///
/// Contains the ordered list of contacts to try and
/// information about the redirect response.
#[derive(Debug, Clone)]
pub struct RedirectResult {
    /// Ordered list of contacts to try (highest q-value first).
    contacts: Vec<RedirectContact>,
    /// The status code that triggered the redirect (300-399).
    status_code: u16,
    /// Retry-After value if present (seconds).
    retry_after: Option<u32>,
}

impl RedirectResult {
    /// Creates a new redirect result.
    fn new(status_code: u16) -> Self {
        Self {
            contacts: Vec::new(),
            status_code,
            retry_after: None,
        }
    }

    /// Returns the contacts ordered by preference.
    #[must_use]
    pub fn contacts(&self) -> &[RedirectContact] {
        &self.contacts
    }

    /// Returns the first (highest preference) contact.
    #[must_use]
    pub fn first_contact(&self) -> Option<&RedirectContact> {
        self.contacts.first()
    }

    /// Returns the status code.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Returns the Retry-After value if present.
    #[must_use]
    pub fn retry_after(&self) -> Option<u32> {
        self.retry_after
    }

    /// Returns true if this is a permanent redirect (301).
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        self.status_code == 301
    }

    /// Returns true if this is a temporary redirect (302).
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        self.status_code == 302
    }

    /// Returns true if there are multiple choices (300).
    #[must_use]
    pub fn is_multiple_choices(&self) -> bool {
        self.status_code == 300
    }

    /// Returns the number of available contacts.
    #[must_use]
    pub fn contact_count(&self) -> usize {
        self.contacts.len()
    }

    /// Returns true if there are no contacts to try.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Consumes self and returns the contacts as an iterator.
    pub fn into_contacts(self) -> impl Iterator<Item = RedirectContact> {
        self.contacts.into_iter()
    }
}

/// Parses a 3xx redirect response and extracts ordered contacts.
///
/// ## RFC 3261 Section 13.2.2.4
///
/// The UAC extracts Contact header field values from the redirect
/// response and places them in its target set. Contacts are ordered
/// by q-value preference.
///
/// ## Arguments
///
/// * `status_code` - The 3xx status code
/// * `contact_headers` - Raw Contact header values
/// * `retry_after` - Optional Retry-After header value
///
/// ## Errors
///
/// Returns an error if the status code is not a redirect (3xx).
pub fn parse_redirect_response(
    status_code: u16,
    contact_headers: &[String],
    retry_after: Option<u32>,
) -> SipResult<RedirectResult> {
    // Validate status code is a redirect
    if !(300..400).contains(&status_code) {
        return Err(SipError::InvalidStatusCode { code: status_code });
    }

    let mut result = RedirectResult::new(status_code);
    result.retry_after = retry_after;

    // Parse each Contact header
    for header_value in contact_headers {
        // Contact headers may contain multiple comma-separated values
        for contact_str in split_contact_header(header_value) {
            if let Ok(name_addr) = contact_str.parse::<NameAddr>() {
                let contact = RedirectContact::from_name_addr(&name_addr, contact_str);
                result.contacts.push(contact);
            }
        }
    }

    // Sort by q-value (highest first)
    result.contacts.sort();

    Ok(result)
}

/// Splits a Contact header value that may contain multiple contacts.
///
/// Handles quoted strings and angle brackets properly.
fn split_contact_header(header: &str) -> Vec<&str> {
    // Handle the special case of "*" (wildcard)
    let header = header.trim();
    if header == "*" {
        return vec![header];
    }

    let mut result = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut in_angle = false;

    let chars: Vec<char> = header.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        match c {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => in_angle = true,
            '>' if !in_quotes => in_angle = false,
            ',' if !in_quotes && !in_angle => {
                let entry = header[start..i].trim();
                if !entry.is_empty() {
                    result.push(entry);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    // Add last entry
    let entry = header[start..].trim();
    if !entry.is_empty() {
        result.push(entry);
    }

    result
}

/// Redirect handler for managing redirect attempts.
///
/// ## Security Considerations
///
/// This handler tracks redirect depth to prevent infinite loops
/// as recommended by RFC 3261 Section 26.4.4.
#[derive(Debug)]
pub struct RedirectHandler {
    /// Maximum redirect depth.
    max_depth: u8,
    /// Current redirect depth.
    current_depth: u8,
    /// URIs that have been tried.
    tried_uris: Vec<SipUri>,
}

impl RedirectHandler {
    /// Creates a new redirect handler with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_depth: DEFAULT_MAX_REDIRECT_DEPTH,
            current_depth: 0,
            tried_uris: Vec::new(),
        }
    }

    /// Creates a handler with a custom maximum depth.
    #[must_use]
    pub fn with_max_depth(max_depth: u8) -> Self {
        Self {
            max_depth,
            current_depth: 0,
            tried_uris: Vec::new(),
        }
    }

    /// Returns the maximum redirect depth.
    #[must_use]
    pub fn max_depth(&self) -> u8 {
        self.max_depth
    }

    /// Returns the current redirect depth.
    #[must_use]
    pub fn current_depth(&self) -> u8 {
        self.current_depth
    }

    /// Returns true if maximum redirect depth has been reached.
    #[must_use]
    pub fn at_max_depth(&self) -> bool {
        self.current_depth >= self.max_depth
    }

    /// Records a redirect attempt and returns the next untried contact.
    ///
    /// ## Arguments
    ///
    /// * `result` - The redirect result to process
    ///
    /// ## Returns
    ///
    /// The next contact URI to try, or None if:
    /// - Maximum depth reached
    /// - All contacts have been tried
    /// - No contacts available
    pub fn next_target(&mut self, result: &RedirectResult) -> Option<SipUri> {
        if self.at_max_depth() {
            return None;
        }

        // Find first contact that hasn't been tried
        for contact in result.contacts() {
            if !self.tried_uris.contains(contact.uri()) {
                self.tried_uris.push(contact.uri().clone());
                self.current_depth += 1;
                return Some(contact.uri().clone());
            }
        }

        None
    }

    /// Returns true if a URI has already been tried.
    #[must_use]
    pub fn has_tried(&self, uri: &SipUri) -> bool {
        self.tried_uris.contains(uri)
    }

    /// Resets the handler for a new request.
    pub fn reset(&mut self) {
        self.current_depth = 0;
        self.tried_uris.clear();
    }
}

impl Default for RedirectHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension trait for headers to support redirect parsing.
pub trait RedirectHeaders {
    /// Extracts redirect contacts from a response with headers.
    fn redirect_contacts(&self) -> Vec<String>;

    /// Extracts Retry-After value if present.
    fn retry_after_value(&self) -> Option<u32>;
}

impl RedirectHeaders for crate::header::Headers {
    fn redirect_contacts(&self) -> Vec<String> {
        self.get_all(&HeaderName::Contact)
            .iter()
            .map(|h| h.value.clone())
            .collect()
    }

    fn retry_after_value(&self) -> Option<u32> {
        self.get_value(&HeaderName::RetryAfter).and_then(|v| {
            // Retry-After may be a date or seconds
            // We only parse the seconds form
            v.split_whitespace().next().and_then(|s| s.parse().ok())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_contact_ordering() {
        let uri1: SipUri = "sip:alice@example1.com".parse().unwrap();
        let uri2: SipUri = "sip:alice@example2.com".parse().unwrap();
        let uri3: SipUri = "sip:alice@example3.com".parse().unwrap();

        let mut contacts = [
            RedirectContact {
                uri: uri1,
                display_name: None,
                q_value: 0.5,
                expires: None,
            },
            RedirectContact {
                uri: uri2,
                display_name: None,
                q_value: 1.0,
                expires: None,
            },
            RedirectContact {
                uri: uri3,
                display_name: None,
                q_value: 0.8,
                expires: None,
            },
        ];

        contacts.sort();

        // Should be ordered by q-value descending
        assert_eq!(contacts[0].q_value(), 1.0);
        assert_eq!(contacts[1].q_value(), 0.8);
        assert_eq!(contacts[2].q_value(), 0.5);
    }

    #[test]
    fn test_parse_redirect_response() {
        let contacts = vec![
            "<sip:alice@example1.com>;q=0.5".to_string(),
            "<sip:alice@example2.com>;q=1.0".to_string(),
        ];

        let result = parse_redirect_response(302, &contacts, None).unwrap();

        assert_eq!(result.status_code(), 302);
        assert_eq!(result.contact_count(), 2);
        assert!(result.is_temporary());

        // First contact should have highest q-value
        let first = result.first_contact().unwrap();
        assert_eq!(first.q_value(), 1.0);
    }

    #[test]
    fn test_parse_redirect_multiple_in_header() {
        let contacts =
            vec!["<sip:alice@example1.com>;q=0.5, <sip:alice@example2.com>;q=0.8".to_string()];

        let result = parse_redirect_response(301, &contacts, None).unwrap();

        assert_eq!(result.contact_count(), 2);
        assert!(result.is_permanent());
    }

    #[test]
    fn test_parse_redirect_invalid_status() {
        let result = parse_redirect_response(200, &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_redirect_handler_depth() {
        let mut handler = RedirectHandler::with_max_depth(2);
        assert_eq!(handler.max_depth(), 2);
        assert_eq!(handler.current_depth(), 0);
        assert!(!handler.at_max_depth());

        let contacts = vec![
            "<sip:alice@example1.com>".to_string(),
            "<sip:alice@example2.com>".to_string(),
            "<sip:alice@example3.com>".to_string(),
        ];

        let result = parse_redirect_response(302, &contacts, None).unwrap();

        // First redirect
        let target1 = handler.next_target(&result);
        assert!(target1.is_some());
        assert_eq!(handler.current_depth(), 1);

        // Second redirect
        let target2 = handler.next_target(&result);
        assert!(target2.is_some());
        assert_eq!(handler.current_depth(), 2);
        assert!(handler.at_max_depth());

        // Should not get another target (max depth reached)
        let target3 = handler.next_target(&result);
        assert!(target3.is_none());
    }

    #[test]
    fn test_redirect_handler_tried_uris() {
        let mut handler = RedirectHandler::new();

        let contacts = vec!["<sip:alice@example.com>".to_string()];
        let result = parse_redirect_response(302, &contacts, None).unwrap();

        let target = handler.next_target(&result);
        assert!(target.is_some());

        // Same URI should not be returned again
        let target2 = handler.next_target(&result);
        assert!(target2.is_none());
    }

    #[test]
    fn test_redirect_handler_reset() {
        let mut handler = RedirectHandler::new();

        let contacts = vec!["<sip:alice@example.com>".to_string()];
        let result = parse_redirect_response(302, &contacts, None).unwrap();

        handler.next_target(&result);
        assert_eq!(handler.current_depth(), 1);

        handler.reset();
        assert_eq!(handler.current_depth(), 0);

        // Should be able to get target again after reset
        let target = handler.next_target(&result);
        assert!(target.is_some());
    }

    #[test]
    fn test_split_contact_header() {
        let header = "<sip:a@example.com>, <sip:b@example.com>";
        let parts = split_contact_header(header);
        assert_eq!(parts.len(), 2);

        // With display name containing comma
        let header = "\"Name, Jr.\" <sip:a@example.com>, <sip:b@example.com>";
        let parts = split_contact_header(header);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("Name, Jr."));
    }

    #[test]
    fn test_redirect_contact_from_name_addr() {
        let name_addr: NameAddr = "<sip:alice@example.com>".parse().unwrap();
        let raw = "<sip:alice@example.com>;q=0.7;expires=3600";

        let contact = RedirectContact::from_name_addr(&name_addr, raw);
        assert_eq!(contact.q_value(), 0.7);
        assert_eq!(contact.expires(), Some(3600));
    }

    #[test]
    fn test_redirect_result_types() {
        let result = parse_redirect_response(300, &[], None).unwrap();
        assert!(result.is_multiple_choices());

        let result = parse_redirect_response(301, &[], None).unwrap();
        assert!(result.is_permanent());

        let result = parse_redirect_response(302, &[], None).unwrap();
        assert!(result.is_temporary());
    }

    #[test]
    fn test_redirect_with_retry_after() {
        let contacts = vec!["<sip:alice@example.com>".to_string()];
        let result = parse_redirect_response(302, &contacts, Some(120)).unwrap();

        assert_eq!(result.retry_after(), Some(120));
    }
}
