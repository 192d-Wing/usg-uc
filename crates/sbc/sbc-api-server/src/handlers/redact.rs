//! Trunk credential redaction.
//!
//! Re-exports [`sbc_config_store::redact`], shared with the central config
//! API so both surfaces use one marker and one round-trip rule.
//!
//! ## NIST 800-53 Rev5: IA-5 (Authenticator Management)

pub use sbc_config_store::redact::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// The site API uses the shared module (one marker for both APIs).
    #[test]
    fn site_api_uses_shared_redaction() {
        assert_eq!(REDACTED, sbc_config_store::redact::REDACTED);
        let mut group = serde_json::json!({"trunks": [{"id": "t1", "sip_password": "s"}]});
        trunk_group(&mut group);
        assert_eq!(
            group,
            sbc_config_store::redact::redacted(
                serde_json::json!({"trunks": [{"id": "t1", "sip_password": "s"}]})
            )
        );
    }
}
