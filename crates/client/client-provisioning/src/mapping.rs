//! Maps a provisioned [`ClientConfig`] onto a [`SipAccount`] the existing SIP
//! UA can register with.
//!
//! Bearer mode (the only mode the server emits today) sets
//! [`SipAuthMode::Bearer`] and stashes the access token on the account; the
//! registration path attaches it as `Authorization: Bearer` per RFC 8898.

use client_types::{SipAccount, SipAuthMode, TransportPreference};
use zeroize::Zeroizing;

use crate::wire::ClientConfig;

/// Builds a [`SipAccount`] (`id = "default"`) from a provisioned config and
/// the current access token.
///
/// - `registrar_uri` is derived from `registrar_domain`, with the scheme
///   following `transport`: `sips:` for TLS, `sip:` for UDP/TCP (the scheme
///   drives the UA's default port — 5061 vs 5060).
/// - `caller_id` is set to the `dn`.
/// - For `auth.mode == "bearer"`, `auth_mode = Bearer` and `bearer_token` is
///   set; other modes fall back to the account default (mTLS).
#[must_use]
pub fn to_sip_account(
    cfg: &ClientConfig,
    access_token: &str,
    transport: TransportPreference,
) -> SipAccount {
    let display_name = cfg
        .user
        .as_ref()
        .map(|u| u.display_name.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| cfg.sip.dn.clone());

    let mut account = SipAccount::new(
        "default",
        display_name,
        &cfg.sip.uri,
        registrar_uri(cfg, transport),
    );
    account.transport = transport;
    account.register_expiry = cfg.registration.expires_seconds;
    account.caller_id = Some(cfg.sip.dn.clone());
    account.enabled = true;

    if cfg.sip.auth.mode.eq_ignore_ascii_case("bearer") {
        account.auth_mode = SipAuthMode::Bearer;
        account.bearer_token = Some(Zeroizing::new(access_token.to_string()));
    }

    account
}

/// Seeds the registrar host with a scheme matching the transport: `sips:`
/// for TLS (default port 5061), `sip:` for UDP/TCP (default port 5060).
fn registrar_uri(cfg: &ClientConfig, transport: TransportPreference) -> String {
    let scheme = match transport {
        TransportPreference::TlsOnly => "sips",
        TransportPreference::Udp | TransportPreference::Tcp => "sip",
    };
    format!("{scheme}:{}", cfg.registration.registrar_domain)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn bearer_config() -> ClientConfig {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "user": { "display_name": "Jane Doe" },
            "sip": {
                "uri": "sip:1455550100@example.mil",
                "dn": "1455550100",
                "domain": "example.mil",
                "auth": { "mode": "bearer", "digest": null }
            },
            "registration": { "expires_seconds": 300, "registrar_domain": "us-east-1.reg.example.mil" },
            "ttl_seconds": 3600
        }))
        .unwrap()
    }

    #[test]
    fn maps_bearer_config_to_account() {
        let acct = to_sip_account(&bearer_config(), "tok-123", TransportPreference::TlsOnly);
        assert_eq!(acct.id, "default");
        assert_eq!(acct.display_name, "Jane Doe");
        assert_eq!(acct.sip_uri, "sip:1455550100@example.mil");
        assert_eq!(acct.registrar_uri, "sips:us-east-1.reg.example.mil");
        assert_eq!(acct.caller_id.as_deref(), Some("1455550100"));
        assert_eq!(acct.register_expiry, 300);
        assert_eq!(acct.auth_mode, SipAuthMode::Bearer);
        assert_eq!(
            acct.bearer_token.as_deref().map(String::as_str),
            Some("tok-123")
        );
    }

    #[test]
    fn udp_transport_uses_sip_scheme() {
        let acct = to_sip_account(&bearer_config(), "tok-123", TransportPreference::Udp);
        assert_eq!(acct.registrar_uri, "sip:us-east-1.reg.example.mil");
        assert_eq!(acct.transport, TransportPreference::Udp);
    }
}
