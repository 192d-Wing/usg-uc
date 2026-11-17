//! Discovery trust bootstrap: service-domain parsing, issuer/endpoint scope,
//! OIDC metadata endpoints, provisioned registrar, and the config fetch path.
//!
//! NIST 800-53 Rev5: IA-5, SC-23, SI-10, AC-4.

// Test crate: assertion helpers panic with the failing input in the message.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::time::Duration;

use client_provisioning::discovery::{
    PINNED_ISSUERS, ServiceDomain, parse_service_domain, verify_client_config,
    verify_device_authorization, verify_discovery, verify_issuer_pinned, verify_oidc_endpoints,
};
use client_provisioning::{
    CaTrust, ClientConfig, DeviceAuthorization, DiscoveryDoc, OidcMetadata, ProvisioningClient,
    ProvisioningError,
};

type MetaSetter = fn(&mut OidcMetadata, &str);

const ICAM_ISSUER: &str = "https://icam.oopl.dev.mil/realms/dcim";

fn svc(input: &str) -> ServiceDomain {
    parse_service_domain(input).unwrap_or_else(|e| panic!("`{input}` should parse: {e}"))
}

fn discovery_doc(issuer: &str, config_endpoint: &str) -> DiscoveryDoc {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "service_name": "Voice",
        "pop_id": "pop-1",
        "oidc": {
            "issuer": issuer,
            "client_id": "usg-uc-softclient",
            "scopes": ["openid", "sip"]
        },
        "provisioning": { "config_endpoint": config_endpoint }
    }))
    .unwrap()
}

fn oidc_meta(issuer: &str, endpoint_host: &str) -> OidcMetadata {
    let base = format!("https://{endpoint_host}/realms/dcim/protocol/openid-connect");
    OidcMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{base}/auth"),
        token_endpoint: format!("{base}/token"),
        device_authorization_endpoint: Some(format!("{base}/auth/device")),
        end_session_endpoint: Some(format!("{base}/logout")),
        revocation_endpoint: Some(format!("{base}/revoke")),
    }
}

fn client_config(registrar_domain: &str) -> ClientConfig {
    client_config_sip(
        registrar_domain,
        "sip:1455550100@oopl.dev.mil",
        "oopl.dev.mil",
    )
}

fn client_config_sip(registrar_domain: &str, uri: &str, domain: &str) -> ClientConfig {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "user": { "display_name": "Jane Doe" },
        "sip": {
            "uri": uri,
            "dn": "1455550100",
            "domain": domain,
            "auth": { "mode": "bearer", "digest": null }
        },
        "registration": { "expires_seconds": 300, "registrar_domain": registrar_domain },
        "ttl_seconds": 3600
    }))
    .unwrap()
}

fn client_config_identity(dn: &str, display_name: &str) -> ClientConfig {
    let mut cfg = client_config("reg.oopl.dev.mil");
    dn.clone_into(&mut cfg.sip.dn);
    if let Some(user) = cfg.user.as_mut() {
        display_name.clone_into(&mut user.display_name);
    }
    cfg
}

fn device_auth(uri: &str, complete: Option<&str>) -> DeviceAuthorization {
    serde_json::from_value(serde_json::json!({
        "device_code": "d",
        "user_code": "WDJB-MJHT",
        "verification_uri": uri,
        "verification_uri_complete": complete,
        "expires_in": 600
    }))
    .unwrap()
}

// ---------------------------------------------------------------------
// parse_service_domain
// ---------------------------------------------------------------------

#[test]
fn parse_accepts_bare_host() {
    let s = svc("sbc.oopl.dev.mil");
    assert_eq!(s.host(), "sbc.oopl.dev.mil");
    assert_eq!(s.port(), None);
    assert_eq!(s.registrable(), "oopl.dev.mil");
}

#[test]
fn parse_accepts_https_prefix_default_port_and_trailing_slash() {
    for input in [
        "https://sbc.oopl.dev.mil:443",
        "https://sbc.oopl.dev.mil/",
        "sbc.oopl.dev.mil/",
        "  sbc.oopl.dev.mil  ",
        "SBC.OOPL.DEV.MIL",
    ] {
        let s = svc(input);
        assert_eq!(s.host(), "sbc.oopl.dev.mil", "input `{input}`");
        assert_eq!(s.port(), None, "input `{input}`");
        assert_eq!(s.registrable(), "oopl.dev.mil", "input `{input}`");
    }
}

#[test]
fn parse_keeps_explicit_non_default_port() {
    let s = svc("sbc.oopl.dev.mil:8443");
    assert_eq!(s.host(), "sbc.oopl.dev.mil");
    assert_eq!(s.port(), Some(8443));
    assert_eq!(s.to_string(), "sbc.oopl.dev.mil:8443");
    assert_eq!(
        s.discovery_url(),
        "https://sbc.oopl.dev.mil:8443/.well-known/sip-client-config"
    );
}

#[test]
fn discovery_url_uses_parsed_host_only() {
    assert_eq!(
        svc("https://SBC.oopl.dev.mil:443/").discovery_url(),
        "https://sbc.oopl.dev.mil/.well-known/sip-client-config"
    );
    assert_eq!(svc("sbc.oopl.dev.mil").to_string(), "sbc.oopl.dev.mil");
}

#[test]
fn registrable_uses_suffix_list_not_last_two_labels() {
    assert_eq!(svc("sbc.oopl.dev.mil").registrable(), "oopl.dev.mil");
    assert_eq!(svc("a.b.oopl.dev.mil").registrable(), "oopl.dev.mil");
    assert_eq!(svc("a.dev.mil").registrable(), "a.dev.mil");
    assert_eq!(svc("sip.example.mil").registrable(), "example.mil");
    assert_eq!(svc("x.y.example.com").registrable(), "example.com");
}

#[test]
fn parse_rejects_fragment_query_path_userinfo() {
    for input in [
        "example.com#.oopl.dev.mil",
        "example.com/#.oopl.dev.mil",
        "example.com?.oopl.dev.mil",
        "sbc.oopl.dev.mil?x=1",
        "sbc.oopl.dev.mil/path",
        "sbc.oopl.dev.mil/.well-known/sip-client-config",
        "user@sbc.oopl.dev.mil",
        "user:pw@sbc.oopl.dev.mil",
        "example.com@sbc.oopl.dev.mil",
        "sbc.oopl.dev.mil@example.com",
        "https://user@sbc.oopl.dev.mil/",
        "example.com\\.oopl.dev.mil",
    ] {
        let err = parse_service_domain(input).expect_err(input);
        assert!(
            matches!(err, ProvisioningError::InvalidServiceDomain(_)),
            "`{input}` -> {err:?}"
        );
    }
}

#[test]
fn parse_rejects_non_https_scheme() {
    for input in [
        "http://sbc.oopl.dev.mil",
        "ftp://sbc.oopl.dev.mil",
        "sips:sbc.oopl.dev.mil",
        "file:///etc/hosts",
    ] {
        assert!(
            matches!(
                parse_service_domain(input),
                Err(ProvisioningError::InvalidServiceDomain(_))
            ),
            "`{input}` must be rejected"
        );
    }
}

#[test]
fn parse_rejects_ip_literals_and_non_dns_hosts() {
    for input in [
        "10.0.0.1",
        "10.0.0.1:443",
        "[::1]",
        "https://[2001:db8::1]/",
        "",
        "   ",
        "sbc oopl.dev.mil",
        "sbc_oopl.dev.mil",
        "sbc.oopl.dev.mil:0",
        "sbc.oopl.dev.mil:99999",
        "sbc.oopl.dev.mil:abc",
    ] {
        assert!(
            matches!(
                parse_service_domain(input),
                Err(ProvisioningError::InvalidServiceDomain(_))
            ),
            "`{input}` must be rejected"
        );
    }
}

#[test]
fn parse_rejects_control_characters() {
    // The URL parser silently strips tab/CR/LF; the input must be refused
    // rather than normalized into a different host.
    for input in [
        "sbc.oopl\r\n.dev.mil",
        "sbc.oopl.dev.mil\r\nHost: example.com",
        "sbc.oopl\t.dev.mil",
        "sbc.oopl.dev.mil\0",
    ] {
        assert!(
            matches!(
                parse_service_domain(input),
                Err(ProvisioningError::InvalidServiceDomain(_))
            ),
            "{input:?} must be rejected"
        );
    }
}

#[test]
fn parse_rejects_public_suffix_and_single_label() {
    for input in ["dev.mil", "mil", "com", "localhost", "https://dev.mil/"] {
        assert!(
            matches!(
                parse_service_domain(input),
                Err(ProvisioningError::InvalidServiceDomain(_))
            ),
            "`{input}` must be rejected"
        );
    }
}

// ---------------------------------------------------------------------
// verify_issuer_pinned (compat entry point; &str service domain)
// ---------------------------------------------------------------------

#[test]
fn issuer_same_registrable_domain_accepted() {
    verify_issuer_pinned("sbc.oopl.dev.mil", ICAM_ISSUER).unwrap();
    verify_issuer_pinned("https://sbc.oopl.dev.mil:443", "https://idp.oopl.dev.mil/x").unwrap();
}

#[test]
fn issuer_pin_does_not_apply_to_unrelated_service_domain() {
    let err = verify_issuer_pinned("voice-oopl.example.com", ICAM_ISSUER).unwrap_err();
    assert!(
        matches!(err, ProvisioningError::IssuerNotTrusted(_)),
        "{err:?}"
    );
}

#[test]
fn issuer_check_rejects_unparseable_service_domain() {
    assert!(verify_issuer_pinned("example.com#.oopl.dev.mil", ICAM_ISSUER).is_err());
    assert!(verify_issuer_pinned("user@sbc.oopl.dev.mil", ICAM_ISSUER).is_err());
}

#[test]
fn issuer_sibling_under_shared_suffix_rejected() {
    for issuer in ["https://idp.b.dev.mil/x", "https://b.dev.mil/x"] {
        let err = verify_issuer_pinned("a.dev.mil", issuer).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::IssuerNotTrusted(_)),
            "{issuer}: {err:?}"
        );
    }
}

#[test]
fn issuer_with_userinfo_or_ip_rejected() {
    for issuer in [
        "https://user@icam.oopl.dev.mil/realms/dcim",
        "https://10.0.0.1/realms/dcim",
        "https://[::1]/realms/dcim",
        "http://icam.oopl.dev.mil/realms/dcim",
    ] {
        assert!(
            matches!(
                verify_issuer_pinned("sbc.oopl.dev.mil", issuer),
                Err(ProvisioningError::IssuerNotTrusted(_))
            ),
            "{issuer} must be rejected"
        );
    }
}

#[test]
fn pinned_issuers_apply_only_to_their_service_scope() {
    assert!(
        PINNED_ISSUERS
            .iter()
            .any(|(scope, host)| *scope == "oopl.dev.mil" && *host == "icam.oopl.dev.mil"),
        "the first-party ICAM pin is scoped to oopl.dev.mil"
    );
    for (scope, issuer_host) in PINNED_ISSUERS {
        let issuer = format!("https://{issuer_host}/realms/x");
        verify_issuer_pinned(&format!("sbc.{scope}"), &issuer)
            .unwrap_or_else(|e| panic!("pin {scope} -> {issuer_host} must hold: {e}"));
        for other in ["voice.example.com", "sbc.example.mil", "x.dev.mil"] {
            assert!(
                verify_issuer_pinned(other, &issuer).is_err(),
                "pin {issuer_host} must not apply to {other}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// verify_discovery
// ---------------------------------------------------------------------

#[test]
fn discovery_on_domain_accepted() {
    let s = svc("sbc.oopl.dev.mil");
    verify_discovery(
        &s,
        &discovery_doc(ICAM_ISSUER, "https://sbc.oopl.dev.mil/v1/client-config"),
    )
    .unwrap();
    // Another host in the same registrable domain is in scope.
    verify_discovery(
        &s,
        &discovery_doc(
            ICAM_ISSUER,
            "https://pop1.oopl.dev.mil:8443/v1/client-config",
        ),
    )
    .unwrap();
}

#[test]
fn discovery_with_real_issuer_on_unrelated_domain_rejected() {
    let s = svc("voice-oopl.example.com");
    let err = verify_discovery(
        &s,
        &discovery_doc(
            ICAM_ISSUER,
            "https://voice-oopl.example.com/v1/client-config",
        ),
    )
    .unwrap_err();
    assert!(
        matches!(err, ProvisioningError::IssuerNotTrusted(_)),
        "{err:?}"
    );
}

#[test]
fn discovery_config_endpoint_off_domain_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for endpoint in [
        "https://example.com/v1/client-config",
        "https://sbc.oopl.dev.mil.example.com/v1/client-config",
        "https://oopl.dev.mil.example.com/v1/client-config",
        "https://other.dev.mil/v1/client-config",
        "https://10.0.0.1/v1/client-config",
        "https://[::1]/v1/client-config",
    ] {
        let err = verify_discovery(&s, &discovery_doc(ICAM_ISSUER, endpoint)).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{endpoint}: {err:?}"
        );
    }
}

#[test]
fn discovery_config_endpoint_sibling_under_shared_suffix_rejected() {
    let s = svc("a.dev.mil");
    let err = verify_discovery(
        &s,
        &discovery_doc(
            "https://idp.a.dev.mil/x",
            "https://b.dev.mil/v1/client-config",
        ),
    )
    .unwrap_err();
    assert!(
        matches!(err, ProvisioningError::UntrustedEndpoint(_)),
        "{err:?}"
    );
}

#[test]
fn discovery_config_endpoint_non_https_or_userinfo_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for endpoint in [
        "http://sbc.oopl.dev.mil/v1/client-config",
        "ftp://sbc.oopl.dev.mil/v1/client-config",
        "https://user@sbc.oopl.dev.mil/v1/client-config",
        "https://user:pw@sbc.oopl.dev.mil/v1/client-config",
        "/v1/client-config",
        "",
    ] {
        let err = verify_discovery(&s, &discovery_doc(ICAM_ISSUER, endpoint)).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{endpoint:?}: {err:?}"
        );
    }
}

#[test]
fn discovery_untrusted_issuer_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for issuer in [
        "https://idp.example.com/realms/x",
        "http://icam.oopl.dev.mil/realms/dcim",
    ] {
        let err = verify_discovery(
            &s,
            &discovery_doc(issuer, "https://sbc.oopl.dev.mil/v1/client-config"),
        )
        .unwrap_err();
        assert!(
            matches!(err, ProvisioningError::IssuerNotTrusted(_)),
            "{issuer}: {err:?}"
        );
    }
}

// ---------------------------------------------------------------------
// verify_oidc_endpoints
// ---------------------------------------------------------------------

#[test]
fn oidc_endpoints_on_issuer_domain_accepted() {
    verify_oidc_endpoints(&oidc_meta(ICAM_ISSUER, "icam.oopl.dev.mil")).unwrap();
    // A different host inside the issuer's registrable domain is in scope.
    verify_oidc_endpoints(&oidc_meta(ICAM_ISSUER, "sso.oopl.dev.mil")).unwrap();
    // Optional endpoints absent.
    let mut m = oidc_meta(ICAM_ISSUER, "icam.oopl.dev.mil");
    m.device_authorization_endpoint = None;
    m.end_session_endpoint = None;
    m.revocation_endpoint = None;
    verify_oidc_endpoints(&m).unwrap();
}

#[test]
fn oidc_each_endpoint_off_issuer_domain_rejected() {
    let bad = "https://example.com/token";
    let setters: [(&str, MetaSetter); 5] = [
        ("authorization", |m, v| m.authorization_endpoint = v.into()),
        ("token", |m, v| m.token_endpoint = v.into()),
        ("device", |m, v| {
            m.device_authorization_endpoint = Some(v.into());
        }),
        ("end_session", |m, v| {
            m.end_session_endpoint = Some(v.into());
        }),
        ("revocation", |m, v| m.revocation_endpoint = Some(v.into())),
    ];
    for (name, set) in setters {
        let mut m = oidc_meta(ICAM_ISSUER, "icam.oopl.dev.mil");
        set(&mut m, bad);
        let err = verify_oidc_endpoints(&m).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn oidc_endpoint_non_https_userinfo_or_lookalike_rejected() {
    for bad in [
        "http://icam.oopl.dev.mil/realms/dcim/protocol/openid-connect/token",
        "https://user@icam.oopl.dev.mil/realms/dcim/protocol/openid-connect/token",
        "https://icam.oopl.dev.mil.example.com/token",
        "https://other.dev.mil/token",
        "https://10.0.0.1/token",
        "not a url",
    ] {
        let mut m = oidc_meta(ICAM_ISSUER, "icam.oopl.dev.mil");
        m.token_endpoint = bad.into();
        assert!(
            matches!(
                verify_oidc_endpoints(&m),
                Err(ProvisioningError::UntrustedEndpoint(_))
            ),
            "{bad} must be rejected"
        );
    }
}

#[test]
fn oidc_sibling_under_shared_suffix_rejected() {
    let m = oidc_meta("https://idp.a.dev.mil/realms/x", "idp.b.dev.mil");
    assert!(matches!(
        verify_oidc_endpoints(&m),
        Err(ProvisioningError::UntrustedEndpoint(_))
    ));
}

// ---------------------------------------------------------------------
// verify_client_config (registrar_domain)
// ---------------------------------------------------------------------

#[test]
fn registrar_in_service_domain_accepted() {
    let s = svc("sbc.oopl.dev.mil");
    for reg in [
        "reg.oopl.dev.mil",
        "us-east-1.reg.oopl.dev.mil",
        "reg.oopl.dev.mil:5061",
        "oopl.dev.mil",
    ] {
        verify_client_config(&s, &client_config(reg))
            .unwrap_or_else(|e| panic!("`{reg}` should be accepted: {e}"));
    }
}

#[test]
fn registrar_off_domain_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for reg in [
        "example.com",
        "reg.example.mil",
        "reg.oopl.dev.mil.example.com",
        "other.dev.mil",
        "dev.mil",
        "10.0.0.1",
        "[::1]",
    ] {
        let err = verify_client_config(&s, &client_config(reg)).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "`{reg}`: {err:?}"
        );
    }
}

#[test]
fn registrar_sibling_under_shared_suffix_rejected() {
    let s = svc("a.dev.mil");
    assert!(matches!(
        verify_client_config(&s, &client_config("reg.b.dev.mil")),
        Err(ProvisioningError::UntrustedEndpoint(_))
    ));
}

#[test]
fn registrar_not_bare_host_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for reg in [
        "sips:reg.oopl.dev.mil",
        "sip:reg.oopl.dev.mil",
        "https://reg.oopl.dev.mil",
        "reg.oopl.dev.mil;transport=udp",
        "reg.oopl.dev.mil;maddr=example.com",
        "user@reg.oopl.dev.mil",
        "reg.oopl.dev.mil@example.com",
        "reg.oopl.dev.mil?x=1",
        "reg.oopl.dev.mil/path",
        "reg.oopl.dev.mil ",
        "reg oopl.dev.mil",
        "reg.oopl.dev.mil\r\n",
        "reg.oopl.dev.mil:99999",
        "reg.oopl.dev.mil:",
        "",
    ] {
        let err = verify_client_config(&s, &client_config(reg)).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{reg:?}: {err:?}"
        );
    }
}

// ---------------------------------------------------------------------
// fetch_client_config enforces the endpoint scope before sending the token
// ---------------------------------------------------------------------

#[tokio::test]
async fn fetch_client_config_refuses_plain_http_without_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let pc = ProvisioningClient::new(&CaTrust::System).unwrap();
    let s = svc("sbc.oopl.dev.mil");

    let res = tokio::time::timeout(
        Duration::from_secs(3),
        pc.fetch_client_config(
            &s,
            &format!("http://127.0.0.1:{port}/v1/client-config"),
            "tok",
        ),
    )
    .await
    .expect("must fail fast, not wait on the listener");
    assert!(
        matches!(res, Err(ProvisioningError::UntrustedEndpoint(_))),
        "{res:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "no connection may be made to an untrusted config endpoint"
    );
}

#[tokio::test]
async fn fetch_client_config_refuses_off_domain_endpoint() {
    let pc = ProvisioningClient::new(&CaTrust::System).unwrap();
    let s = svc("sbc.oopl.dev.mil");
    // `.invalid` (RFC 6761) never resolves; the request must be refused
    // before any lookup, so the error is the scope error, not transport.
    let res = pc
        .fetch_client_config(&s, "https://config.example.invalid/v1/client-config", "tok")
        .await;
    assert!(
        matches!(res, Err(ProvisioningError::UntrustedEndpoint(_))),
        "{res:?}"
    );
}

// ---------------------------------------------------------------------
// verify_client_config (sip.uri / sip.domain)
// ---------------------------------------------------------------------

#[test]
fn sip_identity_in_service_domain_accepted() {
    let s = svc("sbc.oopl.dev.mil");
    for (uri, domain) in [
        ("sip:1455550100@oopl.dev.mil", "oopl.dev.mil"),
        ("sips:1455550100@sip.oopl.dev.mil", "sip.oopl.dev.mil"),
        ("SIP:1455550100@oopl.dev.mil:5061", "OOPL.dev.mil"),
        ("sip:oopl.dev.mil", "oopl.dev.mil"),
        ("sip:jane.doe%2Bx@oopl.dev.mil", "oopl.dev.mil"),
    ] {
        verify_client_config(&s, &client_config_sip("reg.oopl.dev.mil", uri, domain))
            .unwrap_or_else(|e| panic!("`{uri}` / `{domain}` should be accepted: {e}"));
    }
}

#[test]
fn sip_uri_off_domain_or_malformed_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for uri in [
        "sip:1455550100@example.com",
        "sip:1455550100@other.dev.mil",
        "sip:1455550100@dev.mil",
        "sip:1455550100@10.0.0.1",
        "sip:1455550100@[::1]",
        "tel:+14155550100",
        "https://oopl.dev.mil/",
        "1455550100@oopl.dev.mil",
        "sip:1455550100@oopl.dev.mil?Route=%3Csip:example.com%3E",
        "sip:1455550100@oopl.dev.mil;maddr=example.com",
        "sip:1455550100@oopl.dev.mil;transport=udp",
        "sip:a@example.com;x=b@oopl.dev.mil",
        "sip:a@b@oopl.dev.mil",
        "sip:user:pw@oopl.dev.mil",
        "sip:@oopl.dev.mil",
        "sip:1455550100@oopl.dev.mil:0",
        "sip:1455550100@oopl.dev.mil:",
        "sip:1455550100@oopl.dev.mil\r\n",
        "sip:1455550100 @oopl.dev.mil",
        "sip:jane%2@oopl.dev.mil",
        "sip:jane%@oopl.dev.mil",
        "sip:jane%zz@oopl.dev.mil",
        "sip:%G0@oopl.dev.mil",
        "sip:",
        "",
    ] {
        let err = verify_client_config(
            &s,
            &client_config_sip("reg.oopl.dev.mil", uri, "oopl.dev.mil"),
        )
        .unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{uri:?}: {err:?}"
        );
    }
}

#[test]
fn sip_domain_off_domain_or_not_bare_host_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for domain in [
        "example.com",
        "other.dev.mil",
        "dev.mil",
        "oopl.dev.mil:5061",
        "sip:oopl.dev.mil",
        "user@oopl.dev.mil",
        "oopl.dev.mil;x=1",
        "10.0.0.1",
        "",
    ] {
        let err = verify_client_config(
            &s,
            &client_config_sip("reg.oopl.dev.mil", "sip:1455550100@oopl.dev.mil", domain),
        )
        .unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{domain:?}: {err:?}"
        );
    }
}

#[test]
fn sip_dn_and_display_name_accepted() {
    let s = svc("sbc.oopl.dev.mil");
    for (dn, name) in [
        ("1455550100", "Jane Doe"),
        ("jane.doe%2Bx", "O'Brien, Jane (Ops)"),
        ("+14155550100", ""),
        ("1455550100", "Zoë Müller"),
    ] {
        verify_client_config(&s, &client_config_identity(dn, name))
            .unwrap_or_else(|e| panic!("{dn:?} / {name:?} should be accepted: {e}"));
    }
    // No `user` block at all is fine; the GUI falls back to `sip.dn`.
    let mut cfg = client_config("reg.oopl.dev.mil");
    cfg.user = None;
    verify_client_config(&s, &cfg).unwrap();
}

#[test]
fn sip_dn_empty_or_not_user_part_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for dn in [
        "",
        "1455550100\r\nVia: x",
        "1455550100\0",
        "jane doe",
        "a@b",
        "a:b",
        "a;b",
        "a?b",
        "a/b",
        "<a>",
        "a%2",
        "a%zz",
        "%",
    ] {
        let err = verify_client_config(&s, &client_config_identity(dn, "Jane Doe")).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{dn:?}: {err:?}"
        );
    }
}

#[test]
fn display_name_control_chars_or_angle_brackets_rejected() {
    let s = svc("sbc.oopl.dev.mil");
    for name in [
        "Jane\r\nVia: SIP/2.0/UDP x",
        "Jane\nDoe",
        "Jane\rDoe",
        "Jane\0Doe",
        "Jane\tDoe",
        "Jane\u{1b}[2J",
        "Jane\u{7f}",
        "Jane\u{85}Doe",
        "Jane <sip:x@example.com>",
        "Jane>",
        "<Jane",
    ] {
        let err =
            verify_client_config(&s, &client_config_identity("1455550100", name)).unwrap_err();
        assert!(
            matches!(err, ProvisioningError::UntrustedEndpoint(_)),
            "{name:?}: {err:?}"
        );
    }
}

// ---------------------------------------------------------------------
// verify_device_authorization (verification_uri[_complete])
// ---------------------------------------------------------------------

#[test]
fn device_verification_uris_on_issuer_domain_accepted() {
    let meta = oidc_meta(ICAM_ISSUER, "icam.oopl.dev.mil");
    let base = "https://icam.oopl.dev.mil/realms/dcim/device";
    verify_device_authorization(&meta, &device_auth(base, None)).unwrap();
    verify_device_authorization(
        &meta,
        &device_auth(base, Some(&format!("{base}?user_code=WDJB-MJHT"))),
    )
    .unwrap();
}

#[test]
fn device_verification_uris_off_issuer_domain_rejected() {
    let meta = oidc_meta(ICAM_ISSUER, "icam.oopl.dev.mil");
    let good = "https://icam.oopl.dev.mil/realms/dcim/device";
    for bad in [
        "https://login.example.com/device",
        "https://icam.other.dev.mil/device",
        "http://icam.oopl.dev.mil/device",
        "https://user@icam.oopl.dev.mil/device",
        "https://10.0.0.1/device",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "not a url",
    ] {
        for device in [device_auth(bad, None), device_auth(good, Some(bad))] {
            let err = verify_device_authorization(&meta, &device).unwrap_err();
            assert!(
                matches!(err, ProvisioningError::UntrustedEndpoint(_)),
                "{bad:?}: {err:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// issuer query / fragment
// ---------------------------------------------------------------------

#[test]
fn issuer_with_query_or_fragment_rejected() {
    for issuer in [
        "https://icam.oopl.dev.mil/realms/dcim?x=1",
        "https://icam.oopl.dev.mil/realms/dcim?",
        "https://icam.oopl.dev.mil/realms/dcim#frag",
        "https://icam.oopl.dev.mil/realms/dcim#",
    ] {
        assert!(
            matches!(
                verify_issuer_pinned("sbc.oopl.dev.mil", issuer),
                Err(ProvisioningError::IssuerNotTrusted(_))
            ),
            "{issuer:?}"
        );
        let doc = discovery_doc(issuer, "https://sbc.oopl.dev.mil/v1/client-config");
        assert!(
            matches!(
                verify_discovery(&svc("sbc.oopl.dev.mil"), &doc),
                Err(ProvisioningError::IssuerNotTrusted(_))
            ),
            "{issuer:?}"
        );
        assert!(
            matches!(
                verify_oidc_endpoints(&oidc_meta(issuer, "icam.oopl.dev.mil")),
                Err(ProvisioningError::UntrustedEndpoint(_))
            ),
            "{issuer:?}"
        );
    }
}

#[tokio::test]
async fn fetch_oidc_metadata_refuses_issuer_with_query_before_io() {
    let pc = ProvisioningClient::new(&CaTrust::System).unwrap();
    // `.invalid` never resolves; the scope error must come before any lookup.
    let res = pc
        .fetch_oidc_metadata("https://icam.example.invalid/realms/x?y=1")
        .await;
    assert!(
        matches!(res, Err(ProvisioningError::IssuerNotTrusted(_))),
        "{res:?}"
    );
}
