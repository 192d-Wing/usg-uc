//! SR-42a (QA-first): rejects an unauthenticated sender can drive at line
//! rate (source-admission 403, bearer REGISTER failure) are audited through
//! `SignalingAudit`, aggregated per (source prefix, policy), through
//! `process_message` with the shared fixtures of the parent test module.
//!
//! ## NIST 800-53 Rev5: AU-3, AU-4, AU-5, SC-5, AC-3

use super::*;

fn authz(events: &[uc_audit::AuditEvent]) -> Vec<uc_audit::event::AuthorizationDecision> {
    events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::AuthorizationDecision(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

fn auth_failures(events: &[uc_audit::AuditEvent]) -> Vec<uc_audit::event::AuthenticationAttempt> {
    events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::AuthenticationAttempt(a) if !a.success => Some(a.clone()),
            _ => None,
        })
        .collect()
}

/// Plan 8: N INVITEs from M rotating sources inside one /24 give one
/// `AuthorizationDecision` (first event unchanged: `source-admission`),
/// then one flushed record with `;count=N-1`. Every INVITE still gets 403.
#[tokio::test]
async fn qa_source_admission_flood_is_aggregated() {
    let stack = trunk_stack(10, ("none", ""), None).await;
    let capture = uc_audit::capture::start();
    let n = 50u8;
    for i in 1..=n {
        let stranger = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, i), 5060);
        let r = flatten(
            stack
                .process_message(
                    &caller_request(
                        "INVITE",
                        DIALED,
                        &format!("acl-flood-{i}@x"),
                        1,
                        None,
                        Some(ALICE_SDP),
                    ),
                    stranger,
                    None,
                )
                .await,
        );
        assert!(responded(&r, 403).is_some(), "INVITE {i} is still refused");
    }
    let first = authz(&capture.events());
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(first[0].policy, "source-admission");
    assert_eq!(
        first[0].source_ip,
        Some(std::net::IpAddr::from([203, 0, 113, 1]))
    );
    let window = stack.signaling_audit().window();
    stack
        .signaling_audit()
        .flush(std::time::Instant::now() + window + std::time::Duration::from_secs(1));
    let all = authz(&capture.events());
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(
        all[1].policy,
        format!("source-admission;count={};prefix=203.0.113.0/24", n - 1)
    );
    assert_eq!(
        all[1].source_ip,
        Some(std::net::IpAddr::from([203, 0, 113, n]))
    );
    let count = stack
        .signaling_audit()
        .metric_values()
        .into_iter()
        .find(|(name, _)| *name == "sbc_source_admission_rejects_total")
        .map(|(_, v)| v);
    assert_eq!(count, Some(u64::from(n)));
}

/// A bearer-only stack (RFC 8898). No token is ever validated in this
/// test, so the JWKS URL is never fetched.
fn bearer_stack() -> SipStack {
    let issuer = "https://idp.example.test";
    // reqwest has no default crypto provider (SR-16): CNSA preconfigured TLS.
    let tls = uc_transport::https_client::create_https_client_config(
        None,
        uc_transport::tls::MinTlsVersion::V1_2,
    )
    .expect("tls config");
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .expect("http client");
    let jwks = Arc::new(proto_jwt::JwksCache::new(http, issuer));
    let validator = Arc::new(
        proto_jwt::Validator::new(
            jwks,
            proto_jwt::ValidatorConfig::new(issuer, vec!["sbc".to_string()]),
        )
        .expect("validator config"),
    );
    let mut stack = SipStack::new(SipStackConfig::default());
    stack.set_bearer_authenticator(Arc::new(BearerAuthenticator::new(
        validator,
        "example.com".to_string(),
    )));
    stack
}

fn register_with_auth(i: u8, auth: Option<&str>) -> Bytes {
    let auth = auth.map_or_else(String::new, |a| format!("Authorization: {a}\r\n"));
    Bytes::from(format!(
        "REGISTER sip:sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/UDP 198.51.100.{i}:5060;branch=z9hG4bK-breg-{i}\r\n\
         From: <sip:alice@sbc.local>;tag=r{i}\r\n\
         To: <sip:alice@sbc.local>\r\n\
         Call-ID: breg-{i}@x\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <sip:alice@198.51.100.{i}:5060>\r\n\
         {auth}\
         Expires: 3600\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

/// Plan 8: a flood of REGISTERs carrying non-Bearer credentials (RFC 6750
/// `invalid_request`) from rotating sources in one /24 is one failed
/// `AuthenticationAttempt` with the static label, then one flushed count.
/// The initial challenge (no credentials) is still not audited.
#[tokio::test]
async fn qa_bearer_register_challenge_flood_is_aggregated() {
    let stack = bearer_stack();
    let capture = uc_audit::capture::start();
    let r = flatten(
        stack
            .process_message(&register_with_auth(200, None), src_v4(200), None)
            .await,
    );
    assert!(responded(&r, 401).is_some());
    assert!(auth_failures(&capture.events()).is_empty());

    let n = 30u8;
    for i in 1..=n {
        let r = flatten(
            stack
                .process_message(
                    &register_with_auth(
                        i,
                        Some(r#"Digest username="alice", realm="x", nonce="n", uri="sip:sbc.local", response="00""#),
                    ),
                    src_v4(i),
                    None,
                )
                .await,
        );
        assert!(responded(&r, 401).is_some(), "REGISTER {i} is challenged");
    }
    let first = auth_failures(&capture.events());
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(
        first[0].failure_reason.as_deref(),
        Some("bearer:invalid_request")
    );
    assert_eq!(first[0].method, uc_audit::event::AuthMethod::Jwt);
    let window = stack.signaling_audit().window();
    stack
        .signaling_audit()
        .flush(std::time::Instant::now() + window + std::time::Duration::from_secs(1));
    let all = auth_failures(&capture.events());
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(
        all[1].failure_reason.as_deref(),
        Some(
            format!(
                "bearer:invalid_request;count={};prefix=198.51.100.0/24",
                n - 1
            )
            .as_str()
        )
    );
    assert_eq!(all[1].source_ip, src_v4(n).ip());
}

fn src_v4(i: u8) -> SbcSocketAddr {
    SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, i), 5060)
}
