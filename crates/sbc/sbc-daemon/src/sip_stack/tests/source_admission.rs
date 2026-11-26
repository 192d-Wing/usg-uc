//! INVITE source admission by exact registered flow, and inbound trunk
//! identity by (source IP, arrival transport) (SR-04).
//!
//! A non-trunk INVITE is admitted only from the exact flow of a live
//! registration: canonical IP, port, transport and, for TCP/TLS, the
//! connection. A trunk is recognised on its configured `protocol` only, so a
//! UDP datagram from a TLS trunk's address is not that trunk (no RFC 3325
//! trust, no per-user limiter exemption, no STIR `source_trunk`, no trunk
//! CSS). Everything else gets the source-admission 403 and its audit record.
//!
//! ## NIST 800-53 Rev5: AC-3, IA-3, SC-5, SC-7, SC-23, AC-21

use super::*;
use crate::stir_binding::ConnId;

/// A phone behind a shared NAT address (TEST-NET-2).
const PHONE_IP: [u8; 4] = [198, 51, 100, 7];

/// A carrier trunk address (TEST-NET-3).
const TRUNK_IP: [u8; 4] = [203, 0, 113, 9];

fn at(ip: [u8; 4], port: u16) -> SbcSocketAddr {
    let [a, b, c, d] = ip;
    SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(a, b, c, d), port)
}

fn ip_of(ip: [u8; 4]) -> std::net::IpAddr {
    std::net::IpAddr::from(ip)
}

/// The trunk-map key of a trunk at `ip` configured with `transport`.
fn trunk_key(ip: [u8; 4], transport: AddrTransport) -> TrunkSourceKey {
    TrunkSourceKey::new(ip_of(ip), transport).unwrap()
}

/// `SourceAdmission::Trunk` for group `carrier` (no CSS) matched on the
/// trunk configured with `transport` at [`TRUNK_IP`].
fn carrier_via(transport: AddrTransport) -> SourceAdmission {
    SourceAdmission::Trunk(
        trunk_key(TRUNK_IP, transport),
        ("carrier".to_string(), None),
    )
}

/// The AOR a [`register`] of `user` binds.
fn aor_of(user: &str) -> String {
    format!("sip:{user}@sbc.local")
}

/// A REGISTER of `user` (private Contact, latched to the source) with the
/// given Call-ID, CSeq and Expires.
fn register_msg(user: &str, src: SbcSocketAddr, call_id: &str, cseq: u32, expires: u32) -> Bytes {
    Bytes::from(format!(
        "REGISTER sip:sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/UDP {src};branch=z9hG4bK-sa-reg-{call_id}-{cseq}\r\n\
         From: <sip:{user}@sbc.local>;tag=r-{call_id}\r\n\
         To: <sip:{user}@sbc.local>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <sip:{user}@10.0.0.7:5060>\r\n\
         Expires: {expires}\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

/// Registers `user` from `src` over `transport` on `conn` (200 asserted
/// unless de-registering).
async fn register(
    stack: &SipStack,
    user: &str,
    src: SbcSocketAddr,
    transport: AddrTransport,
    conn: Option<ConnId>,
) {
    register_ex(stack, user, src, transport, conn, ("sa-reg@test", 1, 3600)).await;
}

/// [`register`] with an explicit (Call-ID, CSeq, Expires).
async fn register_ex(
    stack: &SipStack,
    user: &str,
    src: SbcSocketAddr,
    transport: AddrTransport,
    conn: Option<ConnId>,
    (call_id, cseq, expires): (&str, u32, u32),
) {
    let r = flatten(
        stack
            .process_message_conn(
                &register_msg(user, src, call_id, cseq, expires),
                src,
                None,
                transport,
                conn,
            )
            .await,
    );
    assert!(responded(&r, 200).is_some(), "REGISTER accepted: {r:?}");
}

/// An initial INVITE from `src` to `target` with From `from_user` and an
/// optional PAI.
fn invite_msg(
    call_id: &str,
    src: SbcSocketAddr,
    from_user: &str,
    target: &str,
    pai: Option<&str>,
) -> Bytes {
    let pai = pai.map_or_else(String::new, |p| format!("P-Asserted-Identity: {p}\r\n"));
    Bytes::from(format!(
        "INVITE sip:{target}@sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/UDP {src};branch=z9hG4bK-sa-{call_id}\r\n\
         From: <sip:{from_user}@sbc.local>;tag=sa-{call_id}\r\n\
         To: <sip:{target}@sbc.local>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         {pai}Contact: <sip:{from_user}@{src}>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{ALICE_SDP}",
        ALICE_SDP.len()
    ))
}

/// `msg` with its Content-Length set to the body's length.
fn fix_content_length(msg: &str) -> String {
    let (head, body) = msg.split_once("\r\n\r\n").expect("header/body split");
    let head: Vec<String> = head
        .split("\r\n")
        .map(|l| {
            if l.starts_with("Content-Length:") {
                format!("Content-Length: {}", body.len())
            } else {
                l.to_string()
            }
        })
        .collect();
    format!("{}\r\n\r\n{body}", head.join("\r\n"))
}

/// Outcome of one INVITE: its results and whether source admission refused
/// it (403, nothing forwarded, `sbc_source_admission_rejects_total` +1). The
/// first refusal per source prefix writes the `source-admission` record at
/// once; repeats in the window are aggregated (SR-42), so a record is
/// checked when present but not required.
struct Sent {
    results: Vec<ProcessResult>,
    denied: bool,
}

async fn send_invite(
    stack: &SipStack,
    msg: &Bytes,
    src: SbcSocketAddr,
    transport: AddrTransport,
    conn: Option<ConnId>,
) -> Sent {
    let rejects = || {
        stack
            .signaling_audit()
            .metric_values()
            .into_iter()
            .find(|(n, _)| *n == "sbc_source_admission_rejects_total")
            .map_or(0, |(_, v)| v)
    };
    let before = rejects();
    let cap = uc_audit::capture::start();
    let results = flatten(
        stack
            .process_message_conn(msg, src, None, transport, conn)
            .await,
    );
    let audited: Vec<_> = authz_events(&cap.events())
        .into_iter()
        .filter(|d| d.policy.starts_with("source-admission"))
        .collect();
    drop(cap);
    let denied = rejects() > before;
    if denied {
        assert_eq!(rejects() - before, 1, "one source-admission reject");
        assert!(audited.len() <= 1, "at most one audit record");
        if let Some(a) = audited.first() {
            assert!(!a.granted);
            assert_eq!(a.action, "INVITE");
            assert_eq!(a.source_ip, Some(src.ip()));
        }
        assert!(
            results.iter().any(is_forbidden),
            "source-admission denial is a 403: {results:?}"
        );
        assert!(forwarded(&results, &Method::Invite).is_none());
    } else {
        assert!(audited.is_empty(), "admitted INVITE wrote a denial record");
    }
    Sent { results, denied }
}

/// [`send_invite`] of a plain endpoint INVITE from `bob` to 9999.
async fn invite(
    stack: &SipStack,
    call_id: &str,
    src: SbcSocketAddr,
    transport: AddrTransport,
    conn: Option<ConnId>,
) -> Sent {
    send_invite(
        stack,
        &invite_msg(call_id, src, "bob", "9999", None),
        src,
        transport,
        conn,
    )
    .await
}

fn ingress(source: SbcSocketAddr, transport: AddrTransport, conn: Option<ConnId>) -> Ingress {
    Ingress {
        source,
        transport,
        conn,
    }
}

/// The contact the registrar latched for `user` (its only binding).
async fn latched_contact(stack: &SipStack, user: &str) -> String {
    let loc = stack.location_service.read().await;
    let bindings = loc.lookup(&aor_of(user));
    assert_eq!(bindings.len(), 1, "one binding");
    bindings[0].contact_uri().to_string()
}

// ----------------------------------------------------------------------
// Endpoint admission by exact flow
// ----------------------------------------------------------------------

/// 1. Same IP, another UDP port: another flow, 403 + audit.
#[tokio::test]
async fn udp_same_ip_other_port_is_403() {
    let stack = SipStack::new(SipStackConfig::default());
    register(&stack, "bob", at(PHONE_IP, 5060), AddrTransport::Udp, None).await;
    let s = invite(
        &stack,
        "sa1@test",
        at(PHONE_IP, 5062),
        AddrTransport::Udp,
        None,
    )
    .await;
    assert!(s.denied, "{:?}", s.results);
    // A UDP port mismatch is not cheap to name: no hint (by design).
    assert_eq!(
        stack
            .admit_invite_source(&ingress(at(PHONE_IP, 5062), AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(DenyHint::None)
    );
}

/// 2. Same IP and port, another transport: 403.
#[tokio::test]
async fn same_ip_port_other_transport_is_403() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 5060);
    register(&stack, "bob", src, AddrTransport::Udp, None).await;
    let c = Some(ConnId::next());
    assert!(
        invite(&stack, "sa2@test", src, AddrTransport::Tcp, c)
            .await
            .denied
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(src, AddrTransport::Tcp, c))
            .await,
        SourceAdmission::Denied(DenyHint::FlowOtherTransport)
    );
}

/// 3. TCP and TLS: a REGISTER on one connection does not admit an INVITE
/// on another from the same `ip:port`.
#[tokio::test]
async fn stream_other_connection_is_403() {
    for transport in [AddrTransport::Tcp, AddrTransport::Tls] {
        let stack = SipStack::new(SipStackConfig::default());
        let src = at(PHONE_IP, 40_000);
        let (c1, c2) = (Some(ConnId::next()), Some(ConnId::next()));
        register(&stack, "bob", src, transport, c1).await;
        assert!(
            invite(&stack, "sa3@test", src, transport, c2).await.denied,
            "{transport}"
        );
        assert_eq!(
            stack
                .admit_invite_source(&ingress(src, transport, c2))
                .await,
            SourceAdmission::Denied(DenyHint::FlowOtherConnection),
            "{transport}"
        );
    }
}

/// 4. The exact registered flow is admitted (UDP; TLS on the same
/// connection).
#[tokio::test]
async fn exact_flow_is_admitted() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 5060);
    register(&stack, "bob", src, AddrTransport::Udp, None).await;
    let s = invite(&stack, "sa4u@test", src, AddrTransport::Udp, None).await;
    assert!(!s.denied, "{:?}", s.results);
    assert_eq!(
        stack
            .admit_invite_source(&ingress(src, AddrTransport::Udp, None))
            .await,
        SourceAdmission::RegisteredFlow
    );

    let tls_src = at(PHONE_IP, 40_001);
    let c = Some(ConnId::next());
    register_ex(
        &stack,
        "carol",
        tls_src,
        AddrTransport::Tls,
        c,
        ("sa4-tls@test", 1, 3600),
    )
    .await;
    let s = invite(&stack, "sa4t@test", tls_src, AddrTransport::Tls, c).await;
    assert!(!s.denied, "{:?}", s.results);
}

/// 4b. Admission does not depend on REGISTER authentication: with
/// `require_auth = true` a live binding on the exact flow admits, another
/// port does not.
#[tokio::test]
async fn exact_flow_admission_with_require_auth() {
    let mut stack = SipStack::new(SipStackConfig::default());
    stack.config.require_auth = true;
    let src = at(PHONE_IP, 5060);
    let aor = aor_of("bob");
    stack
        .location_service
        .write()
        .await
        .add_binding(proto_registrar::Binding::new(
            &aor,
            "sip:bob@198.51.100.7:5060;transport=udp",
            "seed@test",
            1,
        ))
        .unwrap();
    stack
        .index_stir_flow(&aor, src, AddrTransport::Udp, None)
        .await;
    assert_eq!(
        stack
            .admit_invite_source(&ingress(src, AddrTransport::Udp, None))
            .await,
        SourceAdmission::RegisteredFlow
    );
    assert!(matches!(
        stack
            .admit_invite_source(&ingress(at(PHONE_IP, 5062), AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(_)
    ));
}

/// 5. An expired binding no longer admits its flow.
#[tokio::test]
async fn expired_binding_is_403() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 5060);
    register(&stack, "bob", src, AddrTransport::Udp, None).await;
    let contact = latched_contact(&stack, "bob").await;
    stack
        .location_service
        .write()
        .await
        .get_binding_mut(&aor_of("bob"), &contact)
        .expect("latched binding")
        .expire();
    assert!(
        invite(&stack, "sa5@test", src, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(src, AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(DenyHint::FlowNotLive)
    );
}

/// 6. De-REGISTER (Expires: 0, same Call-ID) drops the flow.
#[tokio::test]
async fn deregistered_flow_is_403() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 5060);
    register_ex(
        &stack,
        "bob",
        src,
        AddrTransport::Udp,
        None,
        ("sa6@test", 1, 3600),
    )
    .await;
    register_ex(
        &stack,
        "bob",
        src,
        AddrTransport::Udp,
        None,
        ("sa6@test", 2, 0),
    )
    .await;
    assert!(
        invite(&stack, "sa6i@test", src, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// 7. A closed TLS connection no longer admits, even tagged with its id.
#[tokio::test]
async fn closed_connection_is_403() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 40_002);
    let c1 = ConnId::next();
    register(&stack, "bob", src, AddrTransport::Tls, Some(c1)).await;
    stack.connection_closed(c1).await;
    assert!(
        invite(&stack, "sa7@test", src, AddrTransport::Tls, Some(c1))
            .await
            .denied
    );
}

/// 8. An admin-deleted registration leaves a stale flow-index entry, which
/// is not trusted.
#[tokio::test]
async fn deleted_registration_is_403() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 5060);
    register(&stack, "bob", src, AddrTransport::Udp, None).await;
    let contact = latched_contact(&stack, "bob").await;
    stack
        .delete_registration(&aor_of("bob"), &contact)
        .await
        .unwrap();
    assert_eq!(stack.stir_flows.read().await.len(), 1, "stale entry kept");
    assert!(
        invite(&stack, "sa8@test", src, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// 9. NAT rebinding: a re-REGISTER (same Call-ID) from a new port moves the
/// binding; the old port is refused, the new one admitted.
#[tokio::test]
async fn rebound_flow_old_port_403_new_port_admitted() {
    let stack = SipStack::new(SipStackConfig::default());
    let (old, new) = (at(PHONE_IP, 5060), at(PHONE_IP, 5070));
    register_ex(
        &stack,
        "bob",
        old,
        AddrTransport::Udp,
        None,
        ("sa9@test", 1, 3600),
    )
    .await;
    register_ex(
        &stack,
        "bob",
        new,
        AddrTransport::Udp,
        None,
        ("sa9@test", 2, 3600),
    )
    .await;
    assert!(
        invite(&stack, "sa9o@test", old, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert!(
        !invite(&stack, "sa9n@test", new, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// 10. An IPv4-mapped source matches the IPv4 flow it registered on.
#[tokio::test]
async fn ipv4_mapped_source_matches_registered_v4_flow() {
    let stack = SipStack::new(SipStackConfig::default());
    register(&stack, "bob", at(PHONE_IP, 5060), AddrTransport::Udp, None).await;
    let [a, b, c, d] = PHONE_IP;
    let mapped = SbcSocketAddr::from(std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv4Addr::new(a, b, c, d).to_ipv6_mapped()),
        5060,
    ));
    assert!(
        !invite(&stack, "sa10@test", mapped, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// 11. A stream REGISTER and INVITE without a connection id (fail-secure:
/// an entry bound without a connection never matches).
#[tokio::test]
async fn stream_invite_without_conn_id_is_403() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 40_003);
    register(&stack, "bob", src, AddrTransport::Tcp, None).await;
    assert!(
        invite(&stack, "sa11@test", src, AddrTransport::Tcp, None)
            .await
            .denied
    );
}

// ----------------------------------------------------------------------
// Trunk identity by (source IP, arrival transport)
// ----------------------------------------------------------------------

/// A stack whose config-file trunk group `carrier` (`trust_domain = true`)
/// has one trunk at [`TRUNK_IP`] with `protocol`.
fn config_trunk_stack(protocol: &str) -> SipStack {
    let mut stack = SipStack::new(SipStackConfig::default());
    let routing = sbc_config::RoutingConfig {
        use_dial_plan: true,
        max_failover_attempts: 1,
        default_trunk_group: "carrier".to_string(),
        emergency_trunk_group: None,
    };
    let groups = vec![sbc_config::TrunkGroupConfig {
        id: "carrier".to_string(),
        name: "Carrier".to_string(),
        strategy: "priority".to_string(),
        trunks: vec![sbc_config::TrunkConfigSchema {
            id: "c1".to_string(),
            host: "203.0.113.9".to_string(),
            port: 5061,
            protocol: protocol.to_string(),
            ..Default::default()
        }],
        zone: None,
        require_tls: false,
        trust_domain: true,
    }];
    stack.init_router_from_config(&routing, &[], &groups);
    stack
}

/// 12a-c. A UDP datagram from a TLS trunk's address is not the trunk: 403
/// unless it is a registered flow, and then an endpoint whose PAI is
/// stripped. TLS from the same address is the trusted trunk.
#[tokio::test]
async fn udp_from_tls_trunk_ip_is_not_a_trunk() {
    let stack = config_trunk_stack("tls");
    let udp_src = at(TRUNK_IP, 5060);
    let tls_src = at(TRUNK_IP, 5061);
    let c = Some(ConnId::next());

    // a. Not registered: 403, with the trunk-other-transport hint.
    assert!(
        invite(&stack, "sa12a@test", udp_src, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(udp_src, AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(DenyHint::TrunkOtherTransport(AddrTransport::Tls))
    );

    // c. Trust follows the transport.
    assert!(
        !stack
            .ingress_trusted(ip_of(TRUNK_IP), AddrTransport::Udp)
            .await
    );
    assert!(
        stack
            .ingress_trusted(ip_of(TRUNK_IP), AddrTransport::Tls)
            .await
    );
    assert!(
        !stack
            .is_trunk_source(ip_of(TRUNK_IP), AddrTransport::Udp)
            .await
    );

    // b. Registered on that UDP flow: an endpoint, not the trunk; its PAI
    // is stripped (RFC 3325 §5), the TLS trunk's is kept.
    register(&stack, "bob", udp_src, AddrTransport::Udp, None).await;
    assert_eq!(
        stack
            .admit_invite_source(&ingress(udp_src, AddrTransport::Udp, None))
            .await,
        SourceAdmission::RegisteredFlow
    );
    let pai = "<sip:+12025550199@carrier.example;user=phone>";
    let raw = invite_msg("sa12b@test", udp_src, "bob", "9999", Some(pai));
    let Ok(SipMessage::Request(req)) = SipMessage::parse(&raw) else {
        panic!("parse");
    };
    let Ok((Some(stripped), _)) = stack
        .preprocess_initial_invite(&req, udp_src, AddrTransport::Udp)
        .await
    else {
        panic!("PAI stripped copy");
    };
    assert!(!stripped.headers.contains(&HeaderName::PAssertedIdentity));
    let Ok((kept, _)) = stack
        .preprocess_initial_invite(&req, tls_src, AddrTransport::Tls)
        .await
    else {
        panic!("accepted");
    };
    assert!(kept.is_none(), "trusted TLS trunk: PAI kept, no copy");

    // 13. TLS from the trunk is the trunk (and its CSS).
    assert_eq!(
        stack
            .admit_invite_source(&ingress(tls_src, AddrTransport::Tls, c))
            .await,
        carrier_via(AddrTransport::Tls)
    );
    assert!(
        !invite(&stack, "sa13@test", tls_src, AddrTransport::Tls, c)
            .await
            .denied
    );
}

/// 12b. The CDR of a call from the UDP flow at a TLS trunk's address is not
/// an inbound trunk call; the TLS trunk's call is.
#[tokio::test]
async fn cdr_direction_follows_trunk_transport() {
    let (stack, cdr) = cdr_stack().await;
    // alice (192.168.1.1) is a TLS-only trunk here; bob is registered.
    stack
        .register_inbound_trunk(
            "pbx",
            None,
            &[("192.168.1.1".to_string(), AddrTransport::Tls)],
        )
        .await;
    let udp_src = alice();
    register(&stack, "alice", udp_src, AddrTransport::Udp, None).await;
    let s = send_invite(
        &stack,
        &caller_request("INVITE", DIALED, "sa12cdr@test", 1, None, Some(ALICE_SDP)),
        udp_src,
        AddrTransport::Udp,
        None,
    )
    .await;
    assert!(!s.denied, "{:?}", s.results);
    let _ = stack
        .process_message(
            &caller_request("CANCEL", DIALED, "sa12cdr@test", 1, None, None),
            udp_src,
            None,
        )
        .await;
    assert_ne!(one_cdr(&cdr).direction, uc_cdr::Direction::Inbound);
}

/// 12d. The per-user limiter exempts a trunk on its own transport only.
#[tokio::test]
async fn per_user_limiter_exempts_trunk_transport_only() {
    let mut stack = SipStack::new(SipStackConfig::default());
    stack.set_user_rate_limiter(uc_dos_protection::KeyedRateLimiter::new(1, 1));
    stack
        .register_inbound_trunk(
            "carrier",
            None,
            &[("203.0.113.9".to_string(), AddrTransport::Tls)],
        )
        .await;
    let options = |n: u32| {
        Bytes::from(format!(
            "OPTIONS sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-sa-rl-{n}\r\n\
             From: <sip:carrier@example.com>;tag={n}\r\n\
             To: <sip:sbc.local>\r\n\
             Call-ID: sa-rl-{n}@test\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n"
        ))
    };
    // UDP from the trunk's address: limited per user (burst 2).
    let udp = at(TRUNK_IP, 5060);
    let mut limited = false;
    for n in 1..=3 {
        let r = flatten(
            stack
                .process_message_conn(&options(n), udp, None, AddrTransport::Udp, None)
                .await,
        );
        limited |= responded(&r, 503).is_some();
    }
    assert!(
        limited,
        "UDP from a TLS trunk's address is per-user limited"
    );
    // TLS from the trunk: exempt.
    let tls = at(TRUNK_IP, 5061);
    let c = Some(ConnId::next());
    for n in 10..=13 {
        let r = flatten(
            stack
                .process_message_conn(&options(n), tls, None, AddrTransport::Tls, c)
                .await,
        );
        assert!(responded(&r, 503).is_none(), "TLS trunk is exempt");
    }
}

/// 12e. STIR: the TLS trunk's Identity is verified; the same address over
/// UDP is no trunk (no `source_trunk`, no verification or passthrough).
#[tokio::test]
async fn stir_source_trunk_follows_trunk_transport() {
    // alice-trunk is a `tls` trunk here, like the SIP-stack entry below.
    let q = qa_stir_stack_with(
        sbc_config::StirFailurePolicy::Mark,
        0,
        1000,
        false,
        false,
        |c| {
            for t in c.trunk_groups.iter_mut().flat_map(|g| g.trunks.iter_mut()) {
                if t.id == "alice-trunk" {
                    t.protocol = "tls".into();
                }
            }
        },
    )
    .await;
    q.stack
        .register_inbound_trunk(
            "pbx",
            None,
            &[("192.168.1.1".to_string(), AddrTransport::Tls)],
        )
        .await;
    let stir = q.stack.stir().unwrap();
    let id = qa_identity(&q.files, 0);
    let tls_src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5061);
    let s = send_invite(
        &q.stack,
        &qa_invite("sa12e-tls@test", Some(&id)),
        tls_src,
        AddrTransport::Tls,
        Some(ConnId::next()),
    )
    .await;
    assert!(!s.denied, "{:?}", s.results);
    assert_eq!(stir.metrics.verify_passed.load(Ordering::Relaxed), 1);

    // UDP, unregistered: refused before STIR runs.
    let s = send_invite(
        &q.stack,
        &qa_invite("sa12e-udp@test", Some(&id)),
        alice(),
        AddrTransport::Udp,
        None,
    )
    .await;
    assert!(s.denied, "{:?}", s.results);

    // UDP, registered: an endpoint. Its Identity is neither verified nor
    // passed through.
    register(&q.stack, "alice", alice(), AddrTransport::Udp, None).await;
    let s = send_invite(
        &q.stack,
        &qa_invite("sa12e-ep@test", Some(&id)),
        alice(),
        AddrTransport::Udp,
        None,
    )
    .await;
    assert!(!s.denied, "{:?}", s.results);
    assert_eq!(stir.metrics.verify_passed.load(Ordering::Relaxed), 1);
    if let Some((b, _)) = forwarded(&s.results, &Method::Invite) {
        assert_ne!(
            b.headers.get_value(&HeaderName::Identity),
            Some(id.as_str())
        );
        assert!(
            b.headers
                .get_all(&HeaderName::PAssertedIdentity)
                .all(|h| !h.value.contains("verstat=TN-Validation-Passed"))
        );
    }
}

/// 14. A trunk configured `tcp` that sends over TLS is matched (transport
/// floor: TLS is at least TCP), on the TCP trunk's key; UDP from it is not.
#[tokio::test]
async fn tcp_configured_trunk_sending_tls_is_matched() {
    let stack = config_trunk_stack("tcp");
    let src = at(TRUNK_IP, 5061);
    let c = Some(ConnId::next());
    assert!(
        !invite(&stack, "sa14@test", src, AddrTransport::Tls, c)
            .await
            .denied
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(src, AddrTransport::Tls, c))
            .await,
        carrier_via(AddrTransport::Tcp)
    );
    assert!(
        stack
            .ingress_trusted(ip_of(TRUNK_IP), AddrTransport::Tls)
            .await
    );
    // UDP is below the floor: not the trunk, and the hint names it.
    assert_eq!(
        stack
            .admit_invite_source(&ingress(at(TRUNK_IP, 5060), AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(DenyHint::TrunkOtherTransport(AddrTransport::Tcp))
    );
    assert_eq!(
        DenyHint::TrunkOtherTransport(AddrTransport::Tcp).as_str(),
        "trunk-address-other-transport"
    );
}

/// RFC 3261 §18.1.1: a `udp` trunk's INVITE too large for UDP arrives over
/// TCP and is still that trunk: PAI trusted as configured, per-user limiter
/// exempt, STIR settings of the UDP trunk (its key) applied.
#[tokio::test]
async fn udp_trunk_large_invite_over_tcp_is_trunk() {
    let mut stack = config_trunk_stack("udp");
    stack.set_user_rate_limiter(uc_dos_protection::KeyedRateLimiter::new(1, 1));
    let src = at(TRUNK_IP, 40_500);
    let c = Some(ConnId::next());
    assert_eq!(
        stack
            .admit_invite_source(&ingress(src, AddrTransport::Tcp, c))
            .await,
        carrier_via(AddrTransport::Udp)
    );
    assert!(
        stack
            .ingress_trusted(ip_of(TRUNK_IP), AddrTransport::Tcp)
            .await
    );
    // A > 1300-byte INVITE (padded SDP attribute) over TCP: admitted, and
    // its PAI is kept (trusted group).
    let pai = "<sip:+12025550199@carrier.example;user=phone>";
    let raw = invite_msg("sa-big@test", src, "carrier", "9999", Some(pai));
    let padded = String::from_utf8_lossy(&raw).replacen(
        "a=sendrecv\r\n",
        &format!("a=sendrecv\r\na=x-pad:{}\r\n", "p".repeat(1400)),
        1,
    );
    let text = fix_content_length(&padded);
    assert!(text.len() > 1300, "large request");
    let big = Bytes::from(text);
    let s = send_invite(&stack, &big, src, AddrTransport::Tcp, c).await;
    assert!(!s.denied, "{:?}", s.results);
    let Ok(SipMessage::Request(req)) = SipMessage::parse(&big) else {
        panic!("parse");
    };
    let Ok((kept, _)) = stack
        .preprocess_initial_invite(&req, src, AddrTransport::Tcp)
        .await
    else {
        panic!("accepted");
    };
    assert!(kept.is_none(), "trusted udp trunk over TCP: PAI kept");
    // Per-user limiter: exempt over TCP like over UDP (burst 2, send 4).
    for n in 0..4 {
        let r = flatten(
            stack
                .process_message_conn(
                    &invite_msg(&format!("sa-big-rl-{n}@test"), src, "carrier", "9999", None),
                    src,
                    None,
                    AddrTransport::Tcp,
                    c,
                )
                .await,
        );
        assert!(responded(&r, 503).is_none(), "trunk exempt over TCP");
    }
}

/// The STIR settings of a `udp` trunk apply to its INVITE over TCP (the
/// resolved trunk key, not the arrival transport, selects them).
#[tokio::test]
async fn stir_udp_trunk_settings_apply_over_tcp() {
    let q = qa_stir_stack_with(
        sbc_config::StirFailurePolicy::Mark,
        0,
        1000,
        false,
        false,
        |_| {},
    )
    .await;
    // alice-trunk (192.168.1.1) is a `udp` config trunk with verify on.
    q.stack
        .register_inbound_trunk(
            "pbx",
            None,
            &[("192.168.1.1".to_string(), AddrTransport::Udp)],
        )
        .await;
    let stir = q.stack.stir().unwrap();
    let id = qa_identity(&q.files, 0);
    let src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 40_600);
    let s = send_invite(
        &q.stack,
        &qa_invite("sa-stir-tcp@test", Some(&id)),
        src,
        AddrTransport::Tcp,
        Some(ConnId::next()),
    )
    .await;
    assert!(!s.denied, "{:?}", s.results);
    assert_eq!(stir.metrics.verify_passed.load(Ordering::Relaxed), 1);
}

/// 15. One address as a UDP trunk of one group and a TLS trunk of another:
/// both kept, each on its transport.
#[tokio::test]
async fn same_ip_udp_and_tls_trunks_in_two_groups_both_kept() {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .register_inbound_trunk(
            "a",
            None,
            &[("203.0.113.9".to_string(), AddrTransport::Udp)],
        )
        .await;
    stack
        .register_inbound_trunk(
            "b",
            None,
            &[("203.0.113.9".to_string(), AddrTransport::Tls)],
        )
        .await;
    let ip = ip_of(TRUNK_IP);
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Udp).await,
        Some(("a".to_string(), None))
    );
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Tls).await,
        Some(("b".to_string(), None))
    );
    // Exact entries win; TCP has none and falls to the UDP group (floor).
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Tcp).await,
        Some(("a".to_string(), None))
    );
}

/// 16. Destination hiding toward a trunk host ignores the transport: a
/// TLS-only trunk at an internal address is still hidden toward.
#[tokio::test]
async fn destination_hidden_toward_trunk_ip_any_transport() {
    let mut stack = SipStack::new(SipStackConfig::default());
    stack
        .init_topology_hider_from_config(&sbc_config::TopologyHidingConfig {
            enabled: true,
            mode: "full".to_string(),
            external_host: "sbc.example.net".to_string(),
            external_port: 5060,
            ..Default::default()
        })
        .expect("valid topology config");
    stack
        .register_inbound_trunk(
            "carrier",
            None,
            &[("10.0.0.9".to_string(), AddrTransport::Tls)],
        )
        .await;
    let trunk = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(10, 0, 0, 9), 5060);
    let internal = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(10, 0, 0, 10), 5060);
    assert!(stack.destination_hidden(trunk).await);
    assert!(!stack.destination_hidden(internal).await);
}

/// A call from the TLS-only trunk at 192.168.1.1 (port 5061, connection
/// `c`) to registered bob, still ringing; and the caller's CANCEL of it.
async fn tls_trunk_call(c: Option<ConnId>) -> (SipStack, Bytes) {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .register_inbound_trunk(
            "test-trunk",
            None,
            &[("192.168.1.1".to_string(), AddrTransport::Tls)],
        )
        .await;
    let _ = stack
        .process_message(
            &register_msg("bob", bob(), "sa17-reg@test", 1, 3600),
            bob(),
            None,
        )
        .await;
    let s = send_invite(
        &stack,
        &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
        TLS_ALICE,
        AddrTransport::Tls,
        c,
    )
    .await;
    assert!(!s.denied, "{:?}", s.results);
    assert!(forwarded(&s.results, &Method::Invite).is_some(), "to bob");
    let cancel = alice_request("CANCEL", 1, None, None);
    let cancel = Bytes::from(String::from_utf8_lossy(&cancel).replacen(
        "z9hG4bK-alice-1-CANCEL",
        "z9hG4bK-alice-1-INVITE",
        1,
    ));
    (stack, cancel)
}

/// The TLS trunk's source in [`tls_trunk_call`].
const TLS_ALICE: SbcSocketAddr =
    SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5061);

/// 17. A trunk call placed over TLS is cancelled over TLS; a CANCEL over UDP
/// from the same address is not the call's peer (481, the call keeps
/// ringing). The A-leg dialog peer is built from the trunk identity
/// admission resolved on TLS.
#[tokio::test]
async fn cancel_and_ack_use_invite_transport_for_trunk_peer() {
    let c = Some(ConnId::next());
    let (stack, cancel) = Box::pin(tls_trunk_call(c)).await;
    let r = flatten(
        stack
            .process_message_conn(&cancel, TLS_ALICE, None, AddrTransport::Udp, None)
            .await,
    );
    // A CANCEL from outside the INVITE's peer matches no transaction: 481
    // (the CANCEL policy of `dialog_match`), never 200.
    assert!(responded(&r, 481).is_some(), "{r:?}");
    assert!(responded(&r, 200).is_none());
    assert!(forwarded(&r, &Method::Cancel).is_none());
    assert_eq!(stack.call_count().await, 1, "call untouched");

    let (stack, cancel) = Box::pin(tls_trunk_call(c)).await;
    let r = flatten(
        stack
            .process_message_conn(&cancel, TLS_ALICE, None, AddrTransport::Tls, c)
            .await,
    );
    assert!(responded(&r, 200).is_some(), "{r:?}");
    assert!(responded(&r, 487).is_some());
    assert_eq!(stack.call_count().await, 0);
}

/// 18. Admission stays exact with many registrations (functional, no
/// timing assert): the last flow admits, a near-miss port does not.
#[tokio::test]
async fn admission_with_10k_registrations_is_exact() {
    let stack = SipStack::new(SipStackConfig::default());
    let n: u16 = 10_000;
    {
        let mut loc = stack.location_service.write().await;
        for i in 0..n {
            let port = 20_000 + i;
            loc.add_binding(proto_registrar::Binding::new(
                format!("sip:u{i}@sbc.local"),
                format!("sip:u{i}@198.51.100.7:{port};transport=udp"),
                format!("seed-{i}@test"),
                1,
            ))
            .unwrap();
        }
    }
    for i in 0..n {
        stack
            .index_stir_flow(
                &format!("sip:u{i}@sbc.local"),
                at(PHONE_IP, 20_000 + i),
                AddrTransport::Udp,
                None,
            )
            .await;
    }
    let last = at(PHONE_IP, 20_000 + n - 1);
    assert_eq!(
        stack
            .admit_invite_source(&ingress(last, AddrTransport::Udp, None))
            .await,
        SourceAdmission::RegisteredFlow
    );
    let near_miss = at(PHONE_IP, 20_000 + n);
    assert!(matches!(
        stack
            .admit_invite_source(&ingress(near_miss, AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(_)
    ));
}

// ----------------------------------------------------------------------
// QA gap tests (SR-04): canonicalisation, de-REGISTER / close sequences,
// a trunk on two transports, WebSocket flows.
// ----------------------------------------------------------------------

/// `PHONE_IP` as an IPv4-mapped IPv6 socket address.
fn mapped(ip: [u8; 4], port: u16) -> SbcSocketAddr {
    let [a, b, c, d] = ip;
    SbcSocketAddr::from(std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv4Addr::new(a, b, c, d).to_ipv6_mapped()),
        port,
    ))
}

/// 10 (reverse). A REGISTER that arrived from an IPv4-mapped source admits
/// the plain IPv4 INVITE on the same flow, over UDP and over TLS on the same
/// connection; another connection is still refused.
#[tokio::test]
async fn ipv4_mapped_register_matches_v4_invite() {
    let stack = SipStack::new(SipStackConfig::default());
    register(
        &stack,
        "bob",
        mapped(PHONE_IP, 5060),
        AddrTransport::Udp,
        None,
    )
    .await;
    assert!(
        !invite(
            &stack,
            "qa10r-u@test",
            at(PHONE_IP, 5060),
            AddrTransport::Udp,
            None
        )
        .await
        .denied
    );
    assert!(
        invite(
            &stack,
            "qa10r-u2@test",
            at(PHONE_IP, 5062),
            AddrTransport::Udp,
            None
        )
        .await
        .denied
    );

    let (c1, c2) = (Some(ConnId::next()), Some(ConnId::next()));
    register_ex(
        &stack,
        "carol",
        mapped(PHONE_IP, 40_010),
        AddrTransport::Tls,
        c1,
        ("qa10r-tls@test", 1, 3600),
    )
    .await;
    assert_eq!(
        stack
            .admit_invite_source(&ingress(at(PHONE_IP, 40_010), AddrTransport::Tls, c1))
            .await,
        SourceAdmission::RegisteredFlow
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(at(PHONE_IP, 40_010), AddrTransport::Tls, c2))
            .await,
        SourceAdmission::Denied(DenyHint::FlowOtherConnection)
    );
}

/// A native IPv6 flow (bracketed latched Contact) is matched exactly: same
/// port admitted, another port refused.
#[tokio::test]
async fn native_ipv6_flow_is_exact() {
    let stack = SipStack::new(SipStackConfig::default());
    let v6 = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
    let src = SbcSocketAddr::new_v6(v6, 5060);
    register(&stack, "bob", src, AddrTransport::Udp, None).await;
    assert!(
        !invite(&stack, "qa-v6@test", src, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert!(
        invite(
            &stack,
            "qa-v6p@test",
            SbcSocketAddr::new_v6(v6, 5062),
            AddrTransport::Udp,
            None
        )
        .await
        .denied
    );
}

/// An IPv4-mapped source is the IPv4 config trunk on its configured
/// transport only (the key canonicalises on lookup through admission).
#[tokio::test]
async fn ipv4_mapped_source_matches_v4_config_trunk_on_its_transport() {
    let stack = config_trunk_stack("tls");
    let c = Some(ConnId::next());
    assert_eq!(
        stack
            .admit_invite_source(&ingress(mapped(TRUNK_IP, 5061), AddrTransport::Tls, c))
            .await,
        carrier_via(AddrTransport::Tls)
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(mapped(TRUNK_IP, 5060), AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(DenyHint::TrunkOtherTransport(AddrTransport::Tls))
    );
    assert!(
        stack
            .ingress_trusted(
                std::net::IpAddr::V6(std::net::Ipv4Addr::from(TRUNK_IP).to_ipv6_mapped()),
                AddrTransport::Tls
            )
            .await
    );
    assert!(
        !stack
            .ingress_trusted(
                std::net::IpAddr::V6(std::net::Ipv4Addr::from(TRUNK_IP).to_ipv6_mapped()),
                AddrTransport::Udp
            )
            .await
    );
}

/// 6 (stream). De-REGISTER on a TLS connection drops that flow: an INVITE on
/// the same connection is then refused.
#[tokio::test]
async fn deregistered_stream_flow_is_403() {
    for transport in [AddrTransport::Tcp, AddrTransport::Tls] {
        let stack = SipStack::new(SipStackConfig::default());
        let src = at(PHONE_IP, 40_020);
        let c = Some(ConnId::next());
        register_ex(&stack, "bob", src, transport, c, ("qa6s@test", 1, 3600)).await;
        assert!(
            !invite(&stack, "qa6s-a@test", src, transport, c)
                .await
                .denied,
            "{transport}"
        );
        register_ex(&stack, "bob", src, transport, c, ("qa6s@test", 2, 0)).await;
        assert!(
            invite(&stack, "qa6s-b@test", src, transport, c)
                .await
                .denied,
            "{transport}"
        );
    }
}

/// 6 (multi-AOR). Two AORs registered from one UDP flow: de-registering one
/// leaves the flow admitted through the other; de-registering both refuses.
#[tokio::test]
async fn deregister_one_aor_keeps_flow_for_the_other() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 5060);
    register_ex(
        &stack,
        "bob",
        src,
        AddrTransport::Udp,
        None,
        ("qa-m-b@test", 1, 3600),
    )
    .await;
    register_ex(
        &stack,
        "carol",
        src,
        AddrTransport::Udp,
        None,
        ("qa-m-c@test", 1, 3600),
    )
    .await;
    register_ex(
        &stack,
        "bob",
        src,
        AddrTransport::Udp,
        None,
        ("qa-m-b@test", 2, 0),
    )
    .await;
    assert!(
        !invite(&stack, "qa-m1@test", src, AddrTransport::Udp, None)
            .await
            .denied,
        "carol still holds the flow"
    );
    register_ex(
        &stack,
        "carol",
        src,
        AddrTransport::Udp,
        None,
        ("qa-m-c@test", 2, 0),
    )
    .await;
    assert!(
        invite(&stack, "qa-m2@test", src, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// 7 (sequence). After a stream connection closes, neither the old nor a
/// new connection from the same `ip:port` is admitted until a REGISTER on
/// the new connection; then only the new connection is.
#[tokio::test]
async fn closed_connection_then_reregister_on_new_connection() {
    for transport in [AddrTransport::Tcp, AddrTransport::Tls] {
        let stack = SipStack::new(SipStackConfig::default());
        let src = at(PHONE_IP, 40_030);
        let (c1, c2) = (ConnId::next(), ConnId::next());
        register(&stack, "bob", src, transport, Some(c1)).await;
        stack.connection_closed(c1).await;
        assert!(
            invite(&stack, "qa7-a@test", src, transport, Some(c1))
                .await
                .denied,
            "{transport} old conn"
        );
        assert!(
            invite(&stack, "qa7-b@test", src, transport, Some(c2))
                .await
                .denied,
            "{transport} new conn before REGISTER"
        );
        register_ex(
            &stack,
            "bob",
            src,
            transport,
            Some(c2),
            ("qa7-r@test", 1, 3600),
        )
        .await;
        assert!(
            !invite(&stack, "qa7-c@test", src, transport, Some(c2))
                .await
                .denied,
            "{transport} new conn after REGISTER"
        );
        assert!(
            invite(&stack, "qa7-d@test", src, transport, Some(c1))
                .await
                .denied,
            "{transport} old conn after REGISTER"
        );
    }
}

/// 7 (isolation). Closing one phone's connection does not drop another
/// phone's flow.
#[tokio::test]
async fn closing_other_connection_keeps_flow() {
    let stack = SipStack::new(SipStackConfig::default());
    let (a, b) = (at(PHONE_IP, 40_040), at(PHONE_IP, 40_041));
    let (c1, c2) = (ConnId::next(), ConnId::next());
    register_ex(
        &stack,
        "bob",
        a,
        AddrTransport::Tls,
        Some(c1),
        ("qa7i-b@test", 1, 3600),
    )
    .await;
    register_ex(
        &stack,
        "carol",
        b,
        AddrTransport::Tls,
        Some(c2),
        ("qa7i-c@test", 1, 3600),
    )
    .await;
    stack.connection_closed(c2).await;
    assert!(
        !invite(&stack, "qa7i-1@test", a, AddrTransport::Tls, Some(c1))
            .await
            .denied
    );
    assert!(
        invite(&stack, "qa7i-2@test", b, AddrTransport::Tls, Some(c2))
            .await
            .denied
    );
}

/// A config-file trunk group with the same host as a UDP and a TLS trunk.
fn dual_transport_trunk_stack() -> SipStack {
    let mut stack = SipStack::new(SipStackConfig::default());
    let routing = sbc_config::RoutingConfig {
        use_dial_plan: true,
        max_failover_attempts: 1,
        default_trunk_group: "carrier".to_string(),
        emergency_trunk_group: None,
    };
    let trunk = |id: &str, port: u16, protocol: &str| sbc_config::TrunkConfigSchema {
        id: id.to_string(),
        host: "203.0.113.9".to_string(),
        port,
        protocol: protocol.to_string(),
        ..Default::default()
    };
    let groups = vec![sbc_config::TrunkGroupConfig {
        id: "carrier".to_string(),
        name: "Carrier".to_string(),
        strategy: "priority".to_string(),
        trunks: vec![trunk("c-udp", 5060, "udp"), trunk("c-tls", 5061, "tls")],
        zone: None,
        require_tls: false,
        trust_domain: true,
    }];
    stack.init_router_from_config(&routing, &[], &groups);
    stack
}

/// One trunk host configured on two transports in one group is that trunk
/// on both (each on its own key); TCP matches the UDP trunk (transport
/// floor, RFC 3261 §18.1.1); WS and WSS never match.
#[tokio::test]
async fn config_trunk_on_two_transports_matches_both_only() {
    let stack = dual_transport_trunk_stack();
    assert_eq!(
        stack
            .admit_invite_source(&ingress(at(TRUNK_IP, 5060), AddrTransport::Udp, None))
            .await,
        carrier_via(AddrTransport::Udp)
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(
                at(TRUNK_IP, 5061),
                AddrTransport::Tls,
                Some(ConnId::next())
            ))
            .await,
        carrier_via(AddrTransport::Tls)
    );
    assert_eq!(
        stack
            .admit_invite_source(&ingress(
                at(TRUNK_IP, 5062),
                AddrTransport::Tcp,
                Some(ConnId::next())
            ))
            .await,
        carrier_via(AddrTransport::Udp)
    );
    assert!(
        stack
            .ingress_trusted(ip_of(TRUNK_IP), AddrTransport::Tcp)
            .await
    );
    for t in [AddrTransport::WebSocket, AddrTransport::WebSocketSecure] {
        assert!(
            matches!(
                stack
                    .admit_invite_source(&ingress(at(TRUNK_IP, 5062), t, Some(ConnId::next())))
                    .await,
                SourceAdmission::Denied(DenyHint::TrunkOtherTransport(_))
            ),
            "{t}"
        );
        assert!(!stack.ingress_trusted(ip_of(TRUNK_IP), t).await, "{t}");
    }
    assert!(
        stack
            .ingress_trusted(ip_of(TRUNK_IP), AddrTransport::Udp)
            .await
    );
    assert!(
        stack
            .ingress_trusted(ip_of(TRUNK_IP), AddrTransport::Tls)
            .await
    );
}

/// API-registered trunk on two transports: a re-sync to TLS only drops the
/// UDP source, and removal drops both.
#[tokio::test]
async fn api_trunk_on_two_transports_resync_and_remove() {
    let stack = SipStack::new(SipStackConfig::default());
    let ip = ip_of(TRUNK_IP);
    let host = "203.0.113.9".to_string();
    stack
        .register_inbound_trunk(
            "carrier",
            Some("css1"),
            &[
                (host.clone(), AddrTransport::Udp),
                (host.clone(), AddrTransport::Tls),
            ],
        )
        .await;
    let want = Some(("carrier".to_string(), Some("css1".to_string())));
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Udp).await,
        want
    );
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Tls).await,
        want
    );
    // TCP: no exact entry, matched by the UDP trunk (transport floor).
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Tcp).await,
        want
    );

    stack
        .register_inbound_trunk("carrier", Some("css1"), &[(host, AddrTransport::Tls)])
        .await;
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Tcp).await,
        None,
        "a TLS trunk does not admit TCP"
    );
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Udp).await,
        None
    );
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Tls).await,
        want
    );
    assert!(
        invite(
            &stack,
            "qa-tr-u@test",
            at(TRUNK_IP, 5060),
            AddrTransport::Udp,
            None
        )
        .await
        .denied
    );

    stack.remove_trunk_group_from_router("carrier").await;
    assert_eq!(
        stack.lookup_inbound_trunk(ip, AddrTransport::Tls).await,
        None
    );
}

/// WebSocket ingress (RFC 7118; the daemon gives each WS connection a
/// `ConnId`): a WS registration admits only its own connection and
/// transport, and is dropped when the connection closes.
#[tokio::test]
async fn websocket_registered_flow_is_exact() {
    for transport in [AddrTransport::WebSocket, AddrTransport::WebSocketSecure] {
        let stack = SipStack::new(SipStackConfig::default());
        let src = at(PHONE_IP, 40_050);
        let (c1, c2) = (ConnId::next(), ConnId::next());
        register(&stack, "bob", src, transport, Some(c1)).await;
        assert_eq!(
            stack
                .admit_invite_source(&ingress(src, transport, Some(c1)))
                .await,
            SourceAdmission::RegisteredFlow,
            "{transport}"
        );
        assert!(
            !invite(&stack, "qa-ws-a@test", src, transport, Some(c1))
                .await
                .denied,
            "{transport}"
        );
        assert!(
            invite(&stack, "qa-ws-b@test", src, transport, Some(c2))
                .await
                .denied,
            "{transport} other conn"
        );
        assert_eq!(
            stack
                .admit_invite_source(&ingress(src, transport, Some(c2)))
                .await,
            SourceAdmission::Denied(DenyHint::FlowOtherConnection),
            "{transport}"
        );
        assert!(
            invite(&stack, "qa-ws-n@test", src, transport, None)
                .await
                .denied,
            "{transport} no conn"
        );
        // Same ip:port and connection id, another transport.
        assert_eq!(
            stack
                .admit_invite_source(&ingress(src, AddrTransport::Tcp, Some(c1)))
                .await,
            SourceAdmission::Denied(DenyHint::FlowOtherTransport),
            "{transport}"
        );
        stack.connection_closed(c1).await;
        assert!(
            invite(&stack, "qa-ws-c@test", src, transport, Some(c1))
                .await
                .denied,
            "{transport} closed"
        );
    }
}

/// A WS/WSS INVITE from an address that is a trunk on every trunk transport
/// is never that trunk (trunks are UDP/TCP/TLS only).
#[tokio::test]
async fn websocket_from_trunk_ip_is_never_a_trunk() {
    let stack = SipStack::new(SipStackConfig::default());
    let host = "203.0.113.9".to_string();
    stack
        .register_inbound_trunk(
            "carrier",
            None,
            &[
                (host.clone(), AddrTransport::Udp),
                (host.clone(), AddrTransport::Tcp),
                (host, AddrTransport::Tls),
            ],
        )
        .await;
    for t in [AddrTransport::WebSocket, AddrTransport::WebSocketSecure] {
        let c = Some(ConnId::next());
        let s = invite(
            &stack,
            &format!("qa-ws-t-{t}@test"),
            at(TRUNK_IP, 443),
            t,
            c,
        )
        .await;
        assert!(s.denied, "{t}: {:?}", s.results);
        assert!(!stack.is_trunk_source(ip_of(TRUNK_IP), t).await, "{t}");
        assert!(!stack.ingress_trusted(ip_of(TRUNK_IP), t).await, "{t}");
    }
}

/// SEC-001 / RFC-3 end to end: the `pbx` group has a verifying, stripping
/// `udp` trunk and a trusted (passthrough) `tls` trunk on one host. A UDP
/// INVITE with a forged Identity gets the UDP trunk's settings: verified
/// (fails) and not relayed; the TLS trunk's passthrough does not leak to it.
#[tokio::test]
async fn stir_settings_follow_resolved_trunk_key_end_to_end() {
    let q = qa_stir_stack_with(
        sbc_config::StirFailurePolicy::Mark,
        0,
        1000,
        false,
        false,
        |c| {
            let pbx = c
                .trunk_groups
                .iter_mut()
                .find(|g| g.id == "pbx")
                .expect("pbx group");
            pbx.trunks.push(sbc_config::TrunkConfigSchema {
                id: "alice-tls".into(),
                host: "192.168.1.1".into(),
                protocol: "tls".into(),
                stir_shaken: sbc_config::TrunkStirConfig {
                    sign: false,
                    verify: false,
                    strip_inbound_identity: false,
                },
                ..Default::default()
            });
        },
    )
    .await;
    let stir = q.stack.stir().unwrap();
    let forged = "e30.e30.sig;info=<https://cert.example.com/a.pem>";
    let s = send_invite(
        &q.stack,
        &qa_invite("sa-sec001@test", Some(forged)),
        alice(),
        AddrTransport::Udp,
        None,
    )
    .await;
    assert!(!s.denied, "{:?}", s.results);
    assert_eq!(stir.metrics.verify_failed.load(Ordering::Relaxed), 1);
    if let Some((b, _)) = forwarded(&s.results, &Method::Invite) {
        assert!(
            b.headers
                .get_all(&HeaderName::Identity)
                .all(|h| h.value != forged),
            "forged UDP Identity relayed"
        );
    }
}

/// RFC-4: one flow binds up to `MAX_AORS_PER_FLOW` (64) AORs; the next is
/// refused, counted in `flow_index_overflow` (exported as
/// `sbc_flow_index_overflow_total`), and the REGISTER still gets 200.
#[tokio::test]
async fn per_flow_aor_cap_is_64_and_overflow_is_counted() {
    let stack = SipStack::new(SipStackConfig::default());
    let src = at(PHONE_IP, 5060);
    let overflow = || {
        stack
            .routing_counters()
            .flow_index_overflow
            .load(Ordering::Relaxed)
    };
    let max = crate::stir_binding::MAX_AORS_PER_FLOW;
    assert_eq!(max, 64);
    for i in 0..max {
        register_ex(
            &stack,
            &format!("line{i}"),
            src,
            AddrTransport::Udp,
            None,
            (&format!("sa-cap-{i}@test"), 1, 3600),
        )
        .await;
    }
    assert_eq!(overflow(), 0);
    let key = crate::stir_binding::flow_key(src.ip(), src.port(), AddrTransport::Udp);
    assert_eq!(
        stack
            .stir_flows
            .read()
            .await
            .get(&key, None)
            .map(<[String]>::len),
        Some(max)
    );
    // The 65th: REGISTER accepted (200, asserted by `register_ex`), not
    // indexed, counted.
    register_ex(
        &stack,
        "line-extra",
        src,
        AddrTransport::Udp,
        None,
        ("sa-cap-extra@test", 1, 3600),
    )
    .await;
    assert_eq!(overflow(), 1);
    assert_eq!(
        stack
            .stir_flows
            .read()
            .await
            .get(&key, None)
            .map(<[String]>::len),
        Some(max)
    );
    // The flow itself still admits (its indexed AORs are live).
    assert!(
        !invite(&stack, "sa-cap-inv@test", src, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// RFC-5: a UA that keeps one Call-ID (RFC 3261 §10.2) and registers
/// contact A from one flow and contact B from another keeps both flows: the
/// second REGISTER re-latches only the binding it carried.
#[tokio::test]
async fn same_call_id_two_flows_keep_their_own_bindings() {
    let stack = SipStack::new(SipStackConfig::default());
    let (f1, f2) = (at(PHONE_IP, 5060), at(PHONE_IP, 5070));
    let reg = |src: SbcSocketAddr, contact: &str, cseq: u32| {
        Bytes::from(format!(
            "REGISTER sip:sbc.local SIP/2.0\r\n\
             Via: SIP/2.0/UDP {src};branch=z9hG4bK-sa-2f-{cseq}\r\n\
             From: <sip:bob@sbc.local>;tag=r2f\r\n\
             To: <sip:bob@sbc.local>\r\n\
             Call-ID: sa-two-flows@test\r\n\
             CSeq: {cseq} REGISTER\r\n\
             Contact: <{contact}>\r\n\
             Expires: 3600\r\n\
             Content-Length: 0\r\n\r\n"
        ))
    };
    for (src, contact, cseq) in [
        (f1, "sip:bob@10.0.0.7:5060", 1),
        (f2, "sip:bob@10.0.0.8:5060", 2),
    ] {
        let r = flatten(
            stack
                .process_message(&reg(src, contact, cseq), src, None)
                .await,
        );
        assert!(responded(&r, 200).is_some(), "{r:?}");
    }
    assert!(
        !invite(&stack, "sa-2f-1@test", f1, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert!(
        !invite(&stack, "sa-2f-2@test", f2, AddrTransport::Udp, None)
            .await
            .denied
    );
    // A refresh of A from flow 1 keeps B on flow 2.
    let r = flatten(
        stack
            .process_message(&reg(f1, "sip:bob@10.0.0.7:5060", 3), f1, None)
            .await,
    );
    assert!(responded(&r, 200).is_some(), "{r:?}");
    assert!(
        !invite(&stack, "sa-2f-3@test", f2, AddrTransport::Udp, None)
            .await
            .denied
    );
    // De-registering B (Expires: 0 on its contact) from flow 2 drops flow 2
    // only.
    let dereg = String::from_utf8_lossy(&reg(f2, "sip:bob@10.0.0.8:5060", 4)).replacen(
        "Expires: 3600",
        "Expires: 0",
        1,
    );
    let r = flatten(stack.process_message(&Bytes::from(dereg), f2, None).await);
    assert!(responded(&r, 200).is_some(), "{r:?}");
    assert!(
        invite(&stack, "sa-2f-4@test", f2, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert!(
        !invite(&stack, "sa-2f-5@test", f1, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// A query REGISTER (no Contact) from another flow neither moves the
/// binding nor indexes that flow.
#[tokio::test]
async fn query_register_changes_no_flow() {
    let stack = SipStack::new(SipStackConfig::default());
    let (f1, f2) = (at(PHONE_IP, 5060), at(PHONE_IP, 5090));
    register_ex(
        &stack,
        "bob",
        f1,
        AddrTransport::Udp,
        None,
        ("sa-q@test", 1, 3600),
    )
    .await;
    let query = Bytes::from(format!(
        "REGISTER sip:sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/UDP {f2};branch=z9hG4bK-sa-q-2\r\n\
         From: <sip:bob@sbc.local>;tag=rq\r\n\
         To: <sip:bob@sbc.local>\r\n\
         Call-ID: sa-q@test\r\n\
         CSeq: 2 REGISTER\r\n\
         Content-Length: 0\r\n\r\n"
    ));
    let r = flatten(stack.process_message(&query, f2, None).await);
    assert!(responded(&r, 200).is_some(), "{r:?}");
    assert!(
        !invite(&stack, "sa-q-1@test", f1, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert!(
        invite(&stack, "sa-q-2@test", f2, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// SEC-003: a UDP datagram from a TLS trunk's address with a stale UDP flow
/// entry is logged as a trunk on another transport, not as a dead
/// registration.
#[tokio::test]
async fn trunk_hint_wins_over_flow_hint() {
    let stack = config_trunk_stack("tls");
    let udp_src = at(TRUNK_IP, 5060);
    register(&stack, "bob", udp_src, AddrTransport::Udp, None).await;
    let contact = latched_contact(&stack, "bob").await;
    stack
        .delete_registration(&aor_of("bob"), &contact)
        .await
        .unwrap();
    assert_eq!(
        stack
            .admit_invite_source(&ingress(udp_src, AddrTransport::Udp, None))
            .await,
        SourceAdmission::Denied(DenyHint::TrunkOtherTransport(AddrTransport::Tls))
    );
}

/// One-Call-ID REGISTER with the given Contact (and optional RFC 5626
/// `+sip.instance`/`reg-id`), CSeq and Expires, from `src`.
fn reg_contact(src: SbcSocketAddr, call_id: &str, contact: &str, cseq: u32, expires: u32) -> Bytes {
    Bytes::from(format!(
        "REGISTER sip:sbc.local SIP/2.0\r\n\
         Via: SIP/2.0/UDP {src};branch=z9hG4bK-sa-rc-{cseq}\r\n\
         From: <sip:bob@sbc.local>;tag=rc\r\n\
         To: <sip:bob@sbc.local>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: {contact}\r\n\
         Expires: {expires}\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

async fn send_reg(stack: &SipStack, msg: &Bytes, src: SbcSocketAddr) {
    let r = flatten(stack.process_message(msg, src, None).await);
    assert!(responded(&r, 200).is_some(), "{r:?}");
}

/// RFC-8: contacts A and B registered from one flow under one Call-ID;
/// removing A alone keeps the flow (B is still latched to it); removing B
/// then drops it.
#[tokio::test]
async fn removing_one_of_two_contacts_on_a_flow_keeps_the_flow() {
    let stack = SipStack::new(SipStackConfig::default());
    let f = at(PHONE_IP, 5060);
    let cid = "sa-rfc8@test";
    send_reg(
        &stack,
        &reg_contact(f, cid, "<sip:bob@10.0.0.7:5060>", 1, 3600),
        f,
    )
    .await;
    send_reg(
        &stack,
        &reg_contact(f, cid, "<sip:bob@10.0.0.8:5060>", 2, 3600),
        f,
    )
    .await;
    send_reg(
        &stack,
        &reg_contact(f, cid, "<sip:bob@10.0.0.7:5060>", 3, 0),
        f,
    )
    .await;
    assert!(
        !invite(&stack, "sa-rfc8-1@test", f, AddrTransport::Udp, None)
            .await
            .denied,
        "B still on the flow"
    );
    send_reg(
        &stack,
        &reg_contact(f, cid, "<sip:bob@10.0.0.8:5060>", 4, 0),
        f,
    )
    .await;
    assert!(
        invite(&stack, "sa-rfc8-2@test", f, AddrTransport::Udp, None)
            .await
            .denied,
        "no binding left on the flow"
    );
}

/// SEC-006 with RFC 5626: a REGISTER with the same `+sip.instance` and
/// `reg-id` but a new Contact URI from a new flow replaces the binding
/// wholesale; the replacement is carried (its URI is this REGISTER's), so
/// the binding moves to the new flow and the old flow no longer admits.
#[tokio::test]
async fn outbound_instance_replacement_moves_the_flow() {
    let stack = SipStack::new(SipStackConfig::default());
    let (f1, f2) = (at(PHONE_IP, 5060), at(PHONE_IP, 5080));
    let cid = "sa-inst@test";
    let inst = ";+sip.instance=\"<urn:uuid:00000000-0000-4000-8000-000000000001>\";reg-id=1";
    send_reg(
        &stack,
        &reg_contact(f1, cid, &format!("<sip:bob@10.0.0.7:5060>{inst}"), 1, 3600),
        f1,
    )
    .await;
    assert!(
        !invite(&stack, "sa-inst-1@test", f1, AddrTransport::Udp, None)
            .await
            .denied
    );
    send_reg(
        &stack,
        &reg_contact(f2, cid, &format!("<sip:bob@10.0.0.9:5060>{inst}"), 2, 3600),
        f2,
    )
    .await;
    assert!(
        !invite(&stack, "sa-inst-2@test", f2, AddrTransport::Udp, None)
            .await
            .denied
    );
    assert!(
        invite(&stack, "sa-inst-3@test", f1, AddrTransport::Udp, None)
            .await
            .denied
    );
}

/// SEC-005 / RFC-10: a config group's `udp` trunk verifies (with
/// `require_identity`); an API resync moves the group's source to TLS, so
/// admission resolves a key the config-built STIR table lacks. The STIR
/// settings fall back to the same group and address: a TLS INVITE without
/// Identity is still rejected.
#[tokio::test]
async fn stir_settings_survive_api_resync_of_protocol() {
    let q = qa_stir_stack_with(
        sbc_config::StirFailurePolicy::Mark,
        0,
        1000,
        false,
        false,
        |c| c.stir_shaken.verification.require_identity = true,
    )
    .await;
    q.stack
        .register_inbound_trunk(
            "pbx",
            None,
            &[("192.168.1.1".to_string(), AddrTransport::Tls)],
        )
        .await;
    let tls_src = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5061);
    let s = send_invite(
        &q.stack,
        &qa_invite("sa-resync@test", None),
        tls_src,
        AddrTransport::Tls,
        Some(ConnId::next()),
    )
    .await;
    assert!(!s.denied, "a trunk");
    assert!(
        response_status(&s.results).is_some_and(|(code, _)| code >= 400),
        "missing Identity rejected: {:?}",
        s.results
    );
    assert!(forwarded(&s.results, &Method::Invite).is_none());
    let stir = q.stack.stir().unwrap();
    assert_eq!(stir.metrics.verify_rejected.load(Ordering::Relaxed), 1);
}

/// RFC-9: a `udp` trunk's INVITE that arrived over TCP (large request)
/// sets the trunk leg's transport floor to UDP, so a later small in-dialog
/// request from the trunk over UDP is the dialog's peer.
#[tokio::test]
async fn udp_trunk_leg_called_over_tcp_accepts_udp_in_dialog() {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .register_inbound_trunk(
            "test-trunk",
            None,
            &[("192.168.1.1".to_string(), AddrTransport::Udp)],
        )
        .await;
    send_reg(
        &stack,
        &register_msg("bob", bob(), "sa-rfc9-reg@test", 1, 3600),
        bob(),
    )
    .await;
    let c = Some(ConnId::next());
    let s = send_invite(
        &stack,
        &alice_request("INVITE", 1, None, Some(ALICE_SDP)),
        alice(),
        AddrTransport::Tcp,
        c,
    )
    .await;
    let b_invite = forwarded(&s.results, &Method::Invite)
        .expect("to bob")
        .0
        .clone();
    let _ = stack
        .process_message(
            &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
            bob(),
            None,
        )
        .await;
    let _ = stack
        .process_message_conn(
            &alice_request("ACK", 1, Some("bobtag"), None),
            alice(),
            None,
            AddrTransport::Tcp,
            c,
        )
        .await;
    let r = flatten(
        stack
            .process_message_conn(
                &alice_request("INVITE", 2, Some("bobtag"), Some(ALICE_SDP)),
                alice(),
                None,
                AddrTransport::Udp,
                None,
            )
            .await,
    );
    assert!(responded(&r, 403).is_none(), "{r:?}");
    assert!(
        forwarded(&r, &Method::Invite).is_some(),
        "re-INVITE relayed: {r:?}"
    );
}

/// SEC-R2-1: a `udp` trunk's INVITE that arrived over TLS (here with a
/// `sips:` Request-URI, or a plain `sip:` one) keeps the TLS floor on the
/// trunk leg: a later plaintext UDP re-INVITE from the trunk gets 403.
#[tokio::test]
async fn udp_trunk_leg_called_over_tls_refuses_udp_in_dialog() {
    for sips in [true, false] {
        let stack = SipStack::new(SipStackConfig::default());
        stack
            .register_inbound_trunk(
                "test-trunk",
                None,
                &[("192.168.1.1".to_string(), AddrTransport::Udp)],
            )
            .await;
        // bob registers over TLS, so a sips: call can reach him.
        let cb = Some(ConnId::next());
        let r = flatten(
            stack
                .process_message_conn(
                    &register_msg("bob", bob(), "sa-r2-1-reg@test", 1, 3600),
                    bob(),
                    None,
                    AddrTransport::Tls,
                    cb,
                )
                .await,
        );
        assert!(responded(&r, 200).is_some(), "{r:?}");
        let ca = Some(ConnId::next());
        let tls_alice = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5061);
        let invite = alice_request("INVITE", 1, None, Some(ALICE_SDP));
        let invite = if sips {
            Bytes::from(String::from_utf8_lossy(&invite).replacen(
                "INVITE sip:bob@sbc.local",
                "INVITE sips:bob@sbc.local",
                1,
            ))
        } else {
            invite
        };
        let s = send_invite(&stack, &invite, tls_alice, AddrTransport::Tls, ca).await;
        let b_invite = forwarded(&s.results, &Method::Invite)
            .unwrap_or_else(|| panic!("sips={sips}: to bob: {:?}", s.results))
            .0
            .clone();
        let _ = stack
            .process_message_conn(
                &response_to(&b_invite, 200, Some("bobtag"), Some(BOB_SDP)),
                bob(),
                None,
                AddrTransport::Tls,
                cb,
            )
            .await;
        let _ = stack
            .process_message_conn(
                &alice_request("ACK", 1, Some("bobtag"), None),
                tls_alice,
                None,
                AddrTransport::Tls,
                ca,
            )
            .await;
        assert_eq!(stack.call_count().await, 1, "sips={sips}: call up");
        let r = flatten(
            stack
                .process_message_conn(
                    &alice_request("INVITE", 2, Some("bobtag"), Some(ALICE_SDP)),
                    alice(),
                    None,
                    AddrTransport::Udp,
                    None,
                )
                .await,
        );
        assert!(responded(&r, 403).is_some(), "sips={sips}: {r:?}");
        assert!(forwarded(&r, &Method::Invite).is_none(), "sips={sips}");
    }
}
