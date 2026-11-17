//! Call-leg SDP media security tests (SDES key and suite relay).
//!
//! RFC 4568 §8 / §8.3: `a=crypto` carries the SRTP master key in the clear
//! inside SDP, so it may only cross a hop whose signalling is confidential
//! and integrity-protected (TLS). RFC 4568 §6.3.1 / §7.1.2 / §9.1 and
//! RFC 7714 §14.1 / CNSA 2.0: only `AEAD_AES_256_GCM` without the
//! `UNENCRYPTED_*` / `UNAUTHENTICATED_*` session parameters is acceptable;
//! an answer carries exactly one crypto attribute; `a=crypto` is
//! media-level only. RFC 3264 §6 / §8: m-lines are never removed and a
//! declined (port 0) section keeps no keying.
//!
//! Sans-IO: trunk stacks from the parent test module, a media controller
//! that logs relay starts, and the thread-local audit capture. All key
//! values are fixed byte patterns, not secrets.
//!
//! NIST 800-53 Rev5: SC-8, SC-12, SC-13, SC-24, SI-10, SI-11, AU-2.

use super::*;
use sbc_media_core::media_pipeline::{
    AllocatedPorts, LegDtlsParams, MediaController, MediaKind, MediaPipelineError,
};

/// 44 octets (AEAD_AES_256_GCM key || salt, RFC 7714 §12): bytes 0..44.
const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKis=";
/// A second 44-octet pattern: bytes 100..144.
const KEY_256_B: &str = "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8=";
/// 30 octets (AES_CM_128 key || salt, RFC 4568 §6.2.1): bytes 200..230
/// (not a prefix of `KEY_256`, so a substring check on it is meaningful).
const KEY_128: &str = "yMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl";

const FP_A: &str = "sha-384 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00";
const FP_SBC: &str = "sha-384 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45";
const MIKEY: &str = "a=key-mgmt:mikey AQAFgM0XflABAAAAAAAAAAAAAAsAyO7wlKGJBAAAAAAAAAAAAAAAAA==\r\n";

fn gcm(tag: u32, key: &str) -> String {
    format!("a=crypto:{tag} AEAD_AES_256_GCM inline:{key}\r\n")
}

fn aes128(tag: u32) -> String {
    format!("a=crypto:{tag} AES_CM_128_HMAC_SHA1_80 inline:{KEY_128}\r\n")
}

/// An offer from the caller: session header plus `media` (m-lines and
/// their attributes, CRLF-terminated).
fn offer(media: &str) -> String {
    format!("v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\n{media}")
}

/// An answer from the callee.
fn answer_body(media: &str) -> String {
    format!("v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n{media}")
}

fn savp_audio(port: u16, crypto: &str) -> String {
    format!("m=audio {port} RTP/SAVP 0\r\n{crypto}a=sendrecv\r\n")
}

fn body_of(req: &proto_sip::message::SipRequest) -> String {
    String::from_utf8_lossy(req.body.as_deref().unwrap_or_default()).to_string()
}

fn resp_body(resp: &proto_sip::message::SipResponse) -> String {
    String::from_utf8_lossy(resp.body.as_deref().unwrap_or_default()).to_string()
}

/// Every forwarded request of `method` with its flow transport.
fn forwarded_all<'a>(
    results: &'a [ProcessResult],
    method: &Method,
) -> Vec<(&'a proto_sip::message::SipRequest, Option<AddrTransport>)> {
    results
        .iter()
        .filter_map(|r| match r {
            ProcessResult::Forward {
                message: SipMessage::Request(req),
                flow,
                ..
            } if req.method == *method => {
                let t = match flow {
                    Flow::Leg(f) => Some(f.transport),
                    Flow::Reply => None,
                };
                Some((req, t))
            }
            _ => None,
        })
        .collect()
}

/// Any final response with status >= 300.
fn final_failure(results: &[ProcessResult]) -> Option<&proto_sip::message::SipResponse> {
    results.iter().find_map(|r| match r {
        ProcessResult::Response {
            message: SipMessage::Response(resp),
            ..
        } if resp.status.code() >= 300 => Some(resp),
        _ => None,
    })
}

fn warning_of(resp: &proto_sip::message::SipResponse) -> String {
    resp.headers
        .get_value(&HeaderName::Warning)
        .map_or_else(String::new, ToString::to_string)
}

/// The refusal never echoes SDP content (RFC 3261 §20.43; SI-11).
fn assert_warning_is_fixed(resp: &proto_sip::message::SipResponse) {
    let w = warning_of(resp);
    for leak in ["inline", "AES_CM", "AEAD", "crypto:", KEY_128, KEY_256] {
        assert!(!w.contains(leak), "Warning echoes SDP ({leak}): {w}");
    }
}

/// Places a call to the trunk dial plan from alice on `transport`.
async fn place_on(
    stack: &SipStack,
    call_id: &str,
    transport: AddrTransport,
    body: &str,
) -> Vec<ProcessResult> {
    flatten(
        stack
            .process_message_on(
                &caller_request("INVITE", DIALED, call_id, 1, None, Some(body)),
                alice(),
                None,
                transport,
            )
            .await,
    )
}

/// Media controller that logs the relay starts.
#[derive(Default)]
struct RelayLog {
    log: std::sync::Mutex<Vec<String>>,
}

impl RelayLog {
    fn push(&self, s: &str) {
        self.log.lock().unwrap().push(s.to_string());
    }
    fn starts(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("start"))
            .count()
    }
}

#[async_trait::async_trait]
impl MediaController for RelayLog {
    async fn create_session_with_zones(
        &self,
        _call_id: &str,
        _mode: Option<uc_media_engine::MediaMode>,
        _a: Option<std::net::IpAddr>,
        _b: Option<std::net::IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        self.push("create");
        Ok(AllocatedPorts {
            a_leg_rtp_port: 20_000,
            b_leg_rtp_port: 20_002,
            media_ip: None,
            dtls_fingerprint: None,
        })
    }
    async fn set_remote_address(
        &self,
        _call_id: &str,
        _is_a_leg: bool,
        _address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        Ok(())
    }
    async fn start_relay(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        self.push("start opaque");
        Ok(())
    }
    async fn start_relay_terminate(
        &self,
        _call_id: &str,
        _a: LegDtlsParams,
        _b: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        self.push("start terminate");
        Ok(())
    }
    async fn stop_relay(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        Ok(())
    }
    async fn remove_session(&self, _call_id: &str) -> Result<(), MediaPipelineError> {
        self.push("remove");
        Ok(())
    }
    async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError> {
        Ok((30_000, 30_001))
    }
    async fn set_media_kind(
        &self,
        _call_id: &str,
        _kind: MediaKind,
    ) -> Result<(), MediaPipelineError> {
        Ok(())
    }
}

/// Trunk stack (t1/t2 with `protos`) with the logging media controller.
async fn media_trunk_stack(protos: [&str; 2]) -> (SipStack, Arc<RelayLog>) {
    let media = Arc::new(RelayLog::default());
    let mut stack = trunk_stack_protos(protos).await;
    stack.set_media_pipeline(Arc::clone(&media) as _);
    (stack, media)
}

// ----------------------------------------------------------------------
// Initial INVITE offer
// ----------------------------------------------------------------------

/// RFC 4568 §8.3: a TLS caller's SDES offer must not be relayed to a callee
/// reached over UDP (registered contact).
#[tokio::test]
async fn sdes_offer_from_tls_to_udp_leg_is_refused_488() {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .register_inbound_trunk("t", None, &[("192.168.1.1".to_string(), 5061)])
        .await;
    let register = b"REGISTER sip:sbc.local SIP/2.0\r\n\
        Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-reg\r\n\
        From: <sip:bob@sbc.local>;tag=r1\r\nTo: <sip:bob@sbc.local>\r\n\
        Call-ID: reg-bob@relay\r\nCSeq: 1 REGISTER\r\n\
        Contact: <sip:bob@127.0.0.1:5060>\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n";
    let _ = stack
        .process_message(&Bytes::from_static(register), bob(), None)
        .await;
    let sdp = offer(&savp_audio(4000, &aes128(1)));
    let inv = alice_request("INVITE", 1, None, Some(&sdp));
    let results = flatten(
        stack
            .process_message_on(
                &inv,
                SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 1), 5061),
                None,
                AddrTransport::Tls,
            )
            .await,
    );
    for (req, _) in forwarded_all(&results, &Method::Invite) {
        assert!(
            !body_of(req).contains("inline:"),
            "SDES key relayed to a UDP leg: {}",
            body_of(req)
        );
    }
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "no B-leg INVITE"
    );
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
}

/// Same rule toward a UDP trunk, with a CNSA suite: the suite does not
/// matter, the hop does. Slots are released (SC-5).
#[tokio::test]
async fn sdes_offer_from_tls_to_udp_trunk_is_refused_488_and_releases_slots() {
    let stack = trunk_stack_protos(["udp", "udp"]).await;
    let results = place_on(
        &stack,
        "sdes-udp@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    for (req, _) in forwarded_all(&results, &Method::Invite) {
        assert!(!body_of(req).contains(KEY_256), "{}", body_of(req));
    }
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "no B-leg INVITE: {results:?}"
    );
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
    assert_all_released(&stack).await;
}

/// RFC 4568 §8.3: the caller's own hop must be confidential too. An SDES
/// offer received over UDP is not relayed even to a TLS trunk.
#[tokio::test]
async fn sdes_offer_from_udp_to_tls_trunk_is_refused_488() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let results = place_on(
        &stack,
        "sdes-from-udp@test",
        AddrTransport::Udp,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_all_released(&stack).await;
}

/// Attribute names are matched case-insensitively (SI-10).
#[tokio::test]
async fn sdes_uppercase_attribute_name_is_policed() {
    let stack = trunk_stack_protos(["udp", "udp"]).await;
    let crypto = format!("a=CRYPTO:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n");
    let results = place_on(
        &stack,
        "sdes-case@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &crypto)),
    )
    .await;
    for (req, _) in forwarded_all(&results, &Method::Invite) {
        assert!(!body_of(req).contains(KEY_256), "{}", body_of(req));
    }
    assert!(responded(&results, 488).is_some(), "{results:?}");
}

/// SI-10: a bare CR inside the body must not hide an `a=crypto` line from
/// the policy while a lenient far-end parser still sees it.
#[tokio::test]
async fn bare_cr_smuggled_crypto_line_is_refused() {
    let stack = trunk_stack_protos(["udp", "udp"]).await;
    let media = format!(
        "m=audio 4000 RTP/AVP 0\r\na=sendrecv\ra=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY_128}\r\n"
    );
    let results = place_on(&stack, "sdes-cr@test", AddrTransport::Tls, &offer(&media)).await;
    for (req, _) in forwarded_all(&results, &Method::Invite) {
        assert!(!body_of(req).contains("inline:"), "{}", body_of(req));
    }
    assert!(responded(&results, 488).is_some(), "{results:?}");
}

/// CNSA 2.0 / RFC 7714: non-CNSA suites are stripped from a TLS-to-TLS
/// offer; the compliant line is kept unchanged.
#[tokio::test]
async fn sdes_offer_tls_to_tls_strips_non_cnsa_suites() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let crypto = format!(
        "{}{}a=crypto:3 AEAD_AES_128_GCM inline:{KEY_128}\r\n",
        aes128(1),
        gcm(2, KEY_256)
    );
    let results = place_on(
        &stack,
        "sdes-strip@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &crypto)),
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert_eq!(body.matches("a=crypto:").count(), 1, "{body}");
    assert!(
        body.contains(&format!("a=crypto:2 AEAD_AES_256_GCM inline:{KEY_256}")),
        "{body}"
    );
    assert!(!body.contains("AES_CM_128"), "{body}");
    assert!(!body.contains("AEAD_AES_128_GCM"), "{body}");
    assert!(!body.contains(KEY_128), "{body}");
    assert!(body.contains("m=audio "), "m-line kept: {body}");
}

/// No acceptable suite left after stripping: 488 (Warning 306), not
/// forwarded.
#[tokio::test]
async fn sdes_offer_tls_to_tls_with_only_aes128_is_refused_488() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let results = place_on(
        &stack,
        "sdes-128@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &aes128(1))),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert!(warning_of(r).starts_with("306 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
    assert_all_released(&stack).await;
}

/// RFC 4568 §6.3.1: `UNENCRYPTED_SRTP`, `UNENCRYPTED_SRTCP` and
/// `UNAUTHENTICATED_SRTP` disable protection; such lines are stripped, and
/// when no other line remains the offer is refused.
#[tokio::test]
async fn sdes_unencrypted_srtp_session_param_is_stripped() {
    for (i, param) in [
        "UNENCRYPTED_SRTP",
        "UNENCRYPTED_SRTCP",
        "UNAUTHENTICATED_SRTP",
    ]
    .into_iter()
    .enumerate()
    {
        let weak = format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256_B} {param}\r\n");

        // Alongside a compliant line: only the compliant line crosses.
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let crypto = format!("{weak}{}", gcm(2, KEY_256));
        let results = place_on(
            &stack,
            &format!("sdes-param-{i}@test"),
            AddrTransport::Tls,
            &offer(&savp_audio(4000, &crypto)),
        )
        .await;
        let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
        let body = body_of(req);
        assert!(!body.contains(param), "{param} crossed: {body}");
        assert!(
            !body.contains(KEY_256_B),
            "{param} line's key crossed: {body}"
        );
        assert_eq!(body.matches("a=crypto:").count(), 1, "{body}");

        // Alone: refused.
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let results = place_on(
            &stack,
            &format!("sdes-param-only-{i}@test"),
            AddrTransport::Tls,
            &offer(&savp_audio(4000, &weak)),
        )
        .await;
        assert!(
            forwarded_all(&results, &Method::Invite).is_empty(),
            "{param}: {results:?}"
        );
        assert!(responded(&results, 488).is_some(), "{param}: {results:?}");
    }
}

/// RFC 4568 §9.1: `a=crypto` is media-level only; a session-level line is
/// stripped from an offer.
#[tokio::test]
async fn sdes_session_level_crypto_is_stripped_from_offer() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\n{}{}",
        gcm(9, KEY_256_B),
        savp_audio(4000, &gcm(1, KEY_256))
    );
    let results = place_on(&stack, "sdes-sess@test", AddrTransport::Tls, &sdp).await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert!(
        !body.contains(KEY_256_B),
        "session-level key crossed: {body}"
    );
    assert_eq!(body.matches("a=crypto:").count(), 1, "{body}");
}

/// RFC 4567 MIKEY: `a=key-mgmt` is stripped from offers next to SDES, and
/// refused when it is the only keying.
#[tokio::test]
async fn key_mgmt_is_stripped_from_offer_and_refused_when_only_keying() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let crypto = format!("{MIKEY}{}", gcm(1, KEY_256));
    let results = place_on(
        &stack,
        "mikey-strip@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &crypto)),
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert!(!body.contains("key-mgmt"), "{body}");
    assert_eq!(body.matches("a=crypto:").count(), 1, "{body}");

    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let results = place_on(
        &stack,
        "mikey-only@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, MIKEY)),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert!(responded(&results, 488).is_some(), "{results:?}");
}

/// RFC 3264 §8: a declined (port 0) section keeps its m-line but no keys.
/// The only active line is RTP/AVP, so the call routes to the UDP trunk;
/// the declined section's key must not go with it.
#[tokio::test]
async fn declined_mline_crypto_is_stripped() {
    let mut stack = trunk_stack_protos(["udp", "udp"]).await;
    // The active line is cleartext: `media.srtp.required = false`.
    stack.set_media_security_policy(&sbc_config::schema::SrtpConfig {
        required: false,
        ..sbc_config::schema::SrtpConfig::default()
    });
    let media = format!(
        "m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\nm=video 0 RTP/SAVP 96\r\n{}",
        aes128(1)
    );
    let results = place_on(&stack, "port0-udp@test", AddrTransport::Tls, &offer(&media)).await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert!(
        !body.contains("inline:"),
        "declined section's key crossed: {body}"
    );
    assert!(!body.contains("a=crypto"), "{body}");
    assert!(
        body.contains("m=video 0 "),
        "m-line kept (RFC 3264 §8): {body}"
    );
}

/// The same on a TLS-to-TLS call: the active line's compliant key crosses,
/// the declined line's does not.
#[tokio::test]
async fn declined_mline_crypto_is_stripped_tls_to_tls() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let media = format!(
        "{}m=video 0 RTP/SAVP 96\r\n{}",
        savp_audio(4000, &gcm(1, KEY_256)),
        gcm(1, KEY_256_B)
    );
    let results = place_on(&stack, "port0-tls@test", AddrTransport::Tls, &offer(&media)).await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert!(body.contains(KEY_256), "{body}");
    assert!(
        !body.contains(KEY_256_B),
        "declined section's key crossed: {body}"
    );
    assert_eq!(body.matches("a=crypto:").count(), 1, "{body}");
}

/// AU-2 / AU-3: the refusal is audited as a denied authorization decision
/// labelled `media_security:<reason>`; no record carries key material.
#[tokio::test]
async fn sdes_refusal_is_audited_without_key_material() {
    let stack = trunk_stack_protos(["udp", "udp"]).await;
    let capture = uc_audit::capture::start();
    let results = place_on(
        &stack,
        "sdes-audit@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    assert!(responded(&results, 488).is_some(), "{results:?}");
    let events = capture.events();
    let decisions: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::AuthorizationDecision(d)
                if d.policy == "media_security:sdes_over_insecure_signalling" =>
            {
                Some(d)
            }
            _ => None,
        })
        .collect();
    assert_eq!(decisions.len(), 1, "{events:?}");
    assert!(!decisions[0].granted);
    assert_eq!(decisions[0].action, "INVITE");
    let dump = format!("{events:?}");
    assert!(!dump.contains("inline:"), "{dump}");
    assert!(!dump.contains(KEY_256), "{dump}");
}

// ----------------------------------------------------------------------
// Terminate mode
// ----------------------------------------------------------------------

/// Terminate mode: the SBC answers each leg with its own DTLS identity, so a
/// caller's `a=crypto` line (here on a DTLS m-line) must not reach the
/// B-leg.
#[tokio::test]
async fn terminate_mode_strips_crypto_from_b_leg_offer() {
    let (mut stack, _media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_dtls_fingerprint_source(Arc::new(
        sbc_media_core::dtls_identity::DtlsFingerprintSource::from_static(FP_SBC.to_string()),
    ));
    let media = format!(
        "m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\na=fingerprint:{FP_A}\r\n{}",
        gcm(1, KEY_256)
    );
    let results = place_on(
        &stack,
        "term-strip@test",
        AddrTransport::Tls,
        &offer(&media),
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert!(!body.contains("a=crypto"), "{body}");
    assert!(!body.contains(KEY_256), "{body}");
    assert!(body.contains("UDP/TLS/RTP/SAVP"), "{body}");
}

/// Terminate mode with an SDES-only RTP/SAVP offer: once `a=crypto` is
/// stripped the line has no keying the SBC can terminate, so the offer is
/// refused (`sdes_not_terminable`, Warning 399), not relayed with keys.
#[tokio::test]
async fn terminate_mode_sdes_only_offer_is_refused_488() {
    let (mut stack, _media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_dtls_fingerprint_source(Arc::new(
        sbc_media_core::dtls_identity::DtlsFingerprintSource::from_static(FP_SBC.to_string()),
    ));
    let results = place_on(
        &stack,
        "term-sdes@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    for (req, _) in forwarded_all(&results, &Method::Invite) {
        assert!(!body_of(req).contains(KEY_256), "{}", body_of(req));
    }
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_all_released(&stack).await;
}

// ----------------------------------------------------------------------
// Answers (183 / 200)
// ----------------------------------------------------------------------

/// Places a compliant TLS-to-TLS SDES call and answers it with `answer`.
/// Returns the stack, media log, the B-leg INVITE, its destination and the
/// answer results.
async fn sdes_call_answered(
    call_id: &str,
    status: u16,
    answer: &str,
) -> (
    SipStack,
    Arc<RelayLog>,
    proto_sip::message::SipRequest,
    SbcSocketAddr,
    Vec<ProcessResult>,
) {
    let (stack, media) = media_trunk_stack(["tls", "tls"]).await;
    let placed = place_on(
        &stack,
        call_id,
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let results = flatten(
        stack
            .process_message_on(
                &response_to(&inv, status, Some("bobtag"), Some(answer)),
                dest,
                None,
                AddrTransport::Tls,
            )
            .await,
    );
    (stack, media, inv, dest, results)
}

/// Non-compliant SDES answers. RFC 4568 §7.1.2: exactly one crypto line,
/// and it must pass the suite and session-parameter checks. No stripping in
/// answers.
fn weak_answers() -> Vec<(&'static str, String)> {
    vec![
        ("aes128", answer_body(&savp_audio(5000, &aes128(1)))),
        (
            "two-lines",
            answer_body(&savp_audio(
                5000,
                &format!("{}{}", gcm(1, KEY_256_B), gcm(2, KEY_256_B)),
            )),
        ),
        (
            "unencrypted",
            answer_body(&savp_audio(
                5000,
                &format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256_B} UNENCRYPTED_SRTP\r\n"),
            )),
        ),
        (
            "key-mgmt",
            answer_body(&savp_audio(5000, &format!("{}{MIKEY}", gcm(1, KEY_256_B)))),
        ),
    ]
}

/// RFC 3261 §13.2.2.4 / §15: a 200 whose SDES answer is not compliant
/// fails the call before any relay starts: ACK + BYE to the callee, 488 to
/// the caller (who never sees the 2xx), and the answer's key never reaches
/// the caller.
#[tokio::test]
async fn sdes_answer_with_weak_suite_tears_down_call() {
    for (i, (label, answer)) in weak_answers().into_iter().enumerate() {
        let (stack, media, _inv, _dest, results) =
            Box::pin(sdes_call_answered(&format!("ans-{i}@test"), 200, &answer)).await;
        assert!(
            responded(&results, 200).is_none(),
            "{label}: 2xx relayed to the caller: {results:?}"
        );
        for r in &results {
            if let ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } = r
            {
                assert!(
                    !resp_body(resp).contains(KEY_256_B),
                    "{label}: answer key relayed"
                );
            }
        }
        assert!(
            forwarded(&results, &Method::Ack).is_some(),
            "{label}: ACK to callee: {results:?}"
        );
        assert!(
            forwarded(&results, &Method::Bye).is_some(),
            "{label}: BYE to callee: {results:?}"
        );
        let (r, _) = responded(&results, 488).expect("488 to the caller");
        assert_warning_is_fixed(r);
        assert_eq!(media.starts(), 0, "{label}: no relay started");
        assert_all_released(&stack).await;
    }
}

/// The refused 200's retransmission finds no call and is re-ACKed only (no
/// second BYE, no relay).
#[tokio::test]
async fn refused_sdes_answer_retransmission_is_reacked_only() {
    let answer = answer_body(&savp_audio(5000, &aes128(1)));
    let (stack, media, inv, dest, results) =
        Box::pin(sdes_call_answered("ans-rtx@test", 200, &answer)).await;
    assert!(responded(&results, 488).is_some(), "{results:?}");
    let again = flatten(
        stack
            .process_message_on(
                &response_to(&inv, 200, Some("bobtag"), Some(&answer)),
                dest,
                None,
                AddrTransport::Tls,
            )
            .await,
    );
    assert!(forwarded(&again, &Method::Bye).is_none(), "{again:?}");
    assert!(responded(&again, 200).is_none(), "{again:?}");
    assert_eq!(media.starts(), 0);
}

/// RFC 3261 §9: a 183 whose SDES answer is not compliant CANCELs the B-leg
/// and fails the caller's INVITE with 488; the early answer is not relayed.
#[tokio::test]
async fn early_183_with_weak_crypto_cancels_b_and_488s_a() {
    let answer = answer_body(&savp_audio(5000, &aes128(1)));
    let (_stack, media, _inv, _dest, results) =
        Box::pin(sdes_call_answered("early@test", 183, &answer)).await;
    assert!(
        responded(&results, 183).is_none(),
        "183 relayed to the caller: {results:?}"
    );
    assert!(
        forwarded(&results, &Method::Cancel).is_some(),
        "CANCEL to callee: {results:?}"
    );
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert_warning_is_fixed(r);
    assert_eq!(media.starts(), 0);
}

// ----------------------------------------------------------------------
// In-dialog offers
// ----------------------------------------------------------------------

/// RFC 3261 §14.2: an SDES re-INVITE from a caller on UDP is refused with
/// 488 and not forwarded; the call keeps its media and a later re-INVITE
/// still relays.
#[tokio::test]
async fn sdes_in_reinvite_from_udp_leg_to_tls_leg_is_refused_488() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let call = "reinv-sdes@test";
    let placed = place_on(&stack, call, AddrTransport::Udp, ALICE_SDP).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    answer(&stack, &inv, dest).await;
    stack
        .process_message(
            &caller_request("ACK", DIALED, call, 1, Some("bobtag"), None),
            alice(),
            None,
        )
        .await;

    let sdes = offer(&savp_audio(4000, &gcm(1, KEY_256)));
    let results = flatten(
        stack
            .process_message(
                &caller_request("INVITE", DIALED, call, 2, Some("bobtag"), Some(&sdes)),
                alice(),
                None,
            )
            .await,
    );
    for (req, _) in forwarded_all(&results, &Method::Invite) {
        assert!(!body_of(req).contains(KEY_256), "{}", body_of(req));
    }
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    let (r, d) = responded(&results, 488).expect("488 to the offerer");
    assert_eq!(d, alice());
    assert_warning_is_fixed(r);

    // The call continues.
    stack
        .process_message(
            &caller_request("ACK", DIALED, call, 2, Some("bobtag"), None),
            alice(),
            None,
        )
        .await;
    let results = flatten(
        stack
            .process_message(
                &caller_request("INVITE", DIALED, call, 3, Some("bobtag"), Some(ALICE_SDP)),
                alice(),
                None,
            )
            .await,
    );
    assert!(
        forwarded(&results, &Method::Invite).is_some(),
        "later re-INVITE relays: {results:?}"
    );
}

// ----------------------------------------------------------------------
// Trunk failover
// ----------------------------------------------------------------------

/// The B-leg template SDP is reused on failover: after the TLS trunk fails,
/// the SDES offer must not be sent to the UDP trunk (the lease is
/// `tls_only`, as for `sips:`).
#[tokio::test]
async fn failover_does_not_carry_sdes_to_udp_trunk() {
    let stack = trunk_stack_protos(["tls", "udp"]).await;
    let results = place_on(
        &stack,
        "fo-sdes@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    let (first, _) = forwarded(&results, &Method::Invite).expect("INVITE to the TLS trunk");
    let first = first.clone();
    assert_eq!(
        flow_of(&results, &Method::Invite).transport,
        AddrTransport::Tls
    );
    let out = flatten(
        stack
            .process_message_on(
                &response_to(&first, 503, Some("t1"), None),
                t1(),
                None,
                AddrTransport::Tls,
            )
            .await,
    );
    for (req, t) in forwarded_all(&out, &Method::Invite) {
        assert!(
            t == Some(AddrTransport::Tls) || !body_of(req).contains("inline:"),
            "SDES key sent on a {t:?} failover leg: {}",
            body_of(req)
        );
    }
    assert!(
        forwarded_all(&out, &Method::Invite).is_empty(),
        "UDP failover target skipped: {out:?}"
    );
    assert!(final_failure(&out).is_some(), "caller gets a final failure");
    assert_all_released(&stack).await;
}

/// Same when the TLS attempt fails to send (connect/handshake/verify).
#[tokio::test]
async fn failover_after_tls_send_failure_does_not_carry_sdes_to_udp_trunk() {
    let stack = trunk_stack_protos(["tls", "udp"]).await;
    let results = place_on(
        &stack,
        "fo-sdes-send@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    let first = forwarded(&results, &Method::Invite)
        .expect("INVITE to the TLS trunk")
        .0
        .clone();
    let out = flatten(ProcessResult::Multiple(
        stack
            .on_invite_sent(&SipMessage::Request(first), false)
            .await,
    ));
    for (req, t) in forwarded_all(&out, &Method::Invite) {
        assert!(
            t == Some(AddrTransport::Tls) || !body_of(req).contains("inline:"),
            "SDES key sent on a {t:?} failover leg: {}",
            body_of(req)
        );
    }
    assert!(
        forwarded_all(&out, &Method::Invite).is_empty(),
        "UDP failover target skipped: {out:?}"
    );
}

// ----------------------------------------------------------------------
// Regression guards (pass before and after)
// ----------------------------------------------------------------------

/// A compliant TLS-to-TLS SDES offer is relayed with its key unchanged.
#[tokio::test]
async fn sdes_compliant_offer_tls_to_tls_is_relayed() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let results = place_on(
        &stack,
        "sdes-ok@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    assert!(
        body_of(req).contains(&format!("a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}")),
        "{}",
        body_of(req)
    );
}

/// A compliant single-line SDES answer is relayed and the relay starts.
#[tokio::test]
async fn sdes_compliant_answer_is_relayed() {
    let answer = answer_body(&savp_audio(5000, &gcm(1, KEY_256_B)));
    let (_stack, media, _inv, _dest, results) =
        Box::pin(sdes_call_answered("ans-ok@test", 200, &answer)).await;
    let (ok, _) = responded(&results, 200).expect("2xx to the caller");
    assert!(resp_body(ok).contains(KEY_256_B));
    assert_eq!(media.starts(), 1);
}

/// The SDES rules do not touch RTP/AVP: with `media.srtp.required =
/// false` a cleartext offer from a TLS caller still routes to a UDP trunk
/// (the default refuses it, `rtp_avp_offer_is_refused_488_when_required`).
#[tokio::test]
async fn rtp_avp_offer_tls_to_udp_still_relays() {
    let mut stack = trunk_stack_protos(["udp", "udp"]).await;
    stack.set_media_security_policy(&sbc_config::schema::SrtpConfig {
        required: false,
        ..sbc_config::schema::SrtpConfig::default()
    });
    let results = place_on(
        &stack,
        "avp@test",
        AddrTransport::Tls,
        &offer(&clear_audio(4000, "RTP/AVP")),
    )
    .await;
    assert!(
        forwarded(&results, &Method::Invite).is_some(),
        "{results:?}"
    );
}

// ----------------------------------------------------------------------
// Fix round 1: remaining relay paths
// ----------------------------------------------------------------------

/// Sends `msg` from `source` over `transport`, flattened.
async fn send(
    stack: &SipStack,
    msg: &Bytes,
    source: SbcSocketAddr,
    transport: AddrTransport,
) -> Vec<ProcessResult> {
    flatten(stack.process_message_on(msg, source, None, transport).await)
}

/// Every response of `status` with its destination.
fn responses(results: &[ProcessResult], status: u16) -> Vec<&proto_sip::message::SipResponse> {
    results
        .iter()
        .filter_map(|r| match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } if resp.status.code() == status => Some(resp),
            _ => None,
        })
        .collect()
}

/// No message in `results` carries an inline SDES key.
fn assert_no_inline_key(results: &[ProcessResult]) {
    for r in results {
        let body = match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } => resp_body(resp),
            ProcessResult::Forward {
                message: SipMessage::Request(req),
                ..
            } => body_of(req),
            _ => continue,
        };
        assert!(!body.contains("inline:"), "SDES key relayed: {body}");
    }
}

/// A call from alice (`caller_on`) to t1 (`trunks` are the t1/t2 transports),
/// answered with `answer` and ACKed: returns the stack, the B-leg INVITE.
async fn established_on(
    call_id: &str,
    caller_on: AddrTransport,
    trunks: [&str; 2],
    offer_sdp: &str,
    answer: &str,
) -> (SipStack, proto_sip::message::SipRequest) {
    let stack = trunk_stack_protos(trunks).await;
    let placed = place_on(&stack, call_id, caller_on, offer_sdp).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let trunk_on = flow_of(&placed, &Method::Invite).transport;
    let ok = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(answer)),
        dest,
        trunk_on,
    )
    .await;
    let (relayed, _) = responded(&ok, 200).expect("answered");
    let tag = relayed.headers.to_tag().expect("A-leg to-tag");
    assert_eq!(tag, "bobtag");
    // RFC 3261 §17.1.1.3: the 2xx ACK is its own transaction (new branch).
    let ack = String::from_utf8_lossy(&caller_request("ACK", DIALED, call_id, 1, Some(&tag), None))
        .replace(
            &format!("z9hG4bK-{call_id}-1"),
            &format!("z9hG4bK-{call_id}-ack"),
        );
    send(&stack, &Bytes::from(ack), alice(), caller_on).await;
    assert!(stack.pending_2xx.read().await.is_empty(), "caller ACKed");
    (stack, inv)
}

/// On a direct T.38 call (image-only offer) the callee's answer
/// has `a=crypto` on its declined audio section. The policy strips it, and
/// the T.38 answer check and rewrite start from the policy's output, so the
/// key never reaches a caller on UDP.
#[tokio::test]
async fn direct_t38_answer_declined_crypto_never_reaches_udp_caller() {
    let (mut stack, _media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_t38_config(sbc_config::T38Config {
        enabled: true,
        allow_cleartext: true,
        ..sbc_config::T38Config::default()
    });
    let t38_offer = offer(
        "m=audio 0 RTP/AVP 0\r\nm=image 4100 udptl t38\r\na=T38FaxVersion:0\r\n\
         a=T38MaxBitRate:14400\r\na=T38FaxUdpEC:t38UDPRedundancy\r\n",
    );
    let placed = place_on(&stack, "t38-sdes@test", AddrTransport::Udp, &t38_offer).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let t38_answer = answer_body(&format!(
        "m=audio 0 RTP/SAVP 0\r\n{}m=image 5100 udptl t38\r\na=T38FaxVersion:0\r\n\
         a=T38MaxBitRate:14400\r\na=T38FaxUdpEC:t38UDPRedundancy\r\n",
        gcm(1, KEY_256_B)
    ));
    let results = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(&t38_answer)),
        dest,
        AddrTransport::Tls,
    )
    .await;
    let (ok, _) = responded(&results, 200).expect("T.38 answer to the caller");
    let body = resp_body(ok);
    assert!(body.contains("m=image"), "{body}");
    assert!(
        !body.contains(KEY_256_B),
        "declined section's key crossed: {body}"
    );
    assert!(!body.contains("a=crypto"), "{body}");
}

/// A PRACK whose body is multipart with an SDP part is refused
/// with 488 + Warning 399 (parts are not walked) and not forwarded.
#[tokio::test]
async fn prack_with_multipart_sdp_is_refused_488() {
    let (stack, b_invite) = Box::pin(ringing_call_100rel()).await;
    let reliable = with_extra(
        &response_to(&b_invite, 183, Some("bobtag"), None),
        "Require: 100rel\r\nRSeq: 7\r\n",
        None,
    );
    let results = flatten(stack.process_message(&reliable, bob(), None).await);
    assert!(responded(&results, 183).is_some(), "{results:?}");
    let sdp = offer(&savp_audio(4000, &gcm(1, KEY_256)));
    let multipart = format!(
        "--b1\r\nContent-Type: Application/SDP\r\n\r\n{sdp}\r\n--b1\r\n\
         Content-Type: text/plain\r\n\r\nhello\r\n--b1--\r\n"
    );
    let prack = with_extra(
        &alice_request("PRACK", 315, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\n",
        Some(("multipart/mixed;boundary=b1", &multipart)),
    );
    let results = flatten(stack.process_message(&prack, alice(), None).await);
    assert!(
        forwarded(&results, &Method::Prack).is_none(),
        "multipart SDP relayed: {results:?}"
    );
    assert_no_inline_key(&results);
    let (r, d) = responded(&results, 488).expect("488 to the PRACK");
    assert_eq!(d, alice());
    assert_eq!(r.headers.cseq(), Some("315 PRACK"));
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
    // A multipart body without SDP still crosses.
    let plain = with_extra(
        &alice_request("PRACK", 316, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\n",
        Some((
            "multipart/mixed;boundary=b1",
            "--b1\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b1--\r\n",
        )),
    );
    let results = flatten(stack.process_message(&plain, alice(), None).await);
    assert!(forwarded(&results, &Method::Prack).is_some(), "{results:?}");
}

/// A reliable 183 on a ringing 100rel call, PRACKed by nothing yet.
async fn ringing_reliable_183() -> SipStack {
    let (stack, b_invite) = Box::pin(ringing_call_100rel()).await;
    let reliable = with_extra(
        &response_to(&b_invite, 183, Some("bobtag"), None),
        "Require: 100rel\r\nRSeq: 7\r\n",
        None,
    );
    let results = flatten(stack.process_message(&reliable, bob(), None).await);
    assert!(responded(&results, 183).is_some(), "{results:?}");
    stack
}

/// The PRACK is refused with 488 + Warning 399 (`unpoliced_body`), not
/// forwarded.
fn assert_prack_refused(results: &[ProcessResult], cseq: &str) {
    assert!(
        forwarded(results, &Method::Prack).is_none(),
        "unpoliced body relayed: {results:?}"
    );
    assert_no_inline_key(results);
    let (r, d) = responded(results, 488).expect("488 to the PRACK");
    assert_eq!(d, alice());
    assert_eq!(r.headers.cseq(), Some(cseq));
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
}

/// A gzip-encoded body is not walked, so it could hide an SDP part: a
/// PRACK with a gzip multipart body is refused, even with no SDP visible;
/// the same multipart with an identity encoding crosses.
#[tokio::test]
async fn prack_with_gzip_multipart_body_is_refused_488() {
    let stack = Box::pin(ringing_reliable_183()).await;
    let multipart = "--b1\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b1--\r\n";
    let prack = with_extra(
        &alice_request("PRACK", 315, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\nContent-Encoding: GZIP\r\n",
        Some(("multipart/mixed;boundary=b1", multipart)),
    );
    let results = flatten(stack.process_message(&prack, alice(), None).await);
    assert_prack_refused(&results, "315 PRACK");
    // A gzip coding after identity still counts.
    let prack = with_extra(
        &alice_request("PRACK", 316, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\nContent-Encoding: identity, gzip\r\n",
        Some(("multipart/mixed;boundary=b1", multipart)),
    );
    let results = flatten(stack.process_message(&prack, alice(), None).await);
    assert_prack_refused(&results, "316 PRACK");
    let plain = with_extra(
        &alice_request("PRACK", 317, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\nContent-Encoding: identity\r\n",
        Some(("multipart/mixed;boundary=b1", multipart)),
    );
    let results = flatten(stack.process_message(&plain, alice(), None).await);
    let (fwd, _) = forwarded(&results, &Method::Prack).expect("multipart PRACK relayed");
    assert!(body_of(fwd).contains("hi"), "{}", body_of(fwd));
}

/// SDES keying outside an `application/sdp` body is refused whatever the
/// `Content-Type` (a `message/sipfrag` here; attribute names are matched
/// case-insensitively).
#[tokio::test]
async fn sipfrag_body_with_crypto_is_refused_488() {
    let stack = Box::pin(ringing_reliable_183()).await;
    let frag = format!(
        "SIP/2.0 200 OK\r\n\r\nm=audio 4000 RTP/SAVP 0\r\n{}",
        gcm(1, KEY_256).replace("a=crypto", "A=Crypto")
    );
    let prack = with_extra(
        &alice_request("PRACK", 315, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\n",
        Some(("message/sipfrag", &frag)),
    );
    let results = flatten(stack.process_message(&prack, alice(), None).await);
    assert_prack_refused(&results, "315 PRACK");
    let mikey = with_extra(
        &alice_request("PRACK", 316, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\n",
        Some(("text/plain", MIKEY)),
    );
    let results = flatten(stack.process_message(&mikey, alice(), None).await);
    assert_prack_refused(&results, "316 PRACK");
}

/// The callee's 2xx to a relayed PRACK with a gzip or a keyed non-SDP body
/// is refused like an SDP answer that may not cross: 488 to the PRACK, and
/// the early call ends (CANCEL callee, 488 on the caller's INVITE).
#[tokio::test]
async fn relayed_prack_response_with_unpoliced_body_is_refused() {
    for (extra, ct, body) in [
        (
            "Content-Encoding: gzip\r\n",
            "text/plain",
            "compressed".to_string(),
        ),
        ("", "message/sipfrag", gcm(1, KEY_256_B)),
    ] {
        let stack = Box::pin(ringing_reliable_183()).await;
        let prack = with_extra(
            &alice_request("PRACK", 315, Some("bobtag"), None),
            "RAck: 7 314 INVITE\r\n",
            None,
        );
        let results = flatten(stack.process_message(&prack, alice(), None).await);
        let (fwd, _) = forwarded(&results, &Method::Prack).expect("PRACK to the callee");
        let fwd = fwd.clone();
        let ok = with_extra(
            &response_to(&fwd, 200, None, None),
            extra,
            Some((ct, &body)),
        );
        let results = flatten(stack.process_message(&ok, bob(), None).await);
        assert!(responded(&results, 200).is_none(), "{ct}: {results:?}");
        assert!(
            forwarded(&results, &Method::Cancel).is_some(),
            "{ct}: {results:?}"
        );
        assert_no_inline_key(&results);
        let cseqs: Vec<_> = responses(&results, 488)
            .iter()
            .filter_map(|r| r.headers.cseq())
            .collect();
        assert!(cseqs.contains(&"315 PRACK"), "{ct}: {cseqs:?}");
        assert!(cseqs.contains(&"314 INVITE"), "{ct}: {cseqs:?}");
    }
}

/// The callee's 2xx carries the offer (the INVITE had none) and
/// the offer is refused. The ACK still carries an answer, declining every
/// stream (RFC 3264 §6), then the callee is BYEd and the caller gets 488.
#[tokio::test]
async fn refused_late_offer_2xx_is_acked_with_declined_answer() {
    // A delayed offer needs `media.srtp.required = false`.
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let placed = flatten(
        stack
            .process_message_on(
                &caller_request("INVITE", DIALED, "late@test", 1, None, None),
                alice(),
                None,
                AddrTransport::Tls,
            )
            .await,
    );
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    assert_eq!(inv.body.as_deref().unwrap_or_default(), b"");
    let late_offer = answer_body(&format!(
        "{}m=video 5002 RTP/SAVP 96\r\n{}",
        savp_audio(5000, &aes128(1)),
        aes128(2)
    ));
    let results = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(&late_offer)),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&results, 200).is_none(), "{results:?}");
    let (ack, _) = forwarded(&results, &Method::Ack).expect("ACK to the callee");
    let answer = body_of(ack);
    assert_eq!(
        ack.headers.get_value(&HeaderName::ContentType),
        Some("application/sdp")
    );
    assert!(answer.contains("m=audio 0 RTP/SAVP 0\r\n"), "{answer}");
    assert!(answer.contains("m=video 0 RTP/SAVP 96\r\n"), "{answer}");
    assert_eq!(answer.matches("m=").count(), 2, "{answer}");
    assert!(!answer.contains("crypto"), "{answer}");
    assert!(forwarded(&results, &Method::Bye).is_some(), "{results:?}");
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert_warning_is_fixed(r);
    assert_all_released(&stack).await;
}

/// On a late-offer call the callee's reliable 183 carries
/// the offer; the caller's PRACK carries the answer and is checked with
/// answer rules (exactly one crypto line), not stripped as an offer.
#[tokio::test]
async fn prack_answer_to_reliable_offer_uses_answer_rules() {
    // A delayed offer needs `media.srtp.required = false`.
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let invite = with_extra(
        &caller_request("INVITE", DIALED, "prack-ans@test", 1, None, None),
        "Supported: 100rel\r\n",
        None,
    );
    let placed = send(&stack, &invite, alice(), AddrTransport::Tls).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let early_offer = answer_body(&savp_audio(
        5000,
        &format!("{}{}", gcm(1, KEY_256_B), gcm(2, KEY_256_B)),
    ));
    let reliable = with_extra(
        &response_to(&inv, 183, Some("bobtag"), None),
        "Require: 100rel\r\nRSeq: 1\r\n",
        Some(("application/sdp", &early_offer)),
    );
    let results = send(&stack, &reliable, dest, AddrTransport::Tls).await;
    assert!(responded(&results, 183).is_some(), "{results:?}");
    // Two crypto lines in an answer (RFC 4568 §7.1.2): refused.
    let two_lines = offer(&savp_audio(
        4000,
        &format!("{}{}", gcm(1, KEY_256), gcm(2, KEY_256)),
    ));
    let prack = with_extra(
        &caller_request(
            "PRACK",
            DIALED,
            "prack-ans@test",
            2,
            Some("bobtag"),
            Some(&two_lines),
        ),
        "RAck: 1 1 INVITE\r\n",
        None,
    );
    let results = send(&stack, &prack, alice(), AddrTransport::Tls).await;
    assert!(
        forwarded(&results, &Method::Prack).is_none(),
        "answer with two crypto lines relayed: {results:?}"
    );
    let (r, _) = responded(&results, 488).expect("488 to the PRACK");
    assert_eq!(r.headers.cseq(), Some("2 PRACK"));
    // One compliant line crosses.
    let one_line = offer(&savp_audio(4000, &gcm(1, KEY_256)));
    let prack = with_extra(
        &caller_request(
            "PRACK",
            DIALED,
            "prack-ans@test",
            3,
            Some("bobtag"),
            Some(&one_line),
        ),
        "RAck: 1 1 INVITE\r\n",
        None,
    );
    let results = send(&stack, &prack, alice(), AddrTransport::Tls).await;
    let (fwd, _) = forwarded(&results, &Method::Prack).expect("PRACK to the callee");
    assert!(body_of(fwd).contains(KEY_256), "{}", body_of(fwd));
}

/// Mirror case: the TLS callee's re-INVITE offers SDES toward a caller on
/// UDP. Refused with 488 to the callee; nothing reaches the caller.
#[tokio::test]
async fn sdes_reinvite_from_tls_callee_to_udp_caller_is_refused_488() {
    let (stack, inv) = Box::pin(established_on(
        "mirror@test",
        AddrTransport::Udp,
        ["tls", "tls"],
        ALICE_SDP,
        BOB_SDP,
    ))
    .await;
    let sdes = answer_body(&savp_audio(5000, &gcm(1, KEY_256_B)));
    let results = send(
        &stack,
        &bob_request(&inv, "INVITE", 7, Some(&sdes)),
        t1(),
        AddrTransport::Tls,
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_no_inline_key(&results);
    let (r, d) = responded(&results, 488).expect("488 to the callee");
    assert_eq!(d, t1());
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_eq!(stack.call_count().await, 1, "the call stays up");
}

/// An UPDATE offer is policed like a re-INVITE: SDES from a UDP caller is
/// refused with 488; non-CNSA lines are stripped TLS to TLS.
#[tokio::test]
async fn update_sdp_body_is_policed() {
    let (stack, _inv) = Box::pin(established_on(
        "upd-udp@test",
        AddrTransport::Udp,
        ["tls", "tls"],
        ALICE_SDP,
        BOB_SDP,
    ))
    .await;
    let sdes = offer(&savp_audio(4000, &gcm(1, KEY_256)));
    let results = send(
        &stack,
        &caller_request(
            "UPDATE",
            DIALED,
            "upd-udp@test",
            2,
            Some("bobtag"),
            Some(&sdes),
        ),
        alice(),
        AddrTransport::Udp,
    )
    .await;
    assert!(
        forwarded(&results, &Method::Update).is_none(),
        "{results:?}"
    );
    assert!(responded(&results, 488).is_some(), "{results:?}");

    let sdes_answer = answer_body(&savp_audio(5000, &gcm(1, KEY_256_B)));
    let (stack, _inv) = Box::pin(established_on(
        "upd-tls@test",
        AddrTransport::Tls,
        ["tls", "tls"],
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
        &sdes_answer,
    ))
    .await;
    let mixed = offer(&savp_audio(
        4000,
        &format!("{}{}", aes128(1), gcm(2, KEY_256)),
    ));
    let results = send(
        &stack,
        &caller_request(
            "UPDATE",
            DIALED,
            "upd-tls@test",
            2,
            Some("bobtag"),
            Some(&mixed),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let (upd, _) = forwarded(&results, &Method::Update).expect("UPDATE to the callee");
    let body = body_of(upd);
    assert!(!body.contains(KEY_128), "{body}");
    assert!(body.contains(KEY_256), "{body}");
}

/// An in-dialog 2xx whose SDES answer may not cross: the answerer's 2xx is
/// ACKed, the originator gets 488, both legs get a BYE, and the call is
/// audited `PolicyTerminated`.
#[tokio::test]
async fn in_dialog_2xx_refusal_byes_both_legs() {
    let sdes_answer = answer_body(&savp_audio(5000, &gcm(1, KEY_256_B)));
    let (stack, _inv) = Box::pin(established_on(
        "reinv-ans@test",
        AddrTransport::Tls,
        ["tls", "tls"],
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
        &sdes_answer,
    ))
    .await;
    let results = send(
        &stack,
        &caller_request(
            "INVITE",
            DIALED,
            "reinv-ans@test",
            2,
            Some("bobtag"),
            Some(&offer(&savp_audio(4000, &gcm(1, KEY_256)))),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let (reinv, dest) = forwarded(&results, &Method::Invite).expect("re-INVITE to the callee");
    let reinv = reinv.clone();
    let capture = uc_audit::capture::start();
    let weak = answer_body(&savp_audio(5000, &aes128(1)));
    let results = send(
        &stack,
        &response_to(&reinv, 200, None, Some(&weak)),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&results, 200).is_none(), "{results:?}");
    assert_no_inline_key(&results);
    let (r, d) = responded(&results, 488).expect("488 to the originator");
    assert_eq!(d, alice());
    assert_eq!(r.headers.cseq(), Some("2 INVITE"));
    assert!(forwarded(&results, &Method::Ack).is_some(), "{results:?}");
    let byes = forwarded_all(&results, &Method::Bye);
    assert_eq!(byes.len(), 2, "BYE on both legs: {results:?}");
    let events = capture.events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::CallTerminated(t)
                if matches!(t.reason, uc_audit::event::TerminationReason::PolicyTerminated)
        )),
        "{events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::AuthorizationDecision(d)
                if d.policy == "media_security:no_acceptable_crypto_suite"
                    && !d.granted
                    && d.identity.contains(DIALED)
        )),
        "answerer is the identity: {events:?}"
    );
    assert_eq!(stack.call_count().await, 0);
}

/// The caller's UPDATE in the early dialog (after the callee's 180,
/// RFC 3311 §5.1) gets a 2xx whose SDP answer has no acceptable suite.
/// The INVITE is unanswered, so there is no confirmed dialog to BYE
/// (RFC 3261 §15): the UPDATE gets 488, the callee a CANCEL (RFC 3261 §9)
/// and the caller's INVITE 488.
#[tokio::test]
async fn early_dialog_update_answer_refusal_cancels_without_bye() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let call = "early-upd@test";
    let placed = place_on(
        &stack,
        call,
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let ringing = send(
        &stack,
        &response_to(&inv, 180, Some("bobtag"), None),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&ringing, 180).is_some(), "{ringing:?}");
    let results = send(
        &stack,
        &caller_request(
            "UPDATE",
            DIALED,
            call,
            2,
            Some("bobtag"),
            Some(&offer(&savp_audio(4000, &gcm(1, KEY_256)))),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let (upd, dest) = forwarded(&results, &Method::Update).expect("early UPDATE to the callee");
    let upd = upd.clone();
    let weak = answer_body(&savp_audio(5000, &aes128(1)));
    let results = send(
        &stack,
        &response_to(&upd, 200, None, Some(&weak)),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(forwarded(&results, &Method::Bye).is_none(), "{results:?}");
    assert!(
        forwarded(&results, &Method::Cancel).is_some(),
        "{results:?}"
    );
    assert_no_inline_key(&results);
    let refusals = responses(&results, 488);
    let cseqs: Vec<_> = refusals.iter().filter_map(|r| r.headers.cseq()).collect();
    assert!(cseqs.contains(&"2 UPDATE"), "{cseqs:?}");
    assert!(cseqs.contains(&"1 INVITE"), "{cseqs:?}");
    assert_all_released(&stack).await;
}

/// AU-3 / AU-12: an initial answer refusal ends the call with a CDR
/// `PolicyDenied`/488 released by the SBC and a `CallTerminated` audit
/// with `PolicyTerminated`.
#[tokio::test]
async fn refused_answer_writes_policy_denied_cdr_and_audit() {
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    let emitter = cdr_emitter();
    stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
        Arc::clone(&emitter),
        &sbc_config::schema::CdrConfig::default(),
    )));
    let placed = place_on(
        &stack,
        "cdr-ans@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let capture = uc_audit::capture::start();
    let results = send(
        &stack,
        &response_to(
            &inv,
            200,
            Some("bobtag"),
            Some(&answer_body(&savp_audio(5000, &aes128(1)))),
        ),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&results, 488).is_some(), "{results:?}");
    assert!(
        capture.events().iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::CallTerminated(t)
                if matches!(t.reason, uc_audit::event::TerminationReason::PolicyTerminated)
        )),
        "{:?}",
        capture.events()
    );
    let c = one_cdr(&emitter);
    assert_eq!(c.release_cause, uc_cdr::ReleaseCause::PolicyDenied);
    assert_eq!(c.release_side, uc_cdr::ReleaseSide::Sbc);
    assert_eq!(c.final_sip_status, 488);
    assert_eq!(c.disposition, uc_cdr::Disposition::Failed);
}

/// The initial INVITE refusal (SDES toward a UDP trunk) writes a
/// `PolicyDenied`/488 CDR too.
#[tokio::test]
async fn refused_offer_writes_policy_denied_cdr() {
    let mut stack = trunk_stack_protos(["udp", "udp"]).await;
    let emitter = cdr_emitter();
    stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
        Arc::clone(&emitter),
        &sbc_config::schema::CdrConfig::default(),
    )));
    let results = place_on(
        &stack,
        "cdr-off@test",
        AddrTransport::Tls,
        &offer(&savp_audio(4000, &gcm(1, KEY_256))),
    )
    .await;
    assert!(responded(&results, 488).is_some(), "{results:?}");
    let c = one_cdr(&emitter);
    assert_eq!(c.release_cause, uc_cdr::ReleaseCause::PolicyDenied);
    assert_eq!(c.final_sip_status, 488);
}

// ----------------------------------------------------------------------
// media.srtp.required (default true): no cleartext or unkeyed active
// stream crosses; DTLS fingerprints are sha-384 only.
//
// These cases use the stack's default policy, which enforces
// `media.srtp.required`. The fixtures here are local on purpose: they do
// not depend on ALICE_SDP / BOB_SDP, which move to DTLS-SRTP.
//
// RFC 3264 §6, §8; RFC 5763 §5; RFC 5764 §8; RFC 8122 §5; RFC 3261 §9,
// §13.2.2.4, §14.2, §15, §20.43. CNSA 2.0 (sha-384 fingerprints).
// NIST 800-53 Rev5: SC-8, SC-8(1), SC-13, CM-6, SC-24, AU-2, SI-10, SI-11.
// ----------------------------------------------------------------------

/// `<hash> <octets colon-separated upper-case hex octets>`, starting at
/// `seed`. Fixed patterns, not real certificate digests.
fn fingerprint(hash: &str, octets: usize, seed: u8) -> String {
    let hex: Vec<String> = (0..octets)
        .map(|i| {
            format!(
                "{:02X}",
                seed.wrapping_add(u8::try_from(i % 256).unwrap_or(0))
            )
        })
        .collect();
    format!("{hash} {}", hex.join(":"))
}

/// The callee's sha-384 fingerprint (48 octets).
fn fp_b() -> String {
    fingerprint("sha-384", 48, 0x40)
}

/// A cleartext audio m-line (`proto` is `RTP/AVP` or `RTP/AVPF`).
fn clear_audio(port: u16, proto: &str) -> String {
    format!("m=audio {port} {proto} 0\r\na=sendrecv\r\n")
}

/// A DTLS-SRTP audio m-line with each of `fps` as a media-level
/// `a=fingerprint` and the given `a=setup` role.
fn dtls_audio_fps(port: u16, setup: &str, fps: &[&str]) -> String {
    let mut s = format!("m=audio {port} UDP/TLS/RTP/SAVP 0\r\na=setup:{setup}\r\n");
    for fp in fps {
        s.push_str("a=fingerprint:");
        s.push_str(fp);
        s.push_str("\r\n");
    }
    s.push_str("a=sendrecv\r\n");
    s
}

/// The caller's compliant DTLS-SRTP offer (sha-384, `actpass`).
fn dtls_offer() -> String {
    offer(&dtls_audio_fps(4000, "actpass", &[FP_A]))
}

/// The callee's compliant DTLS-SRTP answer (sha-384, `active`).
fn dtls_answer() -> String {
    answer_body(&dtls_audio_fps(5000, "active", &[&fp_b()]))
}

/// The refusal of a cleartext or unkeyed stream: 488 with Warning 302.
fn assert_refused_302(results: &[ProcessResult]) {
    let (r, _) = responded(results, 488).expect("488");
    assert!(warning_of(r).starts_with("302 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
}

/// The refusal of a fingerprint: 488 with Warning 306.
fn assert_refused_306(results: &[ProcessResult]) {
    let (r, _) = responded(results, 488).expect("488");
    assert!(warning_of(r).starts_with("306 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
}

/// A refusal with Warning 399 (missing fingerprint, delayed offer, ...).
fn assert_refused_399(results: &[ProcessResult]) {
    let (r, _) = responded(results, 488).expect("488");
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    assert_warning_is_fixed(r);
}

/// A denied `media_security:<label>` decision for `action` was audited.
fn assert_denied(events: &[uc_audit::AuditEvent], label: &str, action: &str) {
    let policy = format!("media_security:{label}");
    assert!(
        events.iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::AuthorizationDecision(d)
                if d.policy == policy && !d.granted && d.action == action
        )),
        "no denied {policy} for {action}: {events:?}"
    );
}

/// Places a DTLS-SRTP call from a TLS caller to a TLS trunk (terminate
/// mode when `terminate`) and answers it with `status` and `answer`.
async fn dtls_call_answered(
    call_id: &str,
    terminate: bool,
    status: u16,
    answer: &str,
) -> (
    SipStack,
    Arc<RelayLog>,
    proto_sip::message::SipRequest,
    SbcSocketAddr,
    Vec<ProcessResult>,
) {
    let (mut stack, media) = media_trunk_stack(["tls", "tls"]).await;
    if terminate {
        stack.set_dtls_fingerprint_source(Arc::new(
            sbc_media_core::dtls_identity::DtlsFingerprintSource::from_static(FP_SBC.to_string()),
        ));
    }
    let placed = place_on(&stack, call_id, AddrTransport::Tls, &dtls_offer()).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let results = send(
        &stack,
        &response_to(&inv, status, Some("bobtag"), Some(answer)),
        dest,
        AddrTransport::Tls,
    )
    .await;
    (stack, media, inv, dest, results)
}

/// The refused initial 2xx: not relayed, ACK + BYE to the callee, no relay
/// started.
fn assert_initial_answer_torn_down(results: &[ProcessResult], media: &RelayLog) {
    assert!(
        responded(results, 200).is_none(),
        "2xx relayed to the caller: {results:?}"
    );
    assert!(
        forwarded(results, &Method::Ack).is_some(),
        "ACK to callee: {results:?}"
    );
    assert!(
        forwarded(results, &Method::Bye).is_some(),
        "BYE to callee: {results:?}"
    );
    assert_eq!(media.starts(), 0, "no relay started: {:?}", media.log);
}

/// Item 11. An RTP/AVP (or RTP/AVPF) offer is refused before routing: 488
/// with Warning 302, no B-leg INVITE, slots released, a `PolicyDenied`/488
/// CDR and a denied `media_security:cleartext_media` decision. The caller's
/// transport does not matter.
#[tokio::test]
async fn rtp_avp_offer_is_refused_488_when_required() {
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    let emitter = cdr_emitter();
    stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
        Arc::clone(&emitter),
        &sbc_config::schema::CdrConfig::default(),
    )));
    let capture = uc_audit::capture::start();
    let results = place_on(
        &stack,
        "req-avp@test",
        AddrTransport::Tls,
        &offer(&clear_audio(4000, "RTP/AVP")),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "no B-leg INVITE: {results:?}"
    );
    assert_refused_302(&results);
    assert_denied(&capture.events(), "cleartext_media", "INVITE");
    let c = one_cdr(&emitter);
    assert_eq!(c.release_cause, uc_cdr::ReleaseCause::PolicyDenied);
    assert_eq!(c.final_sip_status, 488);
    assert_all_released(&stack).await;

    for (i, (proto, transport)) in [
        ("RTP/AVPF", AddrTransport::Tls),
        ("RTP/AVP", AddrTransport::Udp),
        ("rtp/avp", AddrTransport::Udp),
    ]
    .into_iter()
    .enumerate()
    {
        let stack = trunk_stack_protos(["udp", "udp"]).await;
        let results = place_on(
            &stack,
            &format!("req-avp-{i}@test"),
            transport,
            &offer(&clear_audio(4000, proto)),
        )
        .await;
        assert!(
            forwarded_all(&results, &Method::Invite).is_empty(),
            "{proto} over {transport:?} relayed: {results:?}"
        );
        assert_refused_302(&results);
        assert_all_released(&stack).await;
    }
}

/// Item 12. The callee answers a DTLS-SRTP offer with RTP/AVP: no relay is
/// started, the callee gets ACK + BYE, the caller 488 (Warning 302).
#[tokio::test]
async fn rtp_avp_answer_to_dtls_offer_is_refused_when_required() {
    let capture = uc_audit::capture::start();
    let (stack, media, _inv, _dest, results) = Box::pin(dtls_call_answered(
        "req-avp-ans@test",
        false,
        200,
        &answer_body(&clear_audio(5000, "RTP/AVP")),
    ))
    .await;
    assert_initial_answer_torn_down(&results, &media);
    assert_refused_302(&results);
    assert_denied(&capture.events(), "cleartext_media", "answer");
    assert_all_released(&stack).await;
}

/// Dialog: the refused cleartext 2xx's retransmission is re-ACKed only
/// (no second BYE, no 2xx to the caller, no relay).
#[tokio::test]
async fn refused_cleartext_answer_retransmission_is_reacked_only() {
    let answer = answer_body(&clear_audio(5000, "RTP/AVP"));
    let (stack, media, inv, dest, results) =
        Box::pin(dtls_call_answered("req-rtx@test", false, 200, &answer)).await;
    assert_refused_302(&results);
    let again = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(&answer)),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(forwarded(&again, &Method::Ack).is_some(), "{again:?}");
    assert!(forwarded(&again, &Method::Bye).is_none(), "{again:?}");
    assert!(responded(&again, 200).is_none(), "{again:?}");
    assert_eq!(media.starts(), 0);
}

/// Item 13. Terminate mode: a callee answer without a fingerprint (DTLS
/// m-line, or RTP/AVP) is refused; the call is not relayed opaquely.
#[tokio::test]
async fn terminate_mode_callee_without_fingerprint_refuses_not_opaque() {
    for (i, (label, media_line, code)) in [
        (
            "dtls-no-fingerprint",
            "m=audio 5000 UDP/TLS/RTP/SAVP 0\r\na=setup:active\r\na=sendrecv\r\n".to_string(),
            "399 ",
        ),
        ("rtp-avp", clear_audio(5000, "RTP/AVP"), "302 "),
    ]
    .into_iter()
    .enumerate()
    {
        let (stack, media, _inv, _dest, results) = Box::pin(dtls_call_answered(
            &format!("term-nofp-{i}@test"),
            true,
            200,
            &answer_body(&media_line),
        ))
        .await;
        assert!(
            !media
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|l| l == "start opaque"),
            "{label}: relayed opaquely: {:?}",
            media.log
        );
        assert_initial_answer_torn_down(&results, &media);
        let (r, _) = responded(&results, 488).expect("488 to the caller");
        assert!(
            warning_of(r).starts_with(code),
            "{label}: {}",
            warning_of(r)
        );
        assert_all_released(&stack).await;
    }
}

/// Item 14. A DTLS offer whose only fingerprint is sha-256 is refused with
/// 488 (Warning 306), not forwarded; no fingerprint hex reaches the audit.
#[tokio::test]
async fn sha256_only_fingerprint_offer_is_refused() {
    Box::pin(assert_fingerprint_only_offer_refused("sha-256", 32)).await;
}

/// CNSA 2.0 allows SHA-512 as well as SHA-384: a sha-512-only DTLS offer
/// is relayed with its fingerprint, and a sha-512 callee answer completes
/// the call. sha-1 is refused like sha-256.
#[tokio::test]
async fn sha512_only_fingerprint_offer_is_accepted() {
    let fp = fingerprint("sha-512", 64, 0x10);
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let results = place_on(
        &stack,
        "sha-512-only@test",
        AddrTransport::Tls,
        &offer(&dtls_audio_fps(4000, "actpass", &[&fp])),
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    assert!(
        body_of(req).contains(&format!("a=fingerprint:{fp}")),
        "{}",
        body_of(req)
    );

    let answer = answer_body(&dtls_audio_fps(
        5000,
        "active",
        &[&fingerprint("sha-512", 64, 0x60)],
    ));
    let (_stack, media, _inv, _dest, results) =
        Box::pin(dtls_call_answered("sha-512-ans@test", false, 200, &answer)).await;
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert_eq!(media.starts(), 1);

    Box::pin(assert_fingerprint_only_offer_refused("sha-1", 20)).await;
}

async fn assert_fingerprint_only_offer_refused(hash: &str, octets: usize) {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let fp = fingerprint(hash, octets, 0x10);
    let capture = uc_audit::capture::start();
    let results = place_on(
        &stack,
        &format!("{hash}-only@test"),
        AddrTransport::Tls,
        &offer(&dtls_audio_fps(4000, "actpass", &[&fp])),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{hash}-only offer relayed: {results:?}"
    );
    assert_refused_306(&results);
    let dump = format!("{:?}", capture.events());
    let hex = fp.split_once(' ').map_or("", |(_, h)| h);
    assert!(!dump.contains(hex), "fingerprint in audit: {dump}");
    assert_all_released(&stack).await;
}

/// The fingerprint value must be 48 colon-separated hex octets: a sha-384
/// label on 32 octets, or non-hex octets, is refused (Warning 306).
#[tokio::test]
async fn sha384_fingerprint_with_malformed_value_is_refused() {
    let bad_hex = fingerprint("sha-384", 48, 0).replacen("00", "ZZ", 1);
    for (i, fp) in [fingerprint("sha-384", 32, 0), bad_hex].iter().enumerate() {
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let results = place_on(
            &stack,
            &format!("fp-bad-{i}@test"),
            AddrTransport::Tls,
            &offer(&dtls_audio_fps(4000, "actpass", &[fp])),
        )
        .await;
        assert!(
            forwarded_all(&results, &Method::Invite).is_empty(),
            "malformed fingerprint relayed: {results:?}"
        );
        assert_refused_306(&results);
        assert_all_released(&stack).await;
    }
}

/// A DTLS m-line with no fingerprint at all (none at session level either)
/// is refused in an offer. A missing attribute is Warning 399 (306 is for
/// an attribute the SBC does not accept).
#[tokio::test]
async fn dtls_offer_without_fingerprint_is_refused() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let results = place_on(
        &stack,
        "fp-none@test",
        AddrTransport::Tls,
        &offer(&dtls_audio_fps(4000, "actpass", &[])),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_399(&results);
    assert_all_released(&stack).await;
}

/// Item 15. On an established DTLS-SRTP call, an RTP/AVP re-INVITE is
/// refused with 488 (Warning 302) and not forwarded; the call stays up and
/// a later DTLS-SRTP re-INVITE relays.
#[tokio::test]
async fn rtp_avp_reinvite_on_srtp_call_is_refused_488_and_call_continues() {
    let call = "req-reinv@test";
    let (stack, _inv) = Box::pin(established_on(
        call,
        AddrTransport::Tls,
        ["tls", "tls"],
        &dtls_offer(),
        &dtls_answer(),
    ))
    .await;
    let capture = uc_audit::capture::start();
    let results = send(
        &stack,
        &caller_request(
            "INVITE",
            DIALED,
            call,
            2,
            Some("bobtag"),
            Some(&offer(&clear_audio(4000, "RTP/AVP"))),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "cleartext re-INVITE relayed: {results:?}"
    );
    let (r, d) = responded(&results, 488).expect("488 to the offerer");
    assert_eq!(d, alice());
    assert_eq!(r.headers.cseq(), Some("2 INVITE"));
    assert_refused_302(&results);
    assert_denied(&capture.events(), "cleartext_media", "INVITE");
    assert_eq!(stack.call_count().await, 1, "the call stays up");

    send(
        &stack,
        &caller_request("ACK", DIALED, call, 2, Some("bobtag"), None),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let results = send(
        &stack,
        &caller_request(
            "INVITE",
            DIALED,
            call,
            3,
            Some("bobtag"),
            Some(&dtls_offer()),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    assert!(
        forwarded(&results, &Method::Invite).is_some(),
        "later DTLS re-INVITE relays: {results:?}"
    );
}

/// Item 16. A cleartext UPDATE offer on a DTLS-SRTP call is refused with
/// 488 (Warning 302) and not forwarded; the call stays up.
#[tokio::test]
async fn cleartext_update_offer_is_refused_488() {
    let call = "req-upd@test";
    let (stack, _inv) = Box::pin(established_on(
        call,
        AddrTransport::Tls,
        ["tls", "tls"],
        &dtls_offer(),
        &dtls_answer(),
    ))
    .await;
    let results = send(
        &stack,
        &caller_request(
            "UPDATE",
            DIALED,
            call,
            2,
            Some("bobtag"),
            Some(&offer(&clear_audio(4000, "RTP/AVP"))),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    assert!(
        forwarded(&results, &Method::Update).is_none(),
        "cleartext UPDATE relayed: {results:?}"
    );
    let (r, _) = responded(&results, 488).expect("488 to the UPDATE");
    assert_eq!(r.headers.cseq(), Some("2 UPDATE"));
    assert_refused_302(&results);
    assert_eq!(stack.call_count().await, 1, "the call stays up");
}

/// The callee's cleartext re-INVITE toward the caller is refused the same
/// way (488 to the callee, nothing reaches the caller).
#[tokio::test]
async fn cleartext_reinvite_from_callee_is_refused_488() {
    let (stack, inv) = Box::pin(established_on(
        "req-reinv-b@test",
        AddrTransport::Tls,
        ["tls", "tls"],
        &dtls_offer(),
        &dtls_answer(),
    ))
    .await;
    let results = send(
        &stack,
        &bob_request(
            &inv,
            "INVITE",
            7,
            Some(&answer_body(&clear_audio(5000, "RTP/AVP"))),
        ),
        t1(),
        AddrTransport::Tls,
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    let (_, d) = responded(&results, 488).expect("488 to the callee");
    assert_eq!(d, t1());
    assert_refused_302(&results);
    assert_eq!(stack.call_count().await, 1);
}

/// Item 19. One cleartext active m-line refuses the whole offer: DTLS-SRTP
/// audio with RTP/AVP video, or with an `m=application` on plain UDP
/// (unsupported protocol), is refused with 488 (Warning 302).
#[tokio::test]
async fn cleartext_video_with_srtp_audio_refuses_whole_offer() {
    let audio = dtls_audio_fps(4000, "actpass", &[FP_A]);
    for (i, extra) in [
        "m=video 4002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
        "m=video 4002 RTP/AVPF 96\r\na=rtpmap:96 H264/90000\r\n",
        "m=application 4004 UDP 100\r\n",
    ]
    .into_iter()
    .enumerate()
    {
        let stack = trunk_stack_protos(["tls", "tls"]).await;
        let results = place_on(
            &stack,
            &format!("req-mix-{i}@test"),
            AddrTransport::Tls,
            &offer(&format!("{audio}{extra}")),
        )
        .await;
        assert!(
            forwarded_all(&results, &Method::Invite).is_empty(),
            "mixed offer relayed ({extra:?}): {results:?}"
        );
        assert_refused_302(&results);
        assert_all_released(&stack).await;
    }
}

/// Item 20. A 183 whose early answer is RTP/AVP: CANCEL to the callee, 488
/// (Warning 302) to the caller, the 183 is not relayed, no relay starts,
/// and the CDR is `PolicyDenied`.
#[tokio::test]
async fn rtp_avp_183_answer_cancels_b_and_488s_a() {
    let (mut stack, media) = media_trunk_stack(["tls", "tls"]).await;
    let emitter = cdr_emitter();
    stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
        Arc::clone(&emitter),
        &sbc_config::schema::CdrConfig::default(),
    )));
    let placed = place_on(&stack, "req-183@test", AddrTransport::Tls, &dtls_offer()).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let results = send(
        &stack,
        &response_to(
            &inv,
            183,
            Some("bobtag"),
            Some(&answer_body(&clear_audio(5000, "RTP/AVP"))),
        ),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(
        responded(&results, 183).is_none(),
        "183 relayed to the caller: {results:?}"
    );
    assert!(
        forwarded(&results, &Method::Cancel).is_some(),
        "CANCEL to callee: {results:?}"
    );
    assert_refused_302(&results);
    assert_eq!(media.starts(), 0);

    // Dialog race: the callee's 200 crosses the CANCEL. It is ACKed and
    // BYEd, never relayed, and no relay starts.
    let late = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(&dtls_answer())),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&late, 200).is_none(), "{late:?}");
    assert!(forwarded(&late, &Method::Ack).is_some(), "{late:?}");
    assert!(forwarded(&late, &Method::Bye).is_some(), "{late:?}");
    assert_eq!(media.starts(), 0);
    let c = one_cdr(&emitter);
    assert_eq!(c.release_cause, uc_cdr::ReleaseCause::PolicyDenied);
    assert_eq!(c.final_sip_status, 488);
    assert_all_released(&stack).await;
}

/// Item 21. A DTLS-SRTP re-INVITE answered with RTP/AVP: the answerer is
/// ACKed, the originator gets 488 (Warning 302), both legs get a BYE, the
/// call is audited `PolicyTerminated` with a denied `cleartext_media`
/// decision.
#[tokio::test]
async fn cleartext_reinvite_2xx_answer_tears_down_both_legs() {
    let call = "req-reinv-ans@test";
    let (stack, _inv) = Box::pin(established_on(
        call,
        AddrTransport::Tls,
        ["tls", "tls"],
        &dtls_offer(),
        &dtls_answer(),
    ))
    .await;
    let results = send(
        &stack,
        &caller_request(
            "INVITE",
            DIALED,
            call,
            2,
            Some("bobtag"),
            Some(&dtls_offer()),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let (reinv, dest) = forwarded(&results, &Method::Invite).expect("re-INVITE to the callee");
    let reinv = reinv.clone();
    let capture = uc_audit::capture::start();
    let results = send(
        &stack,
        &response_to(
            &reinv,
            200,
            None,
            Some(&answer_body(&clear_audio(5000, "RTP/AVP"))),
        ),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&results, 200).is_none(), "{results:?}");
    let (r, d) = responded(&results, 488).expect("488 to the originator");
    assert_eq!(d, alice());
    assert_eq!(r.headers.cseq(), Some("2 INVITE"));
    assert_refused_302(&results);
    assert!(forwarded(&results, &Method::Ack).is_some(), "{results:?}");
    assert_eq!(
        forwarded_all(&results, &Method::Bye).len(),
        2,
        "BYE on both legs: {results:?}"
    );
    let events = capture.events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::CallTerminated(t)
                if matches!(t.reason, uc_audit::event::TerminationReason::PolicyTerminated)
        )),
        "{events:?}"
    );
    assert_denied(&events, "cleartext_media", "answer");
    assert_eq!(stack.call_count().await, 0);
}

/// A PRACK carrying a cleartext offer on a ringing call is refused with
/// 488 (Warning 302) and not forwarded. The ringing call comes from the
/// shared 100rel helper, so this needs that helper's INVITE offer to pass
/// the policy (ALICE_SDP moved to DTLS-SRTP).
#[tokio::test]
async fn cleartext_prack_offer_is_refused_488() {
    let stack = Box::pin(ringing_reliable_183()).await;
    let prack = with_extra(
        &alice_request("PRACK", 315, Some("bobtag"), None),
        "RAck: 7 314 INVITE\r\n",
        Some(("application/sdp", &offer(&clear_audio(4000, "RTP/AVP")))),
    );
    let results = flatten(stack.process_message(&prack, alice(), None).await);
    assert!(
        forwarded(&results, &Method::Prack).is_none(),
        "cleartext PRACK offer relayed: {results:?}"
    );
    let (r, _) = responded(&results, 488).expect("488 to the PRACK");
    assert_eq!(r.headers.cseq(), Some("315 PRACK"));
    assert_refused_302(&results);
}

/// Item 23. sha-384 plus an extra sha-256 line: in an offer and in an
/// answer the sha-256 line is stripped and the sha-384 line crosses
/// (RFC 8122 §5 allows several; removing one cannot weaken the binding). A
/// sha-256-only answer is refused.
#[tokio::test]
async fn sha384_fingerprint_with_extra_sha256_line_is_stripped_in_offer_and_answer() {
    let sha256 = fingerprint("sha-256", 32, 0x80);
    let sha256_hex = sha256.split_once(' ').map_or("", |(_, h)| h).to_string();

    // Offer: media-level extra line stripped.
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let results = place_on(
        &stack,
        "fp-mixed-offer@test",
        AddrTransport::Tls,
        &offer(&dtls_audio_fps(4000, "actpass", &[FP_A, &sha256])),
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert!(
        !body.to_ascii_lowercase().contains("sha-256"),
        "sha-256 line crossed: {body}"
    );
    assert!(!body.contains(&sha256_hex), "{body}");
    assert_eq!(body.matches("a=fingerprint:").count(), 1, "{body}");
    assert!(body.contains(&format!("a=fingerprint:{FP_A}")), "{body}");

    // Offer: session-level extra line stripped too.
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let session_level = format!(
        "v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\n\
         a=fingerprint:{sha256}\r\n{}",
        dtls_audio_fps(4000, "actpass", &[FP_A])
    );
    let results = place_on(
        &stack,
        "fp-mixed-session@test",
        AddrTransport::Tls,
        &session_level,
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    let body = body_of(req);
    assert!(
        !body.contains(&sha256_hex),
        "session-level sha-256 crossed: {body}"
    );
    assert!(body.contains(&format!("a=fingerprint:{FP_A}")), "{body}");

    // Answer: the extra line is stripped from the 2xx the caller gets.
    let b = fp_b();
    let (_stack, media, _inv, _dest, results) = Box::pin(dtls_call_answered(
        "fp-mixed-ans-0@test",
        false,
        200,
        &answer_body(&dtls_audio_fps(5000, "active", &[&b, &sha256])),
    ))
    .await;
    let (ok, _) = responded(&results, 200).expect("2xx to the caller");
    let body = resp_body(ok);
    assert!(!body.contains(&sha256_hex), "sha-256 crossed: {body}");
    assert_eq!(body.matches("a=fingerprint:").count(), 1, "{body}");
    assert!(body.contains(&format!("a=fingerprint:{b}")), "{body}");
    assert_eq!(media.starts(), 1);

    // Answer: only sha-256 is refused.
    let (stack, media, _inv, _dest, results) = Box::pin(dtls_call_answered(
        "fp-mixed-ans-1@test",
        false,
        200,
        &answer_body(&dtls_audio_fps(5000, "active", &[&sha256])),
    ))
    .await;
    assert_initial_answer_torn_down(&results, &media);
    let (r, _) = responded(&results, 488).expect("sha-256 only: 488");
    assert!(warning_of(r).starts_with("306 "), "{}", warning_of(r));
    assert_all_released(&stack).await;
}

// Guards: these pass before and after the change.

/// A compliant DTLS-SRTP call (sha-384 both ways) is relayed and the relay
/// starts; upper-case hash names and a session-level fingerprint count.
#[tokio::test]
async fn dtls_srtp_sha384_call_is_relayed() {
    let (_stack, media, _inv, _dest, results) = Box::pin(dtls_call_answered(
        "dtls-ok@test",
        false,
        200,
        &dtls_answer(),
    ))
    .await;
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert_eq!(media.starts(), 1);

    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let upper = FP_A.replacen("sha-384", "SHA-384", 1);
    let results = place_on(
        &stack,
        "dtls-upper@test",
        AddrTransport::Tls,
        &offer(&dtls_audio_fps(4000, "actpass", &[&upper])),
    )
    .await;
    assert!(
        forwarded(&results, &Method::Invite).is_some(),
        "{results:?}"
    );

    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let session_level = format!(
        "v=0\r\no=- 1 1 IN IP4 192.168.1.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\n\
         a=fingerprint:{FP_A}\r\n{}",
        dtls_audio_fps(4000, "actpass", &[])
    );
    let results = place_on(
        &stack,
        "dtls-session@test",
        AddrTransport::Tls,
        &session_level,
    )
    .await;
    assert!(
        forwarded(&results, &Method::Invite).is_some(),
        "{results:?}"
    );
}

/// RFC 3264 §8: a declined (port 0) cleartext m-line next to DTLS-SRTP
/// audio is not checked; the offer crosses with both m-lines.
#[tokio::test]
async fn declined_cleartext_mline_next_to_dtls_audio_is_relayed() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let media = format!(
        "{}m=video 0 RTP/AVP 96\r\n",
        dtls_audio_fps(4000, "actpass", &[FP_A])
    );
    let results = place_on(
        &stack,
        "dtls-declined@test",
        AddrTransport::Tls,
        &offer(&media),
    )
    .await;
    let (req, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    assert_eq!(body_of(req).matches("m=").count(), 2, "{}", body_of(req));
}
// PENDING: not built. These cases need APIs that do not exist yet:
//
// - `SipStack::set_media_security_policy(&sbc_config::schema::SrtpConfig)`
//   (next to `set_t38_config`);
// - `SipStack::relay_plan(&MediaSecurityPolicy, has_dtls_identity,
//   caller_fingerprint: Option<&String>, caller_setup, answer_sdp: &str)
//   -> RelayPlan`, replacing `terminate_params`;
// - `enum RelayPlan { Terminate(LegDtlsParams, LegDtlsParams), Opaque,
//   Refuse(MediaPolicyViolation) }` in `sip_stack.rs`;
// - `MediaSecurityPolicy { mode, require_srtp }` and the
//   `CleartextMedia` / `FingerprintMissing` / `FingerprintHashNotAllowed`
//   variants in `proto_b2bua::media_policy`.
//
// Enable: append this file to `tests/media_security.rs` (it uses that
// file's helpers: `place_on`, `send`, `media_trunk_stack`, `dtls_offer`,
// `dtls_answer`, `dtls_audio_fps`, `clear_audio`, `fingerprint`, `fp_b`,
// `FP_A`, `FP_SBC`, ...) and delete it:
//
//   cat media_security_required.rs.pending >> media_security.rs
//   git rm media_security_required.rs.pending
//
// Adjust names here if the change chose different ones.
//
// NIST 800-53 Rev5: SC-8, SC-24, CM-6. RFC 5763 §5; RFC 5764 §8.

// ----------------------------------------------------------------------
// media.srtp.required = false, and the relay plan
// ----------------------------------------------------------------------

fn srtp_config(
    required: bool,
    mode: sbc_config::schema::SrtpMode,
) -> sbc_config::schema::SrtpConfig {
    sbc_config::schema::SrtpConfig {
        required,
        mode,
        ..sbc_config::schema::SrtpConfig::default()
    }
}

/// Item 17. The relay plan at 200-OK time, pure.
///
/// - Terminate with sha-384 fingerprints on both legs: `Terminate`, with
///   each leg's peer fingerprint and the SBC's DTLS role.
/// - Terminate, a leg without a (sha-384) fingerprint: `Refuse` when
///   required, else `Opaque` (logged).
/// - Passthrough, required, cleartext answer: `Refuse(CleartextMedia)`;
///   a keyed or all-declined answer: `Opaque`.
#[test]
fn relay_plan_refuses_unkeyed_leg_when_required() {
    use crate::sdp_dtls::SetupRole;
    use proto_b2bua::media_policy::{KeyingMode, MediaPolicyViolation, MediaSecurityPolicy};
    use sbc_media_core::dtls_sidecar::Role;

    let p = |mode, require_srtp| MediaSecurityPolicy { mode, require_srtp };
    let caller_fp = FP_A.to_string();
    let dtls = dtls_answer();
    let no_fp = answer_body("m=audio 5000 UDP/TLS/RTP/SAVP 0\r\na=setup:active\r\n");
    let sha256 = answer_body(&dtls_audio_fps(
        5000,
        "active",
        &[&fingerprint("sha-256", 32, 0x80)],
    ));
    let plain = answer_body(&clear_audio(5000, "RTP/AVP"));
    let sdes = answer_body(&savp_audio(5000, &gcm(1, KEY_256_B)));
    let declined = answer_body(&clear_audio(0, "RTP/AVP"));

    // Terminate, both sha-384.
    for required in [true, false] {
        match SipStack::relay_plan(
            &p(KeyingMode::Terminate, required),
            true,
            Some(&caller_fp),
            Some(SetupRole::ActPass),
            &dtls,
        ) {
            RelayPlan::Terminate(a, b) => {
                assert_eq!(a.peer_fingerprint, FP_A);
                assert!(matches!(a.role, Role::Server));
                assert_eq!(b.peer_fingerprint, fp_b());
                assert!(matches!(b.role, Role::Server));
            }
            other => panic!("required={required}: {other:?}"),
        }
    }

    // Terminate, a leg without a usable fingerprint.
    for (label, caller, answer) in [
        ("callee none", Some(&caller_fp), no_fp.as_str()),
        ("callee cleartext", Some(&caller_fp), plain.as_str()),
        ("caller none", None, dtls.as_str()),
    ] {
        let plan = SipStack::relay_plan(
            &p(KeyingMode::Terminate, true),
            true,
            caller,
            Some(SetupRole::ActPass),
            answer,
        );
        assert!(matches!(plan, RelayPlan::Refuse(_)), "{label}: {plan:?}");
        let plan = SipStack::relay_plan(
            &p(KeyingMode::Terminate, false),
            true,
            caller,
            Some(SetupRole::ActPass),
            answer,
        );
        assert!(
            matches!(plan, RelayPlan::Opaque),
            "{label} optional: {plan:?}"
        );
    }
    assert!(matches!(
        SipStack::relay_plan(
            &p(KeyingMode::Terminate, true),
            true,
            Some(&caller_fp),
            None,
            &no_fp,
        ),
        RelayPlan::Refuse(MediaPolicyViolation::FingerprintMissing { .. })
    ));
    // A sha-256 callee fingerprint is never terminated.
    for required in [true, false] {
        let plan = SipStack::relay_plan(
            &p(KeyingMode::Terminate, required),
            true,
            Some(&caller_fp),
            None,
            &sha256,
        );
        assert!(!matches!(plan, RelayPlan::Terminate(..)), "{plan:?}");
    }
    // A sha-256 caller fingerprint is never terminated either.
    let caller_sha256 = fingerprint("sha-256", 32, 0x80);
    let plan = SipStack::relay_plan(
        &p(KeyingMode::Terminate, true),
        true,
        Some(&caller_sha256),
        None,
        &dtls,
    );
    assert!(matches!(plan, RelayPlan::Refuse(_)), "{plan:?}");

    // Passthrough.
    assert!(matches!(
        SipStack::relay_plan(&p(KeyingMode::Passthrough, true), false, None, None, &plain),
        RelayPlan::Refuse(MediaPolicyViolation::CleartextMedia { .. })
    ));
    for (label, answer) in [("dtls", &dtls), ("sdes", &sdes), ("declined", &declined)] {
        let plan =
            SipStack::relay_plan(&p(KeyingMode::Passthrough, true), false, None, None, answer);
        assert!(matches!(plan, RelayPlan::Opaque), "{label}: {plan:?}");
    }
    assert!(matches!(
        SipStack::relay_plan(
            &p(KeyingMode::Passthrough, false),
            false,
            None,
            None,
            &plain
        ),
        RelayPlan::Opaque
    ));
}

/// Item 18. Guard: with `media.srtp.required = false` a cleartext call
/// works as before: the RTP/AVP offer routes (to a UDP trunk too), the
/// RTP/AVP answer is relayed and the opaque relay starts.
#[tokio::test]
async fn required_false_keeps_rtp_avp_working() {
    let (mut stack, media) = media_trunk_stack(["udp", "udp"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let placed = place_on(
        &stack,
        "opt-avp@test",
        AddrTransport::Tls,
        &offer(&clear_audio(4000, "RTP/AVP")),
    )
    .await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let results = send(
        &stack,
        &response_to(
            &inv,
            200,
            Some("bobtag"),
            Some(&answer_body(&clear_audio(5000, "RTP/AVP"))),
        ),
        dest,
        AddrTransport::Udp,
    )
    .await;
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert_eq!(media.starts(), 1);
    assert!(
        media
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l == "start opaque"),
        "{:?}",
        media.log
    );
}

/// With `required = false` the fingerprint rule still applies: a
/// sha-256-only DTLS offer is refused (Warning 306).
#[tokio::test]
async fn required_false_still_enforces_sha384_fingerprints() {
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let results = place_on(
        &stack,
        "opt-sha256@test",
        AddrTransport::Tls,
        &offer(&dtls_audio_fps(
            4000,
            "actpass",
            &[&fingerprint("sha-256", 32, 0x80)],
        )),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_306(&results);
    assert_all_released(&stack).await;
}

/// With `required = false` in terminate mode, a cleartext callee answer
/// falls back to the opaque relay (logged), as before.
#[tokio::test]
async fn required_false_terminate_cleartext_callee_relays_opaquely() {
    let (mut stack, media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_dtls_fingerprint_source(Arc::new(
        sbc_media_core::dtls_identity::DtlsFingerprintSource::from_static(FP_SBC.to_string()),
    ));
    stack.set_media_security_policy(&srtp_config(false, sbc_config::schema::SrtpMode::Terminate));
    let placed = place_on(&stack, "opt-term@test", AddrTransport::Tls, &dtls_offer()).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let results = send(
        &stack,
        &response_to(
            &inv,
            200,
            Some("bobtag"),
            Some(&answer_body(&clear_audio(5000, "RTP/AVP"))),
        ),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert!(
        media
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l == "start opaque"),
        "{:?}",
        media.log
    );
}

/// The setter can switch enforcement back on: `required = true` refuses
/// RTP/AVP again (the same stack as the default).
#[tokio::test]
async fn set_media_security_policy_required_true_refuses_rtp_avp() {
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    stack.set_media_security_policy(&srtp_config(
        true,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let results = place_on(
        &stack,
        "set-req@test",
        AddrTransport::Tls,
        &offer(&clear_audio(4000, "RTP/AVP")),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_302(&results);
}

/// T.38 with `required = true` and `allow_cleartext`: an image-only offer
/// (audio declined) still routes; the T.38 rules, not the SRTP rule,
/// govern `m=image`.
#[tokio::test]
async fn required_true_t38_image_offer_still_routes() {
    let (mut stack, _media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_t38_config(sbc_config::T38Config {
        enabled: true,
        allow_cleartext: true,
        ..sbc_config::T38Config::default()
    });
    stack.set_media_security_policy(&srtp_config(
        true,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let t38_offer = offer(
        "m=audio 0 RTP/AVP 0\r\nm=image 4100 udptl t38\r\na=T38FaxVersion:0\r\n\
         a=T38MaxBitRate:14400\r\na=T38FaxUdpEC:t38UDPRedundancy\r\n",
    );
    let placed = place_on(&stack, "req-t38@test", AddrTransport::Tls, &t38_offer).await;
    assert!(forwarded(&placed, &Method::Invite).is_some(), "{placed:?}");
}

// ----------------------------------------------------------------------
// Delayed offer, emergency calls, m=image, no-route, terminate identity
//
// RFC 3261 §13.2.1, §14.2, §20.43; RFC 3262 §5, §7.2; RFC 3264 §6;
// RFC 3362; 47 CFR 9.16. NIST 800-53 Rev5: SC-8, SC-24, CM-6, AU-2.
// ----------------------------------------------------------------------

/// Exactly one granted `media_security:<label>` decision for `action` was
/// audited.
fn assert_granted_once(events: &[uc_audit::AuditEvent], label: &str, action: &str) {
    let policy = format!("media_security:{label}");
    let n = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                uc_audit::AuditEvent::AuthorizationDecision(d)
                    if d.policy == policy && d.granted && d.action == action
            )
        })
        .count();
    assert_eq!(n, 1, "granted {policy} for {action}: {events:?}");
}

/// Under `media.srtp.required` an INVITE without SDP is refused before
/// routing: 488 with Warning 399 "Delayed offer not supported when SRTP is
/// required", no B-leg INVITE, a denied `media_security:delayed_offer`
/// decision, a `PolicyDenied`/488 CDR and every slot released. A body that
/// is neither `application/sdp` nor multipart is no offer either.
#[tokio::test]
async fn delayed_offer_is_refused_488_before_routing_when_required() {
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    let emitter = cdr_emitter();
    stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
        Arc::clone(&emitter),
        &sbc_config::schema::CdrConfig::default(),
    )));
    let capture = uc_audit::capture::start();
    let results = send(
        &stack,
        &caller_request("INVITE", DIALED, "delayed@test", 1, None, None),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "delayed offer routed: {results:?}"
    );
    assert_refused_399(&results);
    let (r, _) = responded(&results, 488).expect("488");
    assert!(
        warning_of(r).ends_with("\"Delayed offer not supported when SRTP is required\""),
        "{}",
        warning_of(r)
    );
    assert_denied(&capture.events(), "delayed_offer", "INVITE");
    let c = one_cdr(&emitter);
    assert_eq!(c.release_cause, uc_cdr::ReleaseCause::PolicyDenied);
    assert_eq!(c.final_sip_status, 488);
    assert_all_released(&stack).await;

    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let text = with_extra(
        &caller_request("INVITE", DIALED, "delayed-text@test", 1, None, None),
        "",
        Some(("text/plain", "m=audio 4000 RTP/AVP 0\r\n")),
    );
    let results = send(&stack, &text, alice(), AddrTransport::Tls).await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_399(&results);
    assert_all_released(&stack).await;
}

/// An emergency call (911) is exempt from `media.srtp.required` only: a
/// cleartext offer and a delayed offer are routed, each audited once as a
/// granted `media_security:emergency_cleartext` decision, and the cleartext
/// answer is relayed.
#[tokio::test]
async fn emergency_cleartext_invite_is_routed_and_audited() {
    let (stack, media) = media_trunk_stack(["udp", "udp"]).await;
    let capture = uc_audit::capture::start();
    let placed = send(
        &stack,
        &caller_request(
            "INVITE",
            "911",
            "e911-clear@test",
            1,
            None,
            Some(&offer(&clear_audio(4000, "RTP/AVP"))),
        ),
        alice(),
        AddrTransport::Udp,
    )
    .await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("emergency INVITE routed");
    assert!(body_of(inv).contains("RTP/AVP"), "{}", body_of(inv));
    assert_granted_once(&capture.events(), "emergency_cleartext", "INVITE");
    let inv = inv.clone();
    let results = send(
        &stack,
        &response_to(
            &inv,
            200,
            Some("bobtag"),
            Some(&answer_body(&clear_audio(5000, "RTP/AVP"))),
        ),
        dest,
        AddrTransport::Udp,
    )
    .await;
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert_eq!(media.starts(), 1);

    let stack = trunk_stack_protos(["udp", "udp"]).await;
    let capture = uc_audit::capture::start();
    let placed = send(
        &stack,
        &caller_request("INVITE", "911", "e911-delayed@test", 1, None, None),
        alice(),
        AddrTransport::Udp,
    )
    .await;
    assert!(
        forwarded(&placed, &Method::Invite).is_some(),
        "emergency delayed offer refused: {placed:?}"
    );
    assert_granted_once(&capture.events(), "emergency_cleartext", "INVITE");
}

/// The emergency exemption covers `media.srtp.required` only: SDES over a
/// UDP hop is still refused (Warning 399), and so is a sha-256-only DTLS
/// fingerprint (Warning 306). Neither is audited as an exemption.
#[tokio::test]
async fn emergency_sdes_over_udp_and_bad_fingerprint_still_refused() {
    for (i, (body, code)) in [
        (offer(&savp_audio(4000, &gcm(1, KEY_256))), "399 "),
        (
            offer(&dtls_audio_fps(
                4000,
                "actpass",
                &[&fingerprint("sha-256", 32, 0x80)],
            )),
            "306 ",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let stack = trunk_stack_protos(["udp", "udp"]).await;
        let capture = uc_audit::capture::start();
        let results = send(
            &stack,
            &caller_request(
                "INVITE",
                "911",
                &format!("e911-refused-{i}@test"),
                1,
                None,
                Some(&body),
            ),
            alice(),
            AddrTransport::Udp,
        )
        .await;
        assert!(
            forwarded_all(&results, &Method::Invite).is_empty(),
            "case {i} relayed: {results:?}"
        );
        let (r, _) = responded(&results, 488).expect("488");
        assert!(
            warning_of(r).starts_with(code),
            "case {i}: {}",
            warning_of(r)
        );
        assert_no_inline_key(&results);
        assert!(
            !capture.events().iter().any(|e| matches!(
                e,
                uc_audit::AuditEvent::AuthorizationDecision(d)
                    if d.policy == "media_security:emergency_cleartext"
            )),
            "case {i}: exemption audited for a refused call"
        );
        assert_all_released(&stack).await;
    }
}

/// Only `m=image ... udptl` is exempt from `media.srtp.required`: an
/// `m=image` line with an RTP profile is checked like any m-line, with
/// T.38 disabled (the default) too.
#[tokio::test]
async fn image_offer_with_rtp_profile_is_checked_as_cleartext() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let capture = uc_audit::capture::start();
    let results = place_on(
        &stack,
        "image-rtp-offer@test",
        AddrTransport::Tls,
        &offer(&format!(
            "{}m=image 4100 RTP/AVP 0\r\n",
            dtls_audio_fps(4000, "actpass", &[FP_A])
        )),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_302(&results);
    assert_denied(&capture.events(), "cleartext_media", "INVITE");
    assert_all_released(&stack).await;
}

/// The callee's 2xx to an audio offer puts an active `m=image` where the
/// offer had audio: `udptl` the T.38 rules do not accept (T.38 disabled)
/// and an RTP profile are both refused before the relay starts.
#[tokio::test]
async fn image_answer_to_audio_offer_is_refused() {
    for (i, (answer, code)) in [
        (
            "m=image 5000 udptl t38\r\na=T38FaxVersion:0\r\na=T38FaxUdpEC:t38UDPRedundancy\r\n",
            "302 ",
        ),
        ("m=image 5000 RTP/AVP 0\r\n", "302 "),
    ]
    .into_iter()
    .enumerate()
    {
        let (stack, media, _inv, _dest, results) = Box::pin(dtls_call_answered(
            &format!("image-ans-{i}@test"),
            false,
            200,
            &answer_body(answer),
        ))
        .await;
        assert_initial_answer_torn_down(&results, &media);
        let (r, _) = responded(&results, 488).expect("488 to the caller");
        assert!(
            warning_of(r).starts_with(code),
            "case {i}: {}",
            warning_of(r)
        );
        assert_all_released(&stack).await;
    }

    // `media.srtp.required = false` does not let it through either.
    let (mut stack, media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let placed = place_on(
        &stack,
        "image-ans-opt@test",
        AddrTransport::Tls,
        &dtls_offer(),
    )
    .await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let results = send(
        &stack,
        &response_to(
            &inv,
            200,
            Some("bobtag"),
            Some(&answer_body("m=image 5000 RTP/AVP 0\r\n")),
        ),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert_initial_answer_torn_down(&results, &media);
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert!(warning_of(r).starts_with("302 "), "{}", warning_of(r));
}

/// Under `media.srtp.required` a call nothing routes is answered 480, not
/// with the announcement (which answers in cleartext RTP/AVP).
#[tokio::test]
async fn no_route_with_required_srtp_is_480_not_announcement() {
    let stack = SipStack::new(SipStackConfig::default());
    stack
        .register_inbound_trunk("test-trunk", None, &[("127.0.0.1".to_string(), 5060)])
        .await;
    let invite = format!(
        "INVITE sip:bob@nonexistent.invalid SIP/2.0\r\n\
         Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bK-noroute\r\n\
         From: <sip:alice@example.com>;tag=nr1\r\n\
         To: <sip:bob@nonexistent.invalid>\r\n\
         Call-ID: noroute-srtp@test\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@client.example.com:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        dtls_offer().len(),
        dtls_offer()
    );
    let source = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
    let results = send(&stack, &Bytes::from(invite), source, AddrTransport::Udp).await;
    assert!(
        responded(&results, 200).is_none(),
        "announcement played: {results:?}"
    );
    let (r, _) = responded(&results, 480).expect("480");
    assert_eq!(r.body.as_deref().unwrap_or_default(), b"", "no SDP answer");
}

/// `media.srtp.mode = Terminate` with no DTLS identity attached (the
/// remote media plane reported none): new calls are refused before routing
/// (488, Warning 399, `dtls_termination_unavailable`), not relayed
/// opaquely. Once the identity is attached the same offer routes.
#[tokio::test]
async fn terminate_mode_without_identity_refuses_new_calls() {
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(true, sbc_config::schema::SrtpMode::Terminate));
    let capture = uc_audit::capture::start();
    for i in 0..2 {
        let results = place_on(
            &stack,
            &format!("term-noid-{i}@test"),
            AddrTransport::Tls,
            &dtls_offer(),
        )
        .await;
        assert!(
            forwarded_all(&results, &Method::Invite).is_empty(),
            "{results:?}"
        );
        assert_refused_399(&results);
    }
    assert_denied(&capture.events(), "dtls_termination_unavailable", "INVITE");
    assert_all_released(&stack).await;

    stack.set_dtls_fingerprint_source(Arc::new(
        sbc_media_core::dtls_identity::DtlsFingerprintSource::from_static(FP_SBC.to_string()),
    ));
    let results = place_on(&stack, "term-id@test", AddrTransport::Tls, &dtls_offer()).await;
    assert!(
        forwarded(&results, &Method::Invite).is_some(),
        "{results:?}"
    );
}

/// `media.srtp.required = false`, delayed offer: the callee's reliable 183
/// carries an offer the policy refuses. It is PRACKed with an answer
/// declining every stream before the CANCEL (RFC 3262 §5), and the caller
/// gets 488.
#[tokio::test]
async fn refused_reliable_183_offer_is_pracked_with_declined_answer() {
    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let invite = with_extra(
        &caller_request("INVITE", DIALED, "prack-decline@test", 1, None, None),
        "Supported: 100rel\r\n",
        None,
    );
    let placed = send(&stack, &invite, alice(), AddrTransport::Tls).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let reliable = with_extra(
        &response_to(&inv, 183, Some("bobtag"), None),
        "Require: 100rel\r\nRSeq: 4\r\n",
        Some((
            "application/sdp",
            &answer_body(&savp_audio(5000, &aes128(1))),
        )),
    );
    let results = send(&stack, &reliable, dest, AddrTransport::Tls).await;
    assert!(responded(&results, 183).is_none(), "{results:?}");
    let order: Vec<&Method> = results
        .iter()
        .filter_map(|r| match r {
            ProcessResult::Forward {
                message: SipMessage::Request(req),
                ..
            } => Some(&req.method),
            _ => None,
        })
        .collect();
    assert_eq!(order, vec![&Method::Prack, &Method::Cancel], "{results:?}");
    let (prack, _) = forwarded(&results, &Method::Prack).expect("PRACK");
    assert_eq!(ext_header_value(&prack.headers, "RAck"), Some("4 1 INVITE"));
    assert!(
        prack
            .headers
            .get_value(&HeaderName::To)
            .is_some_and(|t| t.contains("tag=bobtag")),
        "{prack:?}"
    );
    assert!(prack.headers.get_value(&HeaderName::Contact).is_none());
    let answer = body_of(prack);
    assert!(answer.contains("m=audio 0 RTP/SAVP 0\r\n"), "{answer}");
    assert!(!answer.contains("crypto"), "{answer}");
    assert_no_inline_key(&results);
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert_warning_is_fixed(r);
    assert_all_released(&stack).await;

    // RFC 3261 §12.2.1.1: the PRACK's CSeq was reserved, so the BYE for a
    // 2xx that crosses the CANCEL in the same dialog takes a higher one.
    let prack_cseq = prack.headers.cseq_parsed().expect("PRACK CSeq").sequence;
    let crossed = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), None),
        dest,
        AddrTransport::Tls,
    )
    .await;
    let (bye, _) = forwarded(&crossed, &Method::Bye).expect("BYE for the crossing 2xx");
    let bye_cseq = bye.headers.cseq_parsed().expect("BYE CSeq").sequence;
    assert!(
        bye_cseq > prack_cseq,
        "BYE {bye_cseq} <= PRACK {prack_cseq}"
    );
}

/// The relay plan is decided before the A-leg 2xx exists: terminate mode,
/// an INVITE whose multipart body has an SDP part without media (so no
/// caller fingerprint), and a DTLS answer. The plan would start no relay, so the
/// 2xx is refused like any insecure answer: ACK + BYE to the callee, 488 to
/// the caller, `PolicyTerminated`, and the caller never sees a 2xx.
#[tokio::test]
async fn relay_plan_refusal_is_decided_before_the_2xx() {
    let (mut stack, media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_dtls_fingerprint_source(Arc::new(
        sbc_media_core::dtls_identity::DtlsFingerprintSource::from_static(FP_SBC.to_string()),
    ));
    let invite = with_extra(
        &caller_request("INVITE", DIALED, "plan-refuse@test", 1, None, None),
        "",
        Some((
            "multipart/mixed;boundary=b1",
            &format!(
                "--b1\r\nContent-Type: application/sdp\r\n\r\n{}--b1--\r\n",
                offer("")
            ),
        )),
    );
    let placed = send(&stack, &invite, alice(), AddrTransport::Tls).await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("B-leg INVITE");
    let inv = inv.clone();
    let capture = uc_audit::capture::start();
    let results = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(&dtls_answer())),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert_initial_answer_torn_down(&results, &media);
    let (r, _) = responded(&results, 488).expect("488 to the caller");
    assert!(warning_of(r).starts_with("399 "), "{}", warning_of(r));
    let events = capture.events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::CallTerminated(t)
                if matches!(t.reason, uc_audit::event::TerminationReason::PolicyTerminated)
        )),
        "{events:?}"
    );
    assert_denied(&events, "fingerprint_missing", "answer");
    assert_all_released(&stack).await;
}

/// The pre-routing check polices `application/sdp` bodies only; a
/// multipart INVITE body is policed whole once routed, so a cleartext SDP
/// part is still refused (488, Warning 302) with every slot released.
#[tokio::test]
async fn multipart_cleartext_offer_is_refused_after_routing() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let sdp = offer(&clear_audio(4000, "RTP/AVP"));
    let multipart = format!(
        "--b1\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n--b1\r\n\
         Content-Type: text/plain\r\n\r\nhello\r\n--b1--\r\n"
    );
    let invite = with_extra(
        &caller_request("INVITE", DIALED, "multipart-clear@test", 1, None, None),
        "",
        Some(("multipart/mixed;boundary=b1", &multipart)),
    );
    let results = send(&stack, &invite, alice(), AddrTransport::Tls).await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_302(&results);
    assert_all_released(&stack).await;
}

/// `media.srtp.mode = Terminate` with no DTLS identity: an emergency call
/// is not refused but relayed opaquely (the caller's fingerprint reaches
/// the callee, the relay starts opaque), audited once as a granted
/// `media_security:emergency_cleartext` decision. Other calls on the same
/// stack are still refused (`dtls_termination_unavailable`).
#[tokio::test]
async fn emergency_call_is_relayed_opaquely_when_termination_unavailable() {
    let (mut stack, media) = media_trunk_stack(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(true, sbc_config::schema::SrtpMode::Terminate));
    let capture = uc_audit::capture::start();
    let placed = send(
        &stack,
        &caller_request(
            "INVITE",
            "911",
            "e911-noid@test",
            1,
            None,
            Some(&dtls_offer()),
        ),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let (inv, dest) = forwarded(&placed, &Method::Invite).expect("emergency INVITE routed");
    assert!(body_of(inv).contains(FP_A), "{}", body_of(inv));
    assert!(!body_of(inv).contains(FP_SBC), "{}", body_of(inv));
    let events = capture.events();
    assert_granted_once(&events, "emergency_cleartext", "INVITE");
    assert!(
        !events.iter().any(|e| matches!(
            e,
            uc_audit::AuditEvent::AuthorizationDecision(d)
                if d.policy == "media_security:dtls_termination_unavailable"
        )),
        "{events:?}"
    );
    let inv = inv.clone();
    let results = send(
        &stack,
        &response_to(&inv, 200, Some("bobtag"), Some(&dtls_answer())),
        dest,
        AddrTransport::Tls,
    )
    .await;
    assert!(responded(&results, 200).is_some(), "{results:?}");
    assert_eq!(media.starts(), 1);
    assert!(
        media
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l == "start opaque"),
        "relay not opaque"
    );

    let results = place_on(
        &stack,
        "noid-normal@test",
        AddrTransport::Tls,
        &dtls_offer(),
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_399(&results);
}

/// Under `media.srtp.required` a multipart INVITE body without an SDP part
/// is no offer: refused before routing like an INVITE without a body
/// (`delayed_offer`). An emergency call with the same body is routed and
/// audited once; with `required = false` the call routes too. Either way
/// the body is not relayed, so it never reaches the callee labelled
/// `application/sdp`.
#[tokio::test]
async fn multipart_without_sdp_part_is_a_delayed_offer() {
    let text_only = |call_id: &str, dialed: &str| {
        with_extra(
            &caller_request("INVITE", dialed, call_id, 1, None, None),
            "",
            Some((
                "multipart/mixed;boundary=b1",
                "--b1\r\nContent-Type: text/plain\r\n\r\nm=audio 4000 RTP/AVP 0\r\n--b1--\r\n",
            )),
        )
    };
    let assert_bodyless = |inv: &proto_sip::message::SipRequest| {
        assert!(
            inv.body.as_deref().unwrap_or_default().is_empty(),
            "{inv:?}"
        );
        assert!(
            inv.headers.get_value(&HeaderName::ContentType).is_none(),
            "{inv:?}"
        );
    };

    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let capture = uc_audit::capture::start();
    let results = send(
        &stack,
        &text_only("mp-nosdp@test", DIALED),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    assert!(
        forwarded_all(&results, &Method::Invite).is_empty(),
        "{results:?}"
    );
    assert_refused_399(&results);
    assert_denied(&capture.events(), "delayed_offer", "INVITE");
    assert_all_released(&stack).await;

    let capture = uc_audit::capture::start();
    let results = send(
        &stack,
        &text_only("mp-nosdp-e911@test", "911"),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let (inv, _) = forwarded(&results, &Method::Invite).expect("emergency INVITE routed");
    assert_bodyless(inv);
    assert_granted_once(&capture.events(), "emergency_cleartext", "INVITE");

    let mut stack = trunk_stack_protos(["tls", "tls"]).await;
    stack.set_media_security_policy(&srtp_config(
        false,
        sbc_config::schema::SrtpMode::Passthrough,
    ));
    let results = send(
        &stack,
        &text_only("mp-nosdp-opt@test", DIALED),
        alice(),
        AddrTransport::Tls,
    )
    .await;
    let (inv, _) = forwarded(&results, &Method::Invite).expect("B-leg INVITE");
    assert_bodyless(inv);
}

/// The emergency exemption is audited once the call is routed: a
/// multipart offer whose SDP part is cleartext is policed after routing,
/// and the emergency call gets exactly one granted record.
#[tokio::test]
async fn emergency_multipart_cleartext_offer_is_audited_once() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
    let sdp = offer(&clear_audio(4000, "RTP/AVP"));
    let multipart = format!(
        "--b1\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n--b1\r\n\
         Content-Type: text/plain\r\n\r\nhello\r\n--b1--\r\n"
    );
    let invite = with_extra(
        &caller_request("INVITE", "911", "e911-mp@test", 1, None, None),
        "",
        Some(("multipart/mixed;boundary=b1", &multipart)),
    );
    let capture = uc_audit::capture::start();
    let results = send(&stack, &invite, alice(), AddrTransport::Tls).await;
    assert!(
        forwarded(&results, &Method::Invite).is_some(),
        "{results:?}"
    );
    assert_granted_once(&capture.events(), "emergency_cleartext", "INVITE");
}
