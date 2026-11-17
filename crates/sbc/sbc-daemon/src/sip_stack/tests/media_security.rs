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
    let stack = trunk_stack_protos(["udp", "udp"]).await;
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

/// RTP/AVP handling is unchanged by the SDES rules: a cleartext offer from
/// a TLS caller still routes to a UDP trunk.
#[tokio::test]
async fn rtp_avp_offer_tls_to_udp_still_relays() {
    let stack = trunk_stack_protos(["udp", "udp"]).await;
    let results = place_on(&stack, "avp@test", AddrTransport::Tls, ALICE_SDP).await;
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

/// SEC-01: on a direct T.38 call (image-only offer) the callee's answer
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

/// SEC-02: a PRACK whose body is multipart with an SDP part is refused
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

/// RFC-01: the callee's 2xx carries the offer (the INVITE had none) and
/// the offer is refused. The ACK still carries an answer, declining every
/// stream (RFC 3264 §6), then the callee is BYEd and the caller gets 488.
#[tokio::test]
async fn refused_late_offer_2xx_is_acked_with_declined_answer() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
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

/// RFC-03 / SEC-05: on a late-offer call the callee's reliable 183 carries
/// the offer; the caller's PRACK carries the answer and is checked with
/// answer rules (exactly one crypto line), not stripped as an offer.
#[tokio::test]
async fn prack_answer_to_reliable_offer_uses_answer_rules() {
    let stack = trunk_stack_protos(["tls", "tls"]).await;
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

/// RFC-02: an UPDATE in the early dialog whose 2xx answer may not cross.
/// No BYE (the dialog is not confirmed): 488 to the UPDATE, CANCEL to the
/// callee and 488 on the caller's INVITE.
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
