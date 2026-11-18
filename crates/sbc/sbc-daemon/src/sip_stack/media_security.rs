//! Call-leg SDP media security for the SIP stack: the glue between
//! [`proto_b2bua::media_policy`] and the SIP outcome of a refusal.
//!
//! Every SDP body that crosses the B2BUA (initial INVITE offer, 183/200
//! answer, re-INVITE/UPDATE offer and answer, PRACK and other relayed
//! bodies) goes through [`apply_media_security`] with the signalling
//! transport of the two hops it crosses. Only `TransportType::Tls` counts as
//! confidential (RFC 4568 §8.3).
//!
//! Refusal by message:
//!
//! - an offer (initial or in-dialog): 488 + `Warning` to the offerer, not
//!   forwarded; an in-dialog refusal keeps the session as it was (RFC 3261
//!   §14.2);
//! - a 183 answer: CANCEL to the callee, 488 to the caller (RFC 3261 §9);
//! - an initial 2xx answer: ACK + BYE to the callee, 488 to the caller, who
//!   never sees the 2xx, and no relay is started (RFC 3261 §13.2.2.4, §15).
//!   When that 2xx carried an offer (the INVITE had none), the ACK carries
//!   an answer that declines every stream (RFC 3264 §6);
//! - an in-dialog 2xx answer: the dialog is committed, so the answerer is
//!   ACKed, the originator gets 488 and both legs get a BYE. In an early
//!   dialog (UPDATE before the 2xx, RFC 3311) there is nothing to BYE: the
//!   UPDATE gets 488, the callee a CANCEL and the caller's INVITE 488.
//!
//! The SIP stack does not walk MIME parts on in-dialog bodies it relays
//! opaquely: a `multipart/*` body with an SDP part is refused
//! (`sdp_in_multipart`), and so is a body with a non-identity
//! `Content-Encoding` or a non-SDP body that mentions `a=crypto` or
//! `a=key-mgmt` (`unpoliced_body`). INVITE, re-INVITE, UPDATE, 18x and 2xx bodies are
//! policed whole, whatever their `Content-Type`.
//!
//! Each refusal is audited as a denied `AuthorizationDecision` with policy
//! `media_security:<label>`. No log line, audit record or `Warning` carries
//! SDP content, key material or fingerprints (SI-11).
//!
//! ## NIST 800-53 Rev5: SC-8, SC-12, SC-13, SC-24, CM-6, AU-2, SI-10, SI-11
//!
//! ## RFC 4568 §8; RFC 3261 §9, §13.2.2.4, §14.2, §15, §20.43; RFC 3264 §6
// POAM: POA&M-347 - refusals are audited per message, not aggregated per
// source and reason; no `sbc_media_security_*` counters are exported, and
// an offer the policy rewrote is visible only in a debug log line.

use super::{
    CallAddresses, PendingReinvite, PendingRelay, ProcessResult, ReleasedCalls, SipStack, audit,
    audit_call_terminated, build_a_leg_response, build_b_leg_cancel, create_response_from_request,
    extract_param, lock_leaf,
};
use crate::flow::Flow;
use proto_b2bua::CallId;
use proto_b2bua::media_policy::{
    KeyingMode, LegContext, LegKeying, MediaPolicyViolation, MediaSecurityPolicy, SdpRole, Secured,
    apply_media_security,
};
use proto_sip::message::{SipRequest, SipResponse};
use proto_sip::{HeaderName, Headers, Method, SipMessage, StatusCode};
use std::borrow::Cow;
use tracing::{debug, warn};
use uc_types::address::{SbcSocketAddr, TransportType as AddrTransport};

/// Signalling confidentiality of the hop an SDP arrives on (`from`) and
/// the hop it is sent on (`to`). Only TLS counts (RFC 4568 §8.3).
// WSS is not offered (`wss_listen` is rejected at config load), so WS/WSS
// legs count as not confidential. `WebSocketSecure` may only be admitted
// here once the SBC itself terminates that leg's TLS.
pub(super) fn legs(from: AddrTransport, to: AddrTransport) -> LegContext {
    LegContext {
        from_confidential: from == AddrTransport::Tls,
        to_confidential: to == AddrTransport::Tls,
    }
}

/// The hops an SDP from one leg of `addrs` to the other crosses.
pub(super) fn legs_for(addrs: &CallAddresses, from_a_leg: bool) -> LegContext {
    let (a, b) = (addrs.a_leg_flow.transport, addrs.b_leg_flow.transport);
    if from_a_leg { legs(a, b) } else { legs(b, a) }
}

/// RFC 3261 §20.43 `Warning` value: fixed code and text, the SBC's host.
pub(super) fn warning(violation: MediaPolicyViolation, host: &str) -> String {
    format!(
        "{} {host} \"{}\"",
        violation.warning_code(),
        violation.warning_text()
    )
}

/// The `AuthorizationDecision` policy label of a refusal.
pub(super) fn policy_label(violation: MediaPolicyViolation) -> String {
    format!("media_security:{}", violation.as_str())
}

/// Checks `body` (SDP) against the media security policy. A body that is
/// not UTF-8 is malformed (SI-10). A rewrite is logged at debug level with
/// counts only (no SDP content, SI-11).
///
/// ## NIST 800-53 Rev5: SC-8, SC-12, SC-13, CM-6
pub(super) fn check<'b>(
    body: &'b [u8],
    role: SdpRole,
    policy: &MediaSecurityPolicy,
    legs: &LegContext,
) -> Result<Secured<'b>, MediaPolicyViolation> {
    let sdp = std::str::from_utf8(body).map_err(|_| MediaPolicyViolation::MalformedSdp)?;
    let secured = apply_media_security(sdp, role, policy, legs)?;
    if matches!(secured.sdp, Cow::Owned(_)) {
        debug!(
            ?role,
            stripped_crypto = secured.stripped_crypto,
            stripped_key_mgmt = secured.stripped_key_mgmt,
            "SDP keying lines stripped by media security policy"
        );
    }
    Ok(secured)
}

/// Whether a relayed body is `multipart/*` with an SDP part, or with a
/// nested multipart that could hide one. Parts are not walked: any mention
/// of either media type in the body counts (fail closed, SI-10).
pub(super) fn multipart_carries_sdp(content_type: &str, body: &[u8]) -> bool {
    let is_multipart = content_type
        .trim_start()
        .get(..10)
        .is_some_and(|t| t.eq_ignore_ascii_case("multipart/"));
    let mentions = |needle: &[u8]| {
        body.windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    };
    is_multipart && (mentions(b"application/sdp") || mentions(b"multipart/"))
}

/// Whether every `Content-Encoding` coding on the message is `identity`
/// (RFC 3261 §20.12; case-insensitive). No header is identity.
fn content_encoding_is_identity(headers: &Headers) -> bool {
    headers.get_all(&HeaderName::ContentEncoding).all(|h| {
        h.value
            .split(',')
            .map(str::trim)
            .all(|c| c.is_empty() || c.eq_ignore_ascii_case("identity"))
    })
}

/// Why a relayed in-dialog body (PRACK, INFO, MESSAGE, NOTIFY and their
/// responses) may not cross unwalked, or `None`. An `application/sdp` body
/// is policed by the caller; this only covers what that check cannot see:
///
/// - a non-identity `Content-Encoding` (gzip and the like) hides the
///   content, whatever its type;
/// - a `multipart/*` body with an SDP part ([`multipart_carries_sdp`]);
/// - any other body that mentions `a=crypto` or `a=key-mgmt` (ASCII
///   case-insensitive), whatever its `Content-Type`.
///
/// ## NIST 800-53 Rev5: SC-8, SC-12, SI-10
///
/// ## RFC 4568 §8; RFC 4567 §3; RFC 3261 §20.12
pub(super) fn unpoliced_body_violation(
    headers: &Headers,
    content_type: &str,
    body: &[u8],
) -> Option<MediaPolicyViolation> {
    if !content_encoding_is_identity(headers) {
        return Some(MediaPolicyViolation::UnpolicedBody);
    }
    if super::is_sdp_content_type(content_type) {
        return None;
    }
    if multipart_carries_sdp(content_type, body) {
        return Some(MediaPolicyViolation::SdpInMultipart);
    }
    let mentions = |needle: &[u8]| {
        body.windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    };
    (mentions(b"a=crypto") || mentions(b"a=key-mgmt"))
        .then_some(MediaPolicyViolation::UnpolicedBody)
}

/// The role of a callee's SDP in a 18x/2xx to the initial INVITE: an
/// answer, or an offer when the INVITE carried none (RFC 3264 §5).
pub(super) fn initial_response_role(addrs: &CallAddresses) -> SdpRole {
    if addrs.b_leg_last_sdp.as_ref().is_some_and(|b| !b.is_empty()) {
        SdpRole::Answer
    } else {
        SdpRole::Offer
    }
}

/// The role of an SDP body in a relayed in-dialog request. A PRACK before
/// the call is answered, on a call whose INVITE carried no offer, answers
/// the offer in the reliable 1xx (RFC 3262 §5); every other body is an
/// offer.
pub(super) fn relayed_request_role(method: &Method, addrs: &CallAddresses) -> SdpRole {
    if *method == Method::Prack
        && !addrs.b_leg_answered
        && initial_response_role(addrs) == SdpRole::Offer
    {
        SdpRole::Answer
    } else {
        SdpRole::Offer
    }
}

/// The `AuthorizationDecision` identity (the answerer) and resource (the
/// other party) for a refused answer.
fn answer_parties(addrs: &CallAddresses, answerer_is_b_leg: bool) -> (String, String) {
    let to_uri = super::extract_uri_from_header(&addrs.b_leg_to);
    let from_uri = super::extract_uri_from_header(&addrs.a_leg_from);
    if answerer_is_b_leg {
        (to_uri, from_uri)
    } else {
        (from_uri, to_uri)
    }
}

/// 488 + `Warning` for a refused offer, to the offerer (RFC 3261 §14.2,
/// §20.43).
pub(super) fn offer_refusal(
    req: &SipRequest,
    source: SbcSocketAddr,
    violation: MediaPolicyViolation,
    host: &str,
) -> ProcessResult {
    let mut r = create_response_from_request(req, StatusCode::NOT_ACCEPTABLE_HERE);
    r.headers.set(HeaderName::Warning, warning(violation, host));
    ProcessResult::Response {
        message: SipMessage::Response(r),
        destination: source,
        flow: Flow::Reply,
    }
}

/// Denied `AuthorizationDecision` for a refused body. `action` is the SIP
/// method, or `answer` for a response.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, AU-12
fn audit_refusal(
    identity: &str,
    resource: &str,
    action: &str,
    source_ip: std::net::IpAddr,
    violation: MediaPolicyViolation,
) {
    audit(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            identity: identity.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            granted: false,
            policy: policy_label(violation),
            source_ip: Some(source_ip),
        },
    ));
}

impl ReleasedCalls {
    /// Records that `to_tag` of a released call's 2xx already got the SBC's
    /// BYE, so a retransmission of that 2xx is re-ACKed only.
    fn note_byed(&mut self, call_id: &str, to_tag: &str) {
        if let Some(e) = self.by_call_id.get_mut(call_id)
            && !e.answered_tags.iter().any(|t| t == to_tag)
            && e.answered_tags.len() < super::RELEASED_CALL_MAX_TAGS
        {
            e.answered_tags.push(to_tag.to_string());
        }
    }
}

impl SipStack {
    /// The configured keying mode: terminate when the SBC holds a DTLS
    /// identity (`media.srtp.mode = terminate`), else passthrough.
    pub(super) fn media_security_policy(&self) -> MediaSecurityPolicy {
        MediaSecurityPolicy {
            mode: if self.dtls_fingerprint_source.is_some() {
                KeyingMode::Terminate
            } else {
                KeyingMode::Passthrough
            },
        }
    }

    /// Checks the callee's SDP in a 18x/2xx to the initial INVITE, from the
    /// B-leg to the A-leg. Returns the body to relay when the policy
    /// rewrote it (`None`: relay as received).
    pub(super) fn secure_initial_response(
        &self,
        body: &[u8],
        addrs: &CallAddresses,
    ) -> Result<Option<String>, MediaPolicyViolation> {
        let secured = check(
            body,
            initial_response_role(addrs),
            &self.media_security_policy(),
            &legs_for(addrs, false),
        )?;
        Ok(match secured.sdp {
            Cow::Owned(s) => Some(s),
            Cow::Borrowed(_) => None,
        })
    }

    /// Checks an in-dialog offer (re-INVITE, UPDATE) from one leg to the
    /// other; only acceptable keying crosses. Returns the body to forward.
    pub(super) fn secure_in_dialog_offer<'b>(
        &self,
        body: &'b [u8],
        addrs: &CallAddresses,
        from_a_leg: bool,
    ) -> Result<Cow<'b, str>, MediaPolicyViolation> {
        self.secure_in_dialog_body(body, addrs, from_a_leg, SdpRole::Offer)
    }

    /// Checks an in-dialog request body from one leg to the other: an
    /// offer (re-INVITE, UPDATE, most PRACKs) or, for `role` Answer, a
    /// PRACK's answer to a reliable 1xx offer. Returns the body to forward.
    pub(super) fn secure_in_dialog_body<'b>(
        &self,
        body: &'b [u8],
        addrs: &CallAddresses,
        from_a_leg: bool,
        role: SdpRole,
    ) -> Result<Cow<'b, str>, MediaPolicyViolation> {
        check(
            body,
            role,
            &self.media_security_policy(),
            &legs_for(addrs, from_a_leg),
        )
        .map(|s| s.sdp)
    }

    /// Checks the far leg's SDP answer to a relayed in-dialog request whose
    /// originator is the A-leg when `originator_from_a_leg`. Returns the
    /// body to relay.
    pub(super) fn secure_relayed_answer<'b>(
        &self,
        body: &'b [u8],
        addrs: &CallAddresses,
        originator_from_a_leg: bool,
    ) -> Result<Cow<'b, str>, MediaPolicyViolation> {
        check(
            body,
            SdpRole::Answer,
            &self.media_security_policy(),
            &legs_for(addrs, !originator_from_a_leg),
        )
        .map(|s| s.sdp)
    }

    /// Checks the initial INVITE's offer toward the routed B-leg (`legs`).
    /// Returns the body to forward when the policy rewrote it (`None`:
    /// forward as received) and whether an SDES key crosses. The T.38
    /// classification's copy of the offer gets the same rewrite.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, SC-13, CM-6
    pub(super) fn secure_initial_offer(
        &self,
        body: Option<&[u8]>,
        legs: &LegContext,
        t38: Option<&mut crate::t38::Classified>,
    ) -> Result<(Option<String>, bool), MediaPolicyViolation> {
        let Some(body) = body.filter(|b| !b.is_empty()) else {
            return Ok((None, false));
        };
        let policy = self.media_security_policy();
        let secured = check(body, SdpRole::Offer, &policy, legs)?;
        let sdes_crossed = secured.keying == LegKeying::Sdes;
        if let Some(c) = t38 {
            let rewritten = match apply_media_security(&c.sdp, SdpRole::Offer, &policy, legs)?.sdp {
                Cow::Owned(s) => Some(s),
                Cow::Borrowed(_) => None,
            };
            if let Some(s) = rewritten {
                c.sdp = s;
            }
        }
        let rewritten = match secured.sdp {
            Cow::Owned(s) => Some(s),
            Cow::Borrowed(_) => None,
        };
        Ok((rewritten, sdes_crossed))
    }

    /// Refuses an in-dialog offer (re-INVITE, UPDATE, PRACK or another
    /// relayed body) with 488; the session stays as it was (RFC 3261
    /// §14.2).
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, AU-2
    pub(super) fn refuse_insecure_in_dialog_offer(
        &self,
        req: &SipRequest,
        source: SbcSocketAddr,
        addrs: &CallAddresses,
        from_a_leg: bool,
        violation: MediaPolicyViolation,
    ) -> ProcessResult {
        warn!(
            method = %req.method,
            call_id = %addrs.a_leg_sip_call_id,
            reason = violation.as_str(),
            "In-dialog SDP offer refused by media security policy, 488"
        );
        let identity = req
            .headers
            .get_value(&HeaderName::From)
            .map_or_else(|| source.to_string(), super::extract_uri_from_header);
        audit_refusal(
            &identity,
            &req.uri.to_string(),
            req.method.as_str(),
            source.ip(),
            violation,
        );
        offer_refusal(req, source, violation, addrs.leg_sent_by(!from_a_leg))
    }

    /// The callee's 2xx to the initial INVITE carries SDP that may not
    /// cross: the 2xx is not relayed and no relay is started. The callee's
    /// dialog is confirmed with an ACK and ended with a BYE (RFC 3261
    /// §13.2.2.4, §15); the caller, who never sees a 2xx, gets 488 with a
    /// `Warning`. A retransmission of the refused 2xx is re-ACKed only.
    /// When the 2xx carried an offer, the ACK carries the answer it needs
    /// (RFC 3264 §5): every stream declined.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, SC-24, AU-2
    pub(super) async fn refuse_insecure_answer(
        &self,
        resp: &SipResponse,
        internal_id: &CallId,
        addrs: &CallAddresses,
        violation: MediaPolicyViolation,
    ) -> ProcessResult {
        let mut a_response = build_a_leg_response(StatusCode::NOT_ACCEPTABLE_HERE, addrs);
        a_response.headers.set(
            HeaderName::Warning,
            warning(violation, addrs.leg_sent_by(false)),
        );
        let mut ack = Self::initial_invite_ack(resp, addrs);
        if initial_response_role(addrs) == SdpRole::Offer {
            attach_declined_answer(&mut ack, resp, addrs);
        }
        let bye = self.reserved_leg_bye(internal_id, addrs, true).await;
        self.fail_call_record(internal_id).await;
        self.cleanup_terminated_call(internal_id, false, crate::cdr::CdrEnd::media_security())
            .await;
        // This to-tag already got our BYE: a retransmitted 2xx gets an ACK
        // only (RFC 3261 §13.2.2.4).
        if let Some(tag) = resp
            .headers
            .get_value(&HeaderName::To)
            .and_then(|t| extract_param(t, "tag"))
        {
            lock_leaf(&self.released_invites).note_byed(&addrs.b_leg_sip_call_id, tag);
        }
        warn!(
            call_id = %addrs.a_leg_sip_call_id,
            reason = violation.as_str(),
            "Callee answer refused by media security policy; ACK + BYE callee, 488 caller"
        );
        let (identity, resource) = answer_parties(addrs, true);
        audit_refusal(
            &identity,
            &resource,
            "answer",
            addrs.b_leg_destination.ip(),
            violation,
        );
        audit_call_terminated(addrs, uc_audit::event::TerminationReason::PolicyTerminated);
        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(a_response),
                destination: addrs.a_leg_source,
                flow: addrs.a_leg_flow.clone().into(),
            },
            ProcessResult::Forward {
                message: SipMessage::Request(ack),
                destination: addrs.b_leg_destination,
                flow: addrs.b_leg_flow.clone().into(),
            },
            ProcessResult::Forward {
                message: SipMessage::Request(bye),
                destination: addrs.b_leg_destination,
                flow: addrs.b_leg_flow.clone().into(),
            },
        ])
    }

    /// The callee's 18x carries SDP that may not cross, before any final
    /// response: CANCEL toward the callee (RFC 3261 §9) and 488 with a
    /// `Warning` on the caller's INVITE. The early answer is not relayed.
    /// A 2xx that crosses the CANCEL is ACKed and BYEd by the released-call
    /// path.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, SC-24, AU-2
    pub(super) async fn refuse_insecure_early_answer(
        &self,
        internal_id: &CallId,
        addrs: &CallAddresses,
        violation: MediaPolicyViolation,
    ) -> ProcessResult {
        self.end_early_dialog(internal_id, addrs, violation, true)
            .await
    }

    /// CANCEL toward the callee and 488 on the caller's INVITE for an
    /// answer refused before the call is answered; the refusal is audited
    /// against the answering leg (`answerer_is_b_leg`).
    async fn end_early_dialog(
        &self,
        internal_id: &CallId,
        addrs: &CallAddresses,
        violation: MediaPolicyViolation,
        answerer_is_b_leg: bool,
    ) -> ProcessResult {
        let mut a_response = build_a_leg_response(StatusCode::NOT_ACCEPTABLE_HERE, addrs);
        a_response.headers.set(
            HeaderName::Warning,
            warning(violation, addrs.leg_sent_by(false)),
        );
        let cancel = build_b_leg_cancel(addrs);
        self.fail_call_record(internal_id).await;
        self.cleanup_terminated_call(internal_id, false, crate::cdr::CdrEnd::media_security())
            .await;
        warn!(
            call_id = %addrs.a_leg_sip_call_id,
            reason = violation.as_str(),
            "Early answer refused by media security policy; CANCEL callee, 488 caller"
        );
        let (identity, resource) = answer_parties(addrs, answerer_is_b_leg);
        audit_refusal(
            &identity,
            &resource,
            "answer",
            addrs.leg_target(answerer_is_b_leg).0.ip(),
            violation,
        );
        audit_call_terminated(addrs, uc_audit::event::TerminationReason::PolicyTerminated);
        ProcessResult::Multiple(vec![
            ProcessResult::Response {
                message: SipMessage::Response(a_response),
                destination: addrs.a_leg_source,
                flow: addrs.a_leg_flow.clone().into(),
            },
            ProcessResult::Forward {
                message: SipMessage::Request(cancel),
                destination: addrs.b_leg_destination,
                flow: addrs.b_leg_flow.clone().into(),
            },
        ])
    }

    /// A relayed re-INVITE/UPDATE got a 2xx whose SDP may not cross. The
    /// answerer's dialog is committed: its re-INVITE 2xx is ACKed, the
    /// originator gets 488 with a `Warning`, and the call is torn down
    /// with a BYE on both legs (`PolicyTerminated`). Before the call is
    /// answered (an UPDATE in the early dialog, RFC 3311 §5.1) no BYE is
    /// allowed: the UPDATE gets 488, the callee a CANCEL and the caller's
    /// INVITE 488 (RFC 3261 §9, §15).
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, SC-24, AU-2
    pub(super) async fn refuse_insecure_in_dialog_answer(
        &self,
        internal_id: &CallId,
        addrs: &CallAddresses,
        pending: &PendingReinvite,
        violation: MediaPolicyViolation,
    ) -> ProcessResult {
        let (mut refused, orig_dest) =
            Self::build_reinvite_response(StatusCode::NOT_ACCEPTABLE_HERE, pending, addrs);
        refused.headers.set(
            HeaderName::Warning,
            warning(violation, addrs.leg_sent_by(!pending.from_a_leg)),
        );
        let mut out = vec![ProcessResult::Response {
            message: SipMessage::Response(refused),
            destination: orig_dest,
            flow: addrs.leg_flow(!pending.from_a_leg).into(),
        }];
        if !addrs.b_leg_answered {
            out.push(
                self.end_early_dialog(internal_id, addrs, violation, pending.from_a_leg)
                    .await,
            );
            return ProcessResult::Multiple(out);
        }
        // POAM: POA&M-350 - the call is released right after this ACK, so a
        // retransmission of the refused re-INVITE 2xx (our ACK lost) finds
        // no call and is not re-ACKed; the far end's BYE handling ends it.
        if pending.method == Method::Invite {
            let ack = Self::build_leg_in_dialog_request(
                addrs,
                pending.from_a_leg,
                &Method::Ack,
                pending.fwd_cseq,
                None,
            );
            let (dest, flow) = addrs.leg_target(pending.from_a_leg);
            out.push(ProcessResult::Forward {
                message: SipMessage::Request(ack),
                destination: dest,
                flow: flow.into(),
            });
        }
        let (answerer, _) = addrs.leg_target(pending.from_a_leg);
        let (identity, resource) = answer_parties(addrs, pending.from_a_leg);
        audit_refusal(&identity, &resource, "answer", answerer.ip(), violation);
        let (byes, snapshot) = self
            .terminate_call(
                &internal_id.to_string(),
                crate::cdr::CdrEnd::media_security(),
                uc_audit::event::TerminationReason::PolicyTerminated,
                "in-dialog answer refused by media security policy",
                true,
            )
            .await;
        out.extend(byes);
        if let Some(snapshot) = snapshot {
            for r in &mut out {
                self.apply_egress_topology(r, None, std::slice::from_ref(&snapshot))
                    .await;
            }
        }
        ProcessResult::Multiple(out)
    }

    /// The far leg's response to a relayed in-dialog request (PRACK and
    /// the like) carries SDP that may not cross. The originator gets 488
    /// with a `Warning` instead, and the call ends: BYE on both legs once
    /// answered, else CANCEL toward the callee and 488 on the caller's
    /// INVITE.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-12, SC-24, AU-2
    pub(super) async fn refuse_insecure_relayed_answer(
        &self,
        internal_id: &CallId,
        addrs: &CallAddresses,
        pending: &PendingRelay,
        violation: MediaPolicyViolation,
    ) -> ProcessResult {
        let (mut refused, orig_dest) = Self::originator_response(
            StatusCode::NOT_ACCEPTABLE_HERE,
            pending.from_a_leg,
            &pending.orig_via,
            &pending.orig_from,
            &pending.orig_to,
            &pending.orig_cseq,
            addrs,
        );
        refused.headers.set(
            HeaderName::Warning,
            warning(violation, addrs.leg_sent_by(!pending.from_a_leg)),
        );
        let mut out = vec![ProcessResult::Response {
            message: SipMessage::Response(refused),
            destination: orig_dest,
            flow: addrs.leg_flow(!pending.from_a_leg).into(),
        }];
        if addrs.b_leg_answered {
            let (answerer, _) = addrs.leg_target(pending.from_a_leg);
            let (identity, resource) = answer_parties(addrs, pending.from_a_leg);
            audit_refusal(&identity, &resource, "answer", answerer.ip(), violation);
            let (byes, snapshot) = self
                .terminate_call(
                    &internal_id.to_string(),
                    crate::cdr::CdrEnd::media_security(),
                    uc_audit::event::TerminationReason::PolicyTerminated,
                    "relayed answer refused by media security policy",
                    true,
                )
                .await;
            out.extend(byes);
            if let Some(snapshot) = snapshot {
                for r in &mut out {
                    self.apply_egress_topology(r, None, std::slice::from_ref(&snapshot))
                        .await;
                }
            }
        } else {
            out.push(
                self.end_early_dialog(internal_id, addrs, violation, pending.from_a_leg)
                    .await,
            );
        }
        ProcessResult::Multiple(out)
    }

    /// Marks the B2BUA call failed with 488 before its state is removed.
    async fn fail_call_record(&self, internal_id: &CallId) {
        let mut calls = self.calls.write().await;
        if let Some(call) = calls.get_mut(internal_id) {
            let status = StatusCode::NOT_ACCEPTABLE_HERE;
            call.fail(status.code(), status.reason_phrase());
        }
    }
}

/// Puts on `ack` an answer that declines every stream of the offer in the
/// refused 2xx (RFC 3264 §6), with the SBC's B-leg media address. Nothing
/// from the offer but plain m-line tokens is echoed; when the offer cannot
/// be read the ACK goes without a body, and the BYE still ends the dialog.
fn attach_declined_answer(ack: &mut SipRequest, resp: &SipResponse, addrs: &CallAddresses) {
    let answer = resp
        .body
        .as_deref()
        .and_then(|b| std::str::from_utf8(b).ok())
        .zip(addrs.media_b_leg_ip.parse::<std::net::IpAddr>().ok())
        .and_then(|(offer, ip)| proto_b2bua::media_policy::declined_answer(offer, ip));
    if let Some(answer) = answer {
        ack.headers.set(HeaderName::ContentType, "application/sdp");
        ack.headers
            .set(HeaderName::ContentLength, answer.len().to_string());
        ack.body = Some(bytes::Bytes::from(answer));
    }
}
