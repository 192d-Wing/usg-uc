//! Media-security gate helpers for the call manager (fail-closed SRTP).
//!
//! On a TLS account every stream is signalled as `UDP/TLS/RTP/SAVPF`, so
//! audio may start only with DTLS-SRTP keys. These helpers run the cheap
//! SDP preflight (transport protocol, fingerprint, setup role) and map the
//! negotiated keys into the audio pipeline's key type.
//!
//! Failure causes are fixed strings: peer-supplied text is never reflected
//! into SIP headers, events or logs.
//!
//! ## NIST 800-53 Rev5 Controls
//! - **SC-8 / SC-8(1)**: no plaintext media on a DTLS-SRTP stream
//! - **SC-23**: fingerprint and setup role bound to the signalled session.
//!   The fingerprints accepted here are the only ones the call's DTLS
//!   association verifies the peer's certificate against (RFC 5763 §5,
//!   RFC 8122 §5);
//!   a mismatch, like every other handshake failure, ends the call.
//! - **SI-10**: SDP preflight validation
//!
//! ## RFC Compliance
//! - RFC 5764 §4.1: media on a DTLS-SRTP stream MUST be SRTP.
//! - RFC 3264 §5.1 / §6: m= proto mismatch is rejected (488 for offers).
//! - RFC 5763 §5: answerer SHOULD be active; `actpass` in an answer is an
//!   error.

use client_audio::{SrtpProfile, SrtpSessionKeys};
use client_sip_ua::sdp_dtls::{self, DtlsSdpParams, Setup};
use client_sip_ua::{DtlsRole, DtlsSrtpProfile, NegotiatedSrtpKeys, SecurityCause};

/// `Warning` header value on a 488 for a media-security failure
/// (RFC 3261 §20.43; warn-agent is a fixed pseudonym, text is fixed).
pub const WARNING_SRTP_REQUIRED: &str = "399 usg-client \"SRTP/DTLS required\"";

/// Which side of the offer/answer exchange the remote SDP is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSdp {
    /// The remote SDP is an offer; we answer it.
    Offer,
    /// The remote SDP answers our `actpass` offer.
    Answer,
}

/// DTLS parameters accepted by the preflight.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// Remote fingerprints and setup.
    pub params: DtlsSdpParams,
    /// Our DTLS role (RFC 5763 §5).
    pub role: DtlsRole,
    /// Our `a=setup` value when answering (`None` for a remote answer).
    pub local_setup: Option<Setup>,
    /// Remote signalled `a=rtcp-mux` (always true: the preflight requires it).
    pub rtcp_mux: bool,
}

/// Checks the remote SDP of a TLS-account call before any DTLS work.
///
/// # Errors
/// A fixed, non-reflective cause string on any failure.
pub fn preflight(sdp: Option<&str>, remote: RemoteSdp) -> Result<Preflight, &'static str> {
    // POAM: POA&M-329 -- delayed-offer (no SDP) INVITE rejected with 488 on
    // DTLS-SRTP accounts; offer-in-200/answer-in-ACK not implemented
    let sdp = sdp
        .filter(|s| !s.trim().is_empty())
        .ok_or("no SDP from remote")?;
    // RFC 3264 §5.1 / §6: a zero port disables a stream, so the audio
    // stream we negotiate is the first *active* one.
    let idx = sdp_dtls::first_active_audio_index(sdp).ok_or("no active audio media section")?;
    // NIST 800-53 Rev5: SC-8(1) -- every active m= section, not just the
    // first audio one, must be DTLS-SRTP (RFC 5764 §4.1).
    if !sdp_dtls::media_is_dtls_srtp(sdp, idx) || !sdp_dtls::all_active_media_dtls_srtp(sdp) {
        return Err("remote media is not UDP/TLS/RTP/SAVP(F)");
    }
    // RFC 5761 §5.1.1 / RFC 5764 §5.1.2: RTCP is secured only over the
    // RTP DTLS association; with no RTCP association, rtcp-mux is required.
    // Design note: there is no separate DTLS association for RTCP, by
    // design. RTCP is carried as SRTCP on the RTP association, so a
    // stream without rtcp-mux is refused.
    if !sdp_dtls::media_has_rtcp_mux(sdp, idx) {
        return Err("remote media lacks a=rtcp-mux");
    }
    let params = sdp_dtls::parse_dtls_params(sdp, idx)
        .map_err(|_| "missing or invalid a=fingerprint/a=setup")?;
    let (role, local_setup) = match remote {
        RemoteSdp::Offer => {
            let local = params
                .setup
                .answer_to_offer()
                .map_err(|_| "unusable a=setup in offer")?;
            let role = local
                .local_role()
                .map_err(|_| "unusable a=setup in offer")?;
            (role, Some(local))
        }
        RemoteSdp::Answer => (
            Setup::role_from_answer(params.setup).map_err(|_| "invalid a=setup in answer")?,
            None,
        ),
    };
    Ok(Preflight {
        rtcp_mux: sdp_dtls::media_has_rtcp_mux(sdp, idx),
        params,
        role,
        local_setup,
    })
}

/// Whether any active `m=` section of `sdp` uses a secure RTP profile
/// (`RTP/SAVP`, `RTP/SAVPF`, `UDP/TLS/RTP/SAVP(F)`, ...).
///
/// Plaintext is acceptable only when every active stream on both sides is
/// `RTP/AVP(F)`; a remote that asks for SAVP(F) must get SRTP or nothing
/// (RFC 3264 §5.1; NIST 800-53 Rev5: SC-8(1)).
#[must_use]
pub fn sdp_requests_srtp(sdp: &str) -> bool {
    sdp.split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .filter_map(|l| l.strip_prefix("m="))
        .any(|m| {
            let mut fields = m.split_ascii_whitespace();
            let port = fields.nth(1).unwrap_or_default();
            let proto = fields.next().unwrap_or_default();
            port.split('/').next() != Some("0") && proto.to_ascii_uppercase().contains("SAVP")
        })
}

/// The `a=setup` value we keep in a re-INVITE answer for an existing DTLS
/// role (actpass is only valid in offers, RFC 5763 §5).
pub const fn setup_for_role(role: DtlsRole) -> Setup {
    match role {
        DtlsRole::Client => Setup::Active,
        DtlsRole::Server => Setup::Passive,
    }
}

/// The fixed text of a DTLS-SRTP failure for `media-security: <cause>`
/// application events and logs: `dtls-timeout`,
/// `dtls-fingerprint-mismatch`, `dtls-peer-authentication`,
/// `dtls-unsupported-parameters`, `dtls-no-srtp-profile`, `dtls-alert`,
/// `dtls-protocol-violation`, `dtls-closed-by-peer`, `dtls-internal`.
///
/// NIST 800-53 Rev5: SI-11 -- nothing the peer chose is in the text; the
/// alert number of `dtls-alert` goes to the DTLS driver's log record only.
#[must_use]
pub const fn cause_text(cause: SecurityCause) -> &'static str {
    cause.as_str()
}

/// Maps negotiated DTLS-SRTP keys into the audio pipeline's key type.
///
/// The profile match is exhaustive: a new DTLS-SRTP profile cannot reach the
/// pipeline without a reviewed mapping (CNSA 2.0: AES-256-GCM only).
pub fn srtp_session_keys(keys: NegotiatedSrtpKeys) -> SrtpSessionKeys {
    let (dtls_profile, local_key, local_salt, remote_key, remote_salt) = keys.into_parts();
    let profile = match dtls_profile {
        DtlsSrtpProfile::AeadAes256Gcm => SrtpProfile::AeadAes256Gcm,
    };
    SrtpSessionKeys::new(profile, local_key, local_salt, remote_key, remote_salt)
}

/// A well-formed DTLS-SRTP audio offer (SAVPF, sha-384 fingerprint,
/// `actpass`, rtcp-mux) for tests that exercise SIP paths on TLS accounts.
#[cfg(test)]
pub fn test_offer_sdp() -> String {
    let fp = proto_dtls_fingerprint_for_tests();
    format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.50\r\ns=-\r\nc=IN IP4 192.0.2.50\r\nt=0 0\r\n\
         m=audio 40000 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
         a=fingerprint:{fp}\r\na=setup:actpass\r\na=rtcp-mux\r\na=sendrecv\r\n"
    )
}

#[cfg(test)]
fn proto_dtls_fingerprint_for_tests() -> String {
    // 48 fixed octets: a syntactically valid sha-384 fingerprint.
    let hex: Vec<String> = (0..48u8).map(|b| format!("{b:02X}")).collect();
    format!("sha-384 {}", hex.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_sip_ua::DtlsIdentity;

    fn offer(proto: &str, extra: &str) -> String {
        let fp = DtlsIdentity::generate().unwrap().sdp_fingerprint();
        format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.50\r\ns=-\r\nc=IN IP4 192.0.2.50\r\nt=0 0\r\n\
             m=audio 40000 {proto} 0\r\na=fingerprint:{fp}\r\n{extra}"
        )
    }

    #[test]
    fn offer_actpass_answers_active_client() {
        let p = preflight(
            Some(&offer(
                "UDP/TLS/RTP/SAVPF",
                "a=setup:actpass\r\na=rtcp-mux\r\n",
            )),
            RemoteSdp::Offer,
        )
        .unwrap();
        assert_eq!(p.role, DtlsRole::Client);
        assert_eq!(p.local_setup, Some(Setup::Active));
        assert!(p.rtcp_mux);
    }

    #[test]
    fn rejects_avp_missing_body_and_actpass_answer() {
        assert!(preflight(None, RemoteSdp::Offer).is_err());
        assert!(preflight(Some(""), RemoteSdp::Offer).is_err());
        assert!(preflight(Some(&offer("RTP/AVP", "")), RemoteSdp::Answer).is_err());
        assert!(preflight(Some(&offer("RTP/SAVP", "")), RemoteSdp::Answer).is_err());
        assert!(
            preflight(
                Some(&offer("UDP/TLS/RTP/SAVPF", "a=setup:actpass\r\n")),
                RemoteSdp::Answer
            )
            .is_err()
        );
        let p = preflight(
            Some(&offer(
                "UDP/TLS/RTP/SAVPF",
                "a=setup:active\r\na=rtcp-mux\r\n",
            )),
            RemoteSdp::Answer,
        )
        .unwrap();
        assert_eq!(p.role, DtlsRole::Server);
    }

    #[test]
    fn srtp_profile_detection() {
        assert!(sdp_requests_srtp(&offer("RTP/SAVP", "")));
        assert!(sdp_requests_srtp(&offer("rtp/savpf", "")));
        assert!(sdp_requests_srtp(&offer("UDP/TLS/RTP/SAVPF", "")));
        assert!(!sdp_requests_srtp(&offer("RTP/AVP", "")));
        assert!(!sdp_requests_srtp(&offer("RTP/AVPF", "")));
        assert!(!sdp_requests_srtp(
            &offer("RTP/SAVP", "").replace("m=audio 40000", "m=audio 0")
        ));
    }

    /// RFC-R1-002: the first active (non-zero port) audio section is the
    /// one checked; an offer whose only audio is disabled is rejected.
    #[test]
    fn selects_first_active_audio_section() {
        let good = offer("UDP/TLS/RTP/SAVPF", "a=setup:actpass\r\na=rtcp-mux\r\n");
        let only_disabled = good.replace("m=audio 40000", "m=audio 0");
        assert_eq!(
            preflight(Some(&only_disabled), RemoteSdp::Offer).unwrap_err(),
            "no active audio media section"
        );

        // A disabled, attribute-less audio section ahead of the active one
        // is skipped; the active section's parameters are used.
        let (session, media) = good.split_at(good.find("m=audio").unwrap());
        let disabled_first = format!("{session}m=audio 0 RTP/AVP 0\r\n{media}");
        let p = preflight(Some(&disabled_first), RemoteSdp::Offer).unwrap();
        assert_eq!(p.role, DtlsRole::Client);
        assert!(p.rtcp_mux);

        // The active section is the one that must be DTLS-SRTP: a disabled
        // secure section does not vouch for an active plaintext one.
        let plain_active = format!("{only_disabled}m=audio 40002 RTP/AVP 0\r\na=rtcp-mux\r\n");
        assert!(preflight(Some(&plain_active), RemoteSdp::Offer).is_err());
    }

    #[test]
    fn rejects_missing_rtcp_mux_and_insecure_second_stream() {
        for remote in [RemoteSdp::Offer, RemoteSdp::Answer] {
            let setup = if remote == RemoteSdp::Offer {
                "actpass"
            } else {
                "active"
            };
            assert!(
                preflight(
                    Some(&offer("UDP/TLS/RTP/SAVPF", &format!("a=setup:{setup}\r\n"))),
                    remote
                )
                .is_err()
            );
            let video = format!(
                "{}m=video 5002 RTP/AVP 96\r\n",
                offer(
                    "UDP/TLS/RTP/SAVPF",
                    &format!("a=setup:{setup}\r\na=rtcp-mux\r\n")
                )
            );
            assert!(preflight(Some(&video), remote).is_err());
            let disabled = video.replace("m=video 5002", "m=video 0");
            assert!(preflight(Some(&disabled), remote).is_ok());
        }
    }
}
