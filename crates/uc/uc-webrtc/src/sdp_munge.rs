//! SDP munging for WebRTC compatibility.
//!
//! This module provides SDP transformation utilities to ensure
//! compatibility between SIP and WebRTC endpoints.
//!
//! The SDP is parsed into a typed [`proto_sdp::SessionDescription`], every
//! m-section is mutated individually and the result is re-serialized. No
//! line-string munging is performed, so per-section attributes (`a=mid`,
//! ICE, DTLS) cannot be attached to the wrong section or orphaned.
//!
//! RFC 8829 §5.2.1: ICE credentials, fingerprint and setup are placed in every
//! m-section. RFC 8843 §7: every m-section carries a unique `a=mid`.
//! RFC 3264 §6/§8.2: m-sections are never removed; unsupported sections are
//! rejected in place (port 0).

use crate::config::SdpConfig;
use crate::error::{WebRtcError, WebRtcResult};
use proto_sdp::{Attribute, AttributeName, MediaType, SessionDescription, TransportProtocol};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Write as _;
use tracing::{debug, warn};

/// Default upper bound on m-sections accepted in one SDP (DoS bound).
pub const DEFAULT_MAX_MEDIA_SECTIONS: usize = 64;

/// Default upper bound on total SDP size in bytes (DoS bound).
pub const DEFAULT_MAX_SDP_BYTES: usize = 64 * 1024;

/// Default upper bound on `a=` lines per section (DoS bound).
pub const DEFAULT_MAX_ATTRIBUTES_PER_SECTION: usize = 256;

/// Maximum accepted length of a single `a=mid` value.
const MAX_MID_LEN: usize = 64;

/// Maximum accepted length of a trickled candidate value.
const MAX_CANDIDATE_LEN: usize = 1024;

/// SCTP-over-DTLS protocol tokens that proto-sdp cannot represent.
///
/// RFC 8841 §4.1: `UDP/DTLS/SCTP`, `TCP/DTLS/SCTP` (and legacy `DTLS/SCTP`).
const SCTP_PROTOCOLS: [&str; 3] = ["UDP/DTLS/SCTP", "TCP/DTLS/SCTP", "DTLS/SCTP"];

/// Attributes that SIP endpoints do not understand and that are stripped
/// when converting WebRTC SDP to SIP SDP.
const WEBRTC_ONLY_ATTRS: [&str; 7] = [
    "ice-options",
    "msid",
    "ssrc-group",
    "rtcp-rsize",
    "sctpmap",
    "sctp-port",
    "max-message-size",
];

/// SDP munging mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSdpMode {
    /// Convert SIP SDP to WebRTC SDP.
    SipToWebRtc,
    /// Convert WebRTC SDP to SIP SDP.
    WebRtcToSip,
    /// Pass through with minimal changes.
    Passthrough,
}

/// DTLS certificate fingerprint hash algorithm (RFC 8122 §5).
///
/// CNSA 2.0: SHA-384 is the default; SHA-256 is accepted for interop only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FingerprintAlgorithm {
    /// SHA-384 (CNSA 2.0 default).
    #[default]
    Sha384,
    /// SHA-256 (interop).
    Sha256,
}

impl FingerprintAlgorithm {
    /// Returns the SDP hash function token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha384 => "sha-384",
            Self::Sha256 => "sha-256",
        }
    }

    /// Returns the digest length in octets.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha256 => 32,
        }
    }
}

/// DTLS setup role (RFC 4145 §4, RFC 5763 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DtlsSetup {
    /// Offerer: either role (RFC 5763 §5 requires actpass in offers).
    #[default]
    Actpass,
    /// Active (DTLS client).
    Active,
    /// Passive (DTLS server).
    Passive,
}

impl DtlsSetup {
    /// Returns the SDP token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Actpass => "actpass",
            Self::Active => "active",
            Self::Passive => "passive",
        }
    }
}

/// Local DTLS/ICE parameters inserted into WebRTC-bound SDP.
///
/// Values are validated before use; nothing is fabricated by the munger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtlsIceParams {
    /// ICE username fragment (RFC 8839 §5.4: 4..=256 ice-chars).
    pub ufrag: String,
    /// ICE password (RFC 8839 §5.4: 22..=256 ice-chars).
    pub pwd: String,
    /// Fingerprint hash algorithm.
    pub fingerprint_alg: FingerprintAlgorithm,
    /// Fingerprint as colon-separated hex octets.
    pub fingerprint: String,
    /// DTLS setup role.
    ///
    /// Precondition (RFC 5763 §5, RFC 8842 §5): when the munged SDP is an
    /// offer this MUST be [`DtlsSetup::Actpass`]; in an answer it MUST be
    /// `Active` or `Passive`. The munger cannot tell offer from answer, so
    /// the caller selects the role; [`SdpMunger::sip_to_webrtc_offer`]
    /// enforces the offer rule.
    pub setup: DtlsSetup,
}

impl DtlsIceParams {
    /// Validates all parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if any value is malformed.
    // NIST 800-53 Rev5: SI-10 (Information Input Validation)
    pub fn validate(&self) -> WebRtcResult<()> {
        validate_ice_credentials(&self.ufrag, &self.pwd)?;
        validate_fingerprint(self.fingerprint_alg, &self.fingerprint)
    }
}

/// SDP munger for WebRTC compatibility.
#[derive(Debug, Clone)]
pub struct SdpMunger {
    /// Configuration.
    config: SdpConfig,
}

/// Parsed SDP plus the original SCTP protocol tokens proto-sdp cannot model.
struct ParsedSdp {
    session: SessionDescription,
    /// Per m-section: original SCTP protocol token, if any.
    sctp_protos: Vec<Option<&'static str>>,
}

impl SdpMunger {
    /// Creates a new SDP munger with the given configuration.
    ///
    /// The configuration is not checked here; every transforming operation
    /// re-validates it and fails closed. Prefer [`Self::try_new`].
    #[must_use]
    pub const fn new(config: SdpConfig) -> Self {
        Self { config }
    }

    /// Creates a new SDP munger, rejecting unsupported configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WebRtcError::ConfigError`] if [`SdpConfig::validate`] fails.
    pub fn try_new(config: SdpConfig) -> WebRtcResult<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Creates a munger with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(SdpConfig::default())
    }

    /// Transforms SDP for the given mode.
    ///
    /// `SipToWebRtc` requires local DTLS/ICE parameters and therefore always
    /// fails here; use [`Self::transform_with`].
    ///
    /// # Errors
    ///
    /// Returns an error if the SDP is malformed, or for `SipToWebRtc`.
    pub fn transform(&self, sdp: &str, mode: WebRtcSdpMode) -> WebRtcResult<String> {
        match mode {
            WebRtcSdpMode::SipToWebRtc => Err(WebRtcError::SdpError {
                reason: "SIP-to-WebRTC conversion requires DTLS/ICE parameters".to_string(),
            }),
            WebRtcSdpMode::WebRtcToSip => self.webrtc_to_sip(sdp),
            WebRtcSdpMode::Passthrough => Ok(sdp.to_string()),
        }
    }

    /// Transforms SDP for the given mode using local DTLS/ICE parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDP or parameters are malformed.
    pub fn transform_with(
        &self,
        sdp: &str,
        mode: WebRtcSdpMode,
        params: &DtlsIceParams,
    ) -> WebRtcResult<String> {
        match mode {
            WebRtcSdpMode::SipToWebRtc => self.sip_to_webrtc(sdp, params),
            WebRtcSdpMode::WebRtcToSip | WebRtcSdpMode::Passthrough => self.transform(sdp, mode),
        }
    }

    /// Converts a SIP SDP offer to a WebRTC SDP offer.
    ///
    /// # Errors
    ///
    /// Returns an error if `params.setup` is not `actpass` (RFC 5763 §5:
    /// the offerer MUST use `actpass`), or as for [`Self::transform_with`].
    pub fn sip_to_webrtc_offer(&self, sdp: &str, params: &DtlsIceParams) -> WebRtcResult<String> {
        if params.setup != DtlsSetup::Actpass {
            return Err(sdp_err("DTLS offer must use a=setup:actpass"));
        }
        self.sip_to_webrtc(sdp, params)
    }

    /// Converts a SIP SDP answer to a WebRTC SDP answer.
    ///
    /// # Errors
    ///
    /// Returns an error if `params.setup` is `actpass` (RFC 5763 §5: the
    /// answerer MUST choose `active` or `passive`), or as for
    /// [`Self::transform_with`].
    pub fn sip_to_webrtc_answer(&self, sdp: &str, params: &DtlsIceParams) -> WebRtcResult<String> {
        if params.setup == DtlsSetup::Actpass {
            return Err(sdp_err("DTLS answer must use a=setup:active or passive"));
        }
        self.sip_to_webrtc(sdp, params)
    }

    /// Converts SIP SDP to WebRTC SDP.
    // NIST 800-53 Rev5: SC-8, SC-8(1) (Transmission Confidentiality and Integrity)
    // NIST 800-53 Rev5: SC-23 (Session Authenticity)
    fn sip_to_webrtc(&self, sdp: &str, params: &DtlsIceParams) -> WebRtcResult<String> {
        // RFC 8827 §6.5: WebRTC media MUST be DTLS-SRTP; SDES cannot be kept.
        // Unimplemented SdpConfig keys are rejected here too (fail closed).
        self.config.validate()?;
        params.validate()?;

        let mut parsed = parse_sdp(sdp, &self.config)?;
        let mids = assign_mids(&mut parsed.session)?;

        // Session-level transport attributes are replaced by per-section ones.
        parsed.session.attributes.retain(|a| {
            !is_transport_attr(&a.name) && !is_bundle_group(a) && !is_name(&a.name, "crypto")
        });
        parsed.session.encryption_key = None;

        let mut bundle_mids: Vec<&str> = Vec::new();
        for (idx, media) in parsed.session.media.iter_mut().enumerate() {
            let mid = mids.get(idx).map_or("", String::as_str);
            let is_sctp = parsed.sctp_protos.get(idx).copied().flatten().is_some();

            if !is_sctp {
                match media.protocol {
                    // RFC 8829 §5.1.2: RTP media uses UDP/TLS/RTP/SAVPF. Plain
                    // RTP/AVP is upgraded, never passed through (no downgrade).
                    TransportProtocol::RtpAvp
                    | TransportProtocol::RtpAvpf
                    | TransportProtocol::RtpSavp
                    | TransportProtocol::RtpSavpf
                    | TransportProtocol::UdpTlsRtpSavp
                    | TransportProtocol::UdpTlsRtpSavpf => {
                        media.protocol = TransportProtocol::UdpTlsRtpSavpf;
                    }
                    // Raw UDP/TCP cannot be secured by WebRTC: reject in place.
                    TransportProtocol::Udp | TransportProtocol::Tcp => {
                        warn!(index = idx, "Rejecting non-RTP m-section for WebRTC");
                        reject_in_place(media);
                        continue;
                    }
                }
            }

            // RFC 8829 §5.2.1 / RFC 4568: SDES keys MUST NOT accompany DTLS-SRTP.
            media.encryption_key = None;
            media.attributes.retain(|a| {
                if is_name(&a.name, "crypto") {
                    debug!("Stripping SDES crypto attribute for WebRTC");
                    return false;
                }
                !is_transport_attr(&a.name)
            });

            if media.port == 0 {
                // Rejected section: keep only its mid, no transport params.
                continue;
            }

            add_transport_attrs(media, params);
            if self.config.rtcp_mux && !is_sctp && !media.has_rtcp_mux() {
                // RFC 5761 §5.1.1 / RFC 8829 §5.2.1
                media.add_attribute(Attribute::flag(AttributeName::RtcpMux));
            }
            bundle_mids.push(mid);
        }

        // RFC 8840 §4.1.1 / RFC 8829 §5.2.1: advertise Trickle ICE support.
        parsed
            .session
            .attributes
            .push(Attribute::new(AttributeName::IceOptions, "trickle"));

        // RFC 8843 §7.2: BUNDLE lists every non-rejected mid.
        if self.config.bundle && !bundle_mids.is_empty() {
            parsed.session.attributes.push(Attribute::new(
                AttributeName::Group,
                format!("BUNDLE {}", bundle_mids.join(" ")),
            ));
        }

        Ok(render(&parsed))
    }

    /// Converts WebRTC SDP to SIP SDP.
    fn webrtc_to_sip(&self, sdp: &str) -> WebRtcResult<String> {
        self.config.validate()?;
        let mut parsed = parse_sdp(sdp, &self.config)?;
        let mut rejected_mids: HashSet<String> = HashSet::new();

        for (idx, media) in parsed.session.media.iter_mut().enumerate() {
            let is_sctp = parsed.sctp_protos.get(idx).copied().flatten().is_some();
            let is_datachannel = is_sctp
                || (media.media_type == MediaType::Application
                    && media.formats.iter().any(|f| f == "webrtc-datachannel"));
            if is_datachannel {
                // RFC 3264 §6/§8.2: never delete an m-line; reject with port 0.
                warn!(
                    index = idx,
                    "Rejecting WebRTC data channel - not supported in SIP"
                );
                if let Some(mid) = media.mid() {
                    rejected_mids.insert(mid.to_string());
                }
                reject_in_place(media);
                continue;
            }

            media.attributes.retain(|a| {
                let strip = WEBRTC_ONLY_ATTRS.iter().any(|n| is_name(&a.name, n));
                if strip {
                    debug!(attr = %a.name, "Stripping WebRTC-only attribute for SIP");
                }
                !strip
            });
        }

        parsed
            .session
            .attributes
            .retain(|a| !WEBRTC_ONLY_ATTRS.iter().any(|n| is_name(&a.name, n)));

        // RFC 8843 §7.3.3: a rejected m-section's mid leaves the BUNDLE group.
        if !rejected_mids.is_empty() {
            parsed.session.attributes.retain_mut(|a| {
                if !is_bundle_group(a) {
                    return true;
                }
                let remaining: Vec<&str> = a
                    .value
                    .as_deref()
                    .unwrap_or_default()
                    .split_whitespace()
                    .skip(1)
                    .filter(|m| !rejected_mids.contains(*m))
                    .collect();
                if remaining.is_empty() {
                    return false;
                }
                a.value = Some(format!("BUNDLE {}", remaining.join(" ")));
                true
            });
        }

        Ok(render(&parsed))
    }

    /// Sets the DTLS fingerprint in every non-rejected m-section.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDP or fingerprint is malformed.
    pub fn add_fingerprint(
        &self,
        sdp: &str,
        algorithm: FingerprintAlgorithm,
        fingerprint: &str,
    ) -> WebRtcResult<String> {
        validate_fingerprint(algorithm, fingerprint)?;
        let value = format!("{} {fingerprint}", algorithm.as_str());
        self.replace_per_section(sdp, &AttributeName::Fingerprint, &[value])
    }

    /// Sets ICE credentials in every non-rejected m-section.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDP or credentials are malformed.
    pub fn add_ice_credentials(&self, sdp: &str, ufrag: &str, pwd: &str) -> WebRtcResult<String> {
        validate_ice_credentials(ufrag, pwd)?;
        let with_ufrag =
            self.replace_per_section(sdp, &AttributeName::IceUfrag, &[ufrag.to_string()])?;
        self.replace_per_section(&with_ufrag, &AttributeName::IcePwd, &[pwd.to_string()])
    }

    /// Adds an ICE candidate to the m-section at `media_index`.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDP or candidate is malformed, or the index is
    /// out of range.
    pub fn add_candidate(
        &self,
        sdp: &str,
        candidate: &str,
        media_index: usize,
    ) -> WebRtcResult<String> {
        let value = candidate.strip_prefix("a=").unwrap_or(candidate);
        let value = value.strip_prefix("candidate:").unwrap_or(value);
        if value.is_empty()
            || value.len() > MAX_CANDIDATE_LEN
            || !value.bytes().all(|b| (0x20..0x7f).contains(&b))
        {
            return Err(sdp_err("invalid ICE candidate"));
        }

        let mut parsed = parse_sdp(sdp, &self.config)?;
        let media = parsed
            .session
            .media
            .get_mut(media_index)
            .ok_or_else(|| sdp_err("candidate media index out of range"))?;
        media.add_attribute(Attribute::new(AttributeName::Candidate, value));
        Ok(render(&parsed))
    }

    /// Sets the DTLS setup role in every non-rejected m-section.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDP is malformed.
    pub fn set_setup(&self, sdp: &str, setup: DtlsSetup) -> WebRtcResult<String> {
        self.replace_per_section(sdp, &AttributeName::Setup, &[setup.as_str().to_string()])
    }

    /// Replaces `name` with `values` in every non-rejected m-section and
    /// removes any session-level instance.
    fn replace_per_section(
        &self,
        sdp: &str,
        name: &AttributeName,
        values: &[String],
    ) -> WebRtcResult<String> {
        let mut parsed = parse_sdp(sdp, &self.config)?;
        parsed.session.attributes.retain(|a| &a.name != name);
        for media in parsed.session.media.iter_mut().filter(|m| m.port != 0) {
            media.attributes.retain(|a| &a.name != name);
            for v in values {
                media.add_attribute(Attribute::new(name.clone(), v.clone()));
            }
        }
        Ok(render(&parsed))
    }

    /// Extracts the DTLS fingerprint (first m-section, else session level).
    #[must_use]
    pub fn extract_fingerprint(sdp: &str) -> Option<(String, String)> {
        let parsed = parse_sdp(sdp, &SdpConfig::default()).ok()?;
        let s = &parsed.session;
        s.media
            .iter()
            .find_map(proto_sdp::MediaDescription::fingerprint)
            .or_else(|| s.fingerprint())
            .map(|(a, f)| (a.to_string(), f.to_string()))
    }

    /// Extracts ICE credentials (first m-section, else session level).
    #[must_use]
    pub fn extract_ice_credentials(sdp: &str) -> Option<(String, String)> {
        let parsed = parse_sdp(sdp, &SdpConfig::default()).ok()?;
        let s = &parsed.session;
        s.media
            .iter()
            .find_map(|m| Some((m.ice_ufrag()?, m.ice_pwd()?)))
            .or_else(|| s.ice_credentials())
            .map(|(u, p)| (u.to_string(), p.to_string()))
    }

    /// Extracts ICE candidates from all m-sections.
    #[must_use]
    pub fn extract_candidates(sdp: &str) -> Vec<String> {
        let Ok(parsed) = parse_sdp(sdp, &SdpConfig::default()) else {
            return Vec::new();
        };
        parsed
            .session
            .media
            .iter()
            .flat_map(|m| m.get_attributes(&AttributeName::Candidate))
            .map(|a| format!("candidate:{}", a.value.as_deref().unwrap_or_default()))
            .collect()
    }
}

impl Default for SdpMunger {
    fn default() -> Self {
        Self::default_config()
    }
}

fn sdp_err(reason: &str) -> WebRtcError {
    WebRtcError::SdpError {
        reason: reason.to_string(),
    }
}

/// Case-insensitive attribute name comparison.
fn is_name(name: &AttributeName, expected: &str) -> bool {
    name.as_str().eq_ignore_ascii_case(expected)
}

/// ICE/DTLS attributes replaced by the gateway's own values.
fn is_transport_attr(name: &AttributeName) -> bool {
    matches!(
        name,
        AttributeName::IceUfrag
            | AttributeName::IcePwd
            | AttributeName::IceOptions
            | AttributeName::Candidate
            | AttributeName::Fingerprint
            | AttributeName::Setup
    ) || is_name(name, "end-of-candidates")
}

fn is_bundle_group(a: &Attribute) -> bool {
    a.name == AttributeName::Group
        && a.value
            .as_deref()
            .and_then(|v| v.split_whitespace().next())
            .is_some_and(|s| s.eq_ignore_ascii_case("BUNDLE"))
}

/// Rejects an m-section in place: port 0, only `a=mid` retained.
///
/// RFC 3264 §6: a rejected stream keeps its m-line with port zero.
fn reject_in_place(media: &mut proto_sdp::MediaDescription) {
    media.port = 0;
    media.num_ports = None;
    media.encryption_key = None;
    media.bandwidth.clear();
    media.attributes.retain(|a| a.name == AttributeName::Mid);
}

fn add_transport_attrs(media: &mut proto_sdp::MediaDescription, params: &DtlsIceParams) {
    // RFC 8839 §5.4 / RFC 8122 §5 / RFC 5763 §5 / RFC 8842 §5
    media.add_attribute(Attribute::new(
        AttributeName::IceUfrag,
        params.ufrag.clone(),
    ));
    media.add_attribute(Attribute::new(AttributeName::IcePwd, params.pwd.clone()));
    media.add_attribute(Attribute::new(
        AttributeName::Fingerprint,
        format!("{} {}", params.fingerprint_alg.as_str(), params.fingerprint),
    ));
    media.add_attribute(Attribute::new(AttributeName::Setup, params.setup.as_str()));
}

/// Validates/collects existing mids and assigns unique ones where absent.
///
/// RFC 8843 §7 / RFC 5888 §4: each m-section has exactly one, unique mid.
// NIST 800-53 Rev5: SI-10 (Information Input Validation)
fn assign_mids(session: &mut SessionDescription) -> WebRtcResult<Vec<String>> {
    let mut used: HashSet<String> = HashSet::new();
    for media in &session.media {
        let mut found = media.get_attributes(&AttributeName::Mid).into_iter();
        if let Some(attr) = found.next() {
            if found.next().is_some() {
                return Err(sdp_err("multiple a=mid in one m-section"));
            }
            let mid = attr.value.as_deref().unwrap_or_default();
            if !is_valid_mid(mid) {
                return Err(sdp_err("invalid a=mid value"));
            }
            if !used.insert(mid.to_string()) {
                return Err(sdp_err("duplicate a=mid value"));
            }
        }
    }

    let mut next = 0usize;
    let mut mids = Vec::with_capacity(session.media.len());
    for media in &mut session.media {
        if let Some(mid) = media.mid() {
            mids.push(mid.to_string());
            continue;
        }
        let mut candidate = next.to_string();
        while used.contains(&candidate) {
            next += 1;
            candidate = next.to_string();
        }
        next += 1;
        used.insert(candidate.clone());
        media
            .attributes
            .insert(0, Attribute::new(AttributeName::Mid, candidate.clone()));
        mids.push(candidate);
    }
    Ok(mids)
}

/// RFC 5888 §4 identification-tag = token (RFC 8866 §9).
fn is_valid_mid(mid: &str) -> bool {
    !mid.is_empty()
        && mid.len() <= MAX_MID_LEN
        && mid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`{|}~".contains(&b))
}

/// RFC 8839 §5.4: ice-char = ALPHA / DIGIT / "+" / "/".
fn validate_ice_credentials(ufrag: &str, pwd: &str) -> WebRtcResult<()> {
    let ice_chars = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    };
    if !(4..=256).contains(&ufrag.len()) || !ice_chars(ufrag) {
        return Err(sdp_err("invalid ICE ufrag"));
    }
    if !(22..=256).contains(&pwd.len()) || !ice_chars(pwd) {
        return Err(sdp_err("invalid ICE pwd"));
    }
    Ok(())
}

/// RFC 8122 §5: fingerprint = 2UHEX *(":" 2UHEX), length matching the hash.
fn validate_fingerprint(alg: FingerprintAlgorithm, fingerprint: &str) -> WebRtcResult<()> {
    let mut count = 0usize;
    for octet in fingerprint.split(':') {
        if octet.len() != 2 || !octet.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(sdp_err("invalid DTLS fingerprint"));
        }
        count += 1;
    }
    if count != alg.digest_len() {
        return Err(sdp_err("DTLS fingerprint length does not match algorithm"));
    }
    Ok(())
}

/// Parses untrusted SDP into a typed session description.
///
/// Pre-validates every line (ASCII `x=` prefix, no control characters) so
/// proto-sdp never sees input it could mis-slice, enforces the m-section cap,
/// and substitutes SCTP protocol tokens (unsupported by proto-sdp) with a
/// placeholder that is restored on render.
// NIST 800-53 Rev5: SI-10 (Information Input Validation), SC-5 (DoS Protection)
fn parse_sdp(sdp: &str, config: &SdpConfig) -> WebRtcResult<ParsedSdp> {
    if sdp.len() > config.max_sdp_bytes {
        return Err(sdp_err("SDP exceeds size limit"));
    }
    let max_media_sections = config.max_media_sections;
    let mut normalized = String::with_capacity(sdp.len());
    let mut sctp_protos = Vec::new();
    let mut attrs_in_section: usize = 0;

    for raw in sdp.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = line.as_bytes();
        // POAM: POA&M-283 proto-sdp `parse_sdp_line` slices `&line[2..]` and panics on a
        // multibyte first character; this ASCII `x=` guard keeps such input away from it.
        if bytes.len() < 2 || !bytes[0].is_ascii_lowercase() || bytes[1] != b'=' {
            return Err(sdp_err("malformed SDP line"));
        }
        // CRLF/control-character injection guard (bare CR, NUL, ...).
        if line.chars().any(|c| c.is_control() && c != '\t') {
            return Err(sdp_err("control character in SDP line"));
        }
        if bytes[0] == b'a' {
            attrs_in_section += 1;
            if attrs_in_section > config.max_attributes_per_section {
                return Err(sdp_err("too many attributes in section"));
            }
        }
        if bytes[0] == b'm' {
            attrs_in_section = 0;
            if sctp_protos.len() >= max_media_sections {
                return Err(sdp_err("too many m-sections"));
            }
            let mut parts = line[2..].split_whitespace();
            let (Some(media), Some(port), Some(proto)) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(sdp_err("malformed m= line"));
            };
            let sctp = SCTP_PROTOCOLS
                .iter()
                .copied()
                .find(|p| p.eq_ignore_ascii_case(proto));
            if let Some(p) = sctp {
                let _ = write!(normalized, "m={media} {port} UDP");
                for fmt in parts {
                    let _ = write!(normalized, " {fmt}");
                }
                normalized.push_str("\r\n");
                sctp_protos.push(Some(p));
                continue;
            }
            sctp_protos.push(None);
        }
        normalized.push_str(line);
        normalized.push_str("\r\n");
    }

    let session: SessionDescription = normalized.parse().map_err(|e| WebRtcError::SdpError {
        reason: format!("SDP parse failed: {e}"),
    })?;
    if session.media.len() != sctp_protos.len() {
        return Err(sdp_err("m-section count mismatch"));
    }
    Ok(ParsedSdp {
        session,
        sctp_protos,
    })
}

/// Serializes a parsed SDP with CRLF line endings, restoring SCTP protocols.
fn render(parsed: &ParsedSdp) -> String {
    let mut header = parsed.session.clone();
    let media = std::mem::take(&mut header.media);

    let mut out = String::new();
    push_crlf(&mut out, &header.to_string());
    for (idx, m) in media.iter().enumerate() {
        let text = m.to_string();
        match parsed.sctp_protos.get(idx).copied().flatten() {
            Some(proto) => {
                let _ = write!(out, "m={} {}", m.media_type, m.port);
                if let Some(n) = m.num_ports {
                    let _ = write!(out, "/{n}");
                }
                let _ = write!(out, " {proto}");
                for f in &m.formats {
                    let _ = write!(out, " {f}");
                }
                out.push_str("\r\n");
                let rest = text.split_once('\n').map_or("", |(_, r)| r);
                push_crlf(&mut out, rest);
            }
            None => push_crlf(&mut out, &text),
        }
    }
    out
}

fn push_crlf(out: &mut String, text: &str) {
    for line in text.lines() {
        out.push_str(line);
        out.push_str("\r\n");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const FP384: &str = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";

    const SAMPLE_SIP_SDP: &str = "v=0\r\n\
o=- 123456 123456 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:key\r\n";

    const THREE_SECTION_SIP_SDP: &str = "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
m=video 49172 RTP/SAVP 96\r\n\
a=rtpmap:96 H264/90000\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:key\r\n\
m=application 49174 UDP/DTLS/SCTP webrtc-datachannel\r\n\
a=sctp-port:5000\r\n";

    const SAMPLE_WEBRTC_SDP: &str = "v=0\r\n\
o=- 123456 123456 IN IP4 0.0.0.0\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE a0 d1 v2\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:xyz123xyz123xyz123xyz1\r\n\
a=fingerprint:sha-384 AA:BB:CC\r\n\
a=setup:actpass\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:a0\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=rtcp-mux\r\n\
a=msid:stream track\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.1 54400 typ host\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:d1\r\n\
a=sctp-port:5000\r\n\
a=max-message-size:262144\r\n\
a=setup:actpass\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:v2\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=rtcp-mux\r\n";

    fn params() -> DtlsIceParams {
        DtlsIceParams {
            ufrag: "Ufr4".to_string(),
            pwd: "pwdpwdpwdpwdpwdpwdpwdp".to_string(),
            fingerprint_alg: FingerprintAlgorithm::default(),
            fingerprint: FP384.to_string(),
            setup: DtlsSetup::Actpass,
        }
    }

    fn sections(sdp: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in sdp.lines() {
            if line.starts_with("m=") {
                out.push(String::new());
            }
            if let Some(last) = out.last_mut() {
                last.push_str(line);
                last.push('\n');
            }
        }
        out
    }

    #[test]
    fn test_sip_to_webrtc() {
        let munger = SdpMunger::default();
        let result = munger
            .transform_with(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &params())
            .unwrap();
        assert!(!result.contains("a=crypto:"));
        assert!(result.contains("a=rtcp-mux"));
        assert!(result.contains("m=audio 49170 UDP/TLS/RTP/SAVPF 0"));
        assert!(result.contains("a=fingerprint:sha-384 "));
        assert!(result.ends_with("\r\n"));
    }

    #[test]
    fn test_sip_to_webrtc_without_params_errors() {
        let munger = SdpMunger::default();
        assert!(
            munger
                .transform(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc)
                .is_err()
        );
    }

    #[test]
    fn test_sip_to_webrtc_rejects_disabled_dtls() {
        let config = SdpConfig {
            force_dtls_srtp: false,
            ..SdpConfig::default()
        };
        let munger = SdpMunger::new(config);
        assert!(
            munger
                .transform_with(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &params())
                .is_err()
        );
    }

    #[test]
    fn test_sip_to_webrtc_every_section() {
        let munger = SdpMunger::default();
        let out = munger
            .transform_with(THREE_SECTION_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &params())
            .unwrap();
        let secs = sections(&out);
        assert_eq!(secs.len(), 3);
        let mut mids = HashSet::new();
        for s in &secs {
            let mid = s
                .lines()
                .find_map(|l| l.strip_prefix("a=mid:"))
                .unwrap()
                .to_string();
            assert!(mids.insert(mid));
            assert!(s.contains("a=fingerprint:sha-384 "));
            assert!(s.contains("a=setup:actpass"));
            assert!(s.contains("a=ice-ufrag:Ufr4"));
            assert!(s.contains("a=ice-pwd:"));
            assert!(!s.contains("a=crypto"));
        }
        assert!(secs[0].contains("UDP/TLS/RTP/SAVPF"));
        assert!(secs[1].contains("UDP/TLS/RTP/SAVPF"));
        assert!(secs[0].contains("a=rtcp-mux"));
        assert!(secs[1].contains("a=rtcp-mux"));
        assert!(secs[2].starts_with("m=application 49174 UDP/DTLS/SCTP webrtc-datachannel"));
        assert!(out.contains("a=group:BUNDLE 0 1 2\r\n"));
        // Re-parses cleanly.
        parse_sdp(&out, &SdpConfig::default()).unwrap();
    }

    #[test]
    fn test_sip_to_webrtc_preserves_mids_and_avoids_collision() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n\
m=audio 1 RTP/AVP 0\r\na=mid:1\r\n\
m=video 2 RTP/AVP 96\r\n";
        let out = SdpMunger::default()
            .transform_with(sdp, WebRtcSdpMode::SipToWebRtc, &params())
            .unwrap();
        assert!(out.contains("a=group:BUNDLE 1 0\r\n"));
    }

    #[test]
    fn test_sip_to_webrtc_duplicate_mid_errors() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n\
m=audio 1 RTP/AVP 0\r\na=mid:x\r\n\
m=video 2 RTP/AVP 96\r\na=mid:x\r\n";
        assert!(
            SdpMunger::default()
                .transform_with(sdp, WebRtcSdpMode::SipToWebRtc, &params())
                .is_err()
        );
    }

    #[test]
    fn test_sip_to_webrtc_bad_params() {
        let munger = SdpMunger::default();
        let mut p = params();
        p.fingerprint_alg = FingerprintAlgorithm::Sha256;
        assert!(
            munger
                .transform_with(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &p)
                .is_err()
        );
        let mut p = params();
        p.ufrag = "a\r\na=x".to_string();
        assert!(
            munger
                .transform_with(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &p)
                .is_err()
        );
    }

    #[test]
    fn test_sha256_configurable() {
        let mut p = params();
        p.fingerprint_alg = FingerprintAlgorithm::Sha256;
        p.fingerprint = FP384[..95].to_string();
        let out = SdpMunger::default()
            .transform_with(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &p)
            .unwrap();
        assert!(out.contains("a=fingerprint:sha-256 "));
    }

    #[test]
    fn test_webrtc_to_sip() {
        let munger = SdpMunger::default();
        let result = munger
            .transform(SAMPLE_WEBRTC_SDP, WebRtcSdpMode::WebRtcToSip)
            .unwrap();
        assert!(!result.contains("a=msid:"));
    }

    #[test]
    fn test_webrtc_to_sip_rejects_datachannel_in_place() {
        let out = SdpMunger::default()
            .transform(SAMPLE_WEBRTC_SDP, WebRtcSdpMode::WebRtcToSip)
            .unwrap();
        let secs = sections(&out);
        assert_eq!(secs.len(), 3);
        assert_eq!(
            secs[1],
            "m=application 0 UDP/DTLS/SCTP webrtc-datachannel\nc=IN IP4 0.0.0.0\na=mid:d1\n"
        );
        assert!(!out.contains("sctp-port"));
        assert!(!out.contains("max-message-size"));
        assert!(out.contains("a=group:BUNDLE a0 v2\r\n"));
        assert!(secs[0].contains("a=rtpmap:111 opus/48000/2"));
        assert!(secs[0].contains("a=candidate:"));
        assert!(secs[2].contains("a=rtpmap:96 VP8/90000"));
        assert!(secs[2].contains("a=rtcp-mux"));
    }

    #[test]
    fn test_malformed_sdp_errors() {
        let munger = SdpMunger::default();
        for bad in [
            "",
            "garbage",
            "v=0\r\n",
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\nm=audio\r\n",
            "\u{20ac}=x\r\n",
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\na=x\ry\r\n",
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\nm=audio 99999 RTP/AVP 0\r\n",
        ] {
            assert!(munger.transform(bad, WebRtcSdpMode::WebRtcToSip).is_err());
            assert!(
                munger
                    .transform_with(bad, WebRtcSdpMode::SipToWebRtc, &params())
                    .is_err()
            );
        }
    }

    #[test]
    fn test_media_section_cap() {
        let mut sdp = String::from("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n");
        for _ in 0..=DEFAULT_MAX_MEDIA_SECTIONS {
            sdp.push_str("m=audio 1 RTP/AVP 0\r\n");
        }
        assert!(
            SdpMunger::default()
                .transform(&sdp, WebRtcSdpMode::WebRtcToSip)
                .is_err()
        );
    }

    #[test]
    fn test_sdp_size_cap() {
        let config = SdpConfig {
            max_sdp_bytes: 64,
            ..SdpConfig::default()
        };
        let err = SdpMunger::new(config)
            .transform(SAMPLE_WEBRTC_SDP, WebRtcSdpMode::WebRtcToSip)
            .unwrap_err();
        assert!(matches!(err, WebRtcError::SdpError { .. }));
        let mut big = String::from(SAMPLE_WEBRTC_SDP);
        while big.len() <= DEFAULT_MAX_SDP_BYTES {
            big.push_str("a=x-pad:0123456789abcdef0123456789abcdef\r\n");
        }
        assert!(
            SdpMunger::default()
                .transform(&big, WebRtcSdpMode::WebRtcToSip)
                .is_err()
        );
    }

    #[test]
    fn test_attribute_per_section_cap() {
        let config = SdpConfig {
            max_attributes_per_section: 3,
            ..SdpConfig::default()
        };
        let munger = SdpMunger::new(config);
        let base = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\nm=audio 1 RTP/AVP 0\r\n";
        let ok = format!("{base}a=a1\r\na=a2\r\na=a3\r\n");
        assert!(munger.transform(&ok, WebRtcSdpMode::WebRtcToSip).is_ok());
        let bad = format!("{ok}a=a4\r\n");
        assert!(munger.transform(&bad, WebRtcSdpMode::WebRtcToSip).is_err());
    }

    #[test]
    fn test_unenforced_config_fails_closed() {
        let config = SdpConfig {
            rewrite_connection: true,
            ..SdpConfig::default()
        };
        assert!(matches!(
            SdpMunger::try_new(config.clone()),
            Err(WebRtcError::ConfigError { .. })
        ));
        let munger = SdpMunger::new(config);
        assert!(matches!(
            munger.transform_with(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &params()),
            Err(WebRtcError::ConfigError { .. })
        ));
        assert!(matches!(
            munger.transform(SAMPLE_WEBRTC_SDP, WebRtcSdpMode::WebRtcToSip),
            Err(WebRtcError::ConfigError { .. })
        ));
        assert!(SdpMunger::try_new(SdpConfig::default()).is_ok());
    }

    #[test]
    fn test_ice_options_trickle_advertised() {
        let out = SdpMunger::default()
            .transform_with(SAMPLE_SIP_SDP, WebRtcSdpMode::SipToWebRtc, &params())
            .unwrap();
        assert_eq!(out.matches("a=ice-options:trickle").count(), 1);
    }

    #[test]
    fn test_setup_role_offer_answer() {
        let munger = SdpMunger::default();
        assert!(
            munger
                .sip_to_webrtc_offer(SAMPLE_SIP_SDP, &params())
                .is_ok()
        );
        assert!(
            munger
                .sip_to_webrtc_answer(SAMPLE_SIP_SDP, &params())
                .is_err()
        );
        let mut active = params();
        active.setup = DtlsSetup::Active;
        assert!(munger.sip_to_webrtc_offer(SAMPLE_SIP_SDP, &active).is_err());
        let out = munger
            .sip_to_webrtc_answer(SAMPLE_SIP_SDP, &active)
            .unwrap();
        assert!(out.contains("a=setup:active"));
    }

    #[test]
    fn test_add_candidate_target_section() {
        let munger = SdpMunger::default();
        let out = munger
            .add_candidate(
                SAMPLE_WEBRTC_SDP,
                "candidate:2 1 UDP 1 192.0.2.9 1 typ host",
                2,
            )
            .unwrap();
        let secs = sections(&out);
        assert!(secs[2].contains("a=candidate:2 1 UDP 1 192.0.2.9 1 typ host"));
        assert!(!secs[0].contains("192.0.2.9"));
        assert!(
            munger
                .add_candidate(SAMPLE_WEBRTC_SDP, "candidate:2", 3)
                .is_err()
        );
        assert!(
            munger
                .add_candidate(SAMPLE_WEBRTC_SDP, "candidate:2\r\na=x", 0)
                .is_err()
        );
    }

    #[test]
    fn test_extract_fingerprint() {
        let (algo, fp) = SdpMunger::extract_fingerprint(SAMPLE_WEBRTC_SDP).unwrap();
        assert_eq!(algo, "sha-384");
        assert_eq!(fp, "AA:BB:CC");
    }

    #[test]
    fn test_extract_ice_credentials() {
        let (ufrag, pwd) = SdpMunger::extract_ice_credentials(SAMPLE_WEBRTC_SDP).unwrap();
        assert_eq!(ufrag, "abcd");
        assert_eq!(pwd, "xyz123xyz123xyz123xyz1");
    }

    #[test]
    fn test_extract_candidates() {
        let candidates = SdpMunger::extract_candidates(SAMPLE_WEBRTC_SDP);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].starts_with("candidate:"));
    }

    #[test]
    fn test_add_fingerprint() {
        let munger = SdpMunger::default();
        let result = munger
            .add_fingerprint(SAMPLE_SIP_SDP, FingerprintAlgorithm::Sha384, FP384)
            .unwrap();
        assert!(result.contains(&format!("a=fingerprint:sha-384 {FP384}")));
        assert!(
            munger
                .add_fingerprint(SAMPLE_SIP_SDP, FingerprintAlgorithm::Sha384, "AA:BB")
                .is_err()
        );
    }

    #[test]
    fn test_add_ice_credentials() {
        let munger = SdpMunger::default();
        let out = munger
            .add_ice_credentials(SAMPLE_WEBRTC_SDP, "newU", "newpwdnewpwdnewpwdnewp")
            .unwrap();
        assert_eq!(out.matches("a=ice-ufrag:newU").count(), 3);
        assert!(!out.contains("a=ice-ufrag:abcd"));
    }

    #[test]
    fn test_set_setup() {
        let munger = SdpMunger::default();
        let result = munger
            .set_setup(SAMPLE_WEBRTC_SDP, DtlsSetup::Active)
            .unwrap();
        assert!(result.contains("a=setup:active"));
        assert!(!result.contains("a=setup:actpass"));
    }
}
