//! Media security policy for an SDP body crossing the B2BUA.
//!
//! [`apply_media_security`] decides, for one SDP offer or answer going from
//! one call leg to the other, whether it may cross and what it looks like
//! once it has crossed. It is pure and synchronous: no I/O, no locks and no
//! cryptographic operations (only suite names and key lengths are read), so
//! the SIP stack calls it on the per-message task and maps a refusal to the
//! SIP outcome that fits the message (488 to an offer, teardown on an
//! answer).
//!
//! Rules (leg A sends the SDP, leg B receives it):
//!
//! - **Declined sections** (port 0, RFC 3264 §8): `a=crypto` and
//!   `a=key-mgmt` are stripped and nothing else is checked. The m-line
//!   itself is kept; m-lines are never removed.
//! - **SDES** (`a=crypto`, RFC 4568) on an active section, passthrough:
//!   the key is in clear text inside the SDP, so both signalling hops must
//!   be confidential (RFC 4568 §8 / §8.3). An offer keeps only acceptable
//!   lines (below) and is refused when none is left. An answer must carry
//!   exactly one acceptable line (RFC 4568 §7.1.2); its active passthrough
//!   SDES sections are never rewritten.
//! - **Acceptable `a=crypto` line** (stricter than RFC 4568 allows, on
//!   purpose): tag `1*9DIGIT`; suite `AEAD_AES_256_GCM` (RFC 7714 §14.1,
//!   CNSA 2.0); exactly one `inline:` key-param whose key is 44 octets; an
//!   optional lifetime of at most 2^48 (the SRTP maximum, RFC 3711 §3.2.1);
//!   an optional MKI `value:length` with length 1..=128 (RFC 4568 §9.2).
//!   Session parameters are an allow-list: `KDR=`, `WSH=` and `FEC_ORDER=`
//!   with valid values. `FEC_KEY` (a second key the policy does not check),
//!   `UNENCRYPTED_SRTP` / `UNENCRYPTED_SRTCP` / `UNAUTHENTICATED_SRTP`
//!   (RFC 4568 §6.3.2, §6.3.3), a repeated parameter and any other parameter
//!   (including `-`-prefixed extensions, RFC 4568 §9.2) make the line
//!   unacceptable.
//! - **SDES, terminate mode**: the SBC keys each leg itself (DTLS-SRTP), so
//!   every `a=crypto` line is stripped, from answers too; a section with no
//!   DTLS keying left is refused. `a=crypto` on a DTLS m-line
//!   (`UDP/TLS/RTP/SAVP(F)`, RFC 5764 §8; `TCP/DTLS/RTP/SAVP(F)`, RFC 7850
//!   §3) is stripped in both modes and both roles. A declined section's
//!   keying lines are stripped in both roles.
//! - **`a=key-mgmt`** (MIKEY, RFC 4567): stripped from offers, refused in
//!   answers, and refused when it is the only keying of a section.
//! - **Session-level `a=crypto`** (not valid, RFC 4568 §9.1): stripped from
//!   offers, refused in answers.
//!
//! - **DTLS fingerprints** (RFC 8122 §5, RFC 5763 §5; whatever
//!   `require_srtp` says): an active DTLS m-line needs at least one
//!   applicable `a=fingerprint` whose hash is `sha-384` or `sha-512` (the
//!   hashes CNSA 2.0 allows, matched case-insensitively) and whose value is
//!   48 or 64 colon-separated hex octets to match. Media-level lines apply,
//!   else the session-level ones. Offers and answers alike lose every other
//!   `a=fingerprint` line (session level and active sections): removing a
//!   line cannot weaken the binding the remaining ones give. The body is
//!   refused only when an active DTLS m-line has no accepted line left.
//!   `sha-256`, `sha-1` and `md5` are refused even though RFC 8122 allows
//!   them (a deliberate CNSA 2.0 deviation).
//! - **`require_srtp`** (`media.srtp.required`): every active m-line other
//!   than `m=image <port> udptl` must be a DTLS profile keyed by a passing
//!   fingerprint (`UDP/TLS/RTP/SAVP(F)`, `TCP/DTLS/RTP/SAVP(F)`,
//!   `TCP/TLS/RTP/SAVP(F)`, and the data-channel profiles
//!   `UDP/DTLS/SCTP` and `TCP/DTLS/SCTP`, RFC 8841), or `RTP/SAVP(F)`
//!   keeping an SDES line that passes the SDES rules. `RTP/AVP(F)` and an
//!   unkeyed `RTP/SAVP(F)` are cleartext media; `UDP`, `TCP`, `udptl`
//!   outside `m=image`, `TCP/TLS/RTP/AVP(F)` and unknown protocols are an
//!   unsupported protocol. In terminate mode only DTLS passes (SDES is not
//!   terminated). One failing m-line refuses the whole body. Only
//!   `m=image ... udptl` follows the T.38 rules of the SIP stack instead; an
//!   `m=image` line with any other protocol is checked like any m-line.
//!
//! Without `require_srtp`, cleartext profiles are not refused here.
//!
//! One tokenizer classifies and rewrites. A body with a NUL or a bare CR
//! (a CR not followed by LF) is refused as malformed, so a lenient parser
//! further on cannot see a line this policy did not see. Line types and
//! attribute names are matched ASCII case-insensitively and after the same
//! whitespace trim `proto-sdp` applies. When `proto-sdp` parses the body,
//! its m-line count and ports must agree with the tokenizer's.
//!
//! ## NIST 800-53 Rev5: SC-8, SC-8(1), SC-12, SC-13, SC-23, CM-6, SI-10
//!
//! ## RFC 4568 §6.3, §7.1.2, §8, §9.1, §9.2; RFC 4567; RFC 7714 §14.1;
//! RFC 5764 §8; RFC 5763 §5; RFC 8122 §5; RFC 8841 §4; RFC 3264 §6, §8
// POAM: POA&M-348 - the SDES confidentiality check is hop by hop (RFC 4568
// §8.3): it covers the two signalling hops the SBC terminates, not hops
// beyond them.

use std::borrow::Cow;

use proto_sdp::{CryptoAttribute, SessionDescription};

/// The only SRTP crypto suite that may cross (RFC 7714 §14.1; CNSA 2.0).
const CNSA_SUITE: &str = "AEAD_AES_256_GCM";

/// `AEAD_AES_256_GCM` master key (32) plus master salt (12), in octets
/// (RFC 7714 §12).
const CNSA_KEYING_OCTETS: usize = 44;

/// Largest acceptable key lifetime: 2^48 packets, the SRTP maximum
/// (RFC 3711 §3.2.1).
const MAX_KEY_LIFETIME: u64 = 1 << 48;

/// Largest MKI length in octets (RFC 4568 §9.2: `mki-length` 1..=128).
const MAX_MKI_LENGTH: u16 = 128;

/// The DTLS fingerprint hashes that may cross and their digest lengths in
/// octets: CNSA 2.0 allows SHA-384 and SHA-512 (RFC 8122 §5 hash names).
const FINGERPRINT_HASHES: [(&str, usize); 2] = [("sha-384", 48), ("sha-512", 64)];

/// Who keys SRTP on the SBC's media relay (`media.srtp.mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyingMode {
    /// The relay forwards SRTP opaquely; the endpoints' keys cross the
    /// SBC in signalling.
    Passthrough,
    /// The SBC terminates DTLS-SRTP on each leg with its own identity.
    Terminate,
}

/// The configured media security policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSecurityPolicy {
    /// Who keys SRTP.
    pub mode: KeyingMode,
    /// `media.srtp.required`: no active stream other than
    /// `m=image ... udptl` crosses without SRTP keying (DTLS-SRTP, or SDES
    /// in passthrough mode). The SIP stack clears it for emergency calls.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-8(1), CM-6
    pub require_srtp: bool,
}

/// The offer/answer role of the SDP body (RFC 3264).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpRole {
    /// An offer: unacceptable keying lines are stripped.
    Offer,
    /// An answer: unacceptable SDES and MIKEY keying is refused, not
    /// stripped. Only lines that never cross in any case are removed:
    /// `a=crypto` on a declined section, on a DTLS m-line, or in terminate
    /// mode, and `a=fingerprint` lines with a hash that is not accepted.
    Answer,
}

/// Signalling confidentiality of the two hops the SDP crosses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegContext {
    /// The hop the SDP arrived on is confidential and integrity-protected
    /// (SIP over TLS).
    pub from_confidential: bool,
    /// The hop the SDP is sent on is confidential and integrity-protected.
    pub to_confidential: bool,
}

/// How the active streams of a body that may cross are keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKeying {
    /// DTLS-SRTP (fingerprint on a DTLS m-line), no SDES left.
    DtlsSrtp,
    /// At least one active stream keeps an SDES line.
    Sdes,
    /// Active streams carry no keying.
    Cleartext,
    /// Every m-line is declined (port 0), or there is none.
    NoActiveStream,
}

/// A body that may cross, as it crosses.
#[derive(Debug, Clone)]
pub struct Secured<'a> {
    /// The body to forward. Borrowed when nothing was stripped.
    pub sdp: Cow<'a, str>,
    /// How the active streams are keyed.
    pub keying: LegKeying,
    /// `a=crypto` lines removed.
    pub stripped_crypto: u16,
    /// `a=key-mgmt` lines removed.
    pub stripped_key_mgmt: u16,
    /// `a=fingerprint` lines removed (not sha-384 or sha-512, or malformed).
    pub stripped_fingerprints: u16,
}

/// The peer's DTLS attributes for the stream the relay anchors: the first
/// active m-line other than `m=image ... udptl`, when it is a DTLS profile.
/// See [`anchored_dtls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredDtls<'a> {
    /// Zero-based index of the m-line.
    pub index: usize,
    /// `<hash> <value>` of the first accepted `a=fingerprint` applying to
    /// it (media level, else session level), trimmed.
    pub fingerprint: &'a str,
    /// The `a=setup` value applying to it (media level, else session
    /// level), trimmed.
    pub setup: Option<&'a str>,
}

/// Why a body may not cross. `index` is the zero-based m-line; a
/// session-level attribute is reported against index 0. Labels and
/// `Warning` texts are fixed and never carry SDP content (SI-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MediaPolicyViolation {
    /// The body has a NUL or a bare CR, an m-line that does not parse, or
    /// the tokenizer and `proto-sdp` disagree on its m-lines.
    MalformedSdp,
    /// No SDES line is acceptable (suite, key length, session parameters),
    /// or an answer does not carry exactly one acceptable line.
    NoAcceptableCryptoSuite {
        /// The m-line.
        index: usize,
    },
    /// SDES keying on a hop whose signalling is not confidential.
    SdesOverInsecureSignalling {
        /// The m-line.
        index: usize,
    },
    /// Terminate mode: the section has SDES keying only, which the SBC does
    /// not terminate.
    SdesNotTerminable {
        /// The m-line.
        index: usize,
    },
    /// `a=key-mgmt` in an answer, or as the only keying of a section.
    UnsupportedKeyManagement {
        /// The m-line.
        index: usize,
    },
    /// An SDP part inside a `multipart/*` body. The SIP stack does not walk
    /// MIME parts on relayed bodies, so it refuses them (fail closed).
    SdpInMultipart,
    /// A relayed body the SIP stack cannot police: it has a non-identity
    /// `Content-Encoding`, or it is not `application/sdp` and carries SDES
    /// or MIKEY keying attributes (fail closed).
    UnpolicedBody,
    /// `require_srtp`: an active stream is cleartext RTP (`RTP/AVP(F)`, or
    /// `RTP/SAVP(F)` with no keying left).
    CleartextMedia {
        /// The m-line.
        index: usize,
    },
    /// `require_srtp`: an active stream's transport protocol is not one the
    /// policy accepts (`UDP`, `TCP`, `udptl` outside `m=image`,
    /// `TCP/TLS/RTP/AVP(F)`, unknown), or an answer puts a stream of
    /// another media type where the offer had audio.
    UnsupportedProtocol {
        /// The m-line.
        index: usize,
    },
    /// An active DTLS m-line has no applicable `a=fingerprint` line.
    FingerprintMissing {
        /// The m-line.
        index: usize,
    },
    /// An active DTLS m-line keeps no accepted `a=fingerprint` line (every
    /// applicable one has another hash, or a malformed value).
    FingerprintHashNotAllowed {
        /// The m-line.
        index: usize,
    },
    /// `require_srtp`: an initial INVITE without an SDP offer. The offer
    /// would arrive in the callee's 2xx and its answer in the ACK, after the
    /// call is answered, so it is refused up front.
    DelayedOffer,
    /// `media.srtp.mode = Terminate` but the SBC has no DTLS identity to
    /// terminate with (for example, the remote media plane reported none).
    TerminationUnavailable,
}

impl MediaPolicyViolation {
    /// Bounded label for metrics and audit (`media_security:<label>`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MalformedSdp => "malformed_sdp",
            Self::NoAcceptableCryptoSuite { .. } => "no_acceptable_crypto_suite",
            Self::SdesOverInsecureSignalling { .. } => "sdes_over_insecure_signalling",
            Self::SdesNotTerminable { .. } => "sdes_not_terminable",
            Self::UnsupportedKeyManagement { .. } => "unsupported_key_management",
            Self::SdpInMultipart => "sdp_in_multipart",
            Self::UnpolicedBody => "unpoliced_body",
            Self::CleartextMedia { .. } => "cleartext_media",
            Self::UnsupportedProtocol { .. } => "unsupported_protocol",
            Self::FingerprintMissing { .. } => "fingerprint_missing",
            Self::FingerprintHashNotAllowed { .. } => "fingerprint_hash_not_allowed",
            Self::DelayedOffer => "delayed_offer",
            Self::TerminationUnavailable => "dtls_termination_unavailable",
        }
    }

    /// RFC 3261 §20.43 warn-code: 302 for a media transport protocol the
    /// SBC does not accept, 306 for an attribute it does not accept, 399 for
    /// a missing attribute, the signalling transport and termination rules.
    pub const fn warning_code(&self) -> u16 {
        match self {
            Self::CleartextMedia { .. } | Self::UnsupportedProtocol { .. } => 302,
            Self::NoAcceptableCryptoSuite { .. }
            | Self::UnsupportedKeyManagement { .. }
            | Self::FingerprintHashNotAllowed { .. } => 306,
            Self::MalformedSdp
            | Self::SdesOverInsecureSignalling { .. }
            | Self::SdesNotTerminable { .. }
            | Self::SdpInMultipart
            | Self::UnpolicedBody
            | Self::FingerprintMissing { .. }
            | Self::DelayedOffer
            | Self::TerminationUnavailable => 399,
        }
    }

    /// Fixed `Warning` text (no SDP content, SI-11).
    pub const fn warning_text(&self) -> &'static str {
        match self {
            Self::MalformedSdp => "Malformed session description",
            Self::NoAcceptableCryptoSuite { .. } => "No acceptable SRTP keying",
            Self::SdesOverInsecureSignalling { .. } => "SDES keying requires TLS on every hop",
            Self::SdesNotTerminable { .. } => "SDES keying cannot be terminated",
            Self::UnsupportedKeyManagement { .. } => "Key management method not supported",
            Self::SdpInMultipart => "SDP in a multipart body is not relayed",
            Self::UnpolicedBody => "Encoded or non-SDP keying body is not relayed",
            Self::CleartextMedia { .. } => "SRTP is required",
            Self::UnsupportedProtocol { .. } => "Media transport protocol not supported",
            Self::FingerprintMissing { .. } => "DTLS fingerprint required",
            Self::FingerprintHashNotAllowed { .. } => {
                "Only sha-384 and sha-512 DTLS fingerprints are accepted"
            }
            Self::DelayedOffer => "Delayed offer not supported when SRTP is required",
            Self::TerminationUnavailable => "DTLS-SRTP termination unavailable",
        }
    }

    /// The m-line the violation is reported against, if any.
    pub const fn index(&self) -> Option<usize> {
        match self {
            Self::MalformedSdp
            | Self::SdpInMultipart
            | Self::UnpolicedBody
            | Self::DelayedOffer
            | Self::TerminationUnavailable => None,
            Self::NoAcceptableCryptoSuite { index }
            | Self::SdesOverInsecureSignalling { index }
            | Self::SdesNotTerminable { index }
            | Self::UnsupportedKeyManagement { index }
            | Self::CleartextMedia { index }
            | Self::UnsupportedProtocol { index }
            | Self::FingerprintMissing { index }
            | Self::FingerprintHashNotAllowed { index } => Some(*index),
        }
    }
}

impl std::fmt::Display for MediaPolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one line is, for the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind {
    /// `m=`: a new section.
    Media,
    /// `a=crypto` (RFC 4568).
    Crypto,
    /// `a=key-mgmt` (RFC 4567).
    KeyMgmt,
    /// `a=fingerprint` (RFC 8122).
    Fingerprint,
    /// `a=setup` (RFC 4145); crosses unchanged.
    Setup,
    /// Anything else; crosses unchanged.
    Other,
}

/// The m-line transport protocol, as far as keying goes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Profile {
    /// Not an accepted profile (`UDP`, `TCP`, `udptl`,
    /// `TCP/TLS/RTP/AVP(F)`, unknown), or session level.
    #[default]
    Other,
    /// Cleartext RTP: `RTP/AVP`, `RTP/AVPF` (and `TCP/RTP/AVP(F)`).
    Avp,
    /// `RTP/SAVP(F)`: keyed by SDES or another key management method.
    Savp,
    /// `UDP/TLS/RTP/SAVP(F)` (RFC 5764 §8), `TCP/DTLS/RTP/SAVP(F)`
    /// (RFC 7850 §3), `TCP/TLS/RTP/SAVP(F)`, or the data-channel profiles
    /// `UDP/DTLS/SCTP` and `TCP/DTLS/SCTP` (RFC 8841 §4): keyed by DTLS, so
    /// the fingerprint rule applies and SDES on them never crosses.
    Dtls,
}

/// Facts about one section (or the session level) gathered in the first
/// pass.
#[derive(Debug, Default, Clone, Copy)]
struct Section {
    port_zero: bool,
    /// `m=image <port> udptl` (T.38): left to the SIP stack's T.38 rules.
    t38: bool,
    profile: Profile,
    /// `a=fingerprint` lines.
    fingerprints: u16,
    /// `a=fingerprint` lines with an accepted hash and a well-formed value.
    fingerprints_ok: u16,
    crypto: u16,
    crypto_ok: u16,
    key_mgmt: u16,
}

/// Which `a=crypto` lines of a section the second pass strips.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum CryptoStrip {
    /// None.
    #[default]
    Keep,
    /// The unacceptable ones (offers).
    Unacceptable,
    /// Every one.
    All,
}

/// What happens to a section's lines in the second pass.
#[derive(Debug, Default, Clone, Copy)]
struct Plan {
    crypto: CryptoStrip,
    strip_key_mgmt: bool,
    /// Strip the `a=fingerprint` lines that are not accepted.
    strip_bad_fingerprint: bool,
}

impl Plan {
    /// Whether this plan removes any line of `s`.
    fn strips_any(self, s: &Section) -> bool {
        (s.crypto > 0
            && (self.crypto == CryptoStrip::All
                || (self.crypto == CryptoStrip::Unacceptable && s.crypto_ok < s.crypto)))
            || (s.key_mgmt > 0 && self.strip_key_mgmt)
            || (self.strip_bad_fingerprint && s.fingerprints_ok < s.fingerprints)
    }
}

/// The first pass over a body: session-level facts, one entry per m-line,
/// and the verdict of each `a=crypto` and `a=fingerprint` line in body
/// order.
struct Scan {
    session: Section,
    sections: Vec<Section>,
    crypto_ok: Vec<bool>,
    fingerprint_ok: Vec<bool>,
}

/// Classifies every line of `sdp` and gathers per-section facts.
fn scan(sdp: &str) -> Result<Scan, MediaPolicyViolation> {
    check_line_structure(sdp)?;
    let mut out = Scan {
        session: Section::default(),
        sections: Vec::new(),
        crypto_ok: Vec::new(),
        fingerprint_ok: Vec::new(),
    };
    for raw in sdp.split_inclusive('\n') {
        let (kind, value) = classify(raw);
        if kind == LineKind::Media {
            out.sections.push(parse_mline(value)?);
            continue;
        }
        let current = out.sections.last_mut().unwrap_or(&mut out.session);
        match kind {
            LineKind::Crypto => {
                let ok = crypto_line_acceptable(value);
                current.crypto = current.crypto.saturating_add(1);
                if ok {
                    current.crypto_ok = current.crypto_ok.saturating_add(1);
                }
                out.crypto_ok.push(ok);
            }
            LineKind::KeyMgmt => current.key_mgmt = current.key_mgmt.saturating_add(1),
            LineKind::Fingerprint => {
                let ok = fingerprint_acceptable(value);
                current.fingerprints = current.fingerprints.saturating_add(1);
                if ok {
                    current.fingerprints_ok = current.fingerprints_ok.saturating_add(1);
                }
                out.fingerprint_ok.push(ok);
            }
            LineKind::Media | LineKind::Setup | LineKind::Other => {}
        }
    }
    Ok(out)
}

/// Applies the media security policy to `sdp` crossing from one leg to the
/// other. Returns the body to forward, or why it may not cross.
///
/// ## NIST 800-53 Rev5: SC-8, SC-8(1), SC-12, SC-13, CM-6, SI-10
pub fn apply_media_security<'a>(
    sdp: &'a str,
    role: SdpRole,
    policy: &MediaSecurityPolicy,
    legs: &LegContext,
) -> Result<Secured<'a>, MediaPolicyViolation> {
    // Pass 1: classify every line and gather per-section facts.
    let scanned = scan(sdp)?;
    let (session, sections) = (&scanned.session, &scanned.sections);
    cross_check(sdp, sections)?;

    // Decide: session level first, then each section in order.
    let session_plan = plan_session(session, role)?;
    let mut plans: Vec<Plan> = Vec::with_capacity(sections.len());
    let mut keying = LegKeying::NoActiveStream;
    for (index, section) in sections.iter().enumerate() {
        let (plan, section_keying) = plan_section(index, section, session, role, policy, legs)?;
        keying = merge_keying(keying, section_keying);
        plans.push(plan);
    }

    // Pass 2: rewrite only when something is stripped.
    let needs_rewrite = session_plan.strips_any(session)
        || plans.iter().zip(sections).any(|(p, s)| p.strips_any(s));
    if !needs_rewrite {
        return Ok(Secured {
            sdp: Cow::Borrowed(sdp),
            keying,
            stripped_crypto: 0,
            stripped_key_mgmt: 0,
            stripped_fingerprints: 0,
        });
    }
    let mut secured = rewrite(sdp, session_plan, &plans, &scanned);
    secured.keying = keying;
    Ok(secured)
}

/// Pass 2: copies `sdp` without the lines the plans strip.
fn rewrite<'a>(sdp: &str, session_plan: Plan, plans: &[Plan], scanned: &Scan) -> Secured<'a> {
    let mut out = String::with_capacity(sdp.len());
    let (mut stripped_crypto, mut stripped_key_mgmt, mut stripped_fingerprints) =
        (0u16, 0u16, 0u16);
    let mut plan = session_plan;
    let mut next_section = 0usize;
    let mut crypto_verdicts = scanned.crypto_ok.iter();
    let mut fingerprint_verdicts = scanned.fingerprint_ok.iter();
    for raw in sdp.split_inclusive('\n') {
        let (kind, _) = classify(raw);
        let (strip, counter) = match kind {
            LineKind::Media => {
                plan = plans.get(next_section).copied().unwrap_or_default();
                next_section += 1;
                (false, None)
            }
            LineKind::Crypto => {
                let ok = crypto_verdicts.next().copied().unwrap_or(false);
                (
                    plan.crypto == CryptoStrip::All
                        || (plan.crypto == CryptoStrip::Unacceptable && !ok),
                    Some(&mut stripped_crypto),
                )
            }
            LineKind::KeyMgmt => (plan.strip_key_mgmt, Some(&mut stripped_key_mgmt)),
            LineKind::Fingerprint => {
                let ok = fingerprint_verdicts.next().copied().unwrap_or(false);
                (
                    plan.strip_bad_fingerprint && !ok,
                    Some(&mut stripped_fingerprints),
                )
            }
            LineKind::Setup | LineKind::Other => (false, None),
        };
        if strip {
            if let Some(n) = counter {
                *n = n.saturating_add(1);
            }
        } else {
            out.push_str(raw);
        }
    }
    Secured {
        sdp: Cow::Owned(out),
        keying: LegKeying::NoActiveStream,
        stripped_crypto,
        stripped_key_mgmt,
        stripped_fingerprints,
    }
}

/// How the active streams of `sdp` are keyed, read without applying the
/// policy.
///
/// A DTLS m-line with an accepted fingerprint (media or session level) is
/// DTLS-SRTP, an `RTP/SAVP(F)` m-line with an `a=crypto` line is SDES, any
/// other active stream is cleartext. `m=image ... udptl` and declined
/// m-lines do not count. One cleartext active stream makes the body
/// cleartext; then SDES wins over DTLS-SRTP. A body that cannot be
/// tokenized is cleartext (fail closed).
///
/// ## NIST 800-53 Rev5: SC-8, SC-24
pub fn classify_keying(sdp: &str) -> LegKeying {
    let Ok(scanned) = scan(sdp) else {
        return LegKeying::Cleartext;
    };
    let session_fp = scanned.session.fingerprints_ok > 0;
    let mut keying = LegKeying::NoActiveStream;
    for s in scanned.sections.iter().filter(|s| !s.port_zero && !s.t38) {
        let section = match s.profile {
            Profile::Dtls if s.fingerprints_ok > 0 || session_fp => LegKeying::DtlsSrtp,
            Profile::Savp if s.crypto > 0 => LegKeying::Sdes,
            _ => return LegKeying::Cleartext,
        };
        keying = merge_keying(keying, section);
    }
    keying
}

/// The peer's DTLS attributes for the stream the relay anchors.
///
/// Read with the policy's own tokenizer (case-insensitive names,
/// `proto-sdp` trim) from the first active m-line other than
/// `m=image ... udptl`. `None` when the body cannot be tokenized, that
/// m-line is not a DTLS profile, or no accepted fingerprint applies to it.
/// Declined sections are never read.
///
/// ## NIST 800-53 Rev5: SC-8, SC-23, SI-10; RFC 8122 §5; RFC 4145 §4
#[must_use]
pub fn anchored_dtls(sdp: &str) -> Option<AnchoredDtls<'_>> {
    #[derive(Default)]
    struct Found<'a> {
        fingerprint: Option<&'a str>,
        setup: Option<&'a str>,
    }
    let scanned = scan(sdp).ok()?;
    let index = scanned
        .sections
        .iter()
        .position(|s| !s.port_zero && !s.t38)?;
    if scanned.sections.get(index)?.profile != Profile::Dtls {
        return None;
    }
    let (mut session, mut media) = (Found::default(), Found::default());
    let mut section: Option<usize> = None;
    for raw in sdp.split_inclusive('\n') {
        let (kind, value) = classify(raw);
        let found = match (kind, section) {
            (LineKind::Media, _) => {
                section = Some(section.map_or(0, |i| i + 1));
                continue;
            }
            (_, None) => &mut session,
            (_, Some(i)) if i == index => &mut media,
            _ => continue,
        };
        match kind {
            LineKind::Fingerprint
                if found.fingerprint.is_none() && fingerprint_acceptable(value) =>
            {
                found.fingerprint = Some(value.trim());
            }
            LineKind::Setup if found.setup.is_none() => found.setup = Some(value.trim()),
            _ => {}
        }
    }
    Some(AnchoredDtls {
        index,
        fingerprint: media.fingerprint.or(session.fingerprint)?,
        setup: media.setup.or(session.setup),
    })
}

/// An answer that declines every stream of `offer`.
///
/// RFC 3264 §6: same m-line count and order, port 0, one of the offered
/// formats; the SBC's `origin` address is in `o=`/`c=`. Used when an offer
/// the policy refused still needs an answer (an offer in a 2xx is answered
/// in the ACK, RFC 3261 §13.2.2.4). `None` when the offer cannot be
/// tokenized or a field to echo is not a plain token (nothing from it is
/// echoed then).
///
/// ## NIST 800-53 Rev5: SI-10; RFC 3264 §6, §8
pub fn declined_answer(offer: &str, origin: std::net::IpAddr) -> Option<String> {
    use std::fmt::Write as _;
    // RFC 8866 §9 token characters, enough for media, proto and fmt.
    let token = |v: &str| {
        !v.is_empty()
            && v.len() <= 64
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_' | b'+'))
    };
    check_line_structure(offer).ok()?;
    let ip = match origin {
        std::net::IpAddr::V4(a) => format!("IP4 {a}"),
        std::net::IpAddr::V6(a) => format!("IP6 {a}"),
    };
    let mut out = format!("v=0\r\no=- 0 0 IN {ip}\r\ns=-\r\nc=IN {ip}\r\nt=0 0\r\n");
    let mut mlines = 0usize;
    for raw in offer.split_inclusive('\n') {
        let (kind, value) = classify(raw);
        if kind != LineKind::Media {
            continue;
        }
        parse_mline(value).ok()?;
        let mut fields = value.split_ascii_whitespace();
        let (Some(media), Some(_port), Some(proto), Some(fmt)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        if !(token(media) && token(proto) && token(fmt)) {
            return None;
        }
        let _ = write!(out, "m={media} 0 {proto} {fmt}\r\n");
        mlines += 1;
    }
    (mlines > 0).then_some(out)
}

/// SI-10: refuses a NUL anywhere and a CR not followed by LF, so line
/// boundaries are the same for every parser.
fn check_line_structure(sdp: &str) -> Result<(), MediaPolicyViolation> {
    let bytes = sdp.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match *b {
            0 => return Err(MediaPolicyViolation::MalformedSdp),
            b'\r' if bytes.get(i + 1) != Some(&b'\n') => {
                return Err(MediaPolicyViolation::MalformedSdp);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Classifies one raw line (terminator included). Returns the kind and the
/// value after `m=` or after the attribute name and its `:`.
fn classify(raw: &str) -> (LineKind, &str) {
    // The same trim `proto-sdp` applies before reading the type letter.
    let line = raw.trim();
    let Some((letter, rest)) = line.split_at_checked(2) else {
        return (LineKind::Other, "");
    };
    if letter.eq_ignore_ascii_case("m=") {
        return (LineKind::Media, rest);
    }
    if !letter.eq_ignore_ascii_case("a=") {
        return (LineKind::Other, "");
    }
    let (name, value) = rest.split_once(':').unwrap_or((rest, ""));
    let name = name.trim();
    let kind = if name.eq_ignore_ascii_case("crypto") {
        LineKind::Crypto
    } else if name.eq_ignore_ascii_case("key-mgmt") {
        LineKind::KeyMgmt
    } else if name.eq_ignore_ascii_case("fingerprint") {
        LineKind::Fingerprint
    } else if name.eq_ignore_ascii_case("setup") {
        LineKind::Setup
    } else {
        LineKind::Other
    };
    (kind, value)
}

/// Parses `<media> <port>[/<n>] <proto> ...` (RFC 8866 §5.14).
fn parse_mline(value: &str) -> Result<Section, MediaPolicyViolation> {
    let mut fields = value.split_ascii_whitespace();
    let (Some(media), Some(port), Some(proto)) = (fields.next(), fields.next(), fields.next())
    else {
        return Err(MediaPolicyViolation::MalformedSdp);
    };
    let port = port.split_once('/').map_or(port, |(p, _)| p);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MediaPolicyViolation::MalformedSdp);
    }
    let port: u16 = port
        .parse()
        .map_err(|_| MediaPolicyViolation::MalformedSdp)?;
    // RFC 5764 §8 (UDP/TLS), RFC 7850 §3 (TCP/DTLS), RFC 8841 §4 (DTLS/SCTP
    // data channels). TCP/TLS/RTP/SAVP(F) stays on the list so SDES never
    // crosses on it either.
    let dtls = [
        "UDP/TLS/RTP/SAVP",
        "UDP/TLS/RTP/SAVPF",
        "TCP/DTLS/RTP/SAVP",
        "TCP/DTLS/RTP/SAVPF",
        "TCP/TLS/RTP/SAVP",
        "TCP/TLS/RTP/SAVPF",
        "UDP/DTLS/SCTP",
        "TCP/DTLS/SCTP",
    ]
    .iter()
    .any(|p| proto.eq_ignore_ascii_case(p));
    // TLS around cleartext RTP (`TCP/TLS/RTP/AVP(F)`) is neither SRTP nor
    // plain RTP to the relay: an unsupported protocol.
    let tls_avp = proto
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("TCP/TLS/"));
    let tail = proto.rsplit('/').next().unwrap_or("");
    let profile = if dtls {
        Profile::Dtls
    } else if tls_avp {
        Profile::Other
    } else if tail.eq_ignore_ascii_case("SAVP") || tail.eq_ignore_ascii_case("SAVPF") {
        Profile::Savp
    } else if tail.eq_ignore_ascii_case("AVP") || tail.eq_ignore_ascii_case("AVPF") {
        Profile::Avp
    } else {
        Profile::Other
    };
    Ok(Section {
        port_zero: port == 0,
        // Only UDPTL is T.38 (RFC 3362); any other `m=image` protocol is
        // policed like any m-line.
        t38: media.eq_ignore_ascii_case("image") && proto.eq_ignore_ascii_case("udptl"),
        profile,
        ..Section::default()
    })
}

/// SI-10: when `proto-sdp` reads the body, it must see the same m-lines
/// (count and ports) as the tokenizer. A body `proto-sdp` rejects is left to
/// the tokenizer, which is the stricter of the two on line structure.
fn cross_check(sdp: &str, sections: &[Section]) -> Result<(), MediaPolicyViolation> {
    let Ok(parsed) = sdp.parse::<SessionDescription>() else {
        return Ok(());
    };
    if parsed.media.len() != sections.len()
        || parsed
            .media
            .iter()
            .zip(sections)
            .any(|(m, s)| (m.port == 0) != s.port_zero)
    {
        return Err(MediaPolicyViolation::MalformedSdp);
    }
    Ok(())
}

/// RFC 4568 §9.1 (`a=crypto` is media-level only) and RFC 4567 at session
/// level: stripped from offers, refused in answers. A session-level
/// `a=fingerprint` that is not accepted is stripped from offers and answers
/// alike (RFC 8122 §5; CNSA 2.0): it either does not apply (every DTLS
/// m-line has media-level lines) or would bind to a hash CNSA 2.0 does not
/// allow.
fn plan_session(session: &Section, role: SdpRole) -> Result<Plan, MediaPolicyViolation> {
    if role == SdpRole::Answer {
        if session.crypto > 0 {
            return Err(MediaPolicyViolation::NoAcceptableCryptoSuite { index: 0 });
        }
        if session.key_mgmt > 0 {
            return Err(MediaPolicyViolation::UnsupportedKeyManagement { index: 0 });
        }
    }
    Ok(Plan {
        crypto: CryptoStrip::All,
        strip_key_mgmt: true,
        strip_bad_fingerprint: true,
    })
}

/// Decides one section. Returns its plan and keying, or the refusal.
fn plan_section(
    index: usize,
    s: &Section,
    session: &Section,
    role: SdpRole,
    policy: &MediaSecurityPolicy,
    legs: &LegContext,
) -> Result<(Plan, LegKeying), MediaPolicyViolation> {
    // RFC 3264 §8: a declined section keeps no keying and is not checked.
    if s.port_zero {
        return Ok((
            Plan {
                crypto: CryptoStrip::All,
                strip_key_mgmt: true,
                strip_bad_fingerprint: false,
            },
            LegKeying::NoActiveStream,
        ));
    }
    let dtls_keyed = check_fingerprints(index, s, session)?;

    // RFC 4567: MIKEY is not supported; an answer cannot be rewritten.
    if s.key_mgmt > 0 && role == SdpRole::Answer {
        return Err(MediaPolicyViolation::UnsupportedKeyManagement { index });
    }

    let (plan, surviving_crypto) = plan_sdes(index, s, role, policy, legs, dtls_keyed)?;

    // `a=key-mgmt` (here or at session level) as the only keying left.
    let had_key_mgmt = s.key_mgmt > 0
        || (session.key_mgmt > 0 && matches!(s.profile, Profile::Savp | Profile::Dtls));
    if had_key_mgmt && surviving_crypto == 0 && !dtls_keyed {
        return Err(MediaPolicyViolation::UnsupportedKeyManagement { index });
    }

    let keying = if surviving_crypto > 0 {
        LegKeying::Sdes
    } else if dtls_keyed {
        LegKeying::DtlsSrtp
    } else {
        LegKeying::Cleartext
    };
    check_required(index, s, policy, keying)?;
    Ok((plan, keying))
}

/// The DTLS fingerprint rule for one active section (RFC 8122 §5, RFC 5763
/// §5; CNSA 2.0), whatever `require_srtp` says. Returns whether a DTLS
/// m-line is keyed by an accepted fingerprint that crosses.
///
/// Offers and answers lose the lines that are not accepted in the rewrite
/// (on any active m-line); media-level lines apply, and when none is left
/// the session-level ones do. No applicable line at all is
/// `FingerprintMissing` (399); only unaccepted ones is
/// `FingerprintHashNotAllowed` (306).
///
/// ## NIST 800-53 Rev5: SC-8, SC-13, SC-23, SI-10
fn check_fingerprints(
    index: usize,
    s: &Section,
    session: &Section,
) -> Result<bool, MediaPolicyViolation> {
    if s.profile != Profile::Dtls {
        return Ok(false);
    }
    if s.fingerprints_ok > 0 || session.fingerprints_ok > 0 {
        return Ok(true);
    }
    if s.fingerprints == 0 && session.fingerprints == 0 {
        Err(MediaPolicyViolation::FingerprintMissing { index })
    } else {
        Err(MediaPolicyViolation::FingerprintHashNotAllowed { index })
    }
}

/// The SDES rules for one active section. Returns its plan and how many
/// `a=crypto` lines cross.
///
/// ## NIST 800-53 Rev5: SC-8, SC-12, SC-13
fn plan_sdes(
    index: usize,
    s: &Section,
    role: SdpRole,
    policy: &MediaSecurityPolicy,
    legs: &LegContext,
    dtls_keyed: bool,
) -> Result<(Plan, u16), MediaPolicyViolation> {
    let mut plan = Plan {
        crypto: CryptoStrip::Keep,
        strip_key_mgmt: true,
        strip_bad_fingerprint: true,
    };
    if s.crypto == 0 {
        return Ok((plan, 0));
    }
    if s.profile == Profile::Dtls || policy.mode == KeyingMode::Terminate {
        // Terminate mode keys every leg itself; a DTLS m-line is keyed by
        // DTLS (RFC 5764). The SDES key never crosses.
        plan.crypto = CryptoStrip::All;
        if policy.mode == KeyingMode::Terminate && !dtls_keyed {
            return Err(MediaPolicyViolation::SdesNotTerminable { index });
        }
        return Ok((plan, 0));
    }
    // RFC 4568 §8 / §8.3: the key may only cross confidential hops.
    if !(legs.from_confidential && legs.to_confidential) {
        return Err(MediaPolicyViolation::SdesOverInsecureSignalling { index });
    }
    match role {
        SdpRole::Offer => {
            if s.crypto_ok == 0 {
                return Err(MediaPolicyViolation::NoAcceptableCryptoSuite { index });
            }
            plan.crypto = CryptoStrip::Unacceptable;
            Ok((plan, s.crypto_ok))
        }
        // RFC 4568 §7.1.2: exactly one crypto attribute.
        SdpRole::Answer => {
            if s.crypto != 1 || s.crypto_ok != 1 {
                return Err(MediaPolicyViolation::NoAcceptableCryptoSuite { index });
            }
            Ok((plan, 1))
        }
    }
}

/// `require_srtp` (`media.srtp.required`) for one active section: it must
/// be SRTP-keyed once the other rules have run. `m=image ... udptl` is left
/// to the SIP stack's T.38 rules. In terminate mode SDES never survives
/// ([`plan_sdes`]), so only DTLS passes there.
///
/// ## NIST 800-53 Rev5: SC-8, SC-8(1), CM-6
// POAM: POA&M-353 - one failing active m-line refuses the whole SDP; the
// stream is not declined in place, so an offer mixing secured audio with a
// non-RTP stream over TLS (BFCP, MSRP) is refused as a whole.
fn check_required(
    index: usize,
    s: &Section,
    policy: &MediaSecurityPolicy,
    keying: LegKeying,
) -> Result<(), MediaPolicyViolation> {
    // An SDES line on a cleartext profile does not make it SRTP
    // (RFC 4568 §3.1: `a=crypto` is for `RTP/SAVP(F)`).
    let keyed = matches!(
        (s.profile, keying),
        (Profile::Savp, LegKeying::Sdes) | (Profile::Dtls, LegKeying::DtlsSrtp)
    );
    if !policy.require_srtp || s.t38 || keyed {
        return Ok(());
    }
    match s.profile {
        Profile::Avp | Profile::Savp | Profile::Dtls => {
            Err(MediaPolicyViolation::CleartextMedia { index })
        }
        Profile::Other => Err(MediaPolicyViolation::UnsupportedProtocol { index }),
    }
}

/// The body's keying from its sections': any SDES wins, then DTLS-SRTP,
/// then cleartext; declined sections do not count.
fn merge_keying(acc: LegKeying, section: LegKeying) -> LegKeying {
    use LegKeying::{Cleartext, DtlsSrtp, NoActiveStream, Sdes};
    match (acc, section) {
        (Sdes, _) | (_, Sdes) => Sdes,
        (DtlsSrtp, _) | (_, DtlsSrtp) => DtlsSrtp,
        (Cleartext, _) | (_, Cleartext) => Cleartext,
        (NoActiveStream, NoActiveStream) => NoActiveStream,
    }
}

/// Whether `<hash> <value>` of one `a=fingerprint` may cross.
///
/// The value is what follows `fingerprint:`. The hash must be `sha-384` or
/// `sha-512` (CNSA 2.0 allows SHA-384 and SHA-512; ASCII
/// case-insensitive), with 48 or 64 colon-separated two-digit hex octets
/// to match (RFC 8122 §5).
///
/// ## NIST 800-53 Rev5: SC-13, SC-23, SI-10
#[must_use]
pub fn fingerprint_acceptable(value: &str) -> bool {
    let mut fields = value.split_ascii_whitespace();
    let (Some(hash), Some(digest), None) = (fields.next(), fields.next(), fields.next()) else {
        return false;
    };
    let Some(&(_, want)) = FINGERPRINT_HASHES
        .iter()
        .find(|(name, _)| hash.eq_ignore_ascii_case(name))
    else {
        return false;
    };
    let mut octets = 0usize;
    for octet in digest.split(':') {
        octets += 1;
        if octets > want || octet.len() != 2 || !octet.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    octets == want
}

/// Whether one `a=crypto` value (after `crypto:`) may cross: tag, the CNSA
/// suite, exactly one well-formed inline key of the right length, and only
/// allow-listed session parameters (see the module rules).
///
/// ## NIST 800-53 Rev5: SC-13, SI-10; RFC 4568 §6.3, §9.1, §9.2; RFC 7714 §14.1
fn crypto_line_acceptable(value: &str) -> bool {
    let value = value.trim();
    let mut fields = value.splitn(4, ' ');
    let (Some(tag), Some(suite), Some(key_params)) = (fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    let session_params = fields.next().unwrap_or("");
    // RFC 4568 §9.1: tag = 1*9DIGIT.
    if tag.is_empty() || tag.len() > 9 || !tag.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !suite.eq_ignore_ascii_case(CNSA_SUITE) {
        return false;
    }
    // Exactly one key-param (RFC 4568 §9.1 allows a list): every extra key
    // needs an MKI the relay does not track, and only one key is checked.
    if key_params.contains(';') {
        return false;
    }
    inline_key_acceptable(tag, key_params) && session_params_acceptable(session_params)
}

/// `inline:<key||salt>[|lifetime][|mki:length]` (RFC 4568 §6.1, §9.2): a
/// 44-octet key, a lifetime of at most 2^48 and a well-formed MKI.
fn inline_key_acceptable(tag: &str, key_param: &str) -> bool {
    const INLINE: &str = "inline:";
    let Some(info) = key_param
        .get(..INLINE.len())
        .filter(|p| p.eq_ignore_ascii_case(INLINE))
        .and_then(|_| key_param.get(INLINE.len()..))
    else {
        return false;
    };
    let mut parts = info.split('|');
    let key = parts.next().unwrap_or("");
    let (lifetime, mki) = match (parts.next(), parts.next(), parts.next()) {
        (None, _, _) => (None, None),
        // One optional field: an MKI has a ':', a lifetime does not.
        (Some(one), None, _) if one.contains(':') => (None, Some(one)),
        (Some(one), None, _) => (Some(one), None),
        (Some(l), Some(m), None) => (Some(l), Some(m)),
        (Some(_), Some(_), Some(_)) => return false,
    };
    if !lifetime.is_none_or(lifetime_acceptable) || !mki.is_none_or(mki_acceptable) {
        return false;
    }
    // The key length is read from the decoded key alone.
    CryptoAttribute::parse(&format!("{tag} {CNSA_SUITE} inline:{key}")).is_ok_and(|attr| {
        attr.validate().is_ok() && attr.key_params.key_material().len() == CNSA_KEYING_OCTETS
    })
}

/// Whether `v` is 1 to `max` ASCII digits.
fn digits(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && v.bytes().all(|b| b.is_ascii_digit())
}

/// `lifetime = ["2^"] 1*(DIGIT)`, 1 to 2^48 packets (RFC 3711 §3.2.1).
fn lifetime_acceptable(lifetime: &str) -> bool {
    let packets = match lifetime.strip_prefix("2^") {
        Some(exp) if digits(exp, 2) => exp.parse::<u32>().ok().and_then(|e| 2u64.checked_pow(e)),
        Some(_) => None,
        None if digits(lifetime, 20) => lifetime.parse::<u64>().ok(),
        None => None,
    };
    packets.is_some_and(|n| (1..=MAX_KEY_LIFETIME).contains(&n))
}

/// `mki = mki-value ":" mki-length`, `mki-value = 1*128DIGIT`,
/// `mki-length = 1*3DIGIT` in 1..=128 (RFC 4568 §9.2).
fn mki_acceptable(mki: &str) -> bool {
    let Some((value, length)) = mki.split_once(':') else {
        return false;
    };
    digits(value, 128)
        && digits(length, 3)
        && length
            .parse::<u16>()
            .is_ok_and(|n| (1..=MAX_MKI_LENGTH).contains(&n))
}

/// Session parameters (RFC 4568 §6.3), an allow-list: `KDR=` 0..=24
/// (§6.3.1), `WSH=` at least 64 (§6.3.6) and `FEC_ORDER=` (§6.3.4), each at
/// most once. Anything else, `FEC_KEY` and the parameters that switch
/// protection off included, makes the line unacceptable.
fn session_params_acceptable(params: &str) -> bool {
    let (mut kdr, mut wsh, mut fec_order) = (false, false, false);
    params.split_ascii_whitespace().all(|p| {
        let Some((name, value)) = p.split_once('=') else {
            return false;
        };
        let (seen, ok) = if name.eq_ignore_ascii_case("KDR") {
            (
                &mut kdr,
                digits(value, 2) && value.parse::<u8>().is_ok_and(|n| n <= 24),
            )
        } else if name.eq_ignore_ascii_case("WSH") {
            (
                &mut wsh,
                digits(value, 10) && value.parse::<u32>().is_ok_and(|n| n >= 64),
            )
        } else if name.eq_ignore_ascii_case("FEC_ORDER") {
            (
                &mut fec_order,
                value.eq_ignore_ascii_case("FEC_SRTP") || value.eq_ignore_ascii_case("SRTP_FEC"),
            )
        } else {
            return false;
        };
        ok && !std::mem::replace(seen, true)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKis=";

    /// A sha-384 fingerprint: 48 octets of a fixed pattern, not a digest.
    const FP: &str = "sha-384 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:\
                      10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:\
                      20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F";

    #[test]
    fn fingerprint_value_checks() {
        assert!(fingerprint_acceptable(FP));
        assert!(fingerprint_acceptable(&FP.to_ascii_lowercase()));
        assert!(fingerprint_acceptable(
            &FP.replacen("sha-384", "SHA-384", 1)
        ));
        assert!(fingerprint_acceptable(&format!("  {FP}  ")));
        assert!(!fingerprint_acceptable(
            &FP.replacen("sha-384", "sha-256", 1)
        ));
        assert!(!fingerprint_acceptable(&FP.replacen("00", "0G", 1)));
        assert!(!fingerprint_acceptable(&FP.replacen("00:", "0:", 1)));
        assert!(!fingerprint_acceptable(&format!("{FP}:30")));
        assert!(!fingerprint_acceptable(&FP.replacen(":2F", "", 1)));
        assert!(!fingerprint_acceptable(&format!("{FP} extra")));
        assert!(!fingerprint_acceptable("sha-384"));
        assert!(!fingerprint_acceptable(""));
        // CNSA 2.0 also allows SHA-512: 64 octets, not 48.
        let sha512 = format!("SHA-512 {}", ["AB"; 64].join(":"));
        assert!(fingerprint_acceptable(&sha512));
        assert!(!fingerprint_acceptable(
            &FP.replacen("sha-384", "sha-512", 1)
        ));
        assert!(!fingerprint_acceptable(
            &sha512.replacen("SHA-512", "sha-384", 1)
        ));
        assert!(!fingerprint_acceptable(&format!(
            "md5 {}",
            ["AB"; 16].join(":")
        )));
    }

    /// The anchored stream's accepted fingerprint and setup: media level
    /// first, else session level; names matched case-insensitively and
    /// trimmed; declined sections and unaccepted hashes never read.
    #[test]
    fn anchored_dtls_reads_the_anchored_stream() {
        let sha256 = format!("sha-256 {}", ["CD"; 32].join(":"));
        let body = format!(
            "v=0\r\na=Fingerprint: {FP}\r\na=SETUP:actpass\r\n\
             m=audio 0 UDP/TLS/RTP/SAVP 0\r\na=fingerprint:{sha256}\r\na=setup:active\r\n\
             m=audio 4000 UDP/TLS/RTP/SAVP 0\r\n A=fingerprint:{sha256}\r\n"
        );
        let a = anchored_dtls(&body).unwrap();
        assert_eq!(a.index, 1);
        assert_eq!(a.fingerprint, FP);
        assert_eq!(a.setup, Some("actpass"));
        let media = format!(
            "v=0\r\nm=image 4100 udptl t38\r\nm=audio 4000 UDP/TLS/RTP/SAVP 0\r\n\
             a=fingerprint:{sha256}\r\na=fingerprint:{FP}\r\na=setup:passive\r\n"
        );
        let a = anchored_dtls(&media).unwrap();
        assert_eq!((a.index, a.fingerprint, a.setup), (1, FP, Some("passive")));
        // Not DTLS, only an unaccepted hash, or nothing active.
        assert!(anchored_dtls("v=0\r\nm=audio 4000 RTP/AVP 0\r\n").is_none());
        assert!(
            anchored_dtls(&format!(
                "v=0\r\nm=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=fingerprint:{sha256}\r\n"
            ))
            .is_none()
        );
        assert!(anchored_dtls("v=0\r\nm=audio 0 UDP/TLS/RTP/SAVP 0\r\n").is_none());
    }

    #[test]
    fn classify_keying_ignores_image_and_fails_closed() {
        let image = "v=0\r\nm=audio 0 RTP/AVP 0\r\nm=image 4100 udptl t38\r\n";
        assert_eq!(classify_keying(image), LegKeying::NoActiveStream);
        let sdes = format!(
            "v=0\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n\
             m=audio 4002 UDP/TLS/RTP/SAVP 0\r\na=fingerprint:{FP}\r\n"
        );
        assert_eq!(classify_keying(&sdes), LegKeying::Sdes);
        assert_eq!(
            classify_keying("v=0\r\nm=audio x\r\n"),
            LegKeying::Cleartext
        );
        assert_eq!(
            classify_keying("v=0\rm=audio 4000 RTP/AVP 0\r\n"),
            LegKeying::Cleartext
        );
    }

    #[test]
    fn crypto_line_checks() {
        assert!(crypto_line_acceptable(&format!(
            "1 AEAD_AES_256_GCM inline:{KEY_256}"
        )));
        assert!(crypto_line_acceptable(&format!(
            "1 aead_aes_256_gcm inline:{KEY_256}|2^31"
        )));
        assert!(!crypto_line_acceptable(&format!(
            "1 AEAD_AES_256_GCM inline:{KEY_256} unencrypted_srtp"
        )));
        assert!(!crypto_line_acceptable(&format!(
            "1234567890 AEAD_AES_256_GCM inline:{KEY_256}"
        )));
        assert!(!crypto_line_acceptable(&format!(
            "1 AEAD_AES_256_GCM inline:{KEY_256};inline:AAAA"
        )));
        // A longer key than the suite takes is not accepted either.
        assert!(!crypto_line_acceptable(&format!(
            "1 AEAD_AES_256_GCM inline:{KEY_256}AAAA"
        )));
        assert!(!crypto_line_acceptable("1 AEAD_AES_256_GCM"));
        assert!(!crypto_line_acceptable(""));
    }

    #[test]
    fn leading_whitespace_does_not_hide_a_line() {
        let body = format!(
            "v=0\r\nm=audio 4000 RTP/SAVP 0\r\n  a=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n"
        );
        let legs = LegContext {
            from_confidential: true,
            to_confidential: false,
        };
        let policy = MediaSecurityPolicy {
            mode: KeyingMode::Passthrough,
            require_srtp: false,
        };
        assert!(matches!(
            apply_media_security(&body, SdpRole::Offer, &policy, &legs),
            Err(MediaPolicyViolation::SdesOverInsecureSignalling { index: 0 })
        ));
    }

    #[test]
    fn session_level_key_mgmt_alone_is_refused_on_a_secure_profile() {
        let body = "v=0\r\na=key-mgmt:mikey AAAA\r\nm=audio 4000 RTP/SAVP 0\r\n";
        let legs = LegContext {
            from_confidential: true,
            to_confidential: true,
        };
        let policy = MediaSecurityPolicy {
            mode: KeyingMode::Passthrough,
            require_srtp: false,
        };
        assert!(matches!(
            apply_media_security(body, SdpRole::Offer, &policy, &legs),
            Err(MediaPolicyViolation::UnsupportedKeyManagement { index: 0 })
        ));
        // On a cleartext profile it is only stripped.
        let avp = body.replace("RTP/SAVP", "RTP/AVP");
        let s = apply_media_security(&avp, SdpRole::Offer, &policy, &legs).unwrap();
        assert_eq!(s.stripped_key_mgmt, 1);
        assert!(!s.sdp.contains("key-mgmt"));
    }

    /// RFC 4568 §9.2: one inline key; a well-formed MKI of 1..=128 octets.
    #[test]
    fn key_param_count_and_mki_are_checked() {
        let ok = |kp: &str| crypto_line_acceptable(&format!("1 AEAD_AES_256_GCM {kp}"));
        assert!(ok(&format!("inline:{KEY_256}|2^31|1:4")));
        assert!(ok(&format!("inline:{KEY_256}|1:4")));
        assert!(ok(&format!("inline:{KEY_256}|7:128")));
        // Two keys, with or without MKIs.
        assert!(!ok(&format!("inline:{KEY_256};inline:{KEY_256}")));
        assert!(!ok(&format!("inline:{KEY_256}|1:4;inline:{KEY_256}|2:4")));
        // Malformed MKIs.
        for mki in ["1:0", "1:129", "1:", ":4", "x:4", "1:4:4", "1:1000"] {
            assert!(!ok(&format!("inline:{KEY_256}|2^31|{mki}")), "{mki}");
        }
        // A fourth field.
        assert!(!ok(&format!("inline:{KEY_256}|2^31|1:4|x")));
        // Not inline.
        assert!(!ok(&format!("uri:{KEY_256}")));
    }

    /// RFC 3711 §3.2.1: a lifetime above 2^48 packets is not acceptable.
    #[test]
    fn lifetime_is_bounded_by_two_to_the_48() {
        let ok =
            |lt: &str| crypto_line_acceptable(&format!("1 AEAD_AES_256_GCM inline:{KEY_256}|{lt}"));
        assert!(ok("2^48"));
        assert!(ok("281474976710656"));
        assert!(ok("1048576"));
        assert!(!ok("2^49"));
        assert!(!ok("281474976710657"));
        assert!(!ok("2^64"));
        assert!(!ok("0"));
        assert!(!ok("+5"));
        assert!(!ok("2^"));
        assert!(!ok(""));
    }

    /// RFC 4568 §6.3: session parameters are an allow-list.
    #[test]
    fn session_params_are_allow_listed() {
        let ok =
            |sp: &str| crypto_line_acceptable(&format!("1 AEAD_AES_256_GCM inline:{KEY_256} {sp}"));
        assert!(ok("KDR=0"));
        assert!(ok("KDR=24 WSH=64 FEC_ORDER=FEC_SRTP"));
        assert!(ok("fec_order=srtp_fec"));
        for bad in [
            "KDR=25",
            "KDR=x",
            "WSH=63",
            "FEC_ORDER=OTHER",
            &format!("FEC_KEY=inline:{KEY_256}"),
            "UNENCRYPTED_SRTP",
            "UNENCRYPTED_SRTCP",
            "UNAUTHENTICATED_SRTP",
            "-VENDOR_EXT",
            "-X=1",
            "UNKNOWN=1",
            "KDR=1 KDR=2",
        ] {
            assert!(!ok(bad), "{bad}");
        }
    }

    /// RFC 7850 §3: TCP/DTLS/RTP/SAVP(F) is a DTLS profile; SDES on it never
    /// crosses, even TLS to TLS.
    #[test]
    fn tcp_dtls_profiles_strip_crypto() {
        let legs = LegContext {
            from_confidential: true,
            to_confidential: true,
        };
        let policy = MediaSecurityPolicy {
            mode: KeyingMode::Passthrough,
            require_srtp: false,
        };
        for proto in ["TCP/DTLS/RTP/SAVP", "TCP/DTLS/RTP/SAVPF"] {
            let body = format!(
                "v=0\r\nm=audio 9 {proto} 0\r\na=fingerprint:{FP}\r\na=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n"
            );
            let s = apply_media_security(&body, SdpRole::Offer, &policy, &legs).unwrap();
            assert!(!s.sdp.contains("a=crypto"), "{proto}: {}", s.sdp);
            assert_eq!(s.keying, LegKeying::DtlsSrtp, "{proto}");
        }
    }

    /// RFC 3264 §6: every offered stream declined, m-line count and order
    /// kept; nothing but plain tokens is echoed.
    #[test]
    fn declined_answer_rejects_every_stream() {
        let ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let offer = format!(
            "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=-\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n\
             m=audio 4000 RTP/SAVP 0 8\r\na=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n\
             m=image 4002 udptl t38\r\n"
        );
        let a = declined_answer(&offer, ip).unwrap();
        assert!(a.contains("o=- 0 0 IN IP4 192.0.2.10\r\n"), "{a}");
        assert!(
            a.contains("m=audio 0 RTP/SAVP 0\r\nm=image 0 udptl t38\r\n"),
            "{a}"
        );
        assert!(!a.contains("crypto"), "{a}");
        assert_eq!(a.matches("m=").count(), 2);
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(
            declined_answer(&offer, v6)
                .unwrap()
                .contains("IN IP6 2001:db8::1")
        );
        // Nothing to decline, or a field that is not a token.
        assert!(declined_answer("v=0\r\n", ip).is_none());
        assert!(declined_answer("v=0\r\nm=audio 4000 RTP/AVP\r\n", ip).is_none());
        assert!(declined_answer("v=0\r\nm=audio 4000 RTP/AVP 0\"<x>\r\n", ip).is_none());
        assert!(declined_answer("v=0\r\nm=audio 4000 RTP/AVP 0\rm=x\r\n", ip).is_none());
    }
}
