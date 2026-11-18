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
//! Cleartext profiles (`RTP/AVP`) are not refused here.
//!
//! One tokenizer classifies and rewrites. A body with a NUL or a bare CR
//! (a CR not followed by LF) is refused as malformed, so a lenient parser
//! further on cannot see a line this policy did not see. Line types and
//! attribute names are matched ASCII case-insensitively and after the same
//! whitespace trim `proto-sdp` applies. When `proto-sdp` parses the body,
//! its m-line count and ports must agree with the tokenizer's.
//!
//! ## NIST 800-53 Rev5: SC-8, SC-12, SC-13, CM-6, SI-10
//!
//! ## RFC 4568 §6.3, §7.1.2, §8, §9.1, §9.2; RFC 4567; RFC 7714 §14.1;
//! RFC 5764 §8; RFC 3264 §6, §8
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
}

/// The offer/answer role of the SDP body (RFC 3264).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpRole {
    /// An offer: unacceptable keying lines are stripped.
    Offer,
    /// An answer: unacceptable keying is refused, not stripped. Only
    /// lines that never cross in any case are removed: `a=crypto` on a
    /// declined section, on a DTLS m-line, or in terminate mode.
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
        }
    }

    /// RFC 3261 §20.43 warn-code: 306 for an attribute the SBC does not
    /// accept, 399 for the transport and termination rules.
    pub const fn warning_code(&self) -> u16 {
        match self {
            Self::NoAcceptableCryptoSuite { .. } | Self::UnsupportedKeyManagement { .. } => 306,
            Self::MalformedSdp
            | Self::SdesOverInsecureSignalling { .. }
            | Self::SdesNotTerminable { .. }
            | Self::SdpInMultipart
            | Self::UnpolicedBody => 399,
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
        }
    }

    /// The m-line the violation is reported against, if any.
    pub const fn index(&self) -> Option<usize> {
        match self {
            Self::MalformedSdp | Self::SdpInMultipart | Self::UnpolicedBody => None,
            Self::NoAcceptableCryptoSuite { index }
            | Self::SdesOverInsecureSignalling { index }
            | Self::SdesNotTerminable { index }
            | Self::UnsupportedKeyManagement { index } => Some(*index),
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
    /// Anything else; crosses unchanged.
    Other,
}

/// The m-line transport protocol, as far as keying goes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Profile {
    /// Not a secure RTP profile (`RTP/AVP`, `udptl`, ...), or session level.
    #[default]
    Other,
    /// `RTP/SAVP(F)`: keyed by SDES or another key management method.
    Savp,
    /// `UDP/TLS/RTP/SAVP(F)` (RFC 5764 §8), `TCP/DTLS/RTP/SAVP(F)`
    /// (RFC 7850 §3) or `TCP/TLS/RTP/SAVP(F)`: keyed by DTLS, so SDES on
    /// them never crosses.
    Dtls,
}

/// Facts about one section (or the session level) gathered in the first
/// pass.
#[derive(Debug, Default, Clone, Copy)]
struct Section {
    port_zero: bool,
    profile: Profile,
    fingerprint: bool,
    crypto: u16,
    crypto_ok: u16,
    key_mgmt: u16,
}

/// What happens to a section's lines in the second pass.
#[derive(Debug, Default, Clone, Copy)]
struct Plan {
    /// Strip every `a=crypto` line (else only the unacceptable ones in an
    /// offer).
    strip_all_crypto: bool,
    /// Strip the unacceptable `a=crypto` lines.
    strip_bad_crypto: bool,
    strip_key_mgmt: bool,
}

/// Applies the media security policy to `sdp` crossing from one leg to the
/// other. Returns the body to forward, or why it may not cross.
///
/// ## NIST 800-53 Rev5: SC-8, SC-12, SC-13, CM-6, SI-10
pub fn apply_media_security<'a>(
    sdp: &'a str,
    role: SdpRole,
    policy: &MediaSecurityPolicy,
    legs: &LegContext,
) -> Result<Secured<'a>, MediaPolicyViolation> {
    check_line_structure(sdp)?;

    // Pass 1: classify every line and gather per-section facts.
    let mut session = Section::default();
    let mut sections: Vec<Section> = Vec::new();
    // Acceptability of each `a=crypto` line, in body order.
    let mut crypto_ok: Vec<bool> = Vec::new();
    for raw in sdp.split_inclusive('\n') {
        let (kind, value) = classify(raw);
        if kind == LineKind::Media {
            sections.push(parse_mline(value)?);
            continue;
        }
        let current = sections.last_mut().unwrap_or(&mut session);
        match kind {
            LineKind::Crypto => {
                let ok = crypto_line_acceptable(value);
                current.crypto = current.crypto.saturating_add(1);
                if ok {
                    current.crypto_ok = current.crypto_ok.saturating_add(1);
                }
                crypto_ok.push(ok);
            }
            LineKind::KeyMgmt => current.key_mgmt = current.key_mgmt.saturating_add(1),
            LineKind::Fingerprint => current.fingerprint = true,
            LineKind::Media | LineKind::Other => {}
        }
    }
    cross_check(sdp, &sections)?;

    // Decide: session level first, then each section in order.
    let session_plan = plan_session(&session, role)?;
    let mut plans: Vec<Plan> = Vec::with_capacity(sections.len());
    let mut keying = LegKeying::NoActiveStream;
    for (index, section) in sections.iter().enumerate() {
        let (plan, section_keying) = plan_section(index, section, &session, role, policy, legs)?;
        keying = merge_keying(keying, section_keying);
        plans.push(plan);
    }

    // Pass 2: rewrite only when something is stripped.
    let strips_anything = |p: &Plan, s: &Section| {
        (s.crypto > 0 && (p.strip_all_crypto || (p.strip_bad_crypto && s.crypto_ok < s.crypto)))
            || (s.key_mgmt > 0 && p.strip_key_mgmt)
    };
    let needs_rewrite = strips_anything(&session_plan, &session)
        || plans
            .iter()
            .zip(&sections)
            .any(|(p, s)| strips_anything(p, s));
    if !needs_rewrite {
        return Ok(Secured {
            sdp: Cow::Borrowed(sdp),
            keying,
            stripped_crypto: 0,
            stripped_key_mgmt: 0,
        });
    }

    let mut out = String::with_capacity(sdp.len());
    let mut stripped_crypto: u16 = 0;
    let mut stripped_key_mgmt: u16 = 0;
    let mut plan = session_plan;
    let mut next_section = 0usize;
    let mut crypto_verdicts = crypto_ok.iter();
    for raw in sdp.split_inclusive('\n') {
        let (kind, _) = classify(raw);
        let strip = match kind {
            LineKind::Media => {
                plan = plans.get(next_section).copied().unwrap_or_default();
                next_section += 1;
                false
            }
            LineKind::Crypto => {
                let ok = crypto_verdicts.next().copied().unwrap_or(false);
                let strip = plan.strip_all_crypto || (plan.strip_bad_crypto && !ok);
                if strip {
                    stripped_crypto = stripped_crypto.saturating_add(1);
                }
                strip
            }
            LineKind::KeyMgmt => {
                if plan.strip_key_mgmt {
                    stripped_key_mgmt = stripped_key_mgmt.saturating_add(1);
                }
                plan.strip_key_mgmt
            }
            LineKind::Fingerprint | LineKind::Other => false,
        };
        if !strip {
            out.push_str(raw);
        }
    }
    Ok(Secured {
        sdp: Cow::Owned(out),
        keying,
        stripped_crypto,
        stripped_key_mgmt,
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
    } else {
        LineKind::Other
    };
    (kind, value)
}

/// Parses `<media> <port>[/<n>] <proto> ...` (RFC 8866 §5.14).
fn parse_mline(value: &str) -> Result<Section, MediaPolicyViolation> {
    let mut fields = value.split_ascii_whitespace();
    let (Some(_media), Some(port), Some(proto)) = (fields.next(), fields.next(), fields.next())
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
    // RFC 5764 §8 (UDP/TLS), RFC 7850 §3 (TCP/DTLS). TCP/TLS/RTP/SAVP(F)
    // stays on the list so SDES never crosses on it either.
    let dtls = [
        "UDP/TLS/RTP/SAVP",
        "UDP/TLS/RTP/SAVPF",
        "TCP/DTLS/RTP/SAVP",
        "TCP/DTLS/RTP/SAVPF",
        "TCP/TLS/RTP/SAVP",
        "TCP/TLS/RTP/SAVPF",
    ]
    .iter()
    .any(|p| proto.eq_ignore_ascii_case(p));
    let tail = proto.rsplit('/').next().unwrap_or("");
    let profile = if dtls {
        Profile::Dtls
    } else if tail.eq_ignore_ascii_case("SAVP") || tail.eq_ignore_ascii_case("SAVPF") {
        Profile::Savp
    } else {
        Profile::Other
    };
    Ok(Section {
        port_zero: port == 0,
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
/// level: stripped from offers, refused in answers.
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
        strip_all_crypto: true,
        strip_bad_crypto: false,
        strip_key_mgmt: true,
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
                strip_all_crypto: true,
                strip_bad_crypto: false,
                strip_key_mgmt: true,
            },
            LegKeying::NoActiveStream,
        ));
    }
    let dtls = s.profile == Profile::Dtls;
    let dtls_keyed = dtls && (s.fingerprint || session.fingerprint);

    // RFC 4567: MIKEY is not supported; an answer cannot be rewritten.
    if s.key_mgmt > 0 && role == SdpRole::Answer {
        return Err(MediaPolicyViolation::UnsupportedKeyManagement { index });
    }

    let mut plan = Plan {
        strip_all_crypto: false,
        strip_bad_crypto: false,
        strip_key_mgmt: true,
    };
    let mut surviving_crypto: u16 = 0;
    if s.crypto > 0 {
        if dtls || policy.mode == KeyingMode::Terminate {
            // Terminate mode keys every leg itself; a DTLS m-line is keyed
            // by DTLS (RFC 5764). The SDES key never crosses.
            plan.strip_all_crypto = true;
            if policy.mode == KeyingMode::Terminate && !dtls_keyed {
                return Err(MediaPolicyViolation::SdesNotTerminable { index });
            }
        } else {
            // RFC 4568 §8 / §8.3: the key may only cross confidential hops.
            if !(legs.from_confidential && legs.to_confidential) {
                return Err(MediaPolicyViolation::SdesOverInsecureSignalling { index });
            }
            match role {
                SdpRole::Offer => {
                    if s.crypto_ok == 0 {
                        return Err(MediaPolicyViolation::NoAcceptableCryptoSuite { index });
                    }
                    plan.strip_bad_crypto = true;
                    surviving_crypto = s.crypto_ok;
                }
                // RFC 4568 §7.1.2: exactly one crypto attribute.
                SdpRole::Answer => {
                    if s.crypto != 1 || s.crypto_ok != 1 {
                        return Err(MediaPolicyViolation::NoAcceptableCryptoSuite { index });
                    }
                    surviving_crypto = 1;
                }
            }
        }
    }

    // `a=key-mgmt` (here or at session level) as the only keying left.
    let had_key_mgmt = s.key_mgmt > 0 || (session.key_mgmt > 0 && s.profile != Profile::Other);
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
    Ok((plan, keying))
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
        };
        for proto in ["TCP/DTLS/RTP/SAVP", "TCP/DTLS/RTP/SAVPF"] {
            let body = format!(
                "v=0\r\nm=audio 9 {proto} 0\r\na=fingerprint:sha-384 AA\r\na=crypto:1 AEAD_AES_256_GCM inline:{KEY_256}\r\n"
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
