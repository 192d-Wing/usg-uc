//! DTLS-SRTP SDP attribute handling for media termination.
//!
//! When the SBC terminates DTLS-SRTP (rather than relaying it opaquely) it is
//! the DTLS endpoint on each leg, so the media SDP it forwards must carry the
//! **SBC's own** `a=fingerprint` and an `a=setup` role the SBC will actually
//! honor — not the peer's. These helpers parse the peer's DTLS attributes (for
//! handshake verification in later phases) and rewrite the outbound SDP to
//! advertise the SBC's identity.
//!
//! Rewriting is line-based to match the existing string-based SDP rewriter
//! (`proto-b2bua`); non-DTLS SDP (no `a=fingerprint`) is left untouched.
//!
//! ## RFC references
//! - RFC 8122 — SDP `a=fingerprint` for DTLS-SRTP
//! - RFC 5763 / RFC 4145 — `a=setup` role negotiation

/// DTLS setup role (RFC 4145 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupRole {
    /// Endpoint will initiate the DTLS handshake (DTLS client).
    Active,
    /// Endpoint will accept the DTLS handshake (DTLS server).
    Passive,
    /// Offerer is willing to be either; the answerer must choose.
    ActPass,
}

impl SetupRole {
    /// Parses an `a=setup` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "active" => Some(Self::Active),
            "passive" => Some(Self::Passive),
            "actpass" => Some(Self::ActPass),
            _ => None,
        }
    }

    /// The `a=setup` token for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::ActPass => "actpass",
        }
    }

    /// The role the SBC takes when **answering** a peer that offered `self`.
    ///
    /// Per RFC 5763 the answerer must commit to `active` or `passive` (never
    /// `actpass`): mirror the peer (`active`↔`passive`), and default to
    /// `passive` (SBC = DTLS server) when the peer offered `actpass`, leaving
    /// the peer to initiate.
    #[must_use]
    pub const fn answer_role(self) -> Self {
        match self {
            Self::Active => Self::Passive,
            Self::Passive => Self::Active,
            Self::ActPass => Self::Passive,
        }
    }
}

/// The peer's DTLS-SRTP parameters extracted from its SDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDtls {
    /// `a=fingerprint` value, e.g. `sha-384 AB:CD:...`.
    pub fingerprint: String,
    /// `a=setup` role, if present.
    pub setup: Option<SetupRole>,
}

/// Extracts the peer's DTLS parameters from an SDP body, if the stream the
/// relay anchors is DTLS-SRTP with an accepted fingerprint. Read with the
/// media security policy's tokenizer ([`proto_b2bua::anchored_dtls`]):
/// names case-insensitive and trimmed, media-level lines before
/// session-level ones, declined sections and fingerprints with a hash
/// CNSA 2.0 does not allow ignored. Returns `None` otherwise.
///
/// ## NIST 800-53 Rev5: SC-8, SC-23; RFC 8122 §5; RFC 4145 §4
#[must_use]
pub fn parse_peer_dtls(sdp: &str) -> Option<PeerDtls> {
    proto_b2bua::anchored_dtls(sdp).map(|d| PeerDtls {
        fingerprint: d.fingerprint.to_string(),
        setup: d.setup.and_then(SetupRole::parse),
    })
}

/// `a=<name>:` at the start of a line, after the trim `proto-sdp` applies
/// and ASCII case-insensitively, as the media security policy reads it.
fn is_attribute(line: &str, name: &str) -> bool {
    let line = line.trim();
    let Some(rest) = line
        .get(..2)
        .filter(|p| p.eq_ignore_ascii_case("a="))
        .and_then(|_| line.get(2..))
    else {
        return false;
    };
    rest.split_once(':')
        .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))
}

/// Rewrites the `a=fingerprint`/`a=setup` lines in `sdp` to advertise the
/// SBC's own `fingerprint` and the given `setup` role: in each section (and
/// at session level) the first `a=fingerprint` line becomes the SBC's and
/// any further one is dropped, so no peer fingerprint crosses. Names are
/// matched as [`parse_peer_dtls`] reads them. Only touches SDP that carries
/// `a=fingerprint` (DTLS-SRTP); plain SDP is returned as-is so this is safe
/// to call unconditionally on terminated calls.
///
/// Preserves the original line endings (SDP uses CRLF on the wire).
///
/// ## NIST 800-53 Rev5: SC-8, SC-23
#[must_use]
pub fn rewrite_local_dtls(sdp: &str, fingerprint: &str, setup: SetupRole) -> String {
    if !sdp.lines().any(|l| is_attribute(l, "fingerprint")) {
        return sdp.to_string();
    }
    // Rebuild line by line, preserving the trailing CR of CRLF endings.
    let mut out = String::with_capacity(sdp.len());
    let mut section_has_fingerprint = false;
    for line in sdp.split_inclusive('\n') {
        // Split the line body from its ("\r\n" / "\n" / "") terminator.
        let (body, term) = split_line_terminator(line);
        let trimmed = body.trim();
        if trimmed
            .get(..2)
            .is_some_and(|p| p.eq_ignore_ascii_case("m="))
        {
            section_has_fingerprint = false;
            out.push_str(body);
        } else if is_attribute(body, "fingerprint") {
            if std::mem::replace(&mut section_has_fingerprint, true) {
                continue;
            }
            out.push_str("a=fingerprint:");
            out.push_str(fingerprint);
        } else if is_attribute(body, "setup") {
            out.push_str("a=setup:");
            out.push_str(setup.as_str());
        } else {
            out.push_str(body);
        }
        out.push_str(term);
    }
    out
}

/// Splits a line (as produced by `split_inclusive('\n')`) into its body and
/// line terminator (`"\r\n"`, `"\n"`, or `""` for a final line with no newline).
fn split_line_terminator(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sha-384 fingerprint: 48 octets of a fixed pattern, not a digest.
    const FP: &str = "sha-384 AA:BB:CC:00:01:02:03:04:05:06:07:08:09:0A:0B:0C:\
                      0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:\
                      20:21:22:23:24:25:26:27:28:29:2A:2B:2C";

    fn dtls_sdp() -> String {
        format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 5004 UDP/TLS/RTP/SAVP 8\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=setup:actpass\r\n\
             a=fingerprint:{FP}\r\n\
             a=sendrecv\r\n"
        )
    }

    #[test]
    fn parses_peer_fingerprint_and_setup() {
        let peer = parse_peer_dtls(&dtls_sdp()).unwrap();
        assert_eq!(peer.fingerprint, FP);
        assert_eq!(peer.setup, Some(SetupRole::ActPass));
    }

    /// The anchored (first active) stream's fingerprint, matched as the
    /// policy matches it: a declined section's line and an unaccepted hash
    /// are never taken, upper-case names and spaces are read.
    #[test]
    fn parses_the_anchored_streams_accepted_fingerprint() {
        let sha256 = format!("sha-256 {}", ["AB"; 32].join(":"));
        let sdp = format!(
            "v=0\r\nm=audio 0 UDP/TLS/RTP/SAVP 8\r\na=fingerprint:{sha256}\r\n\
             m=audio 5004 UDP/TLS/RTP/SAVP 8\r\nA=Fingerprint: {sha256}\r\n\
             a=FINGERPRINT : {FP}\r\na=Setup:active\r\n"
        );
        let peer = parse_peer_dtls(&sdp).unwrap();
        assert_eq!(peer.fingerprint, FP);
        assert_eq!(peer.setup, Some(SetupRole::Active));
        // Only an unaccepted hash, or a short value: no peer DTLS.
        let only_256 =
            format!("v=0\r\nm=audio 5004 UDP/TLS/RTP/SAVP 8\r\na=fingerprint:{sha256}\r\n");
        assert!(parse_peer_dtls(&only_256).is_none());
        assert!(
            parse_peer_dtls(
                "v=0\r\nm=audio 5004 UDP/TLS/RTP/SAVP 8\r\na=fingerprint:sha-384 AA:BB\r\n"
            )
            .is_none()
        );
    }

    /// Every peer fingerprint line is replaced or dropped, whatever its
    /// case, so only the SBC's crosses.
    #[test]
    fn rewrite_replaces_mixed_case_lines_and_drops_extras() {
        let sdp = format!(
            "v=0\r\na=FINGERPRINT:{FP}\r\nm=audio 5004 UDP/TLS/RTP/SAVP 8\r\n\
             a=Fingerprint:{FP}\r\n a=fingerprint:sha-512 {}\r\nA=SETUP:actpass\r\n",
            ["01"; 64].join(":")
        );
        let out = rewrite_local_dtls(&sdp, "sha-384 DD:EE:FF", SetupRole::Passive);
        assert_eq!(
            out.matches("a=fingerprint:sha-384 DD:EE:FF\r\n").count(),
            2,
            "{out}"
        );
        assert!(!out.contains("AA:BB:CC"), "{out}");
        assert!(!out.to_ascii_lowercase().contains("sha-512"), "{out}");
        assert!(out.contains("a=setup:passive\r\n"), "{out}");
        assert!(!out.contains("actpass"), "{out}");
    }

    #[test]
    fn plain_sdp_has_no_dtls() {
        let plain = "v=0\r\nm=audio 5004 RTP/AVP 8\r\na=sendrecv\r\n";
        assert!(parse_peer_dtls(plain).is_none());
        // Rewrite is a no-op on plain SDP.
        assert_eq!(
            rewrite_local_dtls(plain, "sha-384 FF", SetupRole::Passive),
            plain
        );
    }

    #[test]
    fn rewrites_to_local_fingerprint_and_role() {
        let out = rewrite_local_dtls(&dtls_sdp(), "sha-384 DD:EE:FF", SetupRole::Passive);
        assert!(out.contains("a=fingerprint:sha-384 DD:EE:FF\r\n"));
        assert!(out.contains("a=setup:passive\r\n"));
        // The peer's values are gone; other lines untouched; CRLF preserved.
        assert!(!out.contains("AA:BB:CC"));
        assert!(!out.contains("actpass"));
        assert!(out.contains("a=rtpmap:8 PCMA/8000\r\n"));
        assert!(out.ends_with("a=sendrecv\r\n"));
    }

    #[test]
    fn answer_role_negotiation() {
        // Mirror the peer; default to passive on actpass.
        assert_eq!(SetupRole::Active.answer_role(), SetupRole::Passive);
        assert_eq!(SetupRole::Passive.answer_role(), SetupRole::Active);
        assert_eq!(SetupRole::ActPass.answer_role(), SetupRole::Passive);
    }
}
