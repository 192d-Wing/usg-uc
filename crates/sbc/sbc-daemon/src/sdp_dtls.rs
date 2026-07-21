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

/// Extracts the peer's DTLS parameters from an SDP body, if it offers
/// DTLS-SRTP (i.e. carries an `a=fingerprint`). Returns `None` for plain SDP.
#[must_use]
pub fn parse_peer_dtls(sdp: &str) -> Option<PeerDtls> {
    let mut fingerprint = None;
    let mut setup = None;
    for line in sdp.lines() {
        let line = line.trim();
        // First fingerprint / first setup wins (session- or first media-level).
        if let Some(v) = line.strip_prefix("a=fingerprint:")
            && fingerprint.is_none()
        {
            fingerprint = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("a=setup:")
            && setup.is_none()
        {
            setup = SetupRole::parse(v);
        }
    }
    fingerprint.map(|fingerprint| PeerDtls { fingerprint, setup })
}

/// Rewrites every `a=fingerprint`/`a=setup` line in `sdp` to advertise the
/// SBC's own `fingerprint` and the given `setup` role. Only touches SDP that
/// already carries `a=fingerprint` (DTLS-SRTP); plain SDP is returned as-is so
/// this is safe to call unconditionally on terminated calls.
///
/// Preserves the original line endings (SDP uses CRLF on the wire).
#[must_use]
pub fn rewrite_local_dtls(sdp: &str, fingerprint: &str, setup: SetupRole) -> String {
    if !sdp.contains("a=fingerprint:") {
        return sdp.to_string();
    }
    // Rebuild line by line, preserving the trailing CR of CRLF endings.
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive('\n') {
        // Split the line body from its ("\r\n" / "\n" / "") terminator.
        let (body, term) = split_line_terminator(line);
        if body.starts_with("a=fingerprint:") {
            out.push_str("a=fingerprint:");
            out.push_str(fingerprint);
        } else if body.starts_with("a=setup:") {
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

    const DTLS_SDP: &str = "v=0\r\n\
        o=- 1 1 IN IP4 10.0.0.1\r\n\
        s=-\r\n\
        c=IN IP4 10.0.0.1\r\n\
        t=0 0\r\n\
        m=audio 5004 UDP/TLS/RTP/SAVP 8\r\n\
        a=rtpmap:8 PCMA/8000\r\n\
        a=setup:actpass\r\n\
        a=fingerprint:sha-384 AA:BB:CC\r\n\
        a=sendrecv\r\n";

    #[test]
    fn parses_peer_fingerprint_and_setup() {
        let peer = parse_peer_dtls(DTLS_SDP).unwrap();
        assert_eq!(peer.fingerprint, "sha-384 AA:BB:CC");
        assert_eq!(peer.setup, Some(SetupRole::ActPass));
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
        let out = rewrite_local_dtls(DTLS_SDP, "sha-384 DD:EE:FF", SetupRole::Passive);
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
