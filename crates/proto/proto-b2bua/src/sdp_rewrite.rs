//! SDP rewriting for B2BUA media anchoring per RFC 7092.
//!
//! This module handles SDP modification based on B2BUA mode:
//!
//! - **SignalingOnly**: Pass SDP through unchanged
//! - **MediaRelay**: Rewrite c= line and media port with B2BUA address
//! - **MediaAware**: Rewrite connection info, preserve codec order
//! - **MediaTermination**: Full SDP modification, independent codec negotiation
//!
//! ## RFC Compliance
//!
//! - **RFC 4566**: SDP format
//! - **RFC 3264**: Offer/Answer model
//! - **RFC 7092**: B2BUA behavior
//! - **RFC 3362 / ITU-T T.38 Annex D**: `m=image` (T.38 fax) stream selection

use crate::B2buaMode;
use crate::mode::{MediaAddress, ModeCharacteristics, SdpModification};
use proto_sdp::{MediaType, SessionDescription, T38Params, TransportProtocol};

/// SDP connection rewrite result.
#[derive(Debug, Clone)]
pub struct SdpRewriteResult {
    /// Original SDP (for reference).
    pub original: String,
    /// Rewritten SDP.
    pub rewritten: String,
    /// Whether any changes were made.
    pub modified: bool,
}

impl SdpRewriteResult {
    /// Creates a passthrough result (no changes).
    pub fn passthrough(sdp: String) -> Self {
        Self {
            original: sdp.clone(),
            rewritten: sdp,
            modified: false,
        }
    }

    /// Creates a modified result.
    pub fn modified(original: String, rewritten: String) -> Self {
        Self {
            original,
            rewritten,
            modified: true,
        }
    }
}

/// SDP rewriter for B2BUA media handling.
#[derive(Debug, Clone)]
pub struct SdpRewriter {
    /// B2BUA mode.
    mode: B2buaMode,
    /// Mode characteristics.
    characteristics: ModeCharacteristics,
}

impl SdpRewriter {
    /// Creates a new SDP rewriter for the given mode.
    pub fn new(mode: B2buaMode) -> Self {
        Self {
            mode,
            characteristics: ModeCharacteristics::for_mode(mode),
        }
    }

    /// Returns the B2BUA mode.
    pub fn mode(&self) -> B2buaMode {
        self.mode
    }

    /// Returns true if SDP rewriting is needed.
    pub fn requires_rewrite(&self) -> bool {
        self.characteristics.requires_sdp_rewrite()
    }

    /// Rewrites an SDP offer for the B-leg.
    ///
    /// This modifies the SDP to use the B2BUA's media address instead of
    /// the caller's address, anchoring media through the B2BUA.
    ///
    /// # Arguments
    ///
    /// * `sdp` - The original SDP offer from the A-leg (caller)
    /// * `local_address` - The B2BUA's address for the B-leg side
    ///
    /// # Returns
    ///
    /// The rewritten SDP to send to the B-leg.
    pub fn rewrite_offer_for_b_leg(
        &self,
        sdp: &str,
        local_address: &MediaAddress,
    ) -> SdpRewriteResult {
        match self.characteristics.sdp_modification {
            SdpModification::Passthrough => SdpRewriteResult::passthrough(sdp.to_string()),
            SdpModification::RewriteConnection | SdpModification::FullModification => {
                let rewritten = Self::rewrite_connection_and_port(sdp, local_address);
                SdpRewriteResult::modified(sdp.to_string(), rewritten)
            }
        }
    }

    /// Rewrites an SDP answer for the A-leg.
    ///
    /// This modifies the SDP answer from the B-leg to use the B2BUA's
    /// media address instead of the callee's address.
    ///
    /// # Arguments
    ///
    /// * `sdp` - The original SDP answer from the B-leg (callee)
    /// * `local_address` - The B2BUA's address for the A-leg side
    ///
    /// # Returns
    ///
    /// The rewritten SDP to send to the A-leg.
    pub fn rewrite_answer_for_a_leg(
        &self,
        sdp: &str,
        local_address: &MediaAddress,
    ) -> SdpRewriteResult {
        match self.characteristics.sdp_modification {
            SdpModification::Passthrough => SdpRewriteResult::passthrough(sdp.to_string()),
            SdpModification::RewriteConnection | SdpModification::FullModification => {
                let rewritten = Self::rewrite_connection_and_port(sdp, local_address);
                SdpRewriteResult::modified(sdp.to_string(), rewritten)
            }
        }
    }

    /// Rewrites a re-INVITE offer.
    ///
    /// Used for mid-dialog re-INVITEs (hold, resume, codec change).
    pub fn rewrite_reinvite(&self, sdp: &str, local_address: &MediaAddress) -> SdpRewriteResult {
        self.rewrite_offer_for_b_leg(sdp, local_address)
    }

    /// Rewrites SDP for hold (sendonly/inactive).
    ///
    /// Per RFC 3264, hold is signaled by setting direction to sendonly
    /// or using 0.0.0.0 as connection address.
    pub fn rewrite_for_hold(&self, sdp: &str, local_address: &MediaAddress) -> SdpRewriteResult {
        let mut rewritten = Self::rewrite_connection_and_port(sdp, local_address);

        // Add or modify direction attribute
        // Find a=sendrecv or a=recvonly and change to a=sendonly
        rewritten = rewritten.replace("a=sendrecv", "a=sendonly");
        rewritten = rewritten.replace("a=recvonly", "a=inactive");

        // If no direction attribute, add sendonly after each m= line section
        if !rewritten.contains("a=sendonly") && !rewritten.contains("a=inactive") {
            // Add after c= line in each media section
            let lines: Vec<&str> = rewritten.lines().collect();
            let mut i = 0;
            let mut modified_lines: Vec<String> = Vec::new();
            let mut in_media_section = false;
            let mut added_direction = false;

            while i < lines.len() {
                let line = lines[i];
                modified_lines.push(line.to_string());

                if line.starts_with("m=") {
                    in_media_section = true;
                    added_direction = false;
                } else if in_media_section && line.starts_with("c=") && !added_direction {
                    modified_lines.push("a=sendonly".to_string());
                    added_direction = true;
                }

                i += 1;
            }

            rewritten = modified_lines.join("\r\n");
            if !rewritten.ends_with("\r\n") {
                rewritten.push_str("\r\n");
            }
        }

        SdpRewriteResult::modified(sdp.to_string(), rewritten)
    }

    /// Rewrites SDP for resume (sendrecv).
    pub fn rewrite_for_resume(&self, sdp: &str, local_address: &MediaAddress) -> SdpRewriteResult {
        let mut rewritten = Self::rewrite_connection_and_port(sdp, local_address);

        // Change direction back to sendrecv
        rewritten = rewritten.replace("a=sendonly", "a=sendrecv");
        rewritten = rewritten.replace("a=inactive", "a=sendrecv");
        rewritten = rewritten.replace("a=recvonly", "a=sendrecv");

        SdpRewriteResult::modified(sdp.to_string(), rewritten)
    }

    /// Internal: Rewrite connection (c=) and media port (m=) lines.
    fn rewrite_connection_and_port(sdp: &str, local_address: &MediaAddress) -> String {
        let mut result = String::with_capacity(sdp.len() + 100);
        let addr_type = if local_address.address.contains(':') {
            "IP6"
        } else {
            "IP4"
        };

        for line in sdp.lines() {
            if line.starts_with("c=") {
                // Replace connection line
                // Format: c=<nettype> <addrtype> <connection-address>
                result.push_str("c=IN ");
                result.push_str(addr_type);
                result.push(' ');
                result.push_str(&local_address.address);
            } else if line.starts_with("m=") {
                // Replace port in media line
                // Format: m=<media> <port> <proto> <fmt> ...
                // RFC 3264 §6/§8: a declined stream (port 0) stays declined;
                // giving it the anchored port would re-enable it.
                if mline_port(line) == Some(0) {
                    result.push_str(line);
                } else if let Some(rewritten) = Self::rewrite_media_line(line, local_address.port) {
                    result.push_str(&rewritten);
                } else {
                    result.push_str(line);
                }
            } else {
                result.push_str(line);
            }
            result.push_str("\r\n");
        }

        result
    }

    /// Rewrites an m= line with a new port.
    fn rewrite_media_line(line: &str, port: u16) -> Option<String> {
        // m=audio 49170 RTP/SAVP 0 8 97
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 4 {
            return None;
        }

        Some(format!("{} {} {} {}", parts[0], port, parts[2], parts[3]))
    }

    /// Rewrites `sdp` so that only the selected m-line is anchored.
    ///
    /// - every `c=` line gets the B2BUA address;
    /// - the selected m-line gets `local_address.port`;
    /// - declined m-lines (port 0) stay declined (RFC 3264 §8.2);
    /// - when the selected stream or any other m-line is `image`, every other
    ///   active m-line is declined in place with port 0, because the relay
    ///   anchors exactly one stream (RFC 3264 §8: m-lines are never removed);
    /// - otherwise other active m-lines keep the legacy behaviour and share
    ///   the anchored port (POA&M-293).
    // POAM: POA&M-293 - one anchored m-line per call; non-T.38 multi-stream
    // SDP keeps sharing the anchored port.
    pub fn rewrite_with_selection(
        sdp: &str,
        local_address: &MediaAddress,
        selected: &AnchoredStream,
    ) -> String {
        let any_image = selected.kind == StreamKind::Image
            || sdp
                .lines()
                .filter(|l| l.starts_with("m="))
                .any(|l| mline_kind(l) == StreamKind::Image);
        let addr_type = if local_address.address.contains(':') {
            "IP6"
        } else {
            "IP4"
        };
        let mut result = String::with_capacity(sdp.len() + 100);
        let mut m_index = 0usize;
        for line in sdp.lines() {
            if line.starts_with("c=") {
                result.push_str("c=IN ");
                result.push_str(addr_type);
                result.push(' ');
                result.push_str(&local_address.address);
            } else if line.starts_with("m=") {
                let idx = m_index;
                m_index += 1;
                let port = if mline_port(line) == Some(0) {
                    None
                } else if idx == selected.index {
                    Some(local_address.port)
                } else if any_image {
                    Some(0)
                } else {
                    Some(local_address.port)
                };
                match port.and_then(|p| Self::rewrite_media_line(line, p)) {
                    Some(rewritten) => result.push_str(&rewritten),
                    None => result.push_str(line),
                }
            } else {
                result.push_str(line);
            }
            result.push_str("\r\n");
        }
        result
    }
}

/// Kind of an anchored media stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// `m=audio`.
    Audio,
    /// `m=image` (T.38 fax, RFC 3362).
    Image,
    /// Any other media type.
    Other,
}

/// Which stream kind to prefer when several m-lines are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPreference {
    /// Prefer an active audio m-line.
    Audio,
    /// Prefer an active image m-line.
    Image,
}

/// The single m-line the media relay anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredStream {
    /// Zero-based m-line index.
    pub index: usize,
    /// Stream kind.
    pub kind: StreamKind,
    /// Port in the SDP (0 = declined).
    pub port: u16,
    /// Transport protocol.
    pub proto: TransportProtocol,
}

const fn kind_of(media_type: MediaType) -> StreamKind {
    match media_type {
        MediaType::Audio => StreamKind::Audio,
        MediaType::Image => StreamKind::Image,
        _ => StreamKind::Other,
    }
}

/// Port of an `m=` line (`m=<media> <port>[/<n>] ...`), if well formed.
fn mline_port(line: &str) -> Option<u16> {
    let port = line.split_whitespace().nth(1)?;
    port.split('/').next()?.parse().ok()
}

/// Kind of an `m=` line from its media token.
fn mline_kind(line: &str) -> StreamKind {
    let media = line
        .strip_prefix("m=")
        .and_then(|l| l.split_whitespace().next());
    match media {
        Some(m) if m.eq_ignore_ascii_case("audio") => StreamKind::Audio,
        Some(m) if m.eq_ignore_ascii_case("image") => StreamKind::Image,
        _ => StreamKind::Other,
    }
}

/// Returns true if any m-line in `sdp` is `m=image` (active or declined).
pub fn has_image_stream(sdp: &str) -> bool {
    sdp.lines()
        .filter(|l| l.starts_with("m="))
        .any(|l| mline_kind(l) == StreamKind::Image)
}

/// Parses `sdp` (RFC 8866, total parser) for stream classification.
fn parse_sdp(sdp: &str) -> Option<SessionDescription> {
    sdp.parse::<SessionDescription>().ok()
}

/// Selects the one active m-line the relay anchors.
///
/// Returns `None` if the SDP does not parse (the caller rejects with 488) or
/// no m-line is active. With [`StreamPreference::Image`] the first active
/// image m-line wins, else the first active audio one; with
/// [`StreamPreference::Audio`] the order is reversed. Failing both, the first
/// active m-line of any kind is selected.
// NIST 800-53 Rev5: SI-10 (SDP is parsed by the total proto-sdp parser)
pub fn select_anchored_stream(sdp: &str, prefer: StreamPreference) -> Option<AnchoredStream> {
    let parsed = parse_sdp(sdp)?;
    let active = |kind: StreamKind| {
        parsed
            .media
            .iter()
            .enumerate()
            .find(|(_, m)| m.port != 0 && kind_of(m.media_type) == kind)
    };
    let (first, second) = match prefer {
        StreamPreference::Image => (StreamKind::Image, StreamKind::Audio),
        StreamPreference::Audio => (StreamKind::Audio, StreamKind::Image),
    };
    let (index, media) = active(first)
        .or_else(|| active(second))
        .or_else(|| parsed.media.iter().enumerate().find(|(_, m)| m.port != 0))?;
    Some(AnchoredStream {
        index,
        kind: kind_of(media.media_type),
        port: media.port,
        proto: media.protocol,
    })
}

/// Returns the m-line at `index` (active or declined), or `None` if the SDP
/// does not parse or has fewer m-lines.
pub fn stream_at(sdp: &str, index: usize) -> Option<AnchoredStream> {
    let parsed = parse_sdp(sdp)?;
    let media = parsed.media.get(index)?;
    Some(AnchoredStream {
        index,
        kind: kind_of(media.media_type),
        port: media.port,
        proto: media.protocol,
    })
}

/// Parses the T.38 Annex D attributes of the m-line at `index`.
///
/// Returns `None` if the SDP does not parse, the index is out of range, or
/// the T.38 attributes are malformed (duplicate, out of range, non-ASCII).
pub fn t38_params_at(sdp: &str, index: usize) -> Option<T38Params> {
    let parsed = parse_sdp(sdp)?;
    T38Params::from_media(parsed.media.get(index)?).ok()
}

/// Replaces the `T38*` attribute lines of the m-section at `index`.
///
/// The canonical lines from `params` (ITU-T T.38 Annex D casing) go at the
/// end of the m-section; other lines are kept byte-for-byte.
pub fn rewrite_t38_attributes(sdp: &str, index: usize, params: &T38Params) -> String {
    let mut out = String::with_capacity(sdp.len() + 64);
    let mut m_index: Option<usize> = None;
    let mut emitted = false;
    let emit = |out: &mut String| {
        for attr in params.to_attributes() {
            out.push_str(&attr.to_string());
            out.push_str("\r\n");
        }
    };
    for line in sdp.lines() {
        if line.starts_with("m=") {
            if m_index == Some(index) && !emitted {
                emit(&mut out);
                emitted = true;
            }
            m_index = Some(m_index.map_or(0, |i| i + 1));
        }
        let is_t38 = line
            .strip_prefix("a=")
            .map(|a| a.split(':').next().unwrap_or(a))
            .is_some_and(proto_sdp::t38::is_t38_attribute_name);
        if m_index == Some(index) && is_t38 {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if m_index == Some(index) && !emitted {
        emit(&mut out);
    }
    out
}

/// Extracts media address from an SDP.
///
/// Returns the connection address and first media port found.
pub fn extract_media_address(sdp: &str) -> Option<MediaAddress> {
    let mut address: Option<String> = None;
    let mut port: Option<u16> = None;

    for line in sdp.lines() {
        if line.starts_with("c=") {
            // c=IN IP4 192.168.1.100
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                address = Some(parts[2].to_string());
            }
        } else if line.starts_with("m=") && port.is_none() {
            // m=audio 49170 RTP/SAVP 0
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                port = parts[1].parse().ok();
            }
        }
    }

    match (address, port) {
        (Some(addr), Some(p)) => Some(MediaAddress::new(addr, p)),
        _ => None,
    }
}

/// Extracts the media address of the m-line at `index`.
///
/// The address is the m-section `c=` if present, else the session-level
/// `c=` (RFC 8866 §5.7); the port is that m-line's port (0 if declined).
pub fn extract_media_address_for(sdp: &str, index: usize) -> Option<MediaAddress> {
    let mut session_addr: Option<String> = None;
    let mut media_addr: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut m_index: Option<usize> = None;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            let next = m_index.map_or(0, |i| i + 1);
            if next > index {
                break;
            }
            m_index = Some(next);
            if next == index {
                port = mline_port(line);
            }
        } else if line.starts_with("c=") {
            let addr = line.split_whitespace().nth(2).map(str::to_string);
            match m_index {
                None => session_addr = addr,
                Some(i) if i == index => media_addr = addr,
                Some(_) => {}
            }
        }
    }
    let addr = media_addr.or(session_addr)?;
    Some(MediaAddress::new(addr, port?))
}

/// Checks if SDP indicates hold (sendonly or inactive).
pub fn is_hold_sdp(sdp: &str) -> bool {
    sdp.contains("a=sendonly") || sdp.contains("a=inactive")
}

/// Checks if SDP uses the "hold" connection address (0.0.0.0).
pub fn is_connection_hold(sdp: &str) -> bool {
    for line in sdp.lines() {
        if line.starts_with("c=") && line.contains("0.0.0.0") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SdpRewriteContext;

    const SAMPLE_SDP: &str = "v=0\r\n\
                              o=- 123456 1 IN IP4 192.168.1.100\r\n\
                              s=-\r\n\
                              c=IN IP4 192.168.1.100\r\n\
                              t=0 0\r\n\
                              m=audio 49170 RTP/SAVP 0 8\r\n\
                              a=rtpmap:0 PCMU/8000\r\n\
                              a=rtpmap:8 PCMA/8000\r\n\
                              a=sendrecv\r\n";

    #[test]
    fn test_signaling_only_passthrough() {
        let rewriter = SdpRewriter::new(B2buaMode::SignalingOnly);
        assert!(!rewriter.requires_rewrite());

        let local = MediaAddress::new("10.0.0.1", 20000);
        let result = rewriter.rewrite_offer_for_b_leg(SAMPLE_SDP, &local);

        assert!(!result.modified);
        assert_eq!(result.rewritten, SAMPLE_SDP);
    }

    #[test]
    fn test_media_relay_rewrites_connection() {
        let rewriter = SdpRewriter::new(B2buaMode::MediaRelay);
        assert!(rewriter.requires_rewrite());

        let local = MediaAddress::new("10.0.0.1", 20000);
        let result = rewriter.rewrite_offer_for_b_leg(SAMPLE_SDP, &local);

        assert!(result.modified);
        assert!(result.rewritten.contains("c=IN IP4 10.0.0.1"));
        assert!(result.rewritten.contains("m=audio 20000"));
        // Verify original IP is not in connection or media lines (o= line is session metadata)
        assert!(!result.rewritten.contains("c=IN IP4 192.168.1.100"));
        assert!(!result.rewritten.contains("m=audio 49170"));
    }

    #[test]
    fn test_media_termination_rewrites() {
        let rewriter = SdpRewriter::new(B2buaMode::MediaTermination);
        assert!(rewriter.requires_rewrite());

        let local = MediaAddress::new("10.0.0.1", 30000);
        let result = rewriter.rewrite_answer_for_a_leg(SAMPLE_SDP, &local);

        assert!(result.modified);
        assert!(result.rewritten.contains("c=IN IP4 10.0.0.1"));
        assert!(result.rewritten.contains("m=audio 30000"));
    }

    #[test]
    fn test_ipv6_address_rewrite() {
        let rewriter = SdpRewriter::new(B2buaMode::MediaRelay);

        let local = MediaAddress::new("2001:db8::1", 20000);
        let result = rewriter.rewrite_offer_for_b_leg(SAMPLE_SDP, &local);

        assert!(result.rewritten.contains("c=IN IP6 2001:db8::1"));
    }

    #[test]
    fn test_rewrite_for_hold() {
        let rewriter = SdpRewriter::new(B2buaMode::MediaRelay);

        let local = MediaAddress::new("10.0.0.1", 20000);
        let result = rewriter.rewrite_for_hold(SAMPLE_SDP, &local);

        assert!(result.rewritten.contains("a=sendonly"));
        assert!(!result.rewritten.contains("a=sendrecv"));
    }

    #[test]
    fn test_rewrite_for_resume() {
        let hold_sdp = SAMPLE_SDP.replace("a=sendrecv", "a=sendonly");
        let rewriter = SdpRewriter::new(B2buaMode::MediaRelay);

        let local = MediaAddress::new("10.0.0.1", 20000);
        let result = rewriter.rewrite_for_resume(&hold_sdp, &local);

        assert!(result.rewritten.contains("a=sendrecv"));
        assert!(!result.rewritten.contains("a=sendonly"));
    }

    #[test]
    fn test_extract_media_address() {
        let addr = extract_media_address(SAMPLE_SDP).unwrap();
        assert_eq!(addr.address, "192.168.1.100");
        assert_eq!(addr.port, 49170);
    }

    #[test]
    fn test_extract_media_address_missing() {
        let sdp = "v=0\r\ns=-\r\nt=0 0\r\n";
        assert!(extract_media_address(sdp).is_none());
    }

    #[test]
    fn test_is_hold_sdp() {
        assert!(!is_hold_sdp(SAMPLE_SDP));
        assert!(is_hold_sdp(&SAMPLE_SDP.replace("sendrecv", "sendonly")));
        assert!(is_hold_sdp("a=inactive\r\n"));
    }

    #[test]
    fn test_is_connection_hold() {
        assert!(!is_connection_hold(SAMPLE_SDP));
        assert!(is_connection_hold("c=IN IP4 0.0.0.0\r\n"));
    }

    #[test]
    fn test_preserve_sdp_structure() {
        let rewriter = SdpRewriter::new(B2buaMode::MediaRelay);
        let local = MediaAddress::new("10.0.0.1", 20000);
        let result = rewriter.rewrite_offer_for_b_leg(SAMPLE_SDP, &local);

        // Verify structure is preserved
        assert!(result.rewritten.starts_with("v=0"));
        assert!(result.rewritten.contains("o="));
        assert!(result.rewritten.contains("s="));
        assert!(result.rewritten.contains("t="));
        assert!(result.rewritten.contains("a=rtpmap:0 PCMU/8000"));
    }

    const T38_REINVITE: &str = "v=0\r\n\
                                o=- 1 2 IN IP4 192.0.2.10\r\n\
                                s=-\r\n\
                                c=IN IP4 192.0.2.10\r\n\
                                t=0 0\r\n\
                                m=audio 0 RTP/AVP 0\r\n\
                                m=image 5000 udptl t38\r\n\
                                c=IN IP4 192.0.2.20\r\n\
                                a=T38FaxVersion:0\r\n\
                                a=t38maxbitrate:33600\r\n\
                                a=T38FaxUdpEC:t38UDPRedundancy\r\n";

    #[test]
    fn test_port_zero_preserved() {
        let rewriter = SdpRewriter::new(B2buaMode::MediaRelay);
        let local = MediaAddress::new("10.0.0.1", 20000);
        let result = rewriter.rewrite_offer_for_b_leg(T38_REINVITE, &local);
        assert!(result.rewritten.contains("m=audio 0 RTP/AVP 0"));
        assert!(result.rewritten.contains("m=image 20000 udptl t38"));
    }

    fn sdp_with(mlines: &[&str]) -> String {
        let mut s = String::from(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n",
        );
        for m in mlines {
            s.push_str(m);
            s.push_str("\r\n");
        }
        s
    }

    #[test]
    fn test_selection() {
        let audio_on_image_off = sdp_with(&["m=audio 4000 RTP/AVP 0", "m=image 0 udptl t38"]);
        let sel = select_anchored_stream(&audio_on_image_off, StreamPreference::Image).unwrap();
        assert_eq!((sel.index, sel.kind), (0, StreamKind::Audio));

        let sel = select_anchored_stream(T38_REINVITE, StreamPreference::Audio).unwrap();
        assert_eq!(
            (sel.index, sel.kind, sel.port),
            (1, StreamKind::Image, 5000)
        );
        assert_eq!(sel.proto, TransportProtocol::Udptl);

        let image_only = sdp_with(&["m=image 6000 udptl t38"]);
        let sel = select_anchored_stream(&image_only, StreamPreference::Audio).unwrap();
        assert_eq!(sel.kind, StreamKind::Image);

        let both = sdp_with(&["m=audio 4000 RTP/AVP 0", "m=image 6000 udptl t38"]);
        let sel = select_anchored_stream(&both, StreamPreference::Image).unwrap();
        assert_eq!(sel.index, 1);
        let sel = select_anchored_stream(&both, StreamPreference::Audio).unwrap();
        assert_eq!(sel.index, 0);
        // Image selected: the other active stream is declined in place.
        let sel = select_anchored_stream(&both, StreamPreference::Image).unwrap();
        let out =
            SdpRewriter::rewrite_with_selection(&both, &MediaAddress::new("10.0.0.1", 20000), &sel);
        assert!(out.contains("m=audio 0 RTP/AVP 0"));
        assert!(out.contains("m=image 20000 udptl t38"));

        // Non-T.38 multi-stream is untouched (legacy shared port).
        let av = sdp_with(&["m=audio 4000 RTP/AVP 0", "m=video 4002 RTP/AVP 96"]);
        let sel = select_anchored_stream(&av, StreamPreference::Audio).unwrap();
        let out =
            SdpRewriter::rewrite_with_selection(&av, &MediaAddress::new("10.0.0.1", 20000), &sel);
        assert!(out.contains("m=audio 20000"));
        assert!(out.contains("m=video 20000"));

        assert!(select_anchored_stream("garbage", StreamPreference::Audio).is_none());
        assert!(
            select_anchored_stream(&sdp_with(&["m=audio 0 RTP/AVP 0"]), StreamPreference::Audio)
                .is_none()
        );
    }

    /// QA: hostile multi-image offers anchor one stream and decline the
    /// rest in place (RFC 3264 §8: m-line count preserved).
    #[test]
    fn test_selection_two_images_and_hostile() {
        let two = sdp_with(&[
            "m=image 6000 udptl t38",
            "m=audio 4000 RTP/AVP 0",
            "m=image 6002 udptl t38",
        ]);
        let sel = select_anchored_stream(&two, StreamPreference::Image).unwrap();
        assert_eq!(sel.index, 0);
        let out =
            SdpRewriter::rewrite_with_selection(&two, &MediaAddress::new("10.0.0.1", 20000), &sel);
        assert_eq!(out.matches("m=").count(), 3);
        assert!(out.contains("m=image 20000 udptl t38"));
        assert!(out.contains("m=audio 0 RTP/AVP 0"));
        assert!(out.contains("m=image 0 udptl t38"));
        // Malformed SDP: no selection (caller answers 488), no panic.
        for bad in [
            sdp_with(&["m=image 99999 udptl t38"]),
            sdp_with(&["m=image"]),
            sdp_with(&["m=image 5000 TCPTL t38"]),
            String::from("v=0\r\nm=image 5000 udptl t38\r\n"),
        ] {
            assert!(
                select_anchored_stream(&bad, StreamPreference::Image).is_none(),
                "{bad:?}"
            );
        }
        // Out-of-range index and garbage for the address helper.
        assert!(extract_media_address_for("garbage", 0).is_none());
        assert!(stream_at(&two, 3).is_none());
        assert!(t38_params_at(&two, 9).is_none());
    }

    #[test]
    fn test_extract_media_address_for() {
        let a = extract_media_address_for(T38_REINVITE, 1).unwrap();
        assert_eq!((a.address.as_str(), a.port), ("192.0.2.20", 5000));
        let a = extract_media_address_for(T38_REINVITE, 0).unwrap();
        assert_eq!((a.address.as_str(), a.port), ("192.0.2.10", 0));
        assert!(extract_media_address_for(T38_REINVITE, 2).is_none());
        assert!(has_image_stream(T38_REINVITE));
        assert!(!has_image_stream(SAMPLE_SDP));
    }

    #[test]
    fn test_rewrite_t38_attributes() {
        let mut p = t38_params_at(T38_REINVITE, 1).unwrap();
        assert!(p.clamp(14400, 1400, 4096));
        let out = rewrite_t38_attributes(T38_REINVITE, 1, &p);
        assert!(out.contains("a=T38MaxBitRate:14400\r\n"));
        assert!(!out.contains("33600"));
        assert!(out.contains("a=T38FaxUdpEC:t38UDPRedundancy"));
        assert_eq!(t38_params_at(&out, 1).unwrap(), p);
        assert!(t38_params_at(&T38_REINVITE.replace("33600", "x"), 1).is_none());
    }

    #[test]
    fn test_sdp_rewrite_context_integration() {
        let mut ctx = SdpRewriteContext::new(B2buaMode::MediaRelay);

        // Set up B2BUA addresses
        ctx.set_a_leg_address(MediaAddress::new("10.0.0.1", 20000));
        ctx.set_b_leg_address(MediaAddress::new("10.0.0.1", 20002));

        // Store remote addresses from SDP
        ctx.set_a_leg_remote_address(MediaAddress::new("192.168.1.10", 30000));
        ctx.set_b_leg_remote_address(MediaAddress::new("172.16.0.10", 40000));

        // Create rewriter
        let rewriter = SdpRewriter::new(ctx.mode());

        // Rewrite offer for B-leg using B2BUA's B-leg address
        if let Some(addr) = ctx.address_for_b_leg() {
            let result = rewriter.rewrite_offer_for_b_leg(SAMPLE_SDP, addr);
            assert!(result.rewritten.contains("c=IN IP4 10.0.0.1"));
            assert!(result.rewritten.contains("m=audio 20002"));
        }
    }
}
