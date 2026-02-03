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

use crate::B2buaMode;
use crate::mode::{MediaAddress, ModeCharacteristics, SdpModification};

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
                let rewritten = self.rewrite_connection_and_port(sdp, local_address);
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
                let rewritten = self.rewrite_connection_and_port(sdp, local_address);
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
        let mut rewritten = self.rewrite_connection_and_port(sdp, local_address);

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
        let mut rewritten = self.rewrite_connection_and_port(sdp, local_address);

        // Change direction back to sendrecv
        rewritten = rewritten.replace("a=sendonly", "a=sendrecv");
        rewritten = rewritten.replace("a=inactive", "a=sendrecv");
        rewritten = rewritten.replace("a=recvonly", "a=sendrecv");

        SdpRewriteResult::modified(sdp.to_string(), rewritten)
    }

    /// Internal: Rewrite connection (c=) and media port (m=) lines.
    fn rewrite_connection_and_port(&self, sdp: &str, local_address: &MediaAddress) -> String {
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
                result.push_str(&format!("c=IN {} {}", addr_type, local_address.address));
            } else if line.starts_with("m=") {
                // Replace port in media line
                // Format: m=<media> <port> <proto> <fmt> ...
                if let Some(rewritten) = self.rewrite_media_line(line, local_address.port) {
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
    fn rewrite_media_line(&self, line: &str, port: u16) -> Option<String> {
        // m=audio 49170 RTP/SAVP 0 8 97
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 4 {
            return None;
        }

        Some(format!("{} {} {} {}", parts[0], port, parts[2], parts[3]))
    }
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
