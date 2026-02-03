//! SDP munging for WebRTC compatibility.
//!
//! This module provides SDP transformation utilities to ensure
//! compatibility between SIP and WebRTC endpoints.

use crate::config::SdpConfig;
use crate::error::WebRtcResult;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, warn};

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

/// SDP munger for WebRTC compatibility.
#[derive(Debug, Clone)]
pub struct SdpMunger {
    /// Configuration.
    config: SdpConfig,
}

impl SdpMunger {
    /// Creates a new SDP munger with the given configuration.
    #[must_use]
    pub fn new(config: SdpConfig) -> Self {
        Self { config }
    }

    /// Creates a munger with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(SdpConfig::default())
    }

    /// Transforms SDP for the given mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDP is malformed.
    pub fn transform(&self, sdp: &str, mode: WebRtcSdpMode) -> WebRtcResult<String> {
        match mode {
            WebRtcSdpMode::SipToWebRtc => self.sip_to_webrtc(sdp),
            WebRtcSdpMode::WebRtcToSip => self.webrtc_to_sip(sdp),
            WebRtcSdpMode::Passthrough => Ok(sdp.to_string()),
        }
    }

    /// Converts SIP SDP to WebRTC SDP.
    fn sip_to_webrtc(&self, sdp: &str) -> WebRtcResult<String> {
        let mut lines: Vec<String> = Vec::new();
        let mut in_media = false;
        let mut current_media;
        let mut has_rtcp_mux = false;
        let mut media_mids: Vec<String> = Vec::new();

        for line in sdp.lines() {
            let line = line.trim();

            // Track media section
            if line.starts_with("m=") {
                // Process previous media section
                if in_media && self.config.rtcp_mux && !has_rtcp_mux {
                    lines.push("a=rtcp-mux".to_string());
                }

                in_media = true;
                current_media = extract_media_type(line);
                has_rtcp_mux = false;

                // Generate mid for bundle
                let mid = format!("{}{}", current_media, media_mids.len());
                media_mids.push(mid);

                lines.push(line.to_string());
                continue;
            }

            // Skip SDES crypto lines if forcing DTLS-SRTP
            if self.config.force_dtls_srtp && line.starts_with("a=crypto:") {
                debug!(line, "Stripping SDES crypto attribute for WebRTC");
                continue;
            }

            // Track attributes
            if line.starts_with("a=rtcp-mux") {
                has_rtcp_mux = true;
            }

            // Add mid if in media section and this is rtpmap line
            if in_media && line.starts_with("a=rtpmap:") && !media_mids.is_empty() {
                // Insert mid before rtpmap if not already added
                if !lines.iter().any(|l| l.starts_with("a=mid:")) {
                    if let Some(mid) = media_mids.last() {
                        lines.push(format!("a=mid:{mid}"));
                    }
                }
            }

            lines.push(line.to_string());
        }

        // Add final rtcp-mux if needed
        if in_media && self.config.rtcp_mux && !has_rtcp_mux {
            lines.push("a=rtcp-mux".to_string());
        }

        // Add bundle group at session level if enabled
        if self.config.bundle && !media_mids.is_empty() {
            // Find where to insert (after o= line)
            if let Some(pos) = lines.iter().position(|l| l.starts_with("o=")) {
                let bundle_line = format!("a=group:BUNDLE {}", media_mids.join(" "));
                // Insert after timing line if present, or after origin
                let insert_pos = lines
                    .iter()
                    .position(|l| l.starts_with("t="))
                    .map_or(pos + 1, |p| p + 1);
                lines.insert(insert_pos, bundle_line);
            }
        }

        Ok(lines.join("\r\n") + "\r\n")
    }

    /// Converts WebRTC SDP to SIP SDP.
    fn webrtc_to_sip(&self, sdp: &str) -> WebRtcResult<String> {
        let mut lines: Vec<String> = Vec::new();
        let webrtc_only_attrs: HashSet<&str> = [
            "a=ice-options:",
            "a=msid:",
            "a=ssrc-group:",
            "a=rtcp-rsize",
            "a=sctpmap:",
            "a=sctp-port:",
            "a=max-message-size:",
        ]
        .into_iter()
        .collect();

        for line in sdp.lines() {
            let line = line.trim();

            // Skip WebRTC-only attributes that SIP endpoints don't understand
            if webrtc_only_attrs.iter().any(|attr| line.starts_with(attr)) {
                debug!(line, "Stripping WebRTC-only attribute for SIP");
                continue;
            }

            // Skip data channel media sections
            if line.starts_with("m=application") && line.contains("webrtc-datachannel") {
                warn!("Skipping WebRTC data channel - not supported in SIP");
                continue;
            }

            lines.push(line.to_string());
        }

        Ok(lines.join("\r\n") + "\r\n")
    }

    /// Adds DTLS fingerprint to SDP.
    #[must_use]
    pub fn add_fingerprint(&self, sdp: &str, algorithm: &str, fingerprint: &str) -> String {
        let fingerprint_line = format!("a=fingerprint:{algorithm} {fingerprint}");

        // Add at session level (after o= line)
        let mut lines: Vec<&str> = sdp.lines().collect();
        if let Some(pos) = lines.iter().position(|l| l.starts_with("o=")) {
            lines.insert(pos + 1, &fingerprint_line);
        }

        lines.join("\r\n") + "\r\n"
    }

    /// Adds ICE credentials to SDP.
    #[must_use]
    pub fn add_ice_credentials(&self, sdp: &str, ufrag: &str, pwd: &str) -> String {
        let ufrag_line = format!("a=ice-ufrag:{ufrag}");
        let pwd_line = format!("a=ice-pwd:{pwd}");

        let mut result = sdp.to_string();

        // Add at session level if not present
        if !result.contains("a=ice-ufrag:") {
            // Insert after o= line
            if let Some(pos) = result.find("\r\no=") {
                if let Some(end) = result[pos + 4..].find("\r\n") {
                    let insert_pos = pos + 4 + end + 2;
                    result.insert_str(insert_pos, &format!("{ufrag_line}\r\n{pwd_line}\r\n"));
                }
            }
        }

        result
    }

    /// Adds an ICE candidate to SDP.
    #[must_use]
    pub fn add_candidate(&self, sdp: &str, candidate: &str, media_index: usize) -> String {
        let candidate_line = if candidate.starts_with("a=") {
            candidate.to_string()
        } else if candidate.starts_with("candidate:") {
            format!("a={candidate}")
        } else {
            format!("a=candidate:{candidate}")
        };

        let mut lines: Vec<&str> = sdp.lines().collect();
        let mut current_media = 0;
        let mut insert_pos = None;

        for (i, line) in lines.iter().enumerate() {
            if line.starts_with("m=") {
                if current_media == media_index {
                    // Find position after this media section's attributes
                    insert_pos = Some(i + 1);
                }
                current_media += 1;
            }
            if insert_pos.is_some() && current_media > media_index && line.starts_with("m=") {
                // Reached next media section, insert before it
                insert_pos = Some(i);
                break;
            }
        }

        if let Some(pos) = insert_pos {
            let pos = pos.min(lines.len());
            lines.insert(pos, &candidate_line);
        }

        lines.join("\r\n") + "\r\n"
    }

    /// Sets the setup attribute for DTLS role.
    #[must_use]
    pub fn set_setup(&self, sdp: &str, setup: &str) -> String {
        let setup_line = format!("a=setup:{setup}");
        let mut result = String::new();
        let mut setup_added = false;

        for line in sdp.lines() {
            if line.starts_with("a=setup:") {
                // Replace existing setup
                result.push_str(&setup_line);
                setup_added = true;
            } else {
                result.push_str(line);
            }
            result.push_str("\r\n");
        }

        // Add setup if not present (after fingerprint or at session level)
        if !setup_added {
            if let Some(pos) = result.find("a=fingerprint:") {
                if let Some(end) = result[pos..].find("\r\n") {
                    let insert_pos = pos + end + 2;
                    result.insert_str(insert_pos, &format!("{setup_line}\r\n"));
                }
            }
        }

        result
    }

    /// Extracts the DTLS fingerprint from SDP.
    #[must_use]
    pub fn extract_fingerprint(sdp: &str) -> Option<(String, String)> {
        for line in sdp.lines() {
            if let Some(rest) = line.strip_prefix("a=fingerprint:") {
                let parts: Vec<&str> = rest.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    return Some((parts[0].to_string(), parts[1].to_string()));
                }
            }
        }
        None
    }

    /// Extracts ICE credentials from SDP.
    #[must_use]
    pub fn extract_ice_credentials(sdp: &str) -> Option<(String, String)> {
        let mut ufrag = None;
        let mut pwd = None;

        for line in sdp.lines() {
            if let Some(rest) = line.strip_prefix("a=ice-ufrag:") {
                ufrag = Some(rest.to_string());
            }
            if let Some(rest) = line.strip_prefix("a=ice-pwd:") {
                pwd = Some(rest.to_string());
            }
        }

        match (ufrag, pwd) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        }
    }

    /// Extracts ICE candidates from SDP.
    #[must_use]
    pub fn extract_candidates(sdp: &str) -> Vec<String> {
        sdp.lines()
            .filter(|line| line.starts_with("a=candidate:"))
            .map(|line| line.strip_prefix("a=").unwrap_or(line).to_string())
            .collect()
    }
}

/// Extracts media type from m= line.
fn extract_media_type(line: &str) -> String {
    line.strip_prefix("m=")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("unknown")
        .to_string()
}

impl Default for SdpMunger {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SAMPLE_SIP_SDP: &str = "v=0\r\n\
o=- 123456 123456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
c=IN IP4 192.168.1.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:key\r\n";

    const SAMPLE_WEBRTC_SDP: &str = "v=0\r\n\
o=- 123456 123456 IN IP4 0.0.0.0\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE audio\r\n\
a=ice-ufrag:abc\r\n\
a=ice-pwd:xyz123\r\n\
a=fingerprint:sha-384 AA:BB:CC\r\n\
a=setup:actpass\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:audio\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=rtcp-mux\r\n\
a=msid:stream track\r\n\
a=candidate:1 1 UDP 2130706431 192.168.1.1 54400 typ host\r\n";

    #[test]
    fn test_sip_to_webrtc() {
        let munger = SdpMunger::default();
        let result = munger.sip_to_webrtc(SAMPLE_SIP_SDP).unwrap();

        // Should strip SDES crypto
        assert!(!result.contains("a=crypto:"));
        // Should add rtcp-mux
        assert!(result.contains("a=rtcp-mux"));
    }

    #[test]
    fn test_webrtc_to_sip() {
        let munger = SdpMunger::default();
        let result = munger.webrtc_to_sip(SAMPLE_WEBRTC_SDP).unwrap();

        // Should strip WebRTC-only attributes
        assert!(!result.contains("a=msid:"));
    }

    #[test]
    fn test_extract_fingerprint() {
        let fingerprint = SdpMunger::extract_fingerprint(SAMPLE_WEBRTC_SDP);
        assert!(fingerprint.is_some());
        let (algo, fp) = fingerprint.unwrap();
        assert_eq!(algo, "sha-384");
        assert_eq!(fp, "AA:BB:CC");
    }

    #[test]
    fn test_extract_ice_credentials() {
        let creds = SdpMunger::extract_ice_credentials(SAMPLE_WEBRTC_SDP);
        assert!(creds.is_some());
        let (ufrag, pwd) = creds.unwrap();
        assert_eq!(ufrag, "abc");
        assert_eq!(pwd, "xyz123");
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
        let result = munger.add_fingerprint(SAMPLE_SIP_SDP, "sha-384", "AA:BB:CC");
        assert!(result.contains("a=fingerprint:sha-384 AA:BB:CC"));
    }

    #[test]
    fn test_set_setup() {
        let munger = SdpMunger::default();
        let result = munger.set_setup(SAMPLE_WEBRTC_SDP, "active");
        assert!(result.contains("a=setup:active"));
        assert!(!result.contains("a=setup:actpass"));
    }
}
