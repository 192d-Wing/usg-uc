//! RFC 7866 Session Recording Client request builder.
//!
//! Pure functions, no I/O: given the RS SDP offer and the recording metadata,
//! produce the `multipart/mixed` body and the header values an SRC needs for
//! the initial RS INVITE to the SRS.
// POAM: POA&M-300 - nothing in sbc-daemon originates the RS INVITE yet.
// POAM: POA&M-308 - inbound multipart/mixed (SRS-initiated requests) is not
// parsed.

use std::fmt::Write as _;

use proto_sdp::{Attribute, AttributeName, SessionDescription};

use crate::error::{SiprecError, SiprecResult};
use crate::metadata::{RecordingMetadata, base64_encode};

/// RFC 7866 §6.1.1: the SRC MUST include the `siprec` option tag in Require.
const REQUIRE_SIPREC: &str = "siprec";
/// RFC 7866 §6.1.1: the SRC MUST include `+sip.src` in its Contact.
const CONTACT_FEATURE_SRC: &str = "+sip.src";
/// RFC 7866 §9: metadata media type.
pub const METADATA_CONTENT_TYPE: &str = "application/rs-metadata+xml";

/// Parts of an RS INVITE produced by [`build_rs_offer`].
///
/// RFC 7866 §6.1.1 header MUSTs are carried in [`RsInviteParts::headers`] so
/// the INVITE builder (POA&M-300) takes them from here rather than from loose
/// constants.
#[derive(Debug, Clone)]
#[must_use = "the RS INVITE must carry the body and the SIPREC headers"]
pub struct RsInviteParts {
    /// `Content-Type` header value (`multipart/mixed;boundary=...`).
    pub content_type: String,
    /// Message body.
    pub body: Vec<u8>,
    /// Mandatory SIPREC header values.
    pub headers: SrcHeaders,
}

/// RFC 7866 §6.1.1 headers the SRC MUST send on the RS INVITE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SrcHeaders;

impl SrcHeaders {
    /// Value for the `Require` header (`siprec`).
    #[must_use]
    pub const fn require(&self) -> &'static str {
        REQUIRE_SIPREC
    }

    /// Contact header parameter marking this UA as an SRC (`+sip.src`).
    #[must_use]
    pub const fn contact_feature(&self) -> &'static str {
        CONTACT_FEATURE_SRC
    }

    /// Formats a Contact header value `<uri>;+sip.src` for `contact_uri`.
    #[must_use]
    pub fn contact_value(&self, contact_uri: &str) -> String {
        format!("<{contact_uri}>;{CONTACT_FEATURE_SRC}")
    }
}

/// Builds the RS INVITE body: the SDP offer with one `a=label` per media
/// stream (RFC 7866 §8.1.1) and the RFC 7865 metadata with
/// `Content-Disposition: recording-session` (RFC 7866 §9.1).
///
/// The `n`-th m-line of `sdp` gets the label of the `n`-th
/// [`RecordingMetadata::streams`] entry; an existing `a=label` is replaced.
/// RFC 7866 §8.1.1: the SRC sends the recorded media, so every m-line is
/// forced to `a=sendonly` (any other direction attribute is replaced).
///
/// # Errors
///
/// - [`SiprecError::SdpError`] if the m-line count differs from the stream count.
/// - Any error from [`RecordingMetadata::to_rfc7865_xml`].
/// - [`SiprecError::MetadataError`] if no collision-free boundary could be
///   chosen or the RNG fails.
// NIST 800-53 Rev5: SI-10 - the boundary is random and verified absent from
// both parts, so attacker-influenced content cannot terminate a part early.
pub fn build_rs_offer(
    sdp: &SessionDescription,
    meta: &RecordingMetadata,
) -> SiprecResult<RsInviteParts> {
    if sdp.media.len() != meta.streams.len() {
        return Err(SiprecError::SdpError {
            reason: format!(
                "RS SDP has {} m-lines but metadata has {} streams",
                sdp.media.len(),
                meta.streams.len()
            ),
        });
    }

    // Serializing first also validates every label as an RFC 4574 token.
    let xml = meta.to_rfc7865_xml()?;

    let mut sdp = sdp.clone();
    let label_name = AttributeName::Custom("label".to_string());
    for (m, stream) in sdp.media.iter_mut().zip(&meta.streams) {
        m.attributes
            .retain(|a| a.name != label_name && !a.is_direction());
        m.attributes.push(Attribute::flag(AttributeName::Sendonly));
        m.attributes
            .push(Attribute::new(label_name.clone(), stream.id.clone()));
    }
    let sdp_text = sdp.to_string();

    // RFC 2046 §5.1.1: the boundary MUST NOT appear in an encapsulated part.
    // A 128-bit random boundary colliding is improbable; regenerate once,
    // then fail closed.
    let mut boundary = None;
    for _ in 0..2 {
        let candidate = random_boundary()?;
        if !sdp_text.contains(&candidate) && !xml.contains(&candidate) {
            boundary = Some(candidate);
            break;
        }
    }
    let boundary = boundary.ok_or_else(|| SiprecError::MetadataError {
        reason: "could not choose a multipart boundary".to_string(),
    })?;

    let mut body = String::with_capacity(sdp_text.len() + xml.len() + 256);
    let _ = write!(
        body,
        "--{boundary}\r\nContent-Type: application/sdp\r\n\r\n{sdp_text}\r\n\
         --{boundary}\r\nContent-Type: {METADATA_CONTENT_TYPE}\r\n\
         Content-Disposition: recording-session\r\n\r\n{xml}\r\n--{boundary}--\r\n"
    );

    Ok(RsInviteParts {
        content_type: format!("multipart/mixed;boundary={boundary}"),
        body: body.into_bytes(),
        headers: SrcHeaders,
    })
}

fn random_boundary() -> SiprecResult<String> {
    let bytes: [u8; 16] =
        uc_crypto::random::generate_random().map_err(|e| SiprecError::MetadataError {
            reason: format!("RNG failure: {e}"),
        })?;
    // '+', '/' and '=' are legal bchars (RFC 2046 §5.1.1) but quoting would be
    // needed for '/', so map to an unquoted-safe alphabet.
    let b64: String = base64_encode(&bytes)
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    Ok(format!("uc-siprec-{b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{MediaStream, Participant};

    const SDP: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
        m=audio 10000 RTP/AVP 0\r\na=sendonly\r\na=label:old\r\n\
        m=audio 10002 RTP/AVP 0\r\na=sendonly\r\n";

    fn meta() -> RecordingMetadata {
        let mut m = RecordingMetadata::new("call@example.com");
        m.add_participant(Participant::new("a", "sip:a@example.com"));
        m.add_participant(Participant::new("b", "sip:b@example.com"));
        m.add_stream(MediaStream::audio("1").with_participant("a"));
        m.add_stream(MediaStream::audio("2").with_participant("b"));
        m
    }

    #[test]
    fn builds_multipart_with_labels_and_disposition() -> Result<(), Box<dyn std::error::Error>> {
        let sdp: SessionDescription = SDP.parse()?;
        let parts = build_rs_offer(&sdp, &meta())?;
        assert_eq!(parts.headers.require(), "siprec");
        assert_eq!(parts.headers.contact_feature(), "+sip.src");
        assert_eq!(
            parts.headers.contact_value("sip:src@192.0.2.1"),
            "<sip:src@192.0.2.1>;+sip.src"
        );
        let boundary = parts
            .content_type
            .strip_prefix("multipart/mixed;boundary=")
            .ok_or("boundary")?;
        let body = String::from_utf8(parts.body)?;

        let delim = format!("--{boundary}");
        let sections: Vec<&str> = body.split(delim.as_str()).collect();
        // preamble(empty), sdp, metadata, "--\r\n"
        assert_eq!(sections.len(), 4);
        assert_eq!(sections.first().copied(), Some(""));
        assert_eq!(sections.get(3).copied(), Some("--\r\n"));

        let sdp_part = sections.get(1).ok_or("sdp part")?;
        assert!(sdp_part.starts_with("\r\nContent-Type: application/sdp\r\n\r\n"));
        assert!(sdp_part.contains("a=label:1"));
        assert!(sdp_part.contains("a=label:2"));
        assert!(!sdp_part.contains("a=label:old"));

        let meta_part = sections.get(2).ok_or("metadata part")?;
        assert!(meta_part.contains("Content-Type: application/rs-metadata+xml\r\n"));
        assert!(meta_part.contains("Content-Disposition: recording-session\r\n"));
        assert!(meta_part.contains("<label>1</label>"));
        Ok(())
    }

    #[test]
    fn forces_sendonly_direction() -> Result<(), Box<dyn std::error::Error>> {
        let sdp: SessionDescription = SDP.replace("a=sendonly", "a=sendrecv").parse()?;
        let parts = build_rs_offer(&sdp, &meta())?;
        let body = String::from_utf8(parts.body)?;
        assert!(!body.contains("a=sendrecv"));
        assert_eq!(body.matches("a=sendonly").count(), 2);
        Ok(())
    }

    #[test]
    fn rejects_stream_count_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let sdp: SessionDescription = SDP.parse()?;
        let mut m = meta();
        m.streams.pop();
        assert!(matches!(
            build_rs_offer(&sdp, &m),
            Err(SiprecError::SdpError { .. })
        ));
        Ok(())
    }
}
