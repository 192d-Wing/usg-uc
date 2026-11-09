//! RFC 7866 Session Recording Client request builder.
//!
//! Pure functions, no I/O: given the RS SDP offer and the recording metadata,
//! produce the `multipart/mixed` body and the header values an SRC needs for
//! the initial RS INVITE to the SRS.
// POAM: POA&M-300 - nothing in sbc-daemon originates the RS INVITE yet
// (sbc-config rejects `[recording].enabled = true` until it does).
// POAM: POA&M-308 - inbound multipart/mixed (SRS-initiated requests) is not
// parsed.

use std::fmt::Write as _;

use proto_sdp::{Attribute, AttributeName, SessionDescription, TransportProtocol};
use zeroize::Zeroizing;

use crate::error::{SiprecError, SiprecResult};
use crate::metadata::{RecordingMetadata, base64_encode};

/// RFC 7866 §6.1.1: the SRC MUST include the `siprec` option tag in Require.
const REQUIRE_SIPREC: &str = "siprec";
/// RFC 7866 §6.1.1: the SRC MUST include `+sip.src` in its Contact.
const CONTACT_FEATURE_SRC: &str = "+sip.src";
/// RFC 7866 §9: metadata media type.
pub const METADATA_CONTENT_TYPE: &str = "application/rs-metadata+xml";

/// RFC 7714 §12: the only SDES crypto suite the RS offer uses (CNSA 2.0:
/// AES-256, no SHA-1 authentication tag).
pub const SDES_SUITE: &str = "AEAD_AES_256_GCM";
/// RFC 7714 §12: 256-bit master key followed by a 96-bit master salt.
const SDES_KEY_LEN: usize = 32;
const SDES_SALT_LEN: usize = 12;

/// SDES master key and salt for one forked RS stream (RFC 4568,
/// `AEAD_AES_256_GCM`). Zeroized on drop; `Debug` never prints the key.
///
/// RFC 4568 §8.3: SDES keys are sent in the SDP, so the RS INVITE MUST only
/// travel over a secure signalling channel (`sips:` / TLS to the SRS).
// NIST 800-53 Rev5: SC-12, SC-13, SI-12 (key material zeroized, never logged)
pub struct SdesKey {
    material: Zeroizing<[u8; SDES_KEY_LEN + SDES_SALT_LEN]>,
}

impl SdesKey {
    /// Generates a fresh key and salt from the `uc-crypto` CSPRNG.
    ///
    /// # Errors
    /// [`SiprecError::MetadataError`] if the RNG fails.
    pub fn generate() -> SiprecResult<Self> {
        let bytes = uc_crypto::random::generate_random::<{ SDES_KEY_LEN + SDES_SALT_LEN }>()
            .map_err(|e| SiprecError::MetadataError {
                reason: format!("RNG failure: {e}"),
            })?;
        Ok(Self {
            material: Zeroizing::new(bytes),
        })
    }

    /// The 256-bit SRTP master key.
    #[must_use]
    pub fn master_key(&self) -> &[u8] {
        self.material.get(..SDES_KEY_LEN).unwrap_or_default()
    }

    /// The 96-bit SRTP master salt.
    #[must_use]
    pub fn master_salt(&self) -> &[u8] {
        self.material.get(SDES_KEY_LEN..).unwrap_or_default()
    }

    /// `a=crypto` value: `<tag> AEAD_AES_256_GCM inline:<base64 key||salt>`.
    fn crypto_attr_value(&self, tag: u32) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{tag} {SDES_SUITE} inline:{}",
            Zeroizing::new(base64_encode(self.material.as_slice())).as_str()
        ))
    }
}

impl std::fmt::Debug for SdesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdesKey")
            .field("suite", &SDES_SUITE)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

/// Parts of an RS INVITE produced by [`build_rs_offer`].
///
/// RFC 7866 §6.1.1 header MUSTs are carried in [`RsInviteParts::headers`] so
/// the INVITE builder (POA&M-300) takes them from here rather than from loose
/// constants.
///
/// `body` carries the SDES `inline:` key material, so it is zeroized on drop
/// and [`Debug`] redacts it.
// NIST 800-53 Rev5: SC-12, SI-12 (key-bearing body zeroized, never logged)
#[derive(Clone)]
#[must_use = "the RS INVITE must carry the body and the SIPREC headers"]
pub struct RsInviteParts {
    /// `Content-Type` header value (`multipart/mixed;boundary=...`).
    pub content_type: String,
    /// Message body (contains SDES key material).
    pub body: Zeroizing<Vec<u8>>,
    /// Mandatory SIPREC header values.
    pub headers: SrcHeaders,
}

impl std::fmt::Debug for RsInviteParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsInviteParts")
            .field("content_type", &self.content_type)
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .field("headers", &self.headers)
            .finish()
    }
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
/// RFC 7866 §11 / POA&M-304: the RS media is SRTP only. Every m-line is
/// forced to `RTP/SAVP` and carries exactly one `a=crypto` for the `n`-th
/// entry of `keys` (any existing `a=crypto` is replaced). The body thus
/// holds key material: it MUST only be sent over TLS (RFC 4568 §8.3).
///
/// # Errors
///
/// - [`SiprecError::SdpError`] if the m-line count differs from the stream
///   count or from the key count.
/// - Any error from [`RecordingMetadata::to_rfc7865_xml`].
/// - [`SiprecError::MetadataError`] if no collision-free boundary could be
///   chosen or the RNG fails.
// NIST 800-53 Rev5: SI-10 - the boundary is random and verified absent from
// both parts, so attacker-influenced content cannot terminate a part early.
pub fn build_rs_offer(
    sdp: &SessionDescription,
    meta: &RecordingMetadata,
    keys: &[SdesKey],
) -> SiprecResult<RsInviteParts> {
    if keys.len() != sdp.media.len() {
        return Err(SiprecError::SdpError {
            reason: format!(
                "RS SDP has {} m-lines but {} SDES keys",
                sdp.media.len(),
                keys.len()
            ),
        });
    }
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
    let crypto_name = AttributeName::Custom("crypto".to_string());
    for ((m, stream), key) in sdp.media.iter_mut().zip(&meta.streams).zip(keys) {
        m.protocol = TransportProtocol::RtpSavp;
        m.attributes
            .retain(|a| a.name != label_name && a.name != crypto_name && !a.is_direction());
        m.attributes.push(Attribute::flag(AttributeName::Sendonly));
        m.attributes
            .push(Attribute::new(label_name.clone(), stream.id.clone()));
        m.attributes.push(Attribute::new(
            crypto_name.clone(),
            key.crypto_attr_value(1).as_str(),
        ));
    }
    let sdp_text = Zeroizing::new(sdp.to_string());
    // The clone holds key material in its attributes; scrub what we can.
    for m in &mut sdp.media {
        m.attributes.retain(|a| a.name != crypto_name);
    }

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

    // Sized up front so `write!` does not reallocate and leave an
    // un-zeroized copy of the key-bearing text behind.
    let mut body = Zeroizing::new(String::with_capacity(
        sdp_text.len() + xml.len() + 4 * boundary.len() + 256,
    ));
    let _ = write!(
        *body,
        "--{boundary}\r\nContent-Type: application/sdp\r\n\r\n{sdp_text}\r\n\
         --{boundary}\r\nContent-Type: {METADATA_CONTENT_TYPE}\r\n\
         Content-Disposition: recording-session\r\n\r\n{xml}\r\n--{boundary}--\r\n",
        sdp_text = sdp_text.as_str()
    );

    Ok(RsInviteParts {
        content_type: format!("multipart/mixed;boundary={boundary}"),
        body: Zeroizing::new(std::mem::take(&mut *body).into_bytes()),
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
        let parts = build_rs_offer(&sdp, &meta(), &keys())?;
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
        let body = std::str::from_utf8(&parts.body)?;

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
        let parts = build_rs_offer(&sdp, &meta(), &keys())?;
        let body = std::str::from_utf8(&parts.body)?;
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
            build_rs_offer(&sdp, &m, &keys()),
            Err(SiprecError::SdpError { .. })
        ));
        Ok(())
    }

    fn keys() -> Vec<SdesKey> {
        let mut k = Vec::new();
        for fill in [0x11u8, 0x22] {
            k.push(SdesKey {
                material: Zeroizing::new([fill; SDES_KEY_LEN + SDES_SALT_LEN]),
            });
        }
        k
    }

    #[test]
    fn offer_is_srtp_with_one_sdes_line_per_stream() -> Result<(), Box<dyn std::error::Error>> {
        let with_old_crypto = SDP.replace(
            "a=label:old\r\n",
            "a=label:old\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAA\r\n",
        );
        let sdp: SessionDescription = with_old_crypto.parse()?;
        let parts = build_rs_offer(&sdp, &meta(), &keys())?;
        let body = std::str::from_utf8(&parts.body)?;
        assert!(!body.contains("AES_CM_128"), "old crypto replaced");
        assert!(!body.contains("RTP/AVP "), "plain RTP refused");
        assert_eq!(body.matches("m=audio").count(), 2);
        assert_eq!(body.matches("RTP/SAVP").count(), 2);
        let k1 = base64_encode(&[0x11; 44]);
        let k2 = base64_encode(&[0x22; 44]);
        assert!(body.contains(&format!("a=crypto:1 AEAD_AES_256_GCM inline:{k1}\r\n")));
        assert!(body.contains(&format!("a=crypto:1 AEAD_AES_256_GCM inline:{k2}\r\n")));
        Ok(())
    }

    #[test]
    fn rejects_key_count_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let sdp: SessionDescription = SDP.parse()?;
        let mut k = keys();
        k.pop();
        assert!(matches!(
            build_rs_offer(&sdp, &meta(), &k),
            Err(SiprecError::SdpError { .. })
        ));
        Ok(())
    }

    /// QA: fresh keys are distinct, and the offer's inline value is exactly
    /// key || salt of the key handed in, per stream, in m-line order.
    #[test]
    fn generated_keys_are_distinct_and_carried_inline() -> Result<(), Box<dyn std::error::Error>> {
        let a = SdesKey::generate()?;
        let b = SdesKey::generate()?;
        assert_ne!(a.master_key(), b.master_key());
        assert_ne!(a.master_salt(), b.master_salt());
        let expect: Vec<String> = [&a, &b]
            .iter()
            .map(|k| base64_encode(&[k.master_key(), k.master_salt()].concat()))
            .collect();
        let sdp: SessionDescription = SDP.parse()?;
        let parts = build_rs_offer(&sdp, &meta(), &[a, b])?;
        let body = std::str::from_utf8(&parts.body)?;
        let lines: Vec<&str> = body
            .lines()
            .filter(|l| l.starts_with("a=crypto:"))
            .collect();
        assert_eq!(lines.len(), 2, "{body}");
        for (line, inline) in lines.iter().zip(&expect) {
            assert_eq!(
                line.trim_end(),
                format!("a=crypto:1 AEAD_AES_256_GCM inline:{inline}")
            );
        }
        let first = body.find(expect[0].as_str()).ok_or("key 1")?;
        let second = body.find(expect[1].as_str()).ok_or("key 2")?;
        assert!(first < second, "keys in m-line order");
        Ok(())
    }

    /// SEC-1: `RsInviteParts` Debug must not print the SDES `inline:` key
    /// carried in `body` (SC-12/SI-12).
    #[test]
    fn rs_invite_parts_debug_does_not_leak_key() -> Result<(), Box<dyn std::error::Error>> {
        let sdp: SessionDescription = SDP.parse()?;
        let parts = build_rs_offer(&sdp, &meta(), &keys())?;
        let dbg = format!("{parts:?}");
        let k1 = base64_encode(&[0x11; 44]);
        let raw: Vec<String> = [0x11u8; 8].iter().map(u8::to_string).collect();
        assert!(!dbg.contains(&k1));
        // The body bytes include b"inline:" followed by the base64 key.
        assert!(
            !dbg.contains(&raw.join(", ")) && !dbg.contains("105, 110, 108, 105, 110, 101, 58")
        );
        Ok(())
    }

    #[test]
    fn sdes_key_debug_is_redacted_and_split() -> Result<(), Box<dyn std::error::Error>> {
        let key = SdesKey::generate()?;
        let dbg = format!("{key:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(&base64_encode(key.master_key())));
        assert_eq!(key.master_key().len(), 32);
        assert_eq!(key.master_salt().len(), 12);
        Ok(())
    }
}
