//! Validation of the SRS answer to the RS offer, and the CS recording
//! preference check.
//!
//! Pure functions, no I/O. The SRS is an authenticated peer (TLS, POA&M-304)
//! but its SDP is still hostile input: everything here is bounds-checked and
//! fails closed with [`SiprecError::SdpError`]. Reasons never echo a value
//! taken from the answer, so they are safe to log and audit.
// POAM: POA&M-301 - no RTCP is sent on the RS, so `rtcp_mux` is reported to
// the caller but nothing acts on it yet; an `a=rtcp:` port in the answer is
// ignored.
// POAM: POA&M-308 - an SRS answer that pauses a stream (`a=inactive`) is
// rejected rather than honoured.

use std::net::{IpAddr, SocketAddr};

use proto_sdp::{
    Attribute, AttributeName, MediaDescription, MediaType, SessionDescription, TransportProtocol,
};

use crate::error::{SiprecError, SiprecResult};
use crate::src_request::SDES_SUITE;

/// Upper bound on RS streams an answer is checked against. The phase 3 SRC
/// offers two (one per CS leg); the cap keeps the result vector bounded
/// whatever the caller passes.
// NIST 800-53 Rev5: SC-5 (bounded state)
pub const MAX_RS_ANSWER_STREAMS: usize = 16;

/// Upper bound on the SDP text [`has_recordpref_never`] scans. Lines that
/// start past this offset are not examined.
// NIST 800-53 Rev5: SC-5 (bounded work on attacker-sized input)
pub const MAX_RECORDPREF_SCAN_BYTES: usize = 64 * 1024;

/// RFC 4568 §4.1 / §5.1.2: the tag the RS offer uses ([`build_rs_offer`]
/// emits tag 1 on every m-line) and the answer MUST echo.
///
/// [`build_rs_offer`]: crate::src_request::build_rs_offer
const OFFERED_CRYPTO_TAG: &str = "1";
/// RFC 4568 §6.1: SRTP key parameters use the `inline` key method.
const KEY_METHOD_PREFIX: &str = "inline:";
/// RFC 7714 §12: 256-bit key + 96-bit salt = 44 octets, which is 60 base64
/// characters ending in exactly one pad (RFC 4648 §4).
const INLINE_KEY_B64_LEN: usize = 60;
/// RFC 4568 §6.3: session parameters that must be negotiated (or that
/// weaken SRTP). The RS offer carries none, so the answer must not either.
const REFUSED_SESSION_PARAMS: [&str; 5] = [
    "UNENCRYPTED_SRTP",
    "UNENCRYPTED_SRTCP",
    "UNAUTHENTICATED_SRTP",
    "FEC_ORDER",
    "FEC_KEY",
];

/// One accepted stream of the SRS answer, in m-line order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsAnswerStream {
    /// Where the SRS wants the forked SRTP for this stream.
    pub addr: SocketAddr,
    /// The SRS accepted `a=rtcp-mux` (RFC 5761 §5.1.1) for this stream.
    pub rtcp_mux: bool,
}

/// Validates the SRS answer to the RS offer and returns the forked-media
/// destination of each stream, in m-line order.
///
/// Every m-line must be accepted; a partial answer is an error so the
/// caller applies the recording failure policy instead of recording one leg.
/// Per m-line the answer must have:
///
/// - `audio`, a non-zero port and no port count (RFC 3264 §6: port 0 is a
///   rejected stream);
/// - `RTP/SAVP` (RFC 3264 §6: the offered profile; RFC 7866 §12.2: the RS
///   media stays SRTP);
/// - exactly one `a=crypto`, with the offered tag `1`, the offered suite
///   `AEAD_AES_256_GCM`, one well-formed `inline:` key and no negotiated
///   session parameter (RFC 4568 §5.1.2, §6.3);
/// - direction `recvonly` (RFC 7866 §7.2; RFC 3264 §6.1), at media level
///   or inherited from session level;
/// - an `IN IP4`/`IN IP6` literal connection address that is unicast and
///   not loopback or unspecified (media or session level `c=`).
///
/// The SRS key is validated for shape only and is neither copied nor
/// returned: the SRC only sends, and what the offerer sends is protected
/// with the offerer's key (RFC 4568 §7.1.x). The caller still owns the
/// answer text and should drop it promptly.
///
/// # Errors
///
/// [`SiprecError::SdpError`] on any violation, and when `expected_streams`
/// is zero or above [`MAX_RS_ANSWER_STREAMS`].
// NIST 800-53 Rev5: SI-10 (RS answer validation), SC-7 (fork destination
// class), SC-8 / SC-13 (no downgrade from SRTP AEAD_AES_256_GCM), SC-24
// (fail to a known state on any violation).
pub fn parse_rs_answer(
    sdp: &SessionDescription,
    expected_streams: usize,
) -> SiprecResult<Vec<RsAnswerStream>> {
    if expected_streams == 0 || expected_streams > MAX_RS_ANSWER_STREAMS {
        return Err(SiprecError::SdpError {
            reason: "RS answer: expected stream count out of range".to_string(),
        });
    }
    // RFC 3264 §6: the answer MUST have exactly as many m-lines as the offer.
    if sdp.media.len() != expected_streams {
        return Err(SiprecError::SdpError {
            reason: format!(
                "RS answer has {} m-lines, offer had {expected_streams}",
                sdp.media.len()
            ),
        });
    }

    let mut streams = Vec::with_capacity(expected_streams);
    for (index, m) in sdp.media.iter().enumerate() {
        streams.push(check_stream(sdp, m).map_err(|what| SiprecError::SdpError {
            reason: format!("RS answer stream {index}: {what}"),
        })?);
    }
    Ok(streams)
}

/// Checks one answered m-line. The error is a fixed description, never a
/// value from the answer.
fn check_stream(
    sdp: &SessionDescription,
    m: &MediaDescription,
) -> Result<RsAnswerStream, &'static str> {
    if m.media_type != MediaType::Audio {
        return Err("media type is not audio");
    }
    if m.port == 0 {
        return Err("stream rejected by the SRS (port 0)");
    }
    if m.num_ports.is_some_and(|n| n != 1) {
        return Err("port count not supported");
    }
    if m.protocol != TransportProtocol::RtpSavp {
        return Err("transport profile is not RTP/SAVP");
    }
    check_crypto(m)?;
    check_direction(sdp, m)?;
    let ip = connection_ip(sdp, m)?;
    Ok(RsAnswerStream {
        addr: SocketAddr::new(ip, m.port),
        rtcp_mux: m.has_rtcp_mux(),
    })
}

/// RFC 4568 §5.1.2: the answer carries exactly one `a=crypto`, echoing the
/// tag and crypto suite of the offered line it accepts.
fn check_crypto(m: &MediaDescription) -> Result<(), &'static str> {
    let mut lines = m.attributes.iter().filter(|a| is_named(a, "crypto"));
    let line = lines.next().ok_or("no a=crypto")?;
    if lines.next().is_some() {
        return Err("more than one a=crypto");
    }
    let value = line.value.as_deref().ok_or("a=crypto has no value")?;

    let mut fields = value.split_ascii_whitespace();
    // Compared as text: `"+1".parse::<u32>()` would also yield 1.
    if fields.next() != Some(OFFERED_CRYPTO_TAG) {
        return Err("a=crypto tag is not the offered tag");
    }
    if !fields
        .next()
        .is_some_and(|suite| suite.eq_ignore_ascii_case(SDES_SUITE))
    {
        return Err("a=crypto suite is not AEAD_AES_256_GCM");
    }
    let key_params = fields.next().ok_or("a=crypto has no key")?;
    if !inline_key_is_well_formed(key_params) {
        return Err("a=crypto key is malformed");
    }
    for param in fields {
        let name = param.split_once('=').map_or(param, |(name, _)| name);
        if REFUSED_SESSION_PARAMS
            .iter()
            .any(|refused| name.eq_ignore_ascii_case(refused))
        {
            return Err("a=crypto carries a refused session parameter");
        }
    }
    Ok(())
}

/// RFC 4568 §6.1: `inline:<key||salt>["|" lifetime]["|" MKI ":" length]`.
/// One key only (the offer had one); lifetime and MKI are ignored because
/// the SRS key is never used. Shape check only, nothing is decoded or kept.
fn inline_key_is_well_formed(key_params: &str) -> bool {
    if key_params.contains(';') {
        return false;
    }
    let Some(prefix) = key_params.get(..KEY_METHOD_PREFIX.len()) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(KEY_METHOD_PREFIX) {
        return false;
    }
    let rest = key_params
        .get(KEY_METHOD_PREFIX.len()..)
        .unwrap_or_default();
    let key = rest.split('|').next().unwrap_or_default().as_bytes();
    let Some((pad, body)) = key.split_last() else {
        return false;
    };
    key.len() == INLINE_KEY_B64_LEN
        && *pad == b'='
        && body
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

/// RFC 7866 §7.2: the SRS answers the SRC's `a=sendonly` streams with
/// `a=recvonly`. RFC 3264 §6.1: a session-level direction applies to an
/// m-line that has none; with neither the default is `sendrecv`.
fn check_direction(sdp: &SessionDescription, m: &MediaDescription) -> Result<(), &'static str> {
    let direction = match single_direction(&m.attributes)? {
        Some(d) => Some(d),
        None => single_direction(&sdp.attributes)?,
    };
    match direction {
        Some(AttributeName::Recvonly) => Ok(()),
        _ => Err("direction is not recvonly"),
    }
}

/// The one direction attribute in `attrs`, `None` if there is none. Two or
/// more is ambiguous and refused.
fn single_direction(attrs: &[Attribute]) -> Result<Option<&AttributeName>, &'static str> {
    let mut found = attrs.iter().filter(|a| a.is_direction()).map(|a| &a.name);
    let first = found.next();
    if found.next().is_some() {
        return Err("more than one direction attribute");
    }
    Ok(first)
}

/// Media-level `c=` wins over session-level (RFC 4566 §5.7). Only address
/// literals are accepted: an FQDN would need a resolver, and a multicast
/// `addr/ttl` form does not parse as an address.
// NIST 800-53 Rev5: SC-7 - the fork must not be pointed at the SBC itself
// (loopback, unspecified) or at a group address.
fn connection_ip(sdp: &SessionDescription, m: &MediaDescription) -> Result<IpAddr, &'static str> {
    let c = m
        .connection
        .as_ref()
        .or(sdp.connection.as_ref())
        .ok_or("no connection address")?;
    if c.net_type != "IN" {
        return Err("connection network type is not IN");
    }
    let ip: IpAddr = c
        .address
        .parse()
        .map_err(|_| "connection address is not an IP literal")?;
    let family_matches = match ip {
        IpAddr::V4(_) => c.addr_type == "IP4",
        IpAddr::V6(_) => c.addr_type == "IP6",
    };
    if !family_matches {
        return Err("connection address does not match its address type");
    }
    // An IPv4-mapped IPv6 literal is judged as the IPv4 address it reaches.
    let effective = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    let broadcast = matches!(effective, IpAddr::V4(v4) if v4.is_broadcast());
    if effective.is_unspecified()
        || effective.is_loopback()
        || effective.is_multicast()
        || broadcast
    {
        return Err("connection address is not a usable unicast address");
    }
    Ok(ip)
}

/// True for a custom attribute called `name` (ASCII case-insensitive, so a
/// second `a=Crypto` line still counts as an extra one).
fn is_named(attr: &Attribute, name: &str) -> bool {
    matches!(&attr.name, AttributeName::Custom(n) if n.eq_ignore_ascii_case(name))
}

/// Returns true if a CS offer or answer asks not to be recorded.
///
/// RFC 7866 §7.1.3 / §7.3.2 define `a=recordpref` with the values `on`,
/// `off`, `pause` and `nopreference`; the request not to record is `off`.
/// `never` is not an RFC 7866 value: it is accepted as a non-standard alias
/// of `off` (the `[recording].recordpref_never` config key is named after
/// it), so the configured policy acts on what conforming user agents send.
///
/// Scope (RFC 7866 §7.3.2, RFC 8866 §6): a media-level `a=recordpref`
/// overrides the session-level one for its stream. The preference is
/// evaluated for the stream the SBC records, the first active (`port != 0`)
/// `m=audio` line: its own value when it carries one, else the
/// session-level value. With no active audio m-line only the session level
/// counts.
///
/// Works on the raw text so it does not depend on the body parsing as SDP.
/// Name and value are matched ASCII case-insensitively and surrounding
/// whitespace is tolerated. Only the first [`MAX_RECORDPREF_SCAN_BYTES`]
/// are scanned.
///
/// The attribute is set by the far end: whether an opt-out is honoured is
/// the caller's policy decision (`recordpref_never = honour | ignore`).
// NIST 800-53 Rev5: SI-10 (bounded, allocation-free scan of untrusted SDP),
// PT-5 (participant recording preference).
#[must_use]
pub fn has_recordpref_never(sdp_text: &str) -> bool {
    /// Where the scan is: before the first m-line, inside the recorded
    /// audio m-line, or inside any other m-line.
    #[derive(PartialEq, Eq)]
    enum Scope {
        Session,
        RecordedAudio,
        OtherMedia,
    }
    let mut scope = Scope::Session;
    let mut audio_seen = false;
    // `Some(true)`: opt-out; `Some(false)`: another preference was stated.
    let mut session_pref: Option<bool> = None;
    let mut media_pref: Option<bool> = None;
    let mut offset = 0usize;
    for line in sdp_text.split('\n') {
        if offset >= MAX_RECORDPREF_SCAN_BYTES {
            break;
        }
        offset = offset.saturating_add(line.len()).saturating_add(1);
        let line = line.trim();
        if let Some(m) = line.strip_prefix("m=") {
            if scope == Scope::RecordedAudio {
                // The recorded stream's section is complete.
                break;
            }
            scope = if !audio_seen && is_active_audio_mline(m) {
                audio_seen = true;
                Scope::RecordedAudio
            } else {
                Scope::OtherMedia
            };
            continue;
        }
        let Some(opt_out) = recordpref_value(line) else {
            continue;
        };
        let slot = match scope {
            Scope::Session => &mut session_pref,
            Scope::RecordedAudio => &mut media_pref,
            Scope::OtherMedia => continue,
        };
        // Repeated in one scope: an opt-out among them wins.
        *slot = Some(slot.unwrap_or(false) || opt_out);
    }
    media_pref.or(session_pref).unwrap_or(false)
}

/// `audio <port> ...` with a non-zero port (RFC 3264 §6: port 0 is a
/// declined stream). `rest` is the m-line after `m=`.
fn is_active_audio_mline(rest: &str) -> bool {
    let mut fields = rest.split_ascii_whitespace();
    fields
        .next()
        .is_some_and(|t| t.eq_ignore_ascii_case("audio"))
        && fields
            .next()
            .and_then(|p| p.split('/').next())
            .and_then(|p| p.parse::<u16>().ok())
            .is_some_and(|p| p != 0)
}

/// `Some(opt_out)` for an `a=recordpref:<value>` line, `None` for any other
/// line.
fn recordpref_value(line: &str) -> Option<bool> {
    let (name, value) = line.strip_prefix("a=")?.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("recordpref") {
        return None;
    }
    let value = value.trim();
    Some(value.eq_ignore_ascii_case("off") || value.eq_ignore_ascii_case("never"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn answer() -> String {
        format!(
            "v=0\r\no=- 1 1 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n\
             m=audio 40000 RTP/SAVP 0\r\na=recvonly\r\na=label:1\r\na=rtcp-mux\r\n\
             a=crypto:1 AEAD_AES_256_GCM inline:{KEY}\r\n\
             m=audio 40002 RTP/SAVP 0\r\nc=IN IP6 2001:db8::7\r\na=recvonly\r\na=label:2\r\n\
             a=crypto:1 AEAD_AES_256_GCM inline:{KEY}|2^31 WSH=128\r\n"
        )
    }

    #[test]
    fn accepts_good_answer() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(KEY.len(), INLINE_KEY_B64_LEN);
        let sdp: SessionDescription = answer().parse()?;
        let streams = parse_rs_answer(&sdp, 2)?;
        assert_eq!(
            streams,
            vec![
                RsAnswerStream {
                    addr: "198.51.100.7:40000".parse()?,
                    rtcp_mux: true,
                },
                RsAnswerStream {
                    addr: "[2001:db8::7]:40002".parse()?,
                    rtcp_mux: false,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn session_level_recvonly_is_inherited() -> Result<(), Box<dyn std::error::Error>> {
        let text = answer()
            .replace("a=recvonly\r\n", "")
            .replace("t=0 0\r\n", "t=0 0\r\na=recvonly\r\n");
        let sdp: SessionDescription = text.parse()?;
        assert_eq!(parse_rs_answer(&sdp, 2)?.len(), 2);
        Ok(())
    }

    #[test]
    fn error_reason_never_echoes_answer_values() -> Result<(), Box<dyn std::error::Error>> {
        let text = answer().replace("AEAD_AES_256_GCM", "EVIL_SUITE_NAME");
        let sdp: SessionDescription = text.parse()?;
        let err = parse_rs_answer(&sdp, 2).err().ok_or("accepted")?;
        let shown = err.to_string();
        assert!(!shown.contains("EVIL_SUITE_NAME"), "{shown}");
        assert!(!shown.contains(KEY), "{shown}");
        Ok(())
    }

    #[test]
    fn expected_stream_count_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let sdp: SessionDescription = answer().parse()?;
        assert!(parse_rs_answer(&sdp, 0).is_err());
        assert!(parse_rs_answer(&sdp, MAX_RS_ANSWER_STREAMS + 1).is_err());
        Ok(())
    }

    #[test]
    fn recordpref_values() {
        assert!(has_recordpref_never("v=0\r\na=recordpref:off\r\n"));
        assert!(has_recordpref_never("v=0\r\na=recordpref:never\r\n"));
        for other in ["on", "pause", "nopreference", "", "offf", "nevermore"] {
            assert!(
                !has_recordpref_never(&format!("v=0\r\na=recordpref:{other}\r\n")),
                "{other}"
            );
        }
        assert!(!has_recordpref_never("v=0\r\na=record:off\r\n"));
        assert!(!has_recordpref_never("v=0\r\ni=recordpref:off\r\n"));
        assert!(!has_recordpref_never(""));
    }

    // RFC 7866 §7.3.2: the media-level value overrides the session-level
    // one for the recorded (first active audio) stream.
    #[test]
    fn recordpref_media_level_overrides_session_level() {
        let sdp = |session: &str, audio: &str, video: &str| {
            format!(
                "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\n{session}t=0 0\r\n\
                 m=audio 4000 RTP/AVP 0\r\n{audio}m=video 4002 RTP/AVP 96\r\n{video}"
            )
        };
        let off = "a=recordpref:off\r\n";
        let on = "a=recordpref:on\r\n";
        assert!(has_recordpref_never(&sdp(off, "", "")), "inherited");
        assert!(has_recordpref_never(&sdp("", off, "")), "media level");
        assert!(has_recordpref_never(&sdp(on, off, "")), "media wins");
        assert!(!has_recordpref_never(&sdp(off, on, "")), "media wins");
        assert!(!has_recordpref_never(&sdp("", "", off)), "not the audio");
        assert!(has_recordpref_never(&sdp(off, "", on)), "video is not it");
        // A declined audio m-line is not the recorded stream.
        let declined = format!(
            "v=0\r\na=recordpref:off\r\nm=audio 0 RTP/AVP 0\r\n{on}m=audio 4000 RTP/AVP 0\r\n"
        );
        assert!(has_recordpref_never(&declined));
        // No audio at all: session level only.
        assert!(has_recordpref_never(
            "v=0\r\na=recordpref:off\r\nm=image 4000 udptl t38\r\na=recordpref:on\r\n"
        ));
    }
}
