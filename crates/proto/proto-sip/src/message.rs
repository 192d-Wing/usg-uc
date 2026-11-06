//! SIP message types per RFC 3261.
//!
//! # Parsing
//!
//! [`SipMessage::parse_with`] is a single-pass byte scanner:
//!
//! - RFC 3261 §7.5: leading CRLFs before the start line are ignored
//!   (bounded by [`MAX_LEADING_CRLF`]; also covers RFC 5626 §3.5.1
//!   keep-alives).
//! - RFC 3261 §7 / §25.1: every line ends in CRLF; bare CR or bare LF is
//!   rejected. Folded lines (leading SP/HTAB, §7.3.1) are unfolded to one SP.
//! - Header names must be `token`; values must be UTF-8 (`TEXT-UTF8`) and
//!   contain no CTL other than HTAB.
//! - The body is opaque bytes: never UTF-8 validated, serialized verbatim.
//! - Content-Length (§20.14, §18.3) is strict and framing-aware; see
//!   [`Framing`].
//!
//! NIST 800-53 Rev5: SI-10 (Information Input Validation), SI-10(3)
//! (Predictable Behavior: reject with no partial state), SC-5 (parser
//! limits), SC-8 (body integrity: bytes survive verbatim so signatures
//! such as S/MIME and RFC 8224 Identity stay valid).

use crate::error::{SipError, SipResult, truncate_for_log};
use crate::header::{Header, HeaderName, Headers, is_token_byte, parse_content_length};
use crate::method::Method;
use crate::response::StatusCode;
use crate::transport::Transport;
use crate::uri::SipUri;
use crate::{
    MAX_HEADER_LEN, MAX_HEADERS, MAX_LEADING_CRLF, MAX_MESSAGE_SIZE, MAX_START_LINE_LEN,
    SIP_VERSION,
};
use bytes::{Bytes, BytesMut};
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

/// How the bytes handed to the parser were framed by the transport.
///
/// RFC 3261 §18.3 defines different Content-Length rules per transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Datagram transport (UDP). Content-Length is optional; octets beyond
    /// it are discarded; a Content-Length larger than the remaining
    /// octets is an error.
    Datagram,
    /// Stream transport (TCP, TLS). Content-Length MUST be present and the
    /// caller has already framed exactly one message, so the remaining
    /// octets must equal it.
    Stream,
    /// Message-framed transport (WS, WSS per RFC 7118 §5; SCTP per
    /// RFC 4168). The transport delimits exactly one SIP message, so
    /// Content-Length is optional, but if present it MUST equal the
    /// remaining octets.
    Message,
}

impl From<Transport> for Framing {
    fn from(t: Transport) -> Self {
        match t {
            Transport::Udp | Transport::DtlsUdp => Self::Datagram,
            // RFC 7118 §5 / RFC 4168: one SIP message per WS / SCTP message.
            Transport::Ws | Transport::Wss | Transport::Sctp => Self::Message,
            Transport::Tcp | Transport::Tls => Self::Stream,
        }
    }
}

/// A SIP message (request or response).
#[derive(Debug, Clone)]
pub enum SipMessage {
    /// SIP request.
    Request(SipRequest),
    /// SIP response.
    Response(SipResponse),
}

impl SipMessage {
    /// Returns the total length (head + body) of the stream-framed message
    /// whose head is `head`.
    ///
    /// `head` must contain the start line and the complete header section
    /// including the terminating empty line. Header names, folding,
    /// compact `l`, duplicates and the value grammar are handled exactly as
    /// [`SipMessage::parse_with`] with [`Framing::Stream`] does, so a stream
    /// framer using this cannot cut at an offset the parser disagrees with.
    ///
    /// RFC 3261 §18.3: Content-Length MUST be present on stream transports.
    /// NIST 800-53 Rev5: SI-10 (framing agreement prevents stream desync).
    ///
    /// # Errors
    ///
    /// Returns an error if the head is malformed or the Content-Length is
    /// missing, duplicated or not `1*DIGIT`. The caller should close the
    /// connection, since the stream can no longer be resynchronised.
    pub fn stream_message_len(head: &[u8]) -> SipResult<usize> {
        if head.len() > MAX_MESSAGE_SIZE {
            return Err(SipError::MessageTooLarge {
                size: head.len(),
                max_size: MAX_MESSAGE_SIZE,
            });
        }
        let (_, headers, body_start) = parse_head(head)?;
        let cl = single_content_length(&headers)?.ok_or_else(|| SipError::MissingHeader {
            name: HeaderName::ContentLength.as_str().to_string(),
        })?;
        let total = body_start.saturating_add(cl);
        if total > MAX_MESSAGE_SIZE {
            return Err(SipError::MessageTooLarge {
                size: total,
                max_size: MAX_MESSAGE_SIZE,
            });
        }
        Ok(total)
    }

    /// Parses a SIP message from bytes using [`Framing::Datagram`] rules.
    ///
    /// Prefer [`SipMessage::parse_with`] with the real transport framing;
    /// stream transports must use [`Framing::Stream`] so a missing
    /// Content-Length is rejected (RFC 3261 §18.3).
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or semantic validation fails.
    pub fn parse(data: &[u8]) -> SipResult<Self> {
        Self::parse_with(data, Framing::Datagram)
    }

    /// Parses a SIP message from bytes with the given transport framing.
    ///
    /// Runs [`SipMessage::validate_semantics`] on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is malformed, exceeds a parser
    /// limit, has invalid framing, or fails semantic validation.
    /// [`SipError::is_client_error`] is true for all of these.
    pub fn parse_with(data: &[u8], framing: Framing) -> SipResult<Self> {
        // NIST 800-53 Rev5: SC-5 - bound total message size first.
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(SipError::MessageTooLarge {
                size: data.len(),
                max_size: MAX_MESSAGE_SIZE,
            });
        }

        let (start_line, headers, body_start) = parse_head(data)?;

        // Body framing (RFC 3261 §18.3, §20.14).
        let body = frame_body(&headers, &data[body_start..], framing)?;

        let msg = if is_status_line(start_line) {
            Self::Response(SipResponse::from_parts(start_line, headers, body)?)
        } else {
            Self::Request(SipRequest::from_parts(start_line, headers, body)?)
        };

        msg.validate_semantics()?;
        Ok(msg)
    }

    /// Validates message-layer semantics that RFC 3261 requires a 400 for:
    ///
    /// - single-valued headers (Call-ID, To, From, `CSeq`, Max-Forwards,
    ///   Content-Length) appear at most once (compact and long forms count
    ///   together; RFC 4475 §3.3.8, §3.3.9),
    /// - `CSeq` sequence < 2^31 and, for requests, `CSeq` method equals the
    ///   request method (RFC 3261 §8.1.1.5, §8.2.2; RFC 4475 §3.1.2.17),
    /// - Max-Forwards is `1*DIGIT` in 0-255 (RFC 3261 §20.22).
    ///
    /// Missing mandatory headers are not checked here; use
    /// [`Headers::validate_request_headers`].
    ///
    /// NIST 800-53 Rev5: SI-10 (Information Input Validation).
    ///
    /// # Errors
    ///
    /// Returns [`SipError::DuplicateHeader`] or [`SipError::InvalidHeader`].
    pub fn validate_semantics(&self) -> SipResult<()> {
        const SINGLE: [HeaderName; 6] = [
            HeaderName::CallId,
            HeaderName::To,
            HeaderName::From,
            HeaderName::CSeq,
            HeaderName::MaxForwards,
            HeaderName::ContentLength,
        ];
        let headers = self.headers();
        let mut counts = [0usize; SINGLE.len()];
        // Power of 10 Rule 2: one pass over a bounded header list.
        for h in headers.iter() {
            if let Some(i) = SINGLE.iter().position(|n| *n == h.name) {
                counts[i] += 1;
                if counts[i] > 1 {
                    return Err(SipError::DuplicateHeader {
                        name: SINGLE[i].as_str().to_string(),
                    });
                }
            }
        }

        if let Some(raw) = headers.cseq() {
            // Allocation-free check (same rules as `CSeqHeader::from_str`).
            let cseq_method = check_cseq(raw)?;
            // RFC 3261 §7.1 / §8.1.1.5: exact, case-sensitive match.
            if let Self::Request(req) = self
                && req.method.as_str() != cseq_method
            {
                return Err(SipError::InvalidHeader {
                    name: "CSeq".to_string(),
                    reason: "CSeq method does not match request method".to_string(),
                });
            }
        }

        if let Some(mf) = headers.get_value(&HeaderName::MaxForwards) {
            let ok = !mf.is_empty()
                && mf.len() <= 10
                && mf.bytes().all(|b| b.is_ascii_digit())
                && mf.parse::<u32>().is_ok_and(|v| v <= 255);
            if !ok {
                return Err(SipError::InvalidHeader {
                    name: "Max-Forwards".to_string(),
                    reason: "must be 1*DIGIT in 0-255".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Returns true if this is a request.
    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Returns true if this is a response.
    #[must_use]
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Returns the headers.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        match self {
            Self::Request(req) => &req.headers,
            Self::Response(resp) => &resp.headers,
        }
    }

    /// Returns mutable headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        match self {
            Self::Request(req) => &mut req.headers,
            Self::Response(resp) => &mut resp.headers,
        }
    }

    /// Returns the body.
    #[must_use]
    pub fn body(&self) -> Option<&Bytes> {
        match self {
            Self::Request(req) => req.body.as_ref(),
            Self::Response(resp) => resp.body.as_ref(),
        }
    }

    /// Returns the Call-ID.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.headers().call_id()
    }

    /// Returns the `CSeq`.
    #[must_use]
    pub fn cseq(&self) -> Option<&str> {
        self.headers().cseq()
    }

    /// Writes the wire form (start line, headers, blank line, body bytes
    /// verbatim) into `buf`.
    pub fn write_to(&self, buf: &mut BytesMut) {
        match self {
            Self::Request(req) => req.write_to(buf),
            Self::Response(resp) => resp.write_to(buf),
        }
    }

    /// Encodes the message to bytes. The body is copied byte-exact.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::Request(req) => req.to_bytes(),
            Self::Response(resp) => resp.to_bytes(),
        }
    }
}

impl fmt::Display for SipMessage {
    /// Log/test form. A non-UTF-8 body is rendered lossily; use
    /// [`SipMessage::to_bytes`] for the wire.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(req) => write!(f, "{req}"),
            Self::Response(resp) => write!(f, "{resp}"),
        }
    }
}

impl FromStr for SipMessage {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        Self::parse(s.as_bytes())
    }
}

/// Validates a `CSeq` value (`1*DIGIT LWS Method`, sequence < 2^31;
/// RFC 3261 §8.1.1.5, §20.16) and returns the method token.
fn check_cseq(raw: &str) -> SipResult<&str> {
    let invalid = |reason: &str| SipError::InvalidHeader {
        name: "CSeq".to_string(),
        reason: reason.to_string(),
    };
    let (seq, method) = raw
        .split_once([' ', '\t'])
        .ok_or_else(|| invalid("expected 'sequence method'"))?;
    let method = method.trim_start_matches([' ', '\t']);
    if seq.is_empty() || seq.len() > 10 || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid sequence number"));
    }
    if seq.parse::<u64>().map_or(true, |v| v > 0x7FFF_FFFF) {
        return Err(invalid("sequence number must be < 2^31"));
    }
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(invalid("method is not a token"));
    }
    Ok(method)
}

/// Returns true if the start line is a Status-Line (`SIP/x.y ...`).
fn is_status_line(line: &str) -> bool {
    line.get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("SIP/"))
}

/// Reads one CRLF-terminated line starting at `start`.
///
/// Returns the line (without CRLF) and the index after the CRLF. The line
/// is checked in the same pass for:
///
/// - RFC 3261 §7: bare CR or bare LF (rejected),
/// - RFC 3261 §25.1: CTLs other than HTAB (rejected; header injection),
/// - the `max` length limit (NIST 800-53 Rev5: SC-5).
fn read_line<'a>(
    data: &'a [u8],
    start: usize,
    max: usize,
    what: &'static str,
) -> SipResult<(&'a [u8], usize)> {
    let rest = data.get(start..).unwrap_or_default();
    let mut i = 0usize;
    // Power of 10 Rule 2: bounded by rest.len().
    while i < rest.len() {
        let b = rest[i];
        if b < 0x20 || b == 0x7F {
            match b {
                b'\t' => {}
                b'\r' => break,
                b'\n' => {
                    return Err(SipError::ParseError {
                        reason: format!("{what}: bare LF line ending"),
                    });
                }
                _ => {
                    return Err(SipError::ParseError {
                        reason: format!("{what}: control character"),
                    });
                }
            }
        }
        i += 1;
        if i > max {
            return Err(SipError::LimitExceeded { what, limit: max });
        }
    }
    if i >= rest.len() {
        return Err(SipError::ParseError {
            reason: format!("{what}: missing CRLF"),
        });
    }
    if rest.get(i + 1) != Some(&b'\n') {
        return Err(SipError::ParseError {
            reason: format!("{what}: bare CR line ending"),
        });
    }
    Ok((&rest[..i], start + i + 2))
}

/// Returns true for SP / HTAB.
fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Trims SP / HTAB from both ends of a byte slice.
fn trim_wsp(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if !is_wsp(*first) {
            break;
        }
        s = rest;
    }
    while let [rest @ .., last] = s {
        if !is_wsp(*last) {
            break;
        }
        s = rest;
    }
    s
}

/// Parses the header section starting at `pos`. Returns the headers and
/// the index of the first body octet (just after the empty line).
///
/// # Loop Bounds (Power of 10 Rule 2)
///
/// Each iteration consumes one CRLF-terminated line; bounded by
/// `data.len()` (≤ [`MAX_MESSAGE_SIZE`]) and by [`MAX_HEADERS`].
fn parse_header_section(data: &[u8], mut pos: usize) -> SipResult<(Headers, usize)> {
    let mut headers = Headers::new();
    let mut field_count = 0usize;
    let mut pending: Option<(HeaderName, String)> = None;

    loop {
        if pos >= data.len() {
            return Err(SipError::ParseError {
                reason: "header section not terminated by empty line".to_string(),
            });
        }
        let (line, next) = read_line(data, pos, MAX_HEADER_LEN, "header line")?;
        pos = next;

        if line.is_empty() {
            break;
        }

        if is_wsp(line[0]) {
            // RFC 3261 §7.3.1: continuation line; unfold to a single SP.
            let Some((_, value)) = pending.as_mut() else {
                return Err(SipError::ParseError {
                    reason: "continuation line before first header".to_string(),
                });
            };
            let cont = to_utf8(trim_wsp(line))?;
            if !cont.is_empty() {
                if value.len() + 1 + cont.len() > MAX_HEADER_LEN {
                    return Err(SipError::LimitExceeded {
                        what: "header length",
                        limit: MAX_HEADER_LEN,
                    });
                }
                if !value.is_empty() {
                    value.push(' ');
                }
                value.push_str(cont);
            }
            continue;
        }

        if let Some((name, value)) = pending.take() {
            push_header(&mut headers, name, value);
        }

        field_count += 1;
        if field_count > MAX_HEADERS {
            return Err(SipError::LimitExceeded {
                what: "header count",
                limit: MAX_HEADERS,
            });
        }

        let colon =
            line.iter()
                .position(|&b| b == b':')
                .ok_or_else(|| SipError::InvalidHeader {
                    name: "unknown".to_string(),
                    reason: "missing colon separator".to_string(),
                })?;
        // RFC 3261 §25.1: HCOLON = *( SP / HTAB ) ":" SWS
        let raw_name = trim_wsp(&line[..colon]);
        if raw_name.is_empty() || !raw_name.iter().all(|&b| is_token_byte(b)) {
            return Err(SipError::InvalidHeader {
                name: truncate_for_log(&String::from_utf8_lossy(raw_name)),
                reason: "header name is not a token".to_string(),
            });
        }
        // Token bytes are ASCII, so this cannot fail.
        let name = HeaderName::lookup(to_utf8(raw_name)?);
        let value = to_utf8(trim_wsp(&line[colon + 1..]))?;
        pending = Some((name, value.to_string()));
    }

    if let Some((name, value)) = pending.take() {
        push_header(&mut headers, name, value);
    }
    Ok((headers, pos))
}

/// Finalises one header field. Every line was CTL-checked by
/// [`read_line`] and folding only inserts SP, so the value is clean.
fn push_header(headers: &mut Headers, name: HeaderName, value: String) {
    headers.add(Header { name, value });
}

/// UTF-8 decode of a header value (RFC 3261 §25.1 `TEXT-UTF8`).
fn to_utf8(b: &[u8]) -> SipResult<&str> {
    std::str::from_utf8(b).map_err(|_| SipError::ParseError {
        reason: "header value is not UTF-8".to_string(),
    })
}

/// Parses the leading CRLFs, start line and header section.
///
/// Returns the start line, the headers and the offset of the body.
fn parse_head(data: &[u8]) -> SipResult<(&str, Headers, usize)> {
    // RFC 3261 §7.5: implementations SHOULD ignore CRLFs preceding the
    // start line. Bounded skip.
    let mut pos = 0usize;
    let mut skipped = 0usize;
    while data.get(pos..pos + 2) == Some(b"\r\n".as_slice()) {
        if skipped == MAX_LEADING_CRLF {
            return Err(SipError::LimitExceeded {
                what: "leading CRLF",
                limit: MAX_LEADING_CRLF,
            });
        }
        skipped += 1;
        pos += 2;
    }
    if pos >= data.len() {
        return Err(SipError::ParseError {
            reason: "empty message".to_string(),
        });
    }

    // Start line.
    let (line, next) = read_line(data, pos, MAX_START_LINE_LEN, "start line")?;
    if line.is_empty() {
        return Err(SipError::ParseError {
            reason: "empty start line".to_string(),
        });
    }
    let start_line = std::str::from_utf8(line).map_err(|_| SipError::ParseError {
        reason: "start line is not UTF-8".to_string(),
    })?;

    // Header section.
    let (headers, body_start) = parse_header_section(data, next)?;
    Ok((start_line, headers, body_start))
}

/// Returns the single strict Content-Length value, if present.
///
/// RFC 4475 §3.3.9: multiple Content-Length values (incl. `l:`) are an error.
fn single_content_length(headers: &Headers) -> SipResult<Option<usize>> {
    let mut cl_iter = headers.get_all(&HeaderName::ContentLength);
    let first = cl_iter.next();
    if cl_iter.next().is_some() {
        return Err(SipError::DuplicateHeader {
            name: HeaderName::ContentLength.as_str().to_string(),
        });
    }
    first.map(|h| parse_content_length(&h.value)).transpose()
}

/// Applies RFC 3261 §18.3 Content-Length rules and returns the body.
///
/// NIST 800-53 Rev5: SI-10 - strict, unambiguous framing so the SBC and
/// the next hop cannot disagree on message boundaries (smuggling).
fn frame_body(headers: &Headers, rest: &[u8], framing: Framing) -> SipResult<Option<Bytes>> {
    let content_length = single_content_length(headers)?;

    let body = match (framing, content_length) {
        // RFC 7118 §5 / RFC 4168: message-framed, Content-Length optional.
        (Framing::Datagram | Framing::Message, None) => rest,
        (Framing::Datagram, Some(cl)) => {
            // RFC 3261 §18.3: octets beyond Content-Length are discarded;
            // a Content-Length larger than the datagram MUST be discarded.
            rest.get(..cl).ok_or(SipError::ContentLengthMismatch {
                header: cl,
                actual: rest.len(),
            })?
        }
        (Framing::Stream, None) => {
            // RFC 3261 §18.3: Content-Length MUST be used with stream transports.
            return Err(SipError::MissingHeader {
                name: HeaderName::ContentLength.as_str().to_string(),
            });
        }
        (Framing::Stream | Framing::Message, Some(cl)) => {
            if cl != rest.len() {
                return Err(SipError::ContentLengthMismatch {
                    header: cl,
                    actual: rest.len(),
                });
            }
            rest
        }
    };
    Ok((!body.is_empty()).then(|| Bytes::copy_from_slice(body)))
}

/// Estimated serialized size of a header list (start line excluded).
fn headers_len(headers: &Headers) -> usize {
    headers
        .iter()
        .map(|h| h.name.as_str().len() + h.value.len() + 4)
        .sum()
}

/// Writes headers, the blank line and the body.
fn write_tail(buf: &mut BytesMut, headers: &Headers, body: Option<&Bytes>) {
    for h in headers.iter() {
        buf.extend_from_slice(h.name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(h.value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    if let Some(body) = body {
        buf.extend_from_slice(body);
    }
}

/// A SIP request.
#[derive(Debug, Clone)]
pub struct SipRequest {
    /// Request method.
    pub method: Method,
    /// Request-URI.
    pub uri: SipUri,
    /// Headers.
    pub headers: Headers,
    /// Message body (optional).
    pub body: Option<Bytes>,
}

impl SipRequest {
    /// Creates a new SIP request.
    #[must_use]
    pub fn new(method: Method, uri: SipUri) -> Self {
        Self {
            method,
            uri,
            headers: Headers::new(),
            body: None,
        }
    }

    /// Sets the message body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Adds a header.
    pub fn add_header(&mut self, header: Header) {
        self.headers.add(header);
    }

    /// Builds a request from a Request-Line and parsed parts.
    ///
    /// RFC 3261 §7.1 / §25.1: `Request-Line = Method SP Request-URI SP
    /// SIP-Version CRLF` - exactly single SPs (RFC 4475 §3.1.2.9/10).
    fn from_parts(line: &str, headers: Headers, body: Option<Bytes>) -> SipResult<Self> {
        let mut parts = line.split(' ');
        let (Some(m), Some(u), Some(v), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(SipError::ParseError {
                reason: format!("invalid request line: {}", truncate_for_log(line)),
            });
        };
        if m.is_empty() || !m.bytes().all(is_token_byte) {
            return Err(SipError::InvalidMethod {
                method: truncate_for_log(m),
            });
        }
        if !v.eq_ignore_ascii_case(SIP_VERSION) {
            return Err(SipError::ParseError {
                reason: format!("unsupported SIP version: {}", truncate_for_log(v)),
            });
        }

        // Method parsing is infallible - unknown methods become Extension variants
        let method: Method = m
            .parse()
            .unwrap_or_else(|e: std::convert::Infallible| match e {});
        let uri: SipUri = u.parse()?;

        Ok(Self {
            method,
            uri,
            headers,
            body,
        })
    }

    /// Writes the wire form into `buf` (body verbatim).
    pub fn write_to(&self, buf: &mut BytesMut) {
        let _ = write!(buf, "{} {} {}\r\n", self.method, self.uri, SIP_VERSION);
        write_tail(buf, &self.headers, self.body.as_ref());
    }

    /// Encodes the request to bytes (body byte-exact).
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let est = 64 + headers_len(&self.headers) + self.body.as_ref().map_or(0, Bytes::len);
        let mut buf = BytesMut::with_capacity(est);
        self.write_to(&mut buf);
        buf.freeze()
    }
}

impl fmt::Display for SipRequest {
    /// Log/test form; a non-UTF-8 body is rendered lossily.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

/// A SIP response.
#[derive(Debug, Clone)]
pub struct SipResponse {
    /// Status code.
    pub status: StatusCode,
    /// Reason phrase (optional override).
    pub reason: Option<String>,
    /// Headers.
    pub headers: Headers,
    /// Message body (optional).
    pub body: Option<Bytes>,
}

impl SipResponse {
    /// Creates a new SIP response.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            reason: None,
            headers: Headers::new(),
            body: None,
        }
    }

    /// Sets a custom reason phrase.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Sets the message body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Adds a header.
    pub fn add_header(&mut self, header: Header) {
        self.headers.add(header);
    }

    /// Returns the reason phrase.
    #[must_use]
    pub fn reason_phrase(&self) -> &str {
        self.reason
            .as_deref()
            .unwrap_or_else(|| self.status.reason_phrase())
    }

    /// Builds a response from a Status-Line and parsed parts.
    ///
    /// RFC 3261 §7.2: `Status-Line = SIP-Version SP Status-Code SP
    /// Reason-Phrase CRLF`; Status-Code is 3DIGIT (RFC 4475 §3.1.2.19).
    fn from_parts(line: &str, headers: Headers, body: Option<Bytes>) -> SipResult<Self> {
        let mut parts = line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let code_str = parts.next().unwrap_or_default();
        let reason = parts.next();

        if !version.eq_ignore_ascii_case(SIP_VERSION) {
            return Err(SipError::ParseError {
                reason: format!("unsupported SIP version: {}", truncate_for_log(version)),
            });
        }
        if code_str.len() != 3 || !code_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SipError::ParseError {
                reason: format!("invalid status code: {}", truncate_for_log(code_str)),
            });
        }
        let code: u16 = code_str.parse().map_err(|_| SipError::ParseError {
            reason: "invalid status code".to_string(),
        })?;
        let status = StatusCode::new(code)?;

        Ok(Self {
            status,
            reason: reason.map(ToString::to_string),
            headers,
            body,
        })
    }

    /// Writes the wire form into `buf` (body verbatim).
    pub fn write_to(&self, buf: &mut BytesMut) {
        let _ = write!(
            buf,
            "{} {} {}\r\n",
            SIP_VERSION,
            self.status.code(),
            self.reason_phrase()
        );
        write_tail(buf, &self.headers, self.body.as_ref());
    }

    /// Encodes the response to bytes (body byte-exact).
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let est = 64 + headers_len(&self.headers) + self.body.as_ref().map_or(0, Bytes::len);
        let mut buf = BytesMut::with_capacity(est);
        self.write_to(&mut buf);
        buf.freeze()
    }
}

impl fmt::Display for SipResponse {
    /// Log/test form; a non-UTF-8 body is rendered lossily.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::header::HeaderName;

    #[test]
    fn test_parse_invite_request() {
        let msg = "INVITE sip:alice@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP pc33.example.com\r\n\
                   Call-ID: abc123@pc33.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

        let parsed: SipMessage = msg.parse().unwrap();
        assert!(parsed.is_request());

        if let SipMessage::Request(req) = parsed {
            assert_eq!(req.method, Method::Invite);
            assert_eq!(req.uri.host, "example.com");
            assert_eq!(req.headers.call_id(), Some("abc123@pc33.example.com"));
        }
    }

    #[test]
    fn test_parse_response() {
        let msg = "SIP/2.0 200 OK\r\n\
                   Via: SIP/2.0/UDP example.com\r\n\
                   Call-ID: abc123\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

        let parsed: SipMessage = msg.parse().unwrap();
        assert!(parsed.is_response());

        if let SipMessage::Response(resp) = parsed {
            assert_eq!(resp.status, StatusCode::OK);
        }
    }

    #[test]
    fn test_create_request() {
        let uri = SipUri::new("example.com").with_user("alice");
        let mut req = SipRequest::new(Method::Invite, uri);
        req.add_header(Header::new(HeaderName::CallId, "test123"));
        req.add_header(Header::new(HeaderName::CSeq, "1 INVITE"));

        let msg = req.to_string();
        assert!(msg.starts_with("INVITE sip:alice@example.com SIP/2.0"));
        assert!(msg.contains("Call-ID: test123"));
    }

    #[test]
    fn test_create_response() {
        let resp = SipResponse::new(StatusCode::OK);
        let msg = resp.to_string();
        assert!(msg.starts_with("SIP/2.0 200 OK"));
    }

    #[test]
    fn test_roundtrip() {
        let original = "INVITE sip:alice@example.com SIP/2.0\r\n\
                        Via: SIP/2.0/UDP pc33.example.com\r\n\
                        Call-ID: abc123\r\n\
                        CSeq: 1 INVITE\r\n\
                        Content-Length: 0\r\n\
                        \r\n";

        let parsed: SipMessage = original.parse().unwrap();
        let reparsed: SipMessage = parsed.to_string().parse().unwrap();

        assert_eq!(parsed.call_id(), reparsed.call_id());
    }

    #[test]
    fn test_message_with_body() {
        let msg = "INVITE sip:alice@example.com SIP/2.0\r\n\
                   Content-Length: 4\r\n\
                   \r\n\
                   test";

        let parsed: SipMessage = msg.parse().unwrap();
        assert_eq!(
            parsed.body().map(std::convert::AsRef::as_ref),
            Some(b"test".as_slice())
        );
    }

    #[test]
    fn test_content_length_mismatch() {
        let msg = "INVITE sip:alice@example.com SIP/2.0\r\n\
                   Content-Length: 10\r\n\
                   \r\n\
                   test";

        let result: SipResult<SipMessage> = msg.parse();
        assert!(matches!(
            result,
            Err(SipError::ContentLengthMismatch { .. })
        ));
    }

    // ==================== Phase 1 hardening ====================

    const HDRS: &str = "Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
                        To: <sip:b@example.com>\r\n\
                        From: <sip:a@example.com>;tag=1\r\n\
                        Call-ID: c1\r\n\
                        CSeq: 1 OPTIONS\r\n\
                        Max-Forwards: 70\r\n";

    fn req_with(extra: &str, body: &[u8]) -> Vec<u8> {
        let mut v = format!("OPTIONS sip:b@example.com SIP/2.0\r\n{HDRS}{extra}\r\n").into_bytes();
        v.extend_from_slice(body);
        v
    }

    fn ok(v: &[u8], f: Framing) -> SipMessage {
        SipMessage::parse_with(v, f).unwrap()
    }

    fn err(v: &[u8], f: Framing) -> SipError {
        SipMessage::parse_with(v, f).unwrap_err()
    }

    #[test]
    fn empty_input_is_error_not_panic() {
        assert!(SipMessage::parse(b"").is_err());
        assert!(SipMessage::parse(b"\r\n\r\n").is_err());
    }

    #[test]
    fn bare_lf_and_bare_cr_rejected() {
        let lf = "OPTIONS sip:b@example.com SIP/2.0\nCall-ID: c\n\n";
        assert!(SipMessage::parse(lf.as_bytes()).is_err());
        let mixed = req_with("X-A: 1\nX-B: 2\r\n", b"");
        assert!(SipMessage::parse(&mixed).is_err());
        let cr = req_with("X-A: 1\rX-B: 2\r\n", b"");
        assert!(SipMessage::parse(&cr).is_err());
    }

    #[test]
    fn leading_crlf_skipped_and_capped() {
        let mut v = b"\r\n\r\n".to_vec();
        v.extend(req_with("", b""));
        assert!(SipMessage::parse(&v).is_ok());

        let mut v = b"\r\n".repeat(crate::MAX_LEADING_CRLF);
        v.extend(req_with("", b""));
        assert!(SipMessage::parse(&v).is_ok());

        let mut v = b"\r\n".repeat(crate::MAX_LEADING_CRLF + 1);
        v.extend(req_with("", b""));
        assert!(matches!(
            SipMessage::parse(&v),
            Err(SipError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn folding_unfolds_to_single_space() {
        let v = req_with("Subject: hello\r\n \t world\r\n", b"");
        let m = ok(&v, Framing::Datagram);
        assert_eq!(
            m.headers().get_value(&HeaderName::Subject),
            Some("hello world")
        );
        // Continuation before any header.
        let v = b"OPTIONS sip:b@example.com SIP/2.0\r\n cont\r\n\r\n";
        assert!(SipMessage::parse(v).is_err());
    }

    #[test]
    fn header_name_must_be_token() {
        assert!(SipMessage::parse(&req_with("Foo Bar: x\r\n", b"")).is_err());
        assert!(SipMessage::parse(&req_with("Foo@Bar: x\r\n", b"")).is_err());
        assert!(SipMessage::parse(&req_with(": x\r\n", b"")).is_err());
        // HCOLON allows WSP before ':'
        assert!(SipMessage::parse(&req_with("X-Foo \t: x\r\n", b"")).is_ok());
    }

    #[test]
    fn ctl_in_value_rejected_htab_accepted() {
        for ctl in [b'\0', 0x01, 0x7F, b'\r'] {
            let mut v = req_with("", b"");
            let pos = v.len() - 2;
            let mut line = b"X-Ctl: a".to_vec();
            line.push(ctl);
            line.extend_from_slice(b"b\r\n");
            v.splice(pos..pos, line);
            assert!(SipMessage::parse(&v).is_err(), "ctl {ctl:#x} accepted");
        }
        let m = ok(&req_with("X-Tab: a\tb\r\n", b""), Framing::Datagram);
        assert_eq!(
            m.headers()
                .get_value(&HeaderName::Custom("x-tab".to_string())),
            Some("a\tb")
        );
    }

    #[test]
    fn non_utf8_value_rejected_but_binary_body_roundtrips() {
        let mut v = req_with("", b"");
        let pos = v.len() - 2;
        v.splice(pos..pos, b"X-Bin: \xff\xfe\r\n".to_vec());
        assert!(SipMessage::parse(&v).is_err());

        let body: &[u8] = b"\x00\xff\xfe\x80binary\r\n\r\n";
        let v = req_with(&format!("Content-Length: {}\r\n", body.len()), body);
        let m = ok(&v, Framing::Stream);
        assert_eq!(m.body().map(AsRef::as_ref), Some(body));
        let out = m.to_bytes();
        assert_eq!(out.as_ref(), v.as_slice());
        let m2 = ok(&out, Framing::Stream);
        assert_eq!(m2.body().map(AsRef::as_ref), Some(body));
    }

    #[test]
    fn content_length_matrix() {
        use Framing::{Datagram, Stream};
        // absent
        assert!(ok(&req_with("", b"abc"), Datagram).body().is_some());
        assert!(matches!(
            err(&req_with("", b""), Stream),
            SipError::MissingHeader { .. }
        ));
        // exact
        for f in [Datagram, Stream] {
            assert_eq!(
                ok(&req_with("Content-Length: 3\r\n", b"abc"), f)
                    .body()
                    .map(AsRef::as_ref),
                Some(b"abc".as_slice())
            );
        }
        // body longer than C-L: UDP truncates (RFC 3261 §18.3), stream errors
        assert_eq!(
            ok(&req_with("Content-Length: 2\r\n", b"abc"), Datagram)
                .body()
                .map(AsRef::as_ref),
            Some(b"ab".as_slice())
        );
        assert!(matches!(
            err(&req_with("Content-Length: 2\r\n", b"abc"), Stream),
            SipError::ContentLengthMismatch { .. }
        ));
        // body shorter than C-L: both error
        for f in [Datagram, Stream] {
            assert!(matches!(
                err(&req_with("Content-Length: 9\r\n", b"abc"), f),
                SipError::ContentLengthMismatch { .. }
            ));
        }
        // duplicates (compact + long)
        for f in [Datagram, Stream] {
            assert!(matches!(
                err(&req_with("l: 3\r\nContent-Length: 3\r\n", b"abc"), f),
                SipError::DuplicateHeader { .. }
            ));
        }
        // malformed values
        for bad in ["+3", "-1", "3 3", "0x3", "12345678901", "", "3a"] {
            for f in [Datagram, Stream] {
                let v = req_with(&format!("Content-Length: {bad}\r\n"), b"abc");
                assert!(
                    matches!(err(&v, f), SipError::InvalidContentLength { .. }),
                    "C-L {bad:?} accepted"
                );
            }
        }
        // trailing WSP is LWS around the value, trimmed
        assert!(SipMessage::parse(&req_with("Content-Length: 3 \r\n", b"abc")).is_ok());
    }

    #[test]
    fn header_count_limit() {
        let n = crate::MAX_HEADERS - 6;
        let extra = (0..n).fold(String::new(), |mut acc, i| {
            let _ = std::fmt::Write::write_fmt(&mut acc, format_args!("X-H{i}: v\r\n"));
            acc
        });
        assert!(SipMessage::parse(&req_with(&extra, b"")).is_ok());
        let extra = (0..=n).fold(String::new(), |mut acc, i| {
            let _ = std::fmt::Write::write_fmt(&mut acc, format_args!("X-H{i}: v\r\n"));
            acc
        });
        assert!(matches!(
            SipMessage::parse(&req_with(&extra, b"")),
            Err(SipError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn header_len_limit() {
        // line = "X-L: " + value; limit applies to the line without CRLF
        let ok_val = "a".repeat(crate::MAX_HEADER_LEN - 5);
        assert!(SipMessage::parse(&req_with(&format!("X-L: {ok_val}\r\n"), b"")).is_ok());
        let bad_val = "a".repeat(crate::MAX_HEADER_LEN - 4);
        assert!(matches!(
            SipMessage::parse(&req_with(&format!("X-L: {bad_val}\r\n"), b"")),
            Err(SipError::LimitExceeded { .. })
        ));
        // folding cannot be used to bypass the limit
        let half = "a".repeat(crate::MAX_HEADER_LEN / 2);
        assert!(matches!(
            SipMessage::parse(&req_with(&format!("X-L: {half}\r\n {half}\r\n"), b"")),
            Err(SipError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn duplicate_single_valued_headers_rejected() {
        for extra in [
            "Call-ID: c2\r\n",
            "i: c2\r\n",
            "To: <sip:x@example.com>\r\n",
            "f: <sip:x@example.com>\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Max-Forwards: 70\r\n",
        ] {
            assert!(
                matches!(
                    SipMessage::parse(&req_with(extra, b"")),
                    Err(SipError::DuplicateHeader { .. })
                ),
                "{extra:?}"
            );
        }
    }

    #[test]
    fn cseq_range_and_method() {
        let base = |cseq: &str, method: &str| {
            format!("{method} sip:b@example.com SIP/2.0\r\nCall-ID: c\r\nCSeq: {cseq}\r\n\r\n")
        };
        assert!(SipMessage::parse(base("2147483647 OPTIONS", "OPTIONS").as_bytes()).is_ok());
        assert!(SipMessage::parse(base("2147483648 OPTIONS", "OPTIONS").as_bytes()).is_err());
        assert!(SipMessage::parse(base("+1 OPTIONS", "OPTIONS").as_bytes()).is_err());
        assert!(SipMessage::parse(base("1 INVITE", "OPTIONS").as_bytes()).is_err());
        // responses: method is not compared, range still is
        let resp = "SIP/2.0 200 OK\r\nCSeq: 4294967295 INVITE\r\n\r\n";
        assert!(SipMessage::parse(resp.as_bytes()).is_err());
    }

    #[test]
    fn max_forwards_range() {
        let v =
            |mf: &str| format!("OPTIONS sip:b@example.com SIP/2.0\r\nMax-Forwards: {mf}\r\n\r\n");
        assert!(SipMessage::parse(v("255").as_bytes()).is_ok());
        assert!(SipMessage::parse(v("0068").as_bytes()).is_ok());
        assert!(SipMessage::parse(v("256").as_bytes()).is_err());
        assert!(SipMessage::parse(v("+5").as_bytes()).is_err());
    }

    #[test]
    fn request_line_strict() {
        for line in [
            "OPTIONS  sip:b@example.com SIP/2.0",
            "OPTIONS sip:b@example.com SIP/2.0 ",
            "OPTIONS sip:b@example.com",
            "OPTIONS sip:b@example.com SIP/7.0",
            "OPT IONS sip:b@example.com SIP/2.0",
        ] {
            let v = format!("{line}\r\nCall-ID: c\r\n\r\n");
            assert!(SipMessage::parse(v.as_bytes()).is_err(), "{line:?}");
        }
        // Status-Code must be 3DIGIT
        assert!(SipMessage::parse(b"SIP/2.0 4294967301 Big\r\n\r\n").is_err());
        assert!(SipMessage::parse(b"SIP/2.0 2000 Big\r\n\r\n").is_err());
        // Empty reason phrase accepted
        assert!(SipMessage::parse(b"SIP/2.0 100 \r\n\r\n").is_ok());
    }

    #[test]
    fn missing_blank_line_rejected() {
        assert!(SipMessage::parse(b"OPTIONS sip:b@example.com SIP/2.0\r\nCall-ID: c\r\n").is_err());
    }

    #[test]
    fn display_keeps_body() {
        let m = ok(
            &req_with("Content-Length: 4\r\n", b"test"),
            Framing::Datagram,
        );
        assert!(m.to_string().ends_with("\r\n\r\ntest"));
    }

    #[test]
    fn framing_from_transport() {
        assert_eq!(Framing::from(Transport::Udp), Framing::Datagram);
        assert_eq!(Framing::from(Transport::Tcp), Framing::Stream);
        assert_eq!(Framing::from(Transport::Tls), Framing::Stream);
        assert_eq!(Framing::from(Transport::Ws), Framing::Message);
        assert_eq!(Framing::from(Transport::Wss), Framing::Message);
        assert_eq!(Framing::from(Transport::Sctp), Framing::Message);
    }

    #[test]
    fn message_framing_content_length_optional_but_exact() {
        // RFC 7118 §5: no Content-Length needed; whole message is the body.
        let m = ok(&req_with("", b"abc"), Framing::Message);
        assert_eq!(m.body().map(bytes::Bytes::len), Some(3));
        assert!(
            SipMessage::parse_with(&req_with("Content-Length: 3\r\n", b"abc"), Framing::Message)
                .is_ok()
        );
        assert!(
            SipMessage::parse_with(&req_with("Content-Length: 2\r\n", b"abc"), Framing::Message)
                .is_err()
        );
        assert!(
            SipMessage::parse_with(&req_with("Content-Length: 4\r\n", b"abc"), Framing::Message)
                .is_err()
        );
    }
}
