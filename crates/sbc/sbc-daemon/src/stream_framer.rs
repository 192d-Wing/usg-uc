//! Incremental SIP framer for stream transports (TCP, TLS, WebSocket).
//!
//! SIP over a stream is framed by Content-Length (RFC 3261 §18.3): a message
//! is complete at end-of-headers (`\r\n\r\n`) plus the declared body length.
//! The framer owns the connection's reassembly buffer and keeps enough state
//! that each byte is searched for the terminator a bounded number of times
//! and each head is parsed once:
//!
//! - the CRLFCRLF search resumes 3 bytes before the end of the previous
//!   search, so a terminator split across reads is still found;
//! - the total message length is cached once the head is complete;
//! - more than `max_header_bytes` buffered without a terminator is an error;
//! - the buffer never holds more than `MAX_STREAM_MESSAGE_SIZE` bytes of
//!   capacity and is released to a small one once idle.
//!
//! One framer belongs to one connection task: no sharing, no locks.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection), SI-10

use bytes::{Buf, Bytes, BytesMut};
use proto_sip::SipMessage;
use uc_transport::MAX_STREAM_MESSAGE_SIZE;

/// Charge unit for a partial message: one per-source token per this many
/// bytes buffered beyond the first unit.
///
/// ## NIST 800-53 Rev5: SC-5
pub const UNFRAMED_CHARGE_BYTES: usize = 4096;

/// An empty buffer holding more capacity than this is replaced after a
/// frame is taken: twice the 4,096-byte stream read chunk (`uc_transport`
/// TCP reader), so ordinary traffic does not reallocate per message.
///
/// ## NIST 800-53 Rev5: SC-5, SC-6
pub const IDLE_RELEASE_CAPACITY: usize = 8_192;

/// Length of the header/body separator.
const TERMINATOR: &[u8] = b"\r\n\r\n";

/// Why a stream could not be framed. The connection is closed: once two
/// parties may disagree on a message boundary the stream cannot be
/// resynchronised (request smuggling).
#[derive(Debug)]
pub enum FramingError {
    /// No Content-Length on a stream transport (RFC 3261 §18.3, §20.14).
    Missing,
    /// Duplicate, malformed or oversized Content-Length, or a malformed
    /// header block (RFC 3261 §7.3.1, §20.14).
    Invalid(proto_sip::SipError),
    /// More than `max_header_bytes` buffered before CRLFCRLF.
    // POAM: POA&M-445 — closed without a 513/400: no response can be
    // addressed without a parsed head.
    HeaderTooLarge {
        /// Bytes buffered when the cap was hit.
        buffered: usize,
    },
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("missing Content-Length on a stream transport"),
            Self::Invalid(e) => write!(f, "{e}"),
            Self::HeaderTooLarge { buffered } => {
                write!(f, "no end of headers within {buffered} bytes")
            }
        }
    }
}

/// A push would hold more than `MAX_STREAM_MESSAGE_SIZE` bytes without a
/// complete message; the caller closes the connection (framing error).
#[derive(Debug, Clone, Copy)]
pub struct BufferFull {
    /// Bytes buffered plus the refused chunk.
    pub needed: usize,
}

/// Keep-alive CRLFs consumed by one [`StreamFramer::next_frame`] call.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeepAlive {
    /// Any keep-alive CRLF was consumed.
    pub seen: bool,
    /// Double-CRLF pings consumed (RFC 5626 §4.4.1).
    pub pings: u32,
}

/// Reassembly buffer plus resume state for one stream connection.
#[derive(Debug)]
pub struct StreamFramer {
    buf: BytesMut,
    /// Size of the allocation behind `buf`. After `split_to` the view's
    /// capacity shrinks but the frame shares (and, once it is dropped, `buf`
    /// still pins) the whole allocation, so the release check uses this.
    allocated: usize,
    /// Bytes of `buf` already searched for CRLFCRLF without a match.
    scan_from: usize,
    /// Total length (head plus body) of the message at the front of `buf`,
    /// once its head is complete.
    total: Option<usize>,
    /// TCP/TLS require Content-Length; message-framed WS does not.
    require_cl: bool,
    max_header_bytes: usize,
    #[cfg(test)]
    scanned: u64,
    #[cfg(test)]
    parses: u32,
}

impl StreamFramer {
    /// `require_cl` is false only for message-framed WebSocket (RFC 7118
    /// §5): a missing Content-Length then means the body is the rest of the
    /// buffer; a duplicate or malformed one is still an error.
    pub fn new(require_cl: bool, max_header_bytes: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            allocated: 0,
            scan_from: 0,
            total: None,
            require_cl,
            max_header_bytes,
            #[cfg(test)]
            scanned: 0,
            #[cfg(test)]
            parses: 0,
        }
    }

    /// Appends received bytes, or refuses them (nothing is buffered) when
    /// the total would exceed `MAX_STREAM_MESSAGE_SIZE`.
    ///
    /// Growth allocates exactly min(max(2 x capacity, needed),
    /// `MAX_STREAM_MESSAGE_SIZE`) and copies, instead of `BytesMut`'s
    /// doubling, so capacity never exceeds 65,535 bytes.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-6
    pub fn push(&mut self, data: &[u8]) -> Result<(), BufferFull> {
        let len = self.buf.len();
        let needed = len.saturating_add(data.len());
        if needed > MAX_STREAM_MESSAGE_SIZE {
            return Err(BufferFull { needed });
        }
        if self.buf.capacity() - len < data.len() {
            let cap = self
                .buf
                .capacity()
                .saturating_mul(2)
                .max(needed)
                .min(MAX_STREAM_MESSAGE_SIZE);
            let mut grown = BytesMut::with_capacity(cap);
            grown.extend_from_slice(&self.buf);
            self.allocated = grown.capacity();
            self.buf = grown;
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Bytes buffered and not yet framed.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The unframed bytes (for the framing-error 400 builder).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Drops all buffered bytes and resume state (RFC 7118 §5 discard).
    pub fn clear(&mut self) {
        self.buf.clear();
        self.scan_from = 0;
        self.total = None;
        self.release_if_idle();
    }

    /// Replaces an empty buffer backed by more than
    /// [`IDLE_RELEASE_CAPACITY`] with an unallocated one, so an idle
    /// connection does not keep a 64 KiB allocation after a large message.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-6
    fn release_if_idle(&mut self) {
        if self.buf.is_empty() && self.allocated > IDLE_RELEASE_CAPACITY {
            self.buf = BytesMut::new();
            self.allocated = 0;
        }
    }

    /// Capacity of the buffer's allocation.
    #[cfg(test)]
    pub fn capacity(&self) -> usize {
        self.allocated.max(self.buf.capacity())
    }

    /// Total bytes compared by the CRLFCRLF search so far.
    #[cfg(test)]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned
    }

    /// Calls to [`SipMessage::stream_message_len`] so far.
    #[cfg(test)]
    pub const fn head_parses(&self) -> u32 {
        self.parses
    }

    /// Removes `n` bytes from the front of the buffer, moving the resume
    /// offset with it.
    fn consume(&mut self, n: usize) -> BytesMut {
        self.scan_from = self.scan_from.saturating_sub(n);
        self.buf.split_to(n)
    }

    /// Drops `n` keep-alive bytes from the front (no split allocation).
    fn discard(&mut self, n: usize) {
        self.scan_from = self.scan_from.saturating_sub(n);
        self.buf.advance(n.min(self.buf.len()));
    }

    /// Extracts the next complete SIP message.
    ///
    /// The length comes from [`SipMessage::stream_message_len`], so the
    /// framer and the parser apply identical header rules (duplicates,
    /// compact `l`, `1*DIGIT`) and cannot cut at different offsets.
    ///
    /// Leading CRLFs (RFC 5626 keep-alive pings/pongs) are discarded and
    /// reported through `keepalive`: each `CRLFCRLF` is a ping that the
    /// caller answers on TCP/TLS; a lone CRLF (a pong) is discarded once
    /// the bytes after it cannot complete a ping, so a ping split across
    /// reads (even one byte at a time) is still recognised.
    ///
    /// Returns `Ok(None)` until a full message is buffered.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SI-10
    pub fn next_frame(&mut self, keepalive: &mut KeepAlive) -> Result<Option<Bytes>, FramingError> {
        if self.total.is_none() {
            let Some(total) = self.locate_message(keepalive)? else {
                return Ok(None);
            };
            self.total = Some(total);
        }
        let buffered = self.buf.len();
        let Some(total) = self.total.filter(|&total| buffered >= total) else {
            return Ok(None);
        };
        self.total = None;
        let frame = self.consume(total).freeze();
        self.release_if_idle();
        Ok(Some(frame))
    }

    /// Strips leading keep-alives and, once the head is complete, returns
    /// the total length of the message at the front of the buffer.
    fn locate_message(&mut self, keepalive: &mut KeepAlive) -> Result<Option<usize>, FramingError> {
        // Discard keep-alive CRLFs between messages.
        loop {
            if self.buf.starts_with(TERMINATOR) {
                self.discard(TERMINATOR.len());
                keepalive.seen = true;
                keepalive.pings = keepalive.pings.saturating_add(1);
            } else if self.buf.starts_with(b"\r\n") && !TERMINATOR.starts_with(&self.buf) {
                // A lone CRLF (pong) is dropped only once the next byte
                // shows it is not the start of a ping.
                self.discard(2);
                keepalive.seen = true;
            } else {
                break;
            }
        }
        self.release_if_idle();
        // Empty, or a prefix of a ping still arriving.
        if TERMINATOR.starts_with(&self.buf) {
            return Ok(None);
        }
        let Some(headers_end) = self.find_headers_end()? else {
            return Ok(None);
        };
        self.parse_head(headers_end).map(Some)
    }

    /// Resumes the CRLFCRLF search; returns the offset just past it.
    ///
    /// A terminator must end within the first `max_header_bytes` bytes, so
    /// the search never looks past that and more buffered bytes without one
    /// is an error, however the stream was segmented.
    fn find_headers_end(&mut self) -> Result<Option<usize>, FramingError> {
        let limit = self.buf.len().min(self.max_header_bytes);
        let start = self.scan_from.saturating_sub(TERMINATOR.len() - 1);
        let window = self.buf.get(start..limit).unwrap_or_default();
        #[cfg(test)]
        {
            self.scanned = self.scanned.saturating_add(window.len() as u64);
        }
        if let Some(pos) = window
            .windows(TERMINATOR.len())
            .position(|w| w == TERMINATOR)
        {
            return Ok(Some(start + pos + TERMINATOR.len()));
        }
        self.scan_from = limit;
        if self.buf.len() > self.max_header_bytes {
            return Err(FramingError::HeaderTooLarge {
                buffered: self.buf.len(),
            });
        }
        Ok(None)
    }

    /// Parses the head once and returns the message's total length.
    fn parse_head(&mut self, headers_end: usize) -> Result<usize, FramingError> {
        #[cfg(test)]
        {
            self.parses = self.parses.saturating_add(1);
        }
        let head = self.buf.get(..headers_end).unwrap_or_default();
        match SipMessage::stream_message_len(head) {
            Ok(total) => Ok(total),
            Err(proto_sip::SipError::MissingHeader { name })
                if name.eq_ignore_ascii_case("content-length") =>
            {
                if self.require_cl {
                    Err(FramingError::Missing)
                } else {
                    Ok(self.buf.len())
                }
            }
            Err(e) => Err(FramingError::Invalid(e)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        FramingError, IDLE_RELEASE_CAPACITY, KeepAlive, MAX_STREAM_MESSAGE_SIZE, StreamFramer,
        UNFRAMED_CHARGE_BYTES,
    };

    const MAX_HEAD: usize = 16_384;

    const REGISTER: &[u8] = b"REGISTER sip:example.mil SIP/2.0\r\n\
        Via: SIP/2.0/TLS host:5061;branch=z9hG4bK1\r\n\
        Content-Length: 0\r\n\
        \r\n";

    const INVITE: &[u8] = b"INVITE sip:b@example.mil SIP/2.0\r\nl: 4\r\n\r\nv=0\n";

    const MESSAGE: &[u8] = b"MESSAGE sip:example.mil SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";

    fn framer() -> StreamFramer {
        StreamFramer::new(true, MAX_HEAD)
    }

    /// Pushes each part, draining every complete frame after each push.
    fn feed(f: &mut StreamFramer, parts: &[&[u8]]) -> (Vec<bytes::Bytes>, u32) {
        let mut out = Vec::new();
        let mut pings = 0;
        for part in parts {
            f.push(part).unwrap();
            loop {
                let mut ka = KeepAlive::default();
                let next = f.next_frame(&mut ka).expect("valid framing");
                pings += ka.pings;
                match next {
                    Some(frame) => out.push(frame),
                    None => break,
                }
            }
        }
        (out, pings)
    }

    /// Frames with stream (Content-Length required) rules.
    fn frame(f: &mut StreamFramer) -> Option<bytes::Bytes> {
        let mut ka = KeepAlive::default();
        f.next_frame(&mut ka).expect("valid framing")
    }

    fn frame_err(msg: &[u8], require_cl: bool) -> FramingError {
        let mut f = StreamFramer::new(require_cl, MAX_HEAD);
        f.push(msg).unwrap();
        let mut ka = KeepAlive::default();
        f.next_frame(&mut ka).expect_err("framing error")
    }

    #[test]
    fn frame_complete_message() {
        let mut f = framer();
        f.push(REGISTER).unwrap();
        let frame_bytes = frame(&mut f).expect("complete message");
        assert_eq!(&frame_bytes[..], REGISTER);
        assert_eq!(f.buffered(), 0);
        assert!(frame(&mut f).is_none());
    }

    #[test]
    fn frame_waits_for_full_body() {
        let mut f = framer();
        f.push(b"MESSAGE sip:example.mil SIP/2.0\r\nContent-Length: 5\r\n\r\nhel")
            .unwrap();
        assert!(frame(&mut f).is_none());
        f.push(b"lo").unwrap();
        let got = frame(&mut f).expect("complete after body");
        assert!(got.ends_with(b"hello"));
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn frame_splits_pipelined_messages_and_skips_keepalives() {
        let mut f = framer();
        f.push(b"\r\n\r\n").unwrap(); // RFC 5626 keep-alive ping
        f.push(REGISTER).unwrap();
        f.push(REGISTER).unwrap();
        let mut ka = KeepAlive::default();
        let first = f.next_frame(&mut ka).unwrap().unwrap();
        assert!(ka.seen);
        assert_eq!(first.len(), REGISTER.len());
        assert_eq!(frame(&mut f).expect("second").len(), REGISTER.len());
        assert!(frame(&mut f).is_none());
    }

    #[test]
    fn frame_partial_headers_returns_none() {
        let mut f = framer();
        f.push(b"REGISTER sip:example.mil SIP/2.0\r\nVia: x")
            .unwrap();
        assert!(frame(&mut f).is_none());
        assert!(f.buffered() > 0); // kept for the next chunk
    }

    #[test]
    fn content_length_compact_form() {
        let msg = b"MESSAGE sip:a SIP/2.0\r\nl: 7\r\n\r\n1234567";
        let mut f = framer();
        f.push(msg).unwrap();
        assert_eq!(frame(&mut f).unwrap().len(), msg.len());
    }

    #[test]
    fn duplicate_content_length_rejected() {
        let equal = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            frame_err(equal, true),
            FramingError::Invalid(proto_sip::SipError::DuplicateHeader { .. })
        ));
        let conflicting = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 5\r\nl: 7\r\n\r\n";
        assert!(matches!(
            frame_err(conflicting, true),
            FramingError::Invalid(proto_sip::SipError::DuplicateHeader { .. })
        ));
        // Still rejected on message-framed WS.
        assert!(matches!(
            frame_err(conflicting, false),
            FramingError::Invalid(_)
        ));
    }

    #[test]
    fn malformed_content_length_rejected() {
        for value in ["-1", "5x", "+5", "", "12345678901", "70000"] {
            let msg = format!("OPTIONS sip:a SIP/2.0\r\nContent-Length: {value}\r\n\r\n");
            assert!(
                matches!(frame_err(msg.as_bytes(), true), FramingError::Invalid(_)),
                "{value:?} accepted"
            );
        }
    }

    #[test]
    fn missing_content_length_rejected_on_stream_framed_on_ws() {
        let msg = b"OPTIONS sip:a SIP/2.0\r\nVia: SIP/2.0/WS h;branch=z9hG4bK1\r\n\r\nbody";
        assert!(matches!(frame_err(msg, true), FramingError::Missing));
        let mut f = StreamFramer::new(false, MAX_HEAD);
        f.push(msg).unwrap();
        let mut ka = KeepAlive::default();
        let got = f.next_frame(&mut ka).unwrap().unwrap();
        assert_eq!(&got[..], &msg[..]);
    }

    // Round-trip: well-formed pipelined messages split at every offset
    // reframe to the identical bytes.
    #[test]
    fn reframing_any_split_is_identical() {
        let mut stream = Vec::new();
        stream.extend_from_slice(REGISTER);
        stream.extend_from_slice(b"\r\n");
        stream.extend_from_slice(INVITE);
        for split in 0..=stream.len() {
            let mut f = framer();
            let mut out = Vec::new();
            for part in [&stream[..split], &stream[split..]] {
                f.push(part).unwrap();
                while let Some(got) = frame(&mut f) {
                    out.push(got);
                }
            }
            assert_eq!(out.len(), 2, "split {split}");
            assert_eq!(&out[0][..], REGISTER);
            assert_eq!(&out[1][..], INVITE);
        }
    }

    #[test]
    fn keepalive_counts_pings_and_waits_on_a_lone_crlf() {
        let mut f = framer();
        f.push(b"\r\n\r\n\r\n\r\n\r\n").unwrap();
        let mut ka = KeepAlive::default();
        assert!(f.next_frame(&mut ka).unwrap().is_none());
        assert_eq!(ka.pings, 2);
        assert_eq!(f.as_bytes(), b"\r\n");
        // A pong (lone CRLF) before a message is dropped, not a ping.
        f.push(REGISTER).unwrap();
        let mut ka = KeepAlive::default();
        assert!(f.next_frame(&mut ka).unwrap().is_some());
        assert_eq!((ka.seen, ka.pings), (true, 0));
    }

    // CRLF between pipelined messages is still a keep-alive and never
    // desynchronises framing; a whitespace or empty Content-Length is
    // malformed.
    #[test]
    fn qa_content_length_whitespace_variants() {
        for value in ["", " ", "1 2", "0x10"] {
            let msg = format!("OPTIONS sip:a SIP/2.0\r\nContent-Length:{value}\r\n\r\n");
            assert!(
                matches!(frame_err(msg.as_bytes(), true), FramingError::Invalid(_)),
                "{value:?} accepted"
            );
        }
        let mut f = framer();
        f.push(b"OPTIONS sip:a SIP/2.0\r\nContent-Length:   0  \r\n\r\n")
            .unwrap();
        assert!(frame(&mut f).is_some());
    }

    // A head ending past `max_header_bytes` is rejected even when it arrives
    // in one read.
    #[test]
    fn framer_rejects_oversized_head_in_one_read() {
        let mut msg = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n".to_vec();
        while msg.len() < MAX_HEAD {
            msg.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        let mut f = framer();
        f.push(&msg).unwrap();
        let mut ka = KeepAlive::default();
        assert!(matches!(
            f.next_frame(&mut ka),
            Err(FramingError::HeaderTooLarge { .. })
        ));
    }

    #[test]
    fn unframed_charge_unit_is_4_kib() {
        assert_eq!(UNFRAMED_CHARGE_BYTES, 4_096);
    }

    // CRLFCRLF search resumes near the end, not at 0.
    #[test]
    fn framer_scan_is_linear_in_bytes() {
        let mut head = b"OPTIONS sip:a SIP/2.0\r\n".to_vec();
        while head.len() < MAX_HEAD {
            head.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        head.truncate(MAX_HEAD);
        assert!(!head.windows(4).any(|w| w == b"\r\n\r\n"));
        let mut f = framer();
        for b in &head {
            f.push(std::slice::from_ref(b)).unwrap();
            let mut ka = KeepAlive::default();
            assert!(f.next_frame(&mut ka).unwrap().is_none());
        }
        assert_eq!(f.buffered(), MAX_HEAD);
        let scanned = f.scanned_bytes();
        assert!(scanned <= 4 * MAX_HEAD as u64, "scanned {scanned}");
        // One byte past the cap without CRLFCRLF is an error.
        f.push(b"a").unwrap();
        let mut ka = KeepAlive::default();
        assert!(matches!(
            f.next_frame(&mut ka),
            Err(FramingError::HeaderTooLarge { buffered }) if buffered == MAX_HEAD + 1
        ));
    }

    // The head is parsed once per message, not once per read.
    #[test]
    fn framer_parses_head_once_per_message() {
        let mut msg = b"MESSAGE sip:a SIP/2.0\r\nContent-Length: 100\r\n\r\n".to_vec();
        let head_len = msg.len();
        msg.extend(std::iter::repeat_n(b'b', 100));
        let mut f = framer();
        f.push(&msg[..head_len]).unwrap();
        let mut ka = KeepAlive::default();
        assert!(f.next_frame(&mut ka).unwrap().is_none());
        let mut out = None;
        for b in &msg[head_len..] {
            f.push(std::slice::from_ref(b)).unwrap();
            let mut ka = KeepAlive::default();
            if let Some(frame) = f.next_frame(&mut ka).unwrap() {
                assert!(out.is_none(), "framed twice");
                out = Some(frame);
            }
        }
        assert_eq!(&out.expect("framed")[..], &msg[..]);
        assert_eq!(f.head_parses(), 1);
        assert_eq!(f.buffered(), 0);
        // The next message parses its own head.
        f.push(REGISTER).unwrap();
        let mut ka = KeepAlive::default();
        assert_eq!(&f.next_frame(&mut ka).unwrap().unwrap()[..], REGISTER);
        assert_eq!(f.head_parses(), 2);
    }

    // A terminator split across 2 or 3 pushes is found exactly once.
    #[test]
    fn framer_terminator_split_at_every_offset() {
        for msg in [REGISTER, MESSAGE] {
            for i in 0..=msg.len() {
                let mut f = framer();
                let (out, _) = feed(&mut f, &[&msg[..i], &msg[i..]]);
                assert_eq!(out.len(), 1, "split {i}");
                assert_eq!(&out[0][..], msg, "split {i}");
                assert_eq!(f.buffered(), 0);
                for j in i..=msg.len() {
                    let mut f = framer();
                    let (out, _) = feed(&mut f, &[&msg[..i], &msg[i..j], &msg[j..]]);
                    assert_eq!(out.len(), 1, "split {i}/{j}");
                    assert_eq!(&out[0][..], msg, "split {i}/{j}");
                }
            }
        }
    }

    // Same frames as a one-shot parse for any split and for a 1-byte drip.
    #[test]
    fn framer_matches_reference_for_all_splits() {
        let mut stream = Vec::new();
        stream.extend_from_slice(REGISTER);
        stream.extend_from_slice(b"\r\n");
        stream.extend_from_slice(INVITE);
        for split in 0..=stream.len() {
            let mut f = framer();
            let (out, _) = feed(&mut f, &[&stream[..split], &stream[split..]]);
            assert_eq!(out.len(), 2, "split {split}");
            assert_eq!(&out[0][..], REGISTER);
            assert_eq!(&out[1][..], INVITE);
        }

        let mut pipelined = Vec::new();
        pipelined.extend_from_slice(b"\r\n\r\n");
        pipelined.extend_from_slice(REGISTER);
        pipelined.extend_from_slice(b"\r\n\r\n");
        pipelined.extend_from_slice(INVITE);
        pipelined.extend_from_slice(b"\r\n");
        pipelined.extend_from_slice(MESSAGE);
        let (reference, ref_pings) = feed(&mut framer(), &[&pipelined]);
        assert_eq!(reference.len(), 3);
        assert_eq!(&reference[0][..], REGISTER);
        assert_eq!(&reference[1][..], INVITE);
        assert_eq!(&reference[2][..], MESSAGE);
        assert_eq!(ref_pings, 2);
        let drip: Vec<&[u8]> = pipelined.chunks(1).collect();
        let mut f = framer();
        let (out, pings) = feed(&mut f, &drip);
        assert_eq!(out, reference);
        assert_eq!(pings, ref_pings);
        assert_eq!(f.buffered(), 0);
    }

    // Stripping a leading ping moves the resume offset with the buffer.
    #[test]
    fn framer_keepalive_strip_adjusts_scan_offset() {
        for i in 0..REGISTER.len() {
            let mut first = b"\r\n\r\n".to_vec();
            first.extend_from_slice(&REGISTER[..i]);
            let mut f = framer();
            let mut ka = KeepAlive::default();
            f.push(&first).unwrap();
            let got = f.next_frame(&mut ka).unwrap();
            assert!(got.is_none(), "split {i}");
            assert_eq!(ka.pings, 1, "split {i}");
            f.push(&REGISTER[i..]).unwrap();
            let mut ka2 = KeepAlive::default();
            let frame = f.next_frame(&mut ka2).unwrap().expect("framed");
            assert_eq!(&frame[..], REGISTER, "split {i}");
            assert_eq!(ka2.pings, 0, "split {i}");
            assert_eq!(f.buffered(), 0);
        }
    }

    // clear() drops the buffer, the resume offset and any cached head.
    #[test]
    fn framer_clear_resets_state() {
        let mut f = framer();
        f.push(b"OPTIONS sip:a SIP/2.0\r\nVia: x").unwrap();
        let mut ka = KeepAlive::default();
        assert!(f.next_frame(&mut ka).unwrap().is_none());
        f.clear();
        assert_eq!(f.buffered(), 0);
        assert_eq!(f.as_bytes(), b"");
        f.push(REGISTER).unwrap();
        assert_eq!(&f.next_frame(&mut ka).unwrap().unwrap()[..], REGISTER);

        // Head complete, body short: the cached length must not survive.
        let mut f = framer();
        f.push(b"MESSAGE sip:a SIP/2.0\r\nContent-Length: 50\r\n\r\nabc")
            .unwrap();
        assert!(f.next_frame(&mut ka).unwrap().is_none());
        f.clear();
        f.push(REGISTER).unwrap();
        assert_eq!(&f.next_frame(&mut ka).unwrap().unwrap()[..], REGISTER);
        assert_eq!(f.buffered(), 0);
    }

    // WS (no Content-Length required): the body is the rest of the buffer.
    #[test]
    fn framer_ws_missing_content_length_takes_rest() {
        let msg = b"OPTIONS sip:a SIP/2.0\r\nVia: SIP/2.0/WS h;branch=z9hG4bK1\r\n\r\nbody";
        let mut f = StreamFramer::new(false, MAX_HEAD);
        f.push(msg).unwrap();
        let mut ka = KeepAlive::default();
        assert_eq!(&f.next_frame(&mut ka).unwrap().unwrap()[..], &msg[..]);
        let mut f = framer();
        f.push(msg).unwrap();
        assert!(matches!(f.next_frame(&mut ka), Err(FramingError::Missing)));
    }

    // as_bytes() exposes the buffered head for the 400 builder.
    #[test]
    fn framer_as_bytes_holds_unframed_input() {
        let bad = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n";
        let mut f = framer();
        f.push(bad).unwrap();
        let mut ka = KeepAlive::default();
        assert!(matches!(
            f.next_frame(&mut ka),
            Err(FramingError::Invalid(_))
        ));
        assert_eq!(f.as_bytes(), &bad[..]);
    }

    /// A `body_len`-byte MESSAGE with a valid head.
    fn big_message(body_len: usize) -> Vec<u8> {
        let mut msg =
            format!("MESSAGE sip:a SIP/2.0\r\nContent-Length: {body_len}\r\n\r\n").into_bytes();
        msg.extend(std::iter::repeat_n(b'b', body_len));
        msg
    }

    // SEC-001: a 4,095-byte first read then the rest of a 65,000-byte
    // message: growth is capped at MAX_STREAM_MESSAGE_SIZE (no doubling to
    // 128 KiB) and the buffer is released once the frame drains.
    #[test]
    fn framer_capacity_is_capped_and_released_when_idle() {
        let ceiling = MAX_STREAM_MESSAGE_SIZE + 4_096;
        // Head length with a 5-digit Content-Length.
        let head_len = big_message(10_000).len() - 10_000;
        let msg = big_message(65_000 - head_len);
        assert_eq!(msg.len(), 65_000);
        let mut f = framer();
        for split in [1, 7, 1_000, 4_095, 4_096, 16_384] {
            let mut framed = 0;
            let (first, rest) = msg.split_at(4_095);
            for part in std::iter::once(first).chain(rest.chunks(split)) {
                f.push(part).unwrap();
                assert!(f.capacity() <= ceiling, "split {split}: {}", f.capacity());
                while let Some(got) = frame(&mut f) {
                    assert_eq!(&got[..], &msg[..]);
                    framed += 1;
                }
                assert!(f.capacity() <= ceiling, "split {split}: {}", f.capacity());
            }
            assert_eq!(framed, 1, "split {split}");
            assert_eq!(f.buffered(), 0);
            assert!(
                f.capacity() <= IDLE_RELEASE_CAPACITY,
                "split {split}: {} after drain",
                f.capacity()
            );
        }
        // Small traffic afterwards still frames.
        f.push(REGISTER).unwrap();
        assert_eq!(&frame(&mut f).expect("framed")[..], REGISTER);
    }

    // SEC-001: a push that would exceed MAX_STREAM_MESSAGE_SIZE is refused
    // before the buffer grows; nothing is appended.
    #[test]
    fn framer_refuses_push_over_max_before_growing() {
        let mut f = framer();
        let chunk = vec![b'x'; 4_096];
        let mut pushed = 0;
        while pushed + chunk.len() <= MAX_STREAM_MESSAGE_SIZE {
            f.push(&chunk).unwrap();
            pushed += chunk.len();
        }
        let before = f.capacity();
        let err = f.push(&chunk).expect_err("over the cap");
        assert_eq!(err.needed, pushed + chunk.len());
        assert_eq!(f.buffered(), pushed);
        assert_eq!(f.capacity(), before);
        assert!(f.capacity() <= MAX_STREAM_MESSAGE_SIZE);
        // Exactly MAX is accepted.
        f.push(&chunk[..MAX_STREAM_MESSAGE_SIZE - pushed]).unwrap();
        assert_eq!(f.buffered(), MAX_STREAM_MESSAGE_SIZE);
        assert!(f.push(b"y").is_err());
    }
}
