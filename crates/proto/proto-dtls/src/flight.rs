//! Outgoing flights and the retransmission timer (RFC 6347 §4.2.3, §4.2.4).
//!
//! A flight is kept as plaintext fragments, not as encoded records: every
//! (re)transmission is encoded again so each record gets a fresh sequence
//! number. A retransmitted record with an old sequence number would be
//! dropped by the peer's replay window, and the sealing key refuses to reuse
//! a nonce.

#![deny(clippy::indexing_slicing)]

use crate::error::{DtlsError, DtlsResult};
use crate::record::{AssociationRecordLayer, ContentType, RECORD_HEADER_LEN};
use crate::wire::handshake_msg::{HANDSHAKE_HEADER_LEN, HandshakeHeader};
use std::time::{Duration, Instant};
use uc_crypto::aead::TAG_LEN;

/// Smallest MTU the association accepts.
///
/// The number is the IPv4 minimum reassembly size (RFC 791), but it is used
/// here as the largest UDP payload (DTLS datagram) the association emits,
/// not as an IP packet size: on a path whose IP MTU is 576 a datagram of
/// this size is 28 bytes (IPv4 and UDP headers) too large, and the driver
/// must configure the payload size the path can carry. Below about 141
/// bytes a `ClientHello` with a cookie no longer fits one datagram, and the
/// server role does not reassemble a first `ClientHello` (it keeps no state
/// before the cookie returns), so smaller values could never complete a
/// handshake.
pub const MIN_MTU: u16 = 576;
/// Largest MTU the association accepts.
pub const MAX_MTU: u16 = 1500;
/// Default MTU: fits IPv6 minimum-MTU paths with room for tunnels.
pub const DEFAULT_MTU: u16 = 1200;
/// Upper bound of the retransmission timer (plan §4.4).
///
/// RFC 6347 §4.2.4.1 suggests doubling up to no less than 60 s and keeping
/// the backed-off value across flights. Both are SHOULDs and both are
/// deliberately not followed: the handshake runs under a hard budget (10 s
/// by default, 60 s at most) on a media path that is already carrying a
/// call, so a timer above 8 s would mean a single retransmission per
/// handshake, and each flight starts again from the configured interval
/// because a flight that arrived shows the path works.
pub const MAX_RTO: Duration = Duration::from_secs(8);

/// Bytes added to a fragment by an epoch-1 record: explicit nonce and tag.
const SEALED_OVERHEAD: usize = 8 + TAG_LEN;

/// One record's worth of a flight, before record protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightItem {
    /// Epoch the record is sent in.
    pub epoch: u16,
    /// Record content type.
    pub content_type: ContentType,
    /// Record fragment: a handshake fragment with its header, or the
    /// one-byte `ChangeCipherSpec`.
    pub fragment: Vec<u8>,
}

/// Returns a handshake message in its unfragmented wire form (header and
/// body), which is what the handshake transcript covers (RFC 6347 §4.2.6).
///
/// # Errors
/// Returns an error if the body does not fit a 24-bit length.
pub fn handshake_message_bytes(msg_type: u8, message_seq: u16, body: &[u8]) -> DtlsResult<Vec<u8>> {
    let header = HandshakeHeader::unfragmented(msg_type, message_seq, body.len())
        .map_err(|e| encode_error(&e))?;
    let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN + body.len());
    header.encode(&mut out).map_err(|e| encode_error(&e))?;
    out.extend_from_slice(body);
    Ok(out)
}

fn encode_error(error: &dyn std::fmt::Display) -> DtlsError {
    DtlsError::HandshakeFailed {
        reason: format!("handshake message encoding failed: {error}"),
    }
}

/// The messages of one flight, ready to be (re)encoded.
#[derive(Debug, Default)]
pub struct Flight {
    items: Vec<FlightItem>,
}

impl Flight {
    /// Creates an empty flight.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// True when the flight holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Removes everything.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// The items, in sending order.
    #[must_use]
    pub fn items(&self) -> &[FlightItem] {
        &self.items
    }

    /// Adds a handshake message, split into fragments that fit one record
    /// in a datagram of `mtu` bytes (RFC 6347 §4.2.3).
    ///
    /// # Errors
    /// Returns an error if `mtu` leaves no room for a fragment or the body
    /// does not fit a 24-bit length.
    pub fn push_handshake(
        &mut self,
        epoch: u16,
        msg_type: u8,
        message_seq: u16,
        body: &[u8],
        mtu: u16,
    ) -> DtlsResult<()> {
        let overhead =
            RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + if epoch == 0 { 0 } else { SEALED_OVERHEAD };
        let room = usize::from(mtu)
            .checked_sub(overhead)
            .filter(|room| *room > 0)
            .ok_or_else(|| DtlsError::InvalidConfig {
                reason: "MTU too small for a handshake fragment".to_string(),
            })?;
        let base = HandshakeHeader::unfragmented(msg_type, message_seq, body.len())
            .map_err(|e| encode_error(&e))?;
        let mut offset = 0usize;
        let mut chunks = body.chunks(room);
        loop {
            // An empty body still produces one (empty) fragment.
            let chunk = chunks.next().unwrap_or(&[]);
            let header = HandshakeHeader {
                fragment_offset: u32::try_from(offset).map_err(|e| encode_error(&e))?,
                fragment_length: u32::try_from(chunk.len()).map_err(|e| encode_error(&e))?,
                ..base
            };
            let mut fragment = Vec::with_capacity(HANDSHAKE_HEADER_LEN + chunk.len());
            header.encode(&mut fragment).map_err(|e| encode_error(&e))?;
            fragment.extend_from_slice(chunk);
            self.items.push(FlightItem {
                epoch,
                content_type: ContentType::Handshake,
                fragment,
            });
            offset += chunk.len();
            if offset >= body.len() {
                return Ok(());
            }
        }
    }

    /// Adds a `ChangeCipherSpec` record (always epoch 0 in this profile).
    pub fn push_change_cipher_spec(&mut self) {
        self.items.push(FlightItem {
            epoch: 0,
            content_type: ContentType::ChangeCipherSpec,
            fragment: vec![1],
        });
    }

    /// Encodes the flight into datagrams of at most `mtu` bytes, packing as
    /// many records as fit into each (RFC 6347 §4.1.1). Every call consumes
    /// fresh record sequence numbers.
    ///
    /// # Errors
    /// Returns an error if a record cannot be protected.
    pub fn encode(
        &self,
        records: &mut AssociationRecordLayer,
        mtu: u16,
    ) -> DtlsResult<Vec<Vec<u8>>> {
        let mtu = usize::from(mtu);
        let mut datagrams = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        for item in &self.items {
            let record = records.seal(item.epoch, item.content_type, &item.fragment)?;
            if !current.is_empty() && current.len() + record.len() > mtu {
                datagrams.push(std::mem::take(&mut current));
            }
            current.extend_from_slice(&record);
        }
        if !current.is_empty() {
            datagrams.push(current);
        }
        Ok(datagrams)
    }
}

/// Retransmission timer with exponential backoff (RFC 6347 §4.2.4.1).
#[derive(Debug, Clone, Copy)]
pub struct RetransmitTimer {
    initial: Duration,
    current: Duration,
    deadline: Option<Instant>,
}

impl RetransmitTimer {
    /// Creates a stopped timer whose first interval is `initial`.
    #[must_use]
    pub const fn new(initial: Duration) -> Self {
        Self {
            initial,
            current: initial,
            deadline: None,
        }
    }

    /// Starts the timer for a new flight: the interval returns to its
    /// initial value.
    pub fn start(&mut self, now: Instant) {
        self.current = self.initial;
        self.deadline = Some(now + self.current);
    }

    /// Records an expiry: doubles the interval (up to [`MAX_RTO`]) and
    /// re-arms.
    pub fn back_off(&mut self, now: Instant) {
        self.current = self
            .current
            .saturating_mul(2)
            .min(MAX_RTO.max(self.initial));
        self.deadline = Some(now + self.current);
    }

    /// Stops the timer.
    pub const fn stop(&mut self) {
        self.deadline = None;
    }

    /// When the timer fires next, if it is running.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The current interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.current
    }

    /// True if the timer is running and `now` has reached its deadline.
    #[must_use]
    pub fn is_due(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::reassembly::Reassembler;
    use crate::record::DatagramRecords;
    use crate::wire::handshake_msg::{HT_CERTIFICATE, HT_SERVER_HELLO_DONE};
    use crate::wire::reader::Reader;

    #[test]
    fn fragments_fit_the_mtu_and_reassemble() {
        let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for mtu in [128, 256, MIN_MTU, DEFAULT_MTU] {
            let mut flight = Flight::new();
            flight
                .push_handshake(0, HT_CERTIFICATE, 3, &body, mtu)
                .unwrap();
            flight
                .push_handshake(0, HT_SERVER_HELLO_DONE, 4, &[], mtu)
                .unwrap();
            flight.push_change_cipher_spec();
            let mut records = AssociationRecordLayer::new();
            let datagrams = flight.encode(&mut records, mtu).unwrap();
            let mut reassembler = Reassembler::new(3);
            let mut ccs = 0;
            for datagram in &datagrams {
                assert!(datagram.len() <= usize::from(mtu));
                for record in DatagramRecords::new(datagram) {
                    let record = record.unwrap();
                    if record.content_type == ContentType::ChangeCipherSpec {
                        ccs += 1;
                        continue;
                    }
                    let mut r = Reader::new(record.payload);
                    let header = HandshakeHeader::parse(&mut r).unwrap();
                    reassembler.push(&header, r.rest(), 0).unwrap();
                }
            }
            assert_eq!(ccs, 1);
            assert_eq!(reassembler.pop().unwrap().body, body);
            assert_eq!(reassembler.pop().unwrap().body, Vec::<u8>::new());
        }
    }

    #[test]
    fn re_encoding_uses_fresh_sequence_numbers() {
        let mut flight = Flight::new();
        flight
            .push_handshake(0, HT_SERVER_HELLO_DONE, 0, &[], 1200)
            .unwrap();
        let mut records = AssociationRecordLayer::new();
        let first = flight.encode(&mut records, 1200).unwrap();
        let second = flight.encode(&mut records, 1200).unwrap();
        let seq = |d: &Vec<Vec<u8>>| {
            DatagramRecords::new(&d[0])
                .next()
                .unwrap()
                .unwrap()
                .sequence_number
        };
        assert_eq!((seq(&first), seq(&second)), (0, 1));
    }

    #[test]
    fn tiny_mtu_is_refused() {
        let mut flight = Flight::new();
        assert!(flight.push_handshake(0, 1, 0, &[1, 2, 3], 25).is_err());
        assert!(flight.push_handshake(1, 1, 0, &[1, 2, 3], 49).is_err());
        assert!(flight.is_empty());
    }

    #[test]
    fn unfragmented_form_has_full_length_fragment() {
        let bytes = handshake_message_bytes(20, 7, &[9; 12]).unwrap();
        assert_eq!(bytes[..12], [20, 0, 0, 12, 0, 7, 0, 0, 0, 0, 0, 12]);
    }

    #[test]
    fn timer_doubles_to_the_cap_and_resets() {
        let t0 = Instant::now();
        let mut timer = RetransmitTimer::new(Duration::from_secs(1));
        assert!(timer.deadline().is_none());
        assert!(!timer.is_due(t0));
        timer.start(t0);
        assert_eq!(timer.deadline(), Some(t0 + Duration::from_secs(1)));
        assert!(!timer.is_due(t0 + Duration::from_millis(999)));
        assert!(timer.is_due(t0 + Duration::from_secs(1)));
        let mut seen = Vec::new();
        for _ in 0..5 {
            timer.back_off(t0);
            seen.push(timer.interval().as_secs());
        }
        assert_eq!(seen, vec![2, 4, 8, 8, 8]);
        timer.start(t0);
        assert_eq!(timer.interval(), Duration::from_secs(1));
        timer.stop();
        assert!(timer.deadline().is_none());
    }
}
