//! Handshake message reassembly and ordering (RFC 6347 §4.2.2, §4.2.3).
//!
//! Fragments arrive in any order, may overlap and may be duplicated. The
//! reassembler hands complete messages to the association strictly in
//! `message_seq` order and keeps its memory inside fixed limits.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection), SI-10
//!
//! Limits (all enforced before any allocation):
//!
//! - message length: [`MAX_MESSAGE_LEN`] for most types,
//!   [`MAX_CERTIFICATE_MESSAGE_LEN`] for `Certificate`;
//! - buffered messages: the next expected one plus [`FUTURE_WINDOW`] after it;
//! - total buffered bytes: [`MAX_BUFFERED_BYTES`];
//! - disjoint ranges tracked per message: [`MAX_RANGES`].
//!
//! ## Unauthenticated fragments (SEC-001)
//!
//! Before the peer's `ChangeCipherSpec` every fragment arrives in a
//! plaintext record that anyone who can spoof the peer's address can forge.
//! A forged fragment must not be able to shut the genuine message out of its
//! slot, so:
//!
//! - a lower `message_seq` has priority for memory: a message is admitted by
//!   evicting buffered messages with a higher `message_seq`, highest first,
//!   and the next expected message therefore always fits;
//! - a fragment that disagrees with its slot about the message type or
//!   length replaces the slot (the older bytes and ranges are thrown away
//!   whole, never merged);
//! - a fragment from a higher epoch replaces a slot from a lower one, and a
//!   fragment from a lower epoch never enters a slot from a higher one;
//! - [`Reassembler::discard_below_epoch`] drops what is left of the old
//!   epoch at the cipher change.
//!
//! A slot therefore only ever holds fragments that agree on type, length
//! and epoch. Fragments that agree on all three cannot be told apart
//! without keys; a forged one is caught by the signature and `Finished`
//! checks of the handshake, not here.

#![deny(clippy::indexing_slicing)]

use crate::wire::handshake_msg::{HT_CERTIFICATE, HandshakeHeader};

/// Largest handshake message body accepted, except `Certificate`.
pub const MAX_MESSAGE_LEN: usize = 2048;
/// Largest `Certificate` message body accepted.
pub const MAX_CERTIFICATE_MESSAGE_LEN: usize = 8192;
/// How far past the next expected `message_seq` a fragment may be and still
/// be buffered. Four covers the longest flight of this profile (five
/// messages) arriving with its first message lost.
pub const FUTURE_WINDOW: u16 = 4;
/// Upper bound on bytes held for incomplete or not-yet-delivered messages.
pub const MAX_BUFFERED_BYTES: usize = 16 * 1024;
/// Most disjoint byte ranges tracked for one message.
pub const MAX_RANGES: usize = 16;

/// A fragment that breaks the protocol limits; nothing is stored for it.
///
/// The association drops and counts it when it came in an unauthenticated
/// (epoch 0) record, and fails when it came in an authenticated one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyViolation {
    /// The message length is above the limit for its type.
    MessageTooLong,
    /// `fragment_offset + fragment_length` exceeds the message length, or
    /// the fragment body does not match `fragment_length`.
    FragmentOutOfBounds,
    /// `message_seq` is beyond the buffering window.
    TooFarAhead,
    /// The buffered-bytes limit would be exceeded even after evicting every
    /// buffered message with a higher `message_seq`.
    BufferLimit,
}

/// What happened to an accepted or ignored fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentOutcome {
    /// The fragment was stored (or added nothing new).
    Buffered,
    /// The fragment belongs to a message that was already delivered: the
    /// peer is retransmitting an earlier flight (RFC 6347 §4.2.4).
    Retransmission,
    /// The fragment was dropped without failing: it arrived in a lower
    /// epoch than the rest of its message, or its ranges are too scattered.
    Rejected,
}

/// A complete handshake message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteMessage {
    /// Handshake message type.
    pub msg_type: u8,
    /// Message sequence number.
    pub message_seq: u16,
    /// Epoch of the records that carried every fragment.
    pub epoch: u16,
    /// Message body.
    pub body: Vec<u8>,
}

#[derive(Debug)]
struct Partial {
    msg_type: u8,
    message_seq: u16,
    epoch: u16,
    data: Vec<u8>,
    /// Sorted, non-overlapping, non-adjacent received ranges `[start, end)`.
    ranges: Vec<(usize, usize)>,
}

impl Partial {
    const fn is_complete(&self) -> bool {
        match self.ranges.as_slice() {
            [] => self.data.is_empty(),
            [(0, end)] => *end == self.data.len(),
            _ => false,
        }
    }

    /// Adds `[start, end)` to the range list, merging neighbours. Returns
    /// false (and changes nothing) if that would exceed [`MAX_RANGES`].
    fn add_range(&mut self, start: usize, end: usize) -> bool {
        let mut merged = Vec::with_capacity(self.ranges.len() + 1);
        let (mut start, mut end) = (start, end);
        let mut placed = false;
        for &(s, e) in &self.ranges {
            if e < start {
                merged.push((s, e));
            } else if s > end {
                if !placed {
                    merged.push((start, end));
                    placed = true;
                }
                merged.push((s, e));
            } else {
                start = start.min(s);
                end = end.max(e);
            }
        }
        if !placed {
            merged.push((start, end));
        }
        if merged.len() > MAX_RANGES {
            return false;
        }
        self.ranges = merged;
        true
    }
}

/// Reassembles and orders incoming handshake messages.
#[derive(Debug)]
pub struct Reassembler {
    next_seq: u16,
    partials: Vec<Partial>,
    buffered: usize,
}

impl Reassembler {
    /// Creates a reassembler expecting `next_seq` first.
    #[must_use]
    pub const fn new(next_seq: u16) -> Self {
        Self {
            next_seq,
            partials: Vec::new(),
            buffered: 0,
        }
    }

    /// The `message_seq` of the next message to deliver.
    #[must_use]
    pub const fn next_seq(&self) -> u16 {
        self.next_seq
    }

    /// Bytes currently held.
    #[must_use]
    pub const fn buffered_bytes(&self) -> usize {
        self.buffered
    }

    /// Offers one fragment, received in a record of `epoch`.
    ///
    /// # Errors
    /// Returns a [`ReassemblyViolation`] when the fragment breaks a limit;
    /// nothing is stored in that case.
    pub fn push(
        &mut self,
        header: &HandshakeHeader,
        fragment: &[u8],
        epoch: u16,
    ) -> Result<FragmentOutcome, ReassemblyViolation> {
        let length = to_usize(header.length)?;
        let offset = to_usize(header.fragment_offset)?;
        let frag_len = to_usize(header.fragment_length)?;
        let limit = if header.msg_type == HT_CERTIFICATE {
            MAX_CERTIFICATE_MESSAGE_LEN
        } else {
            MAX_MESSAGE_LEN
        };
        if length > limit {
            return Err(ReassemblyViolation::MessageTooLong);
        }
        let end = offset
            .checked_add(frag_len)
            .filter(|end| *end <= length && fragment.len() == frag_len)
            .ok_or(ReassemblyViolation::FragmentOutOfBounds)?;

        if header.message_seq < self.next_seq {
            return Ok(FragmentOutcome::Retransmission);
        }
        if header.message_seq - self.next_seq > FUTURE_WINDOW {
            return Err(ReassemblyViolation::TooFarAhead);
        }

        let is_known = |p: &Partial| p.message_seq == header.message_seq;
        let existing = self.partials.iter().position(is_known);
        let mut replaced = None;
        if let Some(partial) = existing.and_then(|index| self.partials.get(index)) {
            // NIST 800-53 Rev5: SC-5 -- a slot cannot be pinned by whoever
            // wrote to it first. A fragment of a later epoch, or one that
            // disagrees about type or length, starts the slot again; one of
            // an earlier epoch is dropped.
            if epoch < partial.epoch {
                return Ok(FragmentOutcome::Rejected);
            }
            if epoch > partial.epoch
                || partial.msg_type != header.msg_type
                || partial.data.len() != length
            {
                replaced = existing;
            }
        }
        if existing.is_none() || replaced.is_some() {
            let released = replaced
                .and_then(|index| self.partials.get(index))
                .map_or(0, |partial| partial.data.len());
            self.make_room(header.message_seq, length, released)?;
            // Eviction may have moved the slot: look it up again.
            if replaced.is_some()
                && let Some(index) = self.partials.iter().position(is_known)
            {
                let old = self.partials.swap_remove(index);
                self.buffered = self.buffered.saturating_sub(old.data.len());
            }
            self.buffered += length;
            self.partials.push(Partial {
                msg_type: header.msg_type,
                message_seq: header.message_seq,
                epoch,
                data: vec![0; length],
                ranges: Vec::new(),
            });
        }
        let Some(partial) = self.partials.iter_mut().find(|p| is_known(p)) else {
            return Ok(FragmentOutcome::Rejected);
        };
        if frag_len == 0 {
            // Only meaningful for an empty message, which is complete as is.
            return Ok(FragmentOutcome::Buffered);
        }
        if !partial.add_range(offset, end) {
            return Ok(FragmentOutcome::Rejected);
        }
        if let Some(target) = partial.data.get_mut(offset..end) {
            target.copy_from_slice(fragment);
        }
        Ok(FragmentOutcome::Buffered)
    }

    /// Makes sure `length` more bytes fit for a message with `message_seq`,
    /// given that `released` bytes of its own slot are about to be freed.
    /// Buffered messages with a higher `message_seq` are evicted, highest
    /// first, until it fits.
    ///
    /// NIST 800-53 Rev5: SC-5 -- forged fragments for later messages cannot
    /// take the memory the next expected message needs: every message is at
    /// most [`MAX_CERTIFICATE_MESSAGE_LEN`], half of [`MAX_BUFFERED_BYTES`],
    /// so the next expected one always fits once everything after it is gone.
    fn make_room(
        &mut self,
        message_seq: u16,
        length: usize,
        released: usize,
    ) -> Result<(), ReassemblyViolation> {
        let held = self.buffered.saturating_sub(released);
        let evictable: usize = self
            .partials
            .iter()
            .filter(|p| p.message_seq > message_seq)
            .map(|p| p.data.len())
            .sum();
        if held.saturating_sub(evictable) + length > MAX_BUFFERED_BYTES {
            return Err(ReassemblyViolation::BufferLimit);
        }
        while self.buffered.saturating_sub(released) + length > MAX_BUFFERED_BYTES {
            let highest = self
                .partials
                .iter()
                .enumerate()
                .filter(|(_, p)| p.message_seq > message_seq)
                .max_by_key(|(_, p)| p.message_seq)
                .map(|(index, _)| index);
            let Some(index) = highest else {
                return Err(ReassemblyViolation::BufferLimit);
            };
            let evicted = self.partials.swap_remove(index);
            self.buffered = self.buffered.saturating_sub(evicted.data.len());
        }
        Ok(())
    }

    /// Drops every buffered message whose fragments came in an epoch below
    /// `epoch`. Returns how many were dropped.
    ///
    /// Called at the peer's `ChangeCipherSpec`: from then on only records of
    /// the new epoch are read, so anything left from the old one could only
    /// have been put there by someone other than the peer.
    pub fn discard_below_epoch(&mut self, epoch: u16) -> usize {
        let before = self.partials.len();
        self.partials.retain(|p| p.epoch >= epoch);
        self.buffered = self.partials.iter().map(|p| p.data.len()).sum();
        before - self.partials.len()
    }

    /// Takes the next message if it is complete, advancing `next_seq`.
    pub fn pop(&mut self) -> Option<CompleteMessage> {
        let message = self.take_next()?;
        self.advance();
        Some(message)
    }

    /// Moves on to the following `message_seq`, after the message from
    /// [`Self::take_next`] has been accepted.
    pub const fn advance(&mut self) {
        self.next_seq = self.next_seq.wrapping_add(1);
    }

    /// Takes the next message if it is complete, emptying its slot but
    /// leaving `next_seq` where it is.
    ///
    /// NIST 800-53 Rev5: SC-5 -- the caller calls [`Self::advance`] only
    /// when it accepts the message. A message it refuses (which, before the
    /// cipher change, anyone could have put there) is thereby thrown away
    /// without using up the `message_seq`, and the genuine message can
    /// still arrive in the same slot.
    pub fn take_next(&mut self) -> Option<CompleteMessage> {
        let index = self
            .partials
            .iter()
            .position(|p| p.message_seq == self.next_seq && p.is_complete())?;
        let partial = self.partials.swap_remove(index);
        self.buffered = self.buffered.saturating_sub(partial.data.len());
        Some(CompleteMessage {
            msg_type: partial.msg_type,
            message_seq: partial.message_seq,
            epoch: partial.epoch,
            body: partial.data,
        })
    }
}

fn to_usize(value: u32) -> Result<usize, ReassemblyViolation> {
    usize::try_from(value).map_err(|_| ReassemblyViolation::FragmentOutOfBounds)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::wire::handshake_msg::{HT_FINISHED, HT_SERVER_HELLO, HT_SERVER_HELLO_DONE};

    fn frag(
        msg_type: u8,
        seq: u16,
        body: &[u8],
        offset: usize,
        len: usize,
    ) -> (HandshakeHeader, Vec<u8>) {
        (
            HandshakeHeader {
                msg_type,
                length: u32::try_from(body.len()).unwrap(),
                message_seq: seq,
                fragment_offset: u32::try_from(offset).unwrap(),
                fragment_length: u32::try_from(len).unwrap(),
            },
            body[offset..offset + len].to_vec(),
        )
    }

    fn body(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    fn push(
        r: &mut Reassembler,
        f: &(HandshakeHeader, Vec<u8>),
    ) -> Result<FragmentOutcome, ReassemblyViolation> {
        r.push(&f.0, &f.1, 0)
    }

    #[test]
    fn in_order_reversed_overlapping_and_duplicated() {
        let b = body(300);
        let orders: [&[(usize, usize)]; 4] = [
            &[(0, 100), (100, 100), (200, 100)],
            &[(200, 100), (100, 100), (0, 100)],
            &[(0, 150), (100, 150), (50, 250)],
            &[(0, 100), (0, 100), (100, 200), (100, 200)],
        ];
        for order in orders {
            let mut r = Reassembler::new(0);
            for &(off, len) in order {
                assert_eq!(
                    push(&mut r, &frag(HT_SERVER_HELLO, 0, &b, off, len)),
                    Ok(FragmentOutcome::Buffered)
                );
            }
            let msg = r.pop().unwrap();
            assert_eq!(msg.body, b);
            assert_eq!(
                (msg.msg_type, msg.message_seq, msg.epoch),
                (HT_SERVER_HELLO, 0, 0)
            );
            assert_eq!(r.next_seq(), 1);
            assert_eq!(r.buffered_bytes(), 0);
            assert!(r.pop().is_none());
        }
    }

    /// SEC-010: a message the caller refuses does not use up its
    /// `message_seq`; the slot is free for the genuine one.
    #[test]
    fn take_next_empties_the_slot_without_advancing() {
        let mut r = Reassembler::new(0);
        push(&mut r, &frag(HT_SERVER_HELLO_DONE, 0, &[], 0, 0)).unwrap();
        let refused = r.take_next().unwrap();
        assert_eq!(
            (refused.msg_type, refused.message_seq),
            (HT_SERVER_HELLO_DONE, 0)
        );
        assert_eq!((r.next_seq(), r.buffered_bytes()), (0, 0));
        assert!(r.take_next().is_none());

        let b = body(40);
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, 0, &b, 0, 40)),
            Ok(FragmentOutcome::Buffered)
        );
        let accepted = r.take_next().unwrap();
        assert_eq!(accepted.body, b);
        r.advance();
        assert_eq!(r.next_seq(), 1);
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, 0, &b, 0, 40)),
            Ok(FragmentOutcome::Retransmission)
        );
    }

    #[test]
    fn interleaved_messages_are_delivered_in_sequence_order() {
        let (a, b) = (body(40), body(60));
        let mut r = Reassembler::new(0);
        push(&mut r, &frag(HT_SERVER_HELLO, 1, &b, 30, 30)).unwrap();
        push(&mut r, &frag(HT_SERVER_HELLO, 0, &a, 0, 20)).unwrap();
        push(&mut r, &frag(HT_SERVER_HELLO, 1, &b, 0, 30)).unwrap();
        assert!(r.pop().is_none());
        push(&mut r, &frag(HT_SERVER_HELLO, 0, &a, 20, 20)).unwrap();
        assert_eq!(r.pop().unwrap().body, a);
        assert_eq!(r.pop().unwrap().body, b);
        assert!(r.pop().is_none());
    }

    #[test]
    fn empty_message_and_old_sequence() {
        let mut r = Reassembler::new(3);
        let done = frag(HT_SERVER_HELLO_DONE, 3, &[], 0, 0);
        assert_eq!(push(&mut r, &done), Ok(FragmentOutcome::Buffered));
        assert_eq!(r.pop().unwrap().body, Vec::<u8>::new());
        assert_eq!(push(&mut r, &done), Ok(FragmentOutcome::Retransmission));
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, 0, &body(5), 0, 5)),
            Ok(FragmentOutcome::Retransmission)
        );
    }

    #[test]
    fn length_caps() {
        let mut r = Reassembler::new(0);
        let big = body(MAX_MESSAGE_LEN + 1);
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, 0, &big, 0, 10)),
            Err(ReassemblyViolation::MessageTooLong)
        );
        assert_eq!(
            push(&mut r, &frag(HT_CERTIFICATE, 0, &big, 0, 10)),
            Ok(FragmentOutcome::Buffered)
        );
        let huge = body(MAX_CERTIFICATE_MESSAGE_LEN + 1);
        assert_eq!(
            push(&mut r, &frag(HT_CERTIFICATE, 1, &huge, 0, 10)),
            Err(ReassemblyViolation::MessageTooLong)
        );
        // 24-bit maximum length in the header allocates nothing.
        let header = HandshakeHeader {
            msg_type: HT_CERTIFICATE,
            length: 0x00FF_FFFF,
            message_seq: 1,
            fragment_offset: 0,
            fragment_length: 1,
        };
        assert_eq!(
            r.push(&header, &[0], 0),
            Err(ReassemblyViolation::MessageTooLong)
        );
        assert_eq!(r.buffered_bytes(), MAX_MESSAGE_LEN + 1);
    }

    #[test]
    fn fragment_bounds_and_consistency() {
        let mut r = Reassembler::new(0);
        let b = body(100);
        let mut beyond = frag(HT_SERVER_HELLO, 0, &b, 90, 10);
        beyond.0.fragment_length = 11;
        beyond.1.push(0);
        assert_eq!(
            push(&mut r, &beyond),
            Err(ReassemblyViolation::FragmentOutOfBounds)
        );
        let mut short_body = frag(HT_SERVER_HELLO, 0, &b, 0, 10);
        short_body.1.pop();
        assert_eq!(
            push(&mut r, &short_body),
            Err(ReassemblyViolation::FragmentOutOfBounds)
        );
        let mut overflow = frag(HT_SERVER_HELLO, 0, &b, 0, 10);
        overflow.0.fragment_offset = 0x00FF_FFFF;
        assert_eq!(
            push(&mut r, &overflow),
            Err(ReassemblyViolation::FragmentOutOfBounds)
        );

        // Nothing above stored anything.
        assert_eq!(r.buffered_bytes(), 0);
    }

    /// A fragment that disagrees with its slot about length or type starts
    /// the slot again: nothing of the older message survives in the result.
    #[test]
    fn conflicting_fragment_replaces_the_slot_and_never_merges() {
        let forged = vec![0xEE; 100];
        let genuine = body(90);
        for forged_type in [HT_SERVER_HELLO, HT_FINISHED] {
            let mut r = Reassembler::new(0);
            // Forged: bytes 0..60 of a 100-byte message.
            push(&mut r, &frag(forged_type, 0, &forged, 0, 60)).unwrap();
            assert_eq!(r.buffered_bytes(), 100);
            // Genuine: the tail first, so a merge would complete the message
            // with forged bytes in front.
            assert_eq!(
                push(&mut r, &frag(HT_SERVER_HELLO, 0, &genuine, 60, 30)),
                Ok(FragmentOutcome::Buffered)
            );
            assert_eq!(r.buffered_bytes(), 90);
            assert!(r.pop().is_none(), "forged ranges survived the reset");
            push(&mut r, &frag(HT_SERVER_HELLO, 0, &genuine, 0, 60)).unwrap();
            let message = r.pop().unwrap();
            assert_eq!(message.msg_type, HT_SERVER_HELLO);
            assert_eq!(message.body, genuine);
            assert_eq!(r.buffered_bytes(), 0);
        }

        // A complete forged message waiting for its turn is replaced too.
        let mut r = Reassembler::new(0);
        push(&mut r, &frag(HT_SERVER_HELLO_DONE, 1, &[], 0, 0)).unwrap();
        push(&mut r, &frag(HT_SERVER_HELLO, 1, &genuine, 0, 90)).unwrap();
        push(&mut r, &frag(HT_SERVER_HELLO, 0, &genuine, 0, 90)).unwrap();
        assert_eq!(r.pop().unwrap().message_seq, 0);
        let message = r.pop().unwrap();
        assert_eq!(
            (message.msg_type, &message.body),
            (HT_SERVER_HELLO, &genuine)
        );
    }

    /// Forged announcements of large later messages cannot keep the next
    /// expected message (or any earlier one) out: later ones are evicted.
    #[test]
    fn lower_sequence_numbers_evict_higher_ones_for_memory() {
        let cert = body(MAX_CERTIFICATE_MESSAGE_LEN);
        let mut r = Reassembler::new(0);
        push(&mut r, &frag(HT_CERTIFICATE, 1, &cert, 0, 0)).unwrap();
        push(&mut r, &frag(HT_CERTIFICATE, 2, &cert, 0, 0)).unwrap();
        assert_eq!(r.buffered_bytes(), MAX_BUFFERED_BYTES);
        // A later message does not fit and evicts nothing.
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, 3, &body(10), 0, 10)),
            Err(ReassemblyViolation::BufferLimit)
        );
        assert_eq!(r.buffered_bytes(), MAX_BUFFERED_BYTES);
        // The next expected message always fits: seq 2 goes, seq 1 stays.
        let hello = body(100);
        push(&mut r, &frag(HT_SERVER_HELLO, 0, &hello, 0, 100)).unwrap();
        assert_eq!(r.buffered_bytes(), MAX_CERTIFICATE_MESSAGE_LEN + 100);
        assert_eq!(r.pop().unwrap().body, hello);
        // The genuine seq 1 (another length) replaces the forged slot, and a
        // maximum-size genuine message at seq 1 fits as well.
        push(&mut r, &frag(HT_CERTIFICATE, 2, &cert, 0, 0)).unwrap();
        push(&mut r, &frag(HT_CERTIFICATE, 1, &body(8000), 0, 8000)).unwrap();
        assert_eq!(r.pop().unwrap().body, body(8000));
        assert!(r.buffered_bytes() <= MAX_BUFFERED_BYTES);

        // Replacing a slot with a longer message that cannot fit changes
        // nothing.
        let mut r = Reassembler::new(0);
        push(&mut r, &frag(HT_CERTIFICATE, 0, &cert, 0, 1)).unwrap();
        push(&mut r, &frag(HT_CERTIFICATE, 1, &body(6192), 0, 1)).unwrap();
        push(&mut r, &frag(HT_SERVER_HELLO, 2, &body(2000), 0, 2000)).unwrap();
        let held = r.buffered_bytes();
        assert_eq!(
            push(&mut r, &frag(HT_CERTIFICATE, 2, &cert, 0, 1)),
            Err(ReassemblyViolation::BufferLimit)
        );
        assert_eq!(r.buffered_bytes(), held);
    }

    /// The `Finished` slot: a forged plaintext message cannot pin it to
    /// epoch 0, and a plaintext fragment cannot get into an epoch-1 message.
    #[test]
    fn higher_epoch_replaces_lower_and_lower_never_enters_higher() {
        let forged = vec![0xEE; 12];
        let genuine = body(12);
        // Forged complete epoch-0 "Finished", then the genuine one in epoch 1.
        let mut r = Reassembler::new(7);
        let f = frag(HT_FINISHED, 7, &forged, 0, 12);
        assert_eq!(r.push(&f.0, &f.1, 0), Ok(FragmentOutcome::Buffered));
        let g = frag(HT_FINISHED, 7, &genuine, 0, 6);
        assert_eq!(r.push(&g.0, &g.1, 1), Ok(FragmentOutcome::Buffered));
        assert!(
            r.pop().is_none(),
            "forged bytes completed an epoch-1 message"
        );
        // Plaintext fragments for the rest are refused.
        let rest = frag(HT_FINISHED, 7, &forged, 6, 6);
        assert_eq!(r.push(&rest.0, &rest.1, 0), Ok(FragmentOutcome::Rejected));
        assert_eq!(r.push(&f.0, &f.1, 0), Ok(FragmentOutcome::Rejected));
        assert!(r.pop().is_none());
        let g = frag(HT_FINISHED, 7, &genuine, 6, 6);
        assert_eq!(r.push(&g.0, &g.1, 1), Ok(FragmentOutcome::Buffered));
        let message = r.pop().unwrap();
        assert_eq!((message.epoch, &message.body), (1, &genuine));
    }

    #[test]
    fn discard_below_epoch_drops_only_the_old_epoch() {
        let b = body(12);
        let mut r = Reassembler::new(3);
        let old = frag(HT_FINISHED, 3, &b, 0, 12);
        let other = frag(HT_SERVER_HELLO, 5, &body(50), 0, 10);
        let new = frag(HT_FINISHED, 4, &b, 0, 12);
        r.push(&old.0, &old.1, 0).unwrap();
        r.push(&other.0, &other.1, 0).unwrap();
        r.push(&new.0, &new.1, 1).unwrap();
        assert_eq!(r.discard_below_epoch(1), 2);
        assert_eq!(r.buffered_bytes(), 12);
        assert!(r.pop().is_none());
        assert_eq!(r.next_seq(), 3);
        assert_eq!(r.discard_below_epoch(1), 0);
    }

    #[test]
    fn window_and_memory_caps() {
        let mut r = Reassembler::new(0);
        let b = body(10);
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, FUTURE_WINDOW, &b, 0, 5)),
            Ok(FragmentOutcome::Buffered)
        );
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, FUTURE_WINDOW + 1, &b, 0, 5)),
            Err(ReassemblyViolation::TooFarAhead)
        );
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, u16::MAX, &b, 0, 5)),
            Err(ReassemblyViolation::TooFarAhead)
        );

        let mut r = Reassembler::new(0);
        let cert = body(MAX_CERTIFICATE_MESSAGE_LEN);
        push(&mut r, &frag(HT_CERTIFICATE, 0, &cert, 0, 1)).unwrap();
        push(&mut r, &frag(HT_CERTIFICATE, 1, &cert, 0, 1)).unwrap();
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, 2, &b, 0, 1)),
            Err(ReassemblyViolation::BufferLimit)
        );
        assert!(r.buffered_bytes() <= MAX_BUFFERED_BYTES);
    }

    #[test]
    fn scattered_ranges_and_mixed_epochs_are_rejected_not_fatal() {
        let mut r = Reassembler::new(0);
        let b = body(200);
        for i in 0..MAX_RANGES {
            assert_eq!(
                push(&mut r, &frag(HT_SERVER_HELLO, 0, &b, i * 4, 1)),
                Ok(FragmentOutcome::Buffered)
            );
        }
        assert_eq!(
            push(&mut r, &frag(HT_SERVER_HELLO, 0, &b, 190, 1)),
            Ok(FragmentOutcome::Rejected)
        );
        // Filling everything still completes the message.
        push(&mut r, &frag(HT_SERVER_HELLO, 0, &b, 0, 200)).unwrap();
        assert_eq!(r.pop().unwrap().body, b);

        let f = frag(HT_FINISHED, 1, &b, 0, 100);
        assert_eq!(r.push(&f.0, &f.1, 0), Ok(FragmentOutcome::Buffered));
        let g = frag(HT_FINISHED, 1, &b, 100, 100);
        let mut high = Reassembler::new(1);
        assert_eq!(high.push(&g.0, &g.1, 1), Ok(FragmentOutcome::Buffered));
        assert_eq!(high.push(&f.0, &f.1, 0), Ok(FragmentOutcome::Rejected));
        assert!(high.pop().is_none());
    }
}
