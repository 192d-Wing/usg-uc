//! Bounded, wait-free hand-off of DTLS datagrams from the audio I/O thread
//! to the DTLS driver task.
//!
//! After the handshake the audio I/O thread is the only reader of the media
//! socket (RFC 5764 §5.1.2). DTLS records that still arrive there (a
//! retransmitted final flight, an alert, `close_notify`) are copied into a
//! single-producer single-consumer byte ring as frames `len:u16 | bytes`;
//! the driver pops whole frames and feeds its association.
//!
//! The producer side ([`DtlsForwardTx::try_forward`]) runs on the audio
//! thread: it never allocates and never waits for the consumer. Its one
//! cost beyond the copy is waking the driver task, which can take two
//! short mutexes and one system call (see `try_forward`); the receiver's
//! rate limit bounds that to 4 per second after a burst of 8, and it never
//! happens for an RTP or RTCP packet. When the ring is full the datagram
//! is refused and the DTLS peer's retransmission recovers.
//!
//! ## NIST 800-53 Rev5
//! - **SC-5**: the ring is allocated once ([`RING_CAPACITY`] bytes per
//!   call) and never grows; a datagram that does not fit whole is refused.
//! - **SI-10**: frame lengths are checked on both sides; a frame is never
//!   delivered torn.

use ringbuf::traits::{Consumer, Observer, Producer, Split};
use ringbuf::{HeapCons, HeapProd, HeapRb};
use std::sync::Arc;
use tokio::sync::Notify;

/// Size of the ring in bytes. Holds five full-size datagrams; a peer sends
/// one or two per retransmission interval.
pub const RING_CAPACITY: usize = 8 * 1024;
/// Largest datagram accepted, in bytes (the association's largest MTU).
pub const MAX_FORWARD_DATAGRAM: usize = 1500;
/// Bytes of the length prefix of a frame.
const FRAME_HEADER: usize = 2;

/// Creates the ring: the producer half for the audio I/O thread, the
/// consumer half for the DTLS driver.
#[must_use]
pub fn dtls_forward_channel() -> (DtlsForwardTx, DtlsForwardRx) {
    let (producer, consumer) = HeapRb::<u8>::new(RING_CAPACITY).split();
    let notify = Arc::new(Notify::new());
    (
        DtlsForwardTx {
            producer,
            notify: Arc::clone(&notify),
        },
        DtlsForwardRx { consumer, notify },
    )
}

/// Producer half, owned by the audio I/O thread.
pub struct DtlsForwardTx {
    producer: HeapProd<u8>,
    notify: Arc<Notify>,
}

impl std::fmt::Debug for DtlsForwardTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsForwardTx")
            .field("vacant", &self.producer.vacant_len())
            .finish_non_exhaustive()
    }
}

impl DtlsForwardTx {
    /// Queues one datagram for the driver. All or nothing: returns `false`
    /// and queues nothing when the datagram is empty, larger than
    /// [`MAX_FORWARD_DATAGRAM`] or does not fit in the free space.
    ///
    /// The copy into the ring is wait-free and allocates nothing. The
    /// wake-up is not free: `Notify::notify_one` is one compare-and-swap
    /// while the driver is not parked on it, but when it is (the usual
    /// case) tokio takes the `Notify`'s waiter-list mutex and then, to
    /// schedule the driver task from this non-runtime thread, the
    /// runtime's injection-queue mutex, and may unpark a worker thread,
    /// which is a system call. Both mutexes are held for a few
    /// instructions by their other users. This is paid only for a datagram
    /// that already passed the receiver's source check and rate limit: at
    /// most 4 times per second after a burst of 8, never per RTP packet.
    pub fn try_forward(&mut self, datagram: &[u8]) -> bool {
        let Ok(len) = u16::try_from(datagram.len()) else {
            return false;
        };
        if datagram.is_empty() || datagram.len() > MAX_FORWARD_DATAGRAM {
            return false;
        }
        // NIST 800-53 Rev5: SC-5 -- bounded queue, drop on full.
        if self.producer.vacant_len() < FRAME_HEADER + datagram.len() {
            return false;
        }
        // This is the only producer, so the free space checked above cannot
        // shrink before these two writes.
        let header = self.producer.push_slice(&len.to_be_bytes());
        let body = self.producer.push_slice(datagram);
        self.notify.notify_one();
        header == FRAME_HEADER && body == datagram.len()
    }
}

/// Consumer half, owned by the DTLS driver task.
pub struct DtlsForwardRx {
    consumer: HeapCons<u8>,
    notify: Arc<Notify>,
}

impl std::fmt::Debug for DtlsForwardRx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsForwardRx")
            .field("occupied", &self.consumer.occupied_len())
            .finish_non_exhaustive()
    }
}

impl DtlsForwardRx {
    /// The wake-up the producer signals after each queued datagram. Wait
    /// on it with `Notify::notified`; a signal that came while nobody
    /// waited is kept, so none is lost.
    ///
    /// Handed out separately because the consumer half itself cannot be
    /// borrowed across an `await` in a spawned task (it is `Send`, not
    /// `Sync`).
    #[must_use]
    pub fn wakeup(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// Pops the next whole datagram into `buf` and returns its length.
    ///
    /// Returns `None` when no complete frame is queued. A frame whose
    /// length field is impossible (zero, over the maximum or larger than
    /// `buf`) cannot come from [`DtlsForwardTx`]; the ring is then emptied
    /// so the stream cannot stay out of step.
    pub fn pop(&mut self, buf: &mut [u8]) -> Option<usize> {
        let mut header = [0u8; FRAME_HEADER];
        if self.consumer.peek_slice(&mut header) < FRAME_HEADER {
            return None;
        }
        let len = usize::from(u16::from_be_bytes(header));
        if len == 0 || len > MAX_FORWARD_DATAGRAM || len > buf.len() {
            self.consumer.clear();
            return None;
        }
        // The producer writes the length and the body in two steps: wait
        // for the body rather than deliver a torn frame.
        if self.consumer.occupied_len() < FRAME_HEADER + len {
            return None;
        }
        self.consumer.skip(FRAME_HEADER);
        let target = buf.get_mut(..len)?;
        (self.consumer.pop_slice(target) == len).then_some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_in_order() {
        let (mut tx, mut rx) = dtls_forward_channel();
        let mut buf = [0u8; MAX_FORWARD_DATAGRAM];
        assert_eq!(rx.pop(&mut buf), None);
        assert!(tx.try_forward(&[22, 1, 2, 3]));
        assert!(tx.try_forward(&[21; 1500]));
        assert!(tx.try_forward(&[23]));
        assert_eq!(rx.pop(&mut buf), Some(4));
        assert_eq!(&buf[..4], &[22, 1, 2, 3]);
        assert_eq!(rx.pop(&mut buf), Some(1500));
        assert!(buf.iter().all(|b| *b == 21));
        assert_eq!(rx.pop(&mut buf), Some(1));
        assert_eq!(buf[0], 23);
        assert_eq!(rx.pop(&mut buf), None);
    }

    #[test]
    fn empty_and_oversize_datagrams_are_refused() {
        let (mut tx, mut rx) = dtls_forward_channel();
        assert!(!tx.try_forward(&[]));
        assert!(!tx.try_forward(&[0; MAX_FORWARD_DATAGRAM + 1]));
        assert!(!tx.try_forward(&vec![0; 70_000]));
        assert_eq!(rx.pop(&mut [0u8; MAX_FORWARD_DATAGRAM]), None);
    }

    /// A full ring refuses the datagram whole: no partial frame is left
    /// behind, and the frames already queued come out intact.
    #[test]
    fn full_ring_refuses_whole_frame() {
        let (mut tx, mut rx) = dtls_forward_channel();
        let mut marks = 0u8;
        while tx.try_forward(&[marks + 1; 1500]) {
            marks += 1;
        }
        let queued = usize::from(marks);
        assert_eq!(queued, RING_CAPACITY / (1500 + FRAME_HEADER));
        // Still refused, however often it is tried.
        assert!(!tx.try_forward(&[0xEE; 1500]));
        // A smaller one that fits the remainder is taken.
        let spare = RING_CAPACITY - queued * (1500 + FRAME_HEADER);
        assert!(spare > FRAME_HEADER + 10);
        assert!(tx.try_forward(&[0x77; 10]));

        let mut buf = [0u8; MAX_FORWARD_DATAGRAM];
        for mark in 1..=marks {
            assert_eq!(rx.pop(&mut buf), Some(1500));
            assert!(buf.iter().all(|b| *b == mark));
        }
        assert_eq!(rx.pop(&mut buf), Some(10));
        assert_eq!(&buf[..10], &[0x77; 10]);
        assert_eq!(rx.pop(&mut buf), None);
    }

    /// Lengths from 1 to the maximum, pushed until refused and popped in
    /// between, across many wrap-arounds of the ring: every frame comes
    /// out whole and in order.
    #[test]
    fn varied_lengths_never_tear_across_wraparound() {
        let (mut tx, mut rx) = dtls_forward_channel();
        let mut buf = [0u8; MAX_FORWARD_DATAGRAM];
        let mut expected = std::collections::VecDeque::new();
        // Small deterministic generator; no extra test dependency.
        let mut state = 0x9E37_79B9u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for round in 0..4000u32 {
            let len = 1 + (next() as usize % MAX_FORWARD_DATAGRAM);
            let fill = (round % 251) as u8;
            let datagram = vec![fill; len];
            if tx.try_forward(&datagram) {
                expected.push_back((len, fill));
            }
            if next() % 3 != 0 {
                match (rx.pop(&mut buf), expected.pop_front()) {
                    (Some(n), Some((len, fill))) => {
                        assert_eq!(n, len);
                        assert!(buf[..n].iter().all(|b| *b == fill));
                    }
                    (None, None) => {}
                    other => panic!("ring and model disagree: {other:?}"),
                }
            }
        }
        while let Some((len, fill)) = expected.pop_front() {
            assert_eq!(rx.pop(&mut buf), Some(len));
            assert!(buf[..len].iter().all(|b| *b == fill));
        }
        assert_eq!(rx.pop(&mut buf), None);
    }

    /// The consumer does not deliver a frame whose body is not there yet,
    /// and recovers from an impossible length by emptying the ring.
    #[test]
    fn incomplete_or_impossible_frames_are_not_delivered() {
        let (mut tx, mut rx) = dtls_forward_channel();
        let mut buf = [0u8; MAX_FORWARD_DATAGRAM];
        // Header only, as seen between the producer's two writes.
        assert_eq!(tx.producer.push_slice(&5u16.to_be_bytes()), 2);
        assert_eq!(rx.pop(&mut buf), None);
        assert_eq!(tx.producer.push_slice(&[9; 5]), 5);
        assert_eq!(rx.pop(&mut buf), Some(5));

        assert_eq!(tx.producer.push_slice(&0u16.to_be_bytes()), 2);
        assert!(tx.try_forward(&[1, 2, 3]));
        assert_eq!(rx.pop(&mut buf), None);
        assert_eq!(rx.pop(&mut buf), None);
        // In step again afterwards.
        assert!(tx.try_forward(&[4, 5]));
        assert_eq!(rx.pop(&mut buf), Some(2));

        // A buffer smaller than the frame is treated the same way.
        assert!(tx.try_forward(&[7; 100]));
        assert_eq!(rx.pop(&mut [0u8; 50]), None);
        assert_eq!(rx.pop(&mut buf), None);
    }

    #[tokio::test]
    async fn forward_wakes_the_consumer_even_if_it_was_not_waiting() {
        let (mut tx, mut rx) = dtls_forward_channel();
        assert!(tx.try_forward(&[22, 0]));
        let wakeup = rx.wakeup();
        tokio::time::timeout(std::time::Duration::from_secs(1), wakeup.notified())
            .await
            .unwrap();
        assert_eq!(rx.pop(&mut [0u8; 16]), Some(2));

        let waiter = tokio::spawn(async move {
            wakeup.notified().await;
            rx.pop(&mut [0u8; 16])
        });
        tokio::task::yield_now().await;
        let sender = std::thread::spawn(move || tx.try_forward(&[23, 1, 2]));
        assert!(sender.join().unwrap());
        let popped = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(popped, Some(3));
    }
}
