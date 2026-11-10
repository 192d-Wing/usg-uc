//! The SIPREC recording fork must not allocate on the per-packet path.
//!
//! A counting global allocator counts every allocation made by this thread
//! while a flag is set, across 10 000 packets through each tap entry point
//! (seal in place with `protect_rtp_in_place` and a non-blocking send
//! included). The brief's budget is zero.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile, SrtpUnprotect};
use sbc_media_core::recording_fork::{
    ForkControl, ForkStream, ForkTap, recording_fork_dropped, recording_fork_packets,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Allocations (including reallocations) made while `COUNTING` is set on the
/// allocating thread.
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    // Const-initialised and without a destructor, so reading it from inside
    // the allocator cannot itself allocate or recurse.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;

impl CountingAllocator {
    fn note() {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// The workspace denies `unsafe_code`; a `GlobalAlloc` cannot be written
// without it. Test binary only, and every call is forwarded unchanged.
#[allow(unsafe_code)]
// SAFETY: every method forwards its arguments unchanged to `System`, which
// upholds the `GlobalAlloc` contract; the only addition is an atomic counter.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::note();
        // SAFETY: `layout` is the caller's, passed through as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::note();
        // SAFETY: `layout` is the caller's, passed through as is.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        Self::note();
        // SAFETY: `ptr` came from this allocator (which is `System`) with
        // `layout`; the caller guarantees `new_size` is valid.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator (which is `System`) with
        // `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Runs `f` and returns how many allocations this thread made inside it.
fn allocations_in(f: impl FnOnce()) -> u64 {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    COUNTING.with(|c| c.set(true));
    f();
    COUNTING.with(|c| c.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

const PACKETS: usize = 10_000;

struct Rig {
    control: Arc<ForkControl>,
    tap: ForkTap,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    drain: Option<std::thread::JoinHandle<()>>,
    srs_ctx: SrtpContext,
}

impl Rig {
    /// An active fork toward a recorder socket that another thread drains
    /// (so the sends succeed and the drain's allocations are not counted).
    fn new() -> Self {
        // Generated per run from the OS-seeded hasher; never a fixed key.
        let random = |n: usize| -> Vec<u8> {
            use std::hash::{BuildHasher, Hasher};
            (0..n)
                .map(|_| {
                    std::collections::hash_map::RandomState::new()
                        .build_hasher()
                        .finish()
                        .to_le_bytes()[0]
                })
                .collect()
        };
        let (key, salt) = (random(32), random(12));
        let material =
            || SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.clone(), salt.clone()).unwrap();
        let ssrc = 0x0F0F_0002;
        let stream = ForkStream::bind(&material(), "127.0.0.1:0".parse().unwrap(), ssrc).unwrap();
        let srs = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let srs_addr = srs.local_addr().unwrap();
        srs.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let drain = {
            let (received, stop) = (Arc::clone(&received), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut buf = [0u8; 2100];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(n) = srs.recv(&mut buf) {
                        received.lock().unwrap().push(buf[..n].to_vec());
                    }
                }
            })
        };
        let control = ForkControl::new();
        let tap = control.tap();
        control.activate(stream, srs_addr).unwrap();
        Self {
            control,
            tap,
            received,
            stop,
            drain: Some(drain),
            srs_ctx: SrtpContext::new(&material(), SrtpDirection::Inbound, ssrc).unwrap(),
        }
    }

    fn finish(mut self) -> (Vec<Vec<u8>>, SrtpContext) {
        // Let the drain thread empty the socket.
        std::thread::sleep(Duration::from_millis(200));
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.drain.take() {
            handle.join().unwrap();
        }
        let received = std::mem::take(&mut *self.received.lock().unwrap());
        (received, self.srs_ctx)
    }
}

fn rtp_plain(payload: usize) -> Vec<u8> {
    let mut pkt = vec![0x80, 0x00, 0x12, 0x34, 0, 0, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD];
    pkt.resize(12 + payload, 0x5A);
    pkt
}

fn rtp_csrc_ext() -> Vec<u8> {
    // V=2, X=1, CC=2, marker set, PT 8; two CSRCs; one-word extension.
    let mut pkt = vec![0x92, 0x88, 0x00, 0x01, 0, 0, 0, 2, 1, 2, 3, 4];
    pkt.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
    pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01, 0x10, 0x01, 0x00, 0x00]);
    pkt.resize(pkt.len() + 160, 0x33);
    pkt
}

// One test function: the allocator and its counters are process-wide, and a
// single thread keeps the count exact.
#[test]
fn fork_tap_does_not_allocate_per_packet() {
    let plain = rtp_plain(160);
    let big = rtp_plain(1400);
    let rich = rtp_csrc_ext();
    // Inputs the tap must skip or drop without allocating either.
    let rtcp = [0x80u8, 200, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0];
    let stun = [0x00u8, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42];
    let truncated = [0x9Fu8, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0];

    // The counter itself works: an allocation on this thread is seen.
    assert!(allocations_in(|| drop(std::hint::black_box(vec![0u8; 64]))) >= 1);

    // --- cleartext relay entry point ------------------------------------
    let mut rig = Rig::new();
    // Warm-up: the first packet takes the stream from the control slot.
    rig.tap.on_rtp(&plain);
    assert!(rig.tap.is_active());

    let sent_before = recording_fork_packets();
    let dropped_before = recording_fork_dropped();
    let tap = &mut rig.tap;
    let allocations = allocations_in(|| {
        for i in 0..PACKETS {
            match i % 8 {
                0 => tap.on_rtp(&rtcp),
                1 => tap.on_rtp(&stun),
                2 => tap.on_rtp(&truncated),
                3 => tap.on_rtp(&big),
                4 => tap.on_rtp(&rich),
                _ => tap.on_rtp(&plain),
            }
        }
    });
    let sent = recording_fork_packets() - sent_before;
    let dropped = recording_fork_dropped() - dropped_before;
    assert_eq!(
        allocations, 0,
        "on_rtp allocated {allocations} times over {PACKETS} packets"
    );
    // 5 of every 8 inputs are forkable; each was sent or counted as dropped
    // (a full loopback buffer drops, it never blocks or allocates).
    let forkable = (PACKETS / 8 * 5) as u64;
    let malformed = (PACKETS / 8) as u64;
    assert_eq!(sent + dropped, forkable + malformed);
    assert!(sent > 0, "nothing was actually sent");

    // What arrived is real SRTP under the stream's key.
    let (received, srs_ctx) = rig.finish();
    let unprotect = SrtpUnprotect::new(&srs_ctx);
    let mut opened = 0usize;
    for datagram in &received {
        if unprotect.unprotect_rtp(datagram).is_ok() {
            opened += 1;
        }
    }
    assert_eq!(opened, received.len(), "every forked packet authenticates");
    assert!(opened > 0, "the recorder received nothing");

    // --- DTLS-terminated relay entry point ------------------------------
    let mut rig = Rig::new();
    let payload = [0x77u8; 160];
    rig.tap.on_decrypted_rtp(&plain, &payload);
    let sent_before = recording_fork_packets();
    let tap = &mut rig.tap;
    let allocations = allocations_in(|| {
        for i in 0..PACKETS {
            if i % 4 == 0 {
                tap.on_decrypted_rtp(&rich, &payload);
            } else {
                tap.on_decrypted_rtp(&plain, &payload);
            }
        }
    });
    assert_eq!(
        allocations, 0,
        "on_decrypted_rtp allocated {allocations} times over {PACKETS} packets"
    );
    assert!(recording_fork_packets() - sent_before > 0);

    // --- stopped / idle tap ----------------------------------------------
    rig.control.stop();
    rig.tap.on_rtp(&plain);
    assert!(!rig.tap.is_active());
    let tap = &mut rig.tap;
    let allocations = allocations_in(|| {
        for _ in 0..PACKETS {
            tap.on_rtp(&plain);
        }
    });
    assert_eq!(allocations, 0, "an idle tap allocated");
    drop(rig.finish());
}
