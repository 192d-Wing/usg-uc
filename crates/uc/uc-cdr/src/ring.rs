//! Bounded in-memory ring of recent CDRs for the management API.
//!
//! Written by the writer thread, read by API handlers. Readers clone `Arc`s
//! out under a short lock, filter after releasing it, and never hold it
//! across an `.await`. Not durable:
//! the file sink is the record of truth.
//!
//! ## NIST 800-53 Rev5: AU-6 (Audit Record Review), SC-5 (bounded state)

use crate::record::CdrStream;
use crate::record::{CallRecord, Disposition};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

/// Default page size for [`CdrRing::query`].
pub const DEFAULT_PAGE_SIZE: usize = 100;

/// Largest page [`CdrRing::query`] returns.
pub const MAX_PAGE_SIZE: usize = 500;

/// Largest accepted ring capacity.
pub const MAX_RING_CAPACITY: usize = 200_000;

/// Query filter. Empty/`None` fields match everything.
#[derive(Debug, Clone, Default)]
pub struct CdrFilter {
    /// Inclusive lower bound on `setup_ms`.
    pub start_ms: Option<u64>,
    /// Exclusive upper bound on `setup_ms`.
    pub end_ms: Option<u64>,
    /// Exact `caller` (as stored, after PII policy).
    pub caller: Option<String>,
    /// Exact `callee_dialed` or `callee_translated`.
    pub callee: Option<String>,
    /// Disposition.
    pub disposition: Option<Disposition>,
    /// `final_trunk` or any `trunks_tried` entry.
    pub trunk: Option<String>,
}

impl CdrFilter {
    /// Whether `r` matches.
    pub fn matches(&self, r: &CallRecord) -> bool {
        if self.start_ms.is_some_and(|s| r.setup_ms < s) {
            return false;
        }
        if self.end_ms.is_some_and(|e| r.setup_ms >= e) {
            return false;
        }
        if self.caller.as_ref().is_some_and(|c| &r.caller != c) {
            return false;
        }
        if let Some(c) = &self.callee
            && &r.callee_dialed != c
            && r.callee_translated.as_ref() != Some(c)
        {
            return false;
        }
        if self.disposition.is_some_and(|d| r.disposition != d) {
            return false;
        }
        if let Some(t) = &self.trunk
            && r.final_trunk.as_ref() != Some(t)
            && !r.trunks_tried.iter().any(|a| &a.trunk_id == t)
        {
            return false;
        }
        true
    }
}

/// One page of query results, newest first.
#[derive(Debug, Clone, Default)]
pub struct CdrPage {
    /// Matching records.
    pub records: Vec<Arc<CallRecord>>,
    /// Token for the next page (`None` when exhausted). Opaque decimal: the
    /// ring position of the last record returned. It is not the record
    /// `sequence`, which is per stream (calls and attempts interleave).
    pub next_page_token: Option<String>,
    /// Records currently held.
    pub total_in_ring: usize,
}

/// Ring contents: records in arrival order, each with its ring position.
type Entry = (u64, Arc<CallRecord>);

/// Ring contents in arrival order, each record with its ring position.
/// Attempts-stream records are held apart, in at most a quarter of the
/// ring, and are evicted first, so a flood of unanswered attempts cannot
/// push answered calls out of the API view (SC-5).
#[derive(Debug, Default)]
struct Slots {
    calls: VecDeque<Entry>,
    attempts: VecDeque<Entry>,
    /// Position of the next pushed record (monotonic per ring).
    next: u64,
}

impl Slots {
    fn len(&self) -> usize {
        self.calls.len() + self.attempts.len()
    }
}

/// Bounded ring; the oldest record is evicted when full, attempts-stream
/// records first.
#[derive(Debug)]
pub struct CdrRing {
    capacity: usize,
    /// Most attempts-stream records held (a quarter of `capacity`).
    attempts_capacity: usize,
    inner: Mutex<Slots>,
}

impl CdrRing {
    /// Creates a ring of `capacity` records (0 disables it), capped at
    /// [`MAX_RING_CAPACITY`]; attempts-stream records use at most a quarter.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.min(MAX_RING_CAPACITY);
        Self {
            capacity,
            attempts_capacity: capacity / 4,
            inner: Mutex::new(Slots {
                calls: VecDeque::with_capacity(capacity.min(4096)),
                attempts: VecDeque::new(),
                next: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Slots> {
        // A poisoned ring only holds finished records: keep serving them.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Configured capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Records held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().len() == 0
    }

    /// Appends a record. Attempts records beyond their share evict the
    /// oldest attempt; a full ring evicts the oldest attempt first, then
    /// the oldest call.
    pub fn push(&self, record: Arc<CallRecord>) {
        if self.capacity == 0 {
            return;
        }
        let attempt = record.stream == CdrStream::Attempts;
        let mut s = self.lock();
        if attempt {
            if self.attempts_capacity == 0 {
                return;
            }
            while s.attempts.len() >= self.attempts_capacity {
                s.attempts.pop_front();
            }
        }
        while s.len() >= self.capacity {
            if s.attempts.pop_front().is_none() {
                s.calls.pop_front();
            }
        }
        let pos = s.next;
        s.next = s.next.wrapping_add(1);
        if attempt {
            s.attempts.push_back((pos, record));
        } else {
            s.calls.push_back((pos, record));
        }
    }

    /// Index of the first record at ring position `>= pos` (positions are
    /// strictly increasing in each deque).
    fn lower_bound(q: &VecDeque<Entry>, pos: u64) -> usize {
        q.partition_point(|(p, _)| *p < pos)
    }

    /// Binary search of one stream's deque by sequence (monotonic within a
    /// stream). A miss is final: no scan under the ring lock.
    fn find(q: &VecDeque<Entry>, seq: u64, record_id: &str) -> Option<Arc<CallRecord>> {
        let i = q.partition_point(|(_, r)| r.sequence < seq);
        q.get(i)
            .filter(|(_, r)| r.record_id == record_id)
            .map(|(_, r)| Arc::clone(r))
    }

    /// Finds a record by `record_id`: `{node}-{seq}` in the calls deque,
    /// `{node}-a{seq}` in the attempts deque, O(log n) under the lock. Any
    /// other form, or a miss, is `None` (the writer produces only these).
    /// After an unclean resume restarted a stream's sequence, older records
    /// of that stream may not be found until they leave the ring.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (bounded work per lookup)
    pub fn get(&self, record_id: &str) -> Option<Arc<CallRecord>> {
        let (_, tail) = record_id.rsplit_once('-')?;
        let digits = |t: &str| {
            (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
                .then(|| t.parse::<u64>().ok())
                .flatten()
        };
        let s = self.lock();
        match tail.strip_prefix('a') {
            Some(t) => Self::find(&s.attempts, digits(t)?, record_id),
            None => Self::find(&s.calls, digits(tail)?, record_id),
        }
    }

    /// Returns matching records newest first. `page_token` is the token from
    /// a previous page; an unparsable token yields an empty page.
    ///
    /// The lock is held only to locate the cursor (binary search) and copy
    /// the candidate `Arc` pointers; filtering runs after it is released,
    /// so the writer's `push` is never held up by a selective query. Up to
    /// [`MAX_RING_CAPACITY`] pointer copies: call it off async workers
    /// (`spawn_blocking`) for large rings.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
    pub fn query(&self, filter: &CdrFilter, page_token: Option<&str>, page_size: usize) -> CdrPage {
        let page_size = match page_size {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        let before = match page_token.filter(|t| !t.is_empty()) {
            None => None,
            Some(t) => match t.parse::<u64>() {
                Ok(s) => Some(s),
                Err(_) => {
                    return CdrPage {
                        total_in_ring: self.len(),
                        ..CdrPage::default()
                    };
                }
            },
        };
        let (candidates, total_in_ring) = {
            let s = self.lock();
            let range = |q: &VecDeque<Entry>| {
                let end = before.map_or(q.len(), |b| Self::lower_bound(q, b));
                q.range(..end).cloned().collect::<Vec<Entry>>()
            };
            let (c, a) = (range(&s.calls), range(&s.attempts));
            let total = s.len();
            drop(s);
            // Merge both streams by ring position (each is ascending).
            let mut merged = Vec::with_capacity(c.len() + a.len());
            let (mut ci, mut ai) = (c.into_iter().peekable(), a.into_iter().peekable());
            loop {
                let take_c = match (ci.peek(), ai.peek()) {
                    (Some((pc, _)), Some((pa, _))) => pc < pa,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => break,
                };
                merged.extend(if take_c { ci.next() } else { ai.next() });
            }
            (merged, total)
        };
        let mut records = Vec::with_capacity(page_size.min(candidates.len()));
        let mut last_pos = None;
        let mut more = false;
        for (pos, r) in candidates.iter().rev() {
            if !filter.matches(r) {
                continue;
            }
            if records.len() == page_size {
                more = true;
                break;
            }
            records.push(Arc::clone(r));
            last_pos = Some(*pos);
        }
        let next_page_token = if more {
            last_pos.map(|p| p.to_string())
        } else {
            None
        };
        CdrPage {
            records,
            next_page_token,
            total_in_ring,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64, d: Disposition) -> Arc<CallRecord> {
        Arc::new(CallRecord {
            sequence: seq,
            record_id: format!("n-{seq}"),
            setup_ms: seq * 10,
            disposition: d,
            ..Default::default()
        })
    }

    #[test]
    fn evicts_oldest() {
        let ring = CdrRing::new(3);
        for i in 0..5 {
            ring.push(rec(i, Disposition::Answered));
        }
        assert_eq!(ring.len(), 3);
        assert!(ring.get("n-1").is_none());
        assert!(ring.get("n-4").is_some());
    }

    #[test]
    fn zero_capacity_disabled() {
        let ring = CdrRing::new(0);
        ring.push(rec(0, Disposition::Answered));
        assert!(ring.is_empty());
    }

    #[test]
    fn paging_and_filter() {
        let ring = CdrRing::new(100);
        for i in 0..10 {
            let d = if i % 2 == 0 {
                Disposition::Answered
            } else {
                Disposition::Failed
            };
            ring.push(rec(i, d));
        }
        let f = CdrFilter {
            disposition: Some(Disposition::Answered),
            ..Default::default()
        };
        let p1 = ring.query(&f, None, 2);
        let seqs: Vec<u64> = p1.records.iter().map(|r| r.sequence).collect();
        assert_eq!(seqs, vec![8, 6]);
        let p2 = ring.query(&f, p1.next_page_token.as_deref(), 2);
        let seqs: Vec<u64> = p2.records.iter().map(|r| r.sequence).collect();
        assert_eq!(seqs, vec![4, 2]);
        let p3 = ring.query(&f, p2.next_page_token.as_deref(), 2);
        assert_eq!(p3.records.len(), 1);
        assert!(p3.next_page_token.is_none());
        assert_eq!(ring.query(&f, Some("bogus"), 2).records.len(), 0);

        let t = CdrFilter {
            start_ms: Some(20),
            end_ms: Some(40),
            ..Default::default()
        };
        assert_eq!(ring.query(&t, None, 0).records.len(), 2);
    }

    /// SR-43: calls and attempts records interleave with overlapping
    /// sequences; paging still returns each record once, newest first, and
    /// `get` finds both id forms.
    #[test]
    fn paging_over_interleaved_streams() {
        let ring = CdrRing::new(100);
        for i in 0..6 {
            ring.push(rec(i, Disposition::Answered));
            ring.push(Arc::new(CallRecord {
                sequence: i,
                record_id: format!("n-a{i}"),
                disposition: Disposition::Rejected,
                stream: CdrStream::Attempts,
                ..Default::default()
            }));
        }
        let all = CdrFilter::default();
        let mut seen = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let p = ring.query(&all, token.as_deref(), 5);
            seen.extend(p.records.iter().map(|r| r.record_id.clone()));
            match p.next_page_token {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        assert_eq!(seen.len(), 12, "{seen:?}");
        assert_eq!(seen[0], "n-a5");
        assert_eq!(seen[1], "n-5");
        let mut dedup = seen.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), 12);
        assert_eq!(ring.get("n-a3").unwrap().sequence, 3);
        assert_eq!(ring.get("n-3").unwrap().record_id, "n-3");
    }

    /// SR-43 round 1 (SEC-010): a flood of attempts records keeps at most a
    /// quarter of the ring and never evicts answered calls.
    #[test]
    fn attempts_flood_does_not_evict_calls() {
        let ring = CdrRing::new(100);
        for i in 0..50 {
            ring.push(rec(i, Disposition::Answered));
        }
        for i in 0..10_000 {
            ring.push(Arc::new(CallRecord {
                sequence: i,
                record_id: format!("n-a{i}"),
                stream: CdrStream::Attempts,
                ..Default::default()
            }));
        }
        assert_eq!(ring.len(), 75);
        for i in 0..50 {
            assert!(ring.get(&format!("n-{i}")).is_some(), "call {i} evicted");
        }
        assert!(ring.get("n-a9999").is_some());
        assert!(ring.get("n-a9974").is_none());
        // A full ring evicts attempts before calls.
        for i in 50..200 {
            ring.push(rec(i, Disposition::Answered));
        }
        assert_eq!(ring.len(), 100);
        assert!(ring.get("n-a9999").is_none());
        assert!(ring.get("n-199").is_some());
    }

    /// SEC-015 (round 2): a lookup is one binary search in its stream; a
    /// malformed id or a miss returns `None` without scanning.
    #[test]
    fn get_is_stream_local_and_final() {
        let ring = CdrRing::new(100);
        for i in 0..10 {
            ring.push(rec(i, Disposition::Answered));
        }
        assert!(ring.get("n-4").is_some());
        assert!(ring.get("n-a4").is_none(), "no cross-stream fallback");
        for bad in ["", "n", "n-", "n-x4", "n-4x", "n-a", "-"] {
            assert!(ring.get(bad).is_none(), "{bad}");
        }
        assert!(ring.get("n-99").is_none());
    }
}
