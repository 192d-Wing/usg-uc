//! Bounded in-memory ring of recent CDRs for the management API.
//!
//! Written by the writer thread, read by API handlers. Readers clone `Arc`s
//! out under a short lock, filter after releasing it, and never hold it
//! across an `.await`. Not durable:
//! the file sink is the record of truth.
//!
//! ## NIST 800-53 Rev5: AU-6 (Audit Record Review), SC-5 (bounded state)

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
    /// Token for the next page (`None` when exhausted). It is the decimal
    /// sequence of the last record returned.
    pub next_page_token: Option<String>,
    /// Records currently held.
    pub total_in_ring: usize,
}

/// Bounded ring; the oldest record is evicted when full.
#[derive(Debug)]
pub struct CdrRing {
    capacity: usize,
    inner: Mutex<VecDeque<Arc<CallRecord>>>,
}

impl CdrRing {
    /// Creates a ring of `capacity` records (0 disables it), capped at
    /// [`MAX_RING_CAPACITY`].
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.min(MAX_RING_CAPACITY);
        Self {
            capacity,
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<Arc<CallRecord>>> {
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
        self.lock().is_empty()
    }

    /// Appends a record, evicting the oldest when full.
    pub fn push(&self, record: Arc<CallRecord>) {
        if self.capacity == 0 {
            return;
        }
        let mut q = self.lock();
        while q.len() >= self.capacity {
            q.pop_front();
        }
        q.push_back(record);
    }

    /// Index of the first record with `sequence >= seq` (sequence is
    /// monotonic within one writer run). Falls back to a linear scan if the
    /// ring is not ordered (sequence restarted after an unclean resume).
    fn lower_bound(q: &VecDeque<Arc<CallRecord>>, seq: u64) -> usize {
        let ordered = match (q.front(), q.back()) {
            (Some(f), Some(b)) => f.sequence <= b.sequence,
            _ => true,
        };
        if ordered {
            q.partition_point(|r| r.sequence < seq)
        } else {
            q.iter().position(|r| r.sequence >= seq).unwrap_or(q.len())
        }
    }

    /// Finds a record by `record_id`.
    pub fn get(&self, record_id: &str) -> Option<Arc<CallRecord>> {
        let q = self.lock();
        // Fast path: ids are `{node}-{sequence}`.
        if let Some(seq) = record_id
            .rsplit_once('-')
            .and_then(|(_, s)| s.parse::<u64>().ok())
        {
            let i = Self::lower_bound(&q, seq);
            if let Some(r) = q.get(i).filter(|r| r.record_id == record_id) {
                return Some(Arc::clone(r));
            }
        }
        q.iter().rev().find(|r| r.record_id == record_id).cloned()
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
            let q = self.lock();
            let end = before.map_or(q.len(), |b| Self::lower_bound(&q, b));
            let c: Vec<Arc<CallRecord>> = q.range(..end).cloned().collect();
            (c, q.len())
        };
        let mut records = Vec::with_capacity(page_size.min(candidates.len()));
        let mut more = false;
        for r in candidates.iter().rev() {
            if before.is_some_and(|b| r.sequence >= b) {
                continue;
            }
            if !filter.matches(r) {
                continue;
            }
            if records.len() == page_size {
                more = true;
                break;
            }
            records.push(Arc::clone(r));
        }
        let next_page_token = if more {
            records.last().map(|r| r.sequence.to_string())
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
}
