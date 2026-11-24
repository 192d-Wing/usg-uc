//! Announcement play concurrency caps: a global cap and a per-destination-IP cap.
//!
//! Shared by the `sbc-announcement-server` pod and the daemon's in-process
//! playback. Both caps are taken before the RTP socket is bound and
//! released by an RAII guard on every exit of the playback task
//! (completion, cancel, timeout, panic unwinding). Back-pressure is refusal, never queueing.
//!
//! The per-destination map holds only destinations with a live play, so it
//! is bounded by the global cap. It uses std's keyed `RandomState` hasher
//! (the keys are caller-chosen addresses).
//!
//! ## NIST 800-53 Rev5: SC-5

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Which cap refused a play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitRefusal {
    /// All global slots are in use (`SBC_ANN_MAX_PLAYS` on the pod).
    Global,
    /// This destination IP already has the per-destination maximum of plays.
    PerDestination,
}

impl std::fmt::Display for LimitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Global => "too many concurrent announcements",
            Self::PerDestination => "too many concurrent announcements to this destination",
        })
    }
}

#[derive(Debug)]
struct Inner {
    max: usize,
    per_dest_max: usize,
    global: Arc<Semaphore>,
    per_dest: Mutex<HashMap<IpAddr, usize>>,
}

impl Inner {
    /// The map stays consistent under a panic elsewhere (each critical
    /// section is a single insert/update/remove), so a poisoned lock is
    /// recovered rather than propagated.
    fn map(&self) -> MutexGuard<'_, HashMap<IpAddr, usize>> {
        self.per_dest.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Counts at the moment a play was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitCounts {
    /// Plays in progress.
    pub active: usize,
    /// Plays in progress toward the refused destination.
    pub active_for_destination: usize,
    /// Destinations with a play in progress.
    pub destinations: usize,
}

/// The caps, shared by every Play. Cheap to clone.
#[derive(Debug, Clone)]
pub struct PlayLimits {
    inner: Arc<Inner>,
}

/// One admitted play; releases both caps on drop.
#[derive(Debug)]
pub struct PlayGuard {
    inner: Arc<Inner>,
    ip: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for PlayGuard {
    fn drop(&mut self) {
        let mut map = self.inner.map();
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

impl PlayLimits {
    /// `max` plays in total, `per_dest` per destination IP (both at least 1).
    #[must_use]
    pub fn new(max: usize, per_dest: usize) -> Self {
        let max = max.max(1);
        Self {
            inner: Arc::new(Inner {
                max,
                per_dest_max: per_dest.clamp(1, max),
                global: Arc::new(Semaphore::new(max)),
                per_dest: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Admits one play toward `ip` (canonical form: a v4-mapped address is
    /// the same destination as its IPv4 form), or refuses without waiting.
    ///
    /// # Errors
    /// The cap that is full.
    pub fn try_acquire(&self, ip: IpAddr) -> Result<PlayGuard, LimitRefusal> {
        self.try_acquire_detailed(ip)
            .map_err(|(refusal, _)| refusal)
    }

    /// As [`Self::try_acquire`]; a refusal also carries the counts at the
    /// moment of refusal, read under the same lock (for the log).
    ///
    /// # Errors
    /// The cap that is full, with the counts.
    pub fn try_acquire_detailed(
        &self,
        ip: IpAddr,
    ) -> Result<PlayGuard, (LimitRefusal, LimitCounts)> {
        let ip = ip.to_canonical();
        let permit = Arc::clone(&self.inner.global).try_acquire_owned();
        let mut map = self.inner.map();
        let counts = |map: &HashMap<IpAddr, usize>| LimitCounts {
            active: self.active(),
            active_for_destination: map.get(&ip).copied().unwrap_or(0),
            destinations: map.len(),
        };
        let Ok(permit) = permit else {
            return Err((LimitRefusal::Global, counts(&map)));
        };
        let n = map.get(&ip).copied().unwrap_or(0);
        if n >= self.inner.per_dest_max {
            // The entry exists (n >= 1), so nothing is inserted; the global
            // permit is dropped on return.
            drop(permit);
            return Err((LimitRefusal::PerDestination, counts(&map)));
        }
        map.insert(ip, n + 1);
        drop(map);
        Ok(PlayGuard {
            inner: Arc::clone(&self.inner),
            ip,
            _permit: permit,
        })
    }

    /// Plays in progress.
    #[must_use]
    pub fn active(&self) -> usize {
        self.inner
            .max
            .saturating_sub(self.inner.global.available_permits())
    }

    /// Plays in progress toward `ip`.
    #[must_use]
    pub fn active_for(&self, ip: IpAddr) -> usize {
        self.inner
            .map()
            .get(&ip.to_canonical())
            .copied()
            .unwrap_or(0)
    }

    /// Destinations with a play in progress (map size).
    #[must_use]
    pub fn tracked_destinations(&self) -> usize {
        self.inner.map().len()
    }
}
