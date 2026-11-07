//! # SBC Audit
//!
//! NIST 800-53 Rev5 compliant audit logging for the USG Session Border Controller.
//!
//! ## NIST 800-53 Rev5 Controls Implemented
//!
//! - **AU-2**: Event Logging - defines auditable events
//! - **AU-3**: Content of Audit Records - specifies required fields
//! - **AU-8**: Time Stamps - UTC timestamps from the system clock, stamped at
//!   sequence assignment
//! - **AU-9**: Protection of Audit Information - integrity via hash chain
//! - **AU-10**: Non-repudiation - planned; the chain is unkeyed today
//!   (`// POAM: POA&M-130`)
//! - **AU-5**: Response to Audit Logging Process Failures - queue drops and
//!   sink write failures are counted, reported, and chained as
//!   `AuditRecordsDropped` markers
//!
//! ## Features
//!
//! - Structured audit events for all SBC operations
//! - Hash chain for tamper detection
//! - Configurable output sinks (structured logging)
//! - Thread-safe global logger with a non-blocking, bounded hand-off
//!
//! ## Example
//!
//! ```ignore
//! use uc_audit::{log_event, AuditEvent, CallAttempt};
//!
//! // Log a call attempt
//! log_event(AuditEvent::CallAttempt(CallAttempt {
//!     call_id: call_id.clone(),
//!     from_uri: "sip:alice@example.com".to_string(),
//!     to_uri: "sip:bob@example.com".to_string(),
//!     source_ip: "2001:db8::1".parse().unwrap(),
//!     attestation: Some(AttestationLevel::Full),
//! }));
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod event;
pub mod record;
pub mod sink;
pub mod verify;

pub use event::{AuditDropReason, AuditEvent, AuditEventType, AuditRecordsDropped};
pub use record::AuditRecord;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Minimum interval between AU-5 error logs about dropped records.
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Records queued for the writer thread before new ones are dropped.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
pub const AUDIT_QUEUE_CAPACITY: usize = 4096;

/// Global audit logger instance.
static AUDIT_LOGGER: OnceLock<AuditHandle> = OnceLock::new();

/// Loss and liveness counters shared by callers and the writer thread.
/// Atomics only: no lock is taken on either side.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
struct AuditCounters {
    /// Queue drops plus sink write failures.
    dropped: AtomicU64,
    /// Records dropped on the caller side (queue full or writer gone).
    queue_drops: AtomicU64,
    /// Queue drops not yet recorded in the chain by a marker.
    queue_drops_unreported: AtomicU64,
    /// Records the sink failed to persist.
    write_failures: AtomicU64,
    /// The last sink write failed; cleared by the next successful write.
    sink_failing: AtomicBool,
    /// Cleared when the writer thread exits (including by panic).
    writer_alive: AtomicBool,
    /// Milliseconds since `epoch` of the last queue-drop report, plus one
    /// (0 = never reported).
    last_drop_report_ms: AtomicU64,
    /// Same, for sink write-failure reports.
    last_failure_report_ms: AtomicU64,
    /// Milliseconds since `epoch` of the most recent loss of any kind, plus
    /// one (0 = never). Not rate-limited, so health checks can tell whether
    /// loss is recent.
    last_drop_ms: AtomicU64,
    /// Same, for sink write failures only.
    last_write_failure_ms: AtomicU64,
    epoch: Instant,
}

impl AuditCounters {
    fn new() -> Self {
        Self {
            dropped: AtomicU64::new(0),
            queue_drops: AtomicU64::new(0),
            queue_drops_unreported: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
            sink_failing: AtomicBool::new(false),
            writer_alive: AtomicBool::new(true),
            last_drop_report_ms: AtomicU64::new(0),
            last_failure_report_ms: AtomicU64::new(0),
            last_drop_ms: AtomicU64::new(0),
            last_write_failure_ms: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    /// Milliseconds since `epoch`, plus one (0 is reserved for "never").
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1)
    }

    /// True at most once per [`DROP_REPORT_INTERVAL`] per `stamp`.
    /// Lock-free; the caller never waits.
    fn should_report(&self, stamp: &AtomicU64) -> bool {
        let now_ms = self.now_ms();
        let last = stamp.load(Ordering::Relaxed);
        let interval_ms = u64::try_from(DROP_REPORT_INTERVAL.as_millis()).unwrap_or(u64::MAX);
        if last != 0 && now_ms.saturating_sub(last) < interval_ms {
            return false;
        }
        stamp
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Counts one record dropped on the caller side and stamps the drop time.
    ///
    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
    fn record_drop(&self, writer_dead: bool) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.queue_drops.fetch_add(1, Ordering::Relaxed);
        self.queue_drops_unreported.fetch_add(1, Ordering::Relaxed);
        self.last_drop_ms.store(self.now_ms(), Ordering::Relaxed);
        if !self.should_report(&self.last_drop_report_ms) {
            return;
        }
        let dropped_total = self.dropped.load(Ordering::Relaxed);
        if writer_dead {
            tracing::error!(
                dropped_total,
                "audit writer thread has exited; audit records are being dropped"
            );
        } else {
            tracing::error!(
                dropped_total,
                "audit queue full; audit records were dropped"
            );
        }
    }

    /// Marks the sink failing and stamps the failure time; when
    /// `count_loss`, also counts one lost record (markers are not counted,
    /// so a long outage does not inflate the loss).
    ///
    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
    fn record_write_failure(&self, error: &std::io::Error, count_loss: bool) {
        let now = self.now_ms();
        self.sink_failing.store(true, Ordering::Relaxed);
        self.last_write_failure_ms.store(now, Ordering::Relaxed);
        if count_loss {
            self.write_failures.fetch_add(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.last_drop_ms.store(now, Ordering::Relaxed);
        }
        if self.should_report(&self.last_failure_report_ms) {
            tracing::error!(
                write_failures = self.write_failures.load(Ordering::Relaxed),
                error = %error,
                "audit sink write failed; audit records are being dropped"
            );
        }
    }
}

/// Audit logger with hash chain integrity.
///
/// Owned by the writer thread; callers reach it through [`log_event`].
pub struct AuditLogger {
    sink: Box<dyn sink::AuditSink>,
    sequence: u64,
    last_hash: [u8; 48],
    counters: Arc<AuditCounters>,
    /// Sink write failures not yet recorded in the chain by a marker.
    pending_sink_drops: u64,
    /// `Some(count)` until the torn-tail marker for the resumed file is
    /// chained.
    pending_torn: Option<u64>,
}

impl AuditLogger {
    /// Creates a logger continuing the sink's persisted chain, if any.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
    fn new(sink: Box<dyn sink::AuditSink>, counters: Arc<AuditCounters>) -> Self {
        let resume = sink
            .resume_point()
            .unwrap_or_else(sink::ResumePoint::genesis);
        Self {
            sink,
            sequence: resume.next_sequence,
            last_hash: resume.last_hash,
            counters,
            pending_sink_drops: 0,
            pending_torn: (!resume.clean).then_some(resume.skipped_lines.max(1)),
        }
    }

    /// Chains and writes one event, timestamped now. The chain advances only
    /// when the sink persisted the record, so a failed write leaves no gap.
    ///
    /// ## NIST 800-53 Rev5: AU-3, AU-8 (timestamp at sequence assignment), AU-9
    fn try_write(&mut self, event: AuditEvent) -> std::io::Result<()> {
        let record = AuditRecord::new(self.sequence, event, chrono::Utc::now(), self.last_hash);
        self.sink.write(&record)?;
        self.sequence = self.sequence.wrapping_add(1);
        self.last_hash = record.hash_chain;
        self.counters.sink_failing.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Chains pending loss markers, then the event; a failed write is
    /// counted as a dropped record.
    ///
    /// While the sink is failing, markers are not retried before each
    /// record (that would multiply failing writes on a full or stale
    /// filesystem); they are chained right after the first record that
    /// persists again.
    ///
    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures), SC-5
    fn log(&mut self, event: AuditEvent) {
        let failing = self.counters.sink_failing.load(Ordering::Relaxed);
        if !failing {
            self.emit_pending();
        }
        match self.try_write(event) {
            Ok(()) if failing => self.emit_pending(),
            Ok(()) => {}
            Err(e) => {
                self.counters.record_write_failure(&e, true);
                self.pending_sink_drops = self.pending_sink_drops.saturating_add(1);
            }
        }
    }

    /// Chains one `AuditRecordsDropped` marker per outstanding loss reason.
    /// A marker that fails to write stays pending (it is not itself counted
    /// as a lost record), so markers never stack up during an outage.
    ///
    /// ## NIST 800-53 Rev5: AU-5, AU-9 (loss is visible inside the chain)
    fn emit_pending(&mut self) {
        if let Some(count) = self.pending_torn {
            let marker = AuditRecordsDropped {
                count,
                total: count,
                reason: AuditDropReason::TornTail,
            };
            if self.write_marker(marker) {
                self.pending_torn = None;
            }
        }
        let queued = self
            .counters
            .queue_drops_unreported
            .swap(0, Ordering::Relaxed);
        if queued > 0 {
            let marker = AuditRecordsDropped {
                count: queued,
                total: self.counters.queue_drops.load(Ordering::Relaxed),
                reason: AuditDropReason::QueueFull,
            };
            if !self.write_marker(marker) {
                self.counters
                    .queue_drops_unreported
                    .fetch_add(queued, Ordering::Relaxed);
            }
        }
        if self.pending_sink_drops > 0 {
            let marker = AuditRecordsDropped {
                count: self.pending_sink_drops,
                total: self.counters.write_failures.load(Ordering::Relaxed),
                reason: AuditDropReason::SinkWriteFailed,
            };
            if self.write_marker(marker) {
                self.pending_sink_drops = 0;
            }
        }
    }

    fn write_marker(&mut self, marker: AuditRecordsDropped) -> bool {
        match self.try_write(AuditEvent::AuditRecordsDropped(marker)) {
            Ok(()) => true,
            Err(e) => {
                self.counters.record_write_failure(&e, false);
                false
            }
        }
    }

    fn flush_sink(&self) {
        if let Err(e) = self.sink.flush() {
            self.counters.record_write_failure(&e, false);
        }
    }
}

/// Work item for the writer thread. The timestamp is taken by the writer
/// when it assigns the sequence (AU-8), not on the caller.
enum Job {
    Record(Box<AuditEvent>),
    Flush(SyncSender<()>),
}

/// Caller-side handle: a bounded queue to the writer thread.
///
/// The hand-off never blocks the caller (async signalling tasks emit audit
/// records): a full queue or a dead writer drops the record and counts it,
/// and `log_event` (caller side) reports the loss on the error log, at most
/// once per [`DROP_REPORT_INTERVAL`].
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
struct AuditHandle {
    tx: SyncSender<Job>,
    counters: Arc<AuditCounters>,
}

/// Clears `writer_alive` when the writer thread ends, even by panic.
struct WriterAliveGuard(Arc<AuditCounters>);

impl Drop for WriterAliveGuard {
    fn drop(&mut self) {
        self.0.writer_alive.store(false, Ordering::Relaxed);
        tracing::error!("audit writer thread exited; audit records will be dropped");
    }
}

/// Writer thread body: chains and writes records in queue order.
fn run_writer(mut logger: AuditLogger, rx: Receiver<Job>) {
    let _alive = WriterAliveGuard(Arc::clone(&logger.counters));
    // Declared after the guard so the queue closes (later sends count as
    // drops) before `writer_alive` is cleared.
    let rx = rx;
    // A torn tail found at open is chained before anything else.
    logger.emit_pending();
    while let Ok(job) = rx.recv() {
        match job {
            Job::Record(event) => logger.log(*event),
            Job::Flush(done) => {
                logger.emit_pending();
                logger.flush_sink();
                let _ = done.try_send(());
            }
        }
    }
    logger.emit_pending();
    logger.flush_sink();
}

/// Initializes the global audit logger.
///
/// This should be called once at application startup.
///
/// ## NIST 800-53 Rev5: AU-2 (Event Logging)
///
/// ## Errors
///
/// Returns an error if the logger is already initialized.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn init() -> Result<(), AuditError> {
    init_with_sink(Box::new(sink::TracingSink))
}

/// Initializes the global audit logger with a custom sink.
///
/// Records are written by a dedicated thread fed through a queue of
/// [`AUDIT_QUEUE_CAPACITY`] records, so sink I/O never runs on the caller.
/// The chain continues from [`sink::AuditSink::resume_point`].
///
/// ## Errors
///
/// Returns an error if the logger is already initialized or the writer
/// thread cannot be started.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn init_with_sink(sink: Box<dyn sink::AuditSink>) -> Result<(), AuditError> {
    if AUDIT_LOGGER.get().is_some() {
        return Err(AuditError::AlreadyInitialized);
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(AUDIT_QUEUE_CAPACITY);
    let counters = Arc::new(AuditCounters::new());
    AUDIT_LOGGER
        .set(AuditHandle {
            tx,
            counters: Arc::clone(&counters),
        })
        .map_err(|_| AuditError::AlreadyInitialized)?;
    let logger = AuditLogger::new(sink, counters);
    std::thread::Builder::new()
        .name("uc-audit-writer".to_string())
        .spawn(move || run_writer(logger, rx))
        .map(|_| ())
        .map_err(|e| AuditError::WriterThread(e.to_string()))
}

/// Logs an audit event to the global logger.
///
/// If the logger is not initialized, this is a no-op. Never blocks: the
/// record is queued for the writer thread, or dropped and counted (see
/// [`dropped_records`]) when the queue is full.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), AU-5
pub fn log_event(event: AuditEvent) {
    #[cfg(feature = "test-capture")]
    capture::record(&event);
    let Some(handle) = AUDIT_LOGGER.get() else {
        return;
    };
    match handle.tx.try_send(Job::Record(Box::new(event))) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => handle.counters.record_drop(false),
        Err(TrySendError::Disconnected(_)) => handle.counters.record_drop(true),
    }
}

/// Point-in-time view of the audit pipeline, for health checks and metrics.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditStats {
    /// Writer thread running (`true` when no logger is initialized).
    pub writer_alive: bool,
    /// Records lost: queue drops plus sink write failures.
    pub dropped: u64,
    /// Records dropped on the caller side (queue full or writer gone).
    pub queue_drops: u64,
    /// Records the sink failed to persist.
    pub write_failures: u64,
    /// The most recent sink write failed (no success since).
    pub sink_failing: bool,
    /// Time since the most recent loss of any kind.
    pub last_drop: Option<Duration>,
    /// Time since the most recent sink write failure.
    pub last_write_failure: Option<Duration>,
}

/// Snapshot of the audit pipeline counters.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[must_use]
pub fn stats() -> AuditStats {
    let Some(h) = AUDIT_LOGGER.get() else {
        return AuditStats {
            writer_alive: true,
            ..AuditStats::default()
        };
    };
    let c = &h.counters;
    let now = c.now_ms();
    AuditStats {
        writer_alive: c.writer_alive.load(Ordering::Relaxed),
        dropped: c.dropped.load(Ordering::Relaxed),
        queue_drops: c.queue_drops.load(Ordering::Relaxed),
        write_failures: c.write_failures.load(Ordering::Relaxed),
        sink_failing: c.sink_failing.load(Ordering::Relaxed),
        last_drop: elapsed_since(c.last_drop_ms.load(Ordering::Relaxed), now),
        last_write_failure: elapsed_since(c.last_write_failure_ms.load(Ordering::Relaxed), now),
    }
}

/// Whether the audit writer thread is running. `true` when no logger is
/// initialized (nothing to fail). A `false` here means every record is
/// being dropped: surface it as unhealthy.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[must_use]
pub fn writer_alive() -> bool {
    AUDIT_LOGGER
        .get()
        .is_none_or(|h| h.counters.writer_alive.load(Ordering::Relaxed))
}

/// Whether the most recent sink write failed (e.g. ENOSPC). `false` when no
/// logger is initialized. Surface it as unhealthy: records are being lost.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[must_use]
pub fn sink_failing() -> bool {
    AUDIT_LOGGER
        .get()
        .is_some_and(|h| h.counters.sink_failing.load(Ordering::Relaxed))
}

/// Audit records lost: dropped because the writer queue was full or the
/// writer thread had exited, plus records the sink failed to persist.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[must_use]
pub fn dropped_records() -> u64 {
    AUDIT_LOGGER
        .get()
        .map_or(0, |h| h.counters.dropped.load(Ordering::Relaxed))
}

/// Audit records the sink failed to persist (included in
/// [`dropped_records`]).
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[must_use]
pub fn write_failures() -> u64 {
    AUDIT_LOGGER
        .get()
        .map_or(0, |h| h.counters.write_failures.load(Ordering::Relaxed))
}

/// Time since the most recent lost audit record (queue drop or sink write
/// failure).
///
/// `None` when no logger is initialized or nothing has been lost. Lets health checks
/// report recent loss as degraded and recover once drops stop, while
/// [`dropped_records`] stays cumulative.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[must_use]
pub fn last_drop_elapsed() -> Option<Duration> {
    let c = &AUDIT_LOGGER.get()?.counters;
    elapsed_since(c.last_drop_ms.load(Ordering::Relaxed), c.now_ms())
}

/// Elapsed time between two `+1`-encoded millisecond stamps; `None` when
/// `last_ms` is 0 (never).
fn elapsed_since(last_ms: u64, now_ms: u64) -> Option<Duration> {
    (last_ms != 0).then(|| Duration::from_millis(now_ms.saturating_sub(last_ms)))
}

/// Waits up to `timeout` for queued records to reach the sink and be
/// flushed. Call at shutdown, off any async runtime worker: it blocks.
///
/// When the queue is full the flush marker is retried until it fits or
/// `timeout` passes, so a burst queued just before shutdown is drained
/// rather than abandoned. Returns `true` when the queue drained in time
/// (or no logger is set).
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
pub fn flush(timeout: Duration) -> bool {
    let Some(handle) = AUDIT_LOGGER.get() else {
        return true;
    };
    let deadline = Instant::now() + timeout;
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let mut job = Job::Flush(done_tx);
    loop {
        match handle.tx.try_send(job) {
            Ok(()) => break,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(back)) => {
                if Instant::now() >= deadline {
                    return false;
                }
                job = back;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    done_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .is_ok()
}

/// Per-thread capture of logged events, for tests asserting audit records.
///
/// Enabled with the `test-capture` feature. Capture is thread-local, so
/// tests on separate threads (and current-thread Tokio runtimes) don't see
/// each other's events.
#[cfg(feature = "test-capture")]
pub mod capture {
    use crate::AuditEvent;
    use std::cell::RefCell;

    thread_local! {
        static CAPTURED: RefCell<Option<Vec<AuditEvent>>> = const { RefCell::new(None) };
    }

    /// Captures events logged on this thread until dropped.
    pub struct CaptureGuard(());

    impl CaptureGuard {
        /// Events captured so far.
        #[must_use]
        pub fn events(&self) -> Vec<AuditEvent> {
            CAPTURED.with(|c| c.borrow().clone().unwrap_or_default())
        }
    }

    impl Drop for CaptureGuard {
        fn drop(&mut self) {
            CAPTURED.with(|c| *c.borrow_mut() = None);
        }
    }

    /// Starts capturing events logged on this thread.
    #[must_use]
    pub fn start() -> CaptureGuard {
        CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
        CaptureGuard(())
    }

    pub(crate) fn record(event: &AuditEvent) {
        CAPTURED.with(|c| {
            if let Some(events) = c.borrow_mut().as_mut() {
                events.push(event.clone());
            }
        });
    }
}

/// Audit subsystem errors.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Logger was already initialized.
    #[error("audit logger already initialized")]
    AlreadyInitialized,
    /// The writer thread could not be started.
    #[error("audit writer thread not started: {0}")]
    WriterThread(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Shared(Arc<sink::MemorySink>);
    impl sink::AuditSink for Shared {
        fn write(&self, record: &AuditRecord) -> std::io::Result<()> {
            self.0.write(record)
        }
    }

    // The only test touching the process-global logger.
    #[test]
    fn global_logger_queues_records_in_order_with_hash_chain() {
        let mem = Arc::new(sink::MemorySink::new());
        init_with_sink(Box::new(Shared(Arc::clone(&mem)))).unwrap();
        assert!(matches!(
            init_with_sink(Box::new(sink::TracingSink)),
            Err(AuditError::AlreadyInitialized)
        ));
        for i in 0..3 {
            log_event(AuditEvent::SystemShutdown(event::SystemShutdown {
                reason: format!("r{i}"),
                graceful: true,
            }));
        }
        assert!(flush(Duration::from_secs(5)));
        let records = mem.records();
        // Other tests on other threads may log into the global logger too;
        // ours arrive in order and the whole chain verifies.
        let ours: Vec<String> = records
            .iter()
            .filter_map(|r| match &r.event {
                AuditEvent::SystemShutdown(e) => Some(e.reason.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ours, vec!["r0", "r1", "r2"]);
        let mut prev = [0u8; 48];
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.sequence, i as u64);
            assert!(r.verify(&prev));
            prev = r.hash_chain;
        }
        assert_eq!(dropped_records(), 0);
        assert_eq!(last_drop_elapsed(), None);
    }

    /// Fails the first `fail` writes, then forwards to memory.
    struct FailN {
        mem: Arc<sink::MemorySink>,
        fail: std::sync::atomic::AtomicU32,
        resume: Option<sink::ResumePoint>,
    }
    impl sink::AuditSink for FailN {
        fn write(&self, record: &AuditRecord) -> std::io::Result<()> {
            let left = self.fail.load(Ordering::Relaxed);
            if left > 0 {
                self.fail.store(left - 1, Ordering::Relaxed);
                return Err(std::io::Error::other("ENOSPC"));
            }
            self.mem.write(record)
        }
        fn resume_point(&self) -> Option<sink::ResumePoint> {
            self.resume
        }
    }

    fn shutdown_ev(i: u32) -> AuditEvent {
        AuditEvent::SystemShutdown(event::SystemShutdown {
            reason: format!("r{i}"),
            graceful: true,
        })
    }

    fn assert_chain(records: &[AuditRecord], first: u64, mut prev: [u8; 48]) {
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.sequence, first + i as u64);
            assert!(r.verify(&prev), "chain broken at {i}");
            prev = r.hash_chain;
        }
    }

    /// Regression (BACKLOG NIT, fixed by #174): timestamp and sequence are
    /// both assigned in the writer, so timestamps never decrease along the
    /// sequence order. NIST 800-53 Rev5: AU-8, AU-3
    #[test]
    fn timestamps_non_decreasing_in_sequence_order() {
        let mem = Arc::new(sink::MemorySink::new());
        let counters = Arc::new(AuditCounters::new());
        let mut logger =
            AuditLogger::new(Box::new(Shared(Arc::clone(&mem))), Arc::clone(&counters));
        for i in 0..50 {
            logger.log(shutdown_ev(i));
        }
        let records = mem.records();
        assert_eq!(records.len(), 50);
        for w in records.windows(2) {
            assert_eq!(w[1].sequence, w[0].sequence + 1);
            assert!(w[1].timestamp >= w[0].timestamp);
        }
    }

    #[test]
    fn failing_sink_counts_and_does_not_advance_chain() {
        let mem = Arc::new(sink::MemorySink::new());
        let counters = Arc::new(AuditCounters::new());
        let mut logger = AuditLogger::new(
            Box::new(FailN {
                mem: Arc::clone(&mem),
                fail: std::sync::atomic::AtomicU32::new(0),
                resume: None,
            }),
            Arc::clone(&counters),
        );
        logger.log(shutdown_ev(0));
        // Swap in a sink that fails the next 3 records; markers are not
        // retried while failing, keeping the chain position.
        logger.sink = Box::new(FailN {
            mem: Arc::clone(&mem),
            fail: std::sync::atomic::AtomicU32::new(3),
            resume: None,
        });
        for i in 1..=3 {
            logger.log(shutdown_ev(i));
            assert!(counters.sink_failing.load(Ordering::Relaxed));
        }
        assert_eq!(
            logger.sequence, 1,
            "failed writes must not advance the chain"
        );
        assert_eq!(counters.write_failures.load(Ordering::Relaxed), 3);
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 3);
        assert_ne!(counters.last_write_failure_ms.load(Ordering::Relaxed), 0);
        logger.log(shutdown_ev(4));
        assert!(!counters.sink_failing.load(Ordering::Relaxed));
        let records = mem.records();
        assert_eq!(records.len(), 3);
        // The marker follows the first record that persisted again.
        assert!(matches!(&records[1].event, AuditEvent::SystemShutdown(_)));
        assert!(matches!(
            &records[2].event,
            AuditEvent::AuditRecordsDropped(m)
                if m.reason == AuditDropReason::SinkWriteFailed && m.count == 3
        ));
        assert_chain(&records, 0, [0u8; 48]);
        // Markers are not counted as further loss.
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn failed_marker_write_stays_pending_without_counting() {
        let mem = Arc::new(sink::MemorySink::new());
        let counters = Arc::new(AuditCounters::new());
        let mut logger = AuditLogger::new(
            Box::new(FailN {
                mem: Arc::clone(&mem),
                fail: std::sync::atomic::AtomicU32::new(3),
                resume: None,
            }),
            Arc::clone(&counters),
        );
        logger.log(shutdown_ev(0)); // record fails (1)
        logger.log(shutdown_ev(1)); // failing: no marker attempt; record fails (2)
        assert_eq!(counters.write_failures.load(Ordering::Relaxed), 2);
        // A flush retries the marker once; it fails (3) and stays pending
        // without counting a lost record.
        logger.emit_pending();
        assert_eq!(counters.write_failures.load(Ordering::Relaxed), 2);
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 2);
        logger.log(shutdown_ev(2)); // persists, then the marker
        let records = mem.records();
        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[1].event,
            AuditEvent::AuditRecordsDropped(m) if m.count == 2 && m.total == 2
        ));
        assert_chain(&records, 0, [0u8; 48]);
    }

    #[test]
    fn logger_resumes_and_marks_torn_tail_first() {
        let mem = Arc::new(sink::MemorySink::new());
        let resume = sink::ResumePoint {
            next_sequence: 7,
            last_hash: [9u8; 48],
            clean: false,
            torn_bytes: 12,
            skipped_lines: 3,
        };
        let mut logger = AuditLogger::new(
            Box::new(FailN {
                mem: Arc::clone(&mem),
                fail: std::sync::atomic::AtomicU32::new(0),
                resume: Some(resume),
            }),
            Arc::new(AuditCounters::new()),
        );
        logger.emit_pending();
        logger.log(shutdown_ev(0));
        let records = mem.records();
        assert!(matches!(
            &records[0].event,
            AuditEvent::AuditRecordsDropped(m)
                if m.reason == AuditDropReason::TornTail && m.count == 3
        ));
        assert_chain(&records, 7, [9u8; 48]);
    }

    #[test]
    fn queue_drops_become_one_marker() {
        let mem = Arc::new(sink::MemorySink::new());
        let counters = Arc::new(AuditCounters::new());
        let mut logger = AuditLogger::new(
            Box::new(FailN {
                mem: Arc::clone(&mem),
                fail: std::sync::atomic::AtomicU32::new(0),
                resume: None,
            }),
            Arc::clone(&counters),
        );
        for _ in 0..5 {
            counters.record_drop(false);
        }
        logger.log(shutdown_ev(0));
        logger.log(shutdown_ev(1));
        let records = mem.records();
        assert_eq!(records.len(), 3);
        assert!(matches!(
            &records[0].event,
            AuditEvent::AuditRecordsDropped(m)
                if m.reason == AuditDropReason::QueueFull && m.count == 5 && m.total == 5
        ));
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn elapsed_since_encodes_never_as_none() {
        assert_eq!(elapsed_since(0, 5_000), None);
        assert_eq!(elapsed_since(1, 1), Some(Duration::ZERO));
        assert_eq!(elapsed_since(1_001, 6_001), Some(Duration::from_secs(5)));
        // Clock never goes backwards, but a racing store must not underflow.
        assert_eq!(elapsed_since(9_000, 8_000), Some(Duration::ZERO));
    }

    #[cfg(feature = "test-capture")]
    #[test]
    fn capture_is_thread_local_and_scoped() {
        let guard = capture::start();
        log_event(AuditEvent::SystemStartup(event::SystemStartup {
            version: "v".to_string(),
            config_path: "p".to_string(),
        }));
        std::thread::spawn(|| {
            log_event(AuditEvent::SystemStartup(event::SystemStartup {
                version: "other".to_string(),
                config_path: "p".to_string(),
            }));
        })
        .join()
        .unwrap();
        assert_eq!(guard.events().len(), 1);
        drop(guard);
        let guard = capture::start();
        assert!(guard.events().is_empty());
    }
}
