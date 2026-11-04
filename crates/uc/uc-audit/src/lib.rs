//! # SBC Audit
//!
//! NIST 800-53 Rev5 compliant audit logging for the USG Session Border Controller.
//!
//! ## NIST 800-53 Rev5 Controls Implemented
//!
//! - **AU-2**: Event Logging - defines auditable events
//! - **AU-3**: Content of Audit Records - specifies required fields
//! - **AU-8**: Time Stamps - uses reliable time sources
//! - **AU-9**: Protection of Audit Information - integrity via hash chain
//! - **AU-10**: Non-repudiation - cryptographic binding of records
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

pub use event::{AuditEvent, AuditEventType};
pub use record::AuditRecord;

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant};

/// Minimum interval between AU-5 error logs about dropped records.
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Records queued for the writer thread before new ones are dropped.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
pub const AUDIT_QUEUE_CAPACITY: usize = 4096;

/// Global audit logger instance.
static AUDIT_LOGGER: OnceLock<AuditHandle> = OnceLock::new();

/// Audit logger with hash chain integrity.
///
/// Owned by the writer thread; callers reach it through [`log_event`].
pub struct AuditLogger {
    sink: Box<dyn sink::AuditSink>,
    sequence: u64,
    last_hash: [u8; 48],
}

impl AuditLogger {
    /// Creates a new audit logger with the given sink.
    fn new(sink: Box<dyn sink::AuditSink>) -> Self {
        Self {
            sink,
            sequence: 0,
            last_hash: [0u8; 48],
        }
    }

    /// Chains and writes one event.
    ///
    /// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), AU-9
    fn log_at(&mut self, event: AuditEvent, timestamp: chrono::DateTime<chrono::Utc>) {
        let record = AuditRecord::new(self.sequence, event, timestamp, self.last_hash);
        self.sequence = self.sequence.wrapping_add(1);
        self.last_hash = record.hash_chain;
        self.sink.write(&record);
    }
}

/// Work item for the writer thread.
enum Job {
    Record(Box<AuditEvent>, chrono::DateTime<chrono::Utc>),
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
    dropped: AtomicU64,
    /// Cleared when the writer thread exits (including by panic).
    writer_alive: AtomicBool,
    /// Milliseconds since `epoch` of the last drop report, plus one (0 =
    /// never reported).
    last_drop_report_ms: AtomicU64,
    epoch: Instant,
}

impl AuditHandle {
    /// Logs dropped records at error level, at most once per
    /// [`DROP_REPORT_INTERVAL`]. Lock-free; the caller never waits.
    ///
    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
    fn report_drop(&self, writer_dead: bool) {
        let now_ms = u64::try_from(self.epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let last = self.last_drop_report_ms.load(Ordering::Relaxed);
        let interval_ms = u64::try_from(DROP_REPORT_INTERVAL.as_millis()).unwrap_or(u64::MAX);
        if last != 0 && now_ms.saturating_sub(last) < interval_ms {
            return;
        }
        if self
            .last_drop_report_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
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
}

/// Clears `writer_alive` when the writer thread ends, even by panic.
struct WriterAliveGuard;

impl Drop for WriterAliveGuard {
    fn drop(&mut self) {
        if let Some(handle) = AUDIT_LOGGER.get() {
            handle.writer_alive.store(false, Ordering::Relaxed);
        }
        tracing::error!("audit writer thread exited; audit records will be dropped");
    }
}

/// Writer thread body: chains and writes records in queue order.
fn run_writer(mut logger: AuditLogger, rx: Receiver<Job>) {
    let _alive = WriterAliveGuard;
    // Declared after the guard so the queue closes (later sends count as
    // drops) before `writer_alive` is cleared.
    let rx = rx;
    while let Ok(job) = rx.recv() {
        match job {
            Job::Record(event, timestamp) => logger.log_at(*event, timestamp),
            Job::Flush(done) => {
                logger.sink.flush();
                let _ = done.try_send(());
            }
        }
    }
    logger.sink.flush();
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
    AUDIT_LOGGER
        .set(AuditHandle {
            tx,
            dropped: AtomicU64::new(0),
            writer_alive: AtomicBool::new(true),
            last_drop_report_ms: AtomicU64::new(0),
            epoch: Instant::now(),
        })
        .map_err(|_| AuditError::AlreadyInitialized)?;
    let logger = AuditLogger::new(sink);
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
    let job = Job::Record(Box::new(event), chrono::Utc::now());
    match handle.tx.try_send(job) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            handle.dropped.fetch_add(1, Ordering::Relaxed);
            handle.report_drop(false);
        }
        Err(TrySendError::Disconnected(_)) => {
            handle.dropped.fetch_add(1, Ordering::Relaxed);
            handle.report_drop(true);
        }
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
        .is_none_or(|h| h.writer_alive.load(Ordering::Relaxed))
}

/// Audit records dropped because the writer queue was full or the writer
/// thread had exited.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#[must_use]
pub fn dropped_records() -> u64 {
    AUDIT_LOGGER
        .get()
        .map_or(0, |h| h.dropped.load(Ordering::Relaxed))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Shared(Arc<sink::MemorySink>);
    impl sink::AuditSink for Shared {
        fn write(&self, record: &AuditRecord) {
            self.0.write(record);
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
