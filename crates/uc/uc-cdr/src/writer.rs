//! Non-blocking CDR emitter: a bounded queue feeding one writer OS thread.
//!
//! Producers (async signaling tasks) call [`CdrEmitter::emit`], which never
//! blocks: a full queue or a dead writer drops the record and counts it. The
//! writer thread applies the PII policy, assigns `node_id`/`sequence`, seals
//! the hash chain, writes the file, hands the record to each secondary sink's
//! own thread and queue (never waiting on it), then publishes the record to
//! the in-memory ring.
//!
//! ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures), AU-12

use crate::chain::{self, GENESIS, HASH_LEN};
use crate::error::{CdrError, CdrResult};
use crate::format;
use crate::pii::PiiPolicy;
use crate::record::{CallRecord, SCHEMA_VERSION};
use crate::ring::{CdrRing, MAX_RING_CAPACITY};
use crate::sink::{CdrObserver, CdrSink, FileSink, FileSinkConfig, valid_node_id};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant, SystemTime};

/// Smallest accepted queue capacity.
pub const MIN_QUEUE_CAPACITY: usize = 64;
/// Largest accepted queue capacity.
pub const MAX_QUEUE_CAPACITY: usize = 1_000_000;
/// Default queue capacity.
pub const DEFAULT_QUEUE_CAPACITY: usize = 8192;
/// Default ring capacity.
pub const DEFAULT_RING_CAPACITY: usize = 10_000;

/// Minimum interval between drop reports (error log + observer).
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(10);
/// Writer wake-up interval for fsync and time rotation.
const TICK: Duration = Duration::from_millis(250);
/// Per-sink queue between the file writer and each secondary sink thread.
pub const SINK_QUEUE_CAPACITY: usize = 4096;
/// Longest shutdown waits for secondary sinks to drain.
const SINK_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// A file write error this recent makes health unhealthy.
pub const UNHEALTHY_WRITE_ERROR_WINDOW: Duration = Duration::from_secs(60);
/// A drop or secondary-sink error this recent makes health degraded.
pub const DEGRADED_DROP_WINDOW: Duration = Duration::from_secs(300);

/// Emitter configuration.
#[derive(Debug, Clone)]
pub struct CdrEmitterConfig {
    /// Node id (`[A-Za-z0-9._-]{1,64}`), stamped on every record.
    pub node_id: String,
    /// Writer queue capacity ([`MIN_QUEUE_CAPACITY`]..=[`MAX_QUEUE_CAPACITY`]).
    pub queue_capacity: usize,
    /// Ring capacity (0..=[`MAX_RING_CAPACITY`]).
    pub ring_capacity: usize,
    /// Seal records into a SHA-384 chain.
    pub hash_chain: bool,
    /// PII policy.
    pub pii: PiiPolicy,
    /// File sink. `None` only for ring-only use (tests, tooling).
    pub file: Option<FileSinkConfig>,
}

impl Default for CdrEmitterConfig {
    fn default() -> Self {
        Self {
            node_id: "sbc".to_string(),
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            ring_capacity: DEFAULT_RING_CAPACITY,
            hash_chain: true,
            pii: PiiPolicy::Full,
            file: Some(FileSinkConfig::default()),
        }
    }
}

/// Settings that can change without a restart.
#[derive(Debug, Clone, Default)]
pub struct CdrReload {
    /// New PII policy.
    pub pii: Option<PiiPolicy>,
    /// New `(retention_files, retention_days)`.
    pub retention: Option<(u32, u32)>,
}

/// Pipeline health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdrHealth {
    /// Working normally.
    Healthy,
    /// Recent drops or secondary-sink errors.
    Degraded,
    /// Writer dead or recent file write error.
    Unhealthy,
}

impl CdrHealth {
    /// `"healthy"`, `"degraded"` or `"unhealthy"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Counter snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CdrStats {
    /// Records accepted onto the queue.
    pub emitted: u64,
    /// Records dropped because the queue was full.
    pub dropped_queue_full: u64,
    /// Records dropped because the writer had exited.
    pub dropped_writer_dead: u64,
    /// Records written to the file sink.
    pub written: u64,
    /// File sink write/open/rotate failures.
    pub write_errors: u64,
    /// Secondary sink (syslog) failures.
    pub sink_errors: u64,
    /// Records a secondary sink never saw because its own queue was full
    /// (slow or stalled collector). The file copy is unaffected.
    pub sink_dropped: u64,
    /// Records waiting on the queue.
    pub queue_depth: u64,
    /// Records in the ring.
    pub ring_size: u64,
    /// Epoch ms of the last successful file write (0 = never).
    pub last_write_ms: u64,
    /// False when the on-disk chain could not be resumed cleanly.
    pub chain_ok: bool,
    /// Whether the writer thread is running.
    pub writer_alive: bool,
    /// Files rotated.
    pub rotations: u64,
}

impl CdrStats {
    /// Total dropped records.
    pub const fn dropped(&self) -> u64 {
        self.dropped_queue_full + self.dropped_writer_dead
    }
}

enum Job {
    Record(Box<CallRecord>),
    Flush(SyncSender<()>),
    Reload(Box<CdrReload>),
    Shutdown(SyncSender<()>),
}

/// State shared by producers, the writer thread and readers.
struct Shared {
    node_id: String,
    ring: CdrRing,
    emitted: AtomicU64,
    dropped_full: AtomicU64,
    dropped_dead: AtomicU64,
    written: AtomicU64,
    write_errors: AtomicU64,
    sink_errors: AtomicU64,
    sink_dropped: AtomicU64,
    queue_depth: AtomicU64,
    last_write_ms: AtomicU64,
    rotations: AtomicU64,
    chain_ok: AtomicBool,
    writer_alive: AtomicBool,
    /// `+1`-encoded ms since `epoch` (0 = never), as in uc-audit.
    last_drop: AtomicU64,
    last_drop_report: AtomicU64,
    last_write_error: AtomicU64,
    last_sink_error: AtomicU64,
    epoch: Instant,
    observer: Option<Arc<dyn CdrObserver>>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1)
    }

    fn since(&self, stamp: &AtomicU64) -> Option<Duration> {
        let last = stamp.load(Ordering::Relaxed);
        (last != 0).then(|| Duration::from_millis(self.now_ms().saturating_sub(last)))
    }

    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
    fn record_drop(&self, writer_dead: bool) {
        if writer_dead {
            self.dropped_dead.fetch_add(1, Ordering::Relaxed);
        } else {
            self.dropped_full.fetch_add(1, Ordering::Relaxed);
        }
        let now = self.now_ms();
        self.last_drop.store(now, Ordering::Relaxed);
        let last = self.last_drop_report.load(Ordering::Relaxed);
        let iv = u64::try_from(DROP_REPORT_INTERVAL.as_millis()).unwrap_or(u64::MAX);
        if last != 0 && now.saturating_sub(last) < iv {
            return;
        }
        if self
            .last_drop_report
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let total =
            self.dropped_full.load(Ordering::Relaxed) + self.dropped_dead.load(Ordering::Relaxed);
        if writer_dead {
            tracing::error!(
                dropped_total = total,
                "CDR writer has exited; CDRs are being dropped"
            );
        } else {
            tracing::error!(dropped_total = total, "CDR queue full; CDRs were dropped");
        }
        if let Some(o) = &self.observer {
            o.on_drop(total, writer_dead);
        }
    }
}

/// Clears `writer_alive` when the writer thread ends, even by panic.
struct AliveGuard(Arc<Shared>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.writer_alive.store(false, Ordering::Relaxed);
        tracing::error!("CDR writer thread exited; CDRs will be dropped");
    }
}

struct WriterState {
    shared: Arc<Shared>,
    file: Option<FileSink>,
    sinks: Vec<SinkWorker>,
    pii: PiiPolicy,
    hash_chain: bool,
    next_sequence: u64,
    last_hash: [u8; HASH_LEN],
}

impl WriterState {
    fn file_error(&self, e: &std::io::Error) {
        self.shared.write_errors.fetch_add(1, Ordering::Relaxed);
        self.shared
            .last_write_error
            .store(self.shared.now_ms(), Ordering::Relaxed);
        tracing::error!(error = %e, "CDR file sink write failed");
        if let Some(o) = &self.shared.observer {
            o.on_write_error(e);
        }
    }

    fn sync_rotations(&self) {
        if let Some(f) = &self.file {
            self.shared
                .rotations
                .store(f.rotations(), Ordering::Relaxed);
        }
    }

    /// ## NIST 800-53 Rev5: AU-3, AU-9 (hash chain), AU-12 (Audit Record Generation)
    fn handle(&mut self, mut rec: CallRecord) {
        self.pii.apply(&mut rec);
        rec.schema_version = SCHEMA_VERSION;
        rec.node_id.clone_from(&self.shared.node_id);
        rec.sequence = self.next_sequence;
        rec.record_id = format!("{}-{}", self.shared.node_id, self.next_sequence);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if self.hash_chain {
            match chain::seal(&mut rec, &self.last_hash) {
                Ok(h) => self.last_hash = h,
                Err(e) => {
                    tracing::error!(error = %e, "CDR hash chain sealing failed");
                    self.shared.chain_ok.store(false, Ordering::Relaxed);
                }
            }
        } else {
            rec.prev_hash.clear();
            rec.hash.clear();
        }
        let line = match format::to_json_line(&rec) {
            Ok(l) => l,
            Err(e) => {
                self.file_error(&std::io::Error::other(e.to_string()));
                return;
            }
        };
        if let Some(f) = self.file.as_mut() {
            match f.write_record(&rec, &line) {
                Ok(()) => {
                    self.shared.written.fetch_add(1, Ordering::Relaxed);
                    let ms = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    self.shared.last_write_ms.store(ms, Ordering::Relaxed);
                }
                Err(e) => self.file_error(&e),
            }
        }
        let rec = Arc::new(rec);
        if !self.sinks.is_empty() {
            let line: Arc<str> = Arc::from(line);
            for s in &self.sinks {
                s.send(&self.shared, &rec, &line);
            }
        }
        self.sync_rotations();
        self.shared.ring.push(rec);
    }

    fn flush(&mut self) {
        if let Some(f) = self.file.as_mut()
            && let Err(e) = f.sync()
        {
            self.file_error(&e);
        }
        for s in &self.sinks {
            // Never waits: a stalled collector must not delay the file.
            if let Some(tx) = &s.tx {
                let _ = tx.try_send(SinkJob::Flush);
            }
        }
    }

    fn tick(&mut self) {
        if let Some(f) = self.file.as_mut()
            && let Err(e) = f.tick(SystemTime::now())
        {
            self.file_error(&e);
        }
        self.sync_rotations();
    }

    fn close(&mut self) {
        self.flush();
        if let Some(f) = self.file.as_mut()
            && let Err(e) = f.close_current()
        {
            self.file_error(&e);
        }
        self.sync_rotations();
        // Let secondary sinks drain what they hold, bounded so a stalled
        // collector cannot hold up shutdown for long.
        for s in &mut self.sinks {
            s.tx = None;
        }
        let deadline = Instant::now() + SINK_DRAIN_TIMEOUT;
        for s in &mut self.sinks {
            while s.thread.as_ref().is_some_and(|t| !t.is_finished()) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if let Some(t) = s.thread.take().filter(std::thread::JoinHandle::is_finished) {
                let _ = t.join();
            }
        }
    }

    fn reload(&mut self, r: CdrReload) {
        if let Some(p) = r.pii {
            self.pii = p;
        }
        if let (Some((files, days)), Some(f)) = (r.retention, self.file.as_mut()) {
            f.set_retention(files, days);
        }
    }
}

enum SinkJob {
    Write(Arc<CallRecord>, Arc<str>),
    Flush,
}

/// A secondary sink on its own thread behind its own bounded queue, so a
/// slow or blackholed collector (connect, DNS, TLS, write timeouts) never
/// delays local file writes. A full queue drops the sink's copy only and
/// counts it in [`CdrStats::sink_dropped`].
///
/// ## NIST 800-53 Rev5: AU-5, AU-9(2), SC-5
struct SinkWorker {
    tx: Option<SyncSender<SinkJob>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SinkWorker {
    fn spawn(mut sink: Box<dyn CdrSink>, shared: Arc<Shared>) -> CdrResult<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<SinkJob>(SINK_QUEUE_CAPACITY);
        let name = sink.name();
        let thread = std::thread::Builder::new()
            .name(format!("uc-cdr-{name}"))
            .spawn(move || {
                let mut failing = false;
                // Ends when the file writer drops the sender (shutdown).
                for job in rx {
                    let res = match job {
                        SinkJob::Write(rec, line) => sink.write(&rec, &line),
                        SinkJob::Flush => sink.flush(),
                    };
                    match res {
                        Ok(()) => {
                            if failing {
                                tracing::info!(sink = name, "CDR sink recovered");
                            }
                            failing = false;
                        }
                        Err(e) => {
                            shared.sink_errors.fetch_add(1, Ordering::Relaxed);
                            shared
                                .last_sink_error
                                .store(shared.now_ms(), Ordering::Relaxed);
                            // Log the transition only, not every record.
                            if !failing {
                                tracing::warn!(sink = name, error = %e, "CDR sink write failed");
                            }
                            failing = true;
                        }
                    }
                }
                let _ = sink.flush();
            })
            .map_err(|e| CdrError::WriterThread {
                message: e.to_string(),
            })?;
        Ok(Self {
            tx: Some(tx),
            thread: Some(thread),
        })
    }

    fn send(&self, shared: &Shared, rec: &Arc<CallRecord>, line: &Arc<str>) {
        let sent = self.tx.as_ref().is_some_and(|tx| {
            tx.try_send(SinkJob::Write(Arc::clone(rec), Arc::clone(line)))
                .is_ok()
        });
        if !sent {
            shared.sink_dropped.fetch_add(1, Ordering::Relaxed);
            shared
                .last_sink_error
                .store(shared.now_ms(), Ordering::Relaxed);
        }
    }
}

fn run_writer(mut state: WriterState, rx: Receiver<Job>) {
    let _alive = AliveGuard(Arc::clone(&state.shared));
    // Declared after the guard so the queue closes (later sends count as
    // writer-dead drops) before `writer_alive` is cleared.
    let rx = rx;
    loop {
        match rx.recv_timeout(TICK) {
            Ok(Job::Record(rec)) => {
                state.shared.queue_depth.fetch_sub(1, Ordering::Relaxed);
                state.handle(*rec);
            }
            Ok(Job::Flush(done)) => {
                state.flush();
                let _ = done.try_send(());
            }
            Ok(Job::Reload(r)) => state.reload(*r),
            Ok(Job::Shutdown(done)) => {
                state.close();
                let _ = done.try_send(());
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                state.close();
                return;
            }
        }
        state.tick();
    }
}

/// Handle to the CDR pipeline. Cheap to share via `Arc`; owns no global state.
pub struct CdrEmitter {
    tx: SyncSender<Job>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for CdrEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdrEmitter")
            .field("node_id", &self.shared.node_id)
            .finish_non_exhaustive()
    }
}

impl CdrEmitter {
    /// Validates `config`, opens the file sink (fails if the directory is not
    /// writable) and starts the `uc-cdr-writer` thread. `sinks` are secondary
    /// sinks (e.g. [`crate::sink::SyslogSink`]).
    ///
    /// ## NIST 800-53 Rev5: AU-5 (fail closed at startup), AU-12
    pub fn start(
        config: CdrEmitterConfig,
        sinks: Vec<Box<dyn CdrSink>>,
        observer: Option<Arc<dyn CdrObserver>>,
    ) -> CdrResult<Arc<Self>> {
        if !valid_node_id(&config.node_id) {
            return Err(CdrError::config(
                "node_id must be 1-64 characters of [A-Za-z0-9._-]",
            ));
        }
        if !(MIN_QUEUE_CAPACITY..=MAX_QUEUE_CAPACITY).contains(&config.queue_capacity) {
            return Err(CdrError::config(format!(
                "queue_capacity must be {MIN_QUEUE_CAPACITY}..={MAX_QUEUE_CAPACITY}"
            )));
        }
        if config.ring_capacity > MAX_RING_CAPACITY {
            return Err(CdrError::config(format!(
                "ring_capacity must be 0..={MAX_RING_CAPACITY}"
            )));
        }
        let (file, resume) = match config.file {
            Some(fc) => {
                let (f, r) =
                    FileSink::open(fc, &config.node_id, config.hash_chain, observer.clone())?;
                (Some(f), Some(r))
            }
            None => (None, None),
        };
        let shared = Arc::new(Shared {
            node_id: config.node_id,
            ring: CdrRing::new(config.ring_capacity),
            emitted: AtomicU64::new(0),
            dropped_full: AtomicU64::new(0),
            dropped_dead: AtomicU64::new(0),
            written: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            sink_errors: AtomicU64::new(0),
            sink_dropped: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            last_write_ms: AtomicU64::new(0),
            rotations: AtomicU64::new(0),
            chain_ok: AtomicBool::new(resume.is_none_or(|r| r.clean)),
            writer_alive: AtomicBool::new(true),
            last_drop: AtomicU64::new(0),
            last_drop_report: AtomicU64::new(0),
            last_write_error: AtomicU64::new(0),
            last_sink_error: AtomicU64::new(0),
            epoch: Instant::now(),
            observer,
        });
        let sinks = sinks
            .into_iter()
            .map(|s| SinkWorker::spawn(s, Arc::clone(&shared)))
            .collect::<CdrResult<Vec<_>>>()?;
        let state = WriterState {
            shared: Arc::clone(&shared),
            file,
            sinks,
            pii: config.pii,
            hash_chain: config.hash_chain,
            next_sequence: resume.map_or(0, |r| r.next_sequence),
            last_hash: resume.map_or(GENESIS, |r| r.last_hash),
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(config.queue_capacity);
        std::thread::Builder::new()
            .name("uc-cdr-writer".to_string())
            .spawn(move || run_writer(state, rx))
            .map_err(|e| CdrError::WriterThread {
                message: e.to_string(),
            })?;
        Ok(Arc::new(Self { tx, shared }))
    }

    /// Queues a record. Never blocks or awaits; safe on any async task.
    /// Strings are capped at [`crate::record::MAX_FIELD_LEN`] here. Returns
    /// `false` when the record was dropped (queue full or writer dead) and
    /// counted.
    ///
    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures), AU-12
    pub fn emit(&self, mut record: CallRecord) -> bool {
        record.sanitize();
        self.shared.queue_depth.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(Job::Record(Box::new(record))) {
            Ok(()) => {
                self.shared.emitted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                self.shared.queue_depth.fetch_sub(1, Ordering::Relaxed);
                let dead = matches!(e, TrySendError::Disconnected(_))
                    || !self.shared.writer_alive.load(Ordering::Relaxed);
                self.shared.record_drop(dead);
                false
            }
        }
    }

    fn send_control(&self, make: impl Fn(SyncSender<()>) -> Job, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let mut job = make(done_tx);
        loop {
            match self.tx.try_send(job) {
                Ok(()) => break,
                Err(TrySendError::Full(j)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    job = j;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        done_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
    }

    /// Waits up to `timeout` for queued records to be written and synced.
    /// Blocks: call off async worker threads (e.g. `spawn_blocking`).
    pub fn flush(&self, timeout: Duration) -> bool {
        self.send_control(Job::Flush, timeout)
    }

    /// Drains the queue, closes the open file (writing its sidecar) and stops
    /// the writer. Later `emit` calls drop. Blocks like [`Self::flush`].
    pub fn shutdown(&self, timeout: Duration) -> bool {
        self.send_control(Job::Shutdown, timeout)
    }

    /// Applies hot-reloadable settings. Non-blocking; `false` if the queue
    /// is full or the writer is gone.
    pub fn reload(&self, reload: CdrReload) -> bool {
        self.tx.try_send(Job::Reload(Box::new(reload))).is_ok()
    }

    /// Node id stamped on records.
    pub fn node_id(&self) -> &str {
        &self.shared.node_id
    }

    /// Recent-record ring for API queries.
    pub fn ring(&self) -> &CdrRing {
        &self.shared.ring
    }

    /// Whether the writer thread is running.
    pub fn writer_alive(&self) -> bool {
        self.shared.writer_alive.load(Ordering::Relaxed)
    }

    /// Time since the last dropped record.
    pub fn last_drop_elapsed(&self) -> Option<Duration> {
        self.shared.since(&self.shared.last_drop)
    }

    /// Time since the last file sink error.
    pub fn last_write_error_elapsed(&self) -> Option<Duration> {
        self.shared.since(&self.shared.last_write_error)
    }

    /// Health: unhealthy if the writer is dead or a file write failed in the
    /// last 60 s; degraded on drops or sink errors in the last 5 min.
    ///
    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
    pub fn health(&self) -> CdrHealth {
        let s = &self.shared;
        if !self.writer_alive()
            || s.since(&s.last_write_error)
                .is_some_and(|d| d < UNHEALTHY_WRITE_ERROR_WINDOW)
        {
            return CdrHealth::Unhealthy;
        }
        let recent = |stamp: &AtomicU64| s.since(stamp).is_some_and(|d| d < DEGRADED_DROP_WINDOW);
        if recent(&s.last_drop) || recent(&s.last_sink_error) {
            return CdrHealth::Degraded;
        }
        CdrHealth::Healthy
    }

    /// Counter snapshot.
    pub fn stats(&self) -> CdrStats {
        let s = &self.shared;
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        CdrStats {
            emitted: l(&s.emitted),
            dropped_queue_full: l(&s.dropped_full),
            dropped_writer_dead: l(&s.dropped_dead),
            written: l(&s.written),
            write_errors: l(&s.write_errors),
            sink_errors: l(&s.sink_errors),
            sink_dropped: l(&s.sink_dropped),
            queue_depth: l(&s.queue_depth),
            ring_size: s.ring.len() as u64,
            last_write_ms: l(&s.last_write_ms),
            chain_ok: s.chain_ok.load(Ordering::Relaxed),
            writer_alive: s.writer_alive.load(Ordering::Relaxed),
            rotations: l(&s.rotations),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii::HmacKey;
    use crate::record::Disposition;
    use crate::sink::FileSinkConfig;
    use std::path::Path;
    use std::sync::Mutex;

    fn file_cfg(dir: &Path) -> FileSinkConfig {
        FileSinkConfig {
            directory: dir.to_path_buf(),
            rotate_interval: None,
            fsync_interval: Duration::ZERO,
            ..FileSinkConfig::default()
        }
    }

    fn rec(caller: &str) -> CallRecord {
        CallRecord {
            caller: caller.to_string(),
            disposition: Disposition::Answered,
            ..Default::default()
        }
    }

    #[test]
    fn emit_write_verify_ring() {
        let dir = tempfile::tempdir().unwrap();
        let em = CdrEmitter::start(
            CdrEmitterConfig {
                node_id: "n1".into(),
                file: Some(file_cfg(dir.path())),
                ..Default::default()
            },
            Vec::new(),
            None,
        )
        .unwrap();
        for i in 0..10 {
            assert!(em.emit(rec(&format!("100{i}\r\n\u{0}"))));
        }
        assert!(em.flush(Duration::from_secs(5)));
        let st = em.stats();
        assert_eq!(st.emitted, 10);
        assert_eq!(st.written, 10);
        assert_eq!(st.ring_size, 10);
        assert!(st.chain_ok && st.writer_alive);
        assert_eq!(em.health(), CdrHealth::Healthy);
        let r = em.ring().get("n1-3").unwrap();
        assert_eq!(r.sequence, 3);
        assert_eq!(r.hash.len(), 96);
        assert!(em.shutdown(Duration::from_secs(5)));
        assert_eq!(em.stats().rotations, 1);
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        assert_eq!(files.len(), 1);
        let rep = chain::verify_file(&files[0]).unwrap();
        assert_eq!(rep.records, 10);
        assert!(chain::verify_sidecar(&files[0]).unwrap());
        // Emitting after shutdown drops and counts.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!em.emit(rec("x")));
        assert_eq!(em.stats().dropped_writer_dead, 1);
        assert_eq!(em.health(), CdrHealth::Unhealthy);
    }

    /// A sink that blocks until released, so the queue can be filled.
    struct Gate(Arc<Mutex<()>>);
    impl CdrSink for Gate {
        fn name(&self) -> &'static str {
            "gate"
        }
        fn write(&mut self, _: &CallRecord, _: &str) -> std::io::Result<()> {
            drop(self.0.lock().unwrap());
            Ok(())
        }
    }

    #[test]
    fn queue_full_drops_and_counts() {
        #[derive(Default)]
        struct Obs(AtomicU64);
        impl CdrObserver for Obs {
            fn on_drop(&self, _: u64, dead: bool) {
                assert!(!dead);
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let gate = Arc::new(Mutex::new(()));
        let held = gate.lock().unwrap();
        let obs = Arc::new(Obs::default());
        let em = CdrEmitter::start(
            CdrEmitterConfig {
                node_id: "n1".into(),
                queue_capacity: MIN_QUEUE_CAPACITY,
                file: None,
                ..Default::default()
            },
            vec![Box::new(Gate(Arc::clone(&gate)))],
            Some(obs.clone() as Arc<dyn CdrObserver>),
        )
        .unwrap();
        let mut accepted = 0u64;
        for _ in 0..(MIN_QUEUE_CAPACITY * 3) {
            if em.emit(rec("a")) {
                accepted += 1;
            }
        }
        let st = em.stats();
        assert!(st.dropped_queue_full > 0);
        assert_eq!(st.emitted, accepted);
        assert_eq!(st.emitted + st.dropped(), (MIN_QUEUE_CAPACITY * 3) as u64);
        assert_eq!(
            obs.0.load(Ordering::Relaxed),
            1,
            "drop report is rate-limited"
        );
        assert_eq!(em.health(), CdrHealth::Degraded);
        drop(held);
        assert!(em.flush(Duration::from_secs(5)));
        assert!(em.writer_alive());
    }

    struct Boom;
    impl CdrSink for Boom {
        fn name(&self) -> &'static str {
            "boom"
        }
        fn write(&mut self, _: &CallRecord, _: &str) -> std::io::Result<()> {
            panic!("sink panic");
        }
    }

    #[test]
    fn sink_panic_does_not_stop_the_file_writer() {
        let dir = tempfile::tempdir().unwrap();
        let em = CdrEmitter::start(
            CdrEmitterConfig {
                node_id: "n1".into(),
                file: Some(file_cfg(dir.path())),
                ..Default::default()
            },
            vec![Box::new(Boom)],
            None,
        )
        .unwrap();
        assert!(em.emit(rec("a")));
        std::thread::sleep(Duration::from_millis(100));
        assert!(em.emit(rec("b")));
        assert!(em.flush(Duration::from_secs(5)));
        let s = em.stats();
        assert!(em.writer_alive());
        assert_eq!(s.written, 2);
        assert!(s.sink_dropped >= 1, "{s:?}");
        assert_eq!(em.health(), CdrHealth::Degraded);
    }

    struct BoomObserver;
    impl CdrObserver for BoomObserver {
        fn on_rotated(&self, _: &Path, _: &str) {
            panic!("observer panic");
        }
    }

    #[test]
    fn writer_panic_clears_alive() {
        let dir = tempfile::tempdir().unwrap();
        let mut fc = file_cfg(dir.path());
        fc.rotate_size_bytes = 1;
        let em = CdrEmitter::start(
            CdrEmitterConfig {
                node_id: "n1".into(),
                file: Some(fc),
                ..Default::default()
            },
            Vec::new(),
            Some(Arc::new(BoomObserver)),
        )
        .unwrap();
        em.emit(rec("a"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while em.writer_alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!em.writer_alive());
        assert!(!em.emit(rec("b")));
        assert_eq!(em.stats().dropped_writer_dead, 1);
        assert_eq!(em.health(), CdrHealth::Unhealthy);
    }

    #[test]
    fn unwritable_directory_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"x").unwrap();
        let res = CdrEmitter::start(
            CdrEmitterConfig {
                node_id: "n1".into(),
                file: Some(file_cfg(&blocker.join("sub"))),
                ..Default::default()
            },
            Vec::new(),
            None,
        );
        assert!(res.is_err());
    }

    #[test]
    fn config_bounds() {
        let bad = |c: CdrEmitterConfig| CdrEmitter::start(c, Vec::new(), None).is_err();
        assert!(bad(CdrEmitterConfig {
            node_id: "a b".into(),
            file: None,
            ..Default::default()
        }));
        assert!(bad(CdrEmitterConfig {
            queue_capacity: 1,
            file: None,
            ..Default::default()
        }));
        assert!(bad(CdrEmitterConfig {
            ring_capacity: MAX_RING_CAPACITY + 1,
            file: None,
            ..Default::default()
        }));
    }

    #[test]
    fn hash_pii_and_reload() {
        let key = HmacKey::from_bytes(vec![9; 48]).unwrap();
        let policy = PiiPolicy::Hash(key);
        let expect = policy.apply_caller("5550100");
        let em = CdrEmitter::start(
            CdrEmitterConfig {
                node_id: "n1".into(),
                file: None,
                hash_chain: false,
                pii: policy,
                ..Default::default()
            },
            Vec::new(),
            None,
        )
        .unwrap();
        em.emit(rec("5550100"));
        assert!(em.flush(Duration::from_secs(5)));
        let r = em.ring().get("n1-0").unwrap();
        assert_eq!(r.caller, expect);
        assert!(r.hash.is_empty() && r.prev_hash.is_empty());
        assert!(em.reload(CdrReload {
            pii: Some(PiiPolicy::Full),
            retention: None,
        }));
        em.emit(rec("5550100"));
        assert!(em.flush(Duration::from_secs(5)));
        assert_eq!(em.ring().get("n1-1").unwrap().caller, "5550100");
    }

    #[test]
    fn sequence_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let start = || {
            CdrEmitter::start(
                CdrEmitterConfig {
                    node_id: "n1".into(),
                    file: Some(file_cfg(dir.path())),
                    ..Default::default()
                },
                Vec::new(),
                None,
            )
            .unwrap()
        };
        let em = start();
        em.emit(rec("a"));
        em.emit(rec("b"));
        assert!(em.shutdown(Duration::from_secs(5)));
        let em = start();
        em.emit(rec("c"));
        assert!(em.shutdown(Duration::from_secs(5)));
        let mut files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        let paths: Vec<&Path> = files.iter().map(std::path::PathBuf::as_path).collect();
        let reps = chain::verify_files(&paths).unwrap();
        assert_eq!(reps[1].first_sequence, 2);
        assert_eq!(reps[1].last_sequence, Some(2));
    }
}
