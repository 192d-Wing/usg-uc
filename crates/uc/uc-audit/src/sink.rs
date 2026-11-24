//! Audit log output sinks.
//!
//! Sinks handle the actual output of audit records.
//!
//! ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity), AU-5
//!
//! [`FileSink`] rotates its file at a size bound and keeps a bounded number
//! of rotated files, so the audit trail on disk is at most
//! `(max_rotated_files + 1) x max_file_bytes`. When that bound is reached
//! the configured [`CapacityAction`] applies. Off-box shipping (AU-4(1)) is
//! the platform's responsibility.
// POAM: POA&M-430 -- the capacity bound is configured, not measured: no
// free-space check or percentage-of-capacity warning (no statvfs here).

use crate::record::AuditRecord;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

/// Notices queued by a sink for the writer before new ones are dropped
/// (each drop is logged).
///
/// ## NIST 800-53 Rev5: SC-5 (bounded state)
const MAX_PENDING_NOTICES: usize = 1024;

/// What a [`FileSink`] does when a rotation would exceed
/// `max_rotated_files`.
///
/// ## NIST 800-53 Rev5: AU-5 b (Response to Audit Logging Process Failures)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapacityAction {
    /// Delete the oldest rotated file. Each deletion is chained as an
    /// `AuditFileDeleted` record, counted and logged at error level.
    #[default]
    OverwriteOldest,
    /// Keep every file and refuse further records with
    /// [`io::ErrorKind::StorageFull`] until an operator removes rotated
    /// files; the pipeline reports unhealthy meanwhile.
    Stop,
}

impl CapacityAction {
    /// Parses the configuration token (`overwrite_oldest` or `stop`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "overwrite_oldest" => Some(Self::OverwriteOldest),
            "stop" => Some(Self::Stop),
            _ => None,
        }
    }

    /// The configuration token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OverwriteOldest => "overwrite_oldest",
            Self::Stop => "stop",
        }
    }
}

/// Size bound of a [`FileSink`].
///
/// ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSinkOptions {
    /// The file is rotated before an append would make it larger than
    /// this (a single record larger than the bound is still written to an
    /// empty file).
    pub max_file_bytes: u64,
    /// Rotated files kept next to the current file.
    pub max_rotated_files: u32,
    /// Action when a rotation would exceed `max_rotated_files`.
    pub on_full: CapacityAction,
}

impl Default for FileSinkOptions {
    /// 64 MiB files, 16 rotated files, overwrite oldest.
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024,
            max_rotated_files: 16,
            on_full: CapacityAction::OverwriteOldest,
        }
    }
}

/// Largest `max_file_bytes` accepted from settings, in MiB.
pub const MAX_FILE_MB_LIMIT: u32 = 4096;
/// Largest `max_rotated_files` accepted from settings.
pub const MAX_ROTATED_FILES_LIMIT: u32 = 1024;

impl FileSinkOptions {
    /// Options from string settings (environment variables) named
    /// `vars = [max file MiB, max rotated files, on-full action]`. Unset or
    /// blank keeps the default; a set value must be in range (1..=4096 MiB,
    /// 1..=1024 files, `overwrite_oldest` | `stop`), never ignored.
    ///
    /// ## NIST 800-53 Rev5: AU-4, AU-5, CM-6
    ///
    /// # Errors
    /// `(var, reason)` for the first invalid value.
    pub fn from_env_values(
        vars: [&'static str; 3],
        get: impl Fn(&'static str) -> Option<String>,
    ) -> Result<Self, (&'static str, String)> {
        let [mb_var, files_var, full_var] = vars;
        let set = |var| get(var).filter(|v| !v.trim().is_empty());
        let mut o = Self::default();
        let range = |var: &'static str, v: &str, max: u32| {
            v.trim()
                .parse::<u32>()
                .ok()
                .filter(|n| (1..=max).contains(n))
                .ok_or_else(|| (var, format!("must be an integer 1..={max} (got {v:?})")))
        };
        if let Some(v) = set(mb_var) {
            o.max_file_bytes = u64::from(range(mb_var, &v, MAX_FILE_MB_LIMIT)?) * 1024 * 1024;
        }
        if let Some(v) = set(files_var) {
            o.max_rotated_files = range(files_var, &v, MAX_ROTATED_FILES_LIMIT)?;
        }
        if let Some(v) = set(full_var) {
            o.on_full = CapacityAction::parse(v.trim()).ok_or_else(|| {
                (
                    full_var,
                    format!("must be overwrite_oldest or stop (got {v:?})"),
                )
            })?;
        }
        Ok(o)
    }
}

/// A file event the writer chains as an audit record.
///
/// ## NIST 800-53 Rev5: AU-4, AU-5, AU-9
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkNotice {
    /// The current file was closed and renamed to `file`.
    Rotated {
        /// Rotated file path.
        file: PathBuf,
        /// SHA-384 of the closed file.
        sha384: [u8; 48],
        /// Sequence of the last record in the closed file.
        last_sequence: u64,
    },
    /// A rotated file was deleted to stay within the capacity bound, or to
    /// reclaim space after a write failed with `StorageFull`.
    Deleted {
        /// Deleted file path.
        file: PathBuf,
        /// `capacity` or `disk_full`.
        reason: &'static str,
        /// First sequence in the deleted file, when its head parsed.
        first_sequence: Option<u64>,
        /// Last sequence in the deleted file, when its tail parsed.
        last_sequence: Option<u64>,
    },
}

/// Losses a sink can only log, exported for the writer's stats (AU-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SinkCounters {
    /// Notices not chained because the pending queue was full.
    pub notices_dropped: u64,
    /// Rotated files the capacity action failed to delete.
    pub delete_failures: u64,
}

/// Longest a cached rotated-file count is trusted in `stop` mode while the
/// directory is unchanged (SC-5: no directory listing per refused record).
const ROTATED_COUNT_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// Names tried after `<name>.<first sequence>` when it is taken (a chain
/// restarted at genesis next to older rotated files).
const ROTATION_NAME_ATTEMPTS: u64 = 1024;

/// Result of [`AuditSink::write_or_rotate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The record was persisted.
    Written,
    /// The sink rotated instead of writing; the record was not persisted.
    /// The writer chains the pending notices (so `AuditFileRotated` is the
    /// first record of the new file) and then writes the record again.
    Rotated,
}

/// Most bytes read from the end of an existing audit file to find the
/// chain resume point. Audit lines are larger than CDR lines (events carry
/// free-text reasons), so this is larger than uc-cdr's bound.
///
/// ## NIST 800-53 Rev5: SC-5 (bounded startup work on a hostile file)
pub const RESUME_TAIL_BYTES: u64 = 1024 * 1024;

/// Mode of a newly created audit file (owner rw, group r for a log shipper).
const FILE_MODE: u32 = 0o640;
/// Mode of a newly created audit directory.
const DIR_MODE: u32 = 0o750;
/// Bits that must not be set on an audit file: owner x, group w/x, other.
const FILE_MODE_FORBIDDEN: u32 = 0o137;

/// Where a sink's on-disk chain ends, so the writer continues it.
///
/// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePoint {
    /// Sequence number of the next record.
    pub next_sequence: u64,
    /// Hash of the last complete record (zero hash at genesis).
    pub last_hash: [u8; 48],
    /// False when an unterminated or unparsable tail was found; the writer
    /// then chains an `AuditRecordsDropped { reason: TornTail }` marker.
    pub clean: bool,
    /// Bytes of an unterminated final fragment removed at open.
    pub torn_bytes: u64,
    /// Lines lost or unusable at open: complete lines after the last good
    /// record that were unparsable or non-canonical, plus one for a torn
    /// fragment. This is the `count` of the `TornTail` marker.
    pub skipped_lines: u64,
}

impl ResumePoint {
    /// Empty file: start the chain at sequence 0 and the zero hash.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            next_sequence: 0,
            last_hash: [0u8; 48],
            clean: true,
            torn_bytes: 0,
            skipped_lines: 0,
        }
    }
}

/// Trait for audit log output destinations.
///
/// ## NIST 800-53 Rev5: AU-4, AU-5
pub trait AuditSink: Send + Sync {
    /// Writes an audit record to the sink.
    ///
    /// # Errors
    /// Returns the error when the record was not persisted. The writer then
    /// does not advance the chain, counts the loss, and reports the audit
    /// pipeline unhealthy until a write succeeds (AU-5).
    fn write(&self, record: &AuditRecord) -> io::Result<()>;

    /// Flushes any buffered records.
    ///
    /// # Errors
    /// Returns the error when buffered records could not be flushed.
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    /// Where the sink's persisted chain ends, if it has one. `None` (the
    /// default) starts a fresh chain at genesis.
    fn resume_point(&self) -> Option<ResumePoint> {
        None
    }

    /// Writes `record`, unless it would cross the sink's size bound: then
    /// the sink rotates and returns [`WriteOutcome::Rotated`] without
    /// writing it. The default never rotates.
    ///
    /// # Errors
    /// As [`AuditSink::write`]; `StorageFull` when the capacity bound is
    /// reached and the capacity action is `stop`.
    fn write_or_rotate(&self, record: &AuditRecord) -> io::Result<WriteOutcome> {
        self.write(record).map(|()| WriteOutcome::Written)
    }

    /// Takes the file events queued since the last call, oldest first. The
    /// writer chains each as an audit record. The default has none.
    fn take_notices(&self) -> Vec<SinkNotice> {
        Vec::new()
    }

    /// Losses the sink could not report as notices. The default has none.
    fn sink_counters(&self) -> SinkCounters {
        SinkCounters::default()
    }
}

/// Sink that outputs to the tracing framework.
///
/// This integrates audit logs with the standard logging infrastructure.
pub struct TracingSink;

impl AuditSink for TracingSink {
    fn write(&self, record: &AuditRecord) -> io::Result<()> {
        // Use structured logging via tracing
        tracing::info!(
            target: "audit",
            sequence = record.sequence,
            timestamp = %record.timestamp,
            event_type = ?record.event.event_type(),
            hash = %hex::encode(record.hash_chain),
            event = %serde_json::to_string(&record.event).unwrap_or_default(),
            "audit event"
        );
        Ok(())
    }
}

/// Mutable state of a [`FileSink`], locked only by the writer thread.
struct FileState {
    file: std::fs::File,
    /// File length after the last successful write.
    good_len: u64,
    /// A failed write left bytes that could not be truncated; the next
    /// write starts with `\n` so the fragment stays on its own line.
    torn: bool,
    /// Sequence of the first record in the current file (names the file
    /// when it is rotated); `None` while the file is empty.
    first_sequence: Option<u64>,
    /// Sequence of the last record in the current file.
    last_sequence: Option<u64>,
    /// A rotation removed the current name but opening the new file
    /// failed; the next write retries the open.
    reopen: bool,
    /// File events for the writer to chain.
    notices: Vec<SinkNotice>,
    /// Running SHA-384 of the current file's bytes; `None` when unknown
    /// (file resumed at open, or a torn write), then computed at rotation.
    hasher: Option<uc_crypto::hash::Sha384>,
    /// `stop` mode: rotated-file count, the directory mtime it was taken
    /// at, and when.
    rotated_cache: Option<(usize, Option<std::time::SystemTime>, std::time::Instant)>,
    counters: SinkCounters,
    /// Test hook: the next write persists only this many bytes, then fails.
    #[cfg(test)]
    fail_after: Option<usize>,
    /// Test hook: the next write fails with `StorageFull`, writing nothing.
    #[cfg(test)]
    fail_full: bool,
}

impl FileState {
    /// Appends one line; on failure truncates back to the last good length.
    fn append_line(&mut self, line: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_full) {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        let prefix: &[u8] = if self.torn { b"\n" } else { b"" };
        let mut result = self.file.write_all(prefix);
        #[cfg(test)]
        if let Some(n) = self.fail_after.take() {
            let n = n.min(line.len());
            result = result
                .and_then(|()| self.file.write_all(line.get(..n).unwrap_or_default()))
                .and_then(|()| Err(io::Error::other("injected write failure")));
        }
        result = result
            .and_then(|()| self.file.write_all(line))
            .and_then(|()| self.file.flush());
        match result {
            Ok(()) => {
                if self.torn {
                    self.good_len = self.file.metadata()?.len();
                    self.torn = false;
                    // The file holds an untracked fragment.
                    self.hasher = None;
                } else {
                    let added = u64::try_from(line.len()).unwrap_or(u64::MAX);
                    self.good_len = self.good_len.saturating_add(added);
                    if let Some(h) = self.hasher.as_mut() {
                        h.update(line);
                    }
                }
                Ok(())
            }
            Err(e) => {
                // Remove the partial line so the file stays a valid chain.
                let good_len = self.good_len;
                if self.file.set_len(good_len).is_err() {
                    self.torn = true;
                }
                Err(e)
            }
        }
    }

    /// Queues a notice for the writer; beyond [`MAX_PENDING_NOTICES`] the
    /// notice is dropped and logged (SC-5).
    fn notify(&mut self, notice: SinkNotice) {
        if self.notices.len() < MAX_PENDING_NOTICES {
            self.notices.push(notice);
        } else {
            self.counters.notices_dropped = self.counters.notices_dropped.saturating_add(1);
            tracing::error!(?notice, "audit sink notice queue full; notice not chained");
        }
    }
}

/// Sink that appends one JSON record per line to a file.
///
/// Records carry the sequence number and SHA-384 hash chain; the chain
/// resumes from the last complete record on open (or from the newest
/// rotated file when the current one is empty), so the current file and its
/// rotated predecessors hold one contiguous chain across restarts and
/// `uc_audit::verify` (or `sbc-cli audit verify`) can check it for gaps and
/// tampering. Each write is flushed so a crash loses at most the record
/// being written; a failed write is truncated away and reported to the
/// writer.
///
/// Before an append would make the file larger than
/// [`FileSinkOptions::max_file_bytes`], the file is fsynced and renamed to
/// `<name>.<first sequence, 20 digits>` (never over an existing file; after
/// a chain restart at genesis the number continues from the newest existing
/// name, so names only grow) and a new `<name>` is opened with the same
/// checks as [`FileSink::open`]. At most
/// [`FileSinkOptions::max_rotated_files`] rotated files are kept; see
/// [`CapacityAction`]. Only regular files whose name is exactly
/// `<name>.<20 digits>` are counted or deleted, lowest number first, and
/// never the newest.
///
/// ## NIST 800-53 Rev5: AU-4, AU-5, AU-9
pub struct FileSink {
    state: std::sync::Mutex<FileState>,
    path: PathBuf,
    resume: ResumePoint,
    options: FileSinkOptions,
}

impl FileSink {
    /// Opens the audit log at `path` with the default size bound
    /// ([`FileSinkOptions::default`]). See [`FileSink::open_with`].
    ///
    /// # Errors
    /// See [`FileSink::open_with`].
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with(path, FileSinkOptions::default())
    }

    /// Opens (creating or appending to) the audit log at `path` and finds the
    /// chain resume point.
    ///
    /// A missing parent directory is created with mode 0750 and a new file
    /// with mode 0640. The path must be a regular file (a symlink or other
    /// file type is refused) in a directory that is not group- or
    /// world-writable. Only once the file is known to be an audit file (empty,
    /// or its tail holds a valid record) is a broader mode tightened to 0640
    /// and an unterminated final fragment (crash-torn write) truncated and
    /// reported through [`ResumePoint::clean`]; a foreign file is never
    /// modified. When the file is empty and rotated files exist, the chain
    /// resumes from the newest rotated file (which is never modified).
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information), AC-3, AC-6, SI-10
    ///
    /// # Errors
    /// `PermissionDenied` for a symlink, non-regular file, a path swapped
    /// during open, or a group/world-writable directory; `InvalidData` when
    /// a non-empty file has no valid record within [`RESUME_TAIL_BYTES`] of
    /// its end; `InvalidInput` for a zero `max_file_bytes` or a path with
    /// no UTF-8 file name; otherwise the I/O error.
    pub fn open_with(path: impl Into<PathBuf>, options: FileSinkOptions) -> io::Result<Self> {
        let path = path.into();
        if options.max_file_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit max_file_bytes must be greater than 0",
            ));
        }
        if file_name(&path).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("audit path {} has no UTF-8 file name", path.display()),
            ));
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            prepare_dir(dir)?;
        }
        let file = open_current(&path)?;
        let (mut resume, truncate_to) = resume_file(&file, &path)?;
        // The file is an audit file (empty or a valid tail): side effects
        // are now safe.
        if let Some(len) = truncate_to {
            file.set_len(len)?;
        }
        tighten_mode(&file, &path)?;
        let good_len = file.metadata()?.len();
        let (first_sequence, last_sequence) = if good_len == 0 {
            if let Some(rp) = resume_from_rotated(&path) {
                resume = rp;
            }
            (None, None)
        } else {
            let last = resume.next_sequence.checked_sub(1);
            let first = first_record_sequence(&path).or(last);
            (first, last)
        };
        if !resume.clean {
            tracing::error!(
                path = %path.display(),
                next_sequence = resume.next_sequence,
                torn_bytes = resume.torn_bytes,
                skipped_lines = resume.skipped_lines,
                "audit file has a torn or unreadable tail; resuming after the last complete record"
            );
        }
        Ok(Self {
            state: std::sync::Mutex::new(FileState {
                file,
                good_len,
                torn: false,
                first_sequence,
                last_sequence,
                reopen: false,
                notices: Vec::new(),
                hasher: (good_len == 0).then(uc_crypto::hash::Sha384::new),
                rotated_cache: None,
                counters: SinkCounters::default(),
                #[cfg(test)]
                fail_after: None,
                #[cfg(test)]
                fail_full: false,
            }),
            path,
            resume,
            options,
        })
    }

    /// The file this sink appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The size bound this sink enforces.
    #[must_use]
    pub const fn options(&self) -> FileSinkOptions {
        self.options
    }

    /// Test hook: make the next write persist `n` bytes and then fail.
    #[cfg(test)]
    fn fail_next_write_after(&self, n: usize) {
        if let Ok(mut st) = self.state.lock() {
            st.fail_after = Some(n);
        }
    }

    /// Test hook: make the next write fail with `StorageFull`.
    #[cfg(test)]
    fn fail_next_write_full(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.fail_full = true;
        }
    }

    /// Serializes and appends `record`, rotating first when it would cross
    /// the size bound. With `write_through` false, a rotation returns
    /// [`WriteOutcome::Rotated`] without writing.
    fn append(&self, record: &AuditRecord, write_through: bool) -> io::Result<WriteOutcome> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut st = self.state.lock().map_err(|_| poisoned())?;
        if st.reopen {
            st.file = open_current(&self.path)?;
            st.good_len = st.file.metadata()?.len();
            st.hasher = (st.good_len == 0).then(uc_crypto::hash::Sha384::new);
            st.reopen = false;
        }
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if st.good_len > 0 && st.good_len.saturating_add(len) > self.options.max_file_bytes {
            self.rotate(&mut st)?;
            if !write_through {
                return Ok(WriteOutcome::Rotated);
            }
        }
        match st.append_line(&line) {
            // AU-5 b: with overwrite_oldest a full volume reclaims the
            // oldest rotated file (audited) and retries once.
            Err(e)
                if e.kind() == io::ErrorKind::StorageFull
                    && self.options.on_full == CapacityAction::OverwriteOldest =>
            {
                if self.delete_oldest(&mut st, 1, "disk_full")? == 0 {
                    return Err(e);
                }
                st.append_line(&line)?;
            }
            other => other?,
        }
        st.first_sequence.get_or_insert(record.sequence);
        st.last_sequence = Some(record.sequence);
        drop(st);
        Ok(WriteOutcome::Written)
    }

    /// Closes the current file under its rotated name, opens a new one and
    /// applies the capacity action. Runs on the writer thread under the
    /// state lock.
    ///
    /// ## NIST 800-53 Rev5: AU-4, AU-5, AU-9, SI-10 (CWE-59, CWE-367)
    fn rotate(&self, st: &mut FileState) -> io::Result<()> {
        let max = usize::try_from(self.options.max_rotated_files).unwrap_or(usize::MAX);
        if self.options.on_full == CapacityAction::Stop {
            let count = self.rotated_count(st)?;
            if count >= max {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    format!(
                        "audit capacity reached ({count} rotated files of {} bytes, \
                         on_full = stop); archive and remove rotated files to resume",
                        self.options.max_file_bytes
                    ),
                ));
            }
        }
        st.rotated_cache = None;
        st.file.sync_all()?;
        let first = st
            .first_sequence
            .or(st.last_sequence)
            .unwrap_or(self.resume.next_sequence);
        // Names only grow: after a chain restart at genesis next to older
        // rotated files, number from the newest existing name + 1, so name
        // order stays rotation order (no clock involved).
        let number = list_rotated(&self.path)?
            .last()
            .map_or(first, |(n, _)| first.max(n.saturating_add(1)));
        let target = self.link_rotated(number)?;
        let sha384 = match st.hasher.take() {
            Some(h) => h.finish(),
            None => sha384_file(&target)?,
        };
        // The rotated name now holds the file: only then drop the current
        // name and start a new file.
        std::fs::remove_file(&self.path)?;
        sync_parent(&self.path);
        let last_sequence = st.last_sequence.unwrap_or(first);
        st.first_sequence = None;
        st.last_sequence = None;
        st.torn = false;
        st.good_len = 0;
        st.hasher = Some(uc_crypto::hash::Sha384::new());
        match open_current(&self.path) {
            Ok(file) => st.file = file,
            Err(e) => {
                st.reopen = true;
                st.notify(SinkNotice::Rotated {
                    file: target,
                    sha384,
                    last_sequence,
                });
                return Err(e);
            }
        }
        tracing::info!(
            file = %target.display(),
            last_sequence,
            "audit file rotated"
        );
        st.notify(SinkNotice::Rotated {
            file: target,
            sha384,
            last_sequence,
        });
        if self.options.on_full == CapacityAction::OverwriteOldest {
            // The new rotated file is the newest; keep the newest `max`.
            let excess = list_rotated(&self.path)?.len().saturating_sub(max);
            self.delete_oldest(st, excess, "capacity")?;
        }
        Ok(())
    }

    /// Links the current file to `<name>.<first:020>`, or the next free
    /// 20-digit name when that one is taken by another file.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (never overwrites), AU-5
    fn link_rotated(&self, first: u64) -> io::Result<PathBuf> {
        let mut last_err = None;
        for k in 0..ROTATION_NAME_ATTEMPTS {
            let target = rotated_path(&self.path, first.saturating_add(k))?;
            match link_no_clobber(&self.path, &target) {
                Ok(()) => {
                    if k > 0 {
                        tracing::warn!(
                            file = %target.display(),
                            first_sequence = first,
                            "audit rotation name for this sequence was taken; used the next free name"
                        );
                    }
                    return Ok(target);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)))
    }

    /// Rotated-file count for the `stop` check, re-listed only when the
    /// directory changed or the cached count is older than
    /// [`ROTATED_COUNT_TTL`].
    fn rotated_count(&self, st: &mut FileState) -> io::Result<usize> {
        let dir_mtime = self
            .path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .and_then(|d| std::fs::metadata(d).ok())
            .and_then(|m| m.modified().ok());
        if let Some((count, at_mtime, at)) = st.rotated_cache
            && at_mtime == dir_mtime
            && dir_mtime.is_some()
            && at.elapsed() < ROTATED_COUNT_TTL
        {
            return Ok(count);
        }
        let count = list_rotated(&self.path)?.len();
        st.rotated_cache = Some((count, dir_mtime, std::time::Instant::now()));
        Ok(count)
    }

    /// Deletes up to `n` oldest rotated files, queuing a `Deleted` notice
    /// with the lost sequence range for each. Returns how many went.
    ///
    /// ## NIST 800-53 Rev5: AU-4, AU-5 b (each deletion is chained), AU-9
    fn delete_oldest(
        &self,
        st: &mut FileState,
        n: usize,
        reason: &'static str,
    ) -> io::Result<usize> {
        if n == 0 {
            return Ok(0);
        }
        let mut rotated = list_rotated(&self.path)?;
        // Never the newest rotated file (the one just closed).
        rotated.pop();
        let mut deleted = 0;
        for (_, old) in rotated.into_iter().take(n) {
            // Re-check right before deleting: only a regular file.
            let regular = std::fs::symlink_metadata(&old).is_ok_and(|m| m.file_type().is_file());
            if !regular {
                continue;
            }
            let (first_sequence, last_sequence) = file_sequence_range(&old);
            match std::fs::remove_file(&old) {
                Ok(()) => {
                    deleted += 1;
                    tracing::error!(
                        file = %old.display(),
                        reason,
                        first_sequence,
                        last_sequence,
                        max_rotated_files = self.options.max_rotated_files,
                        "audit capacity action: oldest rotated audit file deleted"
                    );
                    st.notify(SinkNotice::Deleted {
                        file: old,
                        reason,
                        first_sequence,
                        last_sequence,
                    });
                }
                Err(e) => {
                    st.counters.delete_failures = st.counters.delete_failures.saturating_add(1);
                    tracing::error!(
                        file = %old.display(),
                        error = %e,
                        "audit capacity action: deleting the oldest rotated file failed"
                    );
                }
            }
        }
        st.rotated_cache = None;
        Ok(deleted)
    }
}

/// First and last record sequence of a closed audit file (bounded reads of
/// its head and tail); `None` for a part that does not parse.
fn file_sequence_range(path: &Path) -> (Option<u64>, Option<u64>) {
    let first = first_record_sequence(path);
    let last = std::fs::File::open(path)
        .and_then(|f| resume_file(&f, path))
        .ok()
        .and_then(|(rp, _)| rp.next_sequence.checked_sub(1));
    (first, last)
}

fn poisoned() -> io::Error {
    io::Error::other("audit file sink lock poisoned")
}

impl AuditSink for FileSink {
    fn write(&self, record: &AuditRecord) -> io::Result<()> {
        self.append(record, true).map(|_| ())
    }

    fn write_or_rotate(&self, record: &AuditRecord) -> io::Result<WriteOutcome> {
        self.append(record, false)
    }

    fn take_notices(&self) -> Vec<SinkNotice> {
        self.state
            .lock()
            .map_or_default(|mut st| std::mem::take(&mut st.notices))
    }

    fn sink_counters(&self) -> SinkCounters {
        self.state.lock().map_or_default(|st| st.counters)
    }

    fn flush(&self) -> io::Result<()> {
        self.state.lock().map_err(|_| poisoned())?.file.flush()
    }

    fn resume_point(&self) -> Option<ResumePoint> {
        Some(self.resume)
    }
}

/// Opens (creating) the current audit file with the symlink and
/// swapped-path checks.
// POAM: POA&M-131 -- no O_NOFOLLOW (uc-audit has no libc dependency).
// The lstat check before open plus the dev/ino comparison after open
// detects a swapped path, but the open itself can still follow a
// symlink planted in the window (the target is opened, not modified).
fn open_current(path: &Path) -> io::Result<std::fs::File> {
    check_regular(path)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(FILE_MODE);
    }
    let file = opts.open(path)?;
    check_same_file(&file, path)?;
    Ok(file)
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|n| n.to_str())
}

/// `<name>.<n:020>` next to `path`. `n` is a monotonic rotation number, at
/// least the file's first sequence (see `FileSink::rotate`), so name order
/// is verify order.
fn rotated_path(path: &Path, first_sequence: u64) -> io::Result<PathBuf> {
    let name = file_name(path).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    Ok(path.with_file_name(format!("{name}.{first_sequence:020}")))
}

/// Rotated regular files of `path`, oldest first by the name's number
/// (names only grow, see `FileSink::rotate`, so this is rotation order and
/// does not depend on the clock). Only names that are exactly
/// `<name>.<20 digits>` count; symlinks and other file types are ignored,
/// never followed.
///
/// ## NIST 800-53 Rev5: AU-9, SI-10 (CWE-59)
fn list_rotated(path: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let Some(name) = file_name(path) else {
        return Ok(Vec::new());
    };
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let fname = entry.file_name();
        let Some(seq) = fname
            .to_str()
            .and_then(|n| n.strip_prefix(name))
            .and_then(|n| n.strip_prefix('.'))
            .filter(|d| d.len() == 20 && d.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|d| d.parse::<u64>().ok())
        else {
            continue;
        };
        // DirEntry::file_type does not follow symlinks.
        if entry.file_type().is_ok_and(|t| t.is_file()) {
            out.push((seq, entry.path()));
        }
    }
    out.sort_unstable_by_key(|(seq, _)| *seq);
    Ok(out)
}

/// Resume point from the newest rotated file, for an empty current file
/// (a crash between rotation and the first append, or the file was moved
/// away). `None` when there are no rotated files. A rotated file whose tail
/// does not parse yields an unclean genesis (the writer chains a marker).
fn resume_from_rotated(path: &Path) -> Option<ResumePoint> {
    let rotated = match list_rotated(path) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "listing rotated audit files failed");
            return None;
        }
    };
    let (_, newest) = rotated.last()?;
    let resumed = std::fs::File::open(newest)
        .and_then(|f| {
            check_same_file(&f, newest)?;
            resume_file(&f, newest)
        })
        .map(|(mut rp, truncate_to)| {
            // A rotated file is never modified: a torn tail stays in place.
            if truncate_to.is_some() {
                rp.clean = false;
            }
            rp
        });
    match resumed {
        Ok(rp) => Some(rp),
        Err(e) => {
            tracing::error!(
                file = %newest.display(),
                error = %e,
                "newest rotated audit file has no usable tail; starting a new chain"
            );
            Some(ResumePoint {
                clean: false,
                skipped_lines: 1,
                ..ResumePoint::genesis()
            })
        }
    }
}

/// Sequence of the first record in `path` (bounded read); `None` when the
/// first line does not parse.
fn first_record_sequence(path: &Path) -> Option<u64> {
    let f = std::fs::File::open(path).ok()?;
    let mut r = io::BufReader::new(f.take(RESUME_TAIL_BYTES));
    let mut line = Vec::new();
    io::BufRead::read_until(&mut r, b'\n', &mut line).ok()?;
    serde_json::from_slice::<AuditRecord>(line.strip_suffix(b"\n")?)
        .ok()
        .map(|rec| rec.sequence)
}

/// SHA-384 of a file, streamed.
fn sha384_file(path: &Path) -> io::Result<[u8; 48]> {
    let mut f = std::fs::File::open(path)?;
    let mut h = uc_crypto::hash::Sha384::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(h.finish())
}

/// Gives `from` the additional name `to`, failing if `to` exists. A hard
/// link is atomic and never replaces an existing file; where links are not
/// supported, falls back to an existence check and rename.
///
/// ## NIST 800-53 Rev5: AU-9 (a rotation never overwrites a file)
fn link_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => Ok(()),
        // A crash between the link and the unlink leaves both names on one
        // file: finish that rotation.
        Err(_) if same_inode(from, to) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(rotation_target_exists(to, &e)),
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            match std::fs::symlink_metadata(to) {
                Ok(_) => Err(rotation_target_exists(
                    to,
                    &io::Error::from(io::ErrorKind::AlreadyExists),
                )),
                Err(nf) if nf.kind() == io::ErrorKind::NotFound => {
                    // Rename into place, then recreate the current name so
                    // the caller's remove_file has a target.
                    std::fs::rename(from, to)?;
                    open_current(from).map(drop)
                }
                Err(other) => Err(other),
            }
        }
        Err(e) => Err(e),
    }
}

/// Both paths are regular files with the same device and inode.
fn same_inode(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::symlink_metadata(a), std::fs::symlink_metadata(b)) {
            (Ok(x), Ok(y)) => {
                x.file_type().is_file()
                    && y.file_type().is_file()
                    && x.dev() == y.dev()
                    && x.ino() == y.ino()
            }
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

fn rotation_target_exists(to: &Path, e: &io::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "audit rotation target {} already exists ({e}); not overwritten, \
             move it aside",
            to.display()
        ),
    )
}

/// Best-effort fsync of the directory holding `path` so the rename is
/// durable.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Creates a missing audit directory with mode 0750; refuses an existing
/// one that is group- or world-writable (another user could swap the file).
///
/// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information), AC-6
fn prepare_dir(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(DIR_MODE);
        }
        return b.create(dir);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "audit directory {} is group- or world-writable (mode {:o}); \
                     remove g+w/o+w",
                    dir.display(),
                    mode & 0o7777
                ),
            ));
        }
    }
    Ok(())
}

fn refused(path: &Path, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("audit path {} {what}; refusing to open", path.display()),
    )
}

/// Refuses an existing audit path that is a symlink or not a regular file.
///
/// ## NIST 800-53 Rev5: AU-9, SI-10 (CWE-59)
fn check_regular(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(refused(path, "is a symlink")),
        Ok(m) if !m.file_type().is_file() => Err(refused(path, "is not a regular file")),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Confirms the opened descriptor is a regular file and is the file now at
/// `path` (not a symlink swapped in between the lstat and the open).
///
/// ## NIST 800-53 Rev5: AU-9, SI-10 (CWE-367)
fn check_same_file(file: &std::fs::File, path: &Path) -> io::Result<()> {
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(refused(path, "is not a regular file"));
    }
    let linked = std::fs::symlink_metadata(path)?;
    if linked.file_type().is_symlink() {
        return Err(refused(path, "was replaced by a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != linked.dev() || opened.ino() != linked.ino() {
            return Err(refused(path, "changed while opening"));
        }
    }
    Ok(())
}

/// Tightens an existing audit file to 0640 when its mode is broader.
#[cfg(unix)]
fn tighten_mode(file: &std::fs::File, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata()?.permissions().mode();
    if mode & FILE_MODE_FORBIDDEN != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
        tracing::warn!(
            path = %path.display(),
            old_mode = format!("{:o}", mode & 0o7777),
            "audit file permissions were broader than 0640; tightened"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn tighten_mode(_file: &std::fs::File, _path: &Path) -> io::Result<()> {
    Ok(())
}

/// Finds the chain resume point of an open audit file. Has no side
/// effects: returns the length to truncate an unterminated final fragment
/// to, which the caller applies only on success.
///
/// ## NIST 800-53 Rev5: AU-9, SI-10 (the file is parsed as untrusted input)
fn resume_file(file: &std::fs::File, path: &Path) -> io::Result<(ResumePoint, Option<u64>)> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok((ResumePoint::genesis(), None));
    }
    let start = len.saturating_sub(RESUME_TAIL_BYTES);
    let mut reader = std::fs::File::open(path)?;
    reader.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity(usize::try_from(len - start).unwrap_or(0));
    reader.take(RESUME_TAIL_BYTES).read_to_end(&mut buf)?;

    let mut skipped_lines = 0u64;
    let mut torn_bytes = 0u64;
    // An unterminated final fragment is a crash-torn write: drop it (once a
    // valid record proves this is an audit file).
    if buf.last() != Some(&b'\n') {
        let keep = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        torn_bytes = u64::try_from(buf.len() - keep).unwrap_or(u64::MAX);
        buf.truncate(keep);
        skipped_lines = 1;
    }
    let mut body: &[u8] = &buf;
    if start > 0 {
        // The read began mid-file: skip the partial first line.
        let skip = body
            .iter()
            .position(|&b| b == b'\n')
            .map_or(body.len(), |i| i + 1);
        body = body.get(skip..).unwrap_or_default();
    }
    let body = body.strip_suffix(b"\n").unwrap_or(body);
    // Walk complete lines newest first; anything unparsable or
    // non-canonical after the last good record is tamper evidence, left in
    // place for the verifier and counted in the marker.
    for line in body.rsplit(|&b| b == b'\n').filter(|_| !body.is_empty()) {
        match crate::record::parse_canonical(line) {
            Ok(r) => {
                let resume = ResumePoint {
                    next_sequence: r.sequence.wrapping_add(1),
                    last_hash: r.hash_chain,
                    clean: skipped_lines == 0,
                    torn_bytes,
                    skipped_lines,
                };
                return Ok((resume, (torn_bytes > 0).then(|| len - torn_bytes)));
            }
            Err(_) => skipped_lines = skipped_lines.saturating_add(1),
        }
    }
    // No valid record: possibly not an audit file at all. Leave it as is.
    Err(no_record(path))
}

fn no_record(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "no parsable audit record in the last {RESUME_TAIL_BYTES} bytes of {}; \
             move the file aside to start a new chain",
            path.display()
        ),
    )
}

/// Sink that collects records in memory (for testing).
#[cfg(test)]
pub struct MemorySink {
    records: std::sync::Mutex<Vec<AuditRecord>>,
}

#[cfg(test)]
impl Default for MemorySink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl MemorySink {
    /// Creates a new memory sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Returns collected records.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().map_or_default(|r| r.clone())
    }
}

#[cfg(test)]
impl AuditSink for MemorySink {
    fn write(&self, record: &AuditRecord) -> io::Result<()> {
        self.records
            .lock()
            .map_err(|_| io::Error::other("memory sink lock poisoned"))?
            .push(record.clone());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn file_sink_appends_one_json_record_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileSink::open(&path).unwrap();
        assert_eq!(sink.path(), path.as_path());
        for seq in 0..2 {
            let event = crate::AuditEvent::SystemStartup(crate::event::SystemStartup {
                version: "test".to_string(),
                config_path: "/dev/null".to_string(),
            });
            let record = AuditRecord::new(seq, event, chrono::Utc::now(), [0u8; 48]);
            sink.write(&record).unwrap();
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        for (i, line) in lines.iter().enumerate() {
            let parsed: AuditRecord = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.sequence, i as u64);
        }
        let _ = std::fs::remove_file(&path);
    }
    use crate::event::{AuditEvent, AuthMethod, AuthenticationAttempt};
    use chrono::Utc;

    #[test]
    fn test_memory_sink() {
        let sink = MemorySink::new();

        let event = AuditEvent::AuthenticationAttempt(AuthenticationAttempt {
            identity: "test".to_string(),
            source_ip: "::1".parse().unwrap(),
            success: true,
            failure_reason: None,
            method: AuthMethod::Digest,
        });

        let record = AuditRecord::new(1, event, Utc::now(), [0u8; 48]);
        sink.write(&record).unwrap();

        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sequence, 1);
    }

    fn ev(i: u64) -> AuditEvent {
        AuditEvent::SystemShutdown(crate::event::SystemShutdown {
            reason: format!("r{i}"),
            graceful: true,
        })
    }

    /// Writes `n` records continuing the sink's resume point.
    fn append(sink: &FileSink, n: u64) {
        let rp = sink.resume_point().unwrap();
        let mut prev = rp.last_hash;
        for seq in rp.next_sequence..rp.next_sequence + n {
            let r = AuditRecord::new(seq, ev(seq), Utc::now(), prev);
            prev = r.hash_chain;
            sink.write(&r).unwrap();
        }
    }

    #[test]
    fn file_sink_resumes_chain_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileSink::open(&path).unwrap();
        assert_eq!(sink.resume_point(), Some(ResumePoint::genesis()));
        append(&sink, 3);
        drop(sink);
        let sink = FileSink::open(&path).unwrap();
        let rp = sink.resume_point().unwrap();
        assert_eq!(rp.next_sequence, 3);
        assert!(rp.clean);
        append(&sink, 2);
        let r = crate::verify::verify_file(&path).unwrap();
        assert_eq!(
            (r.records, r.first_sequence, r.last_sequence),
            (5, Some(0), Some(4))
        );
        assert!(r.anchored);
    }

    #[test]
    fn resume_truncates_unterminated_tail_and_marks_unclean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        append(&FileSink::open(&path).unwrap(), 2);
        let good_len = std::fs::metadata(&path).unwrap().len();
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"{\"sequence\":2,\"times").unwrap();
        }
        let sink = FileSink::open(&path).unwrap();
        let rp = sink.resume_point().unwrap();
        assert!(!rp.clean);
        assert_eq!(rp.next_sequence, 2);
        assert_eq!(rp.torn_bytes, 20);
        assert_eq!(rp.skipped_lines, 1);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), good_len);
        append(&sink, 1);
        assert_eq!(crate::verify::verify_file(&path).unwrap().records, 3);
    }

    #[test]
    fn resume_skips_unparsable_complete_lines_as_unclean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        append(&FileSink::open(&path).unwrap(), 2);
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"garbage\nmore garbage\n").unwrap();
        }
        let rp = FileSink::open(&path).unwrap().resume_point().unwrap();
        assert!(!rp.clean);
        assert_eq!(rp.torn_bytes, 0);
        assert_eq!(rp.skipped_lines, 2);
        assert_eq!(rp.next_sequence, 2);
        // Left in place: the verifier reports it.
        assert!(crate::verify::verify_file(&path).is_err());
    }

    #[test]
    fn resume_fails_on_non_empty_file_without_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, b"not an audit record\n").unwrap();
        let err = FileSink::open(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Only an unterminated fragment: could be a foreign file, so it is
        // refused and left untouched rather than truncated.
        std::fs::write(&path, b"{\"seq").unwrap();
        let err = FileSink::open(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"seq");
    }

    #[cfg(unix)]
    #[test]
    fn foreign_file_is_not_modified() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let content = b"key = value\nsecret = no-newline-at-end";
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = FileSink::open(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), content);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "mode must not be tightened on a foreign file");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_refused_and_target_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.conf");
        std::fs::write(&target, b"no newline").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = dir.path().join("audit.log");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let err = FileSink::open(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&target).unwrap(), b"no newline");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        // A dangling symlink must not create the target either.
        let dangling = dir.path().join("dangling.log");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(FileSink::open(&dangling).is_err());
        assert!(!dir.path().join("nowhere").exists());
        // A directory at the path is not a regular file.
        let d = dir.path().join("d.log");
        std::fs::create_dir(&d).unwrap();
        assert_eq!(
            FileSink::open(&d).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(unix)]
    #[test]
    fn writable_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        for mode in [0o770, 0o757] {
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = FileSink::open(shared.join("audit.log")).err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{mode:o}");
            assert!(!shared.join("audit.log").exists());
        }
    }

    #[test]
    fn resume_skips_non_canonical_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        append(&FileSink::open(&path).unwrap(), 2);
        let text = std::fs::read_to_string(&path).unwrap();
        let last = text.lines().last().unwrap();
        let injected = last.replacen('{', "{\"note\":\"approved\",", 1);
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop();
        let rewritten = format!("{}\n{injected}\n", lines.join("\n"));
        std::fs::write(&path, rewritten).unwrap();
        let rp = FileSink::open(&path).unwrap().resume_point().unwrap();
        assert!(!rp.clean);
        assert_eq!(rp.next_sequence, 1);
        assert_eq!(rp.skipped_lines, 1);
    }

    #[test]
    fn file_sink_truncates_torn_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileSink::open(&path).unwrap();
        append(&sink, 1);
        let len = std::fs::metadata(&path).unwrap().len();
        sink.fail_next_write_after(10);
        let r = AuditRecord::new(1, ev(1), Utc::now(), [0u8; 48]);
        assert!(sink.write(&r).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
        // The writer retries with the unchanged chain position.
        let first = crate::verify::verify_file(&path).unwrap();
        let mut prev = [0u8; 48];
        hex::decode_to_slice(&first.last_hash, &mut prev).unwrap();
        sink.write(&AuditRecord::new(1, ev(1), Utc::now(), prev))
            .unwrap();
        assert_eq!(crate::verify::verify_file(&path).unwrap().records, 2);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_0640_in_0750_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        let path = nested.join("audit.log");
        drop(FileSink::open(&path).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // The process umask can only narrow these.
        assert_eq!(mode(&nested) & !0o750, 0);
        assert_eq!(mode(&path) & !0o640, 0);
        let loose = dir.path().join("loose.log");
        std::fs::write(&loose, b"").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(FileSink::open(&loose).unwrap());
        assert_eq!(mode(&loose), 0o640);
    }

    // ── SR-42: size rotation and AU-4/AU-5 capacity bound (QA-first) ──

    fn opts(
        max_file_bytes: u64,
        max_rotated_files: u32,
        on_full: CapacityAction,
    ) -> FileSinkOptions {
        FileSinkOptions {
            max_file_bytes,
            max_rotated_files,
            on_full,
        }
    }

    /// Bytes of one serialized test record line (they differ by a few bytes
    /// with the sequence width).
    fn line_len() -> u64 {
        let r = AuditRecord::new(10, ev(10), Utc::now(), [0u8; 48]);
        serde_json::to_vec(&r).unwrap().len() as u64 + 1
    }

    /// A file limit that holds four test records.
    fn four_records() -> u64 {
        let l = line_len();
        l * 4 + l / 2
    }

    /// Writes `n` chained records from `(seq, prev)`, advancing both.
    fn chain_n(sink: &FileSink, seq: &mut u64, prev: &mut [u8; 48], n: u64) {
        for _ in 0..n {
            let r = AuditRecord::new(*seq, ev(*seq), Utc::now(), *prev);
            sink.write(&r).unwrap();
            *prev = r.hash_chain;
            *seq += 1;
        }
    }

    /// The 20-digit suffix of a rotated file name `<name>.<first_seq:020>`.
    fn rotated_seq(path: &Path, p: &Path) -> Option<u64> {
        let name = path.file_name()?.to_str()?;
        let digits = p
            .file_name()?
            .to_str()?
            .strip_prefix(name)?
            .strip_prefix('.')?;
        (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| digits.parse().ok())
            .flatten()
    }

    /// Rotated regular files of `path` (not symlinks), sorted by name.
    fn rotated(path: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| rotated_seq(path, p).is_some())
            .filter(|p| std::fs::symlink_metadata(p).unwrap().file_type().is_file())
            .collect();
        v.sort();
        v
    }

    /// Rotated files oldest first, then the current file.
    fn set_paths(path: &Path) -> Vec<PathBuf> {
        let mut v = rotated(path);
        v.push(path.to_path_buf());
        v
    }

    fn verify_set(path: &Path) -> Vec<crate::verify::VerifyReport> {
        let files = set_paths(path);
        let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
        crate::verify::verify_files(&refs).unwrap()
    }

    /// Plan 8 (SR-42b): the sink rotates before an append would cross
    /// `max_file_bytes`; the rotated set plus the current file verify as one
    /// chain, every continuation is anchored to its predecessor, and each
    /// closed file is reported once with its SHA-384 and last sequence.
    /// NIST 800-53 Rev5: AU-4, AU-9
    #[test]
    fn rotates_at_max_file_bytes_and_chain_verifies_across_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let max = four_records();
        let sink =
            FileSink::open_with(&path, opts(max, 64, CapacityAction::OverwriteOldest)).unwrap();
        let (mut seq, mut prev) = (0u64, [0u8; 48]);
        chain_n(&sink, &mut seq, &mut prev, 20);

        let files = set_paths(&path);
        assert!(files.len() >= 5, "expected >= 4 rotations, got {files:?}");
        for f in &files {
            let len = std::fs::metadata(f).unwrap().len();
            assert!(len <= max, "{} is {len} bytes, over {max}", f.display());
        }
        let reps = verify_set(&path);
        assert_eq!(reps.iter().map(|r| r.records).sum::<u64>(), 20);
        assert!(reps.iter().all(|r| r.anchored), "{reps:?}");
        for w in reps.windows(2) {
            assert_eq!(w[1].first_sequence, w[0].last_sequence.map(|s| s + 1));
        }
        // Alone, a continuation file verifies but is unanchored.
        let alone = crate::verify::verify_file(&files[1]).unwrap();
        assert!(!alone.anchored);

        let rot: Vec<(PathBuf, [u8; 48], u64)> = sink
            .take_notices()
            .into_iter()
            .filter_map(|n| match n {
                SinkNotice::Rotated {
                    file,
                    sha384,
                    last_sequence,
                } => Some((file, sha384, last_sequence)),
                SinkNotice::Deleted { .. } => None,
            })
            .collect();
        assert_eq!(rot.len(), files.len() - 1, "one notice per closed file");
        for ((file, sha, last), (p, rep)) in rot.iter().zip(files.iter().zip(&reps)) {
            assert_eq!(file, p);
            assert_eq!(Some(*last), rep.last_sequence);
            assert_eq!(*sha, uc_crypto::hash::sha384(&std::fs::read(p).unwrap()));
        }
        assert!(sink.take_notices().is_empty(), "notices are taken once");
    }

    /// Plan 8: a rotated file is named for the first sequence it holds,
    /// zero-padded to 20 digits, so name order is chronological across a
    /// digit-count boundary (99 -> 100).
    #[test]
    fn rotated_file_name_is_first_sequence_and_sorts_chronologically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileSink::open_with(
            &path,
            opts(four_records(), 64, CapacityAction::OverwriteOldest),
        )
        .unwrap();
        // Continue a chain from sequence 90 so file names cross 99 -> 100.
        let (mut seq, mut prev) = (90u64, [7u8; 48]);
        chain_n(&sink, &mut seq, &mut prev, 24);
        let files = rotated(&path);
        assert!(files.len() >= 4, "{files:?}");
        let mut by_number = files.clone();
        by_number.sort_by_key(|p| rotated_seq(&path, p).unwrap());
        assert_eq!(files, by_number, "lexical order is sequence order");
        for f in &files {
            let rep = crate::verify::verify_file(f).unwrap();
            assert_eq!(rep.first_sequence, rotated_seq(&path, f), "{}", f.display());
        }
        assert!(
            files
                .iter()
                .any(|f| rotated_seq(&path, f).is_some_and(|s| s >= 100)),
            "the test must cross the 3-digit boundary"
        );
    }

    /// Plan 8 / decision (a): `overwrite_oldest` keeps at most
    /// `max_rotated_files` rotated files (bound `(N+1) x max_file_bytes`),
    /// deleting the oldest and reporting each deletion.
    /// NIST 800-53 Rev5: AU-4, AU-5
    #[test]
    fn overwrite_oldest_bounds_file_count_and_emits_deleted_notice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let max = four_records();
        let sink =
            FileSink::open_with(&path, opts(max, 3, CapacityAction::OverwriteOldest)).unwrap();
        let (mut seq, mut prev) = (0u64, [0u8; 48]);
        chain_n(&sink, &mut seq, &mut prev, 40);

        let kept = rotated(&path);
        assert_eq!(kept.len(), 3, "{kept:?}");
        let total: u64 = set_paths(&path)
            .iter()
            .map(|p| std::fs::metadata(p).unwrap().len())
            .sum();
        assert!(total <= 4 * max, "capacity bound: {total} > {}", 4 * max);

        let notices = sink.take_notices();
        let rotations = notices
            .iter()
            .filter(|n| matches!(n, SinkNotice::Rotated { .. }))
            .count();
        let deleted: Vec<PathBuf> = notices
            .into_iter()
            .filter_map(|n| match n {
                SinkNotice::Deleted { file, .. } => Some(file),
                SinkNotice::Rotated { .. } => None,
            })
            .collect();
        assert_eq!(deleted.len(), rotations - 3, "one notice per deleted file");
        let oldest_kept = rotated_seq(&path, &kept[0]).unwrap();
        for d in &deleted {
            assert!(!d.exists(), "{} still exists", d.display());
            assert!(
                rotated_seq(&path, d).unwrap() < oldest_kept,
                "oldest deleted first"
            );
        }
        // What is left still verifies (its head is unanchored) and ends at
        // the last record written.
        let reps = verify_set(&path);
        assert!(!reps[0].anchored);
        assert!(reps[1..].iter().all(|r| r.anchored));
        assert_eq!(reps.last().unwrap().last_sequence, Some(39));
    }

    /// Plan 8: `stop` keeps the current file, fails the write with
    /// `StorageFull` once the rotated set is full (nothing deleted, chain
    /// position unchanged), and recovers once an operator removes files.
    /// NIST 800-53 Rev5: AU-5
    #[test]
    fn stop_mode_fails_write_with_storage_full_and_recovers_after_files_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let max = four_records();
        let sink = FileSink::open_with(&path, opts(max, 2, CapacityAction::Stop)).unwrap();
        let (mut seq, mut prev) = (0u64, [0u8; 48]);
        let err = loop {
            assert!(seq < 100, "stop mode never refused a write");
            let r = AuditRecord::new(seq, ev(seq), Utc::now(), prev);
            match sink.write(&r) {
                Ok(()) => {
                    prev = r.hash_chain;
                    seq += 1;
                }
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::StorageFull, "{err}");
        let kept = rotated(&path);
        assert_eq!(kept.len(), 2);
        assert!(
            !sink
                .take_notices()
                .iter()
                .any(|n| matches!(n, SinkNotice::Deleted { .. })),
            "stop mode never deletes"
        );
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len <= max);
        // Still full: the retry fails and the file is unchanged.
        let r = AuditRecord::new(seq, ev(seq), Utc::now(), prev);
        assert_eq!(
            sink.write(&r).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
        // An operator archives the oldest file: the same record now persists.
        std::fs::remove_file(&kept[0]).unwrap();
        sink.write(&r).unwrap();
        prev = r.hash_chain;
        seq += 1;
        chain_n(&sink, &mut seq, &mut prev, 1);
        let reps = verify_set(&path);
        assert_eq!(reps.last().unwrap().last_sequence, Some(seq - 1));
        assert!(reps[1..].iter().all(|r| r.anchored));
    }

    /// Plan 8: a crash between the rename and the first append leaves an
    /// empty (or missing) current file next to rotated files. Resume must
    /// continue from the newest rotated file, not restart at sequence 0.
    /// NIST 800-53 Rev5: AU-9
    #[test]
    fn resume_after_rotation_with_empty_current_continues_sequence() {
        for missing in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("audit.log");
            let o = || opts(four_records(), 64, CapacityAction::OverwriteOldest);
            let (mut seq, mut prev) = (0u64, [0u8; 48]);
            {
                let sink = FileSink::open_with(&path, o()).unwrap();
                chain_n(&sink, &mut seq, &mut prev, 10);
            }
            // Finish the rotation the crash interrupted: rename the current
            // file to its rotated name, leave an empty (or no) current file.
            let first = crate::verify::verify_file(&path)
                .unwrap()
                .first_sequence
                .unwrap();
            let target = dir.path().join(format!("audit.log.{first:020}"));
            std::fs::rename(&path, &target).unwrap();
            if !missing {
                std::fs::write(&path, b"").unwrap();
            }
            let sink = FileSink::open_with(&path, o()).unwrap();
            let rp = sink.resume_point().unwrap();
            assert_eq!(rp.next_sequence, 10, "missing current = {missing}");
            assert_eq!(rp.last_hash, prev);
            assert!(rp.clean);
            chain_n(&sink, &mut seq, &mut prev, 2);
            let reps = verify_set(&path);
            assert!(reps.iter().all(|r| r.anchored), "{reps:?}");
            assert_eq!(reps.iter().map(|r| r.records).sum::<u64>(), 12);
        }
    }

    /// Plan 8: only exact `<name>.<20 digits>` regular files are rotation
    /// candidates; a planted symlink with that name, its target, and other
    /// look-alike names are never deleted or followed.
    /// NIST 800-53 Rev5: AU-9, SI-10 (CWE-59)
    #[cfg(unix)]
    #[test]
    fn rotation_never_deletes_foreign_or_symlinked_files() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let victim = other.path().join("victim.conf");
        std::fs::write(&victim, b"keep me").unwrap();
        let link = dir.path().join("audit.log.00000000000000000001");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let foreign = [
            "audit.log.bak",
            "audit.log.123",
            "audit.log.0000000000000000000x",
            "audit.log.000000000000000000001",
            "audit.logx.00000000000000000000",
        ];
        for f in foreign {
            std::fs::write(dir.path().join(f), f.as_bytes()).unwrap();
        }
        let sink = FileSink::open_with(
            &path,
            opts(four_records(), 1, CapacityAction::OverwriteOldest),
        )
        .unwrap();
        let (mut seq, mut prev) = (0u64, [0u8; 48]);
        chain_n(&sink, &mut seq, &mut prev, 30);

        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        for f in foreign {
            assert_eq!(
                std::fs::read(dir.path().join(f)).unwrap(),
                f.as_bytes(),
                "{f}"
            );
        }
        assert!(rotated(&path).len() <= 1);
        assert!(
            !sink
                .take_notices()
                .iter()
                .any(|n| matches!(n, SinkNotice::Deleted { file, .. } if file == &link)),
        );
    }

    /// Plan 8: a regular file already at the rotation target is never
    /// overwritten, and no record reported as written is lost.
    /// NIST 800-53 Rev5: AU-9, AU-5
    #[test]
    fn rotation_target_exists_is_refused_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let planted = dir.path().join("audit.log.00000000000000000000");
        std::fs::write(&planted, b"precious\n").unwrap();
        let sink = FileSink::open_with(
            &path,
            opts(four_records(), 8, CapacityAction::OverwriteOldest),
        )
        .unwrap();
        let (mut seq, mut prev) = (0u64, [0u8; 48]);
        let mut persisted = Vec::new();
        for _ in 0..12 {
            let r = AuditRecord::new(seq, ev(seq), Utc::now(), prev);
            if sink.write(&r).is_ok() {
                persisted.push(seq);
                prev = r.hash_chain;
                seq += 1;
            }
        }
        assert_eq!(std::fs::read(&planted).unwrap(), b"precious\n");
        assert_ne!(persisted, [] as [u64; 0]);
        // Every record the sink accepted is on disk, in one verifiable chain
        // that does not include the planted file.
        let mut on_disk = Vec::new();
        let mut files: Vec<PathBuf> = rotated(&path)
            .into_iter()
            .filter(|p| p != &planted)
            .collect();
        files.push(path);
        let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
        crate::verify::verify_files(&refs).unwrap();
        for f in &files {
            for line in std::fs::read_to_string(f).unwrap().lines() {
                on_disk.push(serde_json::from_str::<AuditRecord>(line).unwrap().sequence);
            }
        }
        assert_eq!(on_disk, persisted);
    }

    /// Settings are enforced or rejected, never ignored.
    /// NIST 800-53 Rev5: AU-4, CM-6
    #[test]
    fn options_from_env_values_bounds() {
        const V: [&str; 3] = ["MB", "FILES", "FULL"];
        let with = |pairs: &[(&'static str, &'static str)]| {
            let pairs = pairs.to_vec();
            FileSinkOptions::from_env_values(V, move |k| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_string())
            })
        };
        assert_eq!(with(&[]).unwrap(), FileSinkOptions::default());
        assert_eq!(with(&[("MB", " ")]).unwrap(), FileSinkOptions::default());
        let o = with(&[("MB", "4096"), ("FILES", "1"), ("FULL", "stop")]).unwrap();
        assert_eq!(o.max_file_bytes, 4096 * 1024 * 1024);
        assert_eq!(o.max_rotated_files, 1);
        assert_eq!(o.on_full, CapacityAction::Stop);
        for (bad, var) in [
            (("MB", "0"), "MB"),
            (("MB", "4097"), "MB"),
            (("MB", "x"), "MB"),
            (("FILES", "0"), "FILES"),
            (("FILES", "1025"), "FILES"),
            (("FULL", "halt"), "FULL"),
        ] {
            assert_eq!(with(&[bad]).unwrap_err().0, var, "{bad:?}");
        }
    }

    /// SR-42 round 1 (SEC-006): with `overwrite_oldest`, a write that fails
    /// with `StorageFull` deletes the oldest rotated file (`disk_full`, with
    /// its sequence range) and succeeds on the retry.
    /// NIST 800-53 Rev5: AU-5 b
    #[test]
    fn overwrite_oldest_reclaims_on_storage_full() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileSink::open_with(
            &path,
            opts(four_records(), 8, CapacityAction::OverwriteOldest),
        )
        .unwrap();
        let (mut seq, mut prev) = (0u64, [0u8; 48]);
        chain_n(&sink, &mut seq, &mut prev, 10);
        let before = rotated(&path);
        assert_eq!(before.len(), 2);
        sink.take_notices();
        sink.fail_next_write_full();
        chain_n(&sink, &mut seq, &mut prev, 1);
        assert!(!before[0].exists(), "oldest reclaimed");
        let n = sink.take_notices();
        assert!(
            n.iter().any(|n| matches!(
                n,
                SinkNotice::Deleted {
                    reason: "disk_full",
                    first_sequence: Some(0),
                    last_sequence: Some(3),
                    ..
                }
            )),
            "{n:?}"
        );
        // Stop mode never deletes: the error is returned.
        let dir2 = tempfile::tempdir().unwrap();
        let p2 = dir2.path().join("audit.log");
        let s2 = FileSink::open_with(&p2, opts(four_records(), 8, CapacityAction::Stop)).unwrap();
        let (mut q, mut h) = (0u64, [0u8; 48]);
        chain_n(&s2, &mut q, &mut h, 10);
        s2.fail_next_write_full();
        let r = AuditRecord::new(q, ev(q), Utc::now(), h);
        assert_eq!(s2.write(&r).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(rotated(&p2).len(), 2);
        // SEC-014: reclaim never deletes the newest rotated file.
        let dir3 = tempfile::tempdir().unwrap();
        let p3 = dir3.path().join("audit.log");
        let s3 = FileSink::open_with(
            &p3,
            opts(four_records(), 8, CapacityAction::OverwriteOldest),
        )
        .unwrap();
        let (mut q, mut h) = (0u64, [0u8; 48]);
        chain_n(&s3, &mut q, &mut h, 5);
        assert_eq!(rotated(&p3).len(), 1);
        s3.fail_next_write_full();
        let r = AuditRecord::new(q, ev(q), Utc::now(), h);
        assert_eq!(s3.write(&r).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(rotated(&p3).len(), 1, "the only rotated file is kept");
    }

    /// SR-42 round 1/2 (SEC-008, SEC-014): a chain restarted at genesis next
    /// to older rotated files neither halts on the taken name nor deletes
    /// its own newest files at capacity: its names continue above the
    /// older ones, and the order does not depend on mtimes (set back here).
    /// NIST 800-53 Rev5: AU-9, AU-5
    #[test]
    fn genesis_restart_uses_free_name_and_evicts_by_age() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let o = || opts(four_records(), 3, CapacityAction::OverwriteOldest);
        let old: Vec<PathBuf> = {
            let sink = FileSink::open_with(&path, o()).unwrap();
            let (mut seq, mut prev) = (0u64, [0u8; 48]);
            chain_n(&sink, &mut seq, &mut prev, 10);
            rotated(&path)
        };
        assert_eq!(old.len(), 2);
        // The operator moves the current file away: next start is genesis
        // (the newest rotated tail is made unreadable to force it).
        std::fs::remove_file(&path).unwrap();
        std::fs::write(old.last().unwrap(), b"garbage\n").unwrap();
        // A clock step: the older chain's files look newer than anything the
        // restarted chain writes.
        let t = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        for p in &old {
            std::fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let sink = FileSink::open_with(&path, o()).unwrap();
        assert_eq!(sink.resume_point().unwrap().next_sequence, 0);
        let (mut seq, mut prev) = (0u64, [0u8; 48]);
        chain_n(&sink, &mut seq, &mut prev, 13);
        let now = rotated(&path);
        assert_eq!(now.len(), 3, "{now:?}");
        for p in &old {
            assert!(!p.exists(), "older-chain file {} kept", p.display());
        }
        // Every record of the new chain is still on disk (newest kept).
        let mut files = now;
        files.sort_by_key(|p| crate::verify::verify_file(p).unwrap().first_sequence);
        files.push(path);
        let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
        let reports = crate::verify::verify_files(&refs).unwrap();
        assert_eq!(reports.last().unwrap().last_sequence, Some(12));
    }
}
