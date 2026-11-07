//! Audit log output sinks.
//!
//! Sinks handle the actual output of audit records.
//!
//! ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity)
//!
//! Storage capacity (volume sizing, rotation, retention) is the platform's
//! responsibility; sinks only report write failures (AU-5).
// POAM: POA&M-133 -- no in-process rotation or retention for audit files.

use crate::record::AuditRecord;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

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
/// ## NIST 800-53 Rev5: AU-5 (capacity, AU-4, is managed by the platform)
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
    /// Test hook: the next write persists only this many bytes, then fails.
    #[cfg(test)]
    fail_after: Option<usize>,
}

impl FileState {
    /// Appends one line; on failure truncates back to the last good length.
    fn append_line(&mut self, line: &[u8]) -> io::Result<()> {
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
                } else {
                    let added = u64::try_from(line.len()).unwrap_or(u64::MAX);
                    self.good_len = self.good_len.saturating_add(added);
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
}

/// Sink that appends one JSON record per line to a file.
///
/// Records carry the sequence number and SHA-384 hash chain; the chain
/// resumes from the last complete record on open, so one file holds one
/// contiguous chain across restarts and `uc_audit::verify` (or
/// `sbc-cli audit verify`) can check it for gaps and tampering. Each write
/// is flushed so a crash loses at most the record being written; a failed
/// write is truncated away and reported to the writer.
///
/// ## NIST 800-53 Rev5: AU-5, AU-9 (capacity, AU-4, is managed by the platform)
pub struct FileSink {
    state: std::sync::Mutex<FileState>,
    path: PathBuf,
    resume: ResumePoint,
}

impl FileSink {
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
    /// modified.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information), AC-3, AC-6, SI-10
    ///
    /// # Errors
    /// `PermissionDenied` for a symlink, non-regular file, a path swapped
    /// during open, or a group/world-writable directory; `InvalidData` when
    /// a non-empty file has no valid record within [`RESUME_TAIL_BYTES`] of
    /// its end; otherwise the I/O error.
    // POAM: POA&M-131 -- no O_NOFOLLOW (uc-audit has no libc dependency).
    // The lstat check before open plus the dev/ino comparison after open
    // detects a swapped path, but the open itself can still follow a
    // symlink planted in the window (the target is opened, not modified).
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            prepare_dir(dir)?;
        }
        check_regular(&path)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(FILE_MODE);
        }
        let file = opts.open(&path)?;
        check_same_file(&file, &path)?;
        let (resume, truncate_to) = resume_file(&file, &path)?;
        // The file is an audit file (empty or a valid tail): side effects
        // are now safe.
        if let Some(len) = truncate_to {
            file.set_len(len)?;
        }
        tighten_mode(&file, &path)?;
        let good_len = file.metadata()?.len();
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
                #[cfg(test)]
                fail_after: None,
            }),
            path,
            resume,
        })
    }

    /// The file this sink appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Test hook: make the next write persist `n` bytes and then fail.
    #[cfg(test)]
    fn fail_next_write_after(&self, n: usize) {
        if let Ok(mut st) = self.state.lock() {
            st.fail_after = Some(n);
        }
    }
}

fn poisoned() -> io::Error {
    io::Error::other("audit file sink lock poisoned")
}

impl AuditSink for FileSink {
    fn write(&self, record: &AuditRecord) -> io::Result<()> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut st = self.state.lock().map_err(|_| poisoned())?;
        let result = st.append_line(&line);
        drop(st);
        result
    }

    fn flush(&self) -> io::Result<()> {
        self.state.lock().map_err(|_| poisoned())?.file.flush()
    }

    fn resume_point(&self) -> Option<ResumePoint> {
        Some(self.resume)
    }
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
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
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
}
