//! CDR sinks: rotated local files and RFC 5424 syslog over a caller-supplied
//! (TLS) stream.
//!
//! The file sink runs on the writer thread; each secondary sink (syslog) runs
//! on its own thread behind its own bounded queue. Neither runs on a
//! signaling task.
//!
//! ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity), AU-9, AU-11

use crate::chain::{self, GENESIS, HASH_LEN, from_hex, to_hex};
use crate::error::{CdrError, CdrResult};
use crate::format::{self, CdrFormat};
use crate::record::CallRecord;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use uc_crypto::hash::Sha384;

/// Bytes read from the end of the newest file when resuming the chain.
const RESUME_TAIL_BYTES: u64 = 256 * 1024;

/// Newest files examined for a resume point before startup fails.
const RESUME_MAX_FILES: usize = 8;

/// Delay between syslog reconnect attempts.
const SYSLOG_RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// Notifications from the writer thread (rotation, write failures).
///
/// Called on the writer thread, except `on_drop` which runs on the emitting task and
/// must not block. Implementations typically raise uc-audit events.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
pub trait CdrObserver: Send + Sync {
    /// A file was closed and its `.sha384` sidecar written.
    fn on_rotated(&self, _file: &Path, _sha384_hex: &str) {}
    /// The file sink failed to write or open a file.
    fn on_write_error(&self, _error: &io::Error) {}
    /// Records are being dropped (rate-limited; called at most once per
    /// report interval).
    fn on_drop(&self, _dropped_total: u64, _writer_dead: bool) {}
}

/// A secondary CDR sink (the file sink is built in).
pub trait CdrSink: Send {
    /// Short name for logs.
    fn name(&self) -> &'static str;
    /// Writes one sealed record; `json_line` is its canonical JSON.
    fn write(&mut self, record: &CallRecord, json_line: &str) -> io::Result<()>;
    /// Flushes buffered output.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// File sink settings.
#[derive(Debug, Clone)]
pub struct FileSinkConfig {
    /// Absolute directory for CDR files.
    pub directory: PathBuf,
    /// File format.
    pub format: CdrFormat,
    /// Rotate once a file reaches this many bytes (0 = never by size).
    pub rotate_size_bytes: u64,
    /// Rotate a non-empty file after this long (`None` = size only).
    pub rotate_interval: Option<Duration>,
    /// Keep at most this many closed files (0 = unlimited).
    pub retention_files: u32,
    /// Delete closed files older than this many days (0 = unlimited).
    pub retention_days: u32,
    /// fsync at most this often (zero = after every record).
    pub fsync_interval: Duration,
}

impl Default for FileSinkConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("/var/lib/usg-sbc/cdr"),
            format: CdrFormat::Jsonl,
            rotate_size_bytes: 100 * 1024 * 1024,
            rotate_interval: Some(Duration::from_secs(3600)),
            retention_files: 168,
            retention_days: 90,
            fsync_interval: Duration::from_secs(1),
        }
    }
}

/// Where the chain resumes after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePoint {
    /// Sequence for the next record.
    pub next_sequence: u64,
    /// Chain value the next record links to.
    pub last_hash: [u8; HASH_LEN],
    /// False when the newest file existed but its tail could not be read
    /// (torn write, foreign content): the on-disk chain has a break.
    pub clean: bool,
}

struct OpenCdrFile {
    path: PathBuf,
    file: File,
    bytes: u64,
    records: u64,
    opened: SystemTime,
    hasher: Sha384,
    last_sync: Instant,
    dirty: bool,
}

/// Rotating file sink.
///
/// Files are `cdr-{node}-{YYYYmmddTHHMMSS}[_NNN].{jsonl|csv}`, mode 0640 in a
/// 0750 directory. Each closed file gets a `.sha384` sidecar (`sha384sum`
/// format).
///
/// ## NIST 800-53 Rev5: AU-4, AU-9 (Protection of Audit Information), AU-11 (Retention)
pub struct FileSink {
    cfg: FileSinkConfig,
    node_id: String,
    current: Option<OpenCdrFile>,
    observer: Option<Arc<dyn CdrObserver>>,
    rotations: u64,
}

impl std::fmt::Debug for FileSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSink")
            .field("cfg", &self.cfg)
            .field("node_id", &self.node_id)
            .field("current", &self.current.as_ref().map(|c| &c.path))
            .finish_non_exhaustive()
    }
}

fn now_ms(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Whether `node_id` is safe in a file name and a syslog header.
pub fn valid_node_id(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id.len() <= 64
        && node_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl FileSink {
    /// Creates the directory (0750) if needed, recovers the chain position
    /// from the newest existing file and opens a new file. Fails if the
    /// directory is not writable (fail closed at startup).
    ///
    /// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
    pub fn open(
        cfg: FileSinkConfig,
        node_id: &str,
        hash_chain: bool,
        observer: Option<Arc<dyn CdrObserver>>,
    ) -> CdrResult<(Self, ResumePoint)> {
        if !cfg.directory.is_absolute() {
            return Err(CdrError::config("cdr directory must be an absolute path"));
        }
        if !valid_node_id(node_id) {
            return Err(CdrError::config(
                "node_id must be 1-64 characters of [A-Za-z0-9._-]",
            ));
        }
        create_dir(&cfg.directory)?;
        let mut sink = Self {
            cfg,
            node_id: node_id.to_string(),
            current: None,
            observer,
            rotations: 0,
        };
        let resume = sink.resume_point()?;
        let start = if hash_chain {
            to_hex(&resume.last_hash)
        } else {
            String::new()
        };
        sink.open_new(&start, resume.next_sequence, SystemTime::now())?;
        Ok((sink, resume))
    }

    /// Files closed so far.
    pub const fn rotations(&self) -> u64 {
        self.rotations
    }

    /// Path of the open file, if any.
    pub fn current_path(&self) -> Option<&Path> {
        self.current.as_ref().map(|c| c.path.as_path())
    }

    /// Updates retention (hot reload).
    pub const fn set_retention(&mut self, files: u32, days: u32) {
        self.cfg.retention_files = files;
        self.cfg.retention_days = days;
    }

    fn prefix(&self) -> String {
        format!("cdr-{}-", self.node_id)
    }

    /// Closed and open CDR files of this node and format, oldest first.
    fn list_files(&self) -> io::Result<Vec<PathBuf>> {
        let prefix = self.prefix();
        let suffix = format!(".{}", self.cfg.format.extension());
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.cfg.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            // Timestamp must follow the node id, so node "a" does not match
            // node "a-b" files.
            let ts_ok = rest.len() > 15
                && rest
                    .as_bytes()
                    .get(..8)
                    .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
                && rest.as_bytes().get(8) == Some(&b'T');
            if ts_ok && name.ends_with(&suffix) && entry.file_type()?.is_file() {
                out.push(entry.path());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Resumes from the newest file that still holds a complete record or
    /// header, so a torn or hostile tail never restarts the sequence at 0
    /// while files exist (that would duplicate `record_id`s).
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information), AU-12
    fn resume_point(&self) -> CdrResult<ResumePoint> {
        let files = self.list_files()?;
        if files.is_empty() {
            return Ok(ResumePoint {
                next_sequence: 0,
                last_hash: GENESIS,
                clean: true,
            });
        }
        let mut clean = true;
        for path in files.iter().rev().take(RESUME_MAX_FILES) {
            let (tail, truncated) = read_tail(path)?;
            let found = match self.cfg.format {
                CdrFormat::Jsonl => resume_jsonl(&tail),
                CdrFormat::Csv => resume_csv(&tail, truncated),
            };
            if let Some(mut r) = found {
                r.clean &= clean;
                if !r.clean {
                    tracing::error!(
                        file = %path.display(),
                        next_sequence = r.next_sequence,
                        "CDR file has a torn or unreadable tail; resuming after the last complete record"
                    );
                }
                return Ok(r);
            }
            clean = false;
        }
        if files.len() <= RESUME_MAX_FILES {
            // Every file was examined and none holds a complete record, so
            // no record_id exists that a fresh chain could duplicate.
            tracing::error!(
                directory = %self.cfg.directory.display(),
                "no complete CDR record on disk; starting a new chain"
            );
            return Ok(ResumePoint {
                next_sequence: 0,
                last_hash: GENESIS,
                clean: false,
            });
        }
        // Nothing usable in the newest files: refuse rather than reuse
        // sequence numbers that may already be on disk.
        Err(CdrError::config(format!(
            "cannot resume the CDR chain from the newest {RESUME_MAX_FILES} files in {}; \
             move the damaged files aside to start a new chain",
            self.cfg.directory.display()
        )))
    }

    fn file_name(&self, now: SystemTime) -> PathBuf {
        let ts = chrono::DateTime::<chrono::Utc>::from(now).format("%Y%m%dT%H%M%S");
        let ext = self.cfg.format.extension();
        let base = format!("cdr-{}-{ts}", self.node_id);
        let mut path = self.cfg.directory.join(format!("{base}.{ext}"));
        let mut n = 1u32;
        // `_NNN` sorts after `.ext`, keeping lexical order chronological.
        while path.exists() && n < 1000 {
            path = self.cfg.directory.join(format!("{base}_{n:03}.{ext}"));
            n += 1;
        }
        path
    }

    fn open_new(
        &mut self,
        chain_start: &str,
        first_sequence: u64,
        now: SystemTime,
    ) -> CdrResult<()> {
        let path = self.file_name(now);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o640);
        }
        let file = opts.open(&path)?;
        let header = format::new_header(
            &self.node_id,
            now_ms(now),
            chain_start.to_string(),
            first_sequence,
        );
        let mut head = match self.cfg.format {
            CdrFormat::Jsonl => format::header_json_line(&header)?,
            CdrFormat::Csv => {
                let mut s = format::csv_comment(&header);
                s.push('\n');
                s.push_str(&format::csv_header());
                s
            }
        };
        head.push('\n');
        let mut f = OpenCdrFile {
            path,
            file,
            bytes: 0,
            records: 0,
            opened: now,
            hasher: Sha384::new(),
            last_sync: Instant::now(),
            dirty: false,
        };
        f.file.write_all(head.as_bytes())?;
        f.hasher.update(head.as_bytes());
        f.bytes = head.len() as u64;
        f.dirty = true;
        self.current = Some(f);
        Ok(())
    }

    /// Writes one sealed record, opening a new file first when none is open.
    pub fn write_record(&mut self, record: &CallRecord, json_line: &str) -> io::Result<()> {
        if self.current.is_none() {
            self.open_new(&record.prev_hash, record.sequence, SystemTime::now())
                .map_err(|e| cdr_to_io(&e))?;
        }
        let mut line = match self.cfg.format {
            CdrFormat::Jsonl => json_line.to_string(),
            CdrFormat::Csv => format::to_csv_row(record).map_err(|e| cdr_to_io(&e))?,
        };
        line.push('\n');
        let every_record = self.cfg.fsync_interval.is_zero();
        let Some(f) = self.current.as_mut() else {
            return Err(io::Error::other("no CDR file open"));
        };
        if let Err(e) = f.file.write_all(line.as_bytes()) {
            // Drop the (possibly partially written) file; the next record
            // opens a fresh one. The sidecar is skipped: content is suspect.
            self.current = None;
            return Err(e);
        }
        f.hasher.update(line.as_bytes());
        f.bytes += line.len() as u64;
        f.records += 1;
        f.dirty = true;
        if every_record {
            f.file.sync_data()?;
            f.dirty = false;
            f.last_sync = Instant::now();
        }
        if self.cfg.rotate_size_bytes > 0 && f.bytes >= self.cfg.rotate_size_bytes {
            self.close_current()?;
        }
        Ok(())
    }

    /// Periodic work: fsync and time-based rotation.
    pub fn tick(&mut self, now: SystemTime) -> io::Result<()> {
        let interval = self.cfg.rotate_interval;
        let fsync_every = self.cfg.fsync_interval;
        let Some(f) = self.current.as_mut() else {
            return Ok(());
        };
        if f.dirty && f.last_sync.elapsed() >= fsync_every {
            f.file.sync_data()?;
            f.dirty = false;
            f.last_sync = Instant::now();
        }
        if let Some(iv) = interval {
            let age = now.duration_since(f.opened).unwrap_or(Duration::ZERO);
            if f.records > 0 && age >= iv {
                self.close_current()?;
            }
        }
        Ok(())
    }

    /// Flushes the open file to disk.
    pub fn sync(&mut self) -> io::Result<()> {
        if let Some(f) = self.current.as_mut() {
            f.file.sync_data()?;
            f.dirty = false;
            f.last_sync = Instant::now();
        }
        Ok(())
    }

    /// Closes the open file: fsync, `.sha384` sidecar, retention.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information), AU-11
    pub fn close_current(&mut self) -> io::Result<()> {
        let Some(f) = self.current.take() else {
            return Ok(());
        };
        f.file.sync_all()?;
        let digest = to_hex(&f.hasher.finish());
        let name = f
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let side = chain::sidecar_path(&f.path);
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o640);
        }
        let mut sf = opts.open(&side)?;
        sf.write_all(format!("{digest}  {name}\n").as_bytes())?;
        sf.sync_all()?;
        self.rotations += 1;
        if let Some(obs) = &self.observer {
            obs.on_rotated(&f.path, &digest);
        }
        self.apply_retention(SystemTime::now())
    }

    // POAM: NIST-05 (AU-5(1)) no free-space check or capacity-threshold
    // alert; capacity is bounded only by retention vs. volume size (config
    // rejects 0/0 and the Helm chart sizes retention to its CDR volume).
    /// Deletes closed files beyond `retention_files` or older than
    /// `retention_days`. The open file is never deleted.
    ///
    /// There is no free-space check or capacity alert: the volume must be
    /// sized for `retention_files` x `rotate_size_mb`.
    ///
    /// ## NIST 800-53 Rev5: AU-11 (Audit Record Retention), SI-12
    pub fn apply_retention(&self, now: SystemTime) -> io::Result<()> {
        let open = self.current_path().map(Path::to_path_buf);
        let mut closed: Vec<PathBuf> = self
            .list_files()?
            .into_iter()
            .filter(|p| Some(p) != open.as_ref())
            .collect();
        let mut doomed = Vec::new();
        if self.cfg.retention_days > 0 {
            let max_age = Duration::from_secs(u64::from(self.cfg.retention_days) * 86_400);
            closed.retain(|p| {
                let old = std::fs::metadata(p)
                    .and_then(|m| m.modified())
                    .is_ok_and(|m| now.duration_since(m).unwrap_or(Duration::ZERO) > max_age);
                if old {
                    doomed.push(p.clone());
                }
                !old
            });
        }
        let keep = self.cfg.retention_files as usize;
        if keep > 0 && closed.len() > keep {
            let excess = closed.len() - keep;
            doomed.extend(closed.drain(..excess));
        }
        for p in doomed {
            std::fs::remove_file(&p)?;
            let side = chain::sidecar_path(&p);
            if side.exists() {
                std::fs::remove_file(side)?;
            }
            tracing::info!(file = %p.display(), "CDR retention: deleted file");
        }
        Ok(())
    }
}

impl CdrSink for FileSink {
    fn name(&self) -> &'static str {
        "file"
    }
    fn write(&mut self, record: &CallRecord, json_line: &str) -> io::Result<()> {
        self.write_record(record, json_line)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync()
    }
}

fn cdr_to_io(e: &CdrError) -> io::Error {
    io::Error::other(e.to_string())
}

fn create_dir(dir: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o750);
    }
    b.create(dir)
}

/// Reads up to [`RESUME_TAIL_BYTES`] from the end of `path`. The flag is
/// true when the read started mid-file (the first line is dropped).
fn read_tail(path: &Path) -> io::Result<(String, bool)> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(RESUME_TAIL_BYTES);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(RESUME_TAIL_BYTES).read_to_end(&mut buf)?;
    let mut s = String::from_utf8_lossy(&buf).into_owned();
    if start > 0 {
        // Drop the partial first line.
        if let Some(i) = s.find('\n') {
            s.drain(..=i);
        }
    }
    Ok((s, start > 0))
}

fn hash_or_genesis(hex: &str) -> Option<[u8; HASH_LEN]> {
    if hex.is_empty() {
        Some(GENESIS)
    } else {
        from_hex(hex)
    }
}

/// Last complete JSONL record (or file header). Unparsable lines after it
/// (a torn write) are skipped and reported as `clean = false`.
fn resume_jsonl(tail: &str) -> Option<ResumePoint> {
    let mut clean = true;
    for line in tail.lines().rev() {
        if line.is_empty() {
            continue;
        }
        if let Ok(r) = serde_json::from_str::<CallRecord>(line) {
            if let Some(last_hash) = hash_or_genesis(&r.hash) {
                return Some(ResumePoint {
                    next_sequence: r.sequence.wrapping_add(1),
                    last_hash,
                    clean,
                });
            }
        } else if let Ok(h) = serde_json::from_str::<crate::record::FileHeader>(line)
            && let Some(last_hash) = hash_or_genesis(&h.chain_start)
        {
            return Some(ResumePoint {
                next_sequence: h.first_sequence,
                last_hash,
                clean,
            });
        }
        // Torn or foreign line: the chain is broken on disk after the
        // record we resume from.
        clean = false;
    }
    None
}

/// Splits CSV text into RFC 4180 records (quoted fields may hold CR/LF and
/// doubled quotes). `in_quotes` is the quote state at the first byte.
/// Records are terminated by LF (an optional CR before it is dropped).
fn csv_records(text: &str, mut in_quotes: bool) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '"' => in_quotes = true,
            ',' => fields.push(std::mem::take(&mut cur)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                fields.push(std::mem::take(&mut cur));
                records.push(std::mem::take(&mut fields));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() || !fields.is_empty() {
        // Unterminated final record (torn write).
        fields.push(cur);
        records.push(fields);
    }
    records
}

/// Resume point from a parsed CSV record, if it is a complete data row or
/// the file's comment line.
fn csv_resume_from(rec: &[String]) -> Option<ResumePoint> {
    if let [only] = rec
        && let Some(comment) = only.strip_prefix("# ")
    {
        let mut seq = None;
        let mut start = None;
        for kv in comment.split_whitespace() {
            if let Some(v) = kv.strip_prefix("first_sequence=") {
                seq = v.parse().ok();
            } else if let Some(v) = kv.strip_prefix("chain_start=") {
                start = Some(hash_or_genesis(v)?);
            }
        }
        return Some(ResumePoint {
            next_sequence: seq?,
            last_hash: start.unwrap_or(GENESIS),
            clean: true,
        });
    }
    if rec.len() != format::CSV_COLUMNS.len() && rec.len() != format::CSV_COLUMNS_V1 {
        return None;
    }
    let seq: u64 = rec.get(1)?.parse().ok()?;
    let last_hash = hash_or_genesis(rec.last()?)?;
    Some(ResumePoint {
        next_sequence: seq.wrapping_add(1),
        last_hash,
        clean: true,
    })
}

/// Last complete CSV row (parsed per RFC 4180, so a quoted CR/LF taken
/// from SIP input cannot hide the row), or the file comment.
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation), AU-9
fn resume_csv(tail: &str, truncated: bool) -> Option<ResumePoint> {
    // A tail that starts mid-file may start inside a quoted field; try
    // both quote states and keep the parse whose last record is valid.
    let states: &[bool] = if truncated { &[false, true] } else { &[false] };
    for &in_quotes in states {
        let mut clean = true;
        for rec in csv_records(tail, in_quotes).iter().rev() {
            if rec.len() == 1 && rec.first().is_some_and(String::is_empty) {
                continue;
            }
            if rec.first().is_some_and(|f| f == "schema_version") {
                continue;
            }
            if let Some(mut r) = csv_resume_from(rec) {
                r.clean = clean;
                return Some(r);
            }
            clean = false;
        }
    }
    None
}

/// Opens a byte stream to a syslog collector.
///
/// The daemon supplies a TLS
/// (RFC 5425) implementation built from its `uc-crypto`/rustls config;
/// implementations must set connect and write timeouts so a stalled
/// collector cannot stall the CDR writer for long.
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity), AU-9(2)
pub trait SyslogConnector: Send {
    /// Connects (and completes the TLS handshake).
    fn connect(&mut self) -> io::Result<Box<dyn Write + Send>>;
}

/// Syslog sink settings.
#[derive(Debug, Clone)]
pub struct SyslogSinkConfig {
    /// RFC 5424 HOSTNAME (usually the node id).
    pub hostname: String,
    /// RFC 5424 APP-NAME.
    pub app_name: String,
    /// Facility 0..=23 (default 16, local0).
    pub facility: u8,
}

impl Default for SyslogSinkConfig {
    fn default() -> Self {
        Self {
            hostname: "-".to_string(),
            app_name: "usg-sbc".to_string(),
            facility: 16,
        }
    }
}

/// RFC 5424 syslog sink with RFC 5425/6587 octet-counting framing. The MSG
/// is the record's canonical JSON; MSGID is `CDR`.
///
/// ## NIST 800-53 Rev5: AU-9(2) (Store on Separate Physical Systems)
pub struct SyslogSink {
    cfg: SyslogSinkConfig,
    connector: Box<dyn SyslogConnector>,
    stream: Option<Box<dyn Write + Send>>,
    last_attempt: Option<Instant>,
}

impl std::fmt::Debug for SyslogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogSink")
            .field("cfg", &self.cfg)
            .field("connected", &self.stream.is_some())
            .finish_non_exhaustive()
    }
}

/// Keeps PRINTUSASCII (33..=126), at most `max` bytes, `-` when empty
/// (RFC 5424 §6.2).
fn header_token(s: &str, max: usize) -> String {
    let t: String = s
        .bytes()
        .filter(|b| (33..=126).contains(b))
        .take(max)
        .map(char::from)
        .collect();
    if t.is_empty() { "-".to_string() } else { t }
}

impl SyslogSink {
    /// Creates the sink; the first connection is made on the first record.
    pub fn new(cfg: &SyslogSinkConfig, connector: Box<dyn SyslogConnector>) -> Self {
        let cfg = SyslogSinkConfig {
            hostname: header_token(&cfg.hostname, 255),
            app_name: header_token(&cfg.app_name, 48),
            facility: cfg.facility.min(23),
        };
        Self {
            cfg,
            connector,
            stream: None,
            last_attempt: None,
        }
    }

    /// Formats one framed RFC 5424 message (`"LEN SP SYSLOG-MSG"`).
    pub fn frame(&self, json_line: &str, now: SystemTime) -> String {
        // Severity 6 (informational).
        let pri = u16::from(self.cfg.facility) * 8 + 6;
        let ts = chrono::DateTime::<chrono::Utc>::from(now).format("%Y-%m-%dT%H:%M:%S%.3fZ");
        // RFC 5424 §6.4: a UTF-8 MSG SHOULD start with a BOM (caller display
        // data may be non-ASCII). The octet count below includes it.
        let msg = format!(
            "<{pri}>1 {ts} {} {} - CDR - \u{FEFF}{json_line}",
            self.cfg.hostname, self.cfg.app_name
        );
        format!("{} {msg}", msg.len())
    }
}

impl CdrSink for SyslogSink {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn write(&mut self, _record: &CallRecord, json_line: &str) -> io::Result<()> {
        if self.stream.is_none() {
            if self
                .last_attempt
                .is_some_and(|t| t.elapsed() < SYSLOG_RECONNECT_BACKOFF)
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "syslog collector unavailable",
                ));
            }
            self.last_attempt = Some(Instant::now());
            self.stream = Some(self.connector.connect()?);
        }
        let framed = self.frame(json_line, SystemTime::now());
        let res = self.stream.as_mut().map_or_else(
            || Err(io::Error::from(io::ErrorKind::NotConnected)),
            |s| s.write_all(framed.as_bytes()).and_then(|()| s.flush()),
        );
        if res.is_err() {
            self.stream = None;
        }
        res
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.as_mut().map_or(Ok(()), Write::flush)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::seal;
    use crate::record::SCHEMA_VERSION;
    use std::sync::Mutex;

    fn cfg(dir: &Path) -> FileSinkConfig {
        FileSinkConfig {
            directory: dir.to_path_buf(),
            format: CdrFormat::Jsonl,
            rotate_size_bytes: 0,
            rotate_interval: None,
            retention_files: 0,
            retention_days: 0,
            fsync_interval: Duration::from_secs(60),
        }
    }

    fn write_n(sink: &mut FileSink, start: u64, prev: &mut [u8; 48], n: u64) {
        for i in start..start + n {
            let mut r = CallRecord {
                schema_version: SCHEMA_VERSION,
                node_id: "n1".into(),
                sequence: i,
                record_id: format!("n1-{i}"),
                ..Default::default()
            };
            *prev = seal(&mut r, prev).unwrap();
            let line = format::to_json_line(&r).unwrap();
            sink.write_record(&r, &line).unwrap();
        }
    }

    #[derive(Default)]
    struct Obs(Mutex<Vec<(PathBuf, String)>>);
    impl CdrObserver for Obs {
        fn on_rotated(&self, file: &Path, sha: &str) {
            self.0
                .lock()
                .unwrap()
                .push((file.to_path_buf(), sha.to_string()));
        }
    }

    #[test]
    fn relative_directory_and_bad_node_rejected() {
        let mut c = cfg(Path::new("/tmp"));
        c.directory = PathBuf::from("relative/dir");
        assert!(FileSink::open(c, "n1", true, None).is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(FileSink::open(cfg(dir.path()), "../x", true, None).is_err());
    }

    #[test]
    fn size_rotation_sidecar_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.rotate_size_bytes = 2000;
        let obs = Arc::new(Obs::default());
        let (mut sink, resume) =
            FileSink::open(c, "n1", true, Some(obs.clone() as Arc<dyn CdrObserver>)).unwrap();
        assert_eq!(resume.next_sequence, 0);
        let mut prev = GENESIS;
        write_n(&mut sink, 0, &mut prev, 20);
        sink.close_current().unwrap();
        let rotated = obs.0.lock().unwrap().clone();
        assert!(rotated.len() >= 2, "expected several rotations");
        for (p, sha) in &rotated {
            assert!(chain::verify_sidecar(p).unwrap());
            assert_eq!(&to_hex(&chain::file_sha384(p).unwrap()), sha);
        }
        let paths: Vec<&Path> = rotated.iter().map(|(p, _)| p.as_path()).collect();
        let reps = chain::verify_files(&paths).unwrap();
        assert_eq!(reps.iter().map(|r| r.records).sum::<u64>(), 20);

        // Sidecar detects tampering.
        let p = &rotated[0].0;
        let mut text = std::fs::read_to_string(p).unwrap();
        text.push_str("{}\n");
        std::fs::write(p, text).unwrap();
        assert!(!chain::verify_sidecar(p).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&rotated[1].0)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o640);
        }
    }

    #[test]
    fn time_rotation_with_fake_clock() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.rotate_interval = Some(Duration::from_secs(300));
        let (mut sink, _) = FileSink::open(c, "n1", true, None).unwrap();
        let t0 = SystemTime::now();
        sink.tick(t0 + Duration::from_secs(600)).unwrap();
        assert_eq!(sink.rotations(), 0, "empty files are not rotated by time");
        let mut prev = GENESIS;
        write_n(&mut sink, 0, &mut prev, 1);
        sink.tick(t0 + Duration::from_secs(100)).unwrap();
        assert_eq!(sink.rotations(), 0);
        sink.tick(t0 + Duration::from_secs(600)).unwrap();
        assert_eq!(sink.rotations(), 1);
        assert!(sink.current_path().is_none());
        write_n(&mut sink, 1, &mut prev, 1);
        assert!(sink.current_path().is_some());
    }

    #[test]
    fn retention_by_count_and_age() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.rotate_size_bytes = 1;
        c.retention_files = 3;
        let (mut sink, _) = FileSink::open(c, "n1", true, None).unwrap();
        let mut prev = GENESIS;
        write_n(&mut sink, 0, &mut prev, 8);
        let files = sink.list_files().unwrap();
        assert_eq!(files.len(), 3);
        for f in &files {
            assert!(chain::sidecar_path(f).exists());
        }
        let sidecars = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".sha384")
            })
            .count();
        assert_eq!(sidecars, 3);

        sink.set_retention(0, 1);
        sink.apply_retention(SystemTime::now() + Duration::from_hours(48))
            .unwrap();
        assert_eq!(sink.list_files().unwrap(), Vec::<PathBuf>::new());
    }

    #[test]
    fn resume_continues_chain_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut prev = GENESIS;
        {
            let (mut sink, _) = FileSink::open(cfg(dir.path()), "n1", true, None).unwrap();
            write_n(&mut sink, 0, &mut prev, 3);
            sink.close_current().unwrap();
        }
        let (mut sink, resume) = FileSink::open(cfg(dir.path()), "n1", true, None).unwrap();
        assert!(resume.clean);
        assert_eq!(resume.next_sequence, 3);
        assert_eq!(resume.last_hash, prev);
        write_n(&mut sink, 3, &mut prev, 2);
        sink.close_current().unwrap();
        let files = sink.list_files().unwrap();
        let paths: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
        assert_eq!(chain::verify_files(&paths).unwrap().len(), 2);
    }

    #[test]
    fn resume_csv() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.format = CdrFormat::Csv;
        let mut prev = GENESIS;
        {
            let (mut sink, _) = FileSink::open(c.clone(), "n1", true, None).unwrap();
            write_n(&mut sink, 0, &mut prev, 4);
            sink.close_current().unwrap();
        }
        let (_sink, resume) = FileSink::open(c, "n1", true, None).unwrap();
        assert_eq!(resume.next_sequence, 4);
        assert_eq!(resume.last_hash, prev);
    }

    #[test]
    fn torn_tail_reports_unclean() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("cdr-n1-20260101T000000.jsonl"),
            "{\"schema_version\":1,\"type\":\"hea",
        )
        .unwrap();
        let (_s, resume) = FileSink::open(cfg(dir.path()), "n1", true, None).unwrap();
        assert!(!resume.clean);
        assert_eq!(resume.next_sequence, 0);
    }

    #[test]
    fn csv_resume_parses_quoted_newlines_and_skips_torn_row() {
        let mut r = CallRecord {
            schema_version: SCHEMA_VERSION,
            node_id: "n1".into(),
            sequence: 7,
            callee_dialed: "x\r\ny,\"z\"".into(),
            ..Default::default()
        };
        let h = seal(&mut r, &GENESIS).unwrap();
        let row = format::to_csv_row(&r).unwrap();
        let text = format!("{}\n{row}\n", format::csv_header());
        let p = super::resume_csv(&text, false).unwrap();
        assert_eq!((p.next_sequence, p.last_hash, p.clean), (8, h, true));
        // A torn row after it: resume from the complete one, marked unclean.
        let torn = format!("{text}1,8,\"half");
        let p = super::resume_csv(&torn, false).unwrap();
        assert_eq!((p.next_sequence, p.clean), (8, false));
        // A tail cut inside a quoted field of an earlier row still finds
        // the last row (the parse that starts in-quotes is used).
        let mut r2 = r.clone();
        r2.sequence = 8;
        let h2 = seal(&mut r2, &h).unwrap();
        let both = format!("{row}\n{}\n", format::to_csv_row(&r2).unwrap());
        let cut = &both[both.find('\n').unwrap() + 1..];
        let p = super::resume_csv(cut, true).unwrap();
        assert_eq!((p.next_sequence, p.last_hash), (9, h2));
    }

    #[test]
    fn unreadable_newest_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..=RESUME_MAX_FILES {
            std::fs::write(
                dir.path().join(format!("cdr-n1-20260101T0000{i:02}.jsonl")),
                "garbage\n",
            )
            .unwrap();
        }
        assert!(FileSink::open(cfg(dir.path()), "n1", true, None).is_err());
    }

    #[test]
    fn other_node_files_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cdr-n1-b-20260101T000000.jsonl"), "junk\n").unwrap();
        let (_s, resume) = FileSink::open(cfg(dir.path()), "n1", true, None).unwrap();
        assert!(resume.clean);
    }

    struct VecConn(Arc<Mutex<Vec<u8>>>, bool);
    struct VecWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for VecWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl SyslogConnector for VecConn {
        fn connect(&mut self) -> io::Result<Box<dyn Write + Send>> {
            if self.1 {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            Ok(Box::new(VecWriter(self.0.clone())))
        }
    }

    #[test]
    fn syslog_octet_counted_rfc5424() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut s = SyslogSink::new(
            &SyslogSinkConfig {
                hostname: "node 1".into(),
                ..Default::default()
            },
            Box::new(VecConn(buf.clone(), false)),
        );
        s.write(&CallRecord::default(), "{\"a\":1}").unwrap();
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let (len, msg) = out.split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), msg.len());
        assert!(msg.starts_with("<134>1 "));
        assert!(msg.contains(" node1 usg-sbc - CDR - \u{FEFF}{\"a\":1}"));
    }

    #[test]
    fn syslog_backoff_after_connect_failure() {
        let mut s = SyslogSink::new(
            &SyslogSinkConfig::default(),
            Box::new(VecConn(Arc::new(Mutex::new(Vec::new())), true)),
        );
        let e1 = s.write(&CallRecord::default(), "{}").unwrap_err();
        assert_eq!(e1.kind(), io::ErrorKind::ConnectionRefused);
        let e2 = s.write(&CallRecord::default(), "{}").unwrap_err();
        assert_eq!(e2.kind(), io::ErrorKind::NotConnected);
    }
}
