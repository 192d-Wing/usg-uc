//! Digest credential source for REGISTER (`[digest_auth]`, POA&M-270).
//!
//! The daemon holds one HA1 (`H(username:realm:password)`, RFC 7616 §3.4.2)
//! per user and algorithm, loaded from an operator-managed file. It never
//! sees a password. An HA1 is password-equivalent for its realm (RFC 7616
//! §5.2), so the file is checked like a private key (regular file, no
//! symlink, owner-only mode, owned by the daemon user or root) and every
//! copy this module and the verifier (`proto_sip::digest_verifier`) make of
//! an HA1 is wiped on drop: the read buffer, the table entries, and the
//! temporary strings of a verification. The hash contexts of the crypto
//! library are outside that statement.
//!
//! File format, one entry per line:
//!
//! ```text
//! # comment
//! username:realm:algorithm:ha1hex
//! ```
//!
//! `algorithm` is `SHA-256` or `SHA-512-256` (`SHA-512-256` is FIPS 180-4
//! SHA-512/256, RFC 7616 §3.2); `ha1hex` is 64 hex characters. An `MD5` or
//! `-sess` line fails the whole load: as the server the SBC picks the
//! algorithm (RFC 7616 §3.7) and does not hold MD5 secrets.
//!
//! `username` is 1..=255 bytes of ASCII in the RFC 3261 §25.1 `user`
//! production: letters, digits, `-_.!~*'()`, `&=+$,;?/` and `%HH` escapes.
//! It is compared byte for byte with the digest `username` and the AOR
//! user, so a name with `@`, a space, a quote, a backslash or a non-ASCII
//! character could never match a REGISTER and fails the load instead of
//! locking that user out silently. The file is plain UTF-8 without a byte
//! order mark; a BOM is a line 1 error.
//!
//! Errors name the line number and the rule that failed, never the line,
//! the username or the HA1.
//!
//! POAM: POA&M-310 - the file is the only credential source; users created
//! through the API server's user store are not usable for SIP digest.
//! POAM: POA&M-311 - removing a user stops new REGISTERs at once, but the
//! user's existing bindings last until they expire.
//! POAM: POA&M-312 - the file is not sealed at rest (SC-28(1)); see
//! `check_credentials_file`.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **IA-5, IA-5(1)**: partial. No plaintext password is stored (HA1
//!   only). An HA1 is not a salted key-derivation hash, and nothing here
//!   requires a protected transport for the exchange (POA&M-314)
//! - **IA-5(6)**: file protection checks, zeroize on drop, redacted `Debug`
//! - **SC-5**: bounded file size and entry count
//! - **SI-10**: every line is validated; one bad line fails the load
//! - **CM-3, AU-2**: loads and reloads are audited: a `ConfigurationChange`
//!   (counts only) and a `CryptoKeyOperation` with the outcome, success
//!   and failure alike

use proto_sip::DigestAlgorithm;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use tracing::{error, info};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Largest credentials file accepted (SC-5).
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Most entries accepted in one credentials file (SC-5).
pub const MAX_ENTRIES: usize = 1_000_000;
/// Hex length of an HA1 for both accepted algorithms (256-bit output).
const HA1_HEX_LEN: usize = 64;
/// Longest username accepted in the file.
const MAX_USERNAME_BYTES: usize = 255;
/// How often, and how many times, a reload checks that readers have let go
/// of the replaced table before it stops waiting (200 ms in total).
const OLD_TABLE_DROP_POLL: std::time::Duration = std::time::Duration::from_millis(1);
const OLD_TABLE_DROP_POLLS: u32 = 200;
/// UTF-8 byte order mark.
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

/// `sbc_digest_credentials_users`: users in the loaded table.
pub const METRIC_USERS: &str = "sbc_digest_credentials_users";
/// `sbc_digest_credentials_reload_failures_total`: reloads that kept the
/// previous table.
pub const METRIC_RELOAD_FAILURES: &str = "sbc_digest_credentials_reload_failures_total";

/// Why a credentials file was refused. `Display` carries the rule and, for
/// a line error, the 1-based line number; never file content.
///
/// ## NIST 800-53 Rev5: IA-5(6), SI-11 (Error Handling)
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DigestCredentialError {
    /// The file itself (type, mode, owner, size) is not acceptable.
    #[error("digest credentials file {0}")]
    File(&'static str),
    /// The file could not be opened or read.
    #[error("digest credentials file could not be read: {0}")]
    Io(std::io::ErrorKind),
    /// A line breaks a format rule.
    #[error("digest credentials file line {line}: {rule}")]
    Line {
        /// 1-based line number.
        line: usize,
        /// The rule that failed.
        rule: &'static str,
    },
    /// The file parsed but cannot be used with the running configuration.
    #[error("digest credentials {0}")]
    Unusable(&'static str),
}

/// One HA1 as lower-case ASCII hex.
///
/// Wiped on drop. No `Clone`, `Display`, `Serialize` or `PartialEq`; the
/// value lives on the heap so moving the table never leaves a copy behind.
///
/// ## NIST 800-53 Rev5: IA-5(6) (Protection of Authenticators)
pub struct Ha1(Box<[u8; HA1_HEX_LEN]>);

impl Ha1 {
    /// Parses 64 hex characters (either case), stored lower-case.
    fn from_hex(hex: &[u8]) -> Option<Self> {
        if hex.len() != HA1_HEX_LEN || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let mut out = Box::new([0u8; HA1_HEX_LEN]);
        for (dst, src) in out.iter_mut().zip(hex) {
            *dst = src.to_ascii_lowercase();
        }
        Some(Self(out))
    }

    /// A random value no client can match, verified for unknown users so
    /// they cost the same as known ones (IA-6).
    ///
    /// # Errors
    /// The system RNG failed.
    pub fn random() -> Result<Self, uc_crypto::CryptoError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let raw = Zeroizing::new(uc_crypto::random::generate_random::<32>()?);
        let mut out = Box::new([0u8; HA1_HEX_LEN]);
        let nibbles = raw.iter().flat_map(|b| [b >> 4, b & 0x0f]);
        for (dst, nibble) in out.iter_mut().zip(nibbles) {
            // A nibble is always below 16.
            *dst = HEX[usize::from(nibble)];
        }
        Ok(Self(out))
    }

    /// The HA1 hex string, for the verifier only.
    #[must_use]
    pub fn expose(&self) -> &str {
        // Always ASCII hex (see the constructors).
        std::str::from_utf8(&self.0[..]).unwrap_or_default()
    }
}

impl Drop for Ha1 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Ha1 {}

impl std::fmt::Debug for Ha1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ha1(<redacted>)")
    }
}

/// A user's HA1 per accepted algorithm.
#[derive(Default)]
struct UserHa1 {
    sha256: Option<Ha1>,
    sha512_256: Option<Ha1>,
}

impl UserHa1 {
    fn slot(&mut self, algorithm: FileAlgorithm) -> &mut Option<Ha1> {
        match algorithm {
            FileAlgorithm::Sha256 => &mut self.sha256,
            FileAlgorithm::Sha512_256 => &mut self.sha512_256,
        }
    }
}

/// The algorithms a credentials line may name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FileAlgorithm {
    Sha256,
    Sha512_256,
}

impl FileAlgorithm {
    /// RFC 7616 §3.7 / RFC 8760 §2.1: no MD5 and no `-sess` on the server.
    const fn from_policy(algorithm: DigestAlgorithm) -> Option<Self> {
        match algorithm {
            DigestAlgorithm::Sha256 => Some(Self::Sha256),
            DigestAlgorithm::Sha512_256 => Some(Self::Sha512_256),
            _ => None,
        }
    }
}

/// An immutable set of credentials for one realm. Replaced whole on reload.
///
/// The map is keyed by usernames from the file and looked up with usernames
/// from the wire; `HashMap`'s default hasher is randomly keyed (SC-5).
pub struct CredentialTable {
    realm: Box<str>,
    users: HashMap<Box<str>, UserHa1>,
}

impl CredentialTable {
    /// The HA1 of `username` for `algorithm`. Usernames match exactly
    /// (case-sensitive, like the AOR user check). `None` for an unknown
    /// user and for a user without an HA1 for that algorithm.
    #[must_use]
    pub fn ha1(&self, username: &str, algorithm: DigestAlgorithm) -> Option<&Ha1> {
        let user = self.users.get(username)?;
        match FileAlgorithm::from_policy(algorithm)? {
            FileAlgorithm::Sha256 => user.sha256.as_ref(),
            FileAlgorithm::Sha512_256 => user.sha512_256.as_ref(),
        }
    }

    /// Number of users.
    #[must_use]
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Whether the table has no users.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// The realm every entry belongs to.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

impl std::fmt::Debug for CredentialTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Count only: no usernames, no HA1.
        f.debug_struct("CredentialTable")
            .field("realm", &self.realm)
            .field("users", &self.users.len())
            .finish()
    }
}

/// Outcome of a successful reload (counts only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReloadSummary {
    /// Users in the new table.
    pub users: usize,
    /// Users not in the previous table.
    pub added: usize,
    /// Users of the previous table that are gone.
    pub removed: usize,
}

/// Size bounds of a load (SC-5). Injectable for tests.
#[derive(Debug, Clone, Copy)]
struct Limits {
    max_bytes: u64,
    max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_FILE_BYTES,
            max_entries: MAX_ENTRIES,
        }
    }
}

/// The credentials in force, swappable on reload.
///
/// Created by the runtime, shared with the SIP stack (reader) and the
/// reload task (writer). `current` is a leaf lock held only to clone or
/// replace the `Arc`; a REGISTER racing a reload sees the old or the new
/// table, never a mix. A failed reload keeps the previous table: never an
/// empty one and never "unauthenticated".
///
/// ## NIST 800-53 Rev5: IA-5, IA-5(1) (partial, see module doc), SC-5,
/// SC-24 (Fail in Known State)
pub struct DigestCredentialStore {
    path: PathBuf,
    realm: Box<str>,
    algorithm: DigestAlgorithm,
    limits: Limits,
    current: RwLock<Arc<CredentialTable>>,
    /// Serializes reloads (SIGHUP loop and the reload API).
    reload_lock: Mutex<()>,
    reload_failures: AtomicU64,
}

impl DigestCredentialStore {
    /// Loads `path` for `realm`. `algorithm` is the one the daemon
    /// challenges with; at least one entry must exist for it.
    ///
    /// # Errors
    /// Any file, line or table rule failed; see [`DigestCredentialError`].
    pub fn load(
        path: &Path,
        realm: &str,
        algorithm: DigestAlgorithm,
    ) -> Result<Self, DigestCredentialError> {
        Self::load_with_limits(path, realm, algorithm, Limits::default())
    }

    fn load_with_limits(
        path: &Path,
        realm: &str,
        algorithm: DigestAlgorithm,
        limits: Limits,
    ) -> Result<Self, DigestCredentialError> {
        let table = load_table(path, realm, algorithm, limits)?;
        Ok(Self {
            path: path.to_path_buf(),
            realm: realm.into(),
            algorithm,
            limits,
            current: RwLock::new(Arc::new(table)),
            reload_lock: Mutex::new(()),
            reload_failures: AtomicU64::new(0),
        })
    }

    /// The table in force. The read lock is held only for the `Arc` clone.
    #[must_use]
    pub fn snapshot(&self) -> Arc<CredentialTable> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Re-reads the file and swaps the table in one step. Blocking file
    /// I/O: call from a blocking context ([`reload_and_audit`]).
    ///
    /// # Errors
    /// The file failed to load; the previous table stays in force and the
    /// failure counter is incremented.
    pub fn reload(&self) -> Result<ReloadSummary, DigestCredentialError> {
        let _serial = self
            .reload_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let table = match load_table(&self.path, &self.realm, self.algorithm, self.limits) {
            Ok(t) => t,
            Err(e) => {
                self.reload_failures.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        let old = self.snapshot();
        let summary = ReloadSummary {
            users: table.users.len(),
            added: table
                .users
                .keys()
                .filter(|u| !old.users.contains_key(*u))
                .count(),
            removed: old
                .users
                .keys()
                .filter(|u| !table.users.contains_key(*u))
                .count(),
        };
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(table);
        // PERF-001: the old table is wiped and freed when its last `Arc`
        // drops. Readers hold a snapshot only for one verification, so wait
        // briefly for them and drop it here, on the reload (blocking)
        // thread, not on a SIP worker. Bounded: after the wait a reader
        // that is still inside a verification drops it.
        for _ in 0..OLD_TABLE_DROP_POLLS {
            if Arc::strong_count(&old) == 1 {
                break;
            }
            std::thread::sleep(OLD_TABLE_DROP_POLL);
        }
        drop(old);
        Ok(summary)
    }

    /// The file this store reads.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Users in the table in force (`sbc_digest_credentials_users`).
    #[must_use]
    pub fn users(&self) -> u64 {
        self.snapshot().len() as u64
    }

    /// Reloads that failed and kept the previous table
    /// (`sbc_digest_credentials_reload_failures_total`).
    #[must_use]
    pub fn reload_failures(&self) -> u64 {
        self.reload_failures.load(Ordering::Relaxed)
    }

    /// A store built from cleartext test passwords, with an HA1 for both
    /// algorithms. It has no file: `reload` fails and keeps the table.
    #[cfg(test)]
    pub fn from_passwords(realm: &str, users: &[(&str, &str)]) -> Self {
        use proto_sip::auth::DigestHasher;
        let mut table = CredentialTable {
            realm: realm.into(),
            users: HashMap::new(),
        };
        for (user, password) in users {
            let a1 = format!("{user}:{realm}:{password}");
            table.users.insert(
                (*user).into(),
                UserHa1 {
                    sha256: Ha1::from_hex(
                        proto_sip::Sha256DigestHasher.hash(a1.as_bytes()).as_bytes(),
                    ),
                    sha512_256: Ha1::from_hex(
                        proto_sip::Sha512_256DigestHasher
                            .hash(a1.as_bytes())
                            .as_bytes(),
                    ),
                },
            );
        }
        Self {
            path: PathBuf::new(),
            realm: realm.into(),
            algorithm: DigestAlgorithm::Sha256,
            limits: Limits::default(),
            current: RwLock::new(Arc::new(table)),
            reload_lock: Mutex::new(()),
            reload_failures: AtomicU64::new(0),
        }
    }
}

impl std::fmt::Debug for DigestCredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigestCredentialStore")
            .field("path", &self.path)
            .field("realm", &self.realm)
            .field("algorithm", &self.algorithm)
            .field("users", &self.snapshot().len())
            .finish_non_exhaustive()
    }
}

/// Reloads `store` off the async runtime, then logs and audits the result
/// on the calling task. A failure keeps the previous credentials.
///
/// # Errors
/// As [`DigestCredentialStore::reload`].
///
/// ## NIST 800-53 Rev5: CM-3, AU-2, AU-12, IA-5
pub async fn reload_and_audit(
    store: &Arc<DigestCredentialStore>,
) -> Result<ReloadSummary, DigestCredentialError> {
    let task_store = Arc::clone(store);
    let result = tokio::task::spawn_blocking(move || task_store.reload())
        .await
        .unwrap_or_else(|_| {
            // The reload task panicked or was cancelled: nothing swapped.
            store.reload_failures.fetch_add(1, Ordering::Relaxed);
            Err(DigestCredentialError::Io(std::io::ErrorKind::Other))
        });
    match &result {
        Ok(s) => info!(
            path = %store.path.display(),
            users = s.users,
            added = s.added,
            removed = s.removed,
            "digest credentials reloaded"
        ),
        Err(e) => error!(
            path = %store.path.display(),
            error = %e,
            "digest credentials reload failed; previous credentials kept"
        ),
    }
    audit_reload(&result, store.algorithm);
    result
}

/// `key_id` of the credential table in `CryptoKeyOperation` audit events.
pub const AUDIT_KEY_ID: &str = "digest_auth.credentials";

/// Audits a credential load that failed with an explicit failure outcome
/// (AU-3). The HA1 table is authenticator material, so the event is a
/// `CryptoKeyOperation`: the one `uc-audit` event for secret material that
/// carries an outcome field. `reason` must be a rule text without file
/// content or a path; `CryptoKeyOperation::failure` strips control
/// characters and caps it.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3 (outcome), AU-12, IA-5
pub fn audit_load_failure(
    operation: uc_audit::event::KeyOperationType,
    algorithm: DigestAlgorithm,
    reason: &str,
) {
    uc_audit::log_event(uc_audit::AuditEvent::CryptoKeyOperation(
        uc_audit::event::CryptoKeyOperation::failure(
            AUDIT_KEY_ID,
            operation,
            algorithm.to_string(),
            reason,
        ),
    ));
}

/// Audits a credential load that succeeded: the success counterpart of
/// [`audit_load_failure`] (same event type and `key_id`, no reason).
///
/// ## NIST 800-53 Rev5: AU-2, AU-3 (outcome), AU-12, IA-5
pub fn audit_load_success(
    operation: uc_audit::event::KeyOperationType,
    algorithm: DigestAlgorithm,
) {
    uc_audit::log_event(uc_audit::AuditEvent::CryptoKeyOperation(
        uc_audit::event::CryptoKeyOperation::success(
            AUDIT_KEY_ID,
            operation,
            algorithm.to_string(),
        ),
    ));
}

/// Audit record for a credential reload: counts on success, the failed
/// rule on failure. No usernames, no file content.
///
/// Either result is recorded twice: as the configuration change (the
/// description only) and, with an explicit outcome, as a
/// `CryptoKeyOperation` ([`audit_load_success`], [`audit_load_failure`]),
/// so one event type shows successes and failures.
fn audit_reload(result: &Result<ReloadSummary, DigestCredentialError>, algorithm: DigestAlgorithm) {
    let description = match result {
        Ok(s) => {
            audit_load_success(uc_audit::event::KeyOperationType::Rotated, algorithm);
            format!(
                "[digest_auth] credentials reloaded: users={} added={} removed={}",
                s.users, s.added, s.removed
            )
        }
        Err(e) => {
            audit_load_failure(
                uc_audit::event::KeyOperationType::Rotated,
                algorithm,
                &e.to_string(),
            );
            format!("[digest_auth] credentials reload failed, previous credentials kept: {e}")
        }
    };
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        uc_audit::event::ConfigurationChange {
            admin: "config-reload".to_string(),
            change_type: uc_audit::event::ConfigChangeType::Reloaded,
            description,
        },
    ));
}

/// Audit record for the startup load: the configuration change (counts
/// only) and the `CryptoKeyOperation` success.
pub fn audit_loaded(store: &DigestCredentialStore) {
    audit_load_success(uc_audit::event::KeyOperationType::Loaded, store.algorithm);
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        uc_audit::event::ConfigurationChange {
            admin: "startup".to_string(),
            change_type: uc_audit::event::ConfigChangeType::Loaded,
            description: format!("[digest_auth] credentials loaded: users={}", store.users()),
        },
    ));
}

/// Opens, checks, reads and parses the file.
fn load_table(
    path: &Path,
    realm: &str,
    algorithm: DigestAlgorithm,
    limits: Limits,
) -> Result<CredentialTable, DigestCredentialError> {
    let Some(configured) = FileAlgorithm::from_policy(algorithm) else {
        return Err(DigestCredentialError::Unusable(
            "cannot be used: the configured algorithm must be SHA-256 or SHA-512-256",
        ));
    };
    let file = open_credentials_file(path)?;
    // fstat on the handle that is read: no TOCTOU between check and read.
    let meta = file
        .metadata()
        .map_err(|e| DigestCredentialError::Io(e.kind()))?;
    check_credentials_file(&meta)?;
    if meta.len() > limits.max_bytes {
        return Err(DigestCredentialError::File("is larger than the size limit"));
    }
    let buf = read_bounded(file, meta.len())?;
    parse_table(&buf, realm, configured, limits.max_entries)
}

/// Opens the file without following a final symlink. `O_NONBLOCK` keeps a
/// FIFO planted at the path from blocking the open; it has no effect on a
/// regular file.
// POAM: POA&M-315 - a symlinked parent directory of the credentials file is
// not detected; planting one needs write access to the credentials directory.
fn open_credentials_file(path: &Path) -> Result<std::fs::File, DigestCredentialError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits());
    }
    opts.open(path).map_err(|e| {
        // ELOOP: the final path component is a symlink.
        #[cfg(unix)]
        if e.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) {
            return DigestCredentialError::File("must not be a symlink");
        }
        DigestCredentialError::Io(e.kind())
    })
}

/// Rejects a non-regular, group/other-accessible or foreign-owned file.
/// `meta` comes from the open handle.
///
/// This is access restriction only (file type, mode and owner): it keeps
/// other local users from reading the HA1 values but does not protect them
/// at rest. Whoever can read the disk, a backup or the file as root reads
/// password-equivalent secrets.
///
/// POAM: POA&M-312 - the HA1 credentials file is not sealed at rest
/// (SC-28(1)); it relies on file permissions and on volume encryption
/// supplied by the platform.
///
/// ## NIST 800-53 Rev5: AC-3, AC-6, IA-5(6) (access restriction; not SC-28)
fn check_credentials_file(meta: &std::fs::Metadata) -> Result<(), DigestCredentialError> {
    if !meta.is_file() {
        return Err(DigestCredentialError::File("must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(DigestCredentialError::File(
                "is accessible by group or other; chmod 0600 (or 0400) it",
            ));
        }
        if !owner_allowed(meta.uid(), nix::unistd::geteuid().as_raw()) {
            return Err(DigestCredentialError::File(
                "must be owned by the SBC's user or root",
            ));
        }
    }
    Ok(())
}

/// The file may belong to the daemon's effective user or to root.
const fn owner_allowed(file_uid: u32, euid: u32) -> bool {
    file_uid == euid || file_uid == 0
}

/// Reads at most `len + 1` bytes into a buffer that is wiped on drop and
/// never reallocated (a reallocation would leave an unwiped copy).
fn read_bounded(
    file: std::fs::File,
    len: u64,
) -> Result<Zeroizing<Vec<u8>>, DigestCredentialError> {
    use std::io::Read as _;
    let too_large = DigestCredentialError::File("is larger than the size limit");
    let cap = usize::try_from(len)
        .ok()
        .and_then(|l| l.checked_add(1))
        .ok_or(too_large)?;
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(cap)
        .map_err(|_| DigestCredentialError::Io(std::io::ErrorKind::OutOfMemory))?;
    file.take(len.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| DigestCredentialError::Io(e.kind()))?;
    if buf.len() as u64 > len {
        return Err(DigestCredentialError::File("changed while it was read"));
    }
    Ok(buf)
}

/// The line rule reported for a username outside [`is_sip_user`].
const USERNAME_RULE: &str = "username must be ASCII in the RFC 3261 user production \
     (letters, digits, -_.!~*'()&=+$,;?/ and %HH escapes)";

/// RFC 3261 §25.1: `user = 1*( unreserved / escaped / user-unreserved )`.
/// ASCII only; no `@`, space, quote or backslash. A digest `username` or
/// AOR user outside it cannot match a file entry byte for byte, so such an
/// entry would be dead (RFC-001 / RFC-002 / SEC-006).
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
fn is_sip_user(user: &[u8]) -> bool {
    let mut bytes = user.iter();
    while let Some(b) = bytes.next() {
        match b {
            // unreserved = alphanum / mark; user-unreserved.
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => {}
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {}
            b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/' => {}
            // escaped = "%" HEXDIG HEXDIG
            b'%' => {
                let (Some(hi), Some(lo)) = (bytes.next(), bytes.next()) else {
                    return false;
                };
                if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    !user.is_empty()
}

/// Parses the whole file. One bad line fails the load (SI-10).
fn parse_table(
    buf: &[u8],
    realm: &str,
    configured: FileAlgorithm,
    max_entries: usize,
) -> Result<CredentialTable, DigestCredentialError> {
    // F1 / SEC-005: a BOM would become part of the first username (U+FEFF
    // is not a control character) and lock that user out without an error.
    if buf.starts_with(UTF8_BOM) {
        return Err(DigestCredentialError::Line {
            line: 1,
            rule: "file starts with a UTF-8 byte order mark; save it without a BOM",
        });
    }
    // PERF-002: size the table once from the line count (an upper bound on
    // the users, itself bounded by `max_entries`), so loading does not
    // rehash as it grows.
    let lines = buf.split(|b| *b == b'\n').count();
    let mut users: HashMap<Box<str>, UserHa1> = HashMap::new();
    users
        .try_reserve(lines.min(max_entries))
        .map_err(|_| DigestCredentialError::Io(std::io::ErrorKind::OutOfMemory))?;
    let mut entries = 0usize;
    let mut configured_entries = 0usize;
    for (idx, raw) in buf.split(|b| *b == b'\n').enumerate() {
        let line = idx.saturating_add(1);
        let err = |rule: &'static str| DigestCredentialError::Line { line, rule };
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.first() == Some(&b'#') || raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let mut fields = raw.split(|b| *b == b':');
        let (Some(user), Some(line_realm), Some(alg), Some(hex), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(err("expected username:realm:algorithm:ha1hex"));
        };
        if user.is_empty() {
            return Err(err("empty username"));
        }
        if user.len() > MAX_USERNAME_BYTES {
            return Err(err("username longer than 255 bytes"));
        }
        if !is_sip_user(user) {
            return Err(err(USERNAME_RULE));
        }
        // ASCII by the check above.
        let Ok(user) = std::str::from_utf8(user) else {
            return Err(err(USERNAME_RULE));
        };
        if line_realm != realm.as_bytes() {
            return Err(err("realm does not match digest_auth.realm"));
        }
        let algorithm = match alg {
            b"SHA-256" => FileAlgorithm::Sha256,
            b"SHA-512-256" => FileAlgorithm::Sha512_256,
            _ if alg.get(..3).is_some_and(|p| p.eq_ignore_ascii_case(b"MD5")) => {
                return Err(err("MD5 credentials are not accepted"));
            }
            _ => {
                return Err(err("algorithm must be SHA-256 or SHA-512-256"));
            }
        };
        let Some(ha1) = Ha1::from_hex(hex) else {
            return Err(err("HA1 must be 64 hex characters"));
        };
        entries = entries.saturating_add(1);
        if entries > max_entries {
            return Err(DigestCredentialError::File(
                "has more entries than the limit",
            ));
        }
        let slot = users.entry(user.into()).or_default().slot(algorithm);
        if slot.is_some() {
            return Err(err("duplicate entry for this username and algorithm"));
        }
        *slot = Some(ha1);
        if algorithm == configured {
            configured_entries = configured_entries.saturating_add(1);
        }
    }
    if configured_entries == 0 {
        return Err(DigestCredentialError::Unusable(
            "file has no entry for the configured digest_auth.algorithm",
        ));
    }
    Ok(CredentialTable {
        realm: realm.into(),
        users,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod test_support {
    //! Credentials files for tests in this crate.
    use std::path::{Path, PathBuf};

    /// `H(user:realm:password)` hex for `algorithm` (`SHA-256` or
    /// `SHA-512-256`).
    pub fn ha1_hex(user: &str, realm: &str, password: &str, algorithm: &str) -> String {
        use proto_sip::auth::DigestHasher;
        let a1 = format!("{user}:{realm}:{password}");
        match algorithm {
            "SHA-256" => proto_sip::Sha256DigestHasher.hash(a1.as_bytes()),
            "SHA-512-256" => proto_sip::Sha512_256DigestHasher.hash(a1.as_bytes()),
            other => panic!("unsupported test algorithm {other}"),
        }
    }

    /// One file line for `user`.
    pub fn line(user: &str, realm: &str, password: &str, algorithm: &str) -> String {
        format!(
            "{user}:{realm}:{algorithm}:{}\n",
            ha1_hex(user, realm, password, algorithm)
        )
    }

    /// Writes `content` to `dir/name` with `mode` (unix), replacing it.
    pub fn write_file(dir: &Path, name: &str, content: &[u8], mode: u32) -> PathBuf {
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::test_support::{ha1_hex, line, write_file};
    use super::*;

    const REALM: &str = "sip.example.test";
    /// A syntactically valid HA1 that must never appear in any output.
    const SENTINEL: &str = "5e471e15e471e15e471e15e471e15e471e15e471e15e471e15e471e15e471e1a";

    fn parse(content: &str) -> Result<CredentialTable, DigestCredentialError> {
        parse_table(
            content.as_bytes(),
            REALM,
            FileAlgorithm::Sha256,
            MAX_ENTRIES,
        )
    }

    fn line_err(content: &str) -> (usize, &'static str) {
        match parse(content) {
            Err(DigestCredentialError::Line { line, rule }) => (line, rule),
            other => panic!("expected a line error, got {other:?}"),
        }
    }

    #[test]
    fn parses_both_algorithms_comments_blank_lines_and_crlf() {
        let upper = SENTINEL.to_ascii_uppercase();
        let content = format!(
            "# digest credentials\r\n\
             \r\n\
             alice:{REALM}:SHA-256:{upper}\r\n\
             \t \n\
             alice:{REALM}:SHA-512-256:{SENTINEL}\n\
             # trailing comment\n\
             bob:{REALM}:SHA-256:{SENTINEL}"
        );
        let table = parse(&content).unwrap();
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
        assert_eq!(table.realm(), REALM);
        // Upper-case hex is normalized.
        assert_eq!(
            table.ha1("alice", DigestAlgorithm::Sha256).map(Ha1::expose),
            Some(SENTINEL)
        );
        assert!(table.ha1("alice", DigestAlgorithm::Sha512_256).is_some());
        assert!(table.ha1("bob", DigestAlgorithm::Sha256).is_some());
        // A user without an HA1 for the algorithm is the same as unknown.
        assert!(table.ha1("bob", DigestAlgorithm::Sha512_256).is_none());
        assert!(table.ha1("carol", DigestAlgorithm::Sha256).is_none());
        // Exact, case-sensitive usernames; no MD5 or -sess lookups.
        assert!(table.ha1("Alice", DigestAlgorithm::Sha256).is_none());
        assert!(table.ha1("alice", DigestAlgorithm::Md5).is_none());
        assert!(table.ha1("alice", DigestAlgorithm::Sha256Sess).is_none());
    }

    #[test]
    fn every_malformed_line_rule_is_reported_with_its_line_number() {
        let ok = format!("alice:{REALM}:SHA-256:{SENTINEL}\n");
        let long_user = "u".repeat(256);
        let cases: Vec<(String, &str)> = vec![
            (format!("alice:{REALM}:SHA-256"), "expected username"),
            (
                format!("alice:{REALM}:SHA-256:{SENTINEL}:extra"),
                "expected username",
            ),
            ("alice".to_string(), "expected username"),
            (format!(":{REALM}:SHA-256:{SENTINEL}"), "empty username"),
            (
                format!("{long_user}:{REALM}:SHA-256:{SENTINEL}"),
                "longer than 255",
            ),
            (
                format!("al\u{1}ice:{REALM}:SHA-256:{SENTINEL}"),
                "RFC 3261 user production",
            ),
            (
                format!("alice:other.example.test:SHA-256:{SENTINEL}"),
                "realm does not match",
            ),
            (format!("alice::SHA-256:{SENTINEL}"), "realm does not match"),
            (format!("alice:{REALM}:MD5:{SENTINEL}"), "MD5"),
            (format!("alice:{REALM}:md5-sess:{SENTINEL}"), "MD5"),
            (
                format!("alice:{REALM}:SHA-256-sess:{SENTINEL}"),
                "algorithm must be",
            ),
            (
                format!("alice:{REALM}:sha-256:{SENTINEL}"),
                "algorithm must be",
            ),
            (format!("alice:{REALM}::{SENTINEL}"), "algorithm must be"),
            (
                format!("alice:{REALM}:SHA-256:{}", &SENTINEL[..63]),
                "64 hex",
            ),
            (format!("alice:{REALM}:SHA-256:{SENTINEL}0"), "64 hex"),
            (
                format!("alice:{REALM}:SHA-256:{}g", &SENTINEL[..63]),
                "64 hex",
            ),
            (format!("alice:{REALM}:SHA-256:"), "64 hex"),
            // Leading whitespace is not trimmed into a comment or a user.
            (format!(" #alice:{REALM}:SHA-256"), "expected username"),
        ];
        for (bad, needle) in cases {
            let content = format!("{ok}# c\n{bad}\n");
            let (line, rule) = line_err(&content);
            assert_eq!(line, 3, "{rule}");
            assert!(rule.contains(needle), "{rule} should mention {needle}");
        }
        // Non-UTF-8 username.
        let mut bytes = ok.into_bytes();
        bytes.extend_from_slice(b"\xff\xfe:");
        bytes.extend_from_slice(format!("{REALM}:SHA-256:{SENTINEL}\n").as_bytes());
        let e = parse_table(&bytes, REALM, FileAlgorithm::Sha256, MAX_ENTRIES).unwrap_err();
        assert_eq!(
            e,
            DigestCredentialError::Line {
                line: 2,
                rule: USERNAME_RULE
            }
        );
    }

    /// F1 / SEC-005: a UTF-8 byte order mark is a line 1 error, not a
    /// silently different first username.
    #[test]
    fn utf8_bom_is_a_line_1_error() {
        for content in [
            format!("\u{feff}alice:{REALM}:SHA-256:{SENTINEL}\n"),
            format!("\u{feff}# comment\nalice:{REALM}:SHA-256:{SENTINEL}\n"),
            format!("\u{feff}\r\nalice:{REALM}:SHA-256:{SENTINEL}\r\n"),
            "\u{feff}".to_string(),
        ] {
            let e = parse(&content).unwrap_err();
            match e {
                DigestCredentialError::Line { line, rule } => {
                    assert_eq!(line, 1);
                    assert!(rule.contains("byte order mark"), "{rule}");
                }
                other => panic!("expected a line 1 error, got {other:?}"),
            }
            assert_no_content(e, "alice");
        }
        // A BOM anywhere else is a username character outside the rule.
        let (line, rule) = line_err(&format!(
            "bob:{REALM}:SHA-256:{SENTINEL}\n\u{feff}alice:{REALM}:SHA-256:{SENTINEL}\n"
        ));
        assert_eq!((line, rule), (2, USERNAME_RULE));
        // Through the real loader: the file is refused and reload keeps
        // the old table.
        let dir = tempfile::tempdir().unwrap();
        let good = format!("alice:{REALM}:SHA-256:{SENTINEL}\n");
        let path = write_file(dir.path(), "digest.ha1", good.as_bytes(), 0o600);
        let store = DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap();
        write_file(
            dir.path(),
            "digest.ha1",
            format!("\u{feff}{good}").as_bytes(),
            0o600,
        );
        assert!(matches!(
            store.reload(),
            Err(DigestCredentialError::Line { line: 1, .. })
        ));
        assert!(
            store
                .snapshot()
                .ha1("alice", DigestAlgorithm::Sha256)
                .is_some()
        );
        assert!(
            DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).is_err(),
            "startup load refuses a BOM too"
        );
    }

    /// RFC-001 / RFC-002 / F2 / SEC-006: file usernames are ASCII in the
    /// RFC 3261 `user` production; anything a REGISTER could never match
    /// byte for byte fails the load with the line number.
    #[test]
    fn usernames_follow_the_rfc3261_user_production() {
        for ok in [
            "alice",
            "Alice.Smith-01",
            "+12025550100",
            "a_b!c~d*e'f(g)h",
            "u&v=w+x$y,z;q?r/s",
            "%41lice",
            "a%2fb",
            "0",
        ] {
            let table = parse(&format!("{ok}:{REALM}:SHA-256:{SENTINEL}\n"))
                .unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert!(table.ha1(ok, DigestAlgorithm::Sha256).is_some(), "{ok}");
        }
        for bad in [
            " alice",
            "alice ",
            "al ice",
            "alice@example.test",
            "@",
            "\"alice\"",
            "al\"ice",
            "al\\ice",
            "j\u{f6}rg",
            "\u{430}lice",
            "al\u{200b}ice",
            "alice#1",
            "<alice>",
            "al[i]ce",
            "a|b",
            "a^b",
            "a`b",
            "a{b}",
            "100%",
            "a%2",
            "a%zzb",
            "a%2gb",
            "al\tice",
            "al\u{7f}ice",
        ] {
            let content =
                format!("ok:{REALM}:SHA-256:{SENTINEL}\n{bad}:{REALM}:SHA-256:{SENTINEL}\n");
            let e = parse(&content).unwrap_err();
            assert_eq!(
                e,
                DigestCredentialError::Line {
                    line: 2,
                    rule: USERNAME_RULE
                },
                "{bad:?}"
            );
            assert_no_content(e, bad);
        }
        assert!(!is_sip_user(b""));
    }

    /// PERF-002: the table is sized once from the line count, capped by the
    /// entry limit, so a huge line count cannot reserve past the limit.
    #[test]
    fn table_is_presized_from_the_line_count() {
        let content = (0..500)
            .map(|i| line(&format!("user{i}"), REALM, "pw-for-test", "SHA-256"))
            .collect::<Vec<_>>()
            .concat();
        let table = parse(&content).unwrap();
        assert_eq!(table.len(), 500);
        assert!(table.users.capacity() >= 500);
        // 10,000 blank lines and one entry with a limit of 4 entries: the
        // reservation follows the limit, not the line count.
        let sparse = format!("{}alice:{REALM}:SHA-256:{SENTINEL}\n", "\n".repeat(10_000));
        let table = parse_table(sparse.as_bytes(), REALM, FileAlgorithm::Sha256, 4).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.users.capacity() < 64, "{}", table.users.capacity());
    }

    /// PERF-001: after a reload the replaced table is dropped by the
    /// reload itself when no reader holds it, and a reader that still holds
    /// a snapshot only delays the reload by the bounded wait.
    #[test]
    fn reload_drops_the_replaced_table_itself() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = format!("alice:{REALM}:SHA-256:{SENTINEL}\n");
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let store = DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap();

        let old = Arc::downgrade(&store.snapshot());
        store.reload().unwrap();
        assert!(old.upgrade().is_none(), "freed on the reload thread");

        // A reader holding the old table: the reload still completes, within
        // the bounded wait, and the reader's snapshot stays usable.
        let held = store.snapshot();
        let started = std::time::Instant::now();
        store.reload().unwrap();
        let waited = started.elapsed();
        assert!(
            waited >= OLD_TABLE_DROP_POLL * (OLD_TABLE_DROP_POLLS / 2),
            "{waited:?}"
        );
        assert!(waited < std::time::Duration::from_secs(5), "{waited:?}");
        assert!(held.ha1("alice", DigestAlgorithm::Sha256).is_some());
        assert!(!Arc::ptr_eq(&held, &store.snapshot()));
    }

    #[test]
    fn duplicate_entry_is_rejected() {
        let dup = format!(
            "alice:{REALM}:SHA-256:{SENTINEL}\nbob:{REALM}:SHA-256:{SENTINEL}\n\
             alice:{REALM}:SHA-256:{SENTINEL}\n"
        );
        let (line, rule) = line_err(&dup);
        assert_eq!(line, 3);
        assert!(rule.contains("duplicate"));
    }

    #[test]
    fn empty_file_and_missing_configured_algorithm_are_rejected() {
        for content in ["", "\n\n", "# only a comment\n"] {
            assert!(matches!(
                parse(content),
                Err(DigestCredentialError::Unusable(_))
            ));
        }
        let only_512 = format!("alice:{REALM}:SHA-512-256:{SENTINEL}\n");
        let e = parse(&only_512).unwrap_err();
        assert!(e.to_string().contains("digest_auth.algorithm"), "{e}");
        assert!(
            parse_table(
                only_512.as_bytes(),
                REALM,
                FileAlgorithm::Sha512_256,
                MAX_ENTRIES
            )
            .is_ok()
        );
    }

    #[test]
    fn errors_never_carry_file_content() {
        let user = "very-secret-user";
        for bad in [
            format!("{user}:{REALM}:MD5:{SENTINEL}\n"),
            format!("{user}:wrong:SHA-256:{SENTINEL}\n"),
            format!("{user}:{REALM}:SHA-256:{SENTINEL}zz\n"),
            format!("{user}:{REALM}:SHA-256:{SENTINEL}:x\n"),
            format!("{user}:{REALM}:SHA-256:{SENTINEL}\n{user}:{REALM}:SHA-256:{SENTINEL}\n"),
        ] {
            let e = parse(&bad).unwrap_err();
            for text in [e.to_string(), format!("{e:?}")] {
                assert!(text.contains("line") || text.contains("Line"), "{text}");
                assert!(!text.contains(SENTINEL), "{text}");
                assert!(!text.contains(user), "{text}");
            }
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let content = format!("very-secret-user:{REALM}:SHA-256:{SENTINEL}\n");
        let table = parse(&content).unwrap();
        let ha1 = table
            .ha1("very-secret-user", DigestAlgorithm::Sha256)
            .unwrap();
        assert_eq!(format!("{ha1:?}"), "Ha1(<redacted>)");
        let text = format!("{table:?}");
        assert!(text.contains("users: 1"), "{text}");
        assert!(!text.contains(SENTINEL) && !text.contains("very-secret-user"));

        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
        let store =
            Arc::new(DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap());
        let config = crate::sip_stack::SipStackConfig {
            digest_credentials: Some(Arc::clone(&store)),
            ..Default::default()
        };
        for text in [format!("{store:?}"), format!("{config:?}")] {
            assert!(text.contains("DigestCredentialStore"), "{text}");
            assert!(!text.contains(SENTINEL), "{text}");
            assert!(!text.contains("very-secret-user"), "{text}");
        }
    }

    #[test]
    fn random_decoy_is_valid_hex_and_differs() {
        let a = Ha1::random().unwrap();
        let b = Ha1::random().unwrap();
        assert_eq!(a.expose().len(), HA1_HEX_LEN);
        assert!(
            a.expose()
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn from_passwords_matches_file_ha1() {
        let store = DigestCredentialStore::from_passwords(REALM, &[("alice", "pw-for-test")]);
        let table = store.snapshot();
        for (alg, name) in [
            (DigestAlgorithm::Sha256, "SHA-256"),
            (DigestAlgorithm::Sha512_256, "SHA-512-256"),
        ] {
            assert_eq!(
                table.ha1("alice", alg).map(Ha1::expose),
                Some(ha1_hex("alice", REALM, "pw-for-test", name).as_str())
            );
        }
        // No file behind it: reload fails and keeps the table.
        assert!(store.reload().is_err());
        assert_eq!(store.reload_failures(), 1);
        assert_eq!(store.users(), 1);
    }

    #[test]
    fn owner_must_be_the_daemon_user_or_root() {
        assert!(owner_allowed(1000, 1000));
        assert!(owner_allowed(0, 1000));
        assert!(owner_allowed(0, 0));
        assert!(!owner_allowed(1001, 1000));
        assert!(!owner_allowed(1000, 0));
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_rules() {
        let dir = tempfile::tempdir().unwrap();
        let content = line("alice", REALM, "pw-for-test", "SHA-256");
        for mode in [0o644, 0o640, 0o604, 0o660, 0o601] {
            let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), mode);
            let e = DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap_err();
            assert!(e.to_string().contains("group or other"), "{mode:o}: {e}");
        }
        for mode in [0o600, 0o400] {
            let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), mode);
            let store = DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap();
            assert_eq!(store.users(), 1);
            assert_eq!(store.path(), path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_directory_fifo_and_missing_file_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let content = line("alice", REALM, "pw-for-test", "SHA-256");
        let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
        let load = |p: &Path| DigestCredentialStore::load(p, REALM, DigestAlgorithm::Sha256);

        let link = dir.path().join("link.ha1");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            load(&link).unwrap_err(),
            DigestCredentialError::File("must not be a symlink")
        );
        assert_eq!(
            load(dir.path()).unwrap_err(),
            DigestCredentialError::File("must be a regular file")
        );
        let fifo = dir.path().join("fifo.ha1");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        assert_eq!(
            load(&fifo).unwrap_err(),
            DigestCredentialError::File("must be a regular file")
        );
        assert_eq!(
            load(&dir.path().join("absent.ha1")).unwrap_err(),
            DigestCredentialError::Io(std::io::ErrorKind::NotFound)
        );
        assert!(load(&path).is_ok());
    }

    #[test]
    fn size_and_entry_caps() {
        let dir = tempfile::tempdir().unwrap();
        let content = format!(
            "{}{}{}",
            line("alice", REALM, "pw-a", "SHA-256"),
            line("bob", REALM, "pw-b", "SHA-256"),
            line("carol", REALM, "pw-c", "SHA-256"),
        );
        let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
        let load = |max_bytes: u64, max_entries: usize| {
            DigestCredentialStore::load_with_limits(
                &path,
                REALM,
                DigestAlgorithm::Sha256,
                Limits {
                    max_bytes,
                    max_entries,
                },
            )
        };
        let len = content.len() as u64;
        assert!(load(len, 3).is_ok());
        assert_eq!(
            load(len - 1, 3).unwrap_err(),
            DigestCredentialError::File("is larger than the size limit")
        );
        assert_eq!(
            load(len, 2).unwrap_err(),
            DigestCredentialError::File("has more entries than the limit")
        );
    }

    #[test]
    fn unsupported_configured_algorithm_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let content = line("alice", REALM, "pw-a", "SHA-256");
        let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
        for alg in [
            DigestAlgorithm::Md5,
            DigestAlgorithm::Md5Sess,
            DigestAlgorithm::Sha256Sess,
            DigestAlgorithm::Sha512_256Sess,
        ] {
            assert!(matches!(
                DigestCredentialStore::load(&path, REALM, alg),
                Err(DigestCredentialError::Unusable(_))
            ));
        }
    }

    #[test]
    fn reload_swaps_on_success_and_keeps_old_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = format!(
            "{}{}",
            line("alice", REALM, "pw-a", "SHA-256"),
            line("bob", REALM, "pw-b", "SHA-256")
        );
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let store = DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap();
        let before = store.snapshot();

        // Good file: bob removed, carol and dave added.
        let v2 = format!(
            "{}{}{}",
            line("alice", REALM, "pw-a2", "SHA-256"),
            line("carol", REALM, "pw-c", "SHA-256"),
            line("dave", REALM, "pw-d", "SHA-256")
        );
        write_file(dir.path(), "digest.ha1", v2.as_bytes(), 0o600);
        assert_eq!(
            store.reload().unwrap(),
            ReloadSummary {
                users: 3,
                added: 2,
                removed: 1
            }
        );
        let after = store.snapshot();
        assert!(after.ha1("bob", DigestAlgorithm::Sha256).is_none());
        assert_eq!(
            after.ha1("alice", DigestAlgorithm::Sha256).map(Ha1::expose),
            Some(ha1_hex("alice", REALM, "pw-a2", "SHA-256").as_str())
        );
        // A snapshot taken before the reload is still the old table.
        assert!(before.ha1("bob", DigestAlgorithm::Sha256).is_some());

        // Bad content, bad mode, then no file: the v2 table stays.
        write_file(dir.path(), "digest.ha1", b"alice:nope\n", 0o600);
        assert!(matches!(
            store.reload(),
            Err(DigestCredentialError::Line { line: 1, .. })
        ));
        write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o644);
        assert!(store.reload().is_err());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            store.reload().unwrap_err(),
            DigestCredentialError::Io(std::io::ErrorKind::NotFound)
        );
        assert_eq!(store.reload_failures(), 3);
        assert_eq!(store.users(), 3);
        assert!(
            store
                .snapshot()
                .ha1("carol", DigestAlgorithm::Sha256)
                .is_some()
        );
    }

    fn config_changes(events: &[uc_audit::AuditEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::ConfigurationChange(c) => Some(c.description.clone()),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn reload_is_audited_without_usernames_or_ha1() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = format!("very-secret-user:{REALM}:SHA-256:{SENTINEL}\n");
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let store =
            Arc::new(DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap());

        let capture = uc_audit::capture::start();
        audit_loaded(&store);
        assert_eq!(
            reload_and_audit(&store).await.unwrap(),
            ReloadSummary {
                users: 1,
                added: 0,
                removed: 0
            }
        );
        let bad = format!("very-secret-user:{REALM}:MD5:{SENTINEL}\n");
        write_file(dir.path(), "digest.ha1", bad.as_bytes(), 0o600);
        assert!(reload_and_audit(&store).await.is_err());
        let events = config_changes(&capture.events());
        assert_eq!(events.len(), 3, "{events:?}");
        assert!(events[0].contains("credentials loaded: users=1"));
        assert!(events[1].contains("users=1 added=0 removed=0"));
        assert!(events[2].contains("reload failed, previous credentials kept"));
        assert!(events[2].contains("line 1"), "{}", events[2]);
        for e in &events {
            assert!(
                !e.contains(SENTINEL) && !e.contains("very-secret-user"),
                "{e}"
            );
        }
        assert_eq!(store.reload_failures(), 1);

        // NIST-005 / NIST-008: every load and reload is also a key
        // operation with an explicit outcome: the startup load and the
        // good reload as successes, the failed reload as a failure.
        let key_ops: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::CryptoKeyOperation(k) => Some(k),
                _ => None,
            })
            .collect();
        assert_eq!(key_ops.len(), 3, "{key_ops:?}");
        for (k, operation) in key_ops.iter().zip([
            uc_audit::event::KeyOperationType::Loaded,
            uc_audit::event::KeyOperationType::Rotated,
        ]) {
            assert_eq!(k.key_id, AUDIT_KEY_ID);
            assert_eq!(k.operation, operation);
            assert_eq!(k.outcome, uc_audit::event::KeyOperationOutcome::Success);
            assert_eq!(k.algorithm, "SHA-256");
            assert_eq!(k.reason, None);
        }
        let f = &key_ops[2];
        assert_eq!(f.key_id, AUDIT_KEY_ID);
        assert_eq!(f.operation, uc_audit::event::KeyOperationType::Rotated);
        assert_eq!(f.outcome, uc_audit::event::KeyOperationOutcome::Failure);
        assert_eq!(f.algorithm, "SHA-256");
        let reason = f.reason.as_deref().unwrap();
        assert!(reason.contains("line 1"), "{reason}");
        assert!(
            reason.contains("MD5 credentials are not accepted"),
            "{reason}"
        );
        let json = serde_json::to_string(f).unwrap();
        assert!(json.contains(r#""outcome":"failure""#), "{json}");
        for text in [reason.to_string(), json] {
            assert!(
                !text.contains(SENTINEL)
                    && !text.contains("very-secret-user")
                    && !text.contains("digest.ha1"),
                "{text}"
            );
        }
    }

    // ---- QA additions (POA&M-270) ----

    /// Asserts that neither `Display` nor `Debug` of `e` carries file
    /// content (the sentinel HA1, in either case, or `user`).
    fn assert_no_content(e: DigestCredentialError, user: &str) {
        for text in [e.to_string(), format!("{e:?}"), format!("{e:#?}")] {
            assert!(!text.contains(SENTINEL), "{text}");
            assert!(!text.contains(&SENTINEL.to_ascii_uppercase()), "{text}");
            assert!(!text.contains(&SENTINEL[..16]), "{text}");
            assert!(!text.contains(user), "{text}");
        }
    }

    /// CR, NUL and other control bytes inside a field never make a second
    /// entry or a silently different user: the line fails, with its number.
    #[test]
    fn qa_cr_nul_and_whitespace_inside_fields_fail_the_line() {
        let user = "very-secret-user";
        let cases: Vec<(String, &str)> = vec![
            // CR in the middle of a username (CRLF-injection shape).
            (
                format!("very-secret\r-user:{REALM}:SHA-256:{SENTINEL}"),
                "RFC 3261 user production",
            ),
            (
                format!("{user}\0:{REALM}:SHA-256:{SENTINEL}"),
                "RFC 3261 user production",
            ),
            (
                format!("{user}\t:{REALM}:SHA-256:{SENTINEL}"),
                "RFC 3261 user production",
            ),
            // C1 control (NEL).
            (
                format!("{user}\u{85}:{REALM}:SHA-256:{SENTINEL}"),
                "RFC 3261 user production",
            ),
            // Only one trailing CR is a line ending.
            (format!("{user}:{REALM}:SHA-256:{SENTINEL}\r"), "64 hex"),
            // Whitespace around the HA1 or the algorithm is not trimmed.
            (format!("{user}:{REALM}:SHA-256:{SENTINEL} "), "64 hex"),
            (format!("{user}:{REALM}:SHA-256: {SENTINEL}"), "64 hex"),
            (
                format!("{user}:{REALM}: SHA-256:{SENTINEL}"),
                "algorithm must be",
            ),
            // Realm compares byte for byte: case and padding matter.
            (
                format!("{user}:{}:SHA-256:{SENTINEL}", REALM.to_ascii_uppercase()),
                "realm does not match",
            ),
            (
                format!("{user}:{REALM} :SHA-256:{SENTINEL}"),
                "realm does not match",
            ),
            (
                format!("{user}:{REALM}\0:SHA-256:{SENTINEL}"),
                "realm does not match",
            ),
            // Classic-Mac line endings: two entries on one "line".
            (
                format!("{user}:{REALM}:SHA-256:{SENTINEL}\rbob:{REALM}:SHA-256:{SENTINEL}"),
                "expected username",
            ),
            // An inline comment is not a comment.
            (
                format!("{user}:{REALM}:SHA-256:{SENTINEL} # note"),
                "64 hex",
            ),
            // Wrong digest lengths: MD5-sized and SHA-512-sized values.
            (
                format!("{user}:{REALM}:SHA-256:{}", &SENTINEL[..32]),
                "64 hex",
            ),
            (
                format!("{user}:{REALM}:SHA-512-256:{SENTINEL}{SENTINEL}"),
                "64 hex",
            ),
            // 64 characters, but not 64 ASCII hex bytes.
            (
                format!("{user}:{REALM}:SHA-256:{}", "\u{ff11}".repeat(64)),
                "64 hex",
            ),
            (
                format!("{user}:{REALM}:SHA-256:0x{}", &SENTINEL[..62]),
                "64 hex",
            ),
            // Any -sess algorithm and other digests.
            (
                format!("{user}:{REALM}:SHA-512-256-sess:{SENTINEL}"),
                "algorithm must be",
            ),
            (
                format!("{user}:{REALM}:SHA-512:{SENTINEL}"),
                "algorithm must be",
            ),
            (format!("{user}:{REALM}:Md5:{}", &SENTINEL[..32]), "MD5"),
        ];
        for (bad, needle) in cases {
            // CRLF file with a comment and a blank line before the bad line.
            let content = format!("# c\r\n\r\nok:{REALM}:SHA-256:{SENTINEL}\r\n{bad}\r\n");
            let e = parse(&content).unwrap_err();
            match e {
                DigestCredentialError::Line { line, rule } => {
                    assert_eq!(line, 4, "{rule}");
                    assert!(rule.contains(needle), "{rule} should mention {needle}");
                }
                other => panic!("expected a line error, got {other:?}"),
            }
            assert_no_content(e, user);
        }
    }

    /// Username bounds: 255 bytes is the longest accepted; usernames are
    /// matched exactly. (Changed in fix round 1: non-ASCII usernames are
    /// now a load error, see `usernames_follow_the_rfc3261_user_production`.)
    #[test]
    fn qa_username_boundaries() {
        let max = "u".repeat(255);
        let content = format!(
            "{max}:{REALM}:SHA-256:{SENTINEL}\n\
             Alice:{REALM}:SHA-256:{SENTINEL}\nalice:{REALM}:SHA-256:{SENTINEL}\n"
        );
        let table = parse(&content).unwrap();
        // Usernames differing only in case are different users.
        assert_eq!(table.len(), 3);
        assert!(table.ha1(&max, DigestAlgorithm::Sha256).is_some());
        assert!(table.ha1("ALICE", DigestAlgorithm::Sha256).is_none());
        assert!(table.ha1("", DigestAlgorithm::Sha256).is_none());
        let (line, rule) = line_err(&format!("{max}u:{REALM}:SHA-256:{SENTINEL}\n"));
        assert_eq!(line, 1);
        assert!(rule.contains("longer than 255"), "{rule}");
        // 256 bytes through multi-byte characters (128 x 2 bytes).
        let long = "\u{f6}".repeat(128);
        let (line, rule) = line_err(&format!("{long}:{REALM}:SHA-256:{SENTINEL}\n"));
        assert_eq!(line, 1);
        assert!(rule.contains("longer than 255"), "{rule}");
        let (line, rule) = line_err(&format!("j\u{f6}rg:{REALM}:SHA-256:{SENTINEL}\n"));
        assert_eq!((line, rule), (1, USERNAME_RULE));
    }

    /// Duplicate detection is per (username, algorithm): both algorithms
    /// for one user are fine, a repeat of either is not, whatever the hex
    /// case, and the reported line is the second occurrence.
    #[test]
    fn qa_duplicate_rules_per_user_and_algorithm() {
        let upper = SENTINEL.to_ascii_uppercase();
        let both = format!(
            "alice:{REALM}:SHA-256:{SENTINEL}\nalice:{REALM}:SHA-512-256:{SENTINEL}\n\
             bob:{REALM}:SHA-256:{SENTINEL}\n"
        );
        assert_eq!(parse(&both).unwrap().len(), 2);

        for (dup, at) in [
            (
                format!("{both}# c\n\nalice:{REALM}:SHA-512-256:{upper}\n"),
                6,
            ),
            (format!("{both}alice:{REALM}:SHA-256:{upper}\n"), 4),
            (format!("{both}\r\nbob:{REALM}:SHA-256:{SENTINEL}"), 5),
        ] {
            let e = parse(&dup).unwrap_err();
            assert_eq!(
                e,
                DigestCredentialError::Line {
                    line: at,
                    rule: "duplicate entry for this username and algorithm"
                }
            );
            assert_no_content(e, "alice");
        }
    }

    /// The entry cap counts entries (lines), not users; comments and blank
    /// lines are free; the shipped defaults are the documented bounds.
    #[test]
    fn qa_entry_cap_boundaries_and_default_limits() {
        assert_eq!(MAX_FILE_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_ENTRIES, 1_000_000);
        let d = Limits::default();
        assert_eq!((d.max_bytes, d.max_entries), (MAX_FILE_BYTES, MAX_ENTRIES));

        let two = format!(
            "# c\n\nalice:{REALM}:SHA-256:{SENTINEL}\n# c\nalice:{REALM}:SHA-512-256:{SENTINEL}\n\n"
        );
        let with = |content: &str, max| {
            parse_table(content.as_bytes(), REALM, FileAlgorithm::Sha256, max).map(|t| t.len())
        };
        assert_eq!(with(&two, 2), Ok(1));
        let over = DigestCredentialError::File("has more entries than the limit");
        assert_eq!(with(&two, 1), Err(over));
        assert_eq!(with(&two, 0), Err(over));
        let three = format!("{two}bob:{REALM}:SHA-256:{SENTINEL}\n");
        assert_eq!(with(&three, 3), Ok(2));
        assert_eq!(with(&three, 2), Err(over));
        assert_no_content(over, "alice");
    }

    /// An empty, blank or comment-only file, and a file without an entry
    /// for the configured algorithm, are refused through the real loader
    /// (never an empty table that would reject or admit everyone silently).
    #[test]
    fn qa_empty_and_unusable_files_are_refused_by_load() {
        let dir = tempfile::tempdir().unwrap();
        let only_256 = format!("alice:{REALM}:SHA-256:{SENTINEL}\n");
        for content in ["", "\n", "\r\n\r\n", " \t \n", "# nothing here\n#\n"] {
            let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
            for alg in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512_256] {
                assert!(
                    matches!(
                        DigestCredentialStore::load(&path, REALM, alg),
                        Err(DigestCredentialError::Unusable(_))
                    ),
                    "{content:?}"
                );
            }
        }
        let path = write_file(dir.path(), "digest.ha1", only_256.as_bytes(), 0o600);
        let e = DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha512_256).unwrap_err();
        assert!(matches!(e, DigestCredentialError::Unusable(_)), "{e:?}");
        assert_no_content(e, "alice");
        // The same file under another configured realm fails on line 1.
        let e = DigestCredentialStore::load(&path, "other.example.test", DigestAlgorithm::Sha256)
            .unwrap_err();
        assert!(
            matches!(e, DigestCredentialError::Line { line: 1, .. }),
            "{e:?}"
        );
        assert_no_content(e, "alice");
    }

    /// More group/other mode bits, a dangling symlink, a symlink to a
    /// directory, and a file the daemon cannot read.
    #[cfg(unix)]
    #[test]
    fn qa_more_mode_symlink_and_unreadable_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let content = line("alice", REALM, "pw-for-test", "SHA-256");
        let load = |p: &Path| DigestCredentialStore::load(p, REALM, DigestAlgorithm::Sha256);
        for mode in [0o620, 0o610, 0o602, 0o440, 0o404, 0o444, 0o666, 0o777] {
            let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), mode);
            let e = load(&path).unwrap_err();
            assert!(e.to_string().contains("group or other"), "{mode:o}: {e}");
        }

        let symlink = DigestCredentialError::File("must not be a symlink");
        let dangling = dir.path().join("dangling.ha1");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert_eq!(load(&dangling).unwrap_err(), symlink);
        let to_dir = dir.path().join("dir.ha1");
        std::os::unix::fs::symlink(dir.path(), &to_dir).unwrap();
        assert_eq!(load(&to_dir).unwrap_err(), symlink);
        // A symlink to a symlink to a good file.
        let good = write_file(dir.path(), "good.ha1", content.as_bytes(), 0o600);
        let hop1 = dir.path().join("hop1.ha1");
        std::os::unix::fs::symlink(&good, &hop1).unwrap();
        let hop2 = dir.path().join("hop2.ha1");
        std::os::unix::fs::symlink(&hop1, &hop2).unwrap();
        assert_eq!(load(&hop2).unwrap_err(), symlink);

        // Owner without read permission. Root reads anything, so the check
        // only means something for an unprivileged test run.
        if !nix::unistd::geteuid().is_root() {
            for mode in [0o000, 0o200, 0o300] {
                let path = write_file(dir.path(), "noread.ha1", content.as_bytes(), mode);
                assert_eq!(
                    load(&path).unwrap_err(),
                    DigestCredentialError::Io(std::io::ErrorKind::PermissionDenied),
                    "{mode:o}"
                );
            }
        }
    }

    /// Every way a reload can fail keeps the table that was in force, and
    /// each failure is counted once.
    #[cfg(unix)]
    #[test]
    fn qa_reload_keeps_old_table_for_every_failure_kind() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = line("alice", REALM, "pw-a", "SHA-256");
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let store = DigestCredentialStore::load_with_limits(
            &path,
            REALM,
            DigestAlgorithm::Sha256,
            Limits {
                max_bytes: (v1.len() * 6) as u64,
                max_entries: 3,
            },
        )
        .unwrap();
        let alice_v1 = ha1_hex("alice", REALM, "pw-a", "SHA-256");
        let still_v1 = |step: &str| {
            let t = store.snapshot();
            assert_eq!(t.len(), 1, "{step}");
            assert_eq!(
                t.ha1("alice", DigestAlgorithm::Sha256).map(Ha1::expose),
                Some(alice_v1.as_str()),
                "{step}"
            );
            assert!(t.ha1("mallory", DigestAlgorithm::Sha256).is_none());
        };
        let mallory = line("mallory", REALM, "pw-m", "SHA-256");
        let mut failures = 0;
        let mut expect_fail = |step: &str, want: Option<DigestCredentialError>| {
            let e = store.reload().expect_err(step);
            if let Some(want) = want {
                assert_eq!(e, want, "{step}");
            }
            assert_no_content(e, "mallory");
            failures += 1;
            assert_eq!(store.reload_failures(), failures, "{step}");
            still_v1(step);
        };

        // Empty and comment-only.
        write_file(dir.path(), "digest.ha1", b"", 0o600);
        expect_fail("empty", None);
        write_file(dir.path(), "digest.ha1", b"# all users removed\n", 0o600);
        expect_fail("comment only", None);
        // One good line and one bad line: nothing of the file is applied.
        let partial = format!("{mallory}alice:{REALM}:MD5:{SENTINEL}\n");
        write_file(dir.path(), "digest.ha1", partial.as_bytes(), 0o600);
        expect_fail(
            "partial",
            Some(DigestCredentialError::Line {
                line: 2,
                rule: "MD5 credentials are not accepted",
            }),
        );
        // Other realm, other algorithm only.
        let other_realm = line("mallory", "other.example.test", "pw-m", "SHA-256");
        write_file(dir.path(), "digest.ha1", other_realm.as_bytes(), 0o600);
        expect_fail("realm", None);
        let other_alg = line("mallory", REALM, "pw-m", "SHA-512-256");
        write_file(dir.path(), "digest.ha1", other_alg.as_bytes(), 0o600);
        expect_fail("algorithm", None);
        // Over the entry cap, then over the size cap.
        let four = format!(
            "{mallory}{}{}{}",
            line("b", REALM, "pw-b", "SHA-256"),
            line("c", REALM, "pw-c", "SHA-256"),
            line("d", REALM, "pw-d", "SHA-256")
        );
        write_file(dir.path(), "digest.ha1", four.as_bytes(), 0o600);
        expect_fail(
            "entries",
            Some(DigestCredentialError::File(
                "has more entries than the limit",
            )),
        );
        let padded = format!("{mallory}# {}\n", "x".repeat(v1.len() * 6));
        write_file(dir.path(), "digest.ha1", padded.as_bytes(), 0o600);
        expect_fail(
            "bytes",
            Some(DigestCredentialError::File("is larger than the size limit")),
        );
        // Group-readable, then replaced by a symlink to a valid file, a
        // directory, and finally nothing.
        write_file(dir.path(), "digest.ha1", mallory.as_bytes(), 0o640);
        expect_fail("mode", None);
        let elsewhere = write_file(dir.path(), "elsewhere.ha1", mallory.as_bytes(), 0o600);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        expect_fail(
            "symlink",
            Some(DigestCredentialError::File("must not be a symlink")),
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        expect_fail(
            "directory",
            Some(DigestCredentialError::File("must be a regular file")),
        );
        std::fs::remove_dir(&path).unwrap();
        expect_fail(
            "missing",
            Some(DigestCredentialError::Io(std::io::ErrorKind::NotFound)),
        );

        // A good file after all that swaps, and the counter stays.
        write_file(dir.path(), "digest.ha1", mallory.as_bytes(), 0o600);
        assert_eq!(
            store.reload().unwrap(),
            ReloadSummary {
                users: 1,
                added: 1,
                removed: 1
            }
        );
        assert_eq!(store.reload_failures(), failures);
        assert!(
            store
                .snapshot()
                .ha1("alice", DigestAlgorithm::Sha256)
                .is_none()
        );
    }

    /// Audit record fields (CM-3, AU-3): the reload event is a
    /// `ConfigurationChange` of type `Reloaded` by `config-reload` with
    /// counts on success and the failed rule on failure; the startup event
    /// is `Loaded` by `startup`. None carries a username, an HA1 or a path.
    #[cfg(unix)]
    #[tokio::test]
    async fn qa_reload_audit_event_fields() {
        use uc_audit::event::ConfigChangeType;
        let dir = tempfile::tempdir().unwrap();
        let v1 = format!(
            "very-secret-user:{REALM}:SHA-256:{SENTINEL}\nold-user:{REALM}:SHA-256:{SENTINEL}\n"
        );
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let store =
            Arc::new(DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap());
        let capture = uc_audit::capture::start();
        audit_loaded(&store);

        let v2 = format!(
            "very-secret-user:{REALM}:SHA-256:{SENTINEL}\nnew-user-1:{REALM}:SHA-256:{SENTINEL}\n\
             new-user-2:{REALM}:SHA-256:{SENTINEL}\n"
        );
        write_file(dir.path(), "digest.ha1", v2.as_bytes(), 0o600);
        assert_eq!(
            reload_and_audit(&store).await.unwrap(),
            ReloadSummary {
                users: 3,
                added: 2,
                removed: 1
            }
        );
        // Three failures of different kinds: file rule, I/O, table rule.
        write_file(dir.path(), "digest.ha1", v2.as_bytes(), 0o644);
        assert!(reload_and_audit(&store).await.is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(reload_and_audit(&store).await.is_err());
        let only_512 = format!("very-secret-user:{REALM}:SHA-512-256:{SENTINEL}\n");
        write_file(dir.path(), "digest.ha1", only_512.as_bytes(), 0o600);
        assert!(reload_and_audit(&store).await.is_err());

        let events: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::ConfigurationChange(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), 5, "{events:?}");
        assert_eq!(events[0].admin, "startup");
        assert_eq!(events[0].change_type, ConfigChangeType::Loaded);
        assert!(events[0].description.contains("users=2"));
        for e in &events[1..] {
            assert_eq!(e.admin, "config-reload");
            assert_eq!(e.change_type, ConfigChangeType::Reloaded);
        }
        assert!(
            events[1]
                .description
                .contains("credentials reloaded: users=3 added=2 removed=1"),
            "{}",
            events[1].description
        );
        for (e, rule) in events[2..].iter().zip([
            "group or other",
            "could not be read",
            "no entry for the configured digest_auth.algorithm",
        ]) {
            assert!(
                e.description
                    .contains("reload failed, previous credentials kept"),
                "{}",
                e.description
            );
            assert!(e.description.contains(rule), "{}", e.description);
        }
        let dir_text = dir.path().display().to_string();
        for e in &events {
            let text = format!("{e:?}");
            assert!(text.contains("[digest_auth]"), "{text}");
            for secret in [
                SENTINEL,
                "very-secret-user",
                "old-user",
                "new-user",
                dir_text.as_str(),
            ] {
                assert!(!text.contains(secret), "{text}");
            }
        }
        // Failures are counted (the `..._reload_failures_total` metric) and
        // the table of the last good reload is still served.
        assert_eq!(store.reload_failures(), 3);
        assert_eq!(store.users(), 3);
    }

    /// `Debug` of everything that can reach a log line, in both forms.
    #[test]
    fn qa_debug_of_snapshots_options_and_decoy_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let content = format!(
            "very-secret-user:{REALM}:SHA-256:{SENTINEL}\n\
             very-secret-user:{REALM}:SHA-512-256:{SENTINEL}\n"
        );
        let path = write_file(dir.path(), "digest.ha1", content.as_bytes(), 0o600);
        let store =
            Arc::new(DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap());
        let snapshot = store.snapshot();
        let found = snapshot.ha1("very-secret-user", DigestAlgorithm::Sha512_256);
        assert_eq!(format!("{found:?}"), "Some(Ha1(<redacted>))");
        let decoy = Ha1::random().unwrap();
        let decoy_text = format!("{decoy:?} {decoy:#?}");
        assert!(!decoy_text.contains(decoy.expose()), "{decoy_text}");
        let some_store = Some(Arc::clone(&store));
        for text in [
            format!("{snapshot:?}"),
            format!("{snapshot:#?}"),
            format!("{store:#?}"),
            format!("{some_store:?}"),
            format!("{found:#?}"),
            format!("{:?}", store.reload()),
        ] {
            assert!(!text.contains(SENTINEL), "{text}");
            assert!(!text.contains("very-secret-user"), "{text}");
        }
    }

    /// A reader racing reloads sees one whole table or the other, never a
    /// mix and never an empty one.
    #[test]
    fn qa_snapshot_during_reload_is_never_mixed_or_empty() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = format!(
            "{}{}",
            line("alice", REALM, "pw-a", "SHA-256"),
            line("bob", REALM, "pw-b", "SHA-256")
        );
        let v2 = line("carol", REALM, "pw-c", "SHA-256");
        let path = write_file(dir.path(), "digest.ha1", v1.as_bytes(), 0o600);
        let store =
            Arc::new(DigestCredentialStore::load(&path, REALM, DigestAlgorithm::Sha256).unwrap());
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let (store, done) = (Arc::clone(&store), Arc::clone(&done));
                std::thread::spawn(move || {
                    let mut seen = 0u64;
                    while !done.load(Ordering::Relaxed) {
                        let t = store.snapshot();
                        let has = |u: &str| t.ha1(u, DigestAlgorithm::Sha256).is_some();
                        let is_v1 = t.len() == 2 && has("alice") && has("bob") && !has("carol");
                        let is_v2 = t.len() == 1 && has("carol") && !has("alice") && !has("bob");
                        assert!(is_v1 || is_v2, "mixed or empty table: {t:?}");
                        seen += 1;
                    }
                    seen
                })
            })
            .collect();
        for i in 0..40 {
            let (content, bad) = match i % 3 {
                0 => (v2.as_bytes(), false),
                1 => (&b"broken\n"[..], true),
                _ => (v1.as_bytes(), false),
            };
            write_file(dir.path(), "digest.ha1", content, 0o600);
            assert_eq!(store.reload().is_err(), bad);
        }
        done.store(true, Ordering::Relaxed);
        for r in readers {
            assert!(r.join().unwrap() > 0);
        }
    }

    /// Table-driven stand-in for a property test (proptest is not a
    /// dev-dependency here): a generated valid file parses to the entries
    /// that were written, and any single-byte corruption parses or errors,
    /// never panics.
    #[test]
    fn generated_files_round_trip_and_corruption_never_panics() {
        use std::fmt::Write as _;
        let mut content = String::from("# generated\n");
        let mut expect = Vec::new();
        for i in 0..24u32 {
            let user = format!("user{i}+{}", "x".repeat((i % 5) as usize));
            for alg in ["SHA-256", "SHA-512-256"] {
                if alg == "SHA-512-256" && i % 3 == 0 {
                    continue;
                }
                let hex = ha1_hex(&user, REALM, &format!("pw-{i}"), alg);
                let sep = if i % 2 == 0 { "\n" } else { "\r\n" };
                let _ = write!(content, "{user}:{REALM}:{alg}:{hex}{sep}");
                if i % 7 == 0 {
                    content.push('\n');
                }
                expect.push((user.clone(), alg, hex));
            }
        }
        let table = parse(&content).unwrap();
        assert_eq!(table.len(), 24);
        for (user, alg, hex) in &expect {
            let alg = if *alg == "SHA-256" {
                DigestAlgorithm::Sha256
            } else {
                DigestAlgorithm::Sha512_256
            };
            assert_eq!(table.ha1(user, alg).map(Ha1::expose), Some(hex.as_str()));
        }

        let base = format!(
            "# c\n{}{}",
            line("alice", REALM, "pw-a", "SHA-256"),
            line("bob", REALM, "pw-b", "SHA-512-256")
        )
        .into_bytes();
        for pos in 0..base.len() {
            for byte in [0x00, b'\n', b'\r', b':', b'#', b' ', b'g', b'A', 0x7f, 0xff] {
                let mut bytes = base.clone();
                bytes[pos] = byte;
                match parse_table(&bytes, REALM, FileAlgorithm::Sha256, MAX_ENTRIES) {
                    Ok(t) => assert!(!t.is_empty()),
                    Err(e) => assert_ne!(e.to_string(), ""),
                }
            }
        }
    }
}
