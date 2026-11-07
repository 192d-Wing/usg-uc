//! PII handling for numbers stored in CDRs.
//!
//! ## NIST 800-53 Rev5: SI-12 (Information Management and Retention), AU-3
//! CNSA 2.0: keyed hashing is HMAC-SHA-384 via `uc-crypto`.

use crate::chain::to_hex;
use crate::error::{CdrError, CdrResult};
use crate::record::CallRecord;
use std::path::Path;
use zeroize::Zeroizing;

/// Shortest accepted HMAC key (bytes): the SHA-384 output length.
pub const MIN_HMAC_KEY_LEN: usize = 48;

/// Longest accepted HMAC key file (bytes).
const MAX_HMAC_KEY_LEN: usize = 4096;

/// Digits/characters left visible by [`PiiPolicy::MaskCaller`].
pub const MASK_KEEP: usize = 4;

/// HMAC-SHA-384 key for number hashing. Zeroized on drop; never printed.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment and Management)
#[derive(Clone)]
pub struct HmacKey(Zeroizing<Vec<u8>>);

impl HmacKey {
    /// Wraps raw key bytes (at least [`MIN_HMAC_KEY_LEN`]).
    pub fn from_bytes(bytes: Vec<u8>) -> CdrResult<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() < MIN_HMAC_KEY_LEN || bytes.len() > MAX_HMAC_KEY_LEN {
            return Err(CdrError::config(format!(
                "pii hash key must be {MIN_HMAC_KEY_LEN}..={MAX_HMAC_KEY_LEN} bytes"
            )));
        }
        Ok(Self(bytes))
    }

    /// Loads a key file. One trailing newline is stripped.
    ///
    /// On unix the file must be a regular file (not a symlink) with no
    /// group or other permission bits (like ssh private keys): anyone who
    /// can read the key can reverse `pii = hash` by brute-forcing the small
    /// E.164 space.
    ///
    /// ## NIST 800-53 Rev5: SC-12, IA-5 (Authenticator Management), SI-12
    pub fn load(path: &Path) -> CdrResult<Self> {
        let mut file = open_key_file(path)?;
        check_key_file(&file.metadata()?)?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        Self::from_bytes(bytes)
    }
}

/// Opens the key file without following a final symlink, so the checks in
/// [`check_key_file`] run on the handle that is read (no TOCTOU between
/// check and read). `O_NONBLOCK` keeps a FIFO planted at the path from
/// blocking the open; it has no effect on regular files.
fn open_key_file(path: &Path) -> CdrResult<std::fs::File> {
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
            return CdrError::config("pii hash key file must not be a symlink");
        }
        e.into()
    })
}

/// Rejects a non-regular or group/other-accessible key file. `meta` comes
/// from the open handle (`fstat`), not from the path.
// POAM: SEC-10 symlinked parent directories are not detected and the owner
// uid is not checked; both need write access to the key directory.
fn check_key_file(meta: &std::fs::Metadata) -> CdrResult<()> {
    if !meta.is_file() {
        return Err(CdrError::config("pii hash key file must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CdrError::config(format!(
                "pii hash key file mode {mode:04o} is accessible by group or other; \
                 chmod 0600 (or 0400) it"
            )));
        }
    }
    Ok(())
}

impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacKey(<redacted>)")
    }
}

/// How caller/callee numbers are stored.
#[derive(Debug, Clone, Default)]
pub enum PiiPolicy {
    /// Store as received (default: billing and fraud review need numbers).
    #[default]
    Full,
    /// Mask the caller fields except the last [`MASK_KEEP`] characters.
    MaskCaller,
    /// Replace caller and callee fields with hex HMAC-SHA-384.
    Hash(HmacKey),
}

impl PiiPolicy {
    /// Applies the policy to one value. Exposed so query terms can be
    /// transformed the same way as stored values.
    pub fn apply_caller(&self, value: &str) -> String {
        match self {
            Self::Full => value.to_string(),
            Self::MaskCaller => mask(value),
            Self::Hash(key) => hash(key, value),
        }
    }

    /// Callee counterpart of [`Self::apply_caller`].
    pub fn apply_callee(&self, value: &str) -> String {
        match self {
            Self::Full | Self::MaskCaller => value.to_string(),
            Self::Hash(key) => hash(key, value),
        }
    }

    /// Applies the policy to a record in place.
    ///
    /// ## NIST 800-53 Rev5: SI-12 (Information Management and Retention)
    pub fn apply(&self, r: &mut CallRecord) {
        if matches!(self, Self::Full) {
            return;
        }
        r.caller = self.apply_caller(&r.caller);
        if let Some(c) = r.caller_translated.as_mut() {
            *c = self.apply_caller(c);
        }
        if matches!(self, Self::Hash(_)) {
            r.callee_dialed = self.apply_callee(&r.callee_dialed);
            if let Some(c) = r.callee_translated.as_mut() {
                *c = self.apply_callee(c);
            }
        }
    }
}

fn mask(value: &str) -> String {
    let n = value.chars().count();
    let keep_from = n.saturating_sub(MASK_KEEP);
    value
        .chars()
        .enumerate()
        .map(|(i, c)| if i < keep_from { '*' } else { c })
        .collect()
}

fn hash(key: &HmacKey, value: &str) -> String {
    to_hex(&uc_crypto::hash::hmac_sha384(&key.0, value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> HmacKey {
        HmacKey::from_bytes(vec![b; 48]).unwrap()
    }

    #[test]
    fn hmac_is_deterministic_and_keyed() {
        let p = PiiPolicy::Hash(key(1));
        let a = p.apply_caller("+15550100");
        assert_eq!(a, p.apply_caller("+15550100"));
        assert_eq!(a.len(), 96);
        assert_ne!(a, p.apply_caller("+15550101"));
        assert_ne!(a, PiiPolicy::Hash(key(2)).apply_caller("+15550100"));
    }

    #[test]
    fn short_key_rejected_and_debug_redacted() {
        assert!(HmacKey::from_bytes(vec![0; 16]).is_err());
        assert!(!format!("{:?}", key(7)).contains('7'));
    }

    #[test]
    fn apply_policies() {
        let base = CallRecord {
            caller: "5550100".into(),
            callee_dialed: "5550199".into(),
            callee_translated: Some("+15550199".into()),
            ..Default::default()
        };
        let mut r = base.clone();
        PiiPolicy::MaskCaller.apply(&mut r);
        assert_eq!(r.caller, "***0100");
        assert_eq!(r.callee_dialed, "5550199");

        let mut r = base.clone();
        PiiPolicy::Hash(key(3)).apply(&mut r);
        assert_eq!(r.caller.len(), 96);
        assert_eq!(r.callee_dialed.len(), 96);
        assert_eq!(r.callee_translated.as_deref().map(str::len), Some(96));

        let mut r = base.clone();
        PiiPolicy::Full.apply(&mut r);
        assert_eq!(r, base);
    }

    #[test]
    fn load_strips_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        let mut data = vec![b'k'; 48];
        data.push(b'\n');
        std::fs::write(&p, &data).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(HmacKey::load(&p).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_key_and_symlink_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        std::fs::write(&p, vec![b'k'; 48]).unwrap();
        for mode in [0o644, 0o640, 0o604] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = HmacKey::load(&p).unwrap_err().to_string();
            assert!(e.contains("group or other"), "{mode:o}: {e}");
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(HmacKey::load(&p).is_ok());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(
            HmacKey::load(&link)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    /// The symlink check is done by `O_NOFOLLOW` on the open itself: a link
    /// to a valid 0400 key is refused even though its target would pass.
    #[cfg(unix)]
    #[test]
    fn symlink_to_valid_key_rejected_by_nofollow_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        std::fs::write(&p, vec![b'k'; 48]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        let e = open_key_file(&link).unwrap_err().to_string();
        assert!(e.contains("symlink"), "{e}");
        assert!(open_key_file(&p).is_ok());
    }

    /// A FIFO at the key path is rejected (fstat on the handle) without
    /// blocking the open.
    #[cfg(unix)]
    #[test]
    fn fifo_key_path_rejected_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fifo");
        nix::unistd::mkfifo(&p, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let e = HmacKey::load(&p).unwrap_err().to_string();
        assert!(e.contains("regular file"), "{e}");
    }
}
