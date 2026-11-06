//! Loads the AES-256-GCM key that protects SIP digest HA1 values at rest.
//!
//! File format: exactly 64 hex characters (32 bytes), optionally followed
//! by a single `\n`. The file is opened with `O_NOFOLLOW` and checked on
//! the open handle (`fstat`): regular file, owned by the effective uid, no
//! group/other permission bits. Anything else is fatal at startup.
//!
//! ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment and
//! Management), SC-28(1), IA-5(1)(c)
// POAM: POA&M-111 file-based key custody (no HSM/KMS) and no rotation
// tooling; symlinked parent directories are not detected.

use std::io::Read;
use std::path::Path;

use uc_crypto::aead::Aes256GcmKey;
use zeroize::Zeroizing;

use crate::state::StateError;

/// Largest file we read: 64 hex chars + `\n`; one extra byte detects longer.
const MAX_LEN: usize = 65;

/// Load and validate the HA1 key file.
#[cfg(unix)]
pub fn load_ha1_key(path: &Path) -> Result<Aes256GcmKey, StateError> {
    use nix::fcntl::OFlag;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits());
    let f = opts.open(path).map_err(|e| {
        if e.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) {
            StateError::Ha1Key("HA1 key file must not be a symlink".into())
        } else {
            StateError::Ha1Key(format!("cannot open HA1 key file: {e}"))
        }
    })?;
    let meta = f
        .metadata()
        .map_err(|e| StateError::Ha1Key(format!("cannot stat HA1 key file: {e}")))?;
    if !meta.is_file() {
        return Err(StateError::Ha1Key(
            "HA1 key file must be a regular file".into(),
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(StateError::Ha1Key(format!(
            "HA1 key file mode {mode:04o} is accessible by group or other; chmod 0400 (or 0600) it"
        )));
    }
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(StateError::Ha1Key(
            "HA1 key file must be owned by the sbc-api user".into(),
        ));
    }

    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_LEN + 1));
    f.take(MAX_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| StateError::Ha1Key(format!("cannot read HA1 key file: {e}")))?;
    let body: &[u8] = match buf.as_slice() {
        [rest @ .., b'\n'] => rest,
        all => all,
    };
    if body.len() != 64 {
        return Err(StateError::Ha1Key(
            "HA1 key file must hold exactly 64 hex characters".into(),
        ));
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| StateError::Ha1Key("HA1 key file is not hex".into()))?;
    uc_user_mgmt::encrypt::parse_hex_key(text)
        .map_err(|_| StateError::Ha1Key("HA1 key file is not valid hex".into()))
}

/// sbc-api-server is Linux-only; refuse to run without owner checks.
#[cfg(not(unix))]
pub fn load_ha1_key(_path: &Path) -> Result<Aes256GcmKey, StateError> {
    Err(StateError::Ha1Key(
        "HA1 key loading is only supported on unix".into(),
    ))
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(dir: &tempfile::TempDir, body: &[u8], mode: u32) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = dir.path().join(format!("k{n}"));
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn key() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn accepts_owner_only_with_optional_newline() {
        let d = tempfile::tempdir().unwrap();
        assert!(load_ha1_key(&write(&d, key().as_bytes(), 0o400)).is_ok());
        let nl = format!("{}\n", key());
        assert!(load_ha1_key(&write(&d, nl.as_bytes(), 0o600)).is_ok());
    }

    #[test]
    fn rejects_bad_files() {
        let d = tempfile::tempdir().unwrap();
        assert!(load_ha1_key(&d.path().join("missing")).is_err());
        for mode in [0o640, 0o604, 0o644] {
            let e = load_ha1_key(&write(&d, key().as_bytes(), mode)).unwrap_err();
            assert!(e.to_string().contains("mode"), "{e}");
        }
        for body in [
            &key().as_bytes()[..63],
            format!("{}0", key()).as_bytes(),
            "zz".repeat(32).as_bytes(),
            format!("{}\n\n", key()).as_bytes(),
            b"".as_slice(),
        ] {
            assert!(load_ha1_key(&write(&d, body, 0o400)).is_err());
        }
        let target = write(&d, key().as_bytes(), 0o400);
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = load_ha1_key(&link).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert!(load_ha1_key(d.path()).is_err(), "directory rejected");
    }

    // QA: CRLF and leading whitespace rejected; errors never echo key bytes.
    #[test]
    fn rejects_crlf_and_does_not_leak_key() {
        let d = tempfile::tempdir().unwrap();
        for body in [format!("{}\r\n", key()), format!(" {}", key())] {
            assert!(load_ha1_key(&write(&d, body.as_bytes(), 0o400)).is_err());
        }
        let e = load_ha1_key(&write(&d, key().as_bytes(), 0o644)).unwrap_err();
        assert!(!format!("{e} {e:?}").contains(&key()));
    }
}
