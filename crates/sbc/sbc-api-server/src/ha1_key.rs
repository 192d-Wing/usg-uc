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

use uc_crypto::aead::RandomNonceKey;
use zeroize::Zeroizing;

use crate::state::StateError;

/// Largest file we read: 64 hex chars + `\n`; one extra byte detects longer.
const MAX_LEN: usize = 65;

/// Load and validate the HA1 key file.
#[cfg(unix)]
pub fn load_ha1_key(path: &Path) -> Result<RandomNonceKey, StateError> {
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
pub fn load_ha1_key(_path: &Path) -> Result<RandomNonceKey, StateError> {
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

/// SR-15: the loaded key is the module-internal-IV `RandomNonceKey` and
/// still opens rows sealed by the previous release (`enc:v1:`, caller IV).
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod sr15_tests {
    use super::*;
    use base64::prelude::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use uc_crypto::aead::{CachedAeadKey, NONCE_LEN, RandomNonceKey};
    use uc_user_mgmt::encrypt::{EncryptedUserStore, MARKER_V1};
    use uc_user_mgmt::model::{AuthType, User};
    use uc_user_mgmt::sqlite::SqliteUserStore;
    use uc_user_mgmt::store::UserStore;

    const HA1: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";
    /// v1 AAD prefix as written by earlier releases (wire format pin).
    const V1_AAD_PREFIX: &[u8] = b"uc-user-mgmt/digest_ha1/v1:";

    fn user(id: &str, name: &str, ha1: &str) -> User {
        User {
            id: id.into(),
            username: name.into(),
            display_name: String::new(),
            email: String::new(),
            sip_uri: format!("sip:{name}@example.invalid"),
            auth_type: AuthType::Digest,
            digest_ha1: Some(ha1.into()),
            certificate_dn: None,
            certificate_san: None,
            calling_search_space: None,
            device_ids: Vec::new(),
            partition: None,
            enabled: true,
            created_at: 1,
            updated_at: 1,
            last_login: None,
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn loaded_key_opens_rows_sealed_by_previous_release() {
        let bytes = Zeroizing::new(uc_crypto::random::generate_key_256().unwrap());
        let hex: Zeroizing<String> =
            Zeroizing::new(bytes.iter().fold(String::with_capacity(64), |mut out, b| {
                use std::fmt::Write as _;
                let _ = write!(out, "{b:02x}");
                out
            }));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ha1.key");
        std::fs::write(&path, format!("{}\n", *hex)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let key: RandomNonceKey = load_ha1_key(&path).unwrap();

        // Row as the previous release wrote it: caller nonce, v1 AAD.
        let nonce = uc_crypto::random::generate_nonce().unwrap();
        let aad = [V1_AAD_PREFIX, b"u-old"].concat();
        let ct = CachedAeadKey::new(&bytes)
            .unwrap()
            .seal(&nonce, &aad, HA1.as_bytes())
            .unwrap();
        let legacy_row = format!(
            "{MARKER_V1}{}",
            BASE64_STANDARD.encode([&nonce[..], &ct].concat())
        );

        let inner = SqliteUserStore::in_memory().unwrap();
        inner
            .create_user(user("u-old", "olduser", &legacy_row))
            .await
            .unwrap();
        let store = EncryptedUserStore::new(inner, key);

        assert_eq!(
            store.get_user("u-old").await.unwrap().digest_ha1.as_deref(),
            Some(HA1)
        );
        assert_eq!(
            store
                .authenticate_digest("olduser", "realm")
                .await
                .unwrap()
                .as_deref(),
            Some(HA1)
        );

        // A row the new key writes opens with the previous release's opener.
        store
            .create_user(user("u-new", "newuser", HA1))
            .await
            .unwrap();
        let raw = store.inner().get_user("u-new").await.unwrap();
        let blob = BASE64_STANDARD
            .decode(raw.digest_ha1.unwrap().strip_prefix(MARKER_V1).unwrap())
            .unwrap();
        let (n, c) = blob.split_at(NONCE_LEN);
        let old = uc_crypto::aead::Aes256GcmKey::new(*bytes).unwrap();
        let pt = old
            .open(
                &n.try_into().unwrap(),
                &[V1_AAD_PREFIX, b"u-new"].concat(),
                c,
            )
            .unwrap();
        assert_eq!(pt, HA1.as_bytes());
    }
}
