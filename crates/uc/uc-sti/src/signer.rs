//! File-backed STIR signing key (authentication service, RFC 8224 §5).
//!
//! The PKCS#8 key is opened with `O_NOFOLLOW`, must be a regular file owned
//! by the effective user and not accessible by group/other. The buffer that
//! held it is zeroized. The configured certificate is checked at load: its
//! public key must match the private key, it must be within its validity
//! period, and it must carry `TNAuthList`.
//!
//! CNSA-EXCEPTION: ATIS-1000074 mandates ES256 (P-256).
//!
//! ## NIST 800-53 Rev5: SC-12, SC-17, SC-28 (Protection of Information at Rest)
// POAM: PKCS#11/HSM key custody; symlinked parent directories not detected.

use crate::error::KeyLoadError;
use proto_stir_shaken::{Alg, Signer, StirShakenError, StirShakenResult};
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::pem::PemObject;
use std::io::Read;
use std::path::Path;
use uc_crypto::interop::ecdsa_p256::P256SigningKey;
use zeroize::Zeroizing;

/// Maximum key/cert file size read.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// A loaded, self-checked signing key.
pub struct FileSigner {
    key: P256SigningKey,
    /// `x5u` published for this key.
    pub x5u: String,
    /// Hex SHA-384 of the signing certificate.
    pub cert_fingerprint_sha384: String,
    /// Certificate `notAfter` (Unix seconds).
    pub not_after: u64,
}

impl std::fmt::Debug for FileSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSigner")
            .field("x5u", &self.x5u)
            .field("cert_fingerprint_sha384", &self.cert_fingerprint_sha384)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl FileSigner {
    /// Loads the key at `key_path` and checks it against `cert_path` at time
    /// `now` (Unix seconds).
    ///
    /// # Errors
    /// [`KeyLoadError`] describing the first failed check (never key bytes).
    pub fn load(
        key_path: &Path,
        cert_path: &Path,
        x5u: &str,
        now: u64,
    ) -> Result<Self, KeyLoadError> {
        let key_bytes = read_key_file(key_path)?;
        let der: Zeroizing<Vec<u8>> = if key_bytes.starts_with(b"-----") {
            let k = PrivatePkcs8KeyDer::from_pem_slice(&key_bytes)
                .map_err(|_| KeyLoadError::Invalid("private key is not a PKCS#8 PEM"))?;
            Zeroizing::new(k.secret_pkcs8_der().to_vec())
        } else {
            Zeroizing::new(key_bytes.to_vec())
        };
        drop(key_bytes);
        let key = P256SigningKey::from_pkcs8(&der)
            .map_err(|_| KeyLoadError::Invalid("private key is not a P-256 PKCS#8 key"))?;

        let cert_pem = read_bounded(cert_path, "certificate")?;
        let certs = uc_crypto::x509::pem_certificates(&cert_pem)
            .map_err(|_| KeyLoadError::Invalid("certificate is not PEM"))?;
        let ee = certs
            .first()
            .ok_or(KeyLoadError::Invalid("certificate file is empty"))?;
        let sti = uc_crypto::x509::parse_sti_certificate(ee)
            .map_err(|_| KeyLoadError::Invalid("certificate is not a P-256 STI certificate"))?;
        if sti.public_key != key.public_key_bytes() {
            return Err(KeyLoadError::Invalid(
                "certificate does not match the private key",
            ));
        }
        if now < sti.not_before || now >= sti.not_after {
            return Err(KeyLoadError::Invalid(
                "signing certificate is expired or not yet valid",
            ));
        }
        if sti.tn_auth.is_empty() {
            return Err(KeyLoadError::Invalid(
                "signing certificate has no TNAuthList (RFC 8226)",
            ));
        }
        Ok(Self {
            key,
            x5u: x5u.to_owned(),
            cert_fingerprint_sha384: crate::hex(&sti.fingerprint_sha384),
            not_after: sti.not_after,
        })
    }

    /// Builds a signer from an in-memory PKCS#8 key (tests, tooling).
    ///
    /// # Errors
    /// The key is not P-256 PKCS#8.
    pub fn from_pkcs8(pkcs8: &[u8], x5u: &str) -> Result<Self, KeyLoadError> {
        Ok(Self {
            key: P256SigningKey::from_pkcs8(pkcs8)
                .map_err(|_| KeyLoadError::Invalid("private key is not a P-256 PKCS#8 key"))?,
            x5u: x5u.to_owned(),
            cert_fingerprint_sha384: String::new(),
            not_after: u64::MAX,
        })
    }
}

impl Signer for FileSigner {
    fn alg(&self) -> Alg {
        Alg::Es256
    }

    fn sign(&self, input: &[u8]) -> StirShakenResult<Vec<u8>> {
        // CNSA-EXCEPTION: ATIS-1000074 mandates ES256 for SHAKEN.
        self.key
            .sign(input)
            .map_err(|_| StirShakenError::SigningFailed)
    }
}

fn open_nofollow(path: &Path, what: &'static str) -> Result<std::fs::File, KeyLoadError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits());
    }
    opts.open(path).map_err(|e| {
        #[cfg(unix)]
        if e.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) {
            return KeyLoadError::Permissions(format!("{what} must not be a symlink"));
        }
        KeyLoadError::Io { what, source: e }
    })
}

fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeyLoadError> {
    let f = open_nofollow(path, "signing key")?;
    let meta = f.metadata().map_err(|e| KeyLoadError::Io {
        what: "signing key",
        source: e,
    })?;
    if !meta.is_file() {
        return Err(KeyLoadError::Permissions(
            "signing key must be a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeyLoadError::Permissions(format!(
                "signing key mode {mode:04o} is accessible by group or other; chmod 0600 (or 0400) it"
            )));
        }
        if meta.uid() != nix::unistd::geteuid().as_raw() {
            return Err(KeyLoadError::Permissions(
                "signing key must be owned by the SBC's user".into(),
            ));
        }
    }
    read_all(f, meta.len(), "signing key")
}

fn read_bounded(path: &Path, what: &'static str) -> Result<Zeroizing<Vec<u8>>, KeyLoadError> {
    let f = open_nofollow(path, what)?;
    let meta = f
        .metadata()
        .map_err(|e| KeyLoadError::Io { what, source: e })?;
    if !meta.is_file() {
        return Err(KeyLoadError::Permissions(format!(
            "{what} must be a regular file"
        )));
    }
    read_all(f, meta.len(), what)
}

fn read_all(
    mut f: std::fs::File,
    len: u64,
    what: &'static str,
) -> Result<Zeroizing<Vec<u8>>, KeyLoadError> {
    if len > MAX_FILE_BYTES {
        return Err(KeyLoadError::Invalid("file too large"));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(len).unwrap_or(0)));
    f.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| KeyLoadError::Io { what, source: e })?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(KeyLoadError::Invalid("file too large"));
    }
    Ok(buf)
}
