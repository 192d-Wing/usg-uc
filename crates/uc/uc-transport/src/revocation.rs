//! Certificate revocation checking with CRL files (SR-29 phase (a)).
//!
//! CRLs are loaded once at startup from a PEM or DER file, or from a
//! directory of `*.pem`, `*.crl` and `*.der` files, and handed to the
//! rustls / webpki verifiers through their built-in `with_crls` path. There
//! is no custom certificate verifier: rustls does the revocation check on
//! every handshake. See `docs/TLS-REVOCATION-DESIGN.md`.
//!
//! - [`CrlSet::load`] reads and bounds the files (file count, per-file and
//!   total size), parses each CRL with webpki (delta and indirect CRLs are
//!   refused), reads `thisUpdate` / `nextUpdate` with a bounded DER walk
//!   ([`CrlInfo::parse`]) and refuses two CRLs from the same issuer (webpki
//!   would use the first one it finds, which may be the older one).
//! - [`Revocation`] pairs a [`CrlSet`] with the [`RevocationPolicy`] (check
//!   depth, unknown status, expired CRL) and builds the client and server
//!   certificate verifiers.
//! - [`classify`] maps a rustls handshake error to a [`RevocationFailure`]
//!   for metrics and the aggregated rejection audit.
//!
//! With no CRL configured none of this runs and the verifiers are built
//! exactly as before.
//!
//! ## NIST 800-53 Rev5: IA-5(2) (PKI-based authentication: revocation
//! status), SC-17 (PKI certificates), IA-3, SC-23, SC-5 (bounded loading)
// POAM: POA&M-401: phase (a) only. CRLs load once at startup (no reload,
// b1), no expiry monitoring or grace period (b2), no load-time CRL signature
// or issuer checks (b3), no OCSP (b4, b5), no CDP fetch (b6), no gRPC (b7).

use crate::error::{RevocationFailure, TransportError, TransportResult};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::CertificateRevocationListDer;
use rustls::pki_types::pem::PemObject;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Most CRL files read from one directory, and most CRLs in one set.
pub const MAX_CRL_FILES: usize = 256;
/// Largest CRL file read.
pub const MAX_CRL_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Largest total of all CRL files in one set.
pub const MAX_CRL_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Which certificates of a chain are checked (`check_depth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckDepth {
    /// Every certificate below the trust anchor (RFC 5280 path validation).
    #[default]
    Chain,
    /// The end-entity certificate only.
    EndEntity,
}

/// What happens to a certificate whose status no CRL covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownStatus {
    /// Fail the handshake.
    #[default]
    Deny,
    /// Accept the certificate.
    Allow,
}

/// What happens when a CRL needed for a check has passed its `nextUpdate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExpiredCrl {
    /// Fail the handshake (fail closed).
    #[default]
    Reject,
    /// Use the CRL anyway (fail open; logged at startup).
    Ignore,
}

/// Revocation policy of one TLS path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RevocationPolicy {
    /// Chain depth checked.
    pub depth: CheckDepth,
    /// Unknown revocation status.
    pub unknown: UnknownStatus,
    /// Expired CRL handling.
    pub expired: ExpiredCrl,
}

/// Metadata of one loaded CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlInfo {
    /// DER of the issuer `Name`.
    pub issuer: Vec<u8>,
    /// `thisUpdate`, Unix seconds.
    pub this_update: i64,
    /// `nextUpdate`, Unix seconds, if the CRL has one.
    pub next_update: Option<i64>,
    /// Number of revoked-certificate entries.
    pub entries: usize,
    /// File the CRL was read from.
    pub source: PathBuf,
}

/// A loaded, checked set of CRLs.
#[derive(Clone)]
pub struct CrlSet {
    crls: Vec<CertificateRevocationListDer<'static>>,
    info: Vec<CrlInfo>,
}

impl std::fmt::Debug for CrlSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlSet")
            .field("crls", &self.crls.len())
            .field("entries", &self.entries())
            .finish_non_exhaustive()
    }
}

fn crl_error(path: &Path, reason: impl std::fmt::Display) -> TransportError {
    TransportError::TlsCertificateError {
        reason: format!("CRL {}: {reason}", path.display()),
    }
}

impl CrlSet {
    /// Loads CRLs from `path`: one PEM file (any number of `X509 CRL`
    /// blocks), one DER file, or a directory of `*.pem`, `*.crl` and
    /// `*.der` regular files.
    ///
    /// In a directory, names starting with `.` are skipped, any other name
    /// must end in `.pem`, `.crl` or `.der`, and a symlink
    /// is followed only when it resolves to a regular file inside the same
    /// directory (the layout of a Kubernetes `ConfigMap` or `Secret` volume).
    /// `path` itself must not be a symlink.
    ///
    /// ## Errors
    ///
    /// A path that cannot be read, is a symlink, holds no CRL, exceeds
    /// [`MAX_CRL_FILES`], [`MAX_CRL_FILE_BYTES`] or [`MAX_CRL_TOTAL_BYTES`],
    /// holds a CRL webpki cannot parse (including delta and indirect CRLs),
    /// or holds two CRLs from the same issuer.
    pub fn load(path: &Path) -> TransportResult<Self> {
        let meta = std::fs::symlink_metadata(path).map_err(|e| crl_error(path, e))?;
        let files = if meta.file_type().is_symlink() {
            return Err(crl_error(path, "is a symlink (not followed)"));
        } else if meta.is_dir() {
            dir_files(path)?
        } else if meta.is_file() {
            vec![path.to_path_buf()]
        } else {
            return Err(crl_error(path, "is not a regular file or directory"));
        };
        let mut total = 0u64;
        let mut set = Self {
            crls: Vec::new(),
            info: Vec::new(),
        };
        for file in files {
            let bytes = read_bounded(&file, MAX_CRL_FILE_BYTES)?;
            total = total.saturating_add(bytes.len() as u64);
            if total > MAX_CRL_TOTAL_BYTES {
                return Err(crl_error(
                    path,
                    format!("CRL files exceed {MAX_CRL_TOTAL_BYTES} bytes in total"),
                ));
            }
            set.add_file(&file, &bytes)?;
        }
        if set.crls.is_empty() {
            return Err(crl_error(path, "contains no CRL"));
        }
        Ok(set)
    }

    /// Builds a set from in-memory CRLs (PEM or DER per item), with the
    /// same checks as [`Self::load`]. `source` names them in errors.
    ///
    /// ## Errors
    ///
    /// As [`Self::load`].
    pub fn from_bytes<'a>(
        source: &Path,
        items: impl IntoIterator<Item = &'a [u8]>,
    ) -> TransportResult<Self> {
        let mut set = Self {
            crls: Vec::new(),
            info: Vec::new(),
        };
        for item in items {
            set.add_file(source, item)?;
        }
        if set.crls.is_empty() {
            return Err(crl_error(source, "contains no CRL"));
        }
        Ok(set)
    }

    fn add_file(&mut self, file: &Path, bytes: &[u8]) -> TransportResult<()> {
        let ders: Vec<CertificateRevocationListDer<'static>> = if looks_like_pem(bytes) {
            CertificateRevocationListDer::pem_slice_iter(bytes)
                .collect::<Result<_, _>>()
                .map_err(|e| crl_error(file, format!("PEM: {e}")))?
        } else {
            vec![CertificateRevocationListDer::from(bytes.to_vec())]
        };
        if ders.is_empty() {
            return Err(crl_error(file, "contains no X509 CRL block"));
        }
        for der in ders {
            if self.crls.len() >= MAX_CRL_FILES {
                return Err(crl_error(file, format!("more than {MAX_CRL_FILES} CRLs")));
            }
            // webpki parses here exactly as the verifier will; delta and
            // indirect CRLs and unsupported versions fail now, at startup.
            webpki::OwnedCertRevocationList::from_der(der.as_ref())
                .map_err(|e| crl_error(file, format!("{e:?}")))?;
            let info = CrlInfo::parse(der.as_ref(), file.to_path_buf())
                .ok_or_else(|| crl_error(file, "malformed CRL"))?;
            if let Some(dup) = self.info.iter().find(|i| i.issuer == info.issuer) {
                return Err(crl_error(
                    file,
                    format!(
                        "second CRL for the same issuer as {} (keep one CRL per issuer)",
                        dup.source.display()
                    ),
                ));
            }
            self.info.push(info);
            self.crls.push(der);
        }
        Ok(())
    }

    /// Number of CRLs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.crls.len()
    }

    /// Whether the set is empty (never true for a loaded set).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.crls.is_empty()
    }

    /// Revoked entries across all CRLs.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.info.iter().map(|i| i.entries).sum()
    }

    /// Per-CRL metadata.
    #[must_use]
    pub fn info(&self) -> &[CrlInfo] {
        &self.info
    }

    /// Earliest `nextUpdate` (Unix seconds) of the set.
    #[must_use]
    pub fn earliest_next_update(&self) -> Option<i64> {
        self.info.iter().filter_map(|i| i.next_update).min()
    }

    /// CRLs whose `nextUpdate` is at or before `now` (Unix seconds).
    pub fn expired_at(&self, now: i64) -> impl Iterator<Item = &CrlInfo> {
        self.info
            .iter()
            .filter(move |i| i.next_update.is_some_and(|n| now >= n))
    }

    /// Total DER bytes of the set (the per-handshake signature check is
    /// linear in this).
    #[must_use]
    pub fn der_bytes(&self) -> usize {
        self.crls.iter().map(|c| c.as_ref().len()).sum()
    }

    /// The CRL DERs, for the verifier builders.
    #[must_use]
    pub fn ders(&self) -> &[CertificateRevocationListDer<'static>] {
        &self.crls
    }
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    bytes[start..].starts_with(b"-----BEGIN")
}

/// The CRL files of a directory, sorted by name.
fn dir_files(dir: &Path) -> TransportResult<Vec<PathBuf>> {
    let canonical_dir = std::fs::canonicalize(dir).map_err(|e| crl_error(dir, e))?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| crl_error(dir, e))? {
        let entry = entry.map_err(|e| crl_error(dir, e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let ext = Path::new(&name)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase());
        if !matches!(ext.as_deref(), Some("pem" | "crl" | "der")) {
            // Never skip silently: a misnamed CRL would leave its issuer
            // unchecked (fail open with "allow" or "end_entity").
            return Err(crl_error(
                &path,
                "not a *.pem, *.crl or *.der file (CRL directories hold CRL files only)",
            ));
        }
        let ft = entry.file_type().map_err(|e| crl_error(&path, e))?;
        if ft.is_symlink() {
            // Followed only inside the directory (ConfigMap / Secret
            // volumes link each key into a `..data` subdirectory).
            let target = std::fs::canonicalize(&path).map_err(|e| crl_error(&path, e))?;
            let inside = target.starts_with(&canonical_dir);
            let regular = std::fs::metadata(&target).is_ok_and(|m| m.is_file());
            if !inside || !regular {
                return Err(crl_error(
                    &path,
                    "symlink to a target outside the CRL directory (not followed)",
                ));
            }
        } else if !ft.is_file() {
            return Err(crl_error(&path, "is not a regular file"));
        }
        out.push(path);
        if out.len() > MAX_CRL_FILES {
            return Err(crl_error(
                dir,
                format!("more than {MAX_CRL_FILES} CRL files"),
            ));
        }
    }
    out.sort();
    Ok(out)
}

fn read_bounded(path: &Path, max: u64) -> TransportResult<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|e| crl_error(path, e))?;
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| crl_error(path, e))?;
    if buf.len() as u64 > max {
        return Err(crl_error(path, format!("larger than {max} bytes")));
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Bounded DER walk of `CertificateList` (RFC 5280 §5.1). webpki does not
// expose `thisUpdate` / `nextUpdate` or the issuer, so we read them here.
// Every read is bounds-checked; malformed input returns `None`.
// ---------------------------------------------------------------------------

const TAG_INTEGER: u8 = 0x02;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;

/// A DER reader over a byte slice.
struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    const fn peek_tag(&self) -> Option<u8> {
        match self.rest.first() {
            Some(b) => Some(*b),
            None => None,
        }
    }

    /// Reads one TLV, returning (tag, value).
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.rest.split_first()?;
        // Low-tag-number form only (RFC 5280 structures never need more).
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            // 0x80 is indefinite length (not DER); more than 4 length
            // bytes is far beyond any CRL we accept.
            if n == 0 || n > 4 {
                return None;
            }
            if rest.len() < n {
                return None;
            }
            let (len_bytes, after) = rest.split_at(n);
            rest = after;
            len_bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
        };
        if len > rest.len() {
            return None;
        }
        let (value, after) = rest.split_at(len);
        self.rest = after;
        Some((tag, value))
    }

    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        match self.read()? {
            (t, v) if t == tag => Some(v),
            _ => None,
        }
    }
}

impl CrlInfo {
    /// Reads issuer, `thisUpdate`, `nextUpdate` and the entry count from a
    /// DER `CertificateList`. Never panics; `None` for malformed input.
    #[must_use]
    pub fn parse(der: &[u8], source: PathBuf) -> Option<Self> {
        let mut outer = Der::new(der);
        let cert_list = outer.expect(TAG_SEQUENCE)?;
        if !outer.is_empty() {
            return None;
        }
        let mut cl = Der::new(cert_list);
        let tbs = cl.expect(TAG_SEQUENCE)?;
        let mut t = Der::new(tbs);
        if t.peek_tag()? == TAG_INTEGER {
            t.read()?; // version
        }
        t.expect(TAG_SEQUENCE)?; // signature AlgorithmIdentifier
        // Keep the whole issuer TLV, as webpki compares the raw Name.
        let before = t.rest;
        let issuer_value = t.expect(TAG_SEQUENCE)?;
        let issuer_len = before.len() - t.rest.len();
        let issuer = before.get(..issuer_len)?.to_vec();
        let _ = issuer_value;
        let this_update = read_time(&mut t)?;
        let next_update = match t.peek_tag() {
            Some(TAG_UTC_TIME | TAG_GENERALIZED_TIME) => Some(read_time(&mut t)?),
            _ => None,
        };
        let mut entries = 0usize;
        if t.peek_tag() == Some(TAG_SEQUENCE) {
            let mut revoked = Der::new(t.read()?.1);
            while !revoked.is_empty() {
                revoked.expect(TAG_SEQUENCE)?;
                entries += 1;
            }
        }
        Some(Self {
            issuer,
            this_update,
            next_update,
            entries,
            source,
        })
    }
}

fn read_time(d: &mut Der<'_>) -> Option<i64> {
    let (tag, v) = d.read()?;
    let digits = |s: &[u8]| -> Option<i64> {
        s.iter().try_fold(0i64, |acc, &b| {
            b.is_ascii_digit().then(|| acc * 10 + i64::from(b - b'0'))
        })
    };
    let (year, rest) = match (tag, v.len()) {
        // YYMMDDHHMMSSZ; RFC 5280 §4.1.2.5.1: YY >= 50 is 19YY.
        (TAG_UTC_TIME, 13) => {
            let yy = digits(&v[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..])
        }
        // YYYYMMDDHHMMSSZ.
        (TAG_GENERALIZED_TIME, 15) => (digits(&v[..4])?, &v[4..]),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let min = digits(&rest[6..8])?;
    let sec = digits(&rest[8..10])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant).
const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Verifiers
// ---------------------------------------------------------------------------

/// CRLs plus the policy they are applied with, for one TLS path.
#[derive(Debug, Clone)]
pub struct Revocation {
    /// The loaded CRLs.
    pub crls: Arc<CrlSet>,
    /// How they are applied.
    pub policy: RevocationPolicy,
}

impl Revocation {
    /// Client-certificate verifier for a mutual-TLS server (V1), on
    /// [`crate::tls::cnsa_provider`].
    ///
    /// ## Errors
    ///
    /// Empty roots or a CRL the verifier refuses.
    pub fn client_verifier(
        &self,
        roots: Arc<RootCertStore>,
    ) -> TransportResult<Arc<dyn ClientCertVerifier>> {
        let mut b = WebPkiClientVerifier::builder_with_provider(
            roots,
            Arc::new(crate::tls::cnsa_provider()),
        )
        .with_crls(self.crls.ders().iter().cloned());
        if self.policy.depth == CheckDepth::EndEntity {
            b = b.only_check_end_entity_revocation();
        }
        if self.policy.unknown == UnknownStatus::Allow {
            b = b.allow_unknown_revocation_status();
        }
        if self.policy.expired == ExpiredCrl::Reject {
            b = b.enforce_revocation_expiration();
        }
        b.build().map_err(|e| TransportError::TlsCertificateError {
            reason: format!("client CA store or CRL rejected: {e}"),
        })
    }

    /// Server-certificate verifier for an outbound TLS client (V2-V5), on
    /// [`crate::tls::cnsa_provider`]. One verifier can back several client
    /// configs (trunk TLS and trunk mTLS share it).
    ///
    /// ## Errors
    ///
    /// Empty roots or a CRL the verifier refuses.
    pub fn server_verifier(
        &self,
        roots: Arc<RootCertStore>,
    ) -> TransportResult<Arc<WebPkiServerVerifier>> {
        let mut b = WebPkiServerVerifier::builder_with_provider(
            roots,
            Arc::new(crate::tls::cnsa_provider()),
        )
        .with_crls(self.crls.ders().iter().cloned());
        if self.policy.depth == CheckDepth::EndEntity {
            b = b.only_check_end_entity_revocation();
        }
        if self.policy.unknown == UnknownStatus::Allow {
            b = b.allow_unknown_revocation_status();
        }
        if self.policy.expired == ExpiredCrl::Reject {
            b = b.enforce_revocation_expiration();
        }
        b.build().map_err(|e| TransportError::TlsCertificateError {
            reason: format!("CA store or CRL rejected: {e}"),
        })
    }
}

/// Revocation cause of a failed handshake, if it was one.
#[must_use]
pub const fn classify(err: &rustls::Error) -> Option<RevocationFailure> {
    use rustls::CertificateError as C;
    match err {
        rustls::Error::InvalidCertificate(C::Revoked) => Some(RevocationFailure::Revoked),
        rustls::Error::InvalidCertificate(C::UnknownRevocationStatus) => {
            Some(RevocationFailure::UnknownStatus)
        }
        rustls::Error::InvalidCertificate(
            C::ExpiredRevocationList | C::ExpiredRevocationListContext { .. },
        ) => Some(RevocationFailure::CrlExpired),
        rustls::Error::InvalidCertRevocationList(_) => Some(RevocationFailure::CrlInvalid),
        _ => None,
    }
}

/// [`classify`] for the `io::Error` tokio-rustls and `rustls::StreamOwned`
/// wrap handshake errors in.
#[must_use]
pub fn classify_io(err: &std::io::Error) -> Option<RevocationFailure> {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .and_then(classify)
}

/// The transport error for a failed handshake: a revocation failure gets
/// its own variant so callers can count and audit it.
pub(crate) fn handshake_error(err: &std::io::Error) -> TransportError {
    classify_io(err).map_or_else(
        || TransportError::TlsHandshakeFailed {
            reason: err.to_string(),
        },
        |reason| TransportError::TlsPeerCertificateRejected {
            reason,
            detail: err.to_string(),
        },
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
