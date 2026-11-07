//! STI-CR trust anchors (ATIS-1000080 §6.3).
//!
//! Loaded from a PEM bundle file or a directory of PEM files and swapped in
//! atomically ([`arc_swap::ArcSwap`]) so the verification path never takes a
//! lock. A failed reload keeps the previous set.
//!
//! ## NIST 800-53 Rev5: SC-17 (PKI Certificates), CM-6

use arc_swap::ArcSwap;
use std::path::Path;
use std::sync::Arc;
use uc_crypto::x509::{TrustAnchorSet, pem_certificates};

/// Maximum files read from an anchor directory.
pub const MAX_ANCHOR_FILES: usize = 1000;
/// Maximum size of one anchor file.
pub const MAX_ANCHOR_FILE_BYTES: u64 = 1024 * 1024;

/// A loaded anchor set with its identity for audit.
#[derive(Debug, Default)]
pub struct AnchorSet {
    /// Anchors.
    pub set: TrustAnchorSet,
    /// Number of anchors.
    pub count: usize,
    /// Hex SHA-384 over the concatenated anchor DER, in load order.
    pub sha384: String,
}

/// Lock-free holder of the active anchor set.
#[derive(Debug)]
pub struct AnchorStore {
    current: ArcSwap<AnchorSet>,
}

impl Default for AnchorStore {
    fn default() -> Self {
        Self {
            current: ArcSwap::from_pointee(AnchorSet::default()),
        }
    }
}

impl AnchorStore {
    /// Creates a store holding `set`.
    #[must_use]
    pub fn new(set: AnchorSet) -> Self {
        Self {
            current: ArcSwap::from_pointee(set),
        }
    }

    /// The active set.
    #[must_use]
    pub fn current(&self) -> Arc<AnchorSet> {
        self.current.load_full()
    }

    /// Replaces the active set.
    pub fn swap(&self, set: AnchorSet) {
        self.current.store(Arc::new(set));
    }
}

/// Loads anchors from `path` (file or directory). Blocking file I/O: call at
/// startup or from `spawn_blocking`.
///
/// # Errors
/// I/O errors, malformed PEM, or an empty result.
pub fn load_anchors(path: &Path) -> Result<AnchorSet, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ders: Vec<Vec<u8>> = Vec::new();
    if meta.is_dir() {
        let mut files: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| matches!(e, "pem" | "crt" | "cer"))
            })
            .collect();
        files.sort();
        if files.len() > MAX_ANCHOR_FILES {
            return Err(format!("more than {MAX_ANCHOR_FILES} anchor files"));
        }
        for f in files {
            ders.extend(read_pem_file(&f)?);
        }
    } else {
        ders = read_pem_file(path)?;
    }
    let (set, skipped) = TrustAnchorSet::from_der_certs(ders.iter().map(Vec::as_slice));
    if set.is_empty() {
        return Err(format!("{}: no usable trust anchors", path.display()));
    }
    if skipped > 0 {
        tracing::warn!(skipped, "STI trust anchors: skipped unusable certificates");
    }
    let mut h = uc_crypto::hash::Sha384::new();
    for d in &ders {
        h.update(d);
    }
    let sha384 = crate::hex(&h.finish());
    Ok(AnchorSet {
        count: set.len(),
        set,
        sha384,
    })
}

fn read_pem_file(p: &Path) -> Result<Vec<Vec<u8>>, String> {
    let meta = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if meta.len() > MAX_ANCHOR_FILE_BYTES {
        return Err(format!("{}: anchor file too large", p.display()));
    }
    let data = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    pem_certificates(&data).map_err(|e| format!("{}: {e}", p.display()))
}
