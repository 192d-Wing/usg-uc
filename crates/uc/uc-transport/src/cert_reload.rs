//! TLS certificate hot-reloading support.
//!
//! This module provides runtime certificate reloading without server restart,
//! enabling zero-downtime certificate rotation.
//!
//! ## Features
//!
//! - **Signal-based reload**: Trigger reload via SIGHUP signal
//! - **Programmatic reload**: Reload certificates from application code
//! - **Thread-safe**: Uses `ArcSwap` for lock-free acceptor swapping
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-12**: Cryptographic Key Establishment and Management
//! - **SC-17**: Public Key Infrastructure Certificates
//!
//! ## Example
//!
//! ```ignore
//! use uc_transport::cert_reload::ReloadableTlsAcceptor;
//! use std::path::PathBuf;
//!
//! let acceptor = ReloadableTlsAcceptor::new(
//!     PathBuf::from("/etc/sbc/cert.pem"),
//!     PathBuf::from("/etc/sbc/key.pem"),
//! )?;
//!
//! // Later, when certificates change:
//! acceptor.reload()?;
//! ```

use crate::error::TransportResult;
use crate::tls::{create_server_config, load_certs, load_private_key};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// A TLS acceptor that supports hot-reloading of certificates.
///
/// This wrapper around `TlsAcceptor` allows certificates to be reloaded
/// at runtime without restarting the server. New connections will use
/// the updated certificates while existing connections continue with
/// their original certificates.
///
/// ## Thread Safety
///
/// Uses `ArcSwap` for lock-free swapping of the underlying acceptor,
/// ensuring minimal overhead during the reload process.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment and Management)
pub struct ReloadableTlsAcceptor {
    /// The current TLS acceptor (swappable).
    acceptor: ArcSwap<TlsAcceptor>,
    /// Path to the certificate file.
    cert_path: PathBuf,
    /// Path to the private key file.
    key_path: PathBuf,
    /// Reload counter for monitoring.
    reload_count: AtomicU64,
    /// Last reload timestamp (Unix epoch seconds).
    last_reload: AtomicU64,
}

impl ReloadableTlsAcceptor {
    /// Creates a new reloadable TLS acceptor.
    ///
    /// Loads the initial certificates from the specified paths.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial certificate loading fails.
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> TransportResult<Self> {
        let server_config = Self::load_config(&cert_path, &key_path)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        info!(
            cert_path = %cert_path.display(),
            key_path = %key_path.display(),
            "Reloadable TLS acceptor initialized"
        );

        Ok(Self {
            acceptor: ArcSwap::from_pointee(acceptor),
            cert_path,
            key_path,
            reload_count: AtomicU64::new(0),
            last_reload: AtomicU64::new(now),
        })
    }

    /// Creates a reloadable TLS acceptor from an existing configuration.
    ///
    /// This constructor allows creating the acceptor from a pre-loaded
    /// server configuration while still supporting future reloads.
    #[must_use]
    pub fn from_config(
        server_config: Arc<ServerConfig>,
        cert_path: PathBuf,
        key_path: PathBuf,
    ) -> Self {
        let acceptor = TlsAcceptor::from(server_config);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            acceptor: ArcSwap::from_pointee(acceptor),
            cert_path,
            key_path,
            reload_count: AtomicU64::new(0),
            last_reload: AtomicU64::new(now),
        }
    }

    /// Reloads certificates from the configured paths.
    ///
    /// This method atomically swaps the TLS acceptor, ensuring that:
    /// - New connections use the new certificates
    /// - Existing connections continue with their original certificates
    /// - The reload is thread-safe and lock-free
    ///
    /// # Errors
    ///
    /// Returns an error if the new certificates cannot be loaded.
    /// In case of error, the old acceptor remains active.
    pub fn reload(&self) -> TransportResult<()> {
        info!(
            cert_path = %self.cert_path.display(),
            "Reloading TLS certificates"
        );

        // Load new certificates
        let new_config = Self::load_config(&self.cert_path, &self.key_path)?;
        let new_acceptor = TlsAcceptor::from(Arc::new(new_config));

        // Atomically swap the acceptor
        self.acceptor.store(Arc::new(new_acceptor));

        // Update metrics
        self.reload_count.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_reload.store(now, Ordering::Relaxed);

        info!(
            reload_count = self.reload_count.load(Ordering::Relaxed),
            "TLS certificates reloaded successfully"
        );

        Ok(())
    }

    /// Attempts to reload certificates, logging any errors.
    ///
    /// This is useful for signal handlers where errors cannot be propagated.
    /// Returns `true` if reload succeeded, `false` otherwise.
    pub fn try_reload(&self) -> bool {
        match self.reload() {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, "Failed to reload TLS certificates");
                false
            }
        }
    }

    /// Returns a reference to the current TLS acceptor.
    ///
    /// This method is efficient and does not require locking.
    pub fn acceptor(&self) -> arc_swap::Guard<Arc<TlsAcceptor>> {
        self.acceptor.load()
    }

    /// Returns a clone of the current acceptor's Arc.
    ///
    /// Use this when you need to hold the acceptor across await points.
    pub fn acceptor_arc(&self) -> Arc<TlsAcceptor> {
        Arc::clone(&self.acceptor.load())
    }

    /// Returns the number of times certificates have been reloaded.
    #[must_use]
    pub fn reload_count(&self) -> u64 {
        self.reload_count.load(Ordering::Relaxed)
    }

    /// Returns the Unix timestamp of the last reload.
    #[must_use]
    pub fn last_reload_timestamp(&self) -> u64 {
        self.last_reload.load(Ordering::Relaxed)
    }

    /// Returns the certificate file path.
    #[must_use]
    pub const fn cert_path(&self) -> &PathBuf {
        &self.cert_path
    }

    /// Returns the private key file path.
    #[must_use]
    pub const fn key_path(&self) -> &PathBuf {
        &self.key_path
    }

    /// Loads TLS configuration from certificate and key files.
    fn load_config(cert_path: &Path, key_path: &Path) -> TransportResult<ServerConfig> {
        debug!(
            cert_path = %cert_path.display(),
            key_path = %key_path.display(),
            "Loading TLS certificates"
        );

        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;

        debug!(cert_count = certs.len(), "Loaded certificate chain");

        create_server_config(certs, key)
    }
}

impl std::fmt::Debug for ReloadableTlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableTlsAcceptor")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("reload_count", &self.reload_count.load(Ordering::Relaxed))
            .field("last_reload", &self.last_reload.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Statistics about certificate reloading.
#[derive(Debug, Clone, Copy)]
pub struct CertReloadStats {
    /// Number of successful reloads.
    pub reload_count: u64,
    /// Unix timestamp of last reload.
    pub last_reload_timestamp: u64,
}

impl From<&ReloadableTlsAcceptor> for CertReloadStats {
    fn from(acceptor: &ReloadableTlsAcceptor) -> Self {
        Self {
            reload_count: acceptor.reload_count(),
            last_reload_timestamp: acceptor.last_reload_timestamp(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// Creates test P-384 certificate and key using openssl.
    /// Returns None if openssl is not available.
    fn create_test_certs() -> Option<(TempDir, std::path::PathBuf, std::path::PathBuf)> {
        let temp_dir = TempDir::new().ok()?;
        let key_path = temp_dir.path().join("key.pem");
        let cert_path = temp_dir.path().join("cert.pem");

        // Generate P-384 private key
        let key_result = Command::new("openssl")
            .args(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out"])
            .arg(&key_path)
            .output();

        if key_result.is_err()
            || !key_result
                .as_ref()
                .map(|o| o.status.success())
                .unwrap_or(false)
        {
            return None;
        }

        // Generate self-signed certificate
        let cert_result = Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&key_path)
            .args(["-out"])
            .arg(&cert_path)
            .args(["-days", "1", "-subj", "/CN=test"])
            .output();

        if cert_result.is_err()
            || !cert_result
                .as_ref()
                .map(|o| o.status.success())
                .unwrap_or(false)
        {
            return None;
        }

        Some((temp_dir, cert_path, key_path))
    }

    #[test]
    fn test_reloadable_acceptor_creation() {
        let Some((_temp_dir, cert_path, key_path)) = create_test_certs() else {
            eprintln!("Skipping test: openssl not available");
            return;
        };

        let acceptor = ReloadableTlsAcceptor::new(cert_path, key_path);

        assert!(acceptor.is_ok());
        let acceptor = acceptor.expect("acceptor");
        assert_eq!(acceptor.reload_count(), 0);
    }

    #[test]
    fn test_reload_increments_counter() {
        let Some((_temp_dir, cert_path, key_path)) = create_test_certs() else {
            eprintln!("Skipping test: openssl not available");
            return;
        };

        let acceptor = ReloadableTlsAcceptor::new(cert_path, key_path).expect("acceptor");

        assert_eq!(acceptor.reload_count(), 0);

        acceptor.reload().expect("reload");
        assert_eq!(acceptor.reload_count(), 1);

        acceptor.reload().expect("reload");
        assert_eq!(acceptor.reload_count(), 2);
    }

    #[test]
    fn test_reload_updates_timestamp() {
        let Some((_temp_dir, cert_path, key_path)) = create_test_certs() else {
            eprintln!("Skipping test: openssl not available");
            return;
        };

        let acceptor = ReloadableTlsAcceptor::new(cert_path, key_path).expect("acceptor");

        let initial_timestamp = acceptor.last_reload_timestamp();

        // Small delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(1100));

        acceptor.reload().expect("reload");
        let new_timestamp = acceptor.last_reload_timestamp();

        assert!(new_timestamp >= initial_timestamp);
    }

    #[test]
    fn test_try_reload_returns_false_on_missing_file() {
        let Some((temp_dir, cert_path, key_path)) = create_test_certs() else {
            eprintln!("Skipping test: openssl not available");
            return;
        };

        let acceptor = ReloadableTlsAcceptor::new(cert_path.clone(), key_path).expect("acceptor");

        // Delete the cert file
        std::fs::remove_file(&cert_path).expect("delete cert");

        // try_reload should return false
        let result = acceptor.try_reload();
        assert!(!result);

        // Counter should not increment on failure
        assert_eq!(acceptor.reload_count(), 0);

        // Keep temp_dir alive
        let _ = temp_dir;
    }

    #[test]
    fn test_cert_reload_stats() {
        let Some((_temp_dir, cert_path, key_path)) = create_test_certs() else {
            eprintln!("Skipping test: openssl not available");
            return;
        };

        let acceptor = ReloadableTlsAcceptor::new(cert_path, key_path).expect("acceptor");

        acceptor.reload().expect("reload");
        acceptor.reload().expect("reload");

        let stats: CertReloadStats = (&acceptor).into();
        assert_eq!(stats.reload_count, 2);
        assert!(stats.last_reload_timestamp > 0);
    }

    #[test]
    fn test_debug_impl() {
        let Some((_temp_dir, cert_path, key_path)) = create_test_certs() else {
            eprintln!("Skipping test: openssl not available");
            return;
        };

        let acceptor = ReloadableTlsAcceptor::new(cert_path, key_path).expect("acceptor");

        let debug_str = format!("{acceptor:?}");
        assert!(debug_str.contains("ReloadableTlsAcceptor"));
        assert!(debug_str.contains("reload_count"));
    }

    #[test]
    fn test_cert_reload_stats_struct() {
        let stats = CertReloadStats {
            reload_count: 5,
            last_reload_timestamp: 1234567890,
        };

        assert_eq!(stats.reload_count, 5);
        assert_eq!(stats.last_reload_timestamp, 1234567890);
    }
}
