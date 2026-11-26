//! Per-site config sync agent (Phase 2 of `docs/CENTRAL-CONFIG-PLAN.md`).
//!
//! Runs as one pod per base. Each cycle it pulls its shard's changes from
//! `central-config-api` and applies them transactionally into the
//! site-local Postgres the SBC daemon and provision/api servers already
//! read — making that local database a synced replica of the site's
//! central shard. The agent is the *only* writer of central-origin rows
//! locally; local break-glass writes (`updated_by = 'local'`) are left
//! alone.
//!
//! - [`apply`] — the transactional snapshot/delta apply engine.
//! - [`source`] — the [`ConfigSource`] reads + the [`reconcile`] policy +
//!   the HTTP [`CentralClient`].
//! - [`config`] — env configuration.
//!
//! [`ConfigSource`]: source::ConfigSource
//! [`reconcile`]: source::reconcile
//! [`CentralClient`]: source::CentralClient

pub mod apply;
pub mod config;
pub mod error;
pub mod refresh;
pub mod source;
pub mod status;
pub mod token;

pub use config::{AuthConfig, Config};
pub use error::{SyncError, SyncResult};
pub use refresh::{GrpcRefresher, NoopRefresher, RefreshItem, Refresher};
pub use source::{CentralClient, ConfigSource, Outcome, reconcile};
pub use status::SyncStatus;
pub use token::{Auth, TokenProvider};

/// Builds the HTTP client for the central sync API and the OIDC token
/// endpoint.
///
/// CNSA suites and groups only (uc-transport `https-client`), OS trust
/// store (`SSL_CERT_FILE` / `SSL_CERT_DIR` honoured), 30 s timeout.
///
/// ## NIST 800-53 Rev5: SC-8(1), SC-13, IA-5(2)
///
/// # Errors
/// [`SyncError::Central`] if the trust store is empty or the client cannot
/// be built.
pub fn build_http_client() -> Result<reqwest::Client, SyncError> {
    let tls = uc_transport::https_client::create_https_client_config(
        None,
        uc_transport::tls::MinTlsVersion::V1_2,
    )
    .map_err(|e| SyncError::Central(format!("TLS config: {e}")))?;
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .use_preconfigured_tls(tls)
        .build()
        .map_err(SyncError::from)
}
