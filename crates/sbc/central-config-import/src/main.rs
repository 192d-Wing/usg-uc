//! central-config-import — onboard a base into the central config DB.
//!
//! Reads the site-local config Postgres and writes every live row into the
//! site's central shard. The site is registered first (creating its
//! partitions) so a fresh shard is ready to receive the rows.
//!
//! Env:
//!
//! ```text
//! IMPORT_SITE_CODE        canonical site code (e.g. MUHJ)
//! IMPORT_SITE_FQDN_BASE   fqdn base for the sites registry row
//! IMPORT_SOURCE_DSN       site-local Postgres DSN (read)
//! IMPORT_CENTRAL_DSN      central config DB DSN (write)
//! IMPORT_ACTOR            recorded writer (default "importer")
//! ```

use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use central_config_import::import_site;
use central_config_store::CentralConfigStore;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let Ok(site) = std::env::var("IMPORT_SITE_CODE") else {
        error!("IMPORT_SITE_CODE is required");
        return ExitCode::from(2);
    };
    let fqdn = std::env::var("IMPORT_SITE_FQDN_BASE")
        .unwrap_or_else(|_| format!("{}.local", site.to_lowercase()));
    let Ok(source_dsn) = std::env::var("IMPORT_SOURCE_DSN") else {
        error!("IMPORT_SOURCE_DSN is required");
        return ExitCode::from(2);
    };
    let Ok(central_dsn) = std::env::var("IMPORT_CENTRAL_DSN") else {
        error!("IMPORT_CENTRAL_DSN is required");
        return ExitCode::from(2);
    };
    let actor = std::env::var("IMPORT_ACTOR").unwrap_or_else(|_| "importer".to_string());

    let source = match PgPoolOptions::new()
        .max_connections(4)
        .connect(&source_dsn)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "connect source DB failed");
            return ExitCode::from(3);
        }
    };
    let central = match CentralConfigStore::connect(&central_dsn).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "connect central DB failed");
            return ExitCode::from(3);
        }
    };

    if let Err(e) = central
        .register_site(&site, &site, &fqdn, "UTC", "active")
        .await
    {
        error!(site = %site, error = %e, "register site failed");
        return ExitCode::from(4);
    }

    match import_site(&source, &central, &site, &actor).await {
        Ok(report) => {
            info!(site = %site, ?report, "import complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(site = %site, error = %e, "import failed");
            ExitCode::from(5)
        }
    }
}
