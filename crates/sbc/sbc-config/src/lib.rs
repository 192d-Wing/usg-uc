//! # SBC Config
//!
//! Configuration schema and validation for the USG Session Border Controller.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CM-2**: Baseline Configuration
//! - **CM-6**: Configuration Settings
//!
//! ## Configuration File Format
//!
//! Configuration is loaded from TOML files. Example:
//!
//! ```toml
//! [general]
//! instance_name = "sbc-prod-01"
//!
//! [transport]
//! listen_addresses = ["[::]:5060", "[::]:5061"]
//!
//! [media]
//! default_mode = "relay"
//! codecs = ["opus", "g711-ulaw", "g711-alaw", "g722"]
//!
//! [security]
//! tls_cert_path = "/etc/sbc/cert.pem"
//! tls_key_path = "/etc/sbc/key.pem"
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod schema;
pub mod validate;

pub use error::{ConfigError, ConfigResult};
pub use schema::SbcConfig;

use std::path::Path;

/// Loads configuration from a TOML file.
///
/// ## NIST 800-53 Rev5: CM-2 (Baseline Configuration)
///
/// ## Errors
///
/// Returns an error if the file cannot be read or parsed.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn load_from_file(path: impl AsRef<Path>) -> ConfigResult<SbcConfig> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::FileRead {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    load_from_str(&content)
}

/// Loads configuration from a TOML string.
///
/// ## Errors
///
/// Returns an error if the string cannot be parsed.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn load_from_str(content: &str) -> ConfigResult<SbcConfig> {
    let config: SbcConfig = toml::from_str(content).map_err(|e| ConfigError::Parse {
        reason: e.to_string(),
    })?;

    validate::validate_config(&config)?;

    Ok(config)
}

/// Creates a default configuration.
///
/// This provides sensible defaults for development/testing.
#[must_use]
pub fn default_config() -> SbcConfig {
    SbcConfig::default()
}
