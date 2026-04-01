//! # SBC Config
//!
//! Configuration schema and validation for the USG Session Border Controller.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CM-2**: Baseline Configuration
//! - **CM-6**: Configuration Settings
//!
//! ## Configuration File Formats
//!
//! Configuration can be loaded from either TOML or YAML files. The format is
//! auto-detected based on file extension (`.toml` for TOML, `.yaml`/`.yml` for YAML).
//!
//! ### TOML Example
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
//!
//! ### YAML Example
//!
//! ```yaml
//! general:
//!   instance_name: sbc-prod-01
//!
//! transport:
//!   listen_addresses:
//!     - "[::]:5060"
//!     - "[::]:5061"
//!
//! media:
//!   default_mode: relay
//!   codecs:
//!     - opus
//!     - g711-ulaw
//!     - g711-alaw
//!     - g722
//!
//! security:
//!   tls_cert_path: /etc/sbc/cert.pem
//!   tls_key_path: /etc/sbc/key.pem
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod interface;
pub mod schema;
pub mod validate;

pub use error::{ConfigError, ConfigResult};
pub use interface::{ResolvedZone, resolve_zones};
pub use schema::{
    DialPlanConfig, DialPlanEntryConfig, HeaderManipulationConfig, ManipulationRuleConfig,
    RoutingConfig, SbcConfig, TopologyHidingConfig, TrunkConfigSchema, TrunkGroupConfig,
    TrunkManipulationRuleConfig, ZoneConfig,
};
#[cfg(feature = "telemetry")]
pub use schema::TelemetryConfig;

use std::path::Path;

/// Configuration file format.
///
/// Supports both TOML and YAML formats for enterprise flexibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigFormat {
    /// TOML format (default, Rust-idiomatic).
    #[default]
    Toml,
    /// YAML format (commonly used in Kubernetes/enterprise deployments).
    Yaml,
}

impl ConfigFormat {
    /// Detects the configuration format from a file extension.
    ///
    /// - `.yaml` or `.yml` → [`ConfigFormat::Yaml`]
    /// - `.toml` or any other extension → [`ConfigFormat::Toml`]
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::Path;
    /// use sbc_config::ConfigFormat;
    ///
    /// assert_eq!(ConfigFormat::from_extension(Path::new("config.yaml")), ConfigFormat::Yaml);
    /// assert_eq!(ConfigFormat::from_extension(Path::new("config.yml")), ConfigFormat::Yaml);
    /// assert_eq!(ConfigFormat::from_extension(Path::new("config.toml")), ConfigFormat::Toml);
    /// assert_eq!(ConfigFormat::from_extension(Path::new("config")), ConfigFormat::Toml);
    /// ```
    #[must_use]
    pub fn from_extension(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml" | "yml") => Self::Yaml,
            _ => Self::Toml,
        }
    }

    /// Returns the file extension for this format.
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Yaml => "yaml",
        }
    }

    /// Returns the MIME type for this format.
    #[must_use]
    pub const fn mime_type(&self) -> &'static str {
        match self {
            Self::Toml => "application/toml",
            Self::Yaml => "application/yaml",
        }
    }
}

impl std::fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml => write!(f, "TOML"),
            Self::Yaml => write!(f, "YAML"),
        }
    }
}

/// Loads configuration from a file with auto-detected format.
///
/// The format is determined by the file extension:
/// - `.yaml` or `.yml` → YAML format
/// - `.toml` or any other → TOML format
///
/// ## NIST 800-53 Rev5: CM-2 (Baseline Configuration)
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_from_file(path: impl AsRef<Path>) -> ConfigResult<SbcConfig> {
    let path = path.as_ref();
    let format = ConfigFormat::from_extension(path);
    load_from_file_with_format(path, format)
}

/// Loads configuration from a file with an explicit format.
///
/// Use this when the file extension doesn't match the actual format,
/// or when you want to override auto-detection.
///
/// ## NIST 800-53 Rev5: CM-2 (Baseline Configuration)
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_from_file_with_format(path: &Path, format: ConfigFormat) -> ConfigResult<SbcConfig> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::FileRead {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    load_from_str_with_format(&content, format)
}

/// Loads configuration from a TOML string.
///
/// This is a convenience function that defaults to TOML format for
/// backward compatibility.
///
/// # Errors
///
/// Returns an error if the string cannot be parsed as TOML.
pub fn load_from_str(content: &str) -> ConfigResult<SbcConfig> {
    load_from_str_with_format(content, ConfigFormat::Toml)
}

/// Loads configuration from a string with an explicit format.
///
/// # Errors
///
/// Returns an error if the string cannot be parsed in the specified format.
pub fn load_from_str_with_format(content: &str, format: ConfigFormat) -> ConfigResult<SbcConfig> {
    let config: SbcConfig = match format {
        ConfigFormat::Toml => toml::from_str(content).map_err(|e| ConfigError::Parse {
            reason: format!("TOML parse error: {e}"),
        })?,
        ConfigFormat::Yaml => serde_yaml_ng::from_str(content).map_err(|e| ConfigError::Parse {
            reason: format!("YAML parse error: {e}"),
        })?,
    };

    validate::validate_config(&config)?;

    Ok(config)
}

/// Loads configuration from a YAML string.
///
/// This is a convenience function for loading YAML configuration directly.
///
/// # Errors
///
/// Returns an error if the string cannot be parsed as YAML.
pub fn load_from_yaml_str(content: &str) -> ConfigResult<SbcConfig> {
    load_from_str_with_format(content, ConfigFormat::Yaml)
}

/// Creates a default configuration.
///
/// This provides sensible defaults for development/testing.
#[must_use]
pub fn default_config() -> SbcConfig {
    SbcConfig::default()
}

/// Serializes configuration to a string in the specified format.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_config(config: &SbcConfig, format: ConfigFormat) -> ConfigResult<String> {
    match format {
        ConfigFormat::Toml => toml::to_string_pretty(config).map_err(|e| ConfigError::Parse {
            reason: format!("TOML serialization error: {e}"),
        }),
        ConfigFormat::Yaml => serde_yaml_ng::to_string(config).map_err(|e| ConfigError::Parse {
            reason: format!("YAML serialization error: {e}"),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_from_extension() {
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.yaml")),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.yml")),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.toml")),
            ConfigFormat::Toml
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config")),
            ConfigFormat::Toml
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("/etc/sbc/sbc.yaml")),
            ConfigFormat::Yaml
        );
    }

    #[test]
    fn test_format_display() {
        assert_eq!(ConfigFormat::Toml.to_string(), "TOML");
        assert_eq!(ConfigFormat::Yaml.to_string(), "YAML");
    }

    #[test]
    fn test_format_extension() {
        assert_eq!(ConfigFormat::Toml.extension(), "toml");
        assert_eq!(ConfigFormat::Yaml.extension(), "yaml");
    }

    #[test]
    fn test_format_mime_type() {
        assert_eq!(ConfigFormat::Toml.mime_type(), "application/toml");
        assert_eq!(ConfigFormat::Yaml.mime_type(), "application/yaml");
    }

    #[test]
    fn test_load_toml_string() {
        let toml_content = r#"
            [general]
            instance_name = "test-sbc"
            max_calls = 5000
        "#;

        let config = load_from_str(toml_content).expect("should parse TOML");
        assert_eq!(config.general.instance_name, "test-sbc");
        assert_eq!(config.general.max_calls, 5000);
    }

    #[test]
    fn test_load_yaml_string() {
        let yaml_content = r"
general:
  instance_name: test-sbc-yaml
  max_calls: 7500
";

        let config = load_from_yaml_str(yaml_content).expect("should parse YAML");
        assert_eq!(config.general.instance_name, "test-sbc-yaml");
        assert_eq!(config.general.max_calls, 7500);
    }

    #[test]
    fn test_yaml_toml_equivalence() {
        let toml_content = r#"
[general]
instance_name = "equiv-test"
max_calls = 10000
max_registrations = 50000

[media]
rtp_port_min = 20000
rtp_port_max = 30000
"#;

        let yaml_content = r"
general:
  instance_name: equiv-test
  max_calls: 10000
  max_registrations: 50000

media:
  rtp_port_min: 20000
  rtp_port_max: 30000
";

        let toml_config = load_from_str(toml_content).expect("should parse TOML");
        let yaml_config = load_from_yaml_str(yaml_content).expect("should parse YAML");

        assert_eq!(
            toml_config.general.instance_name,
            yaml_config.general.instance_name
        );
        assert_eq!(toml_config.general.max_calls, yaml_config.general.max_calls);
        assert_eq!(
            toml_config.general.max_registrations,
            yaml_config.general.max_registrations
        );
        assert_eq!(
            toml_config.media.rtp_port_min,
            yaml_config.media.rtp_port_min
        );
        assert_eq!(
            toml_config.media.rtp_port_max,
            yaml_config.media.rtp_port_max
        );
    }

    #[test]
    fn test_serialize_config() {
        let config = default_config();

        let toml_output = serialize_config(&config, ConfigFormat::Toml).expect("TOML serialize");
        assert!(toml_output.contains("instance_name"));

        let yaml_output = serialize_config(&config, ConfigFormat::Yaml).expect("YAML serialize");
        assert!(yaml_output.contains("instance_name"));
    }

    #[test]
    fn test_invalid_yaml() {
        let invalid_yaml = "general: [unclosed";
        let result = load_from_yaml_str(invalid_yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("YAML parse error"));
    }

    #[test]
    fn test_invalid_toml() {
        let invalid_toml = "[general\nunclosed";
        let result = load_from_str(invalid_toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("TOML parse error"));
    }
}
