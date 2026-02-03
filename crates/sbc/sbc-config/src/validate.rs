//! Configuration validation.
//!
//! ## NIST 800-53 Rev5: CM-6 (Configuration Settings)
//!
//! Validates configuration settings for correctness and CNSA 2.0 compliance.

use crate::error::{ConfigError, ConfigResult};
use crate::schema::SbcConfig;
use uc_types::protocol::{CnsaCurve, CnsaHash, CnsaSrtpProfile};

/// Validates the entire configuration.
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings)
///
/// ## Errors
///
/// Returns an error if validation fails.
pub fn validate_config(config: &SbcConfig) -> ConfigResult<()> {
    validate_general(&config.general)?;
    validate_transport(&config.transport)?;
    validate_media(&config.media)?;
    validate_security(&config.security)?;
    validate_stir_shaken(&config.stir_shaken)?;
    validate_rate_limit(&config.rate_limit)?;

    Ok(())
}

fn validate_general(config: &crate::schema::GeneralConfig) -> ConfigResult<()> {
    if config.instance_name.is_empty() {
        return Err(ConfigError::Validation {
            message: "instance_name cannot be empty".to_string(),
        });
    }

    if config.max_calls == 0 {
        return Err(ConfigError::Validation {
            message: "max_calls must be greater than 0".to_string(),
        });
    }

    Ok(())
}

fn validate_transport(config: &crate::schema::TransportConfig) -> ConfigResult<()> {
    // Must have at least one listen address
    let total_listeners = config.udp_listen.len()
        + config.tcp_listen.len()
        + config.tls_listen.len()
        + config.ws_listen.len()
        + config.wss_listen.len();

    if total_listeners == 0 {
        return Err(ConfigError::Validation {
            message: "at least one listen address must be configured".to_string(),
        });
    }

    // Validate timeouts
    if config.tcp_timeout_secs == 0 {
        return Err(ConfigError::Validation {
            message: "tcp_timeout_secs must be greater than 0".to_string(),
        });
    }

    Ok(())
}

fn validate_media(config: &crate::schema::MediaConfig) -> ConfigResult<()> {
    // Validate port range
    if config.rtp_port_min >= config.rtp_port_max {
        return Err(ConfigError::Validation {
            message: "rtp_port_min must be less than rtp_port_max".to_string(),
        });
    }

    if config.rtp_port_min < 1024 {
        return Err(ConfigError::Validation {
            message: "rtp_port_min should be >= 1024 (non-privileged)".to_string(),
        });
    }

    // Must have at least one codec
    if config.codecs.is_empty() {
        return Err(ConfigError::Validation {
            message: "at least one codec must be configured".to_string(),
        });
    }

    // CNSA 2.0: Validate SRTP profile
    validate_cnsa_srtp(&config.srtp)?;

    // CNSA 2.0: Validate DTLS fingerprint hash
    validate_cnsa_hash(config.dtls.fingerprint_hash)?;

    Ok(())
}

fn validate_security(config: &crate::schema::SecurityConfig) -> ConfigResult<()> {
    // CNSA 2.0: Validate curve
    validate_cnsa_curve(config.curve)?;

    // CNSA 2.0: Validate TLS version
    match config.min_tls_version.as_str() {
        "1.3" => Ok(()),
        "1.2" => {
            // TLS 1.2 is allowed but 1.3 is preferred
            Ok(())
        }
        _ => Err(ConfigError::CnsaViolation {
            message: "minimum TLS version must be 1.2 or 1.3".to_string(),
        }),
    }
}

fn validate_stir_shaken(config: &crate::schema::StirShakenConfig) -> ConfigResult<()> {
    // If signing is enabled, certificate and key must be provided
    if config.signing_enabled {
        if config.certificate_path.is_none() {
            return Err(ConfigError::Validation {
                message: "STIR/SHAKEN signing requires certificate_path".to_string(),
            });
        }

        if config.private_key_path.is_none() {
            return Err(ConfigError::Validation {
                message: "STIR/SHAKEN signing requires private_key_path".to_string(),
            });
        }

        if config.certificate_url.is_none() {
            return Err(ConfigError::Validation {
                message: "STIR/SHAKEN signing requires certificate_url".to_string(),
            });
        }
    }

    // Validate attestation level
    match config.default_attestation.as_str() {
        "A" | "B" | "C" => Ok(()),
        _ => Err(ConfigError::Validation {
            message: "default_attestation must be A, B, or C".to_string(),
        }),
    }
}

fn validate_rate_limit(config: &crate::schema::RateLimitConfig) -> ConfigResult<()> {
    if config.enabled {
        if config.global_rps == 0 {
            return Err(ConfigError::Validation {
                message: "global_rps must be greater than 0 when rate limiting is enabled"
                    .to_string(),
            });
        }

        if config.burst_multiplier < 1.0 {
            return Err(ConfigError::Validation {
                message: "burst_multiplier must be >= 1.0".to_string(),
            });
        }
    }

    Ok(())
}

/// Validates CNSA 2.0 SRTP profile compliance.
fn validate_cnsa_srtp(config: &crate::schema::SrtpConfig) -> ConfigResult<()> {
    // Only AEAD_AES_256_GCM is permitted
    match config.profile {
        CnsaSrtpProfile::AeadAes256Gcm => Ok(()),
    }
}

/// Validates CNSA 2.0 hash algorithm compliance.
fn validate_cnsa_hash(hash: CnsaHash) -> ConfigResult<()> {
    match hash {
        CnsaHash::Sha384 | CnsaHash::Sha512 => Ok(()),
    }
}

/// Validates CNSA 2.0 elliptic curve compliance.
fn validate_cnsa_curve(curve: CnsaCurve) -> ConfigResult<()> {
    match curve {
        CnsaCurve::P384 | CnsaCurve::P521 => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_default_config() {
        let config = SbcConfig::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_empty_instance_name() {
        let mut config = SbcConfig::default();
        config.general.instance_name = String::new();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_port_range() {
        let mut config = SbcConfig::default();
        config.media.rtp_port_min = 50000;
        config.media.rtp_port_max = 40000;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_no_codecs() {
        let mut config = SbcConfig::default();
        config.media.codecs.clear();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_stir_shaken_signing_without_cert() {
        let mut config = SbcConfig::default();
        config.stir_shaken.signing_enabled = true;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_tls_version() {
        let mut config = SbcConfig::default();
        config.security.min_tls_version = "1.0".to_string();
        assert!(validate_config(&config).is_err());
    }
}
