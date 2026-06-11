//! Env-only config. Same approach as sbc-api-server / sbc-provision-server
//! — Helm sets everything via Deployment env.

use std::net::SocketAddr;

use thiserror::Error;

/// Errors raised while reading config from the environment.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    #[error("invalid {var}: {reason}")]
    Invalid { var: &'static str, reason: String },
}

/// Runtime configuration, one value per `SBC_CLIENT_CONFIG_*` env var.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the HTTP server listens. `SBC_CLIENT_CONFIG_LISTEN_ADDR`,
    /// default `0.0.0.0:80` (same shape as the other HTTP pods).
    pub listen_addr: SocketAddr,

    /// Human-readable service name shown by clients on the sign-in page.
    /// `SBC_CLIENT_CONFIG_SERVICE_NAME`, default `"USG UC"`.
    pub service_name: String,

    /// Identifier of the POP this pod runs in (e.g. `us-east-1`); returned
    /// in the discovery document. `SBC_CLIENT_CONFIG_POP_ID`, required.
    pub pop_id: String,

    /// Externally visible HTTPS base URL of this pod's POP (e.g.
    /// `https://us-east-1.pop.example.mil`). Used to build the
    /// `provisioning.config_endpoint` URL in the discovery document.
    /// `SBC_CLIENT_CONFIG_PUBLIC_URL`, required.
    pub public_url: String,

    /// OIDC issuer URL (e.g. `https://idp.example.mil/realms/voice`).
    /// Tokens must carry this `iss`; OIDC metadata + JWKS are fetched from
    /// it. `SBC_CLIENT_CONFIG_OIDC_ISSUER`, required.
    pub oidc_issuer: String,

    /// OAuth client id the soft client uses for the browser sign-in flow;
    /// returned in the discovery document.
    /// `SBC_CLIENT_CONFIG_OIDC_CLIENT_ID`, required.
    pub oidc_client_id: String,

    /// Audience (`aud`) tokens must carry to call `/v1/client-config`.
    /// `SBC_CLIENT_CONFIG_OIDC_AUDIENCE`, default `usg-uc-provisioning`.
    pub oidc_audience: String,

    /// Scopes the client should request, returned in the discovery
    /// document. `SBC_CLIENT_CONFIG_OIDC_SCOPES` (comma-separated),
    /// default `openid,profile,offline_access,sip`.
    pub oidc_scopes: Vec<String>,

    /// SIP domain of user AORs (e.g. `example.mil`).
    /// `SBC_CLIENT_CONFIG_SIP_DOMAIN`, required.
    pub sip_domain: String,

    /// POP-scoped registrar domain the client resolves via NAPTR/SRV
    /// (RFC 3263), e.g. `us-east-1.reg.example.mil`.
    /// `SBC_CLIENT_CONFIG_REGISTRAR_DOMAIN`, required.
    pub registrar_domain: String,

    /// REGISTER expiry handed to clients, seconds.
    /// `SBC_CLIENT_CONFIG_REG_EXPIRES_SECS`, default 300.
    pub reg_expires_secs: u32,

    /// Codec preference list. `SBC_CLIENT_CONFIG_CODECS` (comma-separated),
    /// default `opus,pcmu,pcma`.
    pub codecs: Vec<String>,

    /// How long clients may use a fetched config before re-fetching,
    /// seconds. `SBC_CLIENT_CONFIG_TTL_SECS`, default 3600.
    pub ttl_secs: u32,

    /// Voicemail pilot URI (e.g. `sip:*97@example.mil`), omitted from the
    /// config when unset. `SBC_CLIENT_CONFIG_VOICEMAIL_URI`.
    pub voicemail_uri: Option<String>,

    /// Minimum client versions surfaced in the discovery document.
    /// `SBC_CLIENT_CONFIG_MIN_VERSION_DESKTOP` / `_ANDROID`, optional.
    pub min_version_desktop: Option<String>,
    /// See [`Config::min_version_desktop`].
    pub min_version_android: Option<String>,

    /// Path to a PEM file containing extra CA certificates to trust when
    /// fetching the OIDC discovery document and JWKS. Required when the `IdP`
    /// uses a private CA not in the Mozilla root bundle.
    /// `SBC_CLIENT_CONFIG_EXTRA_CA_CERT_FILE`, optional.
    pub extra_ca_cert_file: Option<String>,
}

impl Config {
    /// Reads config from process environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads config through a lookup closure — `from_env` in production,
    /// a map in tests (mutating process env in tests is unsafe under
    /// edition 2024 and races between threads).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let listen_addr = get("SBC_CLIENT_CONFIG_LISTEN_ADDR")
            .unwrap_or_else(|| "0.0.0.0:80".to_string())
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                var: "SBC_CLIENT_CONFIG_LISTEN_ADDR",
                reason: e.to_string(),
            })?;

        let service_name =
            get("SBC_CLIENT_CONFIG_SERVICE_NAME").unwrap_or_else(|| "USG UC".to_string());

        let pop_id = required(&get, "SBC_CLIENT_CONFIG_POP_ID")?;
        let public_url = required(&get, "SBC_CLIENT_CONFIG_PUBLIC_URL")?
            .trim_end_matches('/')
            .to_string();

        let oidc_issuer = required(&get, "SBC_CLIENT_CONFIG_OIDC_ISSUER")?
            .trim_end_matches('/')
            .to_string();
        if !oidc_issuer.starts_with("https://") {
            // http:// issuers are a test-bench foot-gun in production; the
            // discovery document is the client's trust bootstrap.
            return Err(ConfigError::Invalid {
                var: "SBC_CLIENT_CONFIG_OIDC_ISSUER",
                reason: "must be an https:// URL".to_string(),
            });
        }
        let oidc_client_id = required(&get, "SBC_CLIENT_CONFIG_OIDC_CLIENT_ID")?;
        let oidc_audience = get("SBC_CLIENT_CONFIG_OIDC_AUDIENCE")
            .unwrap_or_else(|| "usg-uc-provisioning".to_string());
        let oidc_scopes = csv(&get("SBC_CLIENT_CONFIG_OIDC_SCOPES")
            .unwrap_or_else(|| "openid,profile,offline_access,sip".to_string()));

        let sip_domain = required(&get, "SBC_CLIENT_CONFIG_SIP_DOMAIN")?;
        let registrar_domain = required(&get, "SBC_CLIENT_CONFIG_REGISTRAR_DOMAIN")?;

        let reg_expires_secs = parse_u32(&get, "SBC_CLIENT_CONFIG_REG_EXPIRES_SECS", 300)?;
        let ttl_secs = parse_u32(&get, "SBC_CLIENT_CONFIG_TTL_SECS", 3600)?;

        let codecs =
            csv(&get("SBC_CLIENT_CONFIG_CODECS").unwrap_or_else(|| "opus,pcmu,pcma".to_string()));

        Ok(Self {
            listen_addr,
            service_name,
            pop_id,
            public_url,
            oidc_issuer,
            oidc_client_id,
            oidc_audience,
            oidc_scopes,
            sip_domain,
            registrar_domain,
            reg_expires_secs,
            codecs,
            ttl_secs,
            voicemail_uri: get("SBC_CLIENT_CONFIG_VOICEMAIL_URI"),
            min_version_desktop: get("SBC_CLIENT_CONFIG_MIN_VERSION_DESKTOP"),
            min_version_android: get("SBC_CLIENT_CONFIG_MIN_VERSION_ANDROID"),
            extra_ca_cert_file: get("SBC_CLIENT_CONFIG_EXTRA_CA_CERT_FILE"),
        })
    }
}

fn required(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
) -> Result<String, ConfigError> {
    get(var)
        .filter(|v| !v.trim().is_empty())
        .ok_or(ConfigError::Missing(var))
}

fn parse_u32(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    get(var).map_or(Ok(default), |raw| {
        raw.parse::<u32>().map_err(|e| ConfigError::Invalid {
            var,
            reason: e.to_string(),
        })
    })
}

fn csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn base_env(var: &str) -> Option<String> {
        match var {
            "SBC_CLIENT_CONFIG_POP_ID" => Some("us-east-1".into()),
            "SBC_CLIENT_CONFIG_PUBLIC_URL" => Some("https://us-east-1.pop.example.mil/".into()),
            "SBC_CLIENT_CONFIG_OIDC_ISSUER" => Some("https://idp.example.mil/realms/voice/".into()),
            "SBC_CLIENT_CONFIG_OIDC_CLIENT_ID" => Some("usg-uc-softclient".into()),
            "SBC_CLIENT_CONFIG_SIP_DOMAIN" => Some("example.mil".into()),
            "SBC_CLIENT_CONFIG_REGISTRAR_DOMAIN" => Some("us-east-1.reg.example.mil".into()),
            _ => None,
        }
    }

    #[test]
    fn minimal_env_with_defaults() {
        let cfg = Config::from_lookup(base_env).expect("config");
        assert_eq!(cfg.listen_addr.port(), 80);
        assert_eq!(cfg.service_name, "USG UC");
        // trailing slashes are normalized off URL-shaped values
        assert_eq!(cfg.public_url, "https://us-east-1.pop.example.mil");
        assert_eq!(cfg.oidc_issuer, "https://idp.example.mil/realms/voice");
        assert_eq!(cfg.oidc_audience, "usg-uc-provisioning");
        assert_eq!(
            cfg.oidc_scopes,
            ["openid", "profile", "offline_access", "sip"]
        );
        assert_eq!(cfg.reg_expires_secs, 300);
        assert_eq!(cfg.ttl_secs, 3600);
        assert_eq!(cfg.codecs, ["opus", "pcmu", "pcma"]);
        assert!(cfg.voicemail_uri.is_none());
    }

    #[test]
    fn missing_required_var_is_reported() {
        let err = Config::from_lookup(|var| {
            (var != "SBC_CLIENT_CONFIG_REGISTRAR_DOMAIN")
                .then(|| base_env(var))
                .flatten()
        })
        .expect_err("must fail");
        assert!(matches!(
            err,
            ConfigError::Missing("SBC_CLIENT_CONFIG_REGISTRAR_DOMAIN")
        ));
    }

    #[test]
    fn http_issuer_is_rejected() {
        let err = Config::from_lookup(|var| {
            if var == "SBC_CLIENT_CONFIG_OIDC_ISSUER" {
                Some("http://idp.example.mil/realms/voice".into())
            } else {
                base_env(var)
            }
        })
        .expect_err("must fail");
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "SBC_CLIENT_CONFIG_OIDC_ISSUER",
                ..
            }
        ));
    }
}
