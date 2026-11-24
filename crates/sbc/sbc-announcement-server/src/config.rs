//! Pod configuration, parsed from env at startup. An invalid or
//! inconsistent value stops startup (exit 2); nothing is silently ignored.
//!
//! ## NIST 800-53 Rev5: CM-6, CM-7, IA-3, SC-5, SC-7

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use sbc_announcement::DestinationPolicy;
use sbc_grpc_api::mtls::{self, MtlsEnvNames, ServerTls};

/// The announcement listener variables (error messages name these).
pub const MTLS_NAMES: MtlsEnvNames = MtlsEnvNames {
    listen: "SBC_ANN_GRPC_LISTEN",
    tls_prefix: "SBC_ANN_GRPC_TLS",
    allowed: "SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES",
};

/// Longest Bound-to-first-packet delay a request (or the pod default) may
/// ask for. Bounds how long an idle socket and task are held.
pub const MAX_INITIAL_DELAY_MS: u32 = 2000;

/// Default and bounds of `SBC_ANN_MAX_PLAYS`.
const DEFAULT_MAX_PLAYS: usize = 128;
const MAX_MAX_PLAYS: usize = 4096;
/// Default of `SBC_ANN_MAX_PLAYS_PER_DEST` (clamped to the global cap).
const DEFAULT_MAX_PLAYS_PER_DEST: usize = 32;
/// Default and upper bound of `SBC_ANN_MAX_PLAY_SECS`.
const DEFAULT_MAX_PLAY_SECS: u64 = 30;
const MAX_MAX_PLAY_SECS: u64 = 120;
/// Default `SBC_ANN_DEFAULT_DELAY_MS` (the daemon's historical ACK-settle
/// sleep).
const DEFAULT_DELAY_MS: u32 = 200;

/// Pod configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub grpc_listen: SocketAddr,
    pub advertised_ip: IpAddr,
    pub bind_ip: Option<IpAddr>,
    pub rtp_port_range: Option<(u16, u16)>,
    pub default_delay_ms: u32,
    /// Listener mTLS; required off loopback.
    pub grpc_tls: Option<ServerTls>,
    /// Client certificate SAN names admitted under mTLS.
    pub allowed_client_names: Vec<String>,
    /// Concurrent plays per replica.
    pub max_plays: usize,
    /// Concurrent plays per destination IP.
    pub max_plays_per_dest: usize,
    /// Longest Play, initial delay included.
    pub max_play: Duration,
    /// Where RTP may be sent.
    pub dest_policy: DestinationPolicy,
}

/// An integer in `min..=max`, or `default` when unset.
fn bounded<T>(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: T,
    min: T,
    max: T,
) -> Result<T, String>
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
{
    let Some(raw) = lookup(name).filter(|v| !v.trim().is_empty()) else {
        return Ok(default);
    };
    match raw.trim().parse::<T>() {
        Ok(v) if v >= min && v <= max => Ok(v),
        _ => Err(format!("{name} must be an integer in {min}..={max}")),
    }
}

impl Config {
    /// From the process environment.
    ///
    /// # Errors
    /// As [`Self::from_lookup`].
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k: &str| std::env::var(k).ok())
    }

    /// From `lookup` (an env-like key/value source).
    ///
    /// # Errors
    /// A message naming the offending variable.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let grpc_listen: SocketAddr = lookup("SBC_ANN_GRPC_LISTEN")
            .unwrap_or_else(|| "0.0.0.0:9095".to_string())
            .parse()
            .map_err(|e| format!("SBC_ANN_GRPC_LISTEN invalid: {e}"))?;

        // NIST 800-53 Rev5: IA-3, SC-8 -- off loopback only with mTLS and a
        // client allow-list (the default 0.0.0.0 listen refuses to start
        // without certificates).
        let grpc_tls = mtls::server_tls_from(
            &MTLS_NAMES,
            lookup("SBC_ANN_GRPC_TLS_CERT_FILE"),
            lookup("SBC_ANN_GRPC_TLS_KEY_FILE"),
            lookup("SBC_ANN_GRPC_TLS_CLIENT_CA_FILE"),
        )?;
        let allowed_client_names = mtls::parse_allowed_client_names(
            &MTLS_NAMES,
            lookup("SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES").as_deref(),
        )?;
        mtls::check_listener(
            &MTLS_NAMES,
            grpc_listen,
            grpc_tls.as_ref(),
            &allowed_client_names,
        )?;

        let bind_ip = match lookup("SBC_ANN_BIND_IP") {
            Some(v) => Some(
                v.parse::<IpAddr>()
                    .map_err(|e| format!("SBC_ANN_BIND_IP invalid: {e}"))?,
            ),
            None => None,
        };

        let advertised_ip = match lookup("SBC_ANN_ADVERTISED_IP") {
            Some(v) => v
                .parse::<IpAddr>()
                .map_err(|e| format!("SBC_ANN_ADVERTISED_IP invalid: {e}"))?,
            None => bind_ip.filter(|ip| !ip.is_unspecified()).ok_or_else(|| {
                "SBC_ANN_ADVERTISED_IP is required (no usable SBC_ANN_BIND_IP fallback): \
                 it is the media IP placed in the announcement SDP"
                    .to_string()
            })?,
        };

        let rtp_port_range = rtp_port_range(&lookup)?;

        let default_delay_ms = bounded(
            &lookup,
            "SBC_ANN_DEFAULT_DELAY_MS",
            DEFAULT_DELAY_MS,
            0,
            MAX_INITIAL_DELAY_MS,
        )?;

        // NIST 800-53 Rev5: SC-5 -- concurrency and duration caps.
        let max_plays = bounded(
            &lookup,
            "SBC_ANN_MAX_PLAYS",
            DEFAULT_MAX_PLAYS,
            1,
            MAX_MAX_PLAYS,
        )?;
        let max_plays_per_dest = bounded(
            &lookup,
            "SBC_ANN_MAX_PLAYS_PER_DEST",
            DEFAULT_MAX_PLAYS_PER_DEST.min(max_plays),
            1,
            max_plays,
        )
        .map_err(|e| format!("{e} (at most SBC_ANN_MAX_PLAYS)"))?;
        let max_play = Duration::from_secs(bounded(
            &lookup,
            "SBC_ANN_MAX_PLAY_SECS",
            DEFAULT_MAX_PLAY_SECS,
            1,
            MAX_MAX_PLAY_SECS,
        )?);

        let dest_policy = dest_policy(&lookup)?;

        Ok(Self {
            grpc_listen,
            advertised_ip,
            bind_ip,
            rtp_port_range,
            default_delay_ms,
            grpc_tls,
            allowed_client_names,
            max_plays,
            max_plays_per_dest,
            max_play,
            dest_policy,
        })
    }
}

/// `SBC_ANN_RTP_PORT_{MIN,MAX}`: both or neither.
fn rtp_port_range(lookup: &impl Fn(&str) -> Option<String>) -> Result<Option<(u16, u16)>, String> {
    match (
        lookup("SBC_ANN_RTP_PORT_MIN"),
        lookup("SBC_ANN_RTP_PORT_MAX"),
    ) {
        (Some(min), Some(max)) => {
            let min: u16 = min
                .parse()
                .map_err(|e| format!("SBC_ANN_RTP_PORT_MIN invalid: {e}"))?;
            let max: u16 = max
                .parse()
                .map_err(|e| format!("SBC_ANN_RTP_PORT_MAX invalid: {e}"))?;
            if min == 0 || min > max {
                return Err(format!("invalid RTP port range {min}-{max}"));
            }
            Ok(Some((min, max)))
        }
        (None, None) => Ok(None),
        _ => Err("SBC_ANN_RTP_PORT_MIN and SBC_ANN_RTP_PORT_MAX must be set together".to_string()),
    }
}

/// The destination policy. NIST 800-53 Rev5: SC-7 -- the loopback flag is
/// lab-only and accepts exactly `true` / `false`.
fn dest_policy(lookup: &impl Fn(&str) -> Option<String>) -> Result<DestinationPolicy, String> {
    let allow_loopback = match lookup("SBC_ANN_ALLOW_LOOPBACK_DEST").as_deref() {
        None | Some("" | "false") => false,
        Some("true") => true,
        Some(_) => return Err("SBC_ANN_ALLOW_LOOPBACK_DEST must be true or false".to_string()),
    };
    let allowed = parse_cidrs(lookup("SBC_ANN_ALLOWED_DEST_CIDRS").as_deref())?;
    Ok(DestinationPolicy {
        allow_loopback,
        allowed,
    })
}

/// `SBC_ANN_ALLOWED_DEST_CIDRS`: comma-separated CIDRs, at most 256; empty
/// means no CIDR restriction.
fn parse_cidrs(raw: Option<&str>) -> Result<Vec<IpNet>, String> {
    sbc_announcement::parse_allowed_cidrs("SBC_ANN_ALLOWED_DEST_CIDRS", raw)
}
