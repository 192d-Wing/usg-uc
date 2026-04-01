//! Network interface resolution.
//!
//! Resolves network interface names (eth0, eth1) to IPv4 addresses
//! at startup using `getifaddrs`. Supports zone-based binding where
//! signaling and media are bound to separate interfaces.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (interface isolation)
//! - **CM-6**: Configuration Settings

use crate::error::ConfigError;
use crate::schema::ZoneConfig;
use std::collections::HashMap;
use std::net::IpAddr;

/// A zone with resolved IP addresses (runtime, not config).
#[derive(Debug, Clone)]
pub struct ResolvedZone {
    /// Zone name.
    pub name: String,
    /// Signaling interface IP (for SIP transports).
    pub signaling_ip: IpAddr,
    /// Media interface IP (for RTP/SRTP ports).
    pub media_ip: IpAddr,
    /// External/public IP for NAT traversal.
    /// `None` means use `signaling_ip` directly.
    pub external_ip: Option<IpAddr>,
    /// Raw external_ip config value (for STUN re-resolution).
    pub external_ip_source: Option<String>,
}

/// Resolves all zones from config to concrete IP addresses.
///
/// Enumerates system interfaces via `getifaddrs`, maps each zone's
/// `signaling_interface` and `media_interface` to IPv4 addresses.
///
/// ## Errors
///
/// Returns `ConfigError::InterfaceNotFound` if any configured
/// interface does not exist on the system.
pub fn resolve_zones(zones: &[ZoneConfig]) -> Result<Vec<ResolvedZone>, ConfigError> {
    let iface_map = enumerate_interfaces()?;

    let mut resolved = Vec::with_capacity(zones.len());
    for zone in zones {
        let signaling_ip = resolve_interface(&zone.signaling_interface, &iface_map)?;
        let media_ip = resolve_interface(&zone.media_interface, &iface_map)?;

        // Resolve external_ip: literal IP, interface name, or leave for async STUN
        let (external_ip, external_ip_source) = match &zone.external_ip {
            Some(value) if value.starts_with("stun") => {
                // STUN discovery — defer to async resolution at runtime
                (None, Some(value.clone()))
            }
            Some(value) => {
                // Try as literal IP first, then as interface name
                let ip = if let Ok(ip) = value.parse::<IpAddr>() {
                    ip
                } else {
                    resolve_interface(value, &iface_map)?
                };
                (Some(ip), Some(value.clone()))
            }
            None => (None, None),
        };

        resolved.push(ResolvedZone {
            name: zone.name.clone(),
            signaling_ip,
            media_ip,
            external_ip,
            external_ip_source,
        });
    }

    Ok(resolved)
}

/// Resolves an interface name to its first non-link-local IPv4 address.
fn resolve_interface(
    name: &str,
    iface_map: &HashMap<String, Vec<IpAddr>>,
) -> Result<IpAddr, ConfigError> {
    let addrs = iface_map
        .get(name)
        .ok_or_else(|| ConfigError::InterfaceNotFound {
            name: name.to_string(),
        })?;

    // Return first non-link-local IPv4 address
    addrs
        .iter()
        .find(|addr| match addr {
            IpAddr::V4(v4) => !v4.is_link_local(),
            IpAddr::V6(_) => false, // Prefer IPv4 for now
        })
        .copied()
        .ok_or_else(|| ConfigError::InterfaceNoAddress {
            name: name.to_string(),
        })
}

/// Enumerates all network interfaces and their IPv4 addresses.
///
/// Returns a map of interface name → list of IP addresses.
fn enumerate_interfaces() -> Result<HashMap<String, Vec<IpAddr>>, ConfigError> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();

    let ifaddrs = nix::ifaddrs::getifaddrs().map_err(|e| ConfigError::Validation {
        message: format!("Failed to enumerate network interfaces: {e}"),
    })?;

    for ifaddr in ifaddrs {
        if let Some(addr) = ifaddr.address {
            if let Some(sockaddr) = addr.as_sockaddr_in() {
                let ip = IpAddr::V4(std::net::Ipv4Addr::from(sockaddr.ip()));
                map.entry(ifaddr.interface_name.clone())
                    .or_default()
                    .push(ip);
            }
        }
    }

    Ok(map)
}

/// Returns a list of all available interface names on the system.
/// Useful for error messages and diagnostics.
pub fn list_interfaces() -> Vec<String> {
    enumerate_interfaces()
        .map(|m| {
            let mut names: Vec<String> = m.keys().cloned().collect();
            names.sort();
            names
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_interfaces() {
        let map = enumerate_interfaces().unwrap();
        // lo0 or lo should exist on any system
        assert!(
            map.contains_key("lo0") || map.contains_key("lo"),
            "Expected loopback interface, got: {:?}",
            map.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_resolve_interface_not_found() {
        let map = enumerate_interfaces().unwrap();
        let result = resolve_interface("nonexistent99", &map);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::InterfaceNotFound { name } => {
                assert_eq!(name, "nonexistent99");
            }
            other => panic!("Expected InterfaceNotFound, got: {other}"),
        }
    }

    #[test]
    fn test_resolve_loopback() {
        let map = enumerate_interfaces().unwrap();
        let lo_name = if map.contains_key("lo0") {
            "lo0"
        } else {
            "lo"
        };
        let ip = resolve_interface(lo_name, &map).unwrap();
        assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_resolve_zones_empty() {
        let zones: Vec<ZoneConfig> = vec![];
        let resolved = resolve_zones(&zones).unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn test_resolve_zone_with_stun_external() {
        let map = enumerate_interfaces().unwrap();
        let lo_name = if map.contains_key("lo0") {
            "lo0"
        } else {
            "lo"
        };

        let zones = vec![ZoneConfig {
            name: "test".to_string(),
            signaling_interface: lo_name.to_string(),
            media_interface: lo_name.to_string(),
            external_ip: Some("stun".to_string()),
        }];

        let resolved = resolve_zones(&zones).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "test");
        // STUN should defer — external_ip is None, source is preserved
        assert!(resolved[0].external_ip.is_none());
        assert_eq!(
            resolved[0].external_ip_source,
            Some("stun".to_string())
        );
    }
}
