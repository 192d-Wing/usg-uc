//! SNMP configuration types.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// SNMP configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SnmpConfig {
    /// Enable SNMP traps.
    pub enabled: bool,
    /// Trap destinations.
    #[serde(default)]
    pub destinations: Vec<TrapDestination>,
    /// Community string.
    pub community: String,
    /// Enterprise OID prefix.
    pub enterprise_oid: String,
    /// System name.
    pub system_name: String,
    /// System location.
    pub system_location: String,
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            destinations: Vec::new(),
            community: "public".to_string(),
            enterprise_oid: "1.3.6.1.4.1.99999".to_string(), // Example enterprise OID
            system_name: "sbc".to_string(),
            system_location: "unknown".to_string(),
        }
    }
}

impl SnmpConfig {
    /// Adds a trap destination.
    #[must_use]
    pub fn with_destination(mut self, address: SocketAddr) -> Self {
        self.destinations.push(TrapDestination::new(address));
        self
    }
}

/// Trap destination configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrapDestination {
    /// Destination address.
    pub address: SocketAddr,
    /// Trap types to send to this destination.
    #[serde(default)]
    pub trap_types: Vec<String>,
    /// Whether this destination is enabled.
    pub enabled: bool,
}

impl TrapDestination {
    /// Creates a new trap destination.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            trap_types: Vec::new(),
            enabled: true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SnmpConfig::default();
        assert!(!config.enabled);
        assert!(config.destinations.is_empty());
        assert_eq!(config.community, "public");
    }

    #[test]
    fn test_with_destination() {
        let config = SnmpConfig::default().with_destination("192.168.1.100:162".parse().unwrap());
        assert_eq!(config.destinations.len(), 1);
    }
}
