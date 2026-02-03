//! DNS-based service discovery (requires `dns` feature).
//!
//! This module is only available when the `dns` feature is enabled.

#![cfg(feature = "dns")]

use crate::config::{DiscoveryMethod, DnsConfig};
use crate::error::{DiscoveryError, DiscoveryResult};
use crate::{DiscoveredPeer, DiscoveryProvider};
use std::future::Future;
use std::pin::Pin;

/// DNS-based discovery provider.
pub struct DnsDiscovery {
    _config: DnsConfig,
    _method: DiscoveryMethod,
}

impl DnsDiscovery {
    /// Creates a new DNS discovery provider.
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid.
    pub fn new(config: DnsConfig, method: DiscoveryMethod) -> DiscoveryResult<Self> {
        Ok(Self {
            _config: config,
            _method: method,
        })
    }
}

impl DiscoveryProvider for DnsDiscovery {
    fn discover(
        &self,
    ) -> Pin<Box<dyn Future<Output = DiscoveryResult<Vec<DiscoveredPeer>>> + Send + '_>> {
        Box::pin(async move {
            // TODO: Implement DNS SRV/A record lookup
            Err(DiscoveryError::ConfigError {
                reason: "DNS discovery not yet implemented".to_string(),
            })
        })
    }

    fn method_name(&self) -> &'static str {
        "dns"
    }
}
