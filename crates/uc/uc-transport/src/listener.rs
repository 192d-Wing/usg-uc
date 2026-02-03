//! Transport listener abstraction.
//!
//! ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)

use crate::error::{TransportError, TransportResult};
use std::future::Future;
use std::pin::Pin;
use uc_types::address::{SbcSocketAddr, TransportType};

/// Type alias for the accept future return type.
pub type AcceptFuture<'a, C> =
    Pin<Box<dyn Future<Output = TransportResult<(C, SbcSocketAddr)>> + Send + 'a>>;

/// Listener for accepting incoming transport connections.
///
/// This trait abstracts over different transport listeners (TCP, TLS, WebSocket).
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
pub trait TransportListener: Send + Sync {
    /// The connection type this listener produces.
    type Connection: Send;

    /// Accepts the next incoming connection.
    ///
    /// ## Errors
    ///
    /// Returns an error if the accept operation fails.
    fn accept(&self) -> AcceptFuture<'_, Self::Connection>;

    /// Returns the local address this listener is bound to.
    fn local_addr(&self) -> &SbcSocketAddr;

    /// Returns the transport type.
    fn transport_type(&self) -> TransportType;

    /// Closes the listener.
    fn close(&self) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + '_>>;
}

/// Configuration for creating listeners.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Address to bind to.
    pub bind_address: SbcSocketAddr,
    /// Transport type.
    pub transport_type: TransportType,
    /// Maximum pending connections (backlog).
    pub backlog: u32,
    /// Enable `SO_REUSEADDR`.
    pub reuse_address: bool,
    /// Enable `SO_REUSEPORT`.
    pub reuse_port: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind_address: SbcSocketAddr::new_v6(std::net::Ipv6Addr::UNSPECIFIED, 5060),
            transport_type: TransportType::Udp,
            backlog: 128,
            reuse_address: true,
            reuse_port: false,
        }
    }
}

impl ListenerConfig {
    /// Creates a new listener config for the given address and transport.
    #[must_use]
    pub fn new(bind_address: SbcSocketAddr, transport_type: TransportType) -> Self {
        Self {
            bind_address,
            transport_type,
            ..Default::default()
        }
    }

    /// Sets the backlog (maximum pending connections).
    #[must_use]
    pub const fn with_backlog(mut self, backlog: u32) -> Self {
        self.backlog = backlog;
        self
    }

    /// Enables or disables `SO_REUSEADDR`.
    #[must_use]
    pub const fn with_reuse_address(mut self, reuse: bool) -> Self {
        self.reuse_address = reuse;
        self
    }

    /// Enables or disables `SO_REUSEPORT`.
    #[must_use]
    pub const fn with_reuse_port(mut self, reuse: bool) -> Self {
        self.reuse_port = reuse;
        self
    }

    /// Validates the configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate(&self) -> TransportResult<()> {
        if self.backlog == 0 {
            return Err(TransportError::InvalidAddress {
                reason: "backlog must be greater than 0".to_string(),
            });
        }
        Ok(())
    }
}
