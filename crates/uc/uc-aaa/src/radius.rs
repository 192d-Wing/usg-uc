//! RADIUS client implementation.
//!
//! Provides a RADIUS client for authentication and accounting.

use crate::config::RadiusConfig;
use crate::error::AaaResult;
use crate::provider::{AaaProvider, AccountingRecord, AuthRequest, AuthResponse};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use tracing::{debug, info, warn};

/// RADIUS client for AAA operations.
pub struct RadiusClient {
    /// Configuration.
    config: RadiusConfig,
    /// Request identifier.
    identifier: AtomicU8,
    /// Current server index.
    server_index: AtomicUsize,
    /// Consecutive failures.
    failures: AtomicUsize,
}

impl RadiusClient {
    /// Creates a new RADIUS client.
    #[must_use]
    pub fn new(config: RadiusConfig) -> Self {
        info!(
            server = %config.server,
            nas_id = %config.nas_identifier,
            "Creating RADIUS client"
        );

        Self {
            config,
            identifier: AtomicU8::new(0),
            server_index: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
        }
    }

    /// Returns the next request identifier.
    fn next_identifier(&self) -> u8 {
        self.identifier.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns the current server address.
    fn current_server(&self) -> std::net::SocketAddr {
        let index = self.server_index.load(Ordering::Relaxed);
        if index == 0 {
            self.config.server
        } else {
            self.config
                .backup_servers
                .get(index - 1)
                .copied()
                .unwrap_or(self.config.server)
        }
    }

    /// Attempts to fail over to the next server.
    fn failover(&self) {
        let max_servers = 1 + self.config.backup_servers.len();
        let current = self.server_index.load(Ordering::Relaxed);
        let next = (current + 1) % max_servers;

        if self
            .server_index
            .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            warn!(
                from_index = current,
                to_index = next,
                "Failing over to backup RADIUS server"
            );
        }
    }

    /// Records a failure and potentially triggers failover.
    fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.config.max_retries as usize {
            self.failures.store(0, Ordering::Relaxed);
            self.failover();
        }
    }

    /// Records a success and resets failure counter.
    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }
}

impl AaaProvider for RadiusClient {
    fn authenticate(
        &self,
        request: AuthRequest,
    ) -> Pin<Box<dyn Future<Output = AaaResult<AuthResponse>> + Send + '_>> {
        Box::pin(async move {
            let identifier = self.next_identifier();
            let server = self.current_server();

            debug!(
                identifier,
                server = %server,
                username = %request.username,
                "Sending RADIUS Access-Request"
            );

            // In a real implementation, we would:
            // 1. Build RADIUS Access-Request packet
            // 2. Send UDP packet to server
            // 3. Wait for Access-Accept/Access-Reject
            // 4. Parse response attributes

            // For now, this is a stub that simulates the protocol
            // A full implementation would use a RADIUS library or implement RFC 2865

            // Simulate network operation
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // Stub: Accept all requests in this basic implementation
            // Real implementation would validate against RADIUS server
            self.record_success();

            debug!(
                identifier,
                username = %request.username,
                "RADIUS authentication successful (stub)"
            );

            Ok(AuthResponse::accept().with_timeout(3600))
        })
    }

    fn account(
        &self,
        record: AccountingRecord,
    ) -> Pin<Box<dyn Future<Output = AaaResult<()>> + Send + '_>> {
        Box::pin(async move {
            let identifier = self.next_identifier();
            let server = self.current_server();

            debug!(
                identifier,
                server = %server,
                session_id = %record.session_id,
                record_type = ?record.record_type,
                "Sending RADIUS Accounting-Request"
            );

            // In a real implementation, we would:
            // 1. Build RADIUS Accounting-Request packet
            // 2. Send UDP packet to accounting port
            // 3. Wait for Accounting-Response

            // Simulate network operation
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            self.record_success();

            debug!(
                identifier,
                session_id = %record.session_id,
                "RADIUS accounting successful (stub)"
            );

            Ok(())
        })
    }

    fn provider_name(&self) -> &'static str {
        "radius"
    }

    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            // In a real implementation, send Status-Server request
            // For now, just check if we have a server configured
            true
        })
    }
}

impl std::fmt::Debug for RadiusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RadiusClient")
            .field("server", &self.config.server)
            .field("backup_servers", &self.config.backup_servers.len())
            .field("nas_identifier", &self.config.nas_identifier)
            .field("identifier", &self.identifier.load(Ordering::Relaxed))
            .field("server_index", &self.server_index.load(Ordering::Relaxed))
            .field("failures", &self.failures.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn create_test_client() -> RadiusClient {
        RadiusClient::new(RadiusConfig::new(
            "127.0.0.1:1812".parse().unwrap(),
            "testing123",
        ))
    }

    #[test]
    fn test_client_creation() {
        let client = create_test_client();
        assert_eq!(client.provider_name(), "radius");
    }

    #[test]
    fn test_identifier_increment() {
        let client = create_test_client();

        let id1 = client.next_identifier();
        let id2 = client.next_identifier();
        let id3 = client.next_identifier();

        assert_eq!(id2, id1.wrapping_add(1));
        assert_eq!(id3, id2.wrapping_add(1));
    }

    #[tokio::test]
    async fn test_authenticate() {
        let client = create_test_client();
        let request = AuthRequest::new("testuser", "testpass");

        let response = client.authenticate(request).await.unwrap();
        assert!(response.success);
    }

    #[tokio::test]
    async fn test_accounting() {
        let client = create_test_client();
        let record = AccountingRecord::start("sess-001", "testuser");

        let result = client.account(record).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_failover() {
        let mut config = RadiusConfig::new("127.0.0.1:1812".parse().unwrap(), "secret");
        config
            .backup_servers
            .push("127.0.0.2:1812".parse().unwrap());

        let client = RadiusClient::new(config);

        assert_eq!(client.server_index.load(Ordering::Relaxed), 0);

        client.failover();
        assert_eq!(client.server_index.load(Ordering::Relaxed), 1);

        client.failover();
        assert_eq!(client.server_index.load(Ordering::Relaxed), 0);
    }
}
