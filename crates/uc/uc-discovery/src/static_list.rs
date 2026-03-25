//! Static peer list discovery.
//!
//! Provides discovery from a pre-configured list of peer addresses.

use crate::error::DiscoveryResult;
use crate::{DiscoveredPeer, DiscoveryProvider};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use tracing::debug;

/// Static discovery provider.
///
/// Returns peers from a pre-configured list of socket addresses.
#[derive(Debug, Clone)]
pub struct StaticDiscovery {
    /// List of peer addresses.
    peers: Vec<SocketAddr>,
}

impl StaticDiscovery {
    /// Creates a new static discovery provider.
    #[must_use]
    pub fn new(peers: Vec<SocketAddr>) -> Self {
        debug!(
            peer_count = peers.len(),
            "Created static discovery provider"
        );
        Self { peers }
    }

    /// Returns the configured peers.
    #[must_use]
    pub fn peers(&self) -> &[SocketAddr] {
        &self.peers
    }

    /// Adds a peer to the list.
    pub fn add_peer(&mut self, peer: SocketAddr) {
        self.peers.push(peer);
    }

    /// Removes a peer from the list.
    pub fn remove_peer(&mut self, peer: &SocketAddr) -> bool {
        if let Some(pos) = self.peers.iter().position(|p| p == peer) {
            self.peers.remove(pos);
            true
        } else {
            false
        }
    }
}

impl DiscoveryProvider for StaticDiscovery {
    fn discover(
        &self,
    ) -> Pin<Box<dyn Future<Output = DiscoveryResult<Vec<DiscoveredPeer>>> + Send + '_>> {
        Box::pin(async move {
            let peers: Vec<DiscoveredPeer> = self
                .peers
                .iter()
                .enumerate()
                .map(|(idx, addr)| DiscoveredPeer::new(*addr).with_priority(idx as u16))
                .collect();

            debug!(peer_count = peers.len(), "Static discovery returned peers");
            Ok(peers)
        })
    }

    fn method_name(&self) -> &'static str {
        "static"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_discovery() {
        let peers = vec!["[::1]:5070".parse().unwrap(), "[::1]:5071".parse().unwrap()];
        let discovery = StaticDiscovery::new(peers.clone());

        let discovered = discovery.discover().await.unwrap();
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].address, peers[0]);
        assert_eq!(discovered[1].address, peers[1]);
    }

    #[test]
    fn test_add_remove_peer() {
        let mut discovery = StaticDiscovery::new(vec![]);
        let addr: SocketAddr = "[::1]:5070".parse().unwrap();

        discovery.add_peer(addr);
        assert_eq!(discovery.peers().len(), 1);

        assert!(discovery.remove_peer(&addr));
        assert!(discovery.peers().is_empty());

        assert!(!discovery.remove_peer(&addr));
    }

    #[test]
    fn test_method_name() {
        let discovery = StaticDiscovery::new(vec![]);
        assert_eq!(discovery.method_name(), "static");
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let peers = vec![
            "[::1]:5070".parse().unwrap(),
            "[::1]:5071".parse().unwrap(),
            "[::1]:5072".parse().unwrap(),
        ];
        let discovery = StaticDiscovery::new(peers);

        let discovered = discovery.discover().await.unwrap();
        assert_eq!(discovered[0].priority, 0);
        assert_eq!(discovered[1].priority, 1);
        assert_eq!(discovered[2].priority, 2);
    }
}
