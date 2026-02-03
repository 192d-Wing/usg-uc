//! TURN allocation management.

use crate::error::{TurnError, TurnResult};
use crate::{DEFAULT_LIFETIME, MAX_CHANNEL_NUMBER, MAX_LIFETIME, MIN_CHANNEL_NUMBER};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// TURN allocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationState {
    /// Allocation is active.
    Active,
    /// Allocation is expired.
    Expired,
}

/// Represents a TURN allocation.
///
/// An allocation binds a client's 5-tuple to a relayed transport address
/// on the TURN server.
#[derive(Debug)]
pub struct Allocation {
    /// Relayed transport address.
    relayed_addr: SocketAddr,
    /// Client 5-tuple (simplified to client address for now).
    client_addr: SocketAddr,
    /// Username for authentication.
    username: String,
    /// Realm for authentication.
    realm: String,
    /// Allocation lifetime in seconds.
    lifetime: u32,
    /// When the allocation was created.
    created_at: Instant,
    /// When the allocation was last refreshed.
    refreshed_at: Instant,
    /// Permissions (peer addresses).
    permissions: HashMap<SocketAddr, Permission>,
    /// Channel bindings.
    channel_bindings: HashMap<u16, ChannelBinding>,
    /// Reverse lookup: peer address -> channel number.
    peer_to_channel: HashMap<SocketAddr, u16>,
    /// State.
    state: AllocationState,
}

impl Allocation {
    /// Creates a new allocation.
    pub fn new(
        relayed_addr: SocketAddr,
        client_addr: SocketAddr,
        username: String,
        realm: String,
        lifetime: Option<u32>,
    ) -> Self {
        let now = Instant::now();
        let lifetime = lifetime.unwrap_or(DEFAULT_LIFETIME).min(MAX_LIFETIME);

        Self {
            relayed_addr,
            client_addr,
            username,
            realm,
            lifetime,
            created_at: now,
            refreshed_at: now,
            permissions: HashMap::new(),
            channel_bindings: HashMap::new(),
            peer_to_channel: HashMap::new(),
            state: AllocationState::Active,
        }
    }

    /// Returns the relayed transport address.
    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed_addr
    }

    /// Returns the client address.
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Returns the username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Returns the current lifetime in seconds.
    pub fn lifetime(&self) -> u32 {
        self.lifetime
    }

    /// Returns when the allocation was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns the remaining lifetime in seconds.
    pub fn remaining_lifetime(&self) -> u32 {
        let elapsed = self.refreshed_at.elapsed();
        let elapsed_secs = elapsed.as_secs() as u32;
        self.lifetime.saturating_sub(elapsed_secs)
    }

    /// Returns the allocation state.
    pub fn state(&self) -> AllocationState {
        if self.remaining_lifetime() == 0 {
            AllocationState::Expired
        } else {
            self.state
        }
    }

    /// Refreshes the allocation with a new lifetime.
    pub fn refresh(&mut self, lifetime: Option<u32>) -> TurnResult<u32> {
        if self.state() == AllocationState::Expired {
            return Err(TurnError::AllocationExpired);
        }

        let new_lifetime = lifetime.unwrap_or(DEFAULT_LIFETIME).min(MAX_LIFETIME);

        if new_lifetime == 0 {
            // Delete allocation
            self.state = AllocationState::Expired;
            return Ok(0);
        }

        self.lifetime = new_lifetime;
        self.refreshed_at = Instant::now();
        Ok(new_lifetime)
    }

    /// Adds or refreshes a permission for a peer address.
    pub fn add_permission(&mut self, peer_addr: SocketAddr) -> TurnResult<()> {
        if self.state() == AllocationState::Expired {
            return Err(TurnError::AllocationExpired);
        }

        // Permission is for IP only, not port
        let peer_ip = SocketAddr::new(peer_addr.ip(), 0);

        self.permissions
            .entry(peer_ip)
            .and_modify(|p| p.refresh())
            .or_insert_with(Permission::new);

        Ok(())
    }

    /// Checks if a permission exists for the peer.
    pub fn has_permission(&self, peer_addr: &SocketAddr) -> bool {
        let peer_ip = SocketAddr::new(peer_addr.ip(), 0);

        self.permissions
            .get(&peer_ip)
            .map(|p| !p.is_expired())
            .unwrap_or(false)
    }

    /// Binds a channel to a peer address.
    pub fn bind_channel(&mut self, channel: u16, peer_addr: SocketAddr) -> TurnResult<()> {
        if self.state() == AllocationState::Expired {
            return Err(TurnError::AllocationExpired);
        }

        // Validate channel number
        if channel < MIN_CHANNEL_NUMBER || channel > MAX_CHANNEL_NUMBER {
            return Err(TurnError::InvalidChannel { channel });
        }

        // Check if channel is already bound to a different peer
        if let Some(existing) = self.channel_bindings.get(&channel) {
            if existing.peer_addr != peer_addr {
                return Err(TurnError::ChannelBindFailed {
                    reason: "channel already bound to different peer".to_string(),
                });
            }
            // Refresh existing binding
            self.channel_bindings
                .get_mut(&channel)
                .map(|b| b.refresh());
        } else {
            // Check if peer already has a different channel
            if let Some(&existing_channel) = self.peer_to_channel.get(&peer_addr) {
                if existing_channel != channel {
                    return Err(TurnError::ChannelBindFailed {
                        reason: "peer already bound to different channel".to_string(),
                    });
                }
            }

            // Create new binding
            self.channel_bindings
                .insert(channel, ChannelBinding::new(peer_addr));
            self.peer_to_channel.insert(peer_addr, channel);
        }

        Ok(())
    }

    /// Gets the peer address for a channel number.
    pub fn get_peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        self.channel_bindings
            .get(&channel)
            .filter(|b| !b.is_expired())
            .map(|b| b.peer_addr)
    }

    /// Gets the channel number for a peer address.
    pub fn get_channel_for_peer(&self, peer_addr: &SocketAddr) -> Option<u16> {
        self.peer_to_channel.get(peer_addr).copied().filter(|&ch| {
            self.channel_bindings
                .get(&ch)
                .map(|b| !b.is_expired())
                .unwrap_or(false)
        })
    }

    /// Returns the set of active channel numbers.
    pub fn active_channels(&self) -> HashSet<u16> {
        self.channel_bindings
            .iter()
            .filter(|(_, b)| !b.is_expired())
            .map(|(&ch, _)| ch)
            .collect()
    }

    /// Cleans up expired permissions and bindings.
    pub fn cleanup_expired(&mut self) {
        self.permissions.retain(|_, p| !p.is_expired());

        let expired_channels: Vec<u16> = self
            .channel_bindings
            .iter()
            .filter(|(_, b)| b.is_expired())
            .map(|(&ch, _)| ch)
            .collect();

        for ch in expired_channels {
            if let Some(binding) = self.channel_bindings.remove(&ch) {
                self.peer_to_channel.remove(&binding.peer_addr);
            }
        }
    }
}

/// Permission for a peer IP address.
#[derive(Debug)]
struct Permission {
    /// When the permission was created/refreshed.
    created_at: Instant,
}

impl Permission {
    /// Permission lifetime (5 minutes per RFC 5766).
    const LIFETIME: Duration = Duration::from_secs(300);

    fn new() -> Self {
        Self {
            created_at: Instant::now(),
        }
    }

    fn refresh(&mut self) {
        self.created_at = Instant::now();
    }

    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Self::LIFETIME
    }
}

/// Channel binding to a peer address.
#[derive(Debug)]
struct ChannelBinding {
    /// Peer address.
    peer_addr: SocketAddr,
    /// When the binding was created/refreshed.
    created_at: Instant,
}

impl ChannelBinding {
    /// Channel binding lifetime (10 minutes per RFC 5766).
    const LIFETIME: Duration = Duration::from_secs(600);

    fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            created_at: Instant::now(),
        }
    }

    fn refresh(&mut self) {
        self.created_at = Instant::now();
    }

    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Self::LIFETIME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_allocation() -> Allocation {
        let relayed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 49152);
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);

        Allocation::new(relayed, client, "alice".to_string(), "example.com".to_string(), None)
    }

    #[test]
    fn test_allocation_creation() {
        let alloc = test_allocation();
        assert_eq!(alloc.state(), AllocationState::Active);
        assert_eq!(alloc.lifetime(), DEFAULT_LIFETIME);
        assert!(alloc.remaining_lifetime() <= DEFAULT_LIFETIME);
    }

    #[test]
    fn test_allocation_refresh() {
        let mut alloc = test_allocation();
        let new_lifetime = alloc.refresh(Some(1200)).unwrap();
        assert_eq!(new_lifetime, MAX_LIFETIME.min(1200));
    }

    #[test]
    fn test_permission() {
        let mut alloc = test_allocation();
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060);

        assert!(!alloc.has_permission(&peer));

        alloc.add_permission(peer).unwrap();
        assert!(alloc.has_permission(&peer));

        // Different port, same IP should have permission
        let peer_diff_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 6000);
        assert!(alloc.has_permission(&peer_diff_port));
    }

    #[test]
    fn test_channel_binding() {
        let mut alloc = test_allocation();
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060);

        // Bind channel
        alloc.bind_channel(0x4000, peer).unwrap();

        assert_eq!(alloc.get_peer_for_channel(0x4000), Some(peer));
        assert_eq!(alloc.get_channel_for_peer(&peer), Some(0x4000));
    }

    #[test]
    fn test_invalid_channel_number() {
        let mut alloc = test_allocation();
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060);

        // Too low
        assert!(alloc.bind_channel(0x3FFF, peer).is_err());
        // Too high
        assert!(alloc.bind_channel(0x7FFF, peer).is_err());
    }

    #[test]
    fn test_channel_conflict() {
        let mut alloc = test_allocation();
        let peer1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060);
        let peer2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5060);

        alloc.bind_channel(0x4000, peer1).unwrap();

        // Same channel, different peer should fail
        assert!(alloc.bind_channel(0x4000, peer2).is_err());

        // Same peer, different channel should fail
        assert!(alloc.bind_channel(0x4001, peer1).is_err());
    }
}
