//! SNMP trap types and sender.

use crate::config::SnmpConfig;
use crate::error::SnmpResult;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// SNMP trap types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapType {
    /// Cold start.
    ColdStart,
    /// Warm start.
    WarmStart,
    /// Link down.
    LinkDown,
    /// Link up.
    LinkUp,
    /// Authentication failure.
    AuthenticationFailure,
    /// Node down.
    NodeDown,
    /// Node up.
    NodeUp,
    /// Call started.
    CallStarted,
    /// Call ended.
    CallEnded,
    /// Registration failed.
    RegistrationFailed,
    /// High CPU usage.
    HighCpu,
    /// High memory usage.
    HighMemory,
    /// Failover occurred.
    Failover,
    /// Custom trap.
    Custom,
}

impl std::fmt::Display for TrapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ColdStart => write!(f, "coldStart"),
            Self::WarmStart => write!(f, "warmStart"),
            Self::LinkDown => write!(f, "linkDown"),
            Self::LinkUp => write!(f, "linkUp"),
            Self::AuthenticationFailure => write!(f, "authenticationFailure"),
            Self::NodeDown => write!(f, "nodeDown"),
            Self::NodeUp => write!(f, "nodeUp"),
            Self::CallStarted => write!(f, "callStarted"),
            Self::CallEnded => write!(f, "callEnded"),
            Self::RegistrationFailed => write!(f, "registrationFailed"),
            Self::HighCpu => write!(f, "highCpu"),
            Self::HighMemory => write!(f, "highMemory"),
            Self::Failover => write!(f, "failover"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// SNMP trap message.
#[derive(Debug, Clone)]
pub struct SnmpTrap {
    /// Trap type.
    pub trap_type: TrapType,
    /// Timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Additional variables.
    pub variables: Vec<TrapVariable>,
    /// Optional message.
    pub message: Option<String>,
}

impl SnmpTrap {
    /// Creates a new trap.
    #[must_use]
    pub fn new(trap_type: TrapType) -> Self {
        Self {
            trap_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            variables: Vec::new(),
            message: None,
        }
    }

    /// Adds a variable.
    #[must_use]
    pub fn with_variable(mut self, oid: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.push(TrapVariable {
            oid: oid.into(),
            value: value.into(),
        });
        self
    }

    /// Sets the message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

/// Trap variable binding.
#[derive(Debug, Clone)]
pub struct TrapVariable {
    /// OID.
    pub oid: String,
    /// Value.
    pub value: String,
}

/// SNMP trap sender.
pub struct TrapSender {
    /// Configuration.
    config: SnmpConfig,
    /// UDP socket.
    socket: Option<Arc<UdpSocket>>,
}

impl TrapSender {
    /// Creates a new trap sender.
    pub async fn new(config: SnmpConfig) -> SnmpResult<Self> {
        let socket = if config.enabled && !config.destinations.is_empty() {
            let socket = UdpSocket::bind("[::]:0").await?;
            info!("SNMP trap sender initialized");
            Some(Arc::new(socket))
        } else {
            None
        };

        Ok(Self { config, socket })
    }

    /// Sends a trap to all configured destinations.
    pub async fn send(&self, trap: &SnmpTrap) -> SnmpResult<()> {
        let Some(socket) = &self.socket else {
            debug!(trap_type = %trap.trap_type, "SNMP disabled, not sending trap");
            return Ok(());
        };

        // Build a simple trap packet (simplified SNMPv2c-like format)
        let packet = self.build_packet(trap)?;

        for dest in &self.config.destinations {
            if !dest.enabled {
                continue;
            }

            match socket.send_to(&packet, dest.address).await {
                Ok(bytes) => {
                    debug!(
                        trap_type = %trap.trap_type,
                        destination = %dest.address,
                        bytes,
                        "Sent SNMP trap"
                    );
                }
                Err(e) => {
                    warn!(
                        trap_type = %trap.trap_type,
                        destination = %dest.address,
                        error = %e,
                        "Failed to send SNMP trap"
                    );
                }
            }
        }

        Ok(())
    }

    /// Builds a trap packet.
    ///
    /// Note: This is a simplified implementation. A full implementation
    /// would use proper ASN.1 BER encoding per RFC 3416.
    fn build_packet(&self, trap: &SnmpTrap) -> SnmpResult<Vec<u8>> {
        // Simplified packet format for demonstration
        // Real implementation would use proper SNMPv2c PDU encoding
        let mut packet = Vec::new();

        // Version (SNMPv2c = 1)
        packet.push(0x30); // SEQUENCE
        packet.push(0x00); // Placeholder for length

        // Community string
        let community = self.config.community.as_bytes();
        packet.push(0x04); // OCTET STRING
        packet.push(community.len() as u8);
        packet.extend_from_slice(community);

        // Trap type indicator (simplified)
        packet.push(0x04);
        let trap_name = trap.trap_type.to_string();
        packet.push(trap_name.len() as u8);
        packet.extend_from_slice(trap_name.as_bytes());

        // Message if present
        if let Some(msg) = &trap.message {
            packet.push(0x04);
            let msg_bytes = msg.as_bytes();
            packet.push(msg_bytes.len().min(255) as u8);
            packet.extend_from_slice(&msg_bytes[..msg_bytes.len().min(255)]);
        }

        // Update length
        let len = packet.len() - 2;
        packet[1] = len as u8;

        Ok(packet)
    }

    /// Sends a cold start trap.
    pub async fn send_cold_start(&self) -> SnmpResult<()> {
        self.send(&SnmpTrap::new(TrapType::ColdStart)).await
    }

    /// Sends a node down trap.
    pub async fn send_node_down(&self, node_id: &str) -> SnmpResult<()> {
        self.send(
            &SnmpTrap::new(TrapType::NodeDown)
                .with_variable("nodeId", node_id)
                .with_message(format!("Node {node_id} is down")),
        )
        .await
    }

    /// Sends a failover trap.
    pub async fn send_failover(&self, from_node: &str, to_node: &str) -> SnmpResult<()> {
        self.send(
            &SnmpTrap::new(TrapType::Failover)
                .with_variable("fromNode", from_node)
                .with_variable("toNode", to_node)
                .with_message(format!("Failover from {from_node} to {to_node}")),
        )
        .await
    }
}

impl std::fmt::Debug for TrapSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrapSender")
            .field("config", &self.config)
            .field("socket", &self.socket.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trap_type_display() {
        assert_eq!(format!("{}", TrapType::ColdStart), "coldStart");
        assert_eq!(format!("{}", TrapType::NodeDown), "nodeDown");
    }

    #[test]
    fn test_trap_creation() {
        let trap = SnmpTrap::new(TrapType::NodeDown)
            .with_variable("nodeId", "node-01")
            .with_message("Node is down");

        assert_eq!(trap.trap_type, TrapType::NodeDown);
        assert_eq!(trap.variables.len(), 1);
        assert_eq!(trap.message, Some("Node is down".to_string()));
    }

    #[tokio::test]
    async fn test_sender_disabled() {
        let config = SnmpConfig::default(); // disabled by default
        let sender = TrapSender::new(config).await.unwrap();

        // Should succeed even when disabled
        let result = sender.send(&SnmpTrap::new(TrapType::ColdStart)).await;
        assert!(result.is_ok());
    }
}
