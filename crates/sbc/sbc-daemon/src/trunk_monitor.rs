//! SIP OPTIONS trunk health monitor.
//!
//! Periodically sends SIP OPTIONS to configured trunks to track
//! availability and response time. Trunks with `options_ping_enabled`
//! are polled at the configured interval.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (trunk availability monitoring)
//! - **SI-4**: System Monitoring

use proto_sip::builder::{RequestBuilder, generate_branch, generate_call_id};
use proto_sip::uri::SipUri;
use proto_sip::SipMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Health status of a monitored trunk.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrunkHealthStatus {
    /// Trunk ID.
    pub trunk_id: String,
    /// Whether the trunk is currently reachable.
    pub reachable: bool,
    /// Last response time in milliseconds.
    pub last_response_ms: Option<u64>,
    /// Last successful ping timestamp (Unix epoch seconds).
    pub last_success: Option<i64>,
    /// Last failure timestamp (Unix epoch seconds).
    pub last_failure: Option<i64>,
    /// Consecutive successful pings.
    pub consecutive_success: u32,
    /// Consecutive failed pings.
    pub consecutive_failures: u32,
    /// Total pings sent.
    pub total_pings: u64,
    /// Total successful responses.
    pub total_success: u64,
    /// Uptime percentage (0.0 - 100.0).
    pub uptime_pct: f64,
    /// Timestamp when the trunk became reachable (Unix epoch seconds).
    /// Resets on every down→up transition.
    pub in_service_since: Option<i64>,
}

impl TrunkHealthStatus {
    fn new(trunk_id: &str) -> Self {
        Self {
            trunk_id: trunk_id.to_string(),
            reachable: false,
            last_response_ms: None,
            last_success: None,
            last_failure: None,
            consecutive_success: 0,
            consecutive_failures: 0,
            total_pings: 0,
            total_success: 0,
            uptime_pct: 0.0,
            in_service_since: None,
        }
    }

    fn record_success(&mut self, response_ms: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Track down→up transition for service duration timer
        if !self.reachable {
            self.in_service_since = Some(now);
        }
        self.reachable = true;
        self.last_response_ms = Some(response_ms);
        self.last_success = Some(now);
        self.consecutive_success += 1;
        self.consecutive_failures = 0;
        self.total_pings += 1;
        self.total_success += 1;
        self.uptime_pct = (self.total_success as f64 / self.total_pings as f64) * 100.0;
    }

    fn record_failure(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        self.reachable = false;
        self.last_response_ms = None;
        self.last_failure = Some(now);
        self.consecutive_failures += 1;
        self.consecutive_success = 0;
        self.in_service_since = None;
        self.total_pings += 1;
        self.uptime_pct = if self.total_pings > 0 {
            (self.total_success as f64 / self.total_pings as f64) * 100.0
        } else {
            0.0
        };
    }
}

/// Configuration for a trunk to monitor.
#[derive(Debug, Clone)]
pub struct MonitoredTrunk {
    /// Trunk ID.
    pub trunk_id: String,
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Ping interval in seconds.
    pub interval_secs: u32,
    /// Zone signaling IP to bind from (if zones configured).
    pub bind_ip: Option<std::net::IpAddr>,
}

/// Trunk health monitor that sends periodic SIP OPTIONS.
pub struct TrunkMonitor {
    /// Health status for each monitored trunk.
    health: Arc<RwLock<HashMap<String, TrunkHealthStatus>>>,
    /// SBC's local domain for From/Via headers.
    local_domain: String,
}

impl TrunkMonitor {
    /// Creates a new trunk monitor.
    pub fn new(local_domain: &str) -> Self {
        Self {
            health: Arc::new(RwLock::new(HashMap::new())),
            local_domain: local_domain.to_string(),
        }
    }

    /// Returns the shared health status map.
    pub fn health(&self) -> Arc<RwLock<HashMap<String, TrunkHealthStatus>>> {
        Arc::clone(&self.health)
    }

    /// Starts monitoring a trunk. Spawns a background task.
    pub fn monitor_trunk(&self, trunk: MonitoredTrunk) -> tokio::task::JoinHandle<()> {
        let health = Arc::clone(&self.health);
        let domain = self.local_domain.clone();
        let trunk_id = trunk.trunk_id.clone();

        // Initialize health entry
        {
            let health_clone = Arc::clone(&health);
            tokio::spawn(async move {
                health_clone
                    .write()
                    .await
                    .entry(trunk_id.clone())
                    .or_insert_with(|| TrunkHealthStatus::new(&trunk_id));
            });
        }

        let interval = Duration::from_secs(u64::from(trunk.interval_secs.max(5)));

        tokio::spawn(async move {
            info!(
                trunk_id = %trunk.trunk_id,
                host = %trunk.host,
                port = trunk.port,
                interval_secs = trunk.interval_secs,
                "Starting OPTIONS health monitor"
            );

            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick
            ticker.tick().await;

            loop {
                ticker.tick().await;

                let result = Self::send_options_ping(
                    &trunk.trunk_id,
                    &trunk.host,
                    trunk.port,
                    &domain,
                    trunk.bind_ip,
                )
                .await;

                let mut h = health.write().await;
                let status = h
                    .entry(trunk.trunk_id.clone())
                    .or_insert_with(|| TrunkHealthStatus::new(&trunk.trunk_id));

                match result {
                    Ok(response_ms) => {
                        status.record_success(response_ms);
                        debug!(
                            trunk_id = %trunk.trunk_id,
                            response_ms,
                            uptime = format!("{:.1}%", status.uptime_pct),
                            "OPTIONS ping OK"
                        );
                    }
                    Err(reason) => {
                        status.record_failure();
                        warn!(
                            trunk_id = %trunk.trunk_id,
                            reason = %reason,
                            consecutive_failures = status.consecutive_failures,
                            "OPTIONS ping FAILED"
                        );
                    }
                }
            }
        })
    }

    /// Sends a single OPTIONS ping and returns response time in ms.
    async fn send_options_ping(
        trunk_id: &str,
        host: &str,
        port: u16,
        domain: &str,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<u64, String> {
        // Resolve target address
        let addr_str = format!("{host}:{port}");
        let target: SocketAddr = addr_str
            .parse()
            .or_else(|_| {
                use std::net::ToSocketAddrs;
                addr_str
                    .to_socket_addrs()
                    .map_err(|e| e.to_string())?
                    .next()
                    .ok_or_else(|| "DNS resolution failed".to_string())
            })
            .map_err(|e| format!("Cannot resolve {addr_str}: {e}"))?;

        // Bind to zone IP on port 5060 (matching the SIP listener) so the
        // OPTIONS goes out the correct interface and the response comes back.
        let socket = if let Some(ip) = bind_ip {
            let bind_addr = std::net::SocketAddr::new(ip, 5060);
            let sock2 = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            ).map_err(|e| format!("Socket create failed: {e}"))?;
            sock2.set_reuse_address(true).ok();
            #[cfg(target_os = "linux")]
            sock2.set_reuse_port(true).ok();
            sock2.set_nonblocking(true).map_err(|e| format!("Set nonblocking failed: {e}"))?;
            sock2.bind(&bind_addr.into()).map_err(|e| format!("Bind to {bind_addr} failed: {e}"))?;
            UdpSocket::from_std(sock2.into())
                .map_err(|e| format!("Convert to tokio socket failed: {e}"))?
        } else {
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Bind failed: {e}"))?
        };

        // Build OPTIONS request
        let uri = SipUri::new(host).with_port(port);
        let _branch = generate_branch();
        let call_id = generate_call_id(domain);
        let local_addr = socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string());

        let request = RequestBuilder::options(uri)
            .via_auto("UDP", &local_addr.split(':').next().unwrap_or("0.0.0.0"), None)
            .from_auto(SipUri::new(domain).with_user("sbc-monitor"), None)
            .to_uri(SipUri::new(host), None)
            .call_id(&call_id)
            .cseq(1)
            .max_forwards(70)
            .build_with_defaults()
            .map_err(|e| format!("Build OPTIONS failed: {e}"))?;

        let msg_bytes = SipMessage::Request(request).to_bytes();

        // Send and time the response
        let start = Instant::now();

        socket
            .send_to(&msg_bytes, target)
            .await
            .map_err(|e| format!("Send failed: {e}"))?;

        // Wait for response with 5-second timeout
        let mut buf = [0u8; 4096];
        let response = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .map_err(|_| format!("Timeout waiting for response from {trunk_id}"))?
            .map_err(|e| format!("Recv failed: {e}"))?;

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let (n, _from) = response;

        // Check for a valid SIP response
        let resp_str = String::from_utf8_lossy(&buf[..n]);
        if resp_str.starts_with("SIP/2.0 ") {
            let status_line = resp_str.lines().next().unwrap_or("");
            let status_code: u16 = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if (200..300).contains(&status_code) {
                Ok(elapsed_ms)
            } else {
                Err(format!("Trunk responded with {status_code}"))
            }
        } else {
            Err("Invalid SIP response".to_string())
        }
    }

    /// Returns health status for all monitored trunks.
    pub async fn get_all_status(&self) -> Vec<TrunkHealthStatus> {
        self.health.read().await.values().cloned().collect()
    }

    /// Returns health status for a specific trunk.
    pub async fn get_status(&self, trunk_id: &str) -> Option<TrunkHealthStatus> {
        self.health.read().await.get(trunk_id).cloned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_success() {
        let mut status = TrunkHealthStatus::new("test-trunk");
        assert!(!status.reachable);
        assert_eq!(status.total_pings, 0);

        status.record_success(15);
        assert!(status.reachable);
        assert_eq!(status.last_response_ms, Some(15));
        assert_eq!(status.consecutive_success, 1);
        assert_eq!(status.total_pings, 1);
        assert_eq!(status.total_success, 1);
        assert!((status.uptime_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_health_status_failure() {
        let mut status = TrunkHealthStatus::new("test-trunk");
        status.record_success(10);
        status.record_failure();

        assert!(!status.reachable);
        assert_eq!(status.consecutive_failures, 1);
        assert_eq!(status.consecutive_success, 0);
        assert_eq!(status.total_pings, 2);
        assert_eq!(status.total_success, 1);
        assert!((status.uptime_pct - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_health_status_multiple() {
        let mut status = TrunkHealthStatus::new("test-trunk");
        for _ in 0..8 {
            status.record_success(10);
        }
        status.record_failure();
        status.record_failure();

        assert_eq!(status.total_pings, 10);
        assert_eq!(status.total_success, 8);
        assert_eq!(status.consecutive_failures, 2);
        assert!((status.uptime_pct - 80.0).abs() < f64::EPSILON);
    }
}
