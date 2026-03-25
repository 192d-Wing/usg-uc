//! Syslog message forwarder.

use crate::config::{SyslogConfig, SyslogTransport};
use crate::error::SyslogResult;
use crate::formatter::{Severity, SyslogMessage};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Syslog forwarder.
pub struct SyslogForwarder {
    /// Configuration.
    config: SyslogConfig,
    /// UDP socket (if using UDP).
    udp_socket: Option<Arc<UdpSocket>>,
    /// TCP connection (if using TCP).
    tcp_stream: Option<Arc<Mutex<TcpStream>>>,
}

impl SyslogForwarder {
    /// Creates a new syslog forwarder.
    pub async fn new(config: SyslogConfig) -> SyslogResult<Self> {
        if !config.enabled {
            return Ok(Self {
                config,
                udp_socket: None,
                tcp_stream: None,
            });
        }

        match config.transport {
            SyslogTransport::Udp => {
                let socket = UdpSocket::bind("[::]:0").await?;
                info!(server = %config.server, "Syslog UDP forwarder initialized");
                Ok(Self {
                    config,
                    udp_socket: Some(Arc::new(socket)),
                    tcp_stream: None,
                })
            }
            SyslogTransport::Tcp => {
                let stream = TcpStream::connect(config.server).await?;
                info!(server = %config.server, "Syslog TCP forwarder initialized");
                Ok(Self {
                    config,
                    udp_socket: None,
                    tcp_stream: Some(Arc::new(Mutex::new(stream))),
                })
            }
        }
    }

    /// Sends a syslog message.
    pub async fn send(&self, message: &SyslogMessage) -> SyslogResult<()> {
        if !self.config.enabled {
            debug!(severity = %message.severity, "Syslog disabled, not forwarding");
            return Ok(());
        }

        let formatted = if self.config.use_rfc5424 {
            message.to_rfc5424()
        } else {
            message.to_bsd()
        };

        match self.config.transport {
            SyslogTransport::Udp => self.send_udp(&formatted).await,
            SyslogTransport::Tcp => self.send_tcp(&formatted).await,
        }
    }

    /// Sends via UDP.
    async fn send_udp(&self, message: &str) -> SyslogResult<()> {
        if let Some(socket) = &self.udp_socket {
            match socket.send_to(message.as_bytes(), self.config.server).await {
                Ok(bytes) => {
                    debug!(bytes, "Sent syslog message via UDP");
                    Ok(())
                }
                Err(e) => {
                    warn!(error = %e, "Failed to send syslog message via UDP");
                    Err(e.into())
                }
            }
        } else {
            Ok(())
        }
    }

    /// Sends via TCP.
    async fn send_tcp(&self, message: &str) -> SyslogResult<()> {
        if let Some(stream) = &self.tcp_stream {
            let mut stream = stream.lock().await;
            // RFC 6587: Use newline-delimited messages
            let msg_with_newline = format!("{message}\n");
            match stream.write_all(msg_with_newline.as_bytes()).await {
                Ok(()) => {
                    debug!("Sent syslog message via TCP");
                    Ok(())
                }
                Err(e) => {
                    warn!(error = %e, "Failed to send syslog message via TCP");
                    Err(e.into())
                }
            }
        } else {
            Ok(())
        }
    }

    /// Sends an info message.
    pub async fn info(&self, message: impl Into<String>) -> SyslogResult<()> {
        let msg = self.create_message(Severity::Info, message);
        self.send(&msg).await
    }

    /// Sends a warning message.
    pub async fn warning(&self, message: impl Into<String>) -> SyslogResult<()> {
        let msg = self.create_message(Severity::Warning, message);
        self.send(&msg).await
    }

    /// Sends an error message.
    pub async fn error(&self, message: impl Into<String>) -> SyslogResult<()> {
        let msg = self.create_message(Severity::Error, message);
        self.send(&msg).await
    }

    /// Sends a critical message.
    pub async fn critical(&self, message: impl Into<String>) -> SyslogResult<()> {
        let msg = self.create_message(Severity::Critical, message);
        self.send(&msg).await
    }

    /// Creates a message with configuration defaults.
    fn create_message(&self, severity: Severity, message: impl Into<String>) -> SyslogMessage {
        let mut msg = SyslogMessage::new(severity, message).with_app_name(&self.config.app_name);

        if let Some(hostname) = &self.config.hostname {
            msg.hostname = hostname.clone();
        }

        msg
    }
}

impl std::fmt::Debug for SyslogForwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogForwarder")
            .field("config", &self.config)
            .field("udp_socket", &self.udp_socket.is_some())
            .field("tcp_stream", &self.tcp_stream.is_some())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forwarder_disabled() {
        let config = SyslogConfig::default(); // disabled by default
        let forwarder = SyslogForwarder::new(config).await.unwrap();

        // Should succeed even when disabled
        let result = forwarder.info("Test message").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_message() {
        let config = SyslogConfig {
            app_name: "test-app".to_string(),
            hostname: Some("test-host".to_string()),
            ..Default::default()
        };
        let forwarder = SyslogForwarder::new(config).await.unwrap();

        let msg = forwarder.create_message(Severity::Info, "Test");
        assert_eq!(msg.app_name, "test-app");
        assert_eq!(msg.hostname, "test-host");
    }
}
