//! UDP transport implementation.
//!
//! ## IPv6-First Design
//!
//! UDP sockets are configured to prefer IPv6 per project requirements.
//! Dual-stack sockets (IPv6 with IPv4-mapped addresses) are used where supported.
//!
//! ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
//!
//! Note: UDP provides no inherent confidentiality or integrity. For secure
//! signaling, use TLS. For secure media, use DTLS-SRTP.

use crate::error::{TransportError, TransportResult};
use crate::listener::ListenerConfig;
use crate::{MAX_UDP_MESSAGE_SIZE, ReceivedMessage, Transport};
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, instrument, trace, warn};
use uc_types::address::{SbcSocketAddr, TransportType};

/// UDP transport for connectionless SIP messaging.
///
/// ## Usage
///
/// ```ignore
/// use uc_transport::udp::UdpTransport;
/// use uc_types::address::SbcSocketAddr;
///
/// let addr = SbcSocketAddr::new_v6("::".parse().unwrap(), 5060);
/// let transport = UdpTransport::bind(addr).await?;
/// ```
///
/// ## NIST 800-53 Rev5: SC-8
///
/// UDP does not provide transmission security. Use TLS for signaling
/// or DTLS-SRTP for media when confidentiality/integrity is required.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    local_addr: SbcSocketAddr,
    recv_buffer: Mutex<Vec<u8>>,
    closed: AtomicBool,
}

impl UdpTransport {
    /// Binds a UDP socket to the specified address.
    ///
    /// ## IPv6-First
    ///
    /// If binding to an IPv6 address, the socket will be configured as
    /// dual-stack (accepting both IPv6 and IPv4-mapped addresses) unless
    /// `IPV6_V6ONLY` is explicitly set.
    ///
    /// ## Errors
    ///
    /// Returns an error if binding fails.
    #[instrument(skip_all, fields(addr = %addr))]
    pub async fn bind(addr: SbcSocketAddr) -> TransportResult<Self> {
        Self::bind_with_config(ListenerConfig::new(addr, TransportType::Udp)).await
    }

    /// Binds a UDP socket with the given configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error if binding fails.
    #[instrument(skip_all, fields(addr = %config.bind_address))]
    pub async fn bind_with_config(config: ListenerConfig) -> TransportResult<Self> {
        config.validate()?;

        let socket_addr: SocketAddr = config.bind_address.into();
        let domain = if socket_addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        // Use socket2 for advanced socket options
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
            TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            }
        })?;

        // Configure socket options
        if config.reuse_address {
            socket
                .set_reuse_address(true)
                .map_err(|e| TransportError::BindFailed {
                    address: config.bind_address,
                    reason: format!("failed to set SO_REUSEADDR: {e}"),
                })?;
        }

        #[cfg(unix)]
        if config.reuse_port {
            socket
                .set_reuse_port(true)
                .map_err(|e| TransportError::BindFailed {
                    address: config.bind_address,
                    reason: format!("failed to set SO_REUSEPORT: {e}"),
                })?;
        }

        // For IPv6, enable dual-stack mode (accept IPv4-mapped addresses)
        if socket_addr.is_ipv6() {
            socket
                .set_only_v6(false)
                .map_err(|e| TransportError::BindFailed {
                    address: config.bind_address,
                    reason: format!("failed to set IPV6_V6ONLY: {e}"),
                })?;
        }

        // Set non-blocking before binding
        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to set non-blocking: {e}"),
            })?;

        // Bind the socket
        socket
            .bind(&socket_addr.into())
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            })?;

        // Convert to tokio UdpSocket
        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket =
            UdpSocket::from_std(std_socket).map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            })?;

        // Get the actual bound address (in case port was 0)
        let local_addr = tokio_socket
            .local_addr()
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to get local address: {e}"),
            })?;

        debug!(local_addr = %local_addr, "UDP transport bound");

        Ok(Self {
            socket: Arc::new(tokio_socket),
            local_addr: local_addr.into(),
            recv_buffer: Mutex::new(vec![0u8; MAX_UDP_MESSAGE_SIZE]),
            closed: AtomicBool::new(false),
        })
    }

    /// Checks if the transport is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Transport for UdpTransport {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
        dest: &'a SbcSocketAddr,
    ) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(TransportError::AlreadyClosed);
            }

            if data.len() > MAX_UDP_MESSAGE_SIZE {
                warn!(
                    size = data.len(),
                    max = MAX_UDP_MESSAGE_SIZE,
                    "UDP message exceeds MTU-safe size"
                );
                return Err(TransportError::MessageTooLarge {
                    size: data.len(),
                    max_size: MAX_UDP_MESSAGE_SIZE,
                });
            }

            let dest_addr: SocketAddr = (*dest).into();
            trace!(dest = %dest_addr, size = data.len(), "sending UDP packet");

            self.socket
                .send_to(data, dest_addr)
                .await
                .map_err(|e| TransportError::SendFailed {
                    address: *dest,
                    reason: e.to_string(),
                })?;

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(TransportError::AlreadyClosed);
            }

            let mut buffer = self.recv_buffer.lock().await;

            let (len, source) = self.socket.recv_from(&mut buffer).await.map_err(|e| {
                TransportError::ReceiveFailed {
                    reason: e.to_string(),
                }
            })?;

            trace!(source = %source, size = len, "received UDP packet");

            Ok(ReceivedMessage {
                data: Bytes::copy_from_slice(&buffer[..len]),
                source: source.into(),
                transport: TransportType::Udp,
            })
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Udp
    }

    fn close(&self) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + '_>> {
        Box::pin(async move {
            if self
                .closed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(TransportError::AlreadyClosed);
            }

            debug!(local_addr = %self.local_addr, "UDP transport closed");
            Ok(())
        })
    }
}

impl std::fmt::Debug for UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpTransport")
            .field("local_addr", &self.local_addr)
            .field("closed", &self.is_closed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[tokio::test]
    async fn test_bind_ipv6() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        assert!(!transport.is_closed());
        assert_eq!(transport.transport_type(), TransportType::Udp);
        assert!(!transport.is_secure());
    }

    #[tokio::test]
    async fn test_bind_ipv4() {
        let addr = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        assert!(!transport.is_closed());
        assert_eq!(transport.transport_type(), TransportType::Udp);
    }

    #[tokio::test]
    async fn test_send_recv() {
        // Create two UDP transports
        let addr1 = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let addr2 = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);

        let transport1 = UdpTransport::bind(addr1).await.unwrap();
        let transport2 = UdpTransport::bind(addr2).await.unwrap();

        let dest = *transport2.local_addr();
        let test_data = b"Hello, SIP!";

        // Send from transport1 to transport2
        transport1.send(test_data, &dest).await.unwrap();

        // Receive on transport2
        let msg = transport2.recv().await.unwrap();

        assert_eq!(&msg.data[..], test_data);
        assert_eq!(msg.transport, TransportType::Udp);
    }

    #[tokio::test]
    async fn test_message_too_large() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        let large_data = vec![0u8; MAX_UDP_MESSAGE_SIZE + 1];
        let dest = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5060);

        let result = transport.send(&large_data, &dest).await;
        assert!(matches!(
            result,
            Err(TransportError::MessageTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn test_close() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        assert!(!transport.is_closed());
        transport.close().await.unwrap();
        assert!(transport.is_closed());

        // Second close should fail
        let result = transport.close().await;
        assert!(matches!(result, Err(TransportError::AlreadyClosed)));
    }

    #[tokio::test]
    async fn test_send_after_close() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 0);
        let transport = UdpTransport::bind(addr).await.unwrap();

        transport.close().await.unwrap();

        let dest = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5060);
        let result = transport.send(b"test", &dest).await;
        assert!(matches!(result, Err(TransportError::AlreadyClosed)));
    }
}
