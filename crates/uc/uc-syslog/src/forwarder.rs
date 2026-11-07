//! Syslog message forwarder.
//!
//! UDP (RFC 5426) and plain TCP (RFC 6587) give no protection in transit.
//! TLS (RFC 5425) authenticates the collector and protects records in
//! transit with the CNSA 2.0 provider from `uc-transport`.

use crate::config::{SYSLOG_TLS_PORT, SyslogConfig, SyslogTlsConfig, SyslogTransport};
use crate::error::{SyslogError, SyslogResult};
use crate::formatter::{Severity, SyslogMessage};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::{debug, info, warn};
use uc_transport::tls::{
    MinTlsVersion, TlsClientOptions, create_client_config_with, load_certs, load_private_key,
    load_root_store,
};

/// Upper bound on TCP connect plus TLS handshake.
const TLS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on sending close_notify / shutting down in `close()`.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// RFC 5425 TLS session to the collector.
struct TlsSink {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    server: SocketAddr,
    /// `None` after a failed write until the next reconnect.
    stream: Mutex<Option<TlsStream<TcpStream>>>,
}

impl TlsSink {
    /// Builds the CNSA 2.0 client config and connects.
    ///
    /// RFC 5425 §5.1/§5.2: the collector MUST be authenticated; the chain is
    /// verified against `ca_file` and the name against `server_name`.
    /// NIST 800-53 Rev5: SC-8, SC-13, IA-3, AU-9
    async fn connect(server: SocketAddr, tls: &SyslogTlsConfig) -> SyslogResult<Self> {
        let cfg_err = |reason: String| SyslogError::ConfigError { reason };
        let roots = load_root_store(&tls.ca_file)
            .map_err(|e| cfg_err(format!("syslog tls ca_file: {e}")))?;
        let client_auth = match (&tls.client_cert, &tls.client_key) {
            (Some(cert), Some(key)) => Some((
                load_certs(cert).map_err(|e| cfg_err(format!("syslog tls client_cert: {e}")))?,
                load_private_key(key)
                    .map_err(|e| cfg_err(format!("syslog tls client_key: {e}")))?,
            )),
            (None, None) => None,
            _ => {
                return Err(cfg_err(
                    "syslog tls client_cert and client_key must be set together".to_string(),
                ));
            }
        };
        let client_config = create_client_config_with(TlsClientOptions {
            roots,
            min_version: if tls.allow_tls12 {
                MinTlsVersion::V1_2
            } else {
                MinTlsVersion::V1_3
            },
            client_auth,
        })
        .map_err(|e| cfg_err(format!("syslog tls: {e}")))?;
        let server_name = ServerName::try_from(tls.server_name.clone())
            .map_err(|e| cfg_err(format!("syslog tls server_name: {e}")))?;
        let sink = Self {
            connector: TlsConnector::from(Arc::new(client_config)),
            server_name,
            server,
            stream: Mutex::new(None),
        };
        let stream = sink.handshake().await?;
        *sink.stream.lock().await = Some(stream);
        Ok(sink)
    }

    /// TCP connect plus TLS handshake, bounded by [`TLS_CONNECT_TIMEOUT`].
    async fn handshake(&self) -> SyslogResult<TlsStream<TcpStream>> {
        let fail = |reason: String| SyslogError::ConnectionFailed {
            address: self.server,
            reason,
        };
        let fut = async {
            let tcp = TcpStream::connect(self.server)
                .await
                .map_err(|e| fail(e.to_string()))?;
            self.connector
                .connect(self.server_name.clone(), tcp)
                .await
                .map_err(|e| fail(format!("TLS handshake: {e}")))
        };
        tokio::time::timeout(TLS_CONNECT_TIMEOUT, fut)
            .await
            .map_err(|_| fail("TLS connect timed out".to_string()))?
    }

    /// Writes one frame; on failure reconnects once and retries.
    ///
    /// Delivery is at-least-once (RFC 5425 §4 does not require
    /// exactly-once): if the failed write reached the collector in whole or
    /// in part, the frame is sent again on the new session. A partial frame
    /// is harmless because framing restarts with the new TLS session.
    ///
    /// The lock is held across the reconnect (up to
    /// [`TLS_CONNECT_TIMEOUT`]), so while the collector is down concurrent
    /// callers queue behind it.
    /// POAM: POA&M-245 when wired into sbc-daemon, signaling and media must
    /// reach the forwarder through a bounded, drop-counting channel, and
    /// reconnects need a backoff (PERF-2).
    async fn send(&self, frame: &[u8]) -> SyslogResult<()> {
        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.as_mut() {
            match write_frame(stream, frame).await {
                Ok(()) => return Ok(()),
                Err(e) => warn!(error = %e, "Syslog TLS write failed, reconnecting"),
            }
        }
        *guard = None;
        // The lock is held across the bounded reconnect so frames are not
        // interleaved or reordered.
        let mut stream = self.handshake().await?;
        write_frame(&mut stream, frame).await?;
        *guard = Some(stream);
        drop(guard);
        Ok(())
    }
}

impl TlsSink {
    /// Sends TLS close_notify and closes the session.
    ///
    /// RFC 5425 §4.4: the sender MUST send close_notify before closing the
    /// connection so the collector can tell a clean close from truncation.
    async fn close(&self) -> SyslogResult<()> {
        let stream = self.stream.lock().await.take();
        if let Some(mut stream) = stream {
            // rustls emits close_notify on shutdown.
            stream.shutdown().await?;
        }
        Ok(())
    }
}

/// Writes and flushes one frame.
async fn write_frame(stream: &mut TlsStream<TcpStream>, frame: &[u8]) -> std::io::Result<()> {
    stream.write_all(frame).await?;
    stream.flush().await
}

/// RFC 5425 §4.3 / RFC 6587 §3.4.1 octet-counting frame:
/// `MSG-LEN SP SYSLOG-MSG`, where MSG-LEN is the byte length.
#[must_use]
pub fn octet_counted_frame(message: &str) -> Vec<u8> {
    let mut frame = format!("{} ", message.len()).into_bytes();
    frame.extend_from_slice(message.as_bytes());
    frame
}

/// Syslog forwarder.
pub struct SyslogForwarder {
    /// Configuration.
    config: SyslogConfig,
    /// UDP socket (if using UDP).
    udp_socket: Option<Arc<UdpSocket>>,
    /// TCP connection (if using TCP).
    tcp_stream: Option<Arc<Mutex<TcpStream>>>,
    /// TLS session (if using TLS).
    tls: Option<TlsSink>,
}

impl SyslogForwarder {
    /// Creates a new syslog forwarder.
    ///
    /// # Errors
    /// Fails closed when `transport = tls` has no `tls` block, when a `tls`
    /// block is given for another transport, or when the TLS handshake
    /// (including collector certificate verification) fails.
    pub async fn new(config: SyslogConfig) -> SyslogResult<Self> {
        if !config.enabled {
            return Ok(Self {
                config,
                udp_socket: None,
                tcp_stream: None,
                tls: None,
            });
        }

        // RFC 5425 §4.1/§4.3: SYSLOG-MSG over TLS is an RFC 5424 message;
        // a BSD (RFC 3164) frame would be misparsed by the collector.
        if config.transport == SyslogTransport::Tls && !config.use_rfc5424 {
            return Err(SyslogError::ConfigError {
                reason: "syslog transport tls requires use_rfc5424 = true".to_string(),
            });
        }

        if config.tls.is_some() && config.transport != SyslogTransport::Tls {
            return Err(SyslogError::ConfigError {
                reason: format!(
                    "syslog tls settings are set but transport is {}",
                    config.transport
                ),
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
                    tls: None,
                })
            }
            SyslogTransport::Tcp => {
                let stream = TcpStream::connect(config.server).await?;
                info!(server = %config.server, "Syslog TCP forwarder initialized");
                Ok(Self {
                    config,
                    udp_socket: None,
                    tcp_stream: Some(Arc::new(Mutex::new(stream))),
                    tls: None,
                })
            }
            SyslogTransport::Tls => {
                let tls_cfg = config
                    .tls
                    .as_ref()
                    .ok_or_else(|| SyslogError::ConfigError {
                        reason: "syslog transport tls requires a tls section".to_string(),
                    })?;
                if config.server.port() != SYSLOG_TLS_PORT {
                    warn!(
                        port = config.server.port(),
                        "Syslog TLS collector is not on the RFC 5425 port 6514"
                    );
                }
                let sink = TlsSink::connect(config.server, tls_cfg).await?;
                info!(server = %config.server, "Syslog TLS forwarder initialized");
                Ok(Self {
                    config,
                    udp_socket: None,
                    tcp_stream: None,
                    tls: Some(sink),
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
            SyslogTransport::Tls => self.send_tls(&formatted).await,
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

    /// Sends via TLS with octet-counting framing (RFC 5425 §4.3).
    async fn send_tls(&self, message: &str) -> SyslogResult<()> {
        let Some(sink) = &self.tls else {
            return Ok(());
        };
        sink.send(&octet_counted_frame(message)).await
    }

    /// Closes the forwarder's connection.
    ///
    /// For TLS this sends close_notify (RFC 5425 §4.4); for TCP it shuts
    /// down the write half. Call before dropping the forwarder: `Drop`
    /// cannot run the async close, and a dropped TLS session looks like
    /// truncation to the collector.
    ///
    /// Bounded by a 5 s timeout so a stalled collector cannot hang
    /// shutdown; on timeout the connection is dropped and an I/O
    /// `TimedOut` error is returned.
    pub async fn close(&self) -> SyslogResult<()> {
        let fut = async {
            if let Some(sink) = &self.tls {
                sink.close().await?;
            }
            if let Some(stream) = &self.tcp_stream {
                stream.lock().await.shutdown().await?;
            }
            Ok(())
        };
        tokio::time::timeout(CLOSE_TIMEOUT, fut)
            .await
            .map_err(|_| {
                SyslogError::from(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "syslog close timed out",
                ))
            })?
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
            .field("tls", &self.tls.is_some())
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

    #[test]
    fn tls_octet_counted_framing() {
        assert_eq!(octet_counted_frame("abc"), b"3 abc");
        // Length counts bytes, not chars.
        assert_eq!(octet_counted_frame("é"), "2 é".as_bytes());
        assert_eq!(octet_counted_frame(""), b"0 ");
    }

    mod tls {
        use super::*;
        use crate::config::SyslogTlsConfig;
        use std::path::{Path, PathBuf};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

        struct Pki {
            ca_pem: String,
            chain: Vec<CertificateDer<'static>>,
            key: PrivateKeyDer<'static>,
        }

        /// A P-384 CA and a P-384 leaf for `localhost`.
        fn pki() -> Pki {
            let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
            let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let leaf_key = rcgen::KeyPair::generate_for(alg).unwrap();
            let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .signed_by(&leaf_key, &ca, &ca_key)
                .unwrap();
            Pki {
                ca_pem: ca.pem(),
                chain: vec![leaf.der().clone()],
                key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            }
        }

        fn write_ca(dir: &Path, pem: &str) -> PathBuf {
            let p = dir.join("ca.pem");
            std::fs::write(&p, pem).unwrap();
            p
        }

        /// Starts a one-shot TLS collector; returns its address and a
        /// handle yielding the bytes it read (or the handshake error).
        async fn collector(
            pki: &Pki,
        ) -> (SocketAddr, tokio::task::JoinHandle<Result<Vec<u8>, String>>) {
            let server_cfg =
                uc_transport::tls::create_server_config(pki.chain.clone(), pki.key.clone_key())
                    .unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
                let mut tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                // Ok only on close_notify; a bare TCP close is UnexpectedEof.
                tls.read_to_end(&mut buf)
                    .await
                    .map_err(|e| format!("read: {e}"))?;
                Ok(buf)
            });
            (addr, handle)
        }

        fn tls_config(ca_file: PathBuf, server_name: &str) -> SyslogTlsConfig {
            SyslogTlsConfig {
                ca_file,
                server_name: server_name.to_string(),
                client_cert: None,
                client_key: None,
                allow_tls12: false,
            }
        }

        #[tokio::test]
        async fn tls_delivers_octet_counted_frames() {
            let pki = pki();
            let dir = tempfile::tempdir().unwrap();
            let ca = write_ca(dir.path(), &pki.ca_pem);
            let (addr, handle) = collector(&pki).await;
            let fwd = SyslogForwarder::new(SyslogConfig {
                use_rfc5424: true,
                ..SyslogConfig::tls(addr, tls_config(ca, "localhost"))
            })
            .await
            .unwrap();
            fwd.info("hello").await.unwrap();
            fwd.info("world").await.unwrap();
            fwd.close().await.unwrap();
            drop(fwd);
            let got = String::from_utf8(handle.await.unwrap().unwrap()).unwrap();
            let (len, rest) = got.split_once(' ').unwrap();
            let len: usize = len.parse().unwrap();
            assert!(rest[..len].ends_with("hello"));
            let (len2, rest2) = rest[len..].split_once(' ').unwrap();
            assert_eq!(rest2.len(), len2.parse::<usize>().unwrap());
            assert!(rest2.ends_with("world"));
        }

        #[tokio::test]
        async fn drop_without_close_is_truncation() {
            // RFC 5425 §4.4: without close() the collector sees no
            // close_notify, proving the clean-EOF assertion above is real.
            let pki = pki();
            let dir = tempfile::tempdir().unwrap();
            let ca = write_ca(dir.path(), &pki.ca_pem);
            let (addr, handle) = collector(&pki).await;
            let fwd = SyslogForwarder::new(SyslogConfig::tls(addr, tls_config(ca, "localhost")))
                .await
                .unwrap();
            fwd.info("x").await.unwrap();
            drop(fwd);
            assert!(handle.await.unwrap().is_err());
        }

        #[tokio::test]
        async fn close_times_out_when_send_lock_held() {
            let pki = pki();
            let dir = tempfile::tempdir().unwrap();
            let ca = write_ca(dir.path(), &pki.ca_pem);
            let (addr, _handle) = collector(&pki).await;
            let fwd = SyslogForwarder::new(SyslogConfig::tls(addr, tls_config(ca, "localhost")))
                .await
                .unwrap();
            // Paused clock auto-advances to the close timeout.
            tokio::time::pause();
            // Simulate a send stuck mid-reconnect holding the session lock.
            let _guard = fwd.tls.as_ref().unwrap().stream.lock().await;
            let err = fwd.close().await.unwrap_err();
            assert!(err.to_string().contains("timed out"), "{err}");
        }

        #[tokio::test]
        async fn tls_with_bsd_format_rejected() {
            let cfg = SyslogConfig {
                use_rfc5424: false,
                ..SyslogConfig::tls(
                    "127.0.0.1:1".parse().unwrap(),
                    tls_config(PathBuf::from("/nonexistent"), "localhost"),
                )
            };
            let err = SyslogForwarder::new(cfg).await.unwrap_err();
            assert!(matches!(err, SyslogError::ConfigError { .. }), "{err}");
        }

        #[test]
        fn tls_constructor_defaults_port_6514() {
            let t = tls_config(PathBuf::from("/x"), "localhost");
            let c = SyslogConfig::tls("192.0.2.1:0".parse().unwrap(), t.clone());
            assert_eq!(c.server.port(), SYSLOG_TLS_PORT);
            assert!(c.use_rfc5424);
            let c = SyslogConfig::tls("192.0.2.1:7000".parse().unwrap(), t);
            assert_eq!(c.server.port(), 7000);
        }

        #[tokio::test]
        async fn untrusted_server_cert_rejected() {
            let server_pki = pki();
            let other = pki();
            let dir = tempfile::tempdir().unwrap();
            let ca = write_ca(dir.path(), &other.ca_pem);
            let (addr, _handle) = collector(&server_pki).await;
            let err = SyslogForwarder::new(SyslogConfig::tls(addr, tls_config(ca, "localhost")))
                .await
                .unwrap_err();
            assert!(matches!(err, SyslogError::ConnectionFailed { .. }), "{err}");
        }

        #[tokio::test]
        async fn wrong_server_name_rejected() {
            let pki = pki();
            let dir = tempfile::tempdir().unwrap();
            let ca = write_ca(dir.path(), &pki.ca_pem);
            let (addr, _handle) = collector(&pki).await;
            let err = SyslogForwarder::new(SyslogConfig::tls(
                addr,
                tls_config(ca, "collector.example.invalid"),
            ))
            .await
            .unwrap_err();
            assert!(matches!(err, SyslogError::ConnectionFailed { .. }), "{err}");
        }

        #[tokio::test]
        async fn tls_config_missing_is_error() {
            let cfg = SyslogConfig {
                enabled: true,
                transport: SyslogTransport::Tls,
                ..Default::default()
            };
            let err = SyslogForwarder::new(cfg).await.unwrap_err();
            assert!(matches!(err, SyslogError::ConfigError { .. }));
        }

        #[tokio::test]
        async fn tls_section_with_plain_transport_rejected() {
            let cfg = SyslogConfig {
                tls: Some(tls_config(PathBuf::from("/nonexistent"), "localhost")),
                ..SyslogConfig::udp("127.0.0.1:514".parse().unwrap())
            };
            let err = SyslogForwarder::new(cfg).await.unwrap_err();
            assert!(matches!(err, SyslogError::ConfigError { .. }));
        }

        #[tokio::test]
        async fn half_client_auth_rejected() {
            let pki = pki();
            let dir = tempfile::tempdir().unwrap();
            let ca = write_ca(dir.path(), &pki.ca_pem);
            let mut t = tls_config(ca, "localhost");
            t.client_cert = Some(dir.path().join("c.pem"));
            let err = SyslogForwarder::new(SyslogConfig::tls("127.0.0.1:1".parse().unwrap(), t))
                .await
                .unwrap_err();
            assert!(matches!(err, SyslogError::ConfigError { .. }));
        }
    }
}
