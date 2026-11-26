//! Loopback fixtures shared by the `uc-transport` benches.

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use uc_transport::listener::ListenerConfig;
use uc_transport::tcp::{TcpListener, TcpTransport};
use uc_transport::tls::{TlsListener, TlsTransport, create_client_config, create_server_config};
use uc_transport::{SbcSocketAddr, Transport, TransportType};

pub fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub fn loopback() -> SbcSocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0)).into()
}

pub fn msg(n: usize) -> Vec<u8> {
    (b'a'..=b'z').cycle().take(n).collect()
}

/// Connected client/server pairs for each stream transport.
pub struct StreamPairs {
    tcp: (TcpTransport, TcpTransport),
    tls: (TlsTransport, TlsTransport),
}

impl StreamPairs {
    pub fn new(rt: &Runtime) -> Self {
        Self {
            tcp: tcp_pair(rt),
            tls: tls_pair(rt),
        }
    }

    /// Destination argument for `send`; ignored by stream transports.
    pub fn dest(&self) -> SbcSocketAddr {
        *self.tcp.0.local_addr()
    }

    /// `(benchmark id, client, server)` for each stream transport.
    pub fn each(&self) -> [(&'static str, &dyn Transport, &dyn Transport); 2] {
        [
            ("tcp", &self.tcp.0, &self.tcp.1),
            ("tls13", &self.tls.0, &self.tls.1),
        ]
    }
}

fn tcp_pair(rt: &Runtime) -> (TcpTransport, TcpTransport) {
    rt.block_on(async {
        let l = TcpListener::bind(loopback()).await.unwrap();
        let addr = *l.local_addr();
        let (c, s) = tokio::join!(TcpTransport::connect(addr), l.accept());
        (c.unwrap(), s.unwrap().0)
    })
}

fn tls_pair(rt: &Runtime) -> (TlsTransport, TlsTransport) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let server_cfg = Arc::new(create_server_config(vec![cert_der.clone()], key_der).unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_cfg = Arc::new(create_client_config(roots).unwrap());
    rt.block_on(async {
        let l = TlsListener::bind(
            ListenerConfig::new(loopback(), TransportType::Tls),
            server_cfg,
        )
        .await
        .unwrap();
        let addr = *l.local_addr();
        let (c, s) = tokio::join!(
            TlsTransport::connect(addr, "localhost", client_cfg),
            l.accept()
        );
        (c.unwrap(), s.unwrap().0)
    })
}
