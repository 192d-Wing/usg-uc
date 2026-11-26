//! TLS transport implementation with CNSA 2.0 compliance.
//!
//! ## CNSA 2.0 Compliance
//!
//! TLS is configured with CNSA 2.0 compliant settings only:
//! - **Protocol**: TLS 1.3 by default; TLS 1.2 only where a deployment sets
//!   `min_tls_version = "1.2"`
//! - **Cipher Suite**: `TLS_AES_256_GCM_SHA384` (1.3) and
//!   `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (1.2)
//! - **Key Exchange**: ML-KEM-1024 (preferred) or P-384 ECDHE (1.2: P-384 only)
//! - **Peer certificates and signatures**: ECDSA P-384 / SHA-384 only (SR-14)
//!
//! Every config built here uses [`cnsa_provider`].
//!
//! ## NIST 800-53 Rev5
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-12**: Cryptographic Key Establishment and Management
//! - **SC-13**: Cryptographic Protection
//! - **IA-3 / IA-5(2)**: peer certificate path and signature algorithm
//!   checks (revocation not checked: POA&M-401)
//! - **SC-28 / IA-5(7)**: TLS private key files are checked fail-closed at
//!   load (see [`load_private_key_with`]): symlinks, group/other-accessible
//!   modes and foreign owners are rejected. Decision: this is a boundary
//!   device, so an insecure key file stops the listener rather than warning.
//!
//! ## IPv6-First Design
//!
//! TLS connections prefer IPv6 per project requirements.

use crate::error::{TransportError, TransportResult};
use crate::listener::ListenerConfig;
use crate::{
    MAX_STREAM_MESSAGE_SIZE, ReceivedMessage, STREAM_READ_CHUNK, StreamTransport, Transport,
    canonical_peer, read_stream_chunk,
};
use bytes::BytesMut;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ServerConfig};
use socket2::{Domain, Protocol, Socket, Type};
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tracing::{debug, instrument, trace};
use uc_types::address::{SbcSocketAddr, TransportType};

/// The CNSA 2.0 rustls crypto provider shared by every TLS client and
/// server in the SBC (SIP-TLS listeners, trunk TLS, RFC 5425 CDR syslog,
/// STIR/SHAKEN `x5u` fetch).
///
/// It is the aws-lc-rs (FIPS) provider with its algorithm lists cut down:
///
/// - **Cipher suites**: `TLS13_AES_256_GCM_SHA384` and, for TLS 1.2 only when
///   a caller enables it, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`. No
///   AES-128, no ChaCha20-Poly1305, no RSA key transport or RSA-signed
///   ECDHE suites.
/// - **Key exchange**: `MLKEM1024` first, then `secp384r1`. No X25519,
///   no P-256, no X25519/P-256 + ML-KEM-768 hybrids.
///
/// ML-KEM-1024 is the CNSA 2.0 key-establishment algorithm (category 5),
/// and the aws-lc FIPS module reports it as FIPS-approved. It is offered
/// first so two up-to-date peers agree a quantum-resistant key. P-384
/// ECDHE stays as the fallback for CNSA 1.0 peers: a peer that only
/// supports P-384 answers with a `HelloRetryRequest` (one extra round trip).
/// TLS 1.2 cannot use ML-KEM, so 1.2 handshakes always use P-384.
///
/// - **Signature verification**: ECDSA P-384 with SHA-384 only (the CNSA
///   1.0 / 2.0 transition profile), for the peer's handshake signature
///   (TLS 1.3 `CertificateVerify`, TLS 1.2 `ServerKeyExchange`/
///   `CertificateVerify`), which binds the end-entity key to P-384, and for
///   every certificate signature below the trust anchor. A peer whose
///   end-entity key or issuing CA keys are RSA, P-256, P-521, Ed25519 or
///   ML-DSA is refused. Trust anchor self-signatures are not verified.
///   ML-DSA-87, the CNSA 2.0 signature, is not yet accepted (POA&M-404).
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection), SC-8, SC-12, IA-3,
/// IA-5(2) (path and signature algorithm; revocation not checked: POA&M-401)
// POAM: POA&M-404: ML-DSA-87 peer signatures are not accepted.
#[must_use]
pub fn cnsa_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![kx_group::MLKEM1024, kx_group::SECP384R1],
        signature_verification_algorithms: CNSA_SIG_ALGS,
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// Peer signature verification for [`cnsa_provider`].
///
/// CNSA 1.0 / 2.0 transition profile: ECDSA P-384 / SHA-384 only. P-521 and
/// SHA-512 are not in either suite. ML-DSA-87 (the CNSA 2.0 signature) is
/// not yet accepted.
///
/// NIST 800-53 Rev5: SC-13, IA-3, IA-5(2) (path and signature algorithm;
/// revocation not checked: POA&M-401)
// POAM: POA&M-404: ML-DSA-87 TLS peer signatures not accepted (no rustls/webpki
// verifier in the FIPS provider yet).
static CNSA_SIG_ALGS: rustls::crypto::WebPkiSupportedAlgorithms =
    rustls::crypto::WebPkiSupportedAlgorithms {
        // Every certificate signature below the trust anchor.
        all: &[webpki::aws_lc_rs::ECDSA_P384_SHA384],
        // Handshake signatures; also limits the schemes rustls advertises.
        mapping: &[(
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            &[webpki::aws_lc_rs::ECDSA_P384_SHA384],
        )],
    };

/// Creates a CNSA 2.0 compliant TLS server configuration.
///
/// ## CNSA 2.0 Requirements
///
/// - TLS 1.3 only
/// - `TLS_AES_256_GCM_SHA384` cipher suite
/// - P-384 certificates
///
/// ## Errors
///
/// Returns an error if the configuration cannot be created.
pub fn create_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> TransportResult<ServerConfig> {
    create_server_config_with(cert_chain, private_key, TlsServerOptions::default())
}

/// Minimum protocol version a TLS server accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MinTlsVersion {
    /// TLS 1.2 and 1.3 (1.3 is still preferred by negotiation).
    V1_2,
    /// TLS 1.3 only (CNSA 2.0 default).
    #[default]
    V1_3,
}

impl MinTlsVersion {
    /// Parses the configuration spelling (`"1.2"` / `"1.3"`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "1.2" => Some(Self::V1_2),
            "1.3" => Some(Self::V1_3),
            _ => None,
        }
    }
}

/// Server-side TLS policy beyond the certificate: the protocol floor and,
/// for mutual TLS, the CA store client certificates must chain to.
#[derive(Debug, Default)]
pub struct TlsServerOptions {
    /// Lowest protocol version accepted.
    pub min_version: MinTlsVersion,
    /// When set, clients must present a certificate issued by one of these
    /// roots (mutual TLS); otherwise no client certificate is requested.
    pub client_ca: Option<rustls::RootCertStore>,
}

/// Creates a TLS server configuration with an explicit policy.
///
/// Uses [`cnsa_provider`] (CNSA 2.0 suites and groups only). With `client_ca` set, the handshake
/// requires and verifies a client certificate (`WebPKI` rules against the
/// given roots), which is how `security.require_mtls` is enforced for SIP.
///
/// ## Errors
///
/// Returns an error if the protocol versions, client verifier or
/// certificate cannot be configured.
pub fn create_server_config_with(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    options: TlsServerOptions,
) -> TransportResult<ServerConfig> {
    let provider = Arc::new(cnsa_provider());
    let versions: &[&'static rustls::SupportedProtocolVersion] = match options.min_version {
        MinTlsVersion::V1_3 => &[&rustls::version::TLS13],
        MinTlsVersion::V1_2 => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };

    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .map_err(|e| TransportError::TlsHandshakeFailed {
            reason: format!("failed to set TLS protocol versions: {e}"),
        })?;

    let builder = match options.client_ca {
        Some(roots) => {
            // POAM: POA&M-401: client certificate revocation is not checked.
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|e| TransportError::TlsCertificateError {
                reason: format!("client CA store rejected: {e}"),
            })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    builder
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| TransportError::TlsCertificateError {
            reason: e.to_string(),
        })
}

/// Loads a PEM bundle of CA certificates into a root store (for mutual TLS).
///
/// ## Errors
///
/// Returns an error if the file cannot be read, holds no certificates, or a
/// certificate is rejected by the store.
pub fn load_root_store(path: &std::path::Path) -> TransportResult<rustls::RootCertStore> {
    let certs = load_certs(path)?;
    if certs.is_empty() {
        return Err(TransportError::TlsCertificateError {
            reason: format!("{} contains no certificates", path.display()),
        });
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| TransportError::TlsCertificateError {
                reason: format!("{}: {e}", path.display()),
            })?;
    }
    Ok(roots)
}

/// Creates a CNSA 2.0 compliant TLS client configuration.
///
/// ## CNSA 2.0 Requirements
///
/// - TLS 1.3 only
/// - `TLS_AES_256_GCM_SHA384` cipher suite
/// - ML-KEM-1024 or P-384 key exchange (see [`cnsa_provider`])
///
/// ## Errors
///
/// Returns an error if the configuration cannot be created.
pub fn create_client_config(root_certs: rustls::RootCertStore) -> TransportResult<ClientConfig> {
    let provider = cnsa_provider();

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::TlsHandshakeFailed {
            reason: format!("failed to set TLS 1.3: {e}"),
        })?
        // POAM: POA&M-401: server certificate revocation is not checked.
        .with_root_certificates(root_certs)
        .with_no_client_auth();

    Ok(config)
}

/// Client-side TLS policy for outbound connections (SIP trunks).
///
/// Certificate verification is always on: there is no option to disable
/// it. The server name (or IP SAN) is checked against the name passed to
/// [`TlsTransport::connect`].
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity),
/// SC-23 (Session Authenticity), IA-3 (Device Identification)
pub struct TlsClientOptions {
    /// Trust anchors the server certificate must chain to.
    pub roots: rustls::RootCertStore,
    /// Lowest protocol version offered.
    pub min_version: MinTlsVersion,
    /// Certificate chain and key presented when the server requests a
    /// client certificate (mutual TLS). `None` means no client auth.
    pub client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
}

impl std::fmt::Debug for TlsClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientOptions")
            .field("roots", &self.roots.len())
            .field("min_version", &self.min_version)
            .field("client_auth", &self.client_auth.is_some())
            .finish()
    }
}

/// Creates a TLS client configuration with an explicit policy.
///
/// Uses [`cnsa_provider`], like [`create_client_config`]. `min_version`
/// selects TLS 1.3 only or TLS 1.2 + 1.3; either way only the CNSA 2.0
/// suites and groups are offered, so a peer that supports only AES-128,
/// `ChaCha20`, X25519 or P-256 fails the handshake.
///
/// ## Errors
///
/// Returns an error if the protocol versions or client certificate cannot
/// be configured.
pub fn create_client_config_with(options: TlsClientOptions) -> TransportResult<ClientConfig> {
    let provider = cnsa_provider();
    let versions: &[&'static rustls::SupportedProtocolVersion] = match options.min_version {
        MinTlsVersion::V1_3 => &[&rustls::version::TLS13],
        MinTlsVersion::V1_2 => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| TransportError::TlsHandshakeFailed {
            reason: format!("failed to set TLS protocol versions: {e}"),
        })?
        // POAM: POA&M-401: server certificate revocation is not checked.
        .with_root_certificates(options.roots);
    match options.client_auth {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| {
            TransportError::TlsCertificateError {
                reason: format!("client certificate rejected: {e}"),
            }
        }),
        None => Ok(builder.with_no_client_auth()),
    }
}

/// Loads a certificate chain from a PEM file.
///
/// ## Errors
///
/// Returns an error if the file cannot be read or parsed.
///
/// # Errors
/// Returns an error if the operation fails.
///
/// # Errors
/// Returns an error if the operation fails.
// POAM: POA&M-404: the SBC's own chain is not checked against the peer
// signature profile at load (only the key curve is).
pub fn load_certs(path: &Path) -> TransportResult<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;

    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| TransportError::TlsCertificateError {
            reason: format!("failed to open cert file: {e}"),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::TlsCertificateError {
            reason: format!("failed to parse certs: {e}"),
        })?;

    if certs.is_empty() {
        return Err(TransportError::TlsCertificateError {
            reason: "no certificates found in file".to_string(),
        });
    }

    Ok(certs)
}

/// Maximum private key file size read (PEM).
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Curve the TLS private key must use, from `security.curve`.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredKeyCurve {
    /// ECDSA P-384 (CNSA 2.0 default).
    P384,
    /// ECDSA P-521.
    P521,
}

impl RequiredKeyCurve {
    const fn as_ec(self) -> uc_crypto::ecdsa::EcCurve {
        match self {
            Self::P384 => uc_crypto::ecdsa::EcCurve::P384,
            Self::P521 => uc_crypto::ecdsa::EcCurve::P521,
        }
    }
}

/// Loads a TLS private key from a PEM file.
///
/// Accepts only ECDSA P-384 (the CNSA 1.0 curve) or P-521 (accepted by repo
/// policy, `CnsaCurve`); ECDSA is transitional under CNSA 2.0.
/// RSA and P-256 keys are rejected. Use [`load_private_key_with`] for an
/// exact match against `security.curve`. The file checks are those of
/// [`load_private_key_with`].
///
/// # Errors
/// The file is insecure, unreadable or unparsable, or the key is not on
/// P-384 or P-521.
// POAM: POA&M-166: sbc-daemon (`server.rs` TLS listener setup) does not yet pass
// `security.curve`; it calls this function, which accepts P-384 or P-521.
// POAM: POA&M-165: symlinked parent directories are not detected; copies held
// inside rustls `PrivateKeyDer` / aws-lc `EVP_PKEY` are not wiped by us.
pub fn load_private_key(path: &Path) -> TransportResult<PrivateKeyDer<'static>> {
    load_private_key_checked(path, None)
}

/// Loads a TLS private key from a PEM file, requiring `required` curve.
///
/// ## Fail-closed file checks (boundary device)
///
/// The key file is opened with `O_NOFOLLOW` and checked on the open
/// descriptor (no TOCTOU window). It is rejected, and the listener does not
/// start, when it:
/// - is a symlink, or not a regular file;
/// - has any group or other permission bit (`mode & 0o077 != 0`);
/// - is not owned by the effective user (root-owned keys are rejected
///   unless the SBC runs as root; this matches uc-sti `FileSigner`, so both
///   key loaders give the same operator guidance: install keys `0600`/`0400`
///   owned by the service account);
/// - is larger than 64 KiB.
///
/// On non-unix targets key loading is refused outright (fail closed), as in
/// the sbc-api-server HA1 key loader.
///
/// The read buffer is zeroized. The returned `PrivateKeyDer` and the copy
/// rustls/aws-lc keep inside the `ServerConfig` are not wiped by this
/// crate (`PrivateKeyDer` implements `Zeroize` but not drop-wipe).
///
/// ## NIST 800-53 Rev5: SC-12, SC-13, SC-28, IA-5(7), AC-3, AC-6
///
/// # Errors
/// The file is insecure, unreadable or unparsable, or the key curve does
/// not match `required`.
// NIST 800-53 Rev5: SC-28, AC-3 (POA&M-164 closed: key file mode/owner/symlink
// checks, fail closed; non-unix refused).
// POAM: POA&M-165: symlinked parent directories are not detected; copies held
// inside rustls `PrivateKeyDer` / aws-lc `EVP_PKEY` are not wiped by us.
pub fn load_private_key_with(
    path: &Path,
    required: RequiredKeyCurve,
) -> TransportResult<PrivateKeyDer<'static>> {
    load_private_key_checked(path, Some(required))
}

pub(crate) fn load_private_key_checked(
    path: &Path,
    required: Option<RequiredKeyCurve>,
) -> TransportResult<PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    use zeroize::Zeroize;

    let pem = read_key_file(path)?;
    let mut key =
        PrivateKeyDer::from_pem_slice(&pem).map_err(|e| TransportError::TlsCertificateError {
            reason: format!("failed to load private key: {e}"),
        })?;
    if let Err(e) = check_key_curve(&key, required) {
        key.zeroize();
        return Err(e);
    }
    Ok(key)
}

/// Rejects a key that is not on the required curve (or, with none, not on
/// P-384/P-521).
fn check_key_curve(
    key: &PrivateKeyDer<'_>,
    required: Option<RequiredKeyCurve>,
) -> TransportResult<()> {
    use uc_crypto::ecdsa::{EcCurve, ec_private_key_curve};

    let found = ec_private_key_curve(key.secret_der());
    let ok = match (found, required) {
        (Some(c), Some(r)) => c == r.as_ec(),
        (Some(c), None) => matches!(c, EcCurve::P384 | EcCurve::P521),
        (None, _) => false,
    };
    if ok {
        return Ok(());
    }
    let found = found.map_or_else(|| "non-EC or unsupported".to_owned(), |c| c.to_string());
    let want = required.map_or_else(|| "P-384 or P-521".to_owned(), |r| r.as_ec().to_string());
    Err(TransportError::TlsCertificateError {
        reason: format!("private key curve {found} does not match security.curve {want}"),
    })
}

fn key_file_error(reason: impl Into<String>) -> TransportError {
    TransportError::TlsCertificateError {
        reason: reason.into(),
    }
}

/// Opens and reads the key file with the fail-closed checks above.
///
/// Mirrors uc-sti `FileSigner` (uc-sti sits above this crate), including
/// its owner rule (`uid == euid`, no uid-0 exception).
#[cfg(unix)]
fn read_key_file(path: &Path) -> TransportResult<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::Read;

    use nix::fcntl::OFlag;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    // O_NONBLOCK: opening a FIFO must not hang startup.
    opts.custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits());
    let f = opts.open(path).map_err(|e| {
        if e.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) {
            return key_file_error("private key file must not be a symlink");
        }
        key_file_error(format!("failed to open private key file: {e}"))
    })?;
    let meta = f
        .metadata()
        .map_err(|e| key_file_error(format!("failed to stat private key file: {e}")))?;
    if !meta.is_file() {
        return Err(key_file_error("private key file must be a regular file"));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(key_file_error(format!(
            "private key file mode {mode:04o} is accessible by group or other; chmod 0600 (or 0400) it"
        )));
    }
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(key_file_error(
            "private key file must be owned by the SBC's user",
        ));
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(key_file_error("private key file too large"));
    }
    let mut buf =
        zeroize::Zeroizing::new(Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0)));
    f.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| key_file_error(format!("failed to read private key file: {e}")))?;
    if buf.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(key_file_error("private key file too large"));
    }
    Ok(buf)
}

/// Non-unix targets cannot check mode/owner on the open descriptor, so key
/// loading is refused (fail closed).
#[cfg(not(unix))]
fn read_key_file(_path: &Path) -> TransportResult<zeroize::Zeroizing<Vec<u8>>> {
    Err(key_file_error(
        "TLS private key loading is only supported on unix",
    ))
}

/// TLS transport for secure SIP messaging.
///
/// ## CNSA 2.0 Compliance
///
/// Connections use the `ClientConfig` passed to [`TlsTransport::connect`].
/// Configs from [`create_client_config`] / [`create_client_config_with`]
/// are CNSA 2.0: `TLS_AES_256_GCM_SHA384` (plus
/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` when TLS 1.2 is allowed) and
/// ML-KEM-1024 or P-384 key exchange, via [`cnsa_provider`].
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
pub struct TlsTransport {
    /// Read and write halves are locked separately so a send from another
    /// task never waits behind a pending `recv` on the reader task.
    reader: Mutex<ReadHalf<TlsStream<TcpStream>>>,
    writer: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    local_addr: SbcSocketAddr,
    peer_addr: SbcSocketAddr,
    read_buffer: Mutex<BytesMut>,
    closed: AtomicBool,
}

impl TlsTransport {
    /// Creates a TLS transport from an established client-side TLS
    /// connection (peer address from `getpeername`).
    fn from_stream(stream: TlsStream<TcpStream>) -> TransportResult<Self> {
        let (io, _session) = stream.get_ref();

        let local_addr = io.local_addr().map_err(|e| TransportError::Io {
            reason: format!("failed to get local address: {e}"),
        })?;

        // NIST 800-53 Rev5: SI-10; supports SC-7, AC-4 - IPv4-mapped peers reported as plain IPv4.
        let peer_addr = canonical_peer(io.peer_addr().map_err(|e| TransportError::Io {
            reason: format!("failed to get peer address: {e}"),
        })?);

        Ok(Self::with_addrs(
            stream,
            local_addr.into(),
            peer_addr.into(),
        ))
    }

    /// Creates a TLS transport for a server-side connection whose TCP
    /// stream came from [`TlsListener::accept_tcp`].
    ///
    /// Infallible: `peer` is the canonical address `accept()` returned, so
    /// a peer that resets right after the handshake cannot turn a
    /// completed handshake into an error (no `getpeername`). The local
    /// address comes from `getsockname`, or `listener_local` if that fails.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
    fn from_accepted(
        stream: TlsStream<TcpStream>,
        peer: SbcSocketAddr,
        listener_local: SbcSocketAddr,
    ) -> Self {
        let (io, _session) = stream.get_ref();
        let local_addr = io.local_addr().map_or(listener_local, SbcSocketAddr::from);
        Self::with_addrs(stream, local_addr, peer)
    }

    /// Builds the transport from an established TLS stream and its
    /// addresses.
    fn with_addrs(
        stream: TlsStream<TcpStream>,
        local_addr: SbcSocketAddr,
        peer_addr: SbcSocketAddr,
    ) -> Self {
        debug!(
            local = %local_addr,
            peer = %peer_addr,
            "TLS transport created"
        );

        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            local_addr,
            peer_addr,
            // NIST 800-53 Rev5: SC-5, SC-6 - one read chunk resident per
            // connection, not a message-sized buffer.
            read_buffer: Mutex::new(BytesMut::with_capacity(STREAM_READ_CHUNK)),
            closed: AtomicBool::new(false),
        }
    }

    /// Connects to a remote TLS endpoint.
    ///
    /// ## CNSA 2.0 Compliance
    ///
    /// The connection uses CNSA 2.0 compliant TLS settings.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection or TLS handshake fails.
    #[instrument(skip(config), fields(dest = %dest))]
    pub async fn connect(
        dest: SbcSocketAddr,
        server_name: &str,
        config: Arc<ClientConfig>,
    ) -> TransportResult<Self> {
        let dest_addr: SocketAddr = dest.into();

        let tcp_stream =
            TcpStream::connect(dest_addr)
                .await
                .map_err(|e| TransportError::ConnectFailed {
                    address: dest,
                    reason: e.to_string(),
                })?;
        let _ = tcp_stream.set_nodelay(true);

        let server_name: rustls::pki_types::ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| TransportError::TlsHandshakeFailed {
                reason: "invalid server name".to_string(),
            })?;

        let connector = TlsConnector::from(config);
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| TransportError::TlsHandshakeFailed {
                reason: e.to_string(),
            })?;

        debug!(dest = %dest_addr, "TLS handshake completed");

        Self::from_stream(TlsStream::Client(tls_stream))
    }

    /// Checks if the transport is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Transport for TlsTransport {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn send<'a>(
        &'a self,
        data: &'a [u8],
        _dest: &'a SbcSocketAddr,
    ) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(TransportError::AlreadyClosed);
            }

            if data.len() > MAX_STREAM_MESSAGE_SIZE {
                return Err(TransportError::MessageTooLarge {
                    size: data.len(),
                    max_size: MAX_STREAM_MESSAGE_SIZE,
                });
            }

            trace!(size = data.len(), "sending TLS data");

            {
                let mut stream = self.writer.lock().await;
                stream
                    .write_all(data)
                    .await
                    .map_err(|e| TransportError::SendFailed {
                        address: self.peer_addr,
                        reason: e.to_string(),
                    })?;

                stream
                    .flush()
                    .await
                    .map_err(|e| TransportError::SendFailed {
                        address: self.peer_addr,
                        reason: e.to_string(),
                    })?;
                drop(stream);
            }

            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn Future<Output = TransportResult<ReceivedMessage>> + Send + '_>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(TransportError::AlreadyClosed);
            }

            let data = {
                let mut read_buffer = self.read_buffer.lock().await;
                let mut stream = self.reader.lock().await;
                read_stream_chunk(&mut *stream, &mut read_buffer).await?
            };

            trace!(size = data.len(), "received TLS data");

            Ok(ReceivedMessage {
                data,
                source: self.peer_addr,
                transport: TransportType::Tls,
            })
        })
    }

    fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tls
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

            {
                let mut stream = self.writer.lock().await;
                let _ = stream.shutdown().await;
                drop(stream);
            }

            debug!(peer = %self.peer_addr, "TLS transport closed");
            Ok(())
        })
    }
}

impl StreamTransport for TlsTransport {
    fn peer_addr(&self) -> &SbcSocketAddr {
        &self.peer_addr
    }

    fn is_connected(&self) -> bool {
        !self.is_closed()
    }
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport")
            .field("reader", &"<mutex>")
            .field("writer", &"<mutex>")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("read_buffer", &"<mutex>")
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// TLS listener for accepting incoming secure connections.
///
/// Connections use the suites, groups and versions of the `ServerConfig`
/// passed to [`TlsListener::bind`]; the listener itself enforces none, so
/// CNSA 2.0 compliance depends on that config. Configs from
/// [`create_server_config`] / [`create_server_config_with`] use
/// [`cnsa_provider`].
///
/// ## NIST 800-53 Rev5: SC-8
pub struct TlsListener {
    listener: TokioTcpListener,
    acceptor: TlsAcceptor,
    local_addr: SbcSocketAddr,
    closed: AtomicBool,
}

impl TlsListener {
    /// Creates a TLS listener with the given configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error if binding fails.
    #[instrument(skip(server_config), fields(addr = %config.bind_address))]
    pub async fn bind(
        config: ListenerConfig,
        server_config: Arc<ServerConfig>,
    ) -> TransportResult<Self> {
        config.validate()?;

        let socket_addr: SocketAddr = config.bind_address.into();
        let domain = if socket_addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|e| {
            TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            }
        })?;

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

        if socket_addr.is_ipv6() {
            socket
                .set_only_v6(false)
                .map_err(|e| TransportError::BindFailed {
                    address: config.bind_address,
                    reason: format!("failed to set IPV6_V6ONLY: {e}"),
                })?;
        }

        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to set non-blocking: {e}"),
            })?;

        socket
            .bind(&socket_addr.into())
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            })?;

        socket
            .listen(i32::try_from(config.backlog).unwrap_or(128))
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to listen: {e}"),
            })?;

        let std_listener: std::net::TcpListener = socket.into();
        let tokio_listener =
            TokioTcpListener::from_std(std_listener).map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: e.to_string(),
            })?;

        let local_addr = tokio_listener
            .local_addr()
            .map_err(|e| TransportError::BindFailed {
                address: config.bind_address,
                reason: format!("failed to get local address: {e}"),
            })?;

        debug!(local_addr = %local_addr, "TLS listener bound");

        Ok(Self {
            listener: tokio_listener,
            acceptor: TlsAcceptor::from(server_config),
            local_addr: local_addr.into(),
            closed: AtomicBool::new(false),
        })
    }

    /// Accepts the next incoming TLS connection.
    ///
    /// This performs the TLS handshake before returning.
    ///
    /// ## Errors
    ///
    /// Returns an error if accept or TLS handshake fails.
    pub async fn accept(&self) -> TransportResult<(TlsTransport, SbcSocketAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::AlreadyClosed);
        }

        let (tcp_stream, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| crate::accept_error(&e))?;

        // NIST 800-53 Rev5: SI-10; supports SC-7, AC-4 - IPv4-mapped peers reported as plain IPv4.
        let peer_addr = canonical_peer(peer_addr);
        debug!(peer = %peer_addr, "accepted TCP connection, starting TLS handshake");

        let tls_stream = self.acceptor.accept(tcp_stream).await.map_err(|e| {
            TransportError::TlsHandshakeFailed {
                reason: e.to_string(),
            }
        })?;

        debug!(peer = %peer_addr, "TLS handshake completed");

        let peer_addr = SbcSocketAddr::from(peer_addr);
        let transport =
            TlsTransport::from_accepted(TlsStream::Server(tls_stream), peer_addr, self.local_addr);
        Ok((transport, peer_addr))
    }

    /// Accepts the next incoming TCP connection without performing the TLS
    /// handshake.
    ///
    /// Use [`complete_handshake`](Self::complete_handshake) on the returned
    /// stream to finish the TLS negotiation. Splitting accept from handshake
    /// lets callers spawn the handshake in a separate task so one slow client
    /// cannot stall the accept loop.
    ///
    /// ## Errors
    ///
    /// Returns an error if the TCP accept fails or the listener is closed.
    pub async fn accept_tcp(&self) -> TransportResult<(TcpStream, SbcSocketAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::AlreadyClosed);
        }

        let (tcp_stream, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| crate::accept_error(&e))?;

        // NIST 800-53 Rev5: SI-10; supports SC-7, AC-4 - IPv4-mapped peers reported as plain IPv4.
        let peer_addr = canonical_peer(peer_addr);
        debug!(peer = %peer_addr, "accepted TCP connection for TLS (handshake deferred)");
        Ok((tcp_stream, peer_addr.into()))
    }

    /// Completes the TLS handshake on a TCP stream from
    /// [`accept_tcp`](Self::accept_tcp); `peer` is the address it returned
    /// and becomes the transport's peer address.
    ///
    /// Intended to run inside a spawned task with a timeout so that one
    /// slow handshake does not block the accept loop.
    ///
    /// ## Errors
    ///
    /// Returns an error if the TLS handshake fails. A peer that resets
    /// after the handshake is not an error here (no `getpeername`).
    pub async fn complete_handshake(
        &self,
        tcp_stream: TcpStream,
        peer: SbcSocketAddr,
    ) -> TransportResult<TlsTransport> {
        let tls_stream = self.acceptor.accept(tcp_stream).await.map_err(|e| {
            TransportError::TlsHandshakeFailed {
                reason: e.to_string(),
            }
        })?;

        Ok(TlsTransport::from_accepted(
            TlsStream::Server(tls_stream),
            peer,
            self.local_addr,
        ))
    }

    /// Returns the local address.
    #[must_use]
    pub const fn local_addr(&self) -> &SbcSocketAddr {
        &self.local_addr
    }

    /// Closes the listener.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn close(&self) -> TransportResult<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TransportError::AlreadyClosed);
        }

        debug!(local_addr = %self.local_addr, "TLS listener closed");
        Ok(())
    }
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener")
            .field("listener", &self.listener)
            .field("acceptor", &"<TlsAcceptor>")
            .field("local_addr", &self.local_addr)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn min_tls_version_parses_configuration_spelling() {
        assert_eq!(MinTlsVersion::parse("1.3"), Some(MinTlsVersion::V1_3));
        assert_eq!(MinTlsVersion::parse(" 1.2 "), Some(MinTlsVersion::V1_2));
        assert_eq!(MinTlsVersion::parse("1.0"), None);
        assert_eq!(MinTlsVersion::default(), MinTlsVersion::V1_3);
    }

    #[test]
    fn test_cnsa_compliant_client_config() {
        let root_store = rustls::RootCertStore::empty();
        let config = create_client_config(root_store).unwrap();

        // Verify TLS 1.3 is configured
        assert_eq!(config.alpn_protocols.len(), 0); // No ALPN by default
    }

    // ---- CNSA 2.0 handshake tests (POA&M-26 / POA&M-40) ----
    //
    // Handshakes run in memory between a `ClientConnection` and a
    // `ServerConnection`, so no sockets are needed.

    use rustls::crypto::CryptoProvider;
    use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
    use rustls::{ClientConnection, ServerConnection};

    struct Pki {
        ca: CertificateDer<'static>,
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
            ca: ca.der().clone(),
            chain: vec![leaf.der().clone()],
            key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        }
    }

    fn roots(pki: &Pki) -> rustls::RootCertStore {
        let mut r = rustls::RootCertStore::empty();
        r.add(pki.ca.clone()).unwrap();
        r
    }

    /// A non-CNSA peer: AES-128-GCM (+ `ChaCha20` on 1.2) and X25519 / P-256.
    fn weak_provider() -> CryptoProvider {
        CryptoProvider {
            cipher_suites: vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ],
            kx_groups: vec![kx_group::X25519, kx_group::SECP256R1],
            ..rustls::crypto::aws_lc_rs::default_provider()
        }
    }

    /// A non-CNSA peer that does use AES-256, but only over X25519.
    fn x25519_only_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![kx_group::X25519],
            ..rustls::crypto::aws_lc_rs::default_provider()
        }
    }

    /// A CNSA 1.0 peer: AES-256-GCM over P-384 only (no ML-KEM).
    fn p384_only_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![kx_group::SECP384R1],
            ..cnsa_provider()
        }
    }

    fn client_with(provider: CryptoProvider, pki: &Pki, v12: bool) -> ClientConfig {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if v12 {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13]
        };
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots(pki))
            .with_no_client_auth()
    }

    fn server_with(provider: CryptoProvider, pki: &Pki) -> ServerConfig {
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(pki.chain.clone(), pki.key.clone_key())
            .unwrap()
    }

    /// Outcome of a successful handshake.
    #[derive(Debug)]
    struct Negotiated {
        suite: rustls::CipherSuite,
        group: Option<rustls::NamedGroup>,
    }

    /// Drives a handshake to completion in memory.
    fn handshake(client: ClientConfig, server: ServerConfig) -> Result<Negotiated, rustls::Error> {
        let mut c = ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap())?;
        let mut s = ServerConnection::new(Arc::new(server))?;
        for _ in 0..16 {
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                s.read_tls(&mut &buf[..]).unwrap();
                s.process_new_packets()?;
            }
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                c.read_tls(&mut &buf[..]).unwrap();
                c.process_new_packets()?;
            }
        }
        assert!(!c.is_handshaking(), "handshake did not finish");
        Ok(Negotiated {
            suite: c.negotiated_cipher_suite().unwrap().suite(),
            group: c
                .negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name),
        })
    }

    #[test]
    fn cnsa_provider_lists_only_cnsa_algorithms() {
        let p = cnsa_provider();
        let suites: Vec<_> = p
            .cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        assert_eq!(
            suites,
            [
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ]
        );
        let groups: Vec<_> = p.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            groups,
            [rustls::NamedGroup::MLKEM1024, rustls::NamedGroup::secp384r1]
        );
    }

    #[test]
    fn cnsa_configs_are_fips() {
        let pki = pki();
        assert!(create_client_config(roots(&pki)).unwrap().fips());
        let server = create_server_config(pki.chain.clone(), pki.key.clone_key()).unwrap();
        assert!(server.fips());
    }

    #[test]
    fn cnsa_client_and_server_agree_ml_kem_1024() {
        let pki = pki();
        let client = create_client_config(roots(&pki)).unwrap();
        let server = create_server_config(pki.chain.clone(), pki.key.clone_key()).unwrap();
        let n = handshake(client, server).unwrap();
        assert_eq!(n.suite, rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(n.group, Some(rustls::NamedGroup::MLKEM1024));
    }

    #[test]
    fn cnsa_client_falls_back_to_p384_with_cnsa1_server() {
        let pki = pki();
        let client = create_client_config(roots(&pki)).unwrap();
        let n = handshake(client, server_with(p384_only_provider(), &pki)).unwrap();
        assert_eq!(n.suite, rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(n.group, Some(rustls::NamedGroup::secp384r1));
    }

    #[test]
    fn cnsa_server_accepts_cnsa1_client() {
        let pki = pki();
        let server = create_server_config(pki.chain.clone(), pki.key.clone_key()).unwrap();
        let n = handshake(client_with(p384_only_provider(), &pki, false), server).unwrap();
        assert_eq!(n.group, Some(rustls::NamedGroup::secp384r1));
    }

    #[test]
    fn cnsa_client_rejects_aes128_x25519_server() {
        let pki = pki();
        let client = create_client_config(roots(&pki)).unwrap();
        assert!(handshake(client, server_with(weak_provider(), &pki)).is_err());
    }

    #[test]
    fn cnsa_client_rejects_x25519_only_server() {
        let pki = pki();
        let client = create_client_config(roots(&pki)).unwrap();
        assert!(handshake(client, server_with(x25519_only_provider(), &pki)).is_err());
    }

    #[test]
    fn cnsa_server_rejects_aes128_x25519_client() {
        let pki = pki();
        for v12 in [false, true] {
            let server = create_server_config_with(
                pki.chain.clone(),
                pki.key.clone_key(),
                TlsServerOptions {
                    min_version: MinTlsVersion::V1_2,
                    client_ca: None,
                },
            )
            .unwrap();
            let client = client_with(weak_provider(), &pki, v12);
            assert!(handshake(client, server).is_err(), "v12={v12}");
        }
    }

    #[test]
    fn cnsa_server_rejects_x25519_only_client() {
        let pki = pki();
        let server = create_server_config(pki.chain.clone(), pki.key.clone_key()).unwrap();
        let client = client_with(x25519_only_provider(), &pki, false);
        assert!(handshake(client, server).is_err());
    }

    #[test]
    fn tls12_is_limited_to_ecdhe_ecdsa_aes256_over_p384() {
        let pki = pki();
        let client = create_client_config_with(TlsClientOptions {
            roots: roots(&pki),
            min_version: MinTlsVersion::V1_2,
            client_auth: None,
        })
        .unwrap();
        // A TLS 1.2-only server with the default (non-CNSA) provider.
        let server = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.chain.clone(), pki.key.clone_key())
        .unwrap();
        let n = handshake(client, server).unwrap();
        assert_eq!(
            n.suite,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        );
        assert_eq!(n.group, Some(rustls::NamedGroup::secp384r1));
    }

    #[test]
    fn client_config_with_rejects_weak_server_on_tls12() {
        let pki = pki();
        let client = create_client_config_with(TlsClientOptions {
            roots: roots(&pki),
            min_version: MinTlsVersion::V1_2,
            client_auth: None,
        })
        .unwrap();
        assert!(handshake(client, server_with(weak_provider(), &pki)).is_err());
    }

    // ---- Peer signature algorithms (SR-14) ----
    // NIST 800-53 Rev5: SC-13, IA-3, IA-5(2) (path and signature algorithm;
    // revocation not checked: POA&M-401)
    // Peers must authenticate with ECDSA P-384 / SHA-384 only: no RSA,
    // P-256, P-521 or Ed25519 end-entity keys and no CA chain signed with
    // anything but P-384 / SHA-384.

    /// A CA with key `ca_alg` and a `localhost` leaf with key `leaf_alg`.
    fn pki_with(
        ca_alg: &'static rcgen::SignatureAlgorithm,
        leaf_alg: &'static rcgen::SignatureAlgorithm,
    ) -> Pki {
        let ca_key = rcgen::KeyPair::generate_for(ca_alg).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate_for(leaf_alg).unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        Pki {
            ca: ca.der().clone(),
            chain: vec![leaf.der().clone()],
            key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        }
    }

    const P256: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
    const P384: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P384_SHA384;
    const P521: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P521_SHA512;
    const RSA: &rcgen::SignatureAlgorithm = &rcgen::PKCS_RSA_SHA256;
    const ED25519: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ED25519;

    /// A server with the default provider (signs with whatever its key
    /// allows), so only the CNSA client's verification policy decides.
    fn permissive_server(pki: &Pki, v12_only: bool) -> ServerConfig {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if v12_only {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13]
        };
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(pki.chain.clone(), pki.key.clone_key())
            .unwrap()
    }

    fn cnsa_client(pki: &Pki, min: MinTlsVersion) -> ClientConfig {
        create_client_config_with(TlsClientOptions {
            roots: roots(pki),
            min_version: min,
            client_auth: None,
        })
        .unwrap()
    }

    /// CNSA client against a permissive server holding `pki`'s leaf.
    fn client_verdict(pki: &Pki, v12: bool) -> Result<Negotiated, rustls::Error> {
        let min = if v12 {
            MinTlsVersion::V1_2
        } else {
            MinTlsVersion::V1_3
        };
        handshake(cnsa_client(pki, min), permissive_server(pki, v12))
    }

    #[test]
    fn cnsa_provider_verifies_only_ecdsa_p384_sha384() {
        let algs = cnsa_provider().signature_verification_algorithms;
        let schemes: Vec<_> = algs.mapping.iter().map(|(s, _)| *s).collect();
        assert_eq!(schemes, [rustls::SignatureScheme::ECDSA_NISTP384_SHA384]);
        for (_, verifiers) in algs.mapping {
            assert!(!verifiers.is_empty());
            for v in *verifiers {
                assert_eq!(v.public_key_alg_id(), rustls::pki_types::alg_id::ECDSA_P384);
                assert_eq!(
                    v.signature_alg_id(),
                    rustls::pki_types::alg_id::ECDSA_SHA384
                );
            }
        }
        // CA chain signatures are held to the same profile.
        assert!(!algs.all.is_empty());
        for v in algs.all {
            assert_eq!(v.public_key_alg_id(), rustls::pki_types::alg_id::ECDSA_P384);
            assert_eq!(
                v.signature_alg_id(),
                rustls::pki_types::alg_id::ECDSA_SHA384
            );
        }
    }

    #[test]
    fn cnsa_client_accepts_p384_server_tls13_and_tls12() {
        let pki = pki_with(P384, P384);
        let n = client_verdict(&pki, false).unwrap();
        assert_eq!(n.suite, rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
        let n = client_verdict(&pki, true).unwrap();
        assert_eq!(
            n.suite,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        );
    }

    /// The CNSA client advertises only `ECDSA_NISTP384_SHA384`, so a
    /// server whose key cannot produce it fails before sending a
    /// `CertificateVerify` (the error is the server's). The verifier itself
    /// is exercised by the `cnsa_server_verifier_*` tests below.
    fn assert_no_common_scheme<T: std::fmt::Debug>(r: &Result<T, rustls::Error>) {
        assert!(
            matches!(
                r,
                Err(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::NoSignatureSchemesInCommon
                ))
            ),
            "{r:?}"
        );
    }

    /// TLS 1.2 form of [`assert_no_common_scheme`]: the server's
    /// `ServerKeyExchange` signer refuses the only offered scheme.
    fn assert_tls12_incompatible_key<T: std::fmt::Debug>(r: &Result<T, rustls::Error>) {
        assert!(
            matches!(r, Err(rustls::Error::General(m)) if m == "incompatible signing key"),
            "{r:?}"
        );
    }

    /// A chain certificate signed with `sig_alg` was refused by the CNSA
    /// verifier, which lists ECDSA-with-SHA-384 as the only supported one.
    fn assert_chain_err<T: std::fmt::Debug>(
        r: &Result<T, rustls::Error>,
        sig_alg: rustls::pki_types::AlgorithmIdentifier,
    ) {
        assert!(
            matches!(
                r,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnsupportedSignatureAlgorithmContext {
                        signature_algorithm_id,
                        supported_algorithms,
                    },
                )) if signature_algorithm_id.as_slice() == sig_alg.as_ref()
                    && supported_algorithms.as_slice()
                        == [rustls::pki_types::alg_id::ECDSA_SHA384]
            ),
            "chain was not refused as UnsupportedSignatureAlgorithmContext (ECDSA_SHA384 only)"
        );
    }

    #[test]
    fn cnsa_client_rejects_p256_server_tls13() {
        assert_no_common_scheme(&client_verdict(&pki_with(P384, P256), false));
    }

    #[test]
    fn cnsa_client_rejects_p256_server_tls12() {
        assert_tls12_incompatible_key(&client_verdict(&pki_with(P384, P256), true));
    }

    #[test]
    fn cnsa_client_rejects_rsa2048_server_tls13() {
        assert_no_common_scheme(&client_verdict(&pki_with(P384, RSA), false));
    }

    /// Already refused before SR-14 (no ECDHE-RSA suite is offered); kept
    /// as a regression guard.
    #[test]
    fn cnsa_client_rejects_rsa2048_server_tls12() {
        let r = client_verdict(&pki_with(P384, RSA), true);
        assert!(
            matches!(
                r,
                Err(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::NoCipherSuitesInCommon
                ))
            ),
            "{r:?}"
        );
    }

    #[test]
    fn cnsa_client_rejects_p521_server_tls13() {
        assert_no_common_scheme(&client_verdict(&pki_with(P384, P521), false));
    }

    #[test]
    fn cnsa_client_rejects_ed25519_server_tls13() {
        assert_no_common_scheme(&client_verdict(&pki_with(P384, ED25519), false));
    }

    #[test]
    fn cnsa_client_rejects_p384_leaf_from_p256_ca() {
        let pki = pki_with(P256, P384);
        let sha256 = rustls::pki_types::alg_id::ECDSA_SHA256;
        assert_chain_err(&client_verdict(&pki, false), sha256);
        assert_chain_err(&client_verdict(&pki, true), sha256);
    }

    #[test]
    fn cnsa_client_rejects_p384_leaf_from_rsa_ca() {
        let pki = pki_with(RSA, P384);
        let rsa = rustls::pki_types::alg_id::RSA_PKCS1_SHA256;
        assert_chain_err(&client_verdict(&pki, false), rsa);
        assert_chain_err(&client_verdict(&pki, true), rsa);
    }

    /// CNSA mTLS server (P-384 server cert) requiring a client cert from
    /// `client_pki`'s CA.
    fn mtls_server(client_pki: &Pki) -> ServerConfig {
        let server_pki = pki_with(P384, P384);
        create_server_config_with(
            server_pki.chain,
            server_pki.key,
            TlsServerOptions {
                min_version: MinTlsVersion::V1_2,
                client_ca: Some(roots(client_pki)),
            },
        )
        .unwrap()
    }

    /// Permissive client (default provider, server cert not checked)
    /// presenting `client_pki`'s leaf.
    fn mtls_client(client_pki: &Pki, v12: bool) -> ClientConfig {
        let versions: &[&'static rustls::SupportedProtocolVersion] = if v12 {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13]
        };
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_client_auth_cert(client_pki.chain.clone(), client_pki.key.clone_key())
            .unwrap()
    }

    /// Server verification is not under test in the mTLS cases.
    #[derive(Debug)]
    struct AcceptAnyServer;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn mtls_verdict(client_pki: &Pki, v12: bool) -> Result<Negotiated, rustls::Error> {
        handshake(mtls_client(client_pki, v12), mtls_server(client_pki))
    }

    #[test]
    fn cnsa_server_accepts_p384_client_cert() {
        let pki = pki_with(P384, P384);
        mtls_verdict(&pki, false).unwrap();
        mtls_verdict(&pki, true).unwrap();
    }

    /// The CNSA server requests only `ECDSA_NISTP384_SHA384`, so a client
    /// whose key cannot produce it sends no certificate and the mandatory
    /// client auth fails. The verifier itself is exercised by the
    /// `cnsa_client_verifier_*` tests below.
    fn assert_no_client_cert<T: std::fmt::Debug>(r: &Result<T, rustls::Error>) {
        assert!(
            matches!(r, Err(rustls::Error::NoCertificatesPresented)),
            "{r:?}"
        );
    }

    #[test]
    fn cnsa_server_rejects_p256_client_cert() {
        let pki = pki_with(P384, P256);
        assert_no_client_cert(&mtls_verdict(&pki, false));
        assert_no_client_cert(&mtls_verdict(&pki, true));
    }

    #[test]
    fn cnsa_server_rejects_rsa2048_client_cert() {
        let pki = pki_with(P384, RSA);
        assert_no_client_cert(&mtls_verdict(&pki, false));
        assert_no_client_cert(&mtls_verdict(&pki, true));
    }

    #[test]
    fn cnsa_server_rejects_p384_client_leaf_from_p256_ca() {
        let pki = pki_with(P256, P384);
        let sha256 = rustls::pki_types::alg_id::ECDSA_SHA256;
        assert_chain_err(&mtls_verdict(&pki, false), sha256);
        assert_chain_err(&mtls_verdict(&pki, true), sha256);
    }

    /// The CNSA client presenting its own P-384 cert to a CNSA mTLS server
    /// still works end to end.
    #[test]
    fn cnsa_client_and_server_mtls_p384() {
        let server_pki = pki_with(P384, P384);
        let client_pki = pki_with(P384, P384);
        let client = create_client_config_with(TlsClientOptions {
            roots: roots(&server_pki),
            min_version: MinTlsVersion::V1_2,
            client_auth: Some((client_pki.chain.clone(), client_pki.key.clone_key())),
        })
        .unwrap();
        let server = create_server_config_with(
            server_pki.chain.clone(),
            server_pki.key.clone_key(),
            TlsServerOptions {
                min_version: MinTlsVersion::V1_2,
                client_ca: Some(roots(&client_pki)),
            },
        )
        .unwrap();
        handshake(client, server).unwrap();
    }

    // ---- SR-14: verifiers built from cnsa_provider(), called directly ----
    //
    // The handshake tests above mostly stop at scheme negotiation. Here the
    // peer is offered every default scheme so it signs with its own key,
    // and the CNSA verifier must refuse that real signature.

    type Verdict = std::sync::Mutex<Option<Result<(), rustls::Error>>>;

    fn record<T>(slot: &Verdict, r: &Result<T, rustls::Error>) {
        *slot.lock().unwrap() = Some(r.as_ref().map(|_| ()).map_err(Clone::clone));
    }

    fn verdict(slot: &Verdict) -> Result<(), rustls::Error> {
        slot.lock().unwrap().clone().expect("verifier not called")
    }

    fn default_schemes() -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn versions(v12: bool) -> Vec<&'static rustls::SupportedProtocolVersion> {
        if v12 {
            vec![&rustls::version::TLS12]
        } else {
            vec![&rustls::version::TLS13]
        }
    }

    fn cnsa_server_verifier(pki: &Pki) -> Arc<rustls::client::WebPkiServerVerifier> {
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots(pki)),
            Arc::new(cnsa_provider()),
        )
        .build()
        .unwrap()
    }

    fn cnsa_client_verifier(pki: &Pki) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
        rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(pki)),
            Arc::new(cnsa_provider()),
        )
        .build()
        .unwrap()
    }

    /// Wraps the CNSA server verifier: records the certificate verdict but
    /// continues, advertises every default scheme, and returns the CNSA
    /// verdict on the handshake signature.
    #[derive(Debug)]
    struct SpyServerVerifier {
        inner: Arc<rustls::client::WebPkiServerVerifier>,
        cert: Verdict,
        sig: Verdict,
    }

    impl rustls::client::danger::ServerCertVerifier for SpyServerVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &rustls::pki_types::ServerName<'_>,
            ocsp: &[u8],
            now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            let r =
                self.inner
                    .verify_server_cert(end_entity, intermediates, server_name, ocsp, now);
            record(&self.cert, &r);
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            let r = self.inner.verify_tls12_signature(message, cert, dss);
            record(&self.sig, &r);
            r
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            let r = self.inner.verify_tls13_signature(message, cert, dss);
            record(&self.sig, &r);
            r
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            default_schemes()
        }
    }

    /// Default-provider client (offers ECDHE-RSA on 1.2) checking `pki`'s
    /// server through a [`SpyServerVerifier`].
    fn spy_client_verdict(
        pki: &Pki,
        v12: bool,
    ) -> (Arc<SpyServerVerifier>, Result<Negotiated, rustls::Error>) {
        let spy = Arc::new(SpyServerVerifier {
            inner: cnsa_server_verifier(pki),
            cert: Verdict::default(),
            sig: Verdict::default(),
        });
        let client = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&versions(v12))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&spy) as _)
        .with_no_client_auth();
        let r = handshake(client, permissive_server(pki, v12));
        (spy, r)
    }

    /// Wraps the CNSA client-certificate verifier the same way.
    #[derive(Debug)]
    struct SpyClientVerifier {
        inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
        cert: Verdict,
        sig: Verdict,
    }

    impl rustls::server::danger::ClientCertVerifier for SpyClientVerifier {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            self.inner.root_hint_subjects()
        }
        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
            let r = self
                .inner
                .verify_client_cert(end_entity, intermediates, now);
            record(&self.cert, &r);
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            let r = self.inner.verify_tls12_signature(message, cert, dss);
            record(&self.sig, &r);
            r
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            let r = self.inner.verify_tls13_signature(message, cert, dss);
            record(&self.sig, &r);
            r
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            default_schemes()
        }
    }

    /// CNSA server (P-384 cert) checking `client_pki`'s client certificate
    /// through a [`SpyClientVerifier`].
    fn spy_mtls_verdict(
        client_pki: &Pki,
        v12: bool,
    ) -> (Arc<SpyClientVerifier>, Result<Negotiated, rustls::Error>) {
        let spy = Arc::new(SpyClientVerifier {
            inner: cnsa_client_verifier(client_pki),
            cert: Verdict::default(),
            sig: Verdict::default(),
        });
        let server_pki = pki_with(P384, P384);
        let server = ServerConfig::builder_with_provider(Arc::new(cnsa_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::clone(&spy) as _)
            .with_single_cert(server_pki.chain, server_pki.key)
            .unwrap();
        let r = handshake(mtls_client(client_pki, v12), server);
        (spy, r)
    }

    /// The handshake signature scheme was not one the CNSA verifier maps.
    fn assert_unmapped_scheme<T: std::fmt::Debug>(r: &Result<T, rustls::Error>) {
        assert!(
            matches!(
                r,
                Err(rustls::Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
                ))
            ),
            "{r:?}"
        );
    }

    #[test]
    fn cnsa_server_verifier_accepts_p384_signature() {
        let pki = pki_with(P384, P384);
        for v12 in [false, true] {
            let (spy, r) = spy_client_verdict(&pki, v12);
            r.unwrap();
            verdict(&spy.cert).unwrap();
            verdict(&spy.sig).unwrap();
        }
    }

    #[test]
    fn cnsa_server_verifier_rejects_p256_and_rsa_signatures() {
        for leaf in [P256, RSA] {
            let pki = pki_with(P384, leaf);
            for v12 in [false, true] {
                let (spy, r) = spy_client_verdict(&pki, v12);
                // The chain itself is P-384 / SHA-384; the end-entity key is
                // refused at the handshake signature.
                verdict(&spy.cert).unwrap();
                assert_unmapped_scheme(&verdict(&spy.sig));
                assert_unmapped_scheme(&r);
            }
        }
    }

    #[test]
    fn cnsa_client_verifier_accepts_p384_signature() {
        let pki = pki_with(P384, P384);
        for v12 in [false, true] {
            let (spy, r) = spy_mtls_verdict(&pki, v12);
            r.unwrap();
            verdict(&spy.cert).unwrap();
            verdict(&spy.sig).unwrap();
        }
    }

    #[test]
    fn cnsa_client_verifier_rejects_p256_and_rsa_signatures() {
        for leaf in [P256, RSA] {
            let pki = pki_with(P384, leaf);
            for v12 in [false, true] {
                let (spy, r) = spy_mtls_verdict(&pki, v12);
                verdict(&spy.cert).unwrap();
                assert_unmapped_scheme(&verdict(&spy.sig));
                assert_unmapped_scheme(&r);
            }
        }
    }

    /// Root (`root_alg`) -> intermediate (`int_alg` key, signed by the root)
    /// -> `localhost` leaf (`leaf_alg` key, signed by the intermediate).
    fn pki_chain3(
        root_alg: &'static rcgen::SignatureAlgorithm,
        int_alg: &'static rcgen::SignatureAlgorithm,
        leaf_alg: &'static rcgen::SignatureAlgorithm,
    ) -> Pki {
        let ca_params = || {
            let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            p
        };
        let root_key = rcgen::KeyPair::generate_for(root_alg).unwrap();
        let root = ca_params().self_signed(&root_key).unwrap();
        let int_key = rcgen::KeyPair::generate_for(int_alg).unwrap();
        let int = ca_params().signed_by(&int_key, &root, &root_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate_for(leaf_alg).unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &int, &int_key)
            .unwrap();
        Pki {
            ca: root.der().clone(),
            chain: vec![leaf.der().clone(), int.der().clone()],
            key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        }
    }

    fn direct_server_cert(pki: &Pki) -> Result<(), rustls::Error> {
        use rustls::client::danger::ServerCertVerifier as _;
        cnsa_server_verifier(pki)
            .verify_server_cert(
                &pki.chain[0],
                &pki.chain[1..],
                &"localhost".try_into().unwrap(),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .map(|_| ())
    }

    fn direct_client_cert(pki: &Pki) -> Result<(), rustls::Error> {
        cnsa_client_verifier(pki)
            .verify_client_cert(
                &pki.chain[0],
                &pki.chain[1..],
                rustls::pki_types::UnixTime::now(),
            )
            .map(|_| ())
    }

    #[test]
    fn cnsa_verifiers_accept_p384_three_level_chain() {
        let pki = pki_chain3(P384, P384, P384);
        direct_server_cert(&pki).unwrap();
        direct_client_cert(&pki).unwrap();
        client_verdict(&pki, false).unwrap();
        client_verdict(&pki, true).unwrap();
        mtls_verdict(&pki, false).unwrap();
        mtls_verdict(&pki, true).unwrap();
    }

    /// The intermediate is signed P-384 / SHA-384 by the root, but its own
    /// key is P-256, so the leaf carries a P-256 / SHA-256 signature.
    #[test]
    fn cnsa_verifiers_reject_p256_intermediate_in_p384_chain() {
        let pki = pki_chain3(P384, P256, P384);
        let sha256 = rustls::pki_types::alg_id::ECDSA_SHA256;
        assert_chain_err(&direct_server_cert(&pki), sha256);
        assert_chain_err(&direct_client_cert(&pki), sha256);
        assert_chain_err(&client_verdict(&pki, false), sha256);
        assert_chain_err(&client_verdict(&pki, true), sha256);
        assert_chain_err(&mtls_verdict(&pki, false), sha256);
        assert_chain_err(&mtls_verdict(&pki, true), sha256);
    }

    /// Records the `signature_algorithms` a CNSA client sends.
    #[derive(Debug)]
    struct HelloRecorder {
        key: Arc<rustls::sign::CertifiedKey>,
        seen: std::sync::Mutex<Vec<rustls::SignatureScheme>>,
    }

    impl rustls::server::ResolvesServerCert for HelloRecorder {
        fn resolve(
            &self,
            hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            *self.seen.lock().unwrap() = hello.signature_schemes().to_vec();
            Some(Arc::clone(&self.key))
        }
    }

    /// Records the schemes a CNSA server puts in `CertificateRequest`.
    #[derive(Debug)]
    struct CertRequestRecorder {
        key: Arc<rustls::sign::CertifiedKey>,
        seen: std::sync::Mutex<Vec<rustls::SignatureScheme>>,
    }

    impl rustls::client::ResolvesClientCert for CertRequestRecorder {
        fn resolve(
            &self,
            _: &[&[u8]],
            schemes: &[rustls::SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            *self.seen.lock().unwrap() = schemes.to_vec();
            Some(Arc::clone(&self.key))
        }
        fn has_certs(&self) -> bool {
            true
        }
    }

    fn certified_key(pki: &Pki) -> Arc<rustls::sign::CertifiedKey> {
        let key = rustls::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(pki.key.clone_key())
            .unwrap();
        Arc::new(rustls::sign::CertifiedKey::new(pki.chain.clone(), key))
    }

    #[test]
    fn cnsa_client_config_advertises_only_p384_sha384() {
        let pki = pki_with(P384, P384);
        for (min, v12) in [(MinTlsVersion::V1_3, false), (MinTlsVersion::V1_2, true)] {
            let rec = Arc::new(HelloRecorder {
                key: certified_key(&pki),
                seen: std::sync::Mutex::default(),
            });
            let server = ServerConfig::builder_with_provider(Arc::new(cnsa_provider()))
                .with_protocol_versions(&versions(v12))
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::clone(&rec) as _);
            handshake(cnsa_client(&pki, min), server).unwrap();
            assert_eq!(
                *rec.seen.lock().unwrap(),
                [rustls::SignatureScheme::ECDSA_NISTP384_SHA384]
            );
        }
    }

    #[test]
    fn cnsa_server_config_requests_only_p384_sha384() {
        let client_pki = pki_with(P384, P384);
        for v12 in [false, true] {
            let rec = Arc::new(CertRequestRecorder {
                key: certified_key(&client_pki),
                seen: std::sync::Mutex::default(),
            });
            let client = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_protocol_versions(&versions(v12))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_client_cert_resolver(Arc::clone(&rec) as _);
            handshake(client, mtls_server(&client_pki)).unwrap();
            assert_eq!(
                *rec.seen.lock().unwrap(),
                [rustls::SignatureScheme::ECDSA_NISTP384_SHA384]
            );
        }
    }

    // ---- Key file checks (POA&M-164) and curve checks (POA&M-166) ----

    #[cfg(unix)]
    mod key_file {
        use super::super::*;
        use std::os::unix::fs::PermissionsExt;

        fn write_key(dir: &Path, name: &str, pem: &str, mode: u32) -> std::path::PathBuf {
            let p = dir.join(name);
            std::fs::write(&p, pem).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        }

        fn pem_for(alg: &'static rcgen::SignatureAlgorithm) -> String {
            rcgen::KeyPair::generate_for(alg).unwrap().serialize_pem()
        }

        fn p384() -> String {
            pem_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        }

        fn err_reason(r: TransportResult<PrivateKeyDer<'static>>) -> String {
            match r {
                Err(TransportError::TlsCertificateError { reason }) => reason,
                Err(e) => format!("unexpected error {e}"),
                Ok(_) => "unexpectedly accepted".to_owned(),
            }
        }

        #[test]
        fn mode_0600_and_0400_accepted() {
            let d = tempfile::tempdir().unwrap();
            let pem = p384();
            for (i, mode) in [0o600, 0o400].into_iter().enumerate() {
                let p = write_key(d.path(), &format!("k{i}.pem"), &pem, mode);
                load_private_key(&p).unwrap();
            }
        }

        #[test]
        fn group_or_world_mode_rejected() {
            let d = tempfile::tempdir().unwrap();
            let pem = p384();
            for (i, mode) in [0o644, 0o640, 0o604, 0o660].into_iter().enumerate() {
                let p = write_key(d.path(), &format!("k{i}.pem"), &pem, mode);
                assert!(err_reason(load_private_key(&p)).contains("group or other"));
            }
        }

        #[test]
        fn symlink_rejected() {
            let d = tempfile::tempdir().unwrap();
            let real = write_key(d.path(), "real.pem", &p384(), 0o600);
            let link = d.path().join("link.pem");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(err_reason(load_private_key(&link)).contains("symlink"));
        }

        #[test]
        fn directory_and_fifo_rejected() {
            let d = tempfile::tempdir().unwrap();
            let sub = d.path().join("dir.pem");
            std::fs::create_dir(&sub).unwrap();
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(err_reason(load_private_key(&sub)).contains("regular file"));

            let fifo = d.path().join("fifo.pem");
            nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
            assert!(err_reason(load_private_key(&fifo)).contains("regular file"));
        }

        #[test]
        fn oversize_rejected() {
            let d = tempfile::tempdir().unwrap();
            let big = "A".repeat(usize::try_from(MAX_KEY_FILE_BYTES).unwrap() + 1);
            let p = write_key(d.path(), "big.pem", &big, 0o600);
            assert!(err_reason(load_private_key(&p)).contains("too large"));
        }

        #[test]
        fn wrong_owner_rejected() {
            // Only root can create a file owned by another user.
            if !nix::unistd::geteuid().is_root() {
                eprintln!("Skipping wrong-owner test: not running as root");
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let p = write_key(d.path(), "k.pem", &p384(), 0o600);
            let nobody = nix::unistd::Uid::from_raw(65534);
            nix::unistd::chown(&p, Some(nobody), None).unwrap();
            assert!(err_reason(load_private_key(&p)).contains("owned"));
        }

        #[test]
        fn curve_enforced() {
            let d = tempfile::tempdir().unwrap();
            let p256 = write_key(
                d.path(),
                "p256.pem",
                &pem_for(&rcgen::PKCS_ECDSA_P256_SHA256),
                0o600,
            );
            let p384k = write_key(d.path(), "p384.pem", &p384(), 0o600);
            let p521 = write_key(
                d.path(),
                "p521.pem",
                &pem_for(&rcgen::PKCS_ECDSA_P521_SHA512),
                0o600,
            );

            assert!(err_reason(load_private_key(&p256)).contains("P-256"));
            load_private_key(&p384k).unwrap();
            load_private_key(&p521).unwrap();

            load_private_key_with(&p384k, RequiredKeyCurve::P384).unwrap();
            assert!(
                err_reason(load_private_key_with(&p521, RequiredKeyCurve::P384)).contains("P-521")
            );
            load_private_key_with(&p521, RequiredKeyCurve::P521).unwrap();
            assert!(
                err_reason(load_private_key_with(&p384k, RequiredKeyCurve::P521)).contains("P-384")
            );
        }

        #[test]
        fn rsa_rejected() {
            let d = tempfile::tempdir().unwrap();
            let p = write_key(
                d.path(),
                "rsa.pem",
                &pem_for(&rcgen::PKCS_RSA_SHA256),
                0o600,
            );
            assert!(err_reason(load_private_key(&p)).contains("non-EC"));
        }

        #[test]
        fn garbage_rejected() {
            let d = tempfile::tempdir().unwrap();
            let p = write_key(d.path(), "junk.pem", "not a key", 0o600);
            assert!(load_private_key(&p).is_err());
        }
    }

    // ---- Dual-stack peer canonicalisation ----
    // NIST 800-53 Rev5: SC-7, SI-10
    // An IPv4 client on a dual-stack `[::]` listener is reported with its
    // plain IPv4 address (not `::ffff:a.b.c.d`).

    /// Binds a TLS listener on `[::]:0`; `None` when the host has no IPv6.
    async fn dual_stack_listener(pki: &Pki) -> Option<TlsListener> {
        let server = create_server_config(pki.chain.clone(), pki.key.clone_key()).unwrap();
        let cfg = ListenerConfig::new(
            SbcSocketAddr::new_v6(std::net::Ipv6Addr::UNSPECIFIED, 0),
            TransportType::Tls,
        );
        match TlsListener::bind(cfg, Arc::new(server)).await {
            Ok(l) => Some(l),
            Err(e) => {
                crate::skip_dual_stack(&format!("cannot bind [::]:0 ({e})"));
                None
            }
        }
    }

    #[tokio::test]
    async fn tls_dual_stack_accept_tcp_reports_plain_ipv4_peer() {
        use std::net::{IpAddr, Ipv4Addr};
        let pki = pki();
        let Some(listener) = dual_stack_listener(&pki).await else {
            return;
        };
        let port = listener.local_addr().port();
        let accept = tokio::spawn(async move { listener.accept_tcp().await });
        let connect = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
        )
        .await;
        let Ok(Ok(_client)) = connect else {
            crate::skip_dual_stack("127.0.0.1 cannot reach a [::] listener (no dual-stack)");
            accept.abort();
            return;
        };
        let (_stream, peer) = accept.await.unwrap().unwrap();
        assert!(
            peer.is_ipv4(),
            "accept_tcp peer must be plain IPv4, got {peer}"
        );
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn tls_dual_stack_accept_reports_plain_ipv4_peer() {
        use std::net::{IpAddr, Ipv4Addr};
        let pki = pki();
        let Some(listener) = dual_stack_listener(&pki).await else {
            return;
        };
        let port = listener.local_addr().port();
        let accept = tokio::spawn(async move { listener.accept().await });
        // Probe dual-stack reachability with the real client; a refused
        // connection means the host maps no IPv4 onto `[::]`.
        let client_cfg = Arc::new(create_client_config(roots(&pki)).unwrap());
        let v4 = SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, port);
        let connect = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TlsTransport::connect(v4, "localhost", client_cfg),
        )
        .await;
        let client = match connect {
            Ok(Ok(c)) => c,
            Ok(Err(TransportError::ConnectFailed { reason, .. })) => {
                crate::skip_dual_stack(&format!(
                    "127.0.0.1 cannot reach a [::] listener ({reason})"
                ));
                accept.abort();
                return;
            }
            other => other
                .expect("TLS connect timed out")
                .expect("TLS connect failed"),
        };
        let (server, peer) = accept.await.unwrap().unwrap();
        assert!(peer.is_ipv4(), "accept peer must be plain IPv4, got {peer}");
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let transport_peer = *server.peer_addr();
        assert!(
            transport_peer.is_ipv4(),
            "transport peer_addr must be plain IPv4, got {transport_peer}"
        );
        client.send(b"x", &v4).await.unwrap();
        let msg = server.recv().await.unwrap();
        assert!(
            msg.source.is_ipv4(),
            "received message source must be plain IPv4, got {}",
            msg.source
        );
    }

    // SR-22 (NIST 800-53 Rev5: SC-5): the server transport takes its peer
    // address from `accept_tcp`, not from `getpeername` after the
    // handshake, so a peer that resets right after the handshake cannot
    // fail the connection. A sentinel peer shows the socket is not asked.
    #[tokio::test]
    async fn tls_complete_handshake_uses_accept_peer() {
        use std::net::Ipv4Addr;
        let pki = pki();
        let server = create_server_config(pki.chain.clone(), pki.key.clone_key()).unwrap();
        let listener = Arc::new(
            TlsListener::bind(
                ListenerConfig::new(
                    SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0),
                    TransportType::Tls,
                ),
                Arc::new(server),
            )
            .await
            .unwrap(),
        );
        let addr = *listener.local_addr();
        let sentinel = SbcSocketAddr::new_v4(Ipv4Addr::new(192, 0, 2, 77), 40_000);
        let l = Arc::clone(&listener);
        let accept = tokio::spawn(async move {
            let (tcp, _peer) = l.accept_tcp().await?;
            l.complete_handshake(tcp, sentinel).await
        });
        let client_cfg = Arc::new(create_client_config(roots(&pki)).unwrap());
        let _client = TlsTransport::connect(addr, "localhost", client_cfg)
            .await
            .unwrap();
        let server = accept.await.unwrap().unwrap();
        assert_eq!(*server.peer_addr(), sentinel);
        assert_eq!(server.local_addr().port(), addr.port());
    }

    // ---- SR-57: per-connection read buffer is one read chunk ----
    // NIST 800-53 Rev5: SC-5, SC-6

    /// Upper bound on the resident read buffer per connection (one 4 KiB
    /// chunk, with allocator slack).
    const QA_MAX_RESIDENT_READ_BUFFER: usize = 8 * 1024;

    async fn qa_tls_pair() -> (TlsTransport, TlsTransport, SbcSocketAddr) {
        let pki = pki();
        let server_cfg = create_server_config(pki.chain.clone(), pki.key.clone_key()).unwrap();
        let cfg = ListenerConfig::new(
            SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 0),
            TransportType::Tls,
        );
        let listener = TlsListener::bind(cfg, Arc::new(server_cfg)).await.unwrap();
        let addr = *listener.local_addr();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client_cfg = Arc::new(create_client_config(roots(&pki)).unwrap());
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TlsTransport::connect(addr, "localhost", client_cfg),
        )
        .await
        .expect("TLS connect timed out")
        .unwrap();
        let server = accept.await.unwrap();
        (client, server, addr)
    }

    async fn qa_tls_recv_exact(t: &TlsTransport, len: usize) -> Vec<u8> {
        let mut got = Vec::with_capacity(len);
        while got.len() < len {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), t.recv())
                .await
                .expect("recv timed out")
                .unwrap();
            got.extend_from_slice(&msg.data);
        }
        got
    }

    #[tokio::test]
    async fn tls_transport_read_buffer_is_one_chunk() {
        let (client, server, addr) = qa_tls_pair().await;
        for (name, t) in [("client", &client), ("server", &server)] {
            let cap = t.read_buffer.lock().await.capacity();
            assert!(
                cap <= QA_MAX_RESIDENT_READ_BUFFER,
                "{name} TLS read buffer after handshake is {cap} bytes, want <= {QA_MAX_RESIDENT_READ_BUFFER}"
            );
        }

        let payload = vec![b'a'; 4096];
        client.send(&payload, &addr).await.unwrap();
        let got = qa_tls_recv_exact(&server, payload.len()).await;
        assert_eq!(got, payload);
        let cap = server.read_buffer.lock().await.capacity();
        assert!(
            cap <= QA_MAX_RESIDENT_READ_BUFFER,
            "server TLS read buffer after a 4 KiB round trip is {cap} bytes, want <= {QA_MAX_RESIDENT_READ_BUFFER}"
        );
    }

    // Regression guard for reading straight into the chunk buffer over TLS.
    #[tokio::test]
    async fn tls_recv_large_message_in_chunks_is_intact() {
        let (client, server, addr) = qa_tls_pair().await;
        let payload: Vec<u8> = (0..60 * 1024_u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        client.send(&payload, &addr).await.unwrap();
        let got = qa_tls_recv_exact(&server, payload.len()).await;
        assert!(got == payload, "60 KiB TLS payload corrupted or reordered");
    }
}
