//! Sans-I/O DTLS 1.2 association for DTLS-SRTP (RFC 6347, RFC 5764).
//!
//! [`DtlsAssociation`] is a state machine. It owns no socket, spawns nothing
//! and never sleeps: the caller feeds it datagrams and the current time, and
//! drains datagrams to send, a next-timeout and events.
//!
//! ```text
//! loop {
//!     while let Some(datagram) = assoc.poll_transmit() { socket.send(datagram) }
//!     while let Some(event) = assoc.poll_event() { ... }
//!     wait for a datagram (-> handle_datagram) or assoc.poll_timeout() (-> handle_timeout)
//! }
//! ```
//!
//! ## Profile (CNSA 2.0, no negotiation beyond it)
//!
//! - DTLS 1.2 only; `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` only.
//! - ECDHE on secp384r1 only; signatures `ecdsa_secp384r1_sha384` only.
//! - `use_srtp` with `SRTP_AEAD_AES_256_GCM` only (RFC 7714), no MKI.
//! - Extended master secret required (RFC 7627).
//! - The peer is always authenticated. As server we always request and
//!   require the client's certificate, so the handshake is mutually
//!   authenticated. As client we authenticate the server and answer its
//!   `CertificateRequest`; a server that sends none still completes, and we
//!   are then not authenticated to it
//!   ([`DtlsAssociation::client_certificate_requested`] tells which).
//! - No session IDs, resumption, tickets, compression, renegotiation or
//!   application data.
//!
//! Anything else fails the association; nothing falls back.
//!
//! ## Peer authentication (RFC 5763 §5, §6.7.1; RFC 8122 §5)
//!
//! In this order: the peer's leaf certificate must match one of the SDP
//! fingerprints given at construction; its key must be ECDSA P-384; the peer
//! must prove possession of that key (`ServerKeyExchange` signature or
//! `CertificateVerify`). The certificate's chain, self-signature and
//! validity period are not checked: the SDP fingerprint, carried by the
//! signalling channel, is the trust anchor.
//!
//! SRTP keys are exported only after the peer's `Finished` has verified.
//!
//! ## NIST 800-53 Rev5
//!
//! - **SC-8 / SC-8(1)**: record protection for the handshake's own traffic
//!   and key establishment for SRTP.
//! - **SC-12**: ECDHE P-384 key establishment, RFC 5764 key export, secrets
//!   wiped when no longer needed.
//! - **SC-13**: every primitive and the TLS 1.2 KDF run in the FIPS module
//!   through `uc-crypto`. The module's approved-service indicator covers the
//!   KDF for the extended master secret only; key expansion, `Finished` and
//!   the RFC 5705 exporter compute inside the module without it (see
//!   [`uc_crypto::tls12`], POA&M-332). The protocol logic in this file is
//!   project code and is not part of the FIPS module.
//! - **SC-23 / IA-3**: fingerprint binding, peer authentication (mutual
//!   whenever we are the server or the server asks for our certificate),
//!   proof of possession, `Finished` verification, replay window.
//! - **SC-5**: stateless cookie, bounded reassembly/transcript/queues, silent
//!   discard of bad records, hard handshake budget. See "Unauthenticated
//!   input during the handshake" below for what a spoofed datagram can and
//!   cannot do.
//! - **SI-10**: all peer input goes through bounds-checked parsers.
//! - **AU-2 / AU-3**: this library emits no audit records. Its driver MUST
//!   write one structured record for every [`AssociationEvent::Connected`]
//!   and [`AssociationEvent::Failed`], with the role, the [`FailureCause`],
//!   the presented fingerprint and whether the handshake was mutually
//!   authenticated. The soft client's driver
//!   (`client-sip-ua/src/dtls_driver.rs`) writes them as structured
//!   `tracing` records: the client has no audit sink, and `uc-audit` is the
//!   SBC's event log. A cause that arose during
//!   the handshake before the peer's `Finished` rests on unauthenticated
//!   input (see below): record it as the reason the handshake failed, not
//!   as proof of what the peer sent; the same holds for the presented
//!   fingerprint.
//!
//! ## Unauthenticated input during the handshake
//!
//! Until the peer's `ChangeCipherSpec`, records are plaintext and anyone who
//! can send from the peer's address can forge them. The cases below cannot
//! end the handshake by themselves:
//!
//! - A plaintext fragment that breaks a reassembly rule or limit is dropped
//!   and counted ([`AssociationStats::fragments_rejected`]), together with
//!   the rest of its datagram. Reassembly slots cannot be pinned (see
//!   [`crate::reassembly`]). A genuine message over a limit is dropped the
//!   same way, so that handshake ends as [`FailureCause::Timeout`] with the
//!   counter as its only trace.
//! - A `HelloRequest` fragment is dropped and counted before reassembly
//!   (RFC 5246 §7.4.1.1): it never holds a slot or uses up a `message_seq`.
//! - A plaintext message that is refused before it changed anything is
//!   thrown away and counted without using up its `message_seq`, so the
//!   genuine message can still take that place. This covers a message of a
//!   type the current state does not accept, one in the wrong epoch, one
//!   that does not parse or is outside the profile, a `Certificate` that
//!   fails the fingerprint or key check, and a `ServerKeyExchange` or
//!   `CertificateVerify` whose signature does not verify. The failure it
//!   would have caused is only remembered. Once one datagram has had more
//!   than `FUTURE_WINDOW + 1` (5) messages refused, the rest of that
//!   datagram is ignored.
//! - A plaintext fatal alert or `close_notify` is likewise only remembered.
//!
//! A remembered cause (the first one seen) fails the handshake, with that
//! [`FailureCause`], if no further message from the peer is accepted before
//! the retransmission timer next expires (or the budget ends); if the
//! handshake moves on, it is forgotten. A genuine alert, wrong message, bad
//! certificate or bad signature is therefore still reported, at most one
//! retransmission interval late. Alerts and messages in epoch 1 are
//! authenticated and act at once, as do the hard limits (messages processed,
//! transcript size, budget): every message delivered in sequence, accepted
//! or thrown away, counts against the 64-message limit. A single datagram
//! can add at most 6 refused messages to that count at once, plus messages
//! it parks ahead (at most one per later sequence number) that are refused
//! afterwards, so fewer than nine forged datagrams cannot use it up.
//!
//! Nothing here can complete a handshake or change the exported keys: only
//! accepted messages enter the transcript, `Finished` is accepted from
//! epoch 1 only, and it verifies only if both sides hold the same transcript.
//!
//! Residual: what remains is a forged message of a type the current state
//! accepts and that cannot be authenticated on its own (`ServerHello`,
//! `HelloVerifyRequest`, `CertificateRequest`, `ServerHelloDone`,
//! `ClientKeyExchange`), at or parked ahead of its sequence number: it is
//! processed as the peer's and ends the handshake (at once for a
//! `ClientKeyExchange` whose point is invalid, otherwise when a later check
//! or `Finished` fails). A forged alert or refused message also ends the
//! handshake if the retransmission timer next expires before another
//! message is accepted (loss of either flight, or a reply slower than the
//! interval). Forged complete in-sequence messages spread over nine
//! or more separate datagrams (at most 6 are refused at once per datagram) can
//! reach the 64-message limit, which ends the handshake at once. All of
//! these fail closed.
//!
//! POAM: POA&M-334 (SC-5) -- spoofed-source plaintext can still end a
//! handshake in the residual cases above: a forged in-state message that
//! cannot be authenticated on its own, a forged alert or refused message
//! followed by a timer expiry before the next accepted message, or forged
//! complete in-sequence messages in nine or more separate datagrams, which
//! can reach the 64-message limit and end the handshake at once. DTLS 1.2
//! has no protection for epoch 0.
//!
//! ## Driver contract
//!
//! - One association serves one remote transport address. The driver passes
//!   only datagrams from that address to [`DtlsAssociation::handle_datagram`];
//!   the association cannot see addresses. A driver that knows the address
//!   before the handshake SHOULD also set [`AssociationConfig::peer_binding`]
//!   so the cookie covers it (RFC 6347 §4.2.1).
//! - The handshake budget starts when the association is constructed:
//!   construct it when the path is ready to carry the handshake.
//! - A fragmented first `ClientHello` is not accepted by the server role
//!   (no state is kept before the cookie returns); at the smallest accepted
//!   MTU ([`crate::flight::MIN_MTU`]) our own `ClientHello` never fragments.
//!
//! The soft client drives this association on its media socket
//! (`client-sip-ua/src/dtls_driver.rs`), one driver task per call.
//!
//! POAM: POA&M-333 (SC-23) -- RFC 8844 (`external_id_hash` unknown-key-share
//! protection) is not implemented.

#![deny(clippy::indexing_slicing)]

use crate::error::{DtlsError, DtlsResult};
use crate::fingerprint::CertificateFingerprint;
use crate::flight::{
    DEFAULT_MTU, Flight, MAX_MTU, MAX_RTO, MIN_MTU, RetransmitTimer, handshake_message_bytes,
};
use crate::key_schedule::{
    COOKIE_LEN, COOKIE_SECRET_LEN, MAX_PEER_BINDING_LEN, MasterSecret, Transcript, compute_cookie,
    server_key_exchange_signed_content,
};
use crate::reassembly::{
    CompleteMessage, FUTURE_WINDOW, FragmentOutcome, MAX_CERTIFICATE_MESSAGE_LEN, MAX_MESSAGE_LEN,
    Reassembler,
};
use crate::record::{
    AssociationRecordLayer, ContentType, DTLS_1_0_VERSION, DTLS_1_2_VERSION, DatagramRecords,
    RecordDiscard, RecordView, encode_plaintext_record,
};
use crate::spki::{P384_POINT_LEN, extract_p384_public_key};
use crate::wire::WireError;
use crate::wire::alert::{self, Alert};
use crate::wire::extensions::{Extensions, UseSrtp};
use crate::wire::handshake_msg::{
    CertificateMsg, CertificateRequest, ClientHello, ClientKeyExchange, DigitallySigned,
    EcdheParams, Finished, HT_CERTIFICATE, HT_CERTIFICATE_REQUEST, HT_CERTIFICATE_VERIFY,
    HT_CLIENT_HELLO, HT_CLIENT_KEY_EXCHANGE, HT_FINISHED, HT_HELLO_REQUEST,
    HT_HELLO_VERIFY_REQUEST, HT_SERVER_HELLO, HT_SERVER_HELLO_DONE, HT_SERVER_KEY_EXCHANGE,
    HandshakeHeader, HelloVerifyRequest, RANDOM_LEN, ServerHello,
};
use crate::wire::reader::Reader;
use crate::{DtlsRole, SrtpKeyingMaterial};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uc_crypto::ecdh::P384EphemeralKeyPair;
use uc_crypto::ecdsa::{P384KeyPair, verify_p384};
use zeroize::Zeroizing;

/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (RFC 5289).
const CIPHER_SUITE: u16 = 0xC02C;
/// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (RFC 5746 §3.3).
const SCSV_RENEGOTIATION_INFO: u16 = 0x00FF;
/// `secp384r1` named group (RFC 8422 §5.1.1).
const GROUP_SECP384R1: u16 = 24;
/// `ecdsa_secp384r1_sha384`: hash SHA-384 (5), signature ECDSA (3).
const SCHEME_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// `SRTP_AEAD_AES_256_GCM` (RFC 7714 §14.2).
const SRTP_AEAD_AES_256_GCM: u16 = 0x0008;
/// `ecdsa_sign` client certificate type (RFC 8422 §5.5).
const CERT_TYPE_ECDSA_SIGN: u8 = 64;
/// Null compression.
const COMPRESSION_NULL: u8 = 0;
/// Uncompressed EC point format.
const POINT_FORMAT_UNCOMPRESSED: u8 = 0;

/// `HelloVerifyRequest`s a client accepts before giving up.
const MAX_HELLO_VERIFY_REQUESTS: u8 = 2;
/// Handshake messages processed per association before it fails.
const MAX_HANDSHAKE_MESSAGES: u32 = 64;
/// Plaintext messages that one datagram may have refused before the rest
/// of it is ignored. Forged messages parked ahead (at most
/// [`FUTURE_WINDOW`], plus one at the expected sequence number) are refused
/// in the middle of the genuine flight's datagram, which therefore must
/// survive that many refusals; the next one cannot be explained that way.
const MAX_REFUSALS_PER_DATAGRAM: u16 = FUTURE_WINDOW + 1;
/// `HelloVerifyRequest`s a server sends per second.
const MAX_HELLO_VERIFY_PER_SECOND: u32 = 4;
/// Datagrams held for the caller to send; more are dropped and counted.
const MAX_QUEUED_DATAGRAMS: usize = 64;
/// Events held for the caller.
const MAX_QUEUED_EVENTS: usize = 8;

/// Default first retransmission interval (RFC 6347 §4.2.4.1).
pub const DEFAULT_INITIAL_RTO: Duration = Duration::from_secs(1);
/// Default total time allowed for the handshake.
pub const DEFAULT_HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);
/// Largest handshake budget accepted.
pub const MAX_HANDSHAKE_BUDGET: Duration = Duration::from_secs(60);
/// Smallest first retransmission interval accepted.
///
/// The hold-off between peer-triggered retransmissions is half the
/// configured interval, so this is also what keeps that hold-off from
/// shrinking to nothing.
pub const MIN_INITIAL_RTO: Duration = Duration::from_millis(50);
/// How long a server keeps its final flight after completing.
///
/// It answers retransmissions of the client's last flight for twice the
/// maximum segment lifetime (RFC 6347 §4.2.4).
pub const FINAL_FLIGHT_RETENTION: Duration = Duration::from_secs(240);
/// Times one flight is resent because the peer retransmitted, on top of the
/// timer-driven retransmissions.
const MAX_PEER_TRIGGERED_RESENDS: u8 = 6;

/// Local certificate chain and signing key.
///
/// The key is shared by reference count; its bytes are never copied here.
#[derive(Clone)]
pub struct DtlsCredentials {
    chain: Vec<Vec<u8>>,
    certificate_message: Vec<u8>,
    fingerprint: CertificateFingerprint,
    key: Arc<P384KeyPair>,
}

impl DtlsCredentials {
    /// Creates credentials from a DER certificate chain (leaf first) and the
    /// leaf's P-384 key pair.
    ///
    /// # Errors
    /// Returns [`DtlsError::InvalidConfig`] if the chain is empty or too
    /// large for one `Certificate` message, or the leaf's public key is not
    /// the P-384 key of `key`.
    pub fn new(certificate_chain: Vec<Vec<u8>>, key: Arc<P384KeyPair>) -> DtlsResult<Self> {
        let invalid = |reason: &str| DtlsError::InvalidConfig {
            reason: reason.to_string(),
        };
        let leaf = certificate_chain
            .first()
            .ok_or_else(|| invalid("certificate chain is empty"))?;
        let leaf_key = extract_p384_public_key(leaf)
            .map_err(|_| invalid("leaf certificate does not hold an ECDSA P-384 key"))?;
        if leaf_key.as_slice() != key.public_key_bytes() {
            return Err(invalid("leaf certificate does not match the private key"));
        }
        let mut certificate_message = Vec::new();
        CertificateMsg {
            chain: certificate_chain.clone(),
        }
        .encode(&mut certificate_message)
        .map_err(|_| invalid("certificate chain cannot be encoded"))?;
        if certificate_message.len() > MAX_CERTIFICATE_MESSAGE_LEN {
            return Err(invalid("certificate chain is too large"));
        }
        let fingerprint = CertificateFingerprint::from_certificate_sha384(leaf);
        Ok(Self {
            chain: certificate_chain,
            certificate_message,
            fingerprint,
            key,
        })
    }

    /// The DER certificate chain, leaf first.
    #[must_use]
    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    /// SHA-384 fingerprint of the leaf certificate, for the SDP
    /// `a=fingerprint` attribute.
    #[must_use]
    pub const fn fingerprint(&self) -> &CertificateFingerprint {
        &self.fingerprint
    }
}

impl std::fmt::Debug for DtlsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsCredentials")
            .field("certificates", &self.chain.len())
            .field("fingerprint", &self.fingerprint)
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Configuration of one association.
#[derive(Debug, Clone)]
pub struct AssociationConfig {
    /// Our DTLS role.
    pub role: DtlsRole,
    /// Our certificate chain and key.
    pub credentials: DtlsCredentials,
    /// Fingerprints signalled for the peer in SDP. The peer's certificate
    /// must match at least one. An empty set is refused at construction.
    pub peer_fingerprints: Vec<CertificateFingerprint>,
    /// Largest datagram to send, in bytes.
    pub mtu: u16,
    /// First retransmission interval, [`MIN_INITIAL_RTO`] to 8 s; doubles
    /// on each expiry up to 8 s.
    pub initial_rto: Duration,
    /// Total time allowed for the handshake, counted from construction.
    pub handshake_budget: Duration,
    /// Opaque bytes identifying the peer's transport address (for example
    /// its IP address and port), at most 64 bytes; mixed into the stateless
    /// cookie (RFC 6347 §4.2.1). Empty by default: the cookie then shows
    /// return routability only to whatever single remote the driver feeds
    /// the association from, which the driver must keep fixed.
    pub peer_binding: Vec<u8>,
}

impl AssociationConfig {
    /// Creates a configuration with the default MTU (1200), initial
    /// retransmission interval (1 s) and handshake budget (10 s).
    #[must_use]
    pub const fn new(
        role: DtlsRole,
        credentials: DtlsCredentials,
        peer_fingerprints: Vec<CertificateFingerprint>,
    ) -> Self {
        Self {
            role,
            credentials,
            peer_fingerprints,
            mtu: DEFAULT_MTU,
            initial_rto: DEFAULT_INITIAL_RTO,
            handshake_budget: DEFAULT_HANDSHAKE_BUDGET,
            peer_binding: Vec::new(),
        }
    }
}

/// Why an association failed.
///
/// Fixed values, safe to log. The one peer-supplied datum is the number in
/// [`FailureCause::PeerAlert`]: the one-byte alert description the peer
/// sent, never text.
///
/// Of the causes that depend on peer input, only
/// [`FailureCause::FinishedMismatch`] and a [`FailureCause::PeerAlert`]
/// received after the peer's `ChangeCipherSpec` are known to rest on
/// authenticated input; any other, like the presented fingerprint before
/// the peer's `Finished` has verified, may stem from forged plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureCause {
    /// The handshake did not finish within the budget.
    Timeout,
    /// The peer's certificate matches none of the SDP fingerprints.
    FingerprintMismatch,
    /// The peer sent no certificate, or one without an ECDSA P-384 key.
    BadCertificate,
    /// The peer's proof of possession is missing or does not verify.
    BadSignature,
    /// The peer's `Finished` does not verify.
    FinishedMismatch,
    /// The peer requires a version, cipher suite, group or signature scheme
    /// outside the profile.
    UnsupportedParameters,
    /// `use_srtp` with `SRTP_AEAD_AES_256_GCM` and no MKI was not negotiated.
    NoSrtpProfile,
    /// The peer does not support the extended master secret.
    NoExtendedMasterSecret,
    /// The peer sent a fatal alert (or closed during the handshake); the
    /// value is the alert description.
    PeerAlert(u8),
    /// The peer broke the protocol or a resource limit.
    ProtocolViolation,
    /// A local operation failed.
    Internal,
}

/// Something the caller must act on.
#[derive(Debug)]
pub enum AssociationEvent {
    /// The handshake completed and the peer is authenticated. Emitted once;
    /// the keys are moved out and are not kept by the association.
    Connected {
        /// SRTP master keys and salts (RFC 5764 §4.2).
        keys: SrtpKeyingMaterial,
    },
    /// The association failed. Terminal.
    Failed {
        /// Why.
        cause: FailureCause,
    },
    /// The peer sent `close_notify` after the handshake. Terminal.
    PeerClosed,
}

/// Counters for diagnostics. All saturate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AssociationStats {
    /// Flights retransmitted (timer or peer-triggered).
    pub retransmits: u32,
    /// Records or datagrams dropped (malformed, wrong epoch or version,
    /// failed authentication, unexpected content).
    pub records_discarded: u32,
    /// Records dropped by the replay window.
    pub replays: u32,
    /// Handshake fragments dropped without failing the association.
    pub fragments_rejected: u32,
    /// Datagrams not queued because the caller had not drained
    /// [`DtlsAssociation::poll_transmit`] (the queue holds 64).
    pub transmit_dropped: u32,
    /// `ChangeCipherSpec` or epoch-1 records that arrived before the
    /// handshake was ready for them (reordering). They are dropped, not
    /// buffered; the peer's retransmission recovers.
    pub early_ccs_or_finished: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Client: `ClientHello` sent; expecting `HelloVerifyRequest` or `ServerHello`.
    ClientWaitServerHello,
    /// Client: expecting the server `Certificate`.
    ClientWaitCertificate,
    /// Client: expecting `ServerKeyExchange`.
    ClientWaitServerKeyExchange,
    /// Client: expecting `CertificateRequest` or `ServerHelloDone`.
    ClientWaitCertificateRequest,
    /// Client: expecting `ServerHelloDone`.
    ClientWaitServerHelloDone,
    /// Client: our `Finished` is sent; expecting the server `ChangeCipherSpec`.
    ClientWaitChangeCipherSpec,
    /// Client: expecting the server `Finished`.
    ClientWaitFinished,
    /// Server: no state yet; expecting a `ClientHello` with a valid cookie.
    ServerWaitClientHello,
    /// Server: expecting the client `Certificate`.
    ServerWaitCertificate,
    /// Server: expecting `ClientKeyExchange`.
    ServerWaitClientKeyExchange,
    /// Server: expecting `CertificateVerify`.
    ServerWaitCertificateVerify,
    /// Server: expecting the client `ChangeCipherSpec`.
    ServerWaitChangeCipherSpec,
    /// Server: expecting the client `Finished`.
    ServerWaitFinished,
    /// Handshake complete.
    Connected,
    /// Failed. Terminal.
    Failed,
    /// Closed locally or by the peer. Terminal.
    Closed,
}

impl State {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Closed)
    }

    const fn is_handshaking(self) -> bool {
        !matches!(self, Self::Connected | Self::Failed | Self::Closed)
    }

    /// True when the next thing expected from the peer is a handshake
    /// message (as opposed to a `ChangeCipherSpec` record).
    const fn expects_handshake_message(self) -> bool {
        self.is_handshaking()
            && !matches!(
                self,
                Self::ClientWaitChangeCipherSpec
                    | Self::ServerWaitChangeCipherSpec
                    | Self::ServerWaitClientHello
            )
    }
}

/// A failure with the alert to send for it, if any.
#[derive(Debug, Clone, Copy)]
struct Failure {
    cause: FailureCause,
    alert: Option<u8>,
}

impl Failure {
    const fn new(cause: FailureCause, alert: u8) -> Self {
        Self {
            cause,
            alert: Some(alert),
        }
    }

    const fn internal() -> Self {
        Self::new(FailureCause::Internal, alert::INTERNAL_ERROR)
    }

    const fn decode() -> Self {
        Self::new(FailureCause::ProtocolViolation, alert::DECODE_ERROR)
    }

    const fn unexpected() -> Self {
        Self::new(FailureCause::ProtocolViolation, alert::UNEXPECTED_MESSAGE)
    }

    const fn unsupported() -> Self {
        Self::new(
            FailureCause::UnsupportedParameters,
            alert::HANDSHAKE_FAILURE,
        )
    }
}

impl From<DtlsError> for Failure {
    fn from(_: DtlsError) -> Self {
        Self::internal()
    }
}

impl From<uc_crypto::CryptoError> for Failure {
    fn from(_: uc_crypto::CryptoError) -> Self {
        Self::internal()
    }
}

impl From<WireError> for Failure {
    fn from(_: WireError) -> Self {
        Self::decode()
    }
}

type Step = Result<(), Failure>;

/// Secrets and bookkeeping that exist only while the handshake runs.
struct HandshakeContext {
    client_random: [u8; RANDOM_LEN],
    server_random: [u8; RANDOM_LEN],
    transcript: Transcript,
    reassembler: Reassembler,
    /// `message_seq` of the next handshake message we send.
    next_send_seq: u16,
    /// Client: our latest `ClientHello` in unfragmented form. It enters the
    /// transcript only once a `ServerHello` answers it (RFC 6347 §4.2.6).
    client_hello: Vec<u8>,
    hello_verify_requests: u8,
    /// Our ECDHE key pair (server: between flight 4 and `ClientKeyExchange`).
    ecdh: Option<P384EphemeralKeyPair>,
    /// The peer's certificate key, once its fingerprint has matched.
    peer_public_key: Option<[u8; P384_POINT_LEN]>,
    /// Client: the server's ECDHE public key, once its signature verified.
    peer_ecdh_public: Option<Vec<u8>>,
    certificate_requested: bool,
    master: Option<MasterSecret>,
    messages_processed: u32,
    /// The handler of the message being processed has started to change
    /// handshake state: a failure from here on cannot be deferred.
    committed: bool,
}

impl HandshakeContext {
    fn new(
        client_random: [u8; RANDOM_LEN],
        server_random: [u8; RANDOM_LEN],
        next_recv_seq: u16,
        next_send_seq: u16,
    ) -> Box<Self> {
        Box::new(Self {
            client_random,
            server_random,
            transcript: Transcript::new(),
            reassembler: Reassembler::new(next_recv_seq),
            next_send_seq,
            client_hello: Vec::new(),
            hello_verify_requests: 0,
            ecdh: None,
            peer_public_key: None,
            peer_ecdh_public: None,
            certificate_requested: false,
            master: None,
            messages_processed: 0,
            committed: false,
        })
    }

    /// Marks the point in a message handler after which handshake state
    /// changes. Every check that may refuse the message comes before it.
    const fn commit(&mut self) {
        self.committed = true;
    }
}

/// A DTLS 1.2 association for DTLS-SRTP key establishment.
///
/// See the [module documentation](self) for the profile and the driving loop.
pub struct DtlsAssociation {
    role: DtlsRole,
    credentials: DtlsCredentials,
    peer_fingerprints: Vec<CertificateFingerprint>,
    mtu: u16,
    state: State,
    records: AssociationRecordLayer,
    handshake: Option<Box<HandshakeContext>>,
    /// Our last flight, kept for retransmission.
    flight: Flight,
    timer: RetransmitTimer,
    /// When the flight was last put on the wire (first send or retransmit).
    last_flight_tx: Option<Instant>,
    /// Shortest time between two peer-triggered retransmissions.
    resend_holdoff: Duration,
    /// Peer-triggered retransmissions of the current flight so far.
    peer_triggered_resends: u8,
    budget_deadline: Instant,
    /// Server, after completion: until when the final flight is kept.
    linger_deadline: Option<Instant>,
    /// What an unauthenticated (epoch 0) alert or refused message would
    /// have failed the handshake with, not yet acted on. The first one is
    /// kept; it is forgotten when a message from the peer is accepted.
    pending_failure: Option<Failure>,
    /// Set when the rest of the datagram being processed must be ignored.
    discard_rest_of_datagram: bool,
    /// Plaintext messages refused while processing the current datagram.
    refusals_in_datagram: u16,
    /// A `CertificateRequest` was part of the handshake.
    certificate_requested: bool,
    /// Bytes identifying the peer's address, covered by the cookie.
    peer_binding: Vec<u8>,
    /// After completion: the peer `message_seq` that would start a new message.
    next_recv_seq: u16,
    /// Server: key of the stateless cookie.
    cookie_secret: Zeroizing<[u8; COOKIE_SECRET_LEN]>,
    /// Server: start of the current one-second window and the
    /// `HelloVerifyRequest`s sent in it.
    hello_verify_window: Option<(Instant, u32)>,
    last_no_renegotiation: Option<Instant>,
    /// SHA-384 fingerprint of the certificate the peer presented.
    presented_fingerprint: Option<CertificateFingerprint>,
    transmit: VecDeque<Vec<u8>>,
    events: VecDeque<AssociationEvent>,
    stats: AssociationStats,
}

impl DtlsAssociation {
    /// Creates an association. A client queues its `ClientHello` at once; a
    /// server waits for one.
    ///
    /// The handshake budget starts at `now`, not at the first datagram:
    /// construct the association when the path to the peer is ready (for
    /// the soft client, once the SDP answer is known), or the time spent
    /// waiting counts against the handshake. An association is for one
    /// handshake with one peer and is not reusable.
    ///
    /// # Errors
    /// Returns [`DtlsError::InvalidConfig`] if `peer_fingerprints` is empty,
    /// the MTU or timers are out of range or `peer_binding` is too long, and
    /// an error if the random generator fails.
    pub fn new(config: AssociationConfig, now: Instant) -> DtlsResult<Self> {
        let invalid = |reason: &str| DtlsError::InvalidConfig {
            reason: reason.to_string(),
        };
        // RFC 8122 §5 / NIST 800-53 Rev5: SC-23 -- without a signalled
        // fingerprint there is nothing to authenticate the peer against.
        if config.peer_fingerprints.is_empty() {
            return Err(invalid("no peer certificate fingerprint"));
        }
        if !(MIN_MTU..=MAX_MTU).contains(&config.mtu) {
            return Err(invalid("MTU out of range"));
        }
        // NIST 800-53 Rev5: SC-5 -- a floor on the interval bounds how often
        // a flight can be (re)sent, by the timer or on the peer's request.
        if config.initial_rto < MIN_INITIAL_RTO || config.initial_rto > MAX_RTO {
            return Err(invalid("initial retransmission interval out of range"));
        }
        if config.peer_binding.len() > MAX_PEER_BINDING_LEN {
            return Err(invalid("peer binding too long"));
        }
        if config.handshake_budget.is_zero() || config.handshake_budget > MAX_HANDSHAKE_BUDGET {
            return Err(invalid("handshake budget out of range"));
        }
        let random_failed = |_| DtlsError::HandshakeFailed {
            reason: "random generation failed".to_string(),
        };
        let cookie_secret = Zeroizing::new(
            uc_crypto::random::generate_random::<COOKIE_SECRET_LEN>().map_err(random_failed)?,
        );
        let mut association = Self {
            role: config.role,
            credentials: config.credentials,
            peer_fingerprints: config.peer_fingerprints,
            mtu: config.mtu,
            state: match config.role {
                DtlsRole::Client => State::ClientWaitServerHello,
                DtlsRole::Server => State::ServerWaitClientHello,
            },
            records: AssociationRecordLayer::new(),
            handshake: None,
            flight: Flight::new(),
            timer: RetransmitTimer::new(config.initial_rto),
            last_flight_tx: None,
            // RFC 6347 §4.2.4: fixed, so the rate limit does not loosen or
            // tighten as the timer backs off.
            resend_holdoff: config.initial_rto / 2,
            peer_triggered_resends: 0,
            budget_deadline: now + config.handshake_budget,
            linger_deadline: None,
            pending_failure: None,
            discard_rest_of_datagram: false,
            refusals_in_datagram: 0,
            certificate_requested: false,
            peer_binding: config.peer_binding,
            next_recv_seq: 0,
            cookie_secret,
            hello_verify_window: None,
            last_no_renegotiation: None,
            presented_fingerprint: None,
            transmit: VecDeque::new(),
            events: VecDeque::new(),
            stats: AssociationStats::default(),
        };
        if config.role.is_client() {
            let client_random =
                uc_crypto::random::generate_random::<RANDOM_LEN>().map_err(random_failed)?;
            let mut hs = HandshakeContext::new(client_random, [0; RANDOM_LEN], 0, 0);
            association
                .send_client_hello(&mut hs, &[], now)
                .map_err(|_| DtlsError::HandshakeFailed {
                    reason: "could not build ClientHello".to_string(),
                })?;
            association.handshake = Some(hs);
        }
        Ok(association)
    }

    /// Our role.
    #[must_use]
    pub const fn role(&self) -> DtlsRole {
        self.role
    }

    /// True once the handshake has completed and until the association
    /// fails or closes.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(self.state, State::Connected)
    }

    /// True once the association has failed or closed.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.state.is_terminal()
    }

    /// SHA-384 fingerprint of the certificate most recently presented as
    /// the peer's, computed locally (safe to log). Present from the moment
    /// a certificate is received, whether or not it was accepted; during
    /// the handshake a refused certificate is unauthenticated input and may
    /// not be the peer's own.
    #[must_use]
    pub const fn presented_fingerprint(&self) -> Option<&CertificateFingerprint> {
        self.presented_fingerprint.as_ref()
    }

    /// True if a `CertificateRequest` was part of the handshake, that is, if
    /// the client was asked to authenticate.
    ///
    /// As server this is true from our first flight on: we always request
    /// (and require) the client's certificate. As client it is true once the
    /// server has asked for ours. A connected association for which this is
    /// false authenticated the server only; one for which it is true is
    /// mutually authenticated.
    ///
    /// NIST 800-53 Rev5: IA-3 / AU-3 -- the driver's audit record states
    /// mutual authentication only when this is true.
    #[must_use]
    pub const fn client_certificate_requested(&self) -> bool {
        self.certificate_requested
    }

    /// Counters.
    #[must_use]
    pub const fn stats(&self) -> AssociationStats {
        self.stats
    }

    /// Takes the next datagram to send to the peer.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.transmit.pop_front()
    }

    /// Takes the next event.
    pub fn poll_event(&mut self) -> Option<AssociationEvent> {
        self.events.pop_front()
    }

    /// When [`Self::handle_timeout`] must be called next, if at all.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.state.is_handshaking() {
            let retransmit = self.timer.deadline().filter(|_| !self.flight.is_empty());
            Some(retransmit.map_or(self.budget_deadline, |d| d.min(self.budget_deadline)))
        } else {
            self.linger_deadline
        }
    }

    /// Advances timers: retransmits the current flight when its timer has
    /// expired (RFC 6347 §4.2.4), fails the handshake when the budget is
    /// used up or a plaintext alert or refused message was followed by no
    /// progress, and frees the final flight when its retention time is over.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.state.is_terminal() {
            return;
        }
        if self.state.is_handshaking() {
            // NIST 800-53 Rev5: SC-5 -- hard bound on the handshake.
            if now >= self.budget_deadline {
                self.fail_out_of_time();
                return;
            }
            if self.timer.is_due(now) && !self.flight.is_empty() {
                // A plaintext alert or a refused message arrived and
                // nothing from the peer was accepted since: take it as the
                // peer's (see on_alert and drive).
                if let Some(failure) = self.pending_failure {
                    self.fail(failure);
                    return;
                }
                self.timer.back_off(now);
                self.retransmit_flight(now);
            }
        } else if self.linger_deadline.is_some_and(|deadline| now >= deadline) {
            self.linger_deadline = None;
            self.flight.clear();
        }
    }

    /// Processes one datagram from the peer.
    ///
    /// Never returns an error: input that cannot be accepted is counted and
    /// dropped without touching any state (RFC 6347 §4.1.2.7), and protocol
    /// failures surface as [`AssociationEvent::Failed`].
    ///
    /// The caller must only pass datagrams from the one remote address this
    /// association serves (see "Driver contract" in the module
    /// documentation): the association has no other way to tell peers apart.
    pub fn handle_datagram(&mut self, datagram: &[u8], now: Instant) {
        if self.state.is_terminal() {
            self.count_discard();
            return;
        }
        // NIST 800-53 Rev5: SC-5 -- the budget also binds a driver that
        // never calls `handle_timeout`.
        if self.state.is_handshaking() && now >= self.budget_deadline {
            self.fail_out_of_time();
            return;
        }
        if datagram.is_empty() {
            self.count_discard();
            return;
        }
        self.discard_rest_of_datagram = false;
        self.refusals_in_datagram = 0;
        for record in DatagramRecords::new(datagram) {
            let Ok(record) = record else {
                self.count_discard();
                break;
            };
            if self.state == State::ServerWaitClientHello {
                self.on_initial_record(&record, now);
            } else {
                match self.records.open(&record) {
                    Ok(plaintext) => {
                        self.on_plaintext(record.content_type, record.epoch, &plaintext, now);
                    }
                    Err(RecordDiscard::Replay) => {
                        self.stats.replays = self.stats.replays.saturating_add(1);
                    }
                    // A protected record before the peer's ChangeCipherSpec
                    // was accepted: its Finished overtook an earlier record.
                    Err(RecordDiscard::Epoch)
                        if record.epoch == 1
                            && self.state.is_handshaking()
                            && self.records.read_epoch() == 0 =>
                    {
                        self.count_early();
                    }
                    Err(_) => self.count_discard(),
                }
            }
            if self.state.is_terminal() || self.discard_rest_of_datagram {
                break;
            }
        }
    }

    /// Closes the association: queues one `close_notify` and drops all keys.
    /// No event is emitted. Does nothing if already failed or closed.
    pub fn close(&mut self) {
        if self.state.is_terminal() {
            return;
        }
        self.queue_alert(Alert::warning(alert::CLOSE_NOTIFY));
        self.terminate(State::Closed);
    }

    // ----- output helpers -------------------------------------------------

    const fn count_discard(&mut self) {
        self.stats.records_discarded = self.stats.records_discarded.saturating_add(1);
    }

    const fn count_fragment_rejected(&mut self) {
        self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
    }

    const fn count_early(&mut self) {
        self.stats.early_ccs_or_finished = self.stats.early_ccs_or_finished.saturating_add(1);
    }

    fn queue_datagram(&mut self, datagram: Vec<u8>) {
        // NIST 800-53 Rev5: SC-5 -- a caller that stops draining cannot make
        // the queue grow without bound; what does not fit is counted.
        if self.transmit.len() < MAX_QUEUED_DATAGRAMS {
            self.transmit.push_back(datagram);
        } else {
            self.stats.transmit_dropped = self.stats.transmit_dropped.saturating_add(1);
        }
    }

    fn queue_event(&mut self, event: AssociationEvent) {
        if self.events.len() < MAX_QUEUED_EVENTS {
            self.events.push_back(event);
        }
    }

    /// Seals an alert in the current write epoch and queues it. Best effort.
    fn queue_alert(&mut self, alert: Alert) {
        let epoch = self.records.write_epoch();
        if let Ok(record) = self
            .records
            .seal(epoch, ContentType::Alert, &alert.encode())
        {
            self.queue_datagram(record);
        }
    }

    /// Moves to a terminal state and drops every secret and buffer.
    ///
    /// NIST 800-53 Rev5: SC-12 -- the handshake context (master secret,
    /// ECDHE key) and the record keys do not outlive the association's use
    /// of them; their buffers are wiped as they drop.
    fn terminate(&mut self, state: State) {
        self.state = state;
        self.handshake = None;
        self.flight.clear();
        self.timer.stop();
        self.linger_deadline = None;
        self.pending_failure = None;
        // Dropping the record layer frees its aws-lc key contexts.
        self.records = AssociationRecordLayer::new();
    }

    /// The handshake budget is used up. If a plaintext alert or a refused
    /// message is still pending, that is the more useful cause.
    fn fail_out_of_time(&mut self) {
        let failure = self.pending_failure.unwrap_or(Failure {
            cause: FailureCause::Timeout,
            alert: None,
        });
        self.fail(failure);
    }

    /// Remembers what unauthenticated input would have failed the handshake
    /// with. The first cause is kept: later input cannot rewrite it.
    fn defer_failure(&mut self, failure: Failure) {
        self.pending_failure.get_or_insert(failure);
    }

    fn fail(&mut self, failure: Failure) {
        if self.state.is_terminal() {
            return;
        }
        if let Some(description) = failure.alert {
            self.queue_alert(Alert::fatal(description));
        }
        self.terminate(State::Failed);
        self.queue_event(AssociationEvent::Failed {
            cause: failure.cause,
        });
    }

    /// Encodes the current flight with fresh record sequence numbers and
    /// queues it.
    fn transmit_flight(&mut self, now: Instant) -> Step {
        let datagrams = self.flight.encode(&mut self.records, self.mtu)?;
        for datagram in datagrams {
            self.queue_datagram(datagram);
        }
        self.last_flight_tx = Some(now);
        Ok(())
    }

    /// Sends a new flight for the first time and starts its timer.
    fn start_flight(&mut self, now: Instant) -> Step {
        self.peer_triggered_resends = 0;
        self.transmit_flight(now)?;
        self.timer.start(now);
        Ok(())
    }

    fn retransmit_flight(&mut self, now: Instant) {
        self.stats.retransmits = self.stats.retransmits.saturating_add(1);
        if let Err(failure) = self.transmit_flight(now) {
            self.fail(failure);
        }
    }

    /// The peer retransmitted a message we already processed, so it may not
    /// have received our flight: send it again (RFC 6347 §4.2.4).
    ///
    /// NIST 800-53 Rev5: SC-5 -- during the handshake the trigger is an
    /// unauthenticated 25-byte fragment, so the answer is limited two ways:
    /// not within half the initial timer interval of the last transmission,
    /// and at most [`MAX_PEER_TRIGGERED_RESENDS`] per flight. The
    /// retransmission timer is left alone: an unauthenticated trigger
    /// neither backs it off nor re-arms it, so forged fragments cannot
    /// stretch the interval or put off its next expiry (which is also when
    /// a pending failure is acted on). After completion the trigger is an
    /// authenticated, replay-checked record and only the hold-off applies.
    fn on_peer_retransmission(&mut self, now: Instant) {
        if self.flight.is_empty() {
            return;
        }
        if self
            .last_flight_tx
            .is_some_and(|last| now.saturating_duration_since(last) < self.resend_holdoff)
        {
            return;
        }
        if self.state.is_handshaking() {
            if self.peer_triggered_resends >= MAX_PEER_TRIGGERED_RESENDS {
                return;
            }
            self.peer_triggered_resends += 1;
        }
        self.retransmit_flight(now);
    }

    /// Adds a handshake message to the flight and, unless it is a
    /// `ClientHello` (handled separately), to the transcript.
    fn queue_handshake(
        &mut self,
        hs: &mut HandshakeContext,
        epoch: u16,
        msg_type: u8,
        body: &[u8],
    ) -> Step {
        let seq = hs.next_send_seq;
        hs.next_send_seq = seq.checked_add(1).ok_or_else(Failure::internal)?;
        if msg_type != HT_CLIENT_HELLO {
            hs.transcript.push(msg_type, seq, body)?;
        }
        self.flight
            .push_handshake(epoch, msg_type, seq, body, self.mtu)?;
        Ok(())
    }

    // ----- input dispatch -------------------------------------------------

    fn on_plaintext(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        plaintext: &[u8],
        now: Instant,
    ) {
        match content_type {
            ContentType::Handshake => self.on_handshake_record(epoch, plaintext, now),
            ContentType::ChangeCipherSpec => self.on_change_cipher_spec(plaintext, now),
            ContentType::Alert => self.on_alert(epoch, plaintext),
            // No application data in this profile (RFC 5764: SRTP is not
            // carried in DTLS records).
            ContentType::ApplicationData => self.count_discard(),
        }
    }

    /// Alerts (RFC 5246 §7.2).
    ///
    /// NIST 800-53 Rev5: SC-5 -- an alert in a plaintext record is not
    /// evidence that the peer sent it. During the handshake it is kept as
    /// the pending cause (unless one is already pending) and acted on only
    /// if the handshake then makes no progress (see `handle_timeout`); a
    /// genuine alert is thereby reported within one retransmission
    /// interval, and a forged one is forgotten as soon as the peer's next
    /// message is accepted. An alert in epoch 1 is authenticated and acts
    /// at once.
    fn on_alert(&mut self, epoch: u16, plaintext: &[u8]) {
        let Ok(received) = Alert::parse(plaintext) else {
            self.count_discard();
            return;
        };
        let is_close = received.description == alert::CLOSE_NOTIFY;
        if !is_close && !received.is_fatal() {
            // Other warnings are ignored.
            return;
        }
        if epoch == 0 && self.state.is_handshaking() {
            self.defer_failure(Failure {
                cause: FailureCause::PeerAlert(received.description),
                alert: None,
            });
            return;
        }
        if is_close && self.state == State::Connected {
            // RFC 5246 §7.2.1: answer close_notify with our own.
            self.queue_alert(Alert::warning(alert::CLOSE_NOTIFY));
            self.terminate(State::Closed);
            self.queue_event(AssociationEvent::PeerClosed);
        } else {
            // A fatal alert, or a close before the handshake finished.
            self.fail(Failure {
                cause: FailureCause::PeerAlert(received.description),
                alert: None,
            });
        }
    }

    fn on_change_cipher_spec(&mut self, plaintext: &[u8], now: Instant) {
        let next = match self.state {
            State::ClientWaitChangeCipherSpec => State::ClientWaitFinished,
            State::ServerWaitChangeCipherSpec => State::ServerWaitFinished,
            // Early (reordered): dropped, not buffered; the peer's
            // retransmission recovers.
            _ if self.state.is_handshaking() && self.records.read_epoch() == 0 => {
                self.count_early();
                return;
            }
            // Repeated, or after completion.
            _ => {
                self.count_discard();
                return;
            }
        };
        if plaintext != [1] {
            self.count_discard();
            return;
        }
        // RFC 6347 §4.1: only the read side moves to epoch 1 here.
        if self.records.activate_read().is_err() {
            self.fail(Failure::internal());
            return;
        }
        // NIST 800-53 Rev5: SC-5 / SC-23 -- from here on only epoch-1
        // records are read. Whatever plaintext fragments are still buffered
        // (they can only sit in the Finished slot or beyond) did not come
        // from the peer's flight and must not occupy those slots.
        if let Some(hs) = self.handshake.as_mut() {
            let purged = hs.reassembler.discard_below_epoch(1);
            self.stats.fragments_rejected = self
                .stats
                .fragments_rejected
                .saturating_add(u32::try_from(purged).unwrap_or(u32::MAX));
        }
        // The ChangeCipherSpec itself is plaintext, so it does not count as
        // progress for a pending alert; the Finished that follows does.
        self.state = next;
        self.drive(now);
    }

    /// A record payload may hold several handshake fragments.
    fn on_handshake_record(&mut self, epoch: u16, plaintext: &[u8], now: Instant) {
        let mut r = Reader::new(plaintext);
        while !r.is_empty() && !self.state.is_terminal() && !self.discard_rest_of_datagram {
            let fragment = HandshakeHeader::parse(&mut r).and_then(|header| {
                let len =
                    usize::try_from(header.fragment_length).map_err(|_| WireError::Truncated)?;
                Ok((header, r.take(len)?))
            });
            let Ok((header, fragment)) = fragment else {
                self.count_fragment_rejected();
                return;
            };
            if self.state == State::Connected {
                self.on_post_handshake_fragment(&header, now);
                continue;
            }
            // RFC 5246 §7.4.1.1: a client ignores a HelloRequest during a
            // handshake, and it is not part of the transcript. A server
            // never expects one: there it is an invalid message, silently
            // discarded (RFC 6347 §4.1.2.7).
            // NIST 800-53 Rev5: SC-5 -- it is dropped here, before
            // reassembly, so that it can neither hold a slot nor use up a
            // message_seq, and it is no progress for a pending failure.
            if header.msg_type == HT_HELLO_REQUEST {
                self.count_fragment_rejected();
                continue;
            }
            let Some(hs) = self.handshake.as_mut() else {
                self.count_fragment_rejected();
                return;
            };
            match hs.reassembler.push(&header, fragment, epoch) {
                Ok(FragmentOutcome::Buffered) => self.drive(now),
                Ok(FragmentOutcome::Retransmission) => self.on_peer_retransmission(now),
                Ok(FragmentOutcome::Rejected) => self.count_fragment_rejected(),
                // NIST 800-53 Rev5: SC-5 -- a plaintext fragment that breaks
                // a rule or limit proves nothing about the peer: it is
                // dropped and counted, with the rest of its datagram, and
                // the handshake goes on.
                Err(_) if epoch == 0 => {
                    self.count_fragment_rejected();
                    self.discard_rest_of_datagram = true;
                    return;
                }
                // In epoch 1 the fragment is the authenticated peer's.
                Err(_) => {
                    self.count_fragment_rejected();
                    self.fail(Failure::new(
                        FailureCause::ProtocolViolation,
                        alert::ILLEGAL_PARAMETER,
                    ));
                }
            }
        }
    }

    /// After completion only two handshake messages mean anything: a
    /// retransmission of the peer's last flight, and a renegotiation attempt.
    fn on_post_handshake_fragment(&mut self, header: &HandshakeHeader, now: Instant) {
        if header.message_seq < self.next_recv_seq {
            self.on_peer_retransmission(now);
        } else if self.role.is_server() && header.msg_type == HT_CLIENT_HELLO {
            // RFC 5746 §4.4 / RFC 5246 §7.2.2: renegotiation is refused with
            // a no_renegotiation warning, at most once per second.
            let recently = self
                .last_no_renegotiation
                .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_secs(1));
            if !recently {
                self.last_no_renegotiation = Some(now);
                self.queue_alert(Alert::warning(alert::NO_RENEGOTIATION));
            }
        } else {
            // HelloRequest (client role) and anything else: ignored.
            self.count_discard();
        }
    }

    /// Processes every message that is complete and next in sequence.
    fn drive(&mut self, now: Instant) {
        while self.state.expects_handshake_message() {
            let Some(mut hs) = self.handshake.take() else {
                return;
            };
            // The slot is emptied, but its message_seq is used up only
            // once the message has been accepted.
            let Some(message) = hs.reassembler.take_next() else {
                self.handshake = Some(hs);
                return;
            };
            // NIST 800-53 Rev5: SC-5 -- cap on messages processed, accepted
            // or not: it also bounds the signature verifications that
            // refused messages can cost.
            hs.messages_processed += 1;
            if hs.messages_processed > MAX_HANDSHAKE_MESSAGES {
                self.fail(Failure::unexpected());
                return;
            }
            hs.committed = false;
            match self.on_message(&mut hs, &message, now) {
                Ok(()) => {
                    hs.reassembler.advance();
                    // The handshake moved on: a plaintext alert or refused
                    // message seen before this one was not the peer's last
                    // word.
                    self.pending_failure = None;
                    if self.state.is_handshaking() {
                        self.handshake = Some(hs);
                    }
                    // Connected: the context, with every handshake secret,
                    // is dropped.
                }
                // NIST 800-53 Rev5: SC-5 -- a plaintext message refused
                // before its handler changed anything proves nothing about
                // the peer: it may be forged, parked at this message_seq
                // ahead of the genuine one. It is thrown away and counted,
                // the message_seq stays open for the genuine message, and
                // the failure is acted on only if the handshake then makes
                // no progress (see `handle_timeout`). Neither the
                // transcript nor any key material has seen it.
                Err(failure)
                    if message.epoch == 0
                        && !hs.committed
                        && failure.cause != FailureCause::Internal =>
                {
                    self.count_fragment_rejected();
                    self.defer_failure(failure);
                    self.handshake = Some(hs);
                    // One datagram cannot use up the message limit: once
                    // it has had more messages refused than parked
                    // forgeries can account for, the rest of it is ignored.
                    self.refusals_in_datagram = self.refusals_in_datagram.saturating_add(1);
                    if self.refusals_in_datagram > MAX_REFUSALS_PER_DATAGRAM {
                        self.discard_rest_of_datagram = true;
                        return;
                    }
                }
                // Authenticated (epoch 1), or the handler had already
                // changed handshake state, or a local operation failed.
                Err(failure) => self.fail(failure),
            }
        }
    }

    fn on_message(
        &mut self,
        hs: &mut HandshakeContext,
        message: &CompleteMessage,
        now: Instant,
    ) -> Step {
        // RFC 6347 §4.2.6 / RFC 5246 §7.4.9: Finished is the first message
        // under the new keys; everything before it is in epoch 0. A message
        // in the wrong epoch is never accepted.
        let expected_epoch = u16::from(message.msg_type == HT_FINISHED);
        if message.epoch != expected_epoch {
            return Err(Failure::unexpected());
        }
        let body = message.body.as_slice();
        // A HelloRequest never gets here: its fragments are dropped before
        // reassembly (see on_handshake_record).
        match (self.state, message.msg_type) {
            (State::ClientWaitServerHello, HT_HELLO_VERIFY_REQUEST) => {
                self.on_hello_verify_request(hs, body, now)
            }
            (State::ClientWaitServerHello, HT_SERVER_HELLO) => self.on_server_hello(hs, message),
            (State::ClientWaitCertificate, HT_CERTIFICATE) => {
                self.on_certificate(hs, message)?;
                self.state = State::ClientWaitServerKeyExchange;
                Ok(())
            }
            (State::ClientWaitServerKeyExchange, HT_SERVER_KEY_EXCHANGE) => {
                self.on_server_key_exchange(hs, message)
            }
            (State::ClientWaitCertificateRequest, HT_CERTIFICATE_REQUEST) => {
                self.on_certificate_request(hs, message)
            }
            (
                State::ClientWaitCertificateRequest | State::ClientWaitServerHelloDone,
                HT_SERVER_HELLO_DONE,
            ) => self.on_server_hello_done(hs, message, now),
            (State::ClientWaitFinished | State::ServerWaitFinished, HT_FINISHED) => {
                self.on_finished(hs, message, now)
            }
            (State::ServerWaitCertificate, HT_CERTIFICATE) => {
                self.on_certificate(hs, message)?;
                self.state = State::ServerWaitClientKeyExchange;
                Ok(())
            }
            (State::ServerWaitClientKeyExchange, HT_CLIENT_KEY_EXCHANGE) => {
                self.on_client_key_exchange(hs, message)
            }
            (State::ServerWaitCertificateVerify, HT_CERTIFICATE_VERIFY) => {
                self.on_certificate_verify(hs, message)
            }
            // NIST 800-53 Rev5: SC-23 / IA-3 -- as server the client MUST
            // authenticate: a handshake that skips Certificate or
            // CertificateVerify is refused.
            (State::ServerWaitCertificate, _) => Err(Failure::new(
                FailureCause::BadCertificate,
                alert::HANDSHAKE_FAILURE,
            )),
            (State::ServerWaitCertificateVerify, _) => Err(Failure::new(
                FailureCause::BadSignature,
                alert::HANDSHAKE_FAILURE,
            )),
            _ => Err(Failure::unexpected()),
        }
    }

    // ----- client ---------------------------------------------------------

    /// Builds and sends a `ClientHello` (flight 1, or flight 3 with a cookie).
    fn send_client_hello(
        &mut self,
        hs: &mut HandshakeContext,
        cookie: &[u8],
        now: Instant,
    ) -> Step {
        let hello = ClientHello {
            version: DTLS_1_2_VERSION,
            random: hs.client_random,
            session_id: Vec::new(),
            cookie: cookie.to_vec(),
            cipher_suites: vec![CIPHER_SUITE],
            compression_methods: vec![COMPRESSION_NULL],
            extensions: Extensions {
                supported_groups: Some(vec![GROUP_SECP384R1]),
                ec_point_formats: Some(vec![POINT_FORMAT_UNCOMPRESSED]),
                signature_algorithms: Some(vec![SCHEME_ECDSA_SECP384R1_SHA384]),
                // RFC 5764 §4.1.1: offer exactly one profile, no MKI.
                use_srtp: Some(UseSrtp {
                    profiles: vec![SRTP_AEAD_AES_256_GCM],
                    mki: Vec::new(),
                }),
                // RFC 7627 §5.2
                extended_master_secret: true,
                // RFC 5746 §3.4: empty renegotiated_connection.
                renegotiation_info: Some(Vec::new()),
                first_unknown: None,
            },
        };
        let mut body = Vec::new();
        hello.encode(&mut body)?;
        hs.client_hello = handshake_message_bytes(HT_CLIENT_HELLO, hs.next_send_seq, &body)?;
        self.flight.clear();
        self.queue_handshake(hs, 0, HT_CLIENT_HELLO, &body)?;
        self.start_flight(now)
    }

    /// RFC 6347 §4.2.1: repeat the `ClientHello` with the server's cookie.
    /// Neither the first `ClientHello` nor this message is in the transcript.
    fn on_hello_verify_request(
        &mut self,
        hs: &mut HandshakeContext,
        body: &[u8],
        now: Instant,
    ) -> Step {
        let request = HelloVerifyRequest::parse(body)?;
        // RFC 6347 §4.2.1: the version here is not the negotiated one;
        // servers send 1.0 or 1.2.
        if request.version != DTLS_1_0_VERSION && request.version != DTLS_1_2_VERSION {
            return Err(Failure::new(
                FailureCause::UnsupportedParameters,
                alert::PROTOCOL_VERSION,
            ));
        }
        // NIST 800-53 Rev5: SC-5 -- a peer cannot keep us in a cookie loop.
        if hs.hello_verify_requests >= MAX_HELLO_VERIFY_REQUESTS {
            return Err(Failure::unexpected());
        }
        hs.commit();
        hs.hello_verify_requests += 1;
        self.send_client_hello(hs, &request.cookie, now)
    }

    fn on_server_hello(&mut self, hs: &mut HandshakeContext, message: &CompleteMessage) -> Step {
        let hello = ServerHello::parse(&message.body)?;
        // NIST 800-53 Rev5: SC-13 -- CNSA 2.0 / plan §2.2: one version, one
        // suite, no compression.
        if hello.version != DTLS_1_2_VERSION {
            return Err(Failure::new(
                FailureCause::UnsupportedParameters,
                alert::PROTOCOL_VERSION,
            ));
        }
        if hello.cipher_suite != CIPHER_SUITE || hello.compression_method != COMPRESSION_NULL {
            return Err(Failure::unsupported());
        }
        // RFC 5246 §7.4.1.4: an extension in the ServerHello that the
        // ClientHello did not offer MUST be answered with
        // unsupported_extension. Our ClientHello offers every extension type
        // this codec decodes, so "not offered" is "not decoded".
        if hello.extensions.first_unknown.is_some() {
            return Err(Failure::new(
                FailureCause::ProtocolViolation,
                alert::UNSUPPORTED_EXTENSION,
            ));
        }
        check_common_extensions(&hello.extensions)?;
        // RFC 5764 §4.1.1: the server selects exactly one offered profile.
        match &hello.extensions.use_srtp {
            // RFC 5764 §4.1.3: we offered no MKI, so a ServerHello carrying
            // one is answered with illegal_parameter.
            Some(use_srtp) if !use_srtp.mki.is_empty() => {
                return Err(Failure::new(
                    FailureCause::NoSrtpProfile,
                    alert::ILLEGAL_PARAMETER,
                ));
            }
            Some(use_srtp) if use_srtp.profiles == [SRTP_AEAD_AES_256_GCM] => {}
            _ => {
                return Err(Failure::new(
                    FailureCause::NoSrtpProfile,
                    alert::HANDSHAKE_FAILURE,
                ));
            }
        }
        hs.commit();
        hs.server_random = hello.random;
        // RFC 6347 §4.2.6: the transcript starts with the ClientHello that
        // this ServerHello answers.
        let client_hello = std::mem::take(&mut hs.client_hello);
        hs.transcript.push_raw(&client_hello)?;
        hs.transcript
            .push(HT_SERVER_HELLO, message.message_seq, &message.body)?;
        self.state = State::ClientWaitCertificate;
        Ok(())
    }

    /// Peer `Certificate`, either role.
    ///
    /// RFC 5763 §6.7.1 / RFC 8122 §5: the certificate MUST match a signalled
    /// fingerprint. This is checked on the raw DER before it is parsed.
    ///
    /// NIST 800-53 Rev5: SC-23 (session authenticity), IA-3.
    ///
    /// Nothing of the handshake changes before every check has passed, so a
    /// refused `Certificate` can be thrown away (see `drive`); the presented
    /// fingerprint is diagnostic only and is overwritten by the next one.
    fn on_certificate(&mut self, hs: &mut HandshakeContext, message: &CompleteMessage) -> Step {
        let certificate = CertificateMsg::parse(&message.body)?;
        let bad_certificate = |cause| Failure::new(cause, alert::BAD_CERTIFICATE);
        let leaf = certificate
            .chain
            .first()
            .ok_or_else(|| bad_certificate(FailureCause::BadCertificate))?;
        self.presented_fingerprint = Some(CertificateFingerprint::from_certificate_sha384(leaf));
        CertificateFingerprint::verify_any(&self.peer_fingerprints, leaf)
            .map_err(|_| bad_certificate(FailureCause::FingerprintMismatch))?;
        // CNSA 2.0: the key must be ECDSA P-384.
        let key = extract_p384_public_key(leaf)
            .map_err(|_| bad_certificate(FailureCause::BadCertificate))?;
        hs.commit();
        hs.peer_public_key = Some(key);
        hs.transcript
            .push(HT_CERTIFICATE, message.message_seq, &message.body)?;
        Ok(())
    }

    /// RFC 8422 §5.4: the ECDHE parameters must be signed by the certificate
    /// key. The signature is mandatory and must use `ecdsa_secp384r1_sha384`.
    fn on_server_key_exchange(
        &mut self,
        hs: &mut HandshakeContext,
        message: &CompleteMessage,
    ) -> Step {
        let mut r = Reader::new(&message.body);
        let params = EcdheParams::parse(&mut r)?;
        let params_raw = message
            .body
            .get(..r.consumed())
            .ok_or_else(Failure::decode)?;
        if params.named_curve != GROUP_SECP384R1 || params.public.len() != P384_POINT_LEN {
            return Err(Failure::unsupported());
        }
        let bad_signature = |alert| Failure::new(FailureCause::BadSignature, alert);
        let signed = DigitallySigned::parse(&mut r)
            .and_then(|signed| r.finish().map(|()| signed))
            .map_err(|_| bad_signature(alert::DECODE_ERROR))?;
        if signed.scheme != SCHEME_ECDSA_SECP384R1_SHA384 {
            return Err(Failure::unsupported());
        }
        let key = hs.peer_public_key.ok_or_else(Failure::internal)?;
        let content =
            server_key_exchange_signed_content(&hs.client_random, &hs.server_random, params_raw);
        verify_p384(&key, &content, &signed.signature)
            .map_err(|_| bad_signature(alert::DECRYPT_ERROR))?;
        hs.commit();
        hs.peer_ecdh_public = Some(params.public);
        hs.transcript
            .push(HT_SERVER_KEY_EXCHANGE, message.message_seq, &message.body)?;
        self.state = State::ClientWaitCertificateRequest;
        Ok(())
    }

    fn on_certificate_request(
        &mut self,
        hs: &mut HandshakeContext,
        message: &CompleteMessage,
    ) -> Step {
        let request = CertificateRequest::parse(&message.body)?;
        if !request.certificate_types.contains(&CERT_TYPE_ECDSA_SIGN)
            || !request
                .signature_algorithms
                .contains(&SCHEME_ECDSA_SECP384R1_SHA384)
        {
            return Err(Failure::unsupported());
        }
        hs.commit();
        hs.certificate_requested = true;
        self.certificate_requested = true;
        hs.transcript
            .push(HT_CERTIFICATE_REQUEST, message.message_seq, &message.body)?;
        self.state = State::ClientWaitServerHelloDone;
        Ok(())
    }

    /// The server's flight is complete: send flight 5 (`Certificate`,
    /// `ClientKeyExchange`, `CertificateVerify`, `ChangeCipherSpec`, `Finished`).
    fn on_server_hello_done(
        &mut self,
        hs: &mut HandshakeContext,
        message: &CompleteMessage,
        now: Instant,
    ) -> Step {
        if !message.body.is_empty() {
            return Err(Failure::decode());
        }
        hs.commit();
        hs.transcript
            .push(HT_SERVER_HELLO_DONE, message.message_seq, &message.body)?;

        self.flight.clear();
        if hs.certificate_requested {
            let certificate = self.credentials.certificate_message.clone();
            self.queue_handshake(hs, 0, HT_CERTIFICATE, &certificate)?;
        }

        // NIST 800-53 Rev5: SC-12 -- ECDHE on P-384; the private key is
        // consumed by the agreement.
        let ecdh = P384EphemeralKeyPair::generate()?;
        let mut key_exchange = Vec::new();
        ClientKeyExchange {
            public: ecdh.public_key_bytes().to_vec(),
        }
        .encode(&mut key_exchange)?;
        self.queue_handshake(hs, 0, HT_CLIENT_KEY_EXCHANGE, &key_exchange)?;

        let peer_public = hs.peer_ecdh_public.take().ok_or_else(Failure::internal)?;
        let pre_master_secret = ecdh
            .agree(&peer_public)
            .map_err(|_| Failure::new(FailureCause::ProtocolViolation, alert::ILLEGAL_PARAMETER))?;
        // RFC 7627 §3: session_hash covers ClientHello..ClientKeyExchange.
        let master =
            MasterSecret::derive_extended(pre_master_secret.as_bytes(), &hs.transcript.hash())?;
        drop(pre_master_secret);

        if hs.certificate_requested {
            // RFC 5246 §7.4.8: sign every handshake message so far.
            let signature = self.credentials.key.sign(hs.transcript.bytes())?;
            let mut verify = Vec::new();
            DigitallySigned {
                scheme: SCHEME_ECDSA_SECP384R1_SHA384,
                signature,
            }
            .encode(&mut verify)?;
            self.queue_handshake(hs, 0, HT_CERTIFICATE_VERIFY, &verify)?;
        }

        master
            .key_block(&hs.client_random, &hs.server_random)?
            .install(self.role, &mut self.records)?;
        // RFC 6347 §4.1: only our write side changes epoch with our CCS.
        self.flight.push_change_cipher_spec();
        self.records.activate_write()?;

        let verify_data = master.verify_data(DtlsRole::Client, &hs.transcript.hash())?;
        self.queue_handshake(hs, 1, HT_FINISHED, &verify_data)?;
        hs.master = Some(master);

        self.start_flight(now)?;
        self.state = State::ClientWaitChangeCipherSpec;
        Ok(())
    }

    // ----- server ---------------------------------------------------------

    /// Server before any state exists: only an unfragmented epoch-0
    /// `ClientHello` is looked at.
    ///
    /// RFC 6347 §4.2.1 / NIST 800-53 Rev5: SC-5 -- without a valid cookie the
    /// only reaction is a `HelloVerifyRequest` (smaller than the
    /// `ClientHello`, rate limited); no handshake state is allocated.
    fn on_initial_record(&mut self, record: &RecordView<'_>, now: Instant) {
        let acceptable_version =
            record.version == DTLS_1_2_VERSION || record.version == DTLS_1_0_VERSION;
        if record.epoch != 0 || record.content_type != ContentType::Handshake || !acceptable_version
        {
            self.count_discard();
            return;
        }
        let mut r = Reader::new(record.payload);
        let Ok(header) = HandshakeHeader::parse(&mut r) else {
            self.count_discard();
            return;
        };
        let length = usize::try_from(header.length).unwrap_or(usize::MAX);
        if header.msg_type != HT_CLIENT_HELLO
            || header.fragment_offset != 0
            || header.fragment_length != header.length
            || length > MAX_MESSAGE_LEN
        {
            self.count_fragment_rejected();
            return;
        }
        let Ok(body) = r.take(length) else {
            self.count_fragment_rejected();
            return;
        };
        // NIST 800-53 Rev5: SC-5 -- cheapest checks first. Without a cookie
        // of the right length nothing can verify, and once the
        // HelloVerifyRequest rate is used up nothing would be sent either:
        // such a datagram costs neither a MAC nor a full parse.
        let Ok(parts) = ClientHello::split_cookie(body) else {
            self.count_fragment_rejected();
            return;
        };
        let has_cookie = parts.cookie.len() == COOKIE_LEN;
        if !has_cookie && !self.hello_verify_allowed(now) {
            self.count_discard();
            return;
        }
        let cookie = compute_cookie(&self.cookie_secret, &self.peer_binding, &parts);
        let verified = has_cookie && uc_crypto::constant_time::eq(parts.cookie, &cookie);
        if !verified && !self.hello_verify_allowed(now) {
            self.count_discard();
            return;
        }
        // A malformed ClientHello gets no answer, cookie or not.
        let Ok(hello) = ClientHello::parse(body) else {
            self.count_fragment_rejected();
            return;
        };
        if !verified {
            self.send_hello_verify_request(&header, record.sequence_number, &cookie, now);
            return;
        }
        // The cookie came back: the peer is reachable at its address and the
        // ClientHello is the one the cookie was issued for.
        if let Err(failure) = self.on_client_hello(&hello, &header, body, record, now) {
            self.fail(failure);
        }
    }

    /// The current one-second window and the `HelloVerifyRequest`s sent in it.
    fn hello_verify_usage(&self, now: Instant) -> (Instant, u32) {
        match self.hello_verify_window {
            Some((start, sent))
                if now.saturating_duration_since(start) < Duration::from_secs(1) =>
            {
                (start, sent)
            }
            _ => (now, 0),
        }
    }

    /// True while another `HelloVerifyRequest` may be sent this second.
    fn hello_verify_allowed(&self, now: Instant) -> bool {
        self.hello_verify_usage(now).1 < MAX_HELLO_VERIFY_PER_SECOND
    }

    fn send_hello_verify_request(
        &mut self,
        client_hello: &HandshakeHeader,
        record_sequence: u64,
        cookie: &[u8],
        now: Instant,
    ) {
        let (window_start, sent) = self.hello_verify_usage(now);
        // NIST 800-53 Rev5: SC-5 -- rate limit on the one thing an
        // unverified source can make us send.
        if sent >= MAX_HELLO_VERIFY_PER_SECOND {
            self.count_discard();
            return;
        }
        self.hello_verify_window = Some((window_start, sent + 1));
        let mut body = Vec::new();
        let request = HelloVerifyRequest {
            // RFC 6347 §4.2.1: servers SHOULD use version 1.0 here.
            version: DTLS_1_0_VERSION,
            cookie: cookie.to_vec(),
        };
        // RFC 6347 §4.2.1: the HelloVerifyRequest reuses the record sequence
        // number of the ClientHello; no counter of ours moves.
        let datagram = request
            .encode(&mut body)
            .ok()
            .and_then(|()| {
                handshake_message_bytes(HT_HELLO_VERIFY_REQUEST, client_hello.message_seq, &body)
                    .ok()
            })
            .and_then(|message| {
                encode_plaintext_record(ContentType::Handshake, record_sequence, &message).ok()
            });
        if let Some(datagram) = datagram {
            self.queue_datagram(datagram);
        }
    }

    /// A `ClientHello` with a valid cookie: check the offer and send flight 4.
    fn on_client_hello(
        &mut self,
        hello: &ClientHello,
        header: &HandshakeHeader,
        body: &[u8],
        record: &RecordView<'_>,
        now: Instant,
    ) -> Step {
        check_client_offer(hello)?;
        let ext = &hello.extensions;

        let server_random = uc_crypto::random::generate_random::<RANDOM_LEN>()?;
        // RFC 6347 §4.2.2: our ServerHello takes the message_seq of this
        // ClientHello (1 after a cookie exchange); the client's next is +1.
        let mut hs = HandshakeContext::new(
            hello.random,
            server_random,
            header.message_seq.wrapping_add(1),
            header.message_seq,
        );
        hs.transcript
            .push(HT_CLIENT_HELLO, header.message_seq, body)?;
        // RFC 6347 §4.2.1: the first ServerHello uses the record sequence
        // number of the ClientHello it answers.
        self.records
            .raise_plaintext_write_sequence(record.sequence_number);

        self.flight.clear();
        let secure_renegotiation = ext.renegotiation_info.is_some()
            || hello.cipher_suites.contains(&SCSV_RENEGOTIATION_INFO);
        let server_hello = ServerHello {
            version: DTLS_1_2_VERSION,
            random: server_random,
            session_id: Vec::new(),
            cipher_suite: CIPHER_SUITE,
            compression_method: COMPRESSION_NULL,
            // RFC 5246 §7.4.1.4: only extensions the client offered.
            extensions: Extensions {
                supported_groups: None,
                ec_point_formats: ext
                    .ec_point_formats
                    .as_ref()
                    .map(|_| vec![POINT_FORMAT_UNCOMPRESSED]),
                signature_algorithms: None,
                // RFC 5764 §4.1.3: an MKI the client offered is not used;
                // the answer carries an empty one.
                use_srtp: Some(UseSrtp {
                    profiles: vec![SRTP_AEAD_AES_256_GCM],
                    mki: Vec::new(),
                }),
                extended_master_secret: true,
                renegotiation_info: secure_renegotiation.then(Vec::new),
                first_unknown: None,
            },
        };
        let mut out = Vec::new();
        server_hello.encode(&mut out)?;
        self.queue_handshake(&mut hs, 0, HT_SERVER_HELLO, &out)?;

        let certificate = self.credentials.certificate_message.clone();
        self.queue_handshake(&mut hs, 0, HT_CERTIFICATE, &certificate)?;

        // NIST 800-53 Rev5: SC-12 -- fresh ECDHE P-384 key per association,
        // signed with the certificate key (RFC 8422 §5.4).
        let ecdh = P384EphemeralKeyPair::generate()?;
        let mut params = Vec::new();
        EcdheParams {
            named_curve: GROUP_SECP384R1,
            public: ecdh.public_key_bytes().to_vec(),
        }
        .encode(&mut params)?;
        let signature = self
            .credentials
            .key
            .sign(&server_key_exchange_signed_content(
                &hs.client_random,
                &hs.server_random,
                &params,
            ))?;
        let mut key_exchange = params;
        DigitallySigned {
            scheme: SCHEME_ECDSA_SECP384R1_SHA384,
            signature,
        }
        .encode(&mut key_exchange)?;
        self.queue_handshake(&mut hs, 0, HT_SERVER_KEY_EXCHANGE, &key_exchange)?;
        hs.ecdh = Some(ecdh);

        // NIST 800-53 Rev5: SC-23 / IA-3 -- always require a client
        // certificate (RFC 5763 §5: both sides authenticate by fingerprint).
        let mut request = Vec::new();
        CertificateRequest {
            certificate_types: vec![CERT_TYPE_ECDSA_SIGN],
            signature_algorithms: vec![SCHEME_ECDSA_SECP384R1_SHA384],
            certificate_authorities: Vec::new(),
        }
        .encode(&mut request)?;
        self.queue_handshake(&mut hs, 0, HT_CERTIFICATE_REQUEST, &request)?;
        self.certificate_requested = true;
        self.queue_handshake(&mut hs, 0, HT_SERVER_HELLO_DONE, &[])?;

        self.start_flight(now)?;
        self.handshake = Some(hs);
        self.state = State::ServerWaitCertificate;
        Ok(())
    }

    fn on_client_key_exchange(
        &mut self,
        hs: &mut HandshakeContext,
        message: &CompleteMessage,
    ) -> Step {
        let key_exchange = ClientKeyExchange::parse(&message.body)?;
        // From here on the message is in the transcript and the ECDHE key
        // is used up: a ClientKeyExchange that parses but whose point the
        // agreement refuses fails at once (it cannot be told from the
        // peer's own; see the residual in the module documentation).
        hs.commit();
        hs.transcript
            .push(HT_CLIENT_KEY_EXCHANGE, message.message_seq, &message.body)?;
        let ecdh = hs.ecdh.take().ok_or_else(Failure::internal)?;
        let pre_master_secret = ecdh
            .agree(&key_exchange.public)
            .map_err(|_| Failure::new(FailureCause::ProtocolViolation, alert::ILLEGAL_PARAMETER))?;
        // RFC 7627 §3: session_hash covers ClientHello..ClientKeyExchange.
        let master =
            MasterSecret::derive_extended(pre_master_secret.as_bytes(), &hs.transcript.hash())?;
        drop(pre_master_secret);
        master
            .key_block(&hs.client_random, &hs.server_random)?
            .install(self.role, &mut self.records)?;
        hs.master = Some(master);
        self.state = State::ServerWaitCertificateVerify;
        Ok(())
    }

    /// RFC 5246 §7.4.8: the client proves possession of its certificate key
    /// by signing every handshake message so far.
    fn on_certificate_verify(
        &mut self,
        hs: &mut HandshakeContext,
        message: &CompleteMessage,
    ) -> Step {
        let bad_signature = |alert| Failure::new(FailureCause::BadSignature, alert);
        let mut r = Reader::new(&message.body);
        let signed = DigitallySigned::parse(&mut r)
            .and_then(|signed| r.finish().map(|()| signed))
            .map_err(|_| bad_signature(alert::DECODE_ERROR))?;
        if signed.scheme != SCHEME_ECDSA_SECP384R1_SHA384 {
            return Err(Failure::unsupported());
        }
        let key = hs.peer_public_key.ok_or_else(Failure::internal)?;
        verify_p384(&key, hs.transcript.bytes(), &signed.signature)
            .map_err(|_| bad_signature(alert::DECRYPT_ERROR))?;
        hs.commit();
        hs.transcript
            .push(HT_CERTIFICATE_VERIFY, message.message_seq, &message.body)?;
        self.state = State::ServerWaitChangeCipherSpec;
        Ok(())
    }

    // ----- both roles -----------------------------------------------------

    /// Verifies the peer's `Finished` (RFC 5246 §7.4.9) and completes the
    /// handshake. As server this also sends flight 6.
    fn on_finished(
        &mut self,
        hs: &mut HandshakeContext,
        message: &CompleteMessage,
        now: Instant,
    ) -> Step {
        // Epoch 1: authenticated, never deferred.
        hs.commit();
        let finished = Finished::parse(&message.body)?;
        let master = hs.master.take().ok_or_else(Failure::internal)?;
        let peer = match self.role {
            DtlsRole::Client => DtlsRole::Server,
            DtlsRole::Server => DtlsRole::Client,
        };
        let expected = master.verify_data(peer, &hs.transcript.hash())?;
        if !uc_crypto::constant_time::eq(&expected, &finished.verify_data) {
            return Err(Failure::new(
                FailureCause::FinishedMismatch,
                alert::DECRYPT_ERROR,
            ));
        }
        hs.transcript
            .push(HT_FINISHED, message.message_seq, &message.body)?;

        self.flight.clear();
        self.timer.stop();
        if self.role.is_server() {
            // Flight 6. The server Finished covers the client Finished.
            self.flight.push_change_cipher_spec();
            self.records.activate_write()?;
            let verify_data = master.verify_data(DtlsRole::Server, &hs.transcript.hash())?;
            self.queue_handshake(hs, 1, HT_FINISHED, &verify_data)?;
            self.peer_triggered_resends = 0;
            self.transmit_flight(now)?;
            // RFC 6347 §4.2.4: the last flight has no timer; it is resent
            // when the peer retransmits its own last flight, and MUST stay
            // available for that for at least twice the maximum segment
            // lifetime. It is about a hundred bytes (ChangeCipherSpec and
            // Finished); resends stay rate limited by the hold-off.
            self.linger_deadline = Some(now + FINAL_FLIGHT_RETENTION);
        }

        // NIST 800-53 Rev5: SC-12 -- keys leave only now: fingerprint,
        // proof of possession and Finished have all verified. `master` is
        // dropped (and wiped) at the end of this function, right after the
        // export (RFC 5764 §4.2).
        let keys = master.export_srtp(&hs.client_random, &hs.server_random)?;
        self.next_recv_seq = message.message_seq.wrapping_add(1);
        self.state = State::Connected;
        self.queue_event(AssociationEvent::Connected { keys });
        Ok(())
    }
}

/// CNSA 2.0 / plan §2.2: a `ClientHello` must offer our one profile.
///
/// NIST 800-53 Rev5: SC-13 -- the profile is fixed; an offer that does not
/// contain it is refused, never negotiated down.
fn check_client_offer(hello: &ClientHello) -> Step {
    if hello.version != DTLS_1_2_VERSION {
        return Err(Failure::new(
            FailureCause::UnsupportedParameters,
            alert::PROTOCOL_VERSION,
        ));
    }
    let ext = &hello.extensions;
    let offers_group = ext
        .supported_groups
        .as_ref()
        .is_some_and(|groups| groups.contains(&GROUP_SECP384R1));
    let offers_scheme = ext
        .signature_algorithms
        .as_ref()
        .is_some_and(|schemes| schemes.contains(&SCHEME_ECDSA_SECP384R1_SHA384));
    if !hello.cipher_suites.contains(&CIPHER_SUITE)
        || !hello.compression_methods.contains(&COMPRESSION_NULL)
        || !offers_group
        || !offers_scheme
    {
        return Err(Failure::unsupported());
    }
    check_common_extensions(ext)?;
    // RFC 5764 §4.1.1: pick our profile from the offer. §4.1.3: an offered
    // MKI is not an error; it is ignored and answered with an empty one.
    let offers_profile = ext
        .use_srtp
        .as_ref()
        .is_some_and(|use_srtp| use_srtp.profiles.contains(&SRTP_AEAD_AES_256_GCM));
    if !offers_profile {
        return Err(Failure::new(
            FailureCause::NoSrtpProfile,
            alert::HANDSHAKE_FAILURE,
        ));
    }
    Ok(())
}

/// Extension rules shared by `ClientHello` and `ServerHello`.
fn check_common_extensions(ext: &Extensions) -> Step {
    // NIST 800-53 Rev5: SC-13 / SC-23 -- RFC 7627 §5.2 / user decision 3:
    // extended master secret is required.
    if !ext.extended_master_secret {
        return Err(Failure::new(
            FailureCause::NoExtendedMasterSecret,
            alert::HANDSHAKE_FAILURE,
        ));
    }
    if ext
        .ec_point_formats
        .as_ref()
        .is_some_and(|formats| !formats.contains(&POINT_FORMAT_UNCOMPRESSED))
    {
        return Err(Failure::unsupported());
    }
    // RFC 5746 §3.4 / §3.6: on an initial handshake the value must be empty.
    if ext
        .renegotiation_info
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(Failure::new(
            FailureCause::ProtocolViolation,
            alert::HANDSHAKE_FAILURE,
        ));
    }
    Ok(())
}

// The driver moves the association into a task (PERF-007): keep it `Send`.
const _: fn() = || {
    const fn assert_send<T: Send>() {}
    assert_send::<DtlsAssociation>();
};

impl std::fmt::Debug for DtlsAssociation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsAssociation")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}
