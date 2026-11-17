//! Media Session for secure RTP/SRTP.
//!
//! Coordinates ICE and DTLS to establish a secure media session for voice
//! calls, and hands the negotiated SRTP keys to the audio pipeline.
//!
//! The session never protects media itself: the audio pipeline builds its
//! own SRTP contexts from [`MediaSession::negotiated_srtp_keys`] with its own
//! SSRC (one SRTP path, no async locks on the media path).
//!
//! ## DTLS-SRTP (RFC 5763, RFC 5764)
//!
//! [`MediaSession::begin_secure`] runs ICE (when it applies) and starts the
//! call's DTLS driver task ([`crate::dtls_driver`]); it does not wait for
//! the handshake. The owner polls [`MediaSession::poll_secure`] and, once
//! that returned `Ready`, [`MediaSession::poll_security_closed`]. Neither
//! blocks. There is one association per session: a second `begin_secure`
//! is refused, and the DTLS role is fixed from that moment.
//!
//! ## Socket ownership (RFC 5764 §5.1.2)
//!
//! The caller binds one `std::net::UdpSocket` per call and passes a
//! `try_clone` here; the port is never rebound.
//!
//! | Phase | Reader |
//! |---|---|
//! | before `begin_secure` | nobody (datagrams wait in the kernel queue) |
//! | ICE checks | the ICE handler; DTLS datagrams go to a small stash |
//! | handshake | the DTLS driver, which then holds the only tokio view |
//! | media | the audio I/O thread |
//!
//! The driver drops its tokio view before it reports the keys, so the
//! audio pipeline is the only reader when it starts. After that the driver
//! only sends, through a std clone of the socket.

use crate::dtls_driver::{
    self, CauseBasis, DriverEvent, DriverHandle, DriverParams, DriverPoll, DriverTimings,
    EarlyDtls, SecureProgress, SecurityCause,
};
use crate::dtls_forward::{DtlsForwardTx, dtls_forward_channel};
use crate::dtls_identity::DtlsIdentity;
use crate::ice_handler::{IceEvent, IceHandler, is_ice_mismatch};
use crate::sdp_dtls::DtlsSdpParams;
use crate::{SipUaError, SipUaResult};
use proto_dtls::{AssociationConfig, DtlsCredentials, DtlsRole, SrtpKeyingMaterial, SrtpProfile};
use proto_ice::{IceConfig, IceCredentials};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// A wiped-on-drop key or salt buffer.
pub type KeyBuf = Zeroizing<Vec<u8>>;

/// SRTP master keys and salts resolved by the final DTLS role
/// (RFC 5764 §4.2): `local_*` protects what we send, `remote_*` what we
/// receive. Not `Clone`; wiped on drop; `Debug` is redacted.
pub struct NegotiatedSrtpKeys {
    /// SRTP protection profile (AES-256-GCM, CNSA 2.0).
    profile: SrtpProfile,
    /// Our write master key.
    local_key: Zeroizing<Vec<u8>>,
    /// Our write master salt.
    local_salt: Zeroizing<Vec<u8>>,
    /// Peer write master key.
    remote_key: Zeroizing<Vec<u8>>,
    /// Peer write master salt.
    remote_salt: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for NegotiatedSrtpKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NegotiatedSrtpKeys")
            .field("profile", &self.profile)
            .field("keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl NegotiatedSrtpKeys {
    /// Resolves the per-direction keys from DTLS-SRTP keying material.
    #[must_use]
    pub fn from_keying_material(km: &SrtpKeyingMaterial, role: DtlsRole) -> Self {
        Self {
            profile: km.profile,
            local_key: Zeroizing::new(km.local_key(role).to_vec()),
            local_salt: Zeroizing::new(km.local_salt(role).to_vec()),
            remote_key: Zeroizing::new(km.remote_key(role).to_vec()),
            remote_salt: Zeroizing::new(km.remote_salt(role).to_vec()),
        }
    }

    /// SRTP protection profile.
    #[must_use]
    pub const fn profile(&self) -> SrtpProfile {
        self.profile
    }

    /// Our write master key.
    #[must_use]
    pub fn local_key(&self) -> &[u8] {
        &self.local_key
    }

    /// Our write master salt.
    #[must_use]
    pub fn local_salt(&self) -> &[u8] {
        &self.local_salt
    }

    /// Peer write master key.
    #[must_use]
    pub fn remote_key(&self) -> &[u8] {
        &self.remote_key
    }

    /// Peer write master salt.
    #[must_use]
    pub fn remote_salt(&self) -> &[u8] {
        &self.remote_salt
    }

    /// Moves the key buffers out without copying them:
    /// `(profile, local_key, local_salt, remote_key, remote_salt)`.
    #[must_use]
    pub fn into_parts(self) -> (SrtpProfile, KeyBuf, KeyBuf, KeyBuf, KeyBuf) {
        (
            self.profile,
            self.local_key,
            self.local_salt,
            self.remote_key,
            self.remote_salt,
        )
    }
}

/// Media session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaSessionState {
    /// Session created but not started.
    New,
    /// Gathering ICE candidates.
    Gathering,
    /// ICE connectivity checks in progress.
    Connecting,
    /// DTLS handshake in progress.
    Securing,
    /// Session established, media can flow.
    Active,
    /// Session is being closed.
    Closing,
    /// Session has been closed.
    Closed,
    /// Session failed to establish.
    Failed,
}

/// Media session manages the complete secure media pipeline.
pub struct MediaSession {
    /// Session state.
    state: MediaSessionState,
    /// ICE handler for connectivity.
    ice_handler: IceHandler,
    /// Our DTLS certificate chain and signing key (the key is shared with
    /// the process-wide identity by reference count, not copied).
    credentials: DtlsCredentials,
    /// Our DTLS role (RFC 5763 §5). Fixed once `begin_secure` has run.
    dtls_role: DtlsRole,
    /// Where the DTLS-SRTP handshake stands.
    secure: SecureState,
    /// The call's DTLS driver task, from `begin_secure` until `close`.
    driver: Option<DriverHandle>,
    /// The one remote address the DTLS association serves.
    dtls_remote: Option<SocketAddr>,
    /// SRTP keying material exported by a completed DTLS handshake.
    keying_material: Option<SrtpKeyingMaterial>,
    /// Per-call media socket (std clone) not yet converted to tokio.
    std_socket: Option<std::net::UdpSocket>,
    /// A second std clone, kept for the DTLS driver's sends after the
    /// handshake.
    send_socket: Option<std::net::UdpSocket>,
    /// Tokio view of the media socket used for ICE and the DTLS handshake.
    socket: Option<Arc<UdpSocket>>,
    /// DTLS datagrams read off the socket by the ICE check loop.
    early_dtls: EarlyDtls,
    /// Local SSRC for outbound RTP.
    local_ssrc: u32,
    /// Remote SSRC for inbound RTP.
    remote_ssrc: Option<u32>,
    /// Local address.
    local_addr: SocketAddr,
    /// Remote address (from ICE).
    remote_addr: Option<SocketAddr>,
    /// Event sender.
    event_tx: mpsc::Sender<MediaSessionEvent>,
    /// ICE event receiver.
    #[allow(dead_code)]
    ice_rx: mpsc::Receiver<IceEvent>,
}

/// Where the session's DTLS-SRTP handshake stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureState {
    /// `begin_secure` has not run.
    Idle,
    /// The driver is running the handshake.
    Handshaking,
    /// Keys are available.
    Ready,
    /// The handshake failed, or could not be started; with what the cause
    /// rests on.
    Failed(SecurityCause, CauseBasis),
    /// The association ended after the handshake (closed by the peer, by
    /// an alert, or locally); keys are gone.
    Ended(SecurityCause),
}

/// Events emitted by the media session.
#[derive(Debug, Clone)]
pub enum MediaSessionEvent {
    /// State changed.
    StateChanged {
        /// New state.
        state: MediaSessionState,
    },
    /// ICE candidate discovered (for SDP).
    LocalCandidate {
        /// SDP candidate line.
        sdp_line: String,
    },
    /// ICE credentials generated (for SDP).
    LocalCredentials {
        /// ICE ufrag.
        ufrag: String,
        /// ICE password.
        pwd: String,
    },
    /// DTLS fingerprint generated (for SDP).
    LocalFingerprint {
        /// SHA-384 fingerprint.
        fingerprint: String,
    },
    /// Media session is ready for RTP.
    Ready {
        /// Local address for sending.
        local_addr: SocketAddr,
        /// Remote address for sending.
        remote_addr: SocketAddr,
    },
    /// Media session failed.
    Failed {
        /// Error reason.
        reason: String,
    },
}

impl MediaSession {
    /// Creates a new media session.
    ///
    /// # Arguments
    /// * `local_addr` - Local address for media
    /// * `is_outbound` - True for outbound calls (ICE controlling). The DTLS
    ///   role defaults by direction and must be set from `a=setup` with
    ///   [`Self::set_dtls_role`] before [`Self::begin_secure`].
    /// * `ice_config` - ICE configuration with STUN/TURN servers
    /// * `socket` - Clone of the per-call media socket (shared fd)
    /// * `identity` - DTLS-SRTP identity (certificate + key)
    /// * `event_tx` - Channel for media session events
    pub fn new(
        local_addr: SocketAddr,
        is_outbound: bool,
        ice_config: IceConfig,
        socket: std::net::UdpSocket,
        identity: &DtlsIdentity,
        event_tx: mpsc::Sender<MediaSessionEvent>,
    ) -> Self {
        // Create the channel for ICE events
        let (ice_tx, ice_rx) = mpsc::channel(32);

        // Create handlers based on call direction
        let ice_handler = if is_outbound {
            IceHandler::for_outbound(local_addr, ice_config, ice_tx)
        } else {
            IceHandler::for_inbound(local_addr, ice_config, ice_tx)
        };

        // Default by direction; the real role comes from a=setup.
        let dtls_role = if is_outbound {
            DtlsRole::Client
        } else {
            DtlsRole::Server
        };

        // Generate random SSRC
        let local_ssrc = rand_ssrc();

        Self {
            state: MediaSessionState::New,
            ice_handler,
            // NIST 800-53 Rev5: SC-12 -- shares the key; no per-call copy.
            credentials: identity.credentials().clone(),
            dtls_role,
            secure: SecureState::Idle,
            driver: None,
            dtls_remote: None,
            keying_material: None,
            std_socket: Some(socket),
            send_socket: None,
            socket: None,
            early_dtls: EarlyDtls::new(),
            local_ssrc,
            remote_ssrc: None,
            local_addr,
            remote_addr: None,
            event_tx,
            ice_rx,
        }
    }

    /// Gets the current session state.
    pub const fn state(&self) -> MediaSessionState {
        self.state
    }

    /// Gets the local SSRC.
    pub const fn local_ssrc(&self) -> u32 {
        self.local_ssrc
    }

    /// Sets the remote SSRC.
    pub const fn set_remote_ssrc(&mut self, ssrc: u32) {
        self.remote_ssrc = Some(ssrc);
    }

    /// Gets local ICE credentials for SDP.
    pub fn local_ice_credentials(&self) -> IceCredentials {
        self.ice_handler.local_credentials()
    }

    /// Sets remote ICE credentials from SDP.
    pub fn set_remote_ice_credentials(&mut self, credentials: IceCredentials) {
        self.ice_handler.set_remote_credentials(credentials);
    }

    /// Sets the DTLS role resolved from `a=setup` (RFC 5763 §5).
    ///
    /// # Errors
    /// Returns an error once [`Self::begin_secure`] has run: the role of an
    /// association cannot change (RFC 5763 §5), and keys are resolved by it
    /// (RFC 5764 §4.2).
    pub fn set_dtls_role(&mut self, role: DtlsRole) -> SipUaResult<()> {
        if self.secure != SecureState::Idle {
            return Err(SipUaError::InvalidState(
                "DTLS role is fixed once the handshake has started".to_string(),
            ));
        }
        self.dtls_role = role;
        Ok(())
    }

    /// Returns the current DTLS role.
    pub const fn dtls_role(&self) -> DtlsRole {
        self.dtls_role
    }

    /// Gets local DTLS fingerprint for SDP (`sha-384 AB:CD:...`).
    pub fn local_dtls_fingerprint(&self) -> String {
        self.credentials.fingerprint().to_sdp()
    }

    /// Gets local ICE candidates formatted for SDP.
    pub fn local_ice_candidates_sdp(&self) -> Vec<String> {
        self.ice_handler.format_sdp_candidates()
    }

    /// Adds a remote ICE candidate from SDP.
    pub fn add_remote_ice_candidate(&mut self, sdp_line: &str) -> SipUaResult<()> {
        let candidate = IceHandler::parse_sdp_candidate(sdp_line)?;
        self.ice_handler.add_remote_candidate(&candidate);
        Ok(())
    }

    /// Sets the remote media address directly (for non-ICE calls).
    ///
    /// This is used when the remote endpoint doesn't support ICE and the
    /// remote address must be extracted from the SDP c= and m= lines.
    pub const fn set_remote_addr(&mut self, addr: SocketAddr) {
        self.remote_addr = Some(addr);
    }

    /// Starts the media session.
    ///
    /// This begins ICE gathering, then connectivity checks,
    /// then DTLS handshake, and finally creates SRTP contexts.
    pub async fn start(&mut self) -> SipUaResult<()> {
        info!("Starting media session");

        self.ensure_socket()?;

        // Update state and notify
        self.set_state(MediaSessionState::Gathering).await;

        // Send local credentials
        let creds = self.ice_handler.local_credentials();
        let _ = self
            .event_tx
            .send(MediaSessionEvent::LocalCredentials {
                ufrag: creds.ufrag.clone(),
                pwd: creds.pwd.clone(),
            })
            .await;

        // Send local fingerprint
        let fp = self.local_dtls_fingerprint();
        if !fp.is_empty() {
            let _ = self
                .event_tx
                .send(MediaSessionEvent::LocalFingerprint { fingerprint: fp })
                .await;
        }

        // Start ICE gathering
        self.ice_handler.gather_candidates().await?;

        // Send local candidates
        for sdp_line in self.ice_handler.format_sdp_candidates() {
            let _ = self
                .event_tx
                .send(MediaSessionEvent::LocalCandidate { sdp_line })
                .await;
        }

        Ok(())
    }

    /// Converts the per-call std socket into the tokio socket shared by ICE
    /// and the DTLS handshake (RFC 8445 §2.2, RFC 5764 §5.1.2). Never binds
    /// a new socket.
    fn ensure_socket(&mut self) -> SipUaResult<Arc<UdpSocket>> {
        if let Some(sock) = &self.socket {
            return Ok(Arc::clone(sock));
        }
        // Once the driver has the socket there is no tokio view to give
        // out, and making one would set O_NONBLOCK under the audio thread.
        let std_sock = self
            .std_socket
            .take()
            .ok_or_else(|| SipUaError::InvalidState("media socket released".to_string()))?;
        // For the DTLS driver's sends after the handshake.
        let send_socket = std_sock
            .try_clone()
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;
        // Sets O_NONBLOCK on the shared file description; the audio
        // pipeline clears it again at handoff (see `release_socket`).
        std_sock
            .set_nonblocking(true)
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;
        let socket = Arc::new(
            UdpSocket::from_std(std_sock).map_err(|e| SipUaError::TransportError(e.to_string()))?,
        );
        self.send_socket = Some(send_socket);
        self.socket = Some(Arc::clone(&socket));
        self.ice_handler.set_socket(Arc::clone(&socket));
        Ok(socket)
    }

    /// Drops every reference this session holds to the media socket so the
    /// audio pipeline becomes its sole reader. Call before starting audio.
    ///
    /// On a DTLS-SRTP call the tokio view already went to the driver in
    /// [`Self::begin_secure`], and the driver dropped it before the keys
    /// were reported; the driver keeps a std clone for sending only.
    pub fn release_socket(&mut self) {
        self.socket = None;
        self.std_socket = None;
        self.send_socket = None;
        self.ice_handler.clear_socket();
    }

    /// Selects the media path (ICE checks when ICE applies) and starts the
    /// DTLS-SRTP handshake with the peer. Returns as soon as the driver
    /// task runs; the handshake result comes from [`Self::poll_secure`].
    ///
    /// `remote` carries the fingerprints of this dialog's SDP that the
    /// peer's certificate must match (RFC 5763 §5 / RFC 8122 §5). Set
    /// the DTLS role first. The handshake budget in `timings` starts when
    /// this function starts the driver, after ICE.
    ///
    /// `async` only because the ICE checks run inside it.
    ///
    /// # Errors
    /// [`SipUaError::InvalidState`] on a second call (one association per
    /// call), and any ICE or configuration failure. On every error the
    /// session is `Failed` and callers must end the call (fail closed).
    pub async fn begin_secure(
        &mut self,
        call_id: &str,
        remote: &DtlsSdpParams,
        timings: DriverTimings,
    ) -> SipUaResult<()> {
        // NIST 800-53 Rev5: SC-23 -- one association per call; from here
        // on the role cannot change either.
        if self.secure != SecureState::Idle {
            return Err(SipUaError::InvalidState(
                "DTLS-SRTP was already started for this call".to_string(),
            ));
        }
        self.secure = SecureState::Failed(SecurityCause::Internal, CauseBasis::Local);
        match self.start_driver(call_id, remote, timings).await {
            Ok(handle) => {
                self.driver = Some(handle);
                self.secure = SecureState::Handshaking;
                self.set_state(MediaSessionState::Securing).await;
                Ok(())
            }
            Err(e) => {
                self.release_socket();
                self.set_state(MediaSessionState::Failed).await;
                Err(e)
            }
        }
    }

    /// Path selection and driver start for [`Self::begin_secure`].
    async fn start_driver(
        &mut self,
        call_id: &str,
        remote: &DtlsSdpParams,
        timings: DriverTimings,
    ) -> SipUaResult<DriverHandle> {
        info!("Establishing media session connectivity");

        // RFC 8122 §5: nothing to authenticate the peer against.
        if remote.fingerprints.is_empty() {
            return Err(SipUaError::DtlsError(
                "no remote fingerprint signalled".to_string(),
            ));
        }
        self.ensure_socket()?;

        self.set_state(MediaSessionState::Connecting).await;

        // RFC 8445 §5.1.1: ICE applies only when the SDP default destination
        // is one of the peer's candidates. A B2BUA that re-anchors c=/m= at
        // itself while relaying the far party's ICE attributes produces an
        // ICE mismatch; media then goes to the default destination directly,
        // without spending the check phase on unreachable candidates.
        let default_destination = self.remote_addr;
        let remote_candidates = self.ice_handler.remote_candidates();
        let mismatch = default_destination.is_some_and(|d| is_ice_mismatch(d, &remote_candidates))
            || remote_candidates.is_empty();

        let (local_addr, remote_addr) = if mismatch {
            let remote = default_destination.ok_or_else(|| {
                SipUaError::IceError("no ICE candidates and no SDP media address".to_string())
            })?;
            info!(
                remote = %remote,
                "ICE mismatch (default destination is not a peer candidate); using SDP address"
            );
            (self.local_addr, remote)
        } else {
            // RFC 5763 §5: a ClientHello that arrives during the checks is
            // kept for the association instead of being thrown away.
            match self.ice_handler.start_checks(&mut self.early_dtls).await {
                Ok(Some(pair)) => pair,
                Ok(None) => {
                    let remote = default_destination.ok_or_else(|| {
                        SipUaError::IceError("ICE failed and no SDP media address".to_string())
                    })?;
                    warn!(remote = %remote, "ICE failed; falling back to SDP media address");
                    (self.local_addr, remote)
                }
                Err(e) => return Err(e),
            }
        };

        self.remote_addr = Some(remote_addr);
        self.dtls_remote = Some(remote_addr);
        info!(
            local = %local_addr,
            remote = %remote_addr,
            "Media path selected"
        );

        let mut config = AssociationConfig::new(
            self.dtls_role,
            self.credentials.clone(),
            remote.fingerprints.clone(),
        );
        config.mtu = timings.mtu;
        config.initial_rto = timings.initial_rto;
        config.handshake_budget = timings.handshake_budget;
        // RFC 6347 §4.2.1 / NIST 800-53 Rev5: SC-23 -- the cookie covers
        // the peer's transport address.
        config.peer_binding = dtls_driver::peer_binding(remote_addr);

        // The session and the ICE handler give up their views: the driver
        // must hold the only one, so that dropping it hands the read side
        // to the audio I/O thread.
        self.ice_handler.clear_socket();
        let socket = self
            .socket
            .take()
            .ok_or_else(|| SipUaError::InvalidState("media socket released".to_string()))?;
        let send_socket = self
            .send_socket
            .take()
            .ok_or_else(|| SipUaError::InvalidState("media socket released".to_string()))?;
        // NIST 800-53 Rev5: SC-23 -- only what came from the selected
        // remote is fed to the association.
        let early = self.early_dtls.take_from(remote_addr);
        dtls_driver::spawn(DriverParams {
            call_id: call_id.to_string(),
            config,
            remote: remote_addr,
            socket,
            send_socket,
            early,
        })
    }

    /// Reports where the DTLS-SRTP handshake stands. Never blocks; call it
    /// from the owner's timer pass.
    ///
    /// `Ready` means the peer was authenticated against the SDP fingerprint
    /// and [`Self::negotiated_srtp_keys`] returns keys. `Failed` is
    /// terminal: the caller must end the call (fail closed).
    pub fn poll_secure(&mut self) -> SecureProgress {
        match self.secure {
            SecureState::Idle => return SecureProgress::Pending,
            SecureState::Ready => return SecureProgress::Ready,
            SecureState::Failed(cause, basis) => return SecureProgress::Failed(cause, basis),
            SecureState::Ended(cause) => {
                return SecureProgress::Failed(cause, CauseBasis::of_termination(cause));
            }
            SecureState::Handshaking => {}
        }
        let polled = self
            .driver
            .as_mut()
            .map_or(DriverPoll::Gone, DriverHandle::poll);
        let (cause, basis) = match polled {
            DriverPoll::Pending => return SecureProgress::Pending,
            DriverPoll::Event(DriverEvent::Connected { keys }) => {
                self.keying_material = Some(keys);
                self.secure = SecureState::Ready;
                self.set_state_now(MediaSessionState::Active);
                if let Some(remote_addr) = self.remote_addr {
                    let _ = self.event_tx.try_send(MediaSessionEvent::Ready {
                        local_addr: self.local_addr,
                        remote_addr,
                    });
                }
                info!("Media session established and ready");
                return SecureProgress::Ready;
            }
            DriverPoll::Event(DriverEvent::Failed(cause, basis)) => (cause, basis),
            // Not sent before `Connected`; fail closed if it happens.
            DriverPoll::Event(DriverEvent::Terminated(cause)) => {
                (cause, CauseBasis::of_termination(cause))
            }
            // The task ended without a result (it panicked or was
            // aborted): fail closed.
            // NIST 800-53 Rev5: AU-2 / AU-3 -- the driver wrote no record
            // for this, so its handle does.
            DriverPoll::Gone => {
                if let Some(driver) = self.driver.as_ref() {
                    driver.record_gone();
                }
                (SecurityCause::Internal, CauseBasis::Local)
            }
        };
        self.driver = None;
        self.secure = SecureState::Failed(cause, basis);
        self.set_state_now(MediaSessionState::Failed);
        SecureProgress::Failed(cause, basis)
    }

    /// The owner's own deadline for the handshake passed while
    /// [`Self::poll_secure`] still said `Pending`: gives up on the
    /// handshake. The driver is closed and the session is `Failed`
    /// (timeout, local basis), which is also what this returns; the caller
    /// must end the call (fail closed). Does nothing but report the state
    /// if the handshake is not running.
    ///
    /// NIST 800-53 Rev5: AU-2 / AU-3 -- leaves the one
    /// `dtls.handshake.failed` record of this handshake, with
    /// `origin="call-manager-deadline"`; the driver then writes none.
    pub fn abandon_secure(&mut self) -> SecureProgress {
        if self.secure != SecureState::Handshaking {
            return self.poll_secure();
        }
        if let Some(driver) = self.driver.take() {
            driver.abandon();
        }
        self.secure = SecureState::Failed(SecurityCause::Timeout, CauseBasis::Local);
        self.set_state_now(MediaSessionState::Failed);
        SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
    }

    /// After `Ready`: reports, once, that the DTLS association ended while
    /// the call was up (peer `close_notify`, peer fatal alert, or the
    /// driver task died). Never blocks.
    ///
    /// The keys are dropped and the session is no longer
    /// [`Self::is_ready`], so audio cannot be (re)started on it. What the
    /// returned cause rests on is [`CauseBasis::of_termination`].
    pub fn poll_security_closed(&mut self) -> Option<SecurityCause> {
        if self.secure != SecureState::Ready {
            return None;
        }
        let cause = match self.driver.as_mut().map(DriverHandle::poll) {
            Some(DriverPoll::Pending) => return None,
            Some(DriverPoll::Event(
                DriverEvent::Terminated(cause) | DriverEvent::Failed(cause, _),
            )) => cause,
            // A second `Connected` cannot happen; a missing or dead driver
            // means the association is no longer serviced.
            // NIST 800-53 Rev5: AU-2 / AU-3 -- the driver wrote no
            // `dtls.association.closed` record for this, so its handle
            // does (`origin="driver-gone"`).
            Some(DriverPoll::Event(DriverEvent::Connected { .. }) | DriverPoll::Gone) | None => {
                if let Some(driver) = self.driver.as_ref() {
                    driver.record_gone();
                }
                SecurityCause::Internal
            }
        };
        self.driver = None;
        // NIST 800-53 Rev5: SC-12 -- keys of a closed association are not
        // kept (wiped on drop).
        self.keying_material = None;
        self.secure = SecureState::Ended(cause);
        self.set_state_now(MediaSessionState::Failed);
        Some(cause)
    }

    /// Creates a new forward ring for post-handshake DTLS datagrams, gives
    /// its consumer half to the driver and returns the producer half for
    /// the audio I/O thread. The last ring attached wins, so call it each
    /// time the audio pipeline is (re)started; any number of calls in a
    /// row succeed (the driver keeps one slot for the newest ring).
    ///
    /// `None` unless the handshake completed and the driver is running.
    pub fn dtls_forward_tx(&mut self) -> Option<DtlsForwardTx> {
        if self.secure != SecureState::Ready {
            return None;
        }
        let driver = self.driver.as_ref()?;
        let (tx, rx) = dtls_forward_channel();
        driver.attach_forward(rx).then_some(tx)
    }

    /// The one remote address the DTLS association serves: DTLS datagrams
    /// from any other address are never passed to it.
    pub const fn dtls_remote(&self) -> Option<SocketAddr> {
        self.dtls_remote
    }

    /// Returns the remote media address if established.
    ///
    /// This returns `Some(addr)` after ICE connectivity is established.
    pub const fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Returns the local media address.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns true if the media session is active and SRTP keys exist.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, MediaSessionState::Active)
            && self.remote_addr.is_some()
            && self.keying_material.is_some()
    }

    /// Returns the negotiated SRTP keys, resolved by the final DTLS role.
    ///
    /// `None` unless [`Self::is_ready`]: callers must fail closed.
    pub fn negotiated_srtp_keys(&self) -> Option<NegotiatedSrtpKeys> {
        if !self.is_ready() {
            return None;
        }
        self.keying_material
            .as_ref()
            .map(|km| NegotiatedSrtpKeys::from_keying_material(km, self.dtls_role))
    }

    /// Closes the media session.
    ///
    /// The DTLS driver is told to close its association (one `close_notify`,
    /// RFC 5246 §7.2.1) and exit; this does not wait for it. During the
    /// handshake that cancels the handshake.
    pub async fn close(&mut self) -> SipUaResult<()> {
        info!("Closing media session");

        self.set_state(MediaSessionState::Closing).await;

        // Close DTLS. Dropping the handle also ends the driver if the
        // command could not be queued.
        if let Some(driver) = self.driver.take() {
            driver.close();
        }
        // A closed session never reports `Ready` (again) and cannot be
        // started a second time.
        self.secure = match self.secure {
            SecureState::Idle | SecureState::Handshaking => {
                SecureState::Failed(SecurityCause::Internal, CauseBasis::Local)
            }
            SecureState::Ready => SecureState::Ended(SecurityCause::Internal),
            ended @ (SecureState::Failed(..) | SecureState::Ended(_)) => ended,
        };

        // Drop keying material (zeroized on drop) and socket references
        self.keying_material = None;
        self.release_socket();

        self.set_state(MediaSessionState::Closed).await;

        Ok(())
    }

    /// Sets the state and notifies listeners without waiting (for the
    /// polling paths, which must not block).
    fn set_state_now(&mut self, state: MediaSessionState) {
        self.state = state;
        let _ = self
            .event_tx
            .try_send(MediaSessionEvent::StateChanged { state });
    }

    /// Sets the state and notifies listeners.
    async fn set_state(&mut self, state: MediaSessionState) {
        self.state = state;
        let _ = self
            .event_tx
            .send(MediaSessionEvent::StateChanged { state })
            .await;
    }
}

/// Generates a random SSRC.
#[allow(clippy::cast_possible_truncation)]
fn rand_ssrc() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // Simple PRNG for SSRC (in production, use a proper RNG)
    ((seed ^ (seed >> 17) ^ (seed << 13)) & 0xFFFF_FFFF) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdp_dtls::Setup;
    use proto_dtls::CertificateFingerprint;
    use std::time::Duration;

    fn session(outbound: bool) -> (MediaSession, std::net::UdpSocket) {
        let (tx, _rx) = mpsc::channel(10);
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_addr = sock.local_addr().unwrap();
        let id = DtlsIdentity::generate().unwrap();
        let session = MediaSession::new(
            local_addr,
            outbound,
            IceConfig::default(),
            sock.try_clone().unwrap(),
            &id,
            tx,
        );
        (session, sock)
    }

    #[tokio::test]
    async fn test_media_session_accessors() {
        let (session, sock) = session(true);
        assert_eq!(session.state(), MediaSessionState::New);
        assert_eq!(session.local_addr(), sock.local_addr().unwrap());
        assert!(session.remote_addr().is_none());
        assert!(!session.is_ready());
        assert!(session.negotiated_srtp_keys().is_none());
        assert!(session.local_dtls_fingerprint().starts_with("sha-384 "));
    }

    fn params(fingerprint: CertificateFingerprint) -> DtlsSdpParams {
        DtlsSdpParams {
            fingerprints: vec![fingerprint],
            setup: Setup::Active,
        }
    }

    #[tokio::test]
    async fn begin_secure_without_fingerprint_fails_closed() {
        let (mut session, _sock) = session(true);
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        session.set_remote_addr(peer.local_addr().unwrap());
        let empty = DtlsSdpParams {
            fingerprints: Vec::new(),
            setup: Setup::Active,
        };
        assert!(
            session
                .begin_secure("c1", &empty, DriverTimings::default())
                .await
                .is_err()
        );
        assert_eq!(session.state(), MediaSessionState::Failed);
        assert!(matches!(session.poll_secure(), SecureProgress::Failed(..)));
        assert!(!session.is_ready());
        assert!(session.negotiated_srtp_keys().is_none());
        assert!(session.dtls_forward_tx().is_none());
        // No second attempt on the same session, with or without a
        // fingerprint.
        let good = params(CertificateFingerprint::from_certificate_sha384(b"peer"));
        assert!(matches!(
            session
                .begin_secure("c1", &good, DriverTimings::default())
                .await,
            Err(SipUaError::InvalidState(_))
        ));
    }

    #[tokio::test]
    async fn begin_secure_without_remote_address_fails_closed() {
        let (mut session, _sock) = session(true);
        let good = params(CertificateFingerprint::from_certificate_sha384(b"peer"));
        assert!(
            session
                .begin_secure("c1", &good, DriverTimings::default())
                .await
                .is_err()
        );
        assert!(matches!(session.poll_secure(), SecureProgress::Failed(..)));
    }

    /// One association per call; the role is fixed when it starts; the
    /// media port is never rebound; a silent peer ends as a timeout and no
    /// keys ever appear.
    #[tokio::test]
    async fn begin_secure_once_locks_role_and_fails_closed_on_silence() {
        let (mut session, sock) = session(true);
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        session.set_remote_addr(peer_addr);
        session.set_dtls_role(DtlsRole::Server).unwrap();
        assert_eq!(session.poll_secure(), SecureProgress::Pending);

        let good = params(CertificateFingerprint::from_certificate_sha384(b"peer"));
        let timings = DriverTimings {
            handshake_budget: Duration::from_millis(300),
            ..DriverTimings::default()
        };
        session.begin_secure("c1", &good, timings).await.unwrap();
        assert_eq!(session.state(), MediaSessionState::Securing);
        assert_eq!(session.dtls_remote(), Some(peer_addr));
        assert_eq!(session.poll_secure(), SecureProgress::Pending);
        assert!(session.dtls_forward_tx().is_none());

        assert!(matches!(
            session.begin_secure("c1", &good, timings).await,
            Err(SipUaError::InvalidState(_))
        ));
        assert!(session.set_dtls_role(DtlsRole::Client).is_err());
        assert_eq!(session.dtls_role(), DtlsRole::Server);
        // The refused second start did not disturb the first.
        assert_eq!(session.poll_secure(), SecureProgress::Pending);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let outcome = loop {
            match session.poll_secure() {
                SecureProgress::Pending => {
                    assert!(tokio::time::Instant::now() < deadline, "no outcome");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                other => break other,
            }
        };
        assert_eq!(
            outcome,
            SecureProgress::Failed(SecurityCause::Timeout, CauseBasis::Local)
        );
        assert_eq!(session.state(), MediaSessionState::Failed);
        assert!(!session.is_ready());
        assert!(session.negotiated_srtp_keys().is_none());
        assert_eq!(session.poll_security_closed(), None);

        session.release_socket();
        // The caller's original socket is still usable after release.
        sock.send_to(b"x", peer_addr).unwrap();
    }

    #[test]
    fn negotiated_keys_follow_role() {
        let km = SrtpKeyingMaterial {
            client_write_key: vec![1; 32],
            server_write_key: vec![2; 32],
            client_write_salt: vec![3; 12],
            server_write_salt: vec![4; 12],
            profile: SrtpProfile::AeadAes256Gcm,
        };
        let c = NegotiatedSrtpKeys::from_keying_material(&km, DtlsRole::Client);
        assert_eq!(c.local_key(), &[1; 32]);
        assert_eq!(c.remote_salt(), &[4; 12]);
        let s = NegotiatedSrtpKeys::from_keying_material(&km, DtlsRole::Server);
        assert_eq!(s.local_key(), &[2; 32]);
        assert_eq!(s.remote_key(), &[1; 32]);
        assert!(!format!("{c:?}").contains('1'));
    }

    #[test]
    fn test_rand_ssrc() {
        let ssrc1 = rand_ssrc();
        let ssrc2 = rand_ssrc();
        assert!(ssrc1 > 0 || ssrc2 > 0);
    }
}
