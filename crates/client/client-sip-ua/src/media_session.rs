//! Media Session for secure RTP/SRTP.
//!
//! Coordinates ICE and DTLS to establish a secure media session for voice
//! calls, and hands the negotiated SRTP keys to the audio pipeline.
//!
//! The session never protects media itself: the audio pipeline builds its
//! own SRTP contexts from [`MediaSession::negotiated_srtp_keys`] with its own
//! SSRC (one SRTP path, no async locks on the media path).
//!
//! ## Socket ownership (RFC 5764 §5.1.2)
//!
//! The caller binds one `std::net::UdpSocket` per call and passes a
//! `try_clone` here. The session converts it to a tokio socket for ICE and
//! DTLS, and [`MediaSession::release_socket`] drops that clone before the
//! audio pipeline takes over the original, so the port is never rebound.

use crate::dtls_handler::{DtlsEvent, DtlsHandler};
use crate::dtls_identity::DtlsIdentity;
use crate::ice_handler::{IceEvent, IceHandler, is_ice_mismatch};
use crate::sdp_dtls::DtlsSdpParams;
use crate::{SipUaError, SipUaResult};
use proto_dtls::{DtlsRole, SrtpKeyingMaterial, SrtpProfile};
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
    /// DTLS handler for security.
    dtls_handler: DtlsHandler,
    /// SRTP keying material exported by a completed DTLS handshake.
    keying_material: Option<SrtpKeyingMaterial>,
    /// Per-call media socket (std clone) not yet converted to tokio.
    std_socket: Option<std::net::UdpSocket>,
    /// Tokio view of the media socket used for ICE and DTLS.
    socket: Option<Arc<UdpSocket>>,
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
    /// DTLS event receiver.
    #[allow(dead_code)]
    dtls_rx: mpsc::Receiver<DtlsEvent>,
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
    ///   [`Self::set_dtls_role`] before [`Self::establish`].
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
        let dtls_cert_chain = identity.cert_chain_der().to_vec();
        let dtls_private_key = identity.key_der().to_vec();
        // Create channels for ICE and DTLS events
        let (ice_tx, ice_rx) = mpsc::channel(32);
        let (dtls_tx, dtls_rx) = mpsc::channel(32);

        // Create handlers based on call direction
        let ice_handler = if is_outbound {
            IceHandler::for_outbound(local_addr, ice_config, ice_tx)
        } else {
            IceHandler::for_inbound(local_addr, ice_config, ice_tx)
        };

        let dtls_handler = if is_outbound {
            DtlsHandler::for_outbound(dtls_cert_chain, dtls_private_key, local_addr, dtls_tx)
        } else {
            DtlsHandler::for_inbound(dtls_cert_chain, dtls_private_key, local_addr, dtls_tx)
        };

        // Generate random SSRC
        let local_ssrc = rand_ssrc();

        Self {
            state: MediaSessionState::New,
            ice_handler,
            dtls_handler,
            keying_material: None,
            std_socket: Some(socket),
            socket: None,
            local_ssrc,
            remote_ssrc: None,
            local_addr,
            remote_addr: None,
            event_tx,
            ice_rx,
            dtls_rx,
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
    /// Returns an error once the handshake has started.
    pub fn set_dtls_role(&mut self, role: DtlsRole) -> SipUaResult<()> {
        self.dtls_handler.set_role(role)
    }

    /// Returns the current DTLS role.
    pub const fn dtls_role(&self) -> DtlsRole {
        self.dtls_handler.role()
    }

    /// Gets local DTLS fingerprint for SDP.
    pub fn local_dtls_fingerprint(&self) -> String {
        self.dtls_handler.local_fingerprint()
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
        let fp = self.dtls_handler.local_fingerprint();
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
    /// and DTLS (RFC 8445 §2.2, RFC 5764 §5.1.2). Never binds a new socket.
    fn ensure_socket(&mut self) -> SipUaResult<Arc<UdpSocket>> {
        if let Some(sock) = &self.socket {
            return Ok(Arc::clone(sock));
        }
        let std_sock = self
            .std_socket
            .take()
            .ok_or_else(|| SipUaError::InvalidState("media socket released".to_string()))?;
        // Sets O_NONBLOCK on the shared file description; the audio
        // pipeline clears it again at handoff (see `release_socket`).
        std_sock
            .set_nonblocking(true)
            .map_err(|e| SipUaError::TransportError(e.to_string()))?;
        let socket = Arc::new(
            UdpSocket::from_std(std_sock).map_err(|e| SipUaError::TransportError(e.to_string()))?,
        );
        self.socket = Some(Arc::clone(&socket));
        self.ice_handler.set_socket(Arc::clone(&socket));
        self.dtls_handler.set_socket(Arc::clone(&socket));
        Ok(socket)
    }

    /// Drops every reference this session holds to the media socket so the
    /// audio pipeline becomes its sole owner. Call after [`Self::establish`]
    /// and before starting audio.
    ///
    /// POAM: POA&M-325 post-handshake DTLS (retransmit, alerts, `close_notify`)
    /// needs a sans-I/O DTLS fed from the audio I/O thread.
    pub fn release_socket(&mut self) {
        self.socket = None;
        self.std_socket = None;
        self.ice_handler.clear_socket();
        self.dtls_handler.clear_socket();
    }

    /// Establishes connectivity and runs the DTLS handshake after the remote
    /// SDP is received.
    ///
    /// `remote` carries the peer fingerprints the DTLS peer certificate must
    /// match (RFC 8122 §5 / RFC 5763 §6.7.1). Set the DTLS role first.
    ///
    /// # Errors
    /// Any ICE or DTLS failure. Until POA&M-324 lands the DTLS step always
    /// fails (no network handshake), so callers fail the call closed.
    pub async fn establish(&mut self, remote: &DtlsSdpParams) -> SipUaResult<()> {
        info!("Establishing media session connectivity");

        if remote.fingerprints.is_empty() {
            self.set_state(MediaSessionState::Failed).await;
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
            match self.ice_handler.start_checks().await {
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
        info!(
            local = %local_addr,
            remote = %remote_addr,
            "Media path selected"
        );

        // Start DTLS handshake
        self.set_state(MediaSessionState::Securing).await;

        let keying_material = match self
            .dtls_handler
            .handshake(remote_addr, &remote.fingerprints)
            .await
        {
            Ok(km) => km,
            Err(e) => {
                self.set_state(MediaSessionState::Failed).await;
                return Err(e);
            }
        };
        if keying_material.profile != SrtpProfile::AeadAes256Gcm {
            self.set_state(MediaSessionState::Failed).await;
            return Err(SipUaError::DtlsError(
                "negotiated SRTP profile is not AEAD_AES_256_GCM (CNSA 2.0)".to_string(),
            ));
        }
        self.keying_material = Some(keying_material);

        // Session is now active
        self.set_state(MediaSessionState::Active).await;

        let _ = self
            .event_tx
            .send(MediaSessionEvent::Ready {
                local_addr,
                remote_addr,
            })
            .await;

        info!("Media session established and ready");

        Ok(())
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
            .map(|km| NegotiatedSrtpKeys::from_keying_material(km, self.dtls_handler.role()))
    }

    /// Closes the media session.
    pub async fn close(&mut self) -> SipUaResult<()> {
        info!("Closing media session");

        self.set_state(MediaSessionState::Closing).await;

        // Close DTLS
        self.dtls_handler.close().await?;

        // Drop keying material (zeroized on drop) and socket references
        self.keying_material = None;
        self.release_socket();

        self.set_state(MediaSessionState::Closed).await;

        Ok(())
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

    #[tokio::test]
    async fn establish_fails_closed_and_never_rebinds() {
        let (mut session, sock) = session(true);
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        session.set_remote_addr(peer.local_addr().unwrap());
        session.set_dtls_role(DtlsRole::Server).unwrap();

        let empty = DtlsSdpParams {
            fingerprints: Vec::new(),
            setup: Setup::Active,
        };
        assert!(session.establish(&empty).await.is_err());

        let params = DtlsSdpParams {
            fingerprints: vec![CertificateFingerprint::from_certificate_sha384(b"peer")],
            setup: Setup::Active,
        };
        // No DTLS handshake implementation yet (POA&M-324): must fail, and
        // must not have bound a second socket on the media port.
        let err = session.establish(&params).await.unwrap_err();
        assert!(!err.to_string().contains("in use"), "{err}");
        assert_eq!(session.state(), MediaSessionState::Failed);
        assert!(!session.is_ready());
        assert!(session.negotiated_srtp_keys().is_none());

        session.release_socket();
        // The caller's original socket is still usable after release.
        sock.send_to(b"x", peer.local_addr().unwrap()).unwrap();
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
