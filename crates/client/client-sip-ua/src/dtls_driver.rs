//! Driver task for one call's DTLS-SRTP association (RFC 5763, RFC 5764).
//!
//! [`proto_dtls::DtlsAssociation`] is a sans-I/O state machine. This module
//! gives it a socket, a clock and a lifetime: one tokio task per call owns
//! the association from the moment the media path and the peer's SDP
//! fingerprint are known until the call ends. Nothing else touches the
//! association, so no lock guards protocol state.
//!
//! ## Two phases
//!
//! - **Handshake**: the driver is the only reader of the media socket
//!   (tokio view). It demultiplexes by first byte and source address
//!   (RFC 7983 §7), feeds the association, sends its flights and drives its
//!   timers.
//! - **Servicing**: when the association reports `Connected` the driver
//!   sends the last flight, drops its tokio view of the socket and only
//!   then reports the keys. From here on the audio I/O thread is the only
//!   reader; DTLS records it sees arrive through a bounded byte ring
//!   ([`crate::dtls_forward`]) and answers go out through a std clone of
//!   the socket. This keeps answering a retransmitted final flight
//!   (RFC 6347 §4.2.4), notices the peer's `close_notify` or fatal alert,
//!   and sends our own `close_notify` when the call ends.
//!
//! ## Fail closed
//!
//! The driver never retries with other parameters and has no fallback.
//! Every outcome other than `Connected` is reported as a
//! [`SecurityCause`]; the call manager ends the call on each of them. No
//! media is sent or accepted by this module at all: datagrams of the RTP
//! class that arrive during the handshake are counted and dropped.
//!
//! ## NIST 800-53 Rev5
//!
//! - **SC-8 / SC-8(1), SC-12**: SRTP keys exist only after the association
//!   verified the peer; they move association -> [`DriverEvent`] -> media
//!   session and are wiped on drop at each step.
//! - **SC-23 / IA-3**: only datagrams from the one remote address chosen
//!   when the driver was started reach the association (exact IP and port,
//!   no latching), in both phases; the cookie covers that address.
//! - **SC-5**: bounded channels (commands 2, events 2, ring 8 KiB, one
//!   slot for the newest forward ring), at most
//!   [`MAX_DATAGRAMS_PER_WAKEUP`] datagrams handled before yielding, a
//!   watchdog above the association's own handshake budget, one
//!   association per driver. A due association timer (retransmission,
//!   handshake budget, RFC 6347 §4.2.4) is handled at the top of every
//!   pass of the driver's loop, before the socket is looked at, so a
//!   datagram flood delays it by at most one batch of
//!   [`MAX_DATAGRAMS_PER_WAKEUP`] datagrams and cannot stop it. What a
//!   flood can still do is fill the socket's receive queue and so crowd
//!   out the peer's datagrams; the handshake then ends at its budget
//!   (fail closed).
//! - **AU-2 / AU-3**: one structured record per outcome (see "Records").
//!   The soft client has no audit sink: records are `tracing` events
//!   (AU-9 is not claimed).
//!
//! ## Records
//!
//! Target `client_sip_ua::dtls_driver`, field `event`:
//!
//! - `dtls.handshake.connected` (info): role, remote, duration, profile,
//!   the verified peer fingerprint, `peer_authenticated=true` and
//!   `mutual_authentication`.
//! - `dtls.handshake.failed` (warn): fixed `cause` token, `failure` (the
//!   name of the association's `FailureCause` variant, which `cause`
//!   groups) and `cause_basis`. Records before the peer's
//!   `ChangeCipherSpec` are plaintext and can be forged by anyone able to
//!   send from the peer's address, so every cause except a timeout, a
//!   local error and a `Finished` mismatch is labelled
//!   `unauthenticated-input`: it is the reason the handshake failed, not
//!   proof of what the peer sent. The same holds for the certificate
//!   fingerprint, logged as `presented_fingerprint_unauthenticated`. An
//!   alert during the handshake is always labelled unauthenticated: the
//!   association does not say which epoch it came from.
//! - `dtls.handshake.cancelled` (info): closed locally before completion
//!   for a reason that is not a security failure (the call was hung up).
//!   Carries `role` and `remote`.
//! - `dtls.association.closed` (info for a local close, warn otherwise):
//!   after `connected`, at most once. `reason` is `local-close`,
//!   `peer-close-notify`, `peer-alert` (only when the association reported
//!   a fatal alert from the peer; `alert` is its description) or
//!   `local-error` (anything else, with `cause` and `failure`).
//!
//! Exactly one of the first three is written per driver, whoever ends the
//! handshake. The driver writes it in every case but two, in which the
//! driver's owner writes a `dtls.handshake.failed` (or, after `connected`,
//! a `dtls.association.closed`) record with `cause_basis="local"` and an
//! `origin` field instead:
//!
//! - `origin="call-manager-deadline"`: the owner's own deadline passed
//!   with the driver still silent ([`DriverHandle::abandon`]). The driver
//!   is then closed and writes no `cancelled` record. If the driver wrote
//!   `connected` just before, the owner's record is a
//!   `dtls.association.closed` with `reason="local-error"` and the
//!   driver writes no `local-close` record.
//! - `origin="driver-gone"`: the driver task ended without reporting
//!   ([`DriverHandle::record_gone`]).
//!
//! Never logged: keys, salts, randoms, cookies, raw peer bytes or
//! peer-supplied text.
//!
//! How to read some fields:
//!
//! - `call_id` is the soft client's internal call identifier. It is not
//!   the SIP `Call-ID` and means nothing to the peer or the SBC.
//! - `cause_basis="peer-authenticated"` is used for one handshake failure,
//!   a `Finished` mismatch (`failure="FinishedMismatch"`): the record that
//!   carried the `Finished` passed the record layer's AEAD check under the
//!   keys both sides derived, but its content does not match our
//!   transcript of the handshake. It does not mean that the peer was
//!   authenticated, nor that the peer misbehaved: the usual reason is that
//!   a handshake message was changed in transit, so the two transcripts
//!   differ.
//! - `peer_authenticated=true` means the peer proved possession of the
//!   key of a certificate whose fingerprint is in this dialog's SDP
//!   (RFC 5763 §5, RFC 8122 §5). It says nothing beyond what the SDP
//!   path vouches for (POA&M-333).
//! - `mutual_authentication` says whether a `CertificateRequest` was part
//!   of the handshake. In the server role we always request and require
//!   the client's certificate, so it is true. In the client role it is
//!   true only when the peer asked for
//!   our certificate; `true` then means we sent our certificate and
//!   proved possession of its key, and that the handshake completed. It
//!   does not show that the peer compared our certificate with the
//!   fingerprint in our SDP: that check is the peer's and is not visible
//!   to us.
//!
//! ## Residual risk
//!
//! - POAM: POA&M-333 (SC-23) -- RFC 8844 is not implemented; trust is
//!   hop-by-hop to whoever wrote the SDP carrying the fingerprint.
//! - POAM: POA&M-334 (SC-5) -- a party able to send from the peer's address
//!   can end a handshake with forged epoch-0 input. The call then ends
//!   (fail closed).
//! - POAM: POA&M-334 (SC-5) -- after the handshake the audio I/O thread
//!   forwards DTLS-class datagrams from the peer's address through a
//!   token bucket (burst 8, 4 per second), charged before the record is
//!   authenticated. A party able to send from the peer's address (a
//!   spoofed source is enough) can keep that bucket empty, so that the
//!   peer's genuine `close_notify`, fatal alert or retransmitted final
//!   flight is dropped. Media keys are not affected; what is lost is the
//!   mid-call close detection (the SIP BYE still ends the call) and, for
//!   a peer that lost our final flight, its recovery.
//! - The DTLS source address does not latch: a peer behind a symmetric NAT
//!   whose DTLS source differs from its negotiated address cannot complete
//!   the handshake.
//! - The remote address is compared as it is, with no normalisation of
//!   IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`): on a dual-stack socket
//!   a peer negotiated as IPv4 whose datagrams the stack reports in the
//!   mapped form (or the reverse) is treated as a wrong source and its
//!   datagrams are dropped, so the handshake ends at its budget (fail
//!   closed). This matters only when the media socket is bound to a
//!   dual-stack IPv6 address.
//! - POAM: POA&M-325 (SC-5 / SC-10) -- STUN on the media socket is not
//!   answered while the handshake runs: the driver classifies it (RFC 7983)
//!   and drops and counts it, as the audio thread does after the handshake
//!   (`non_media_dropped`). There is no handoff to ICE and no consent
//!   freshness (RFC 7675); a peer that requires a STUN answer on this
//!   5-tuple before or during DTLS gets none.
//! - POAM: POA&M-327 -- a re-INVITE that changes the fingerprint, setup or
//!   transport address keeps the existing association.
//! - POAM: POA&M-325 (SC-10 / AC-12) -- a call with no audio thread (no
//!   audio device, or the audio start failed) has no reader on the socket
//!   after the handshake, so post-handshake DTLS is not serviced and a
//!   peer's `close_notify` or fatal alert is not seen on such a call. The
//!   call manager logs a warning when that happens.

use crate::dtls_forward::{DtlsForwardRx, MAX_FORWARD_DATAGRAM};
use crate::{SipUaError, SipUaResult};
use proto_dtls::association::{DEFAULT_HANDSHAKE_BUDGET, DEFAULT_INITIAL_RTO};
use proto_dtls::{
    AssociationConfig, AssociationEvent, AssociationStats, CertificateFingerprint, DtlsAssociation,
    DtlsRole, FailureCause, SrtpKeyingMaterial,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Datagrams handled per wake-up of the driver before it yields to the
/// runtime and looks at its timers again (NIST 800-53 Rev5: SC-5: a flood
/// can starve neither the worker nor the association's timers).
pub const MAX_DATAGRAMS_PER_WAKEUP: usize = 32;
/// How long after the association's own handshake budget the driver's
/// watchdog ends a handshake that the association failed to end.
pub const WATCHDOG_MARGIN: Duration = Duration::from_secs(1);
/// Consecutive socket read errors after which the handshake is abandoned.
const MAX_CONSECUTIVE_READ_ERRORS: u32 = 16;
/// Pause after a socket read error, so a persistent error cannot spin.
const READ_ERROR_PAUSE: Duration = Duration::from_millis(10);
/// Capacity of the command channel (handle -> driver). The one command is
/// `Close`; a full or closed channel ends the driver just the same.
const COMMAND_QUEUE: usize = 2;
/// Capacity of the event channel (driver -> handle): at most one
/// `Connected` or `Failed`, then at most one `Terminated`.
const EVENT_QUEUE: usize = 2;
/// Receive buffer: one byte more than the largest datagram the association
/// can be given, so an oversized datagram is recognised rather than cut.
const RECV_BUFFER: usize = MAX_FORWARD_DATAGRAM + 1;
/// The SRTP protection profile of the CNSA 2.0 DTLS profile (RFC 7714).
const SRTP_PROFILE_NAME: &str = "AEAD_AES_256_GCM";

/// Transport parameters of the handshake.
///
/// Checked by `DtlsAssociation::new`: MTU 576..=1500, first retransmission
/// interval 50 ms..=8 s, budget up to 60 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverTimings {
    /// Largest DTLS datagram to send, in bytes.
    pub mtu: u16,
    /// First retransmission interval; doubles on each expiry
    /// (RFC 6347 §4.2.4.1).
    pub initial_rto: Duration,
    /// Total time allowed for the handshake, counted from the moment the
    /// driver is started.
    pub handshake_budget: Duration,
}

impl Default for DriverTimings {
    /// 1200 bytes, 1 s, 10 s.
    fn default() -> Self {
        Self {
            mtu: 1200,
            initial_rto: DEFAULT_INITIAL_RTO,
            handshake_budget: DEFAULT_HANDSHAKE_BUDGET,
        }
    }
}

/// Why a call's media security failed or ended. Fixed values; the one
/// peer-supplied datum is the alert number, which goes into log records
/// only (see [`SecurityCause::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityCause {
    /// The handshake did not finish within its budget.
    Timeout,
    /// The peer's certificate matches none of the SDP fingerprints.
    FingerprintMismatch,
    /// The peer's certificate, proof of possession or `Finished` is bad.
    PeerAuthentication,
    /// The peer requires parameters outside the CNSA 2.0 profile.
    UnsupportedParameters,
    /// `SRTP_AEAD_AES_256_GCM` was not negotiated.
    NoSrtpProfile,
    /// A fatal alert was received; the value is its description.
    Alert(u8),
    /// The peer broke the protocol or a resource limit.
    ProtocolViolation,
    /// The peer closed the association (`close_notify`) during the call.
    ClosedByPeer,
    /// A local operation failed, or the driver task ended unexpectedly.
    Internal,
}

impl SecurityCause {
    /// The fixed token for events and logs. The alert number is not part
    /// of it, so no peer-chosen value reaches the application event.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "dtls-timeout",
            Self::FingerprintMismatch => "dtls-fingerprint-mismatch",
            Self::PeerAuthentication => "dtls-peer-authentication",
            Self::UnsupportedParameters => "dtls-unsupported-parameters",
            Self::NoSrtpProfile => "dtls-no-srtp-profile",
            Self::Alert(_) => "dtls-alert",
            Self::ProtocolViolation => "dtls-protocol-violation",
            Self::ClosedByPeer => "dtls-closed-by-peer",
            Self::Internal => "dtls-internal",
        }
    }

    /// The alert description, for [`SecurityCause::Alert`].
    #[must_use]
    pub const fn alert(self) -> Option<u8> {
        match self {
            Self::Alert(description) => Some(description),
            _ => None,
        }
    }

    /// Maps the association's cause. Variants added to the library later
    /// are reported as [`SecurityCause::Internal`] until mapped here.
    const fn from_failure(cause: FailureCause) -> Self {
        match cause {
            FailureCause::Timeout => Self::Timeout,
            FailureCause::FingerprintMismatch => Self::FingerprintMismatch,
            FailureCause::BadCertificate
            | FailureCause::BadSignature
            | FailureCause::FinishedMismatch => Self::PeerAuthentication,
            FailureCause::UnsupportedParameters | FailureCause::NoExtendedMasterSecret => {
                Self::UnsupportedParameters
            }
            FailureCause::NoSrtpProfile => Self::NoSrtpProfile,
            FailureCause::PeerAlert(description) => Self::Alert(description),
            FailureCause::ProtocolViolation => Self::ProtocolViolation,
            _ => Self::Internal,
        }
    }
}

impl std::fmt::Display for SecurityCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a [`SecurityCause`] rests on: the `cause_basis` field of the log
/// records, carried with the cause so that the call-level log line can
/// state it too.
///
/// NIST 800-53 Rev5: AU-3 -- until the peer's `ChangeCipherSpec` the
/// handshake is plaintext: a cause derived from it is the reason the
/// handshake failed, not evidence of what the peer sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseBasis {
    /// A local condition: a timer, a local error, the owner's deadline.
    Local,
    /// A record that passed the record layer's AEAD check (see the module
    /// documentation, "Records", for what that does and does not show).
    PeerAuthenticated,
    /// Input that anyone able to send from the peer's address could have
    /// forged.
    UnauthenticatedInput,
}

impl CauseBasis {
    /// The fixed token for log records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::PeerAuthenticated => "peer-authenticated",
            Self::UnauthenticatedInput => "unauthenticated-input",
        }
    }

    /// The basis of a handshake failure. Only a `Finished` mismatch is
    /// known to rest on authenticated input; an alert during the handshake
    /// is labelled unauthenticated because the association does not report
    /// its epoch. Unknown future causes get the conservative label.
    const fn of_handshake_failure(cause: FailureCause) -> Self {
        match cause {
            FailureCause::Timeout | FailureCause::Internal => Self::Local,
            FailureCause::FinishedMismatch => Self::PeerAuthenticated,
            _ => Self::UnauthenticatedInput,
        }
    }

    /// The basis of the end of a connected association. The peer's
    /// `close_notify` and fatal alert are epoch-1 records, authenticated
    /// and replay-checked by the association; every other end is ours.
    #[must_use]
    pub const fn of_termination(cause: SecurityCause) -> Self {
        match cause {
            SecurityCause::Alert(_) | SecurityCause::ClosedByPeer => Self::PeerAuthenticated,
            _ => Self::Local,
        }
    }
}

impl std::fmt::Display for CauseBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The name of the association's failure variant, for the `failure` record
/// field. `cause` groups several of these (three are
/// `dtls-peer-authentication`); this keeps them apart. Fixed text; the
/// alert description is not part of it.
const fn failure_name(cause: FailureCause) -> &'static str {
    match cause {
        FailureCause::Timeout => "Timeout",
        FailureCause::FingerprintMismatch => "FingerprintMismatch",
        FailureCause::BadCertificate => "BadCertificate",
        FailureCause::BadSignature => "BadSignature",
        FailureCause::FinishedMismatch => "FinishedMismatch",
        FailureCause::UnsupportedParameters => "UnsupportedParameters",
        FailureCause::NoSrtpProfile => "NoSrtpProfile",
        FailureCause::NoExtendedMasterSecret => "NoExtendedMasterSecret",
        FailureCause::PeerAlert(_) => "PeerAlert",
        FailureCause::ProtocolViolation => "ProtocolViolation",
        FailureCause::Internal => "Internal",
        // Variants added to the library later, until named here.
        _ => "Unknown",
    }
}

/// Where the media session stands with its DTLS-SRTP handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureProgress {
    /// The handshake is running (or was never started).
    Pending,
    /// The handshake completed; SRTP keys are available.
    Ready,
    /// The handshake failed, or the association ended later. Terminal.
    /// With what the cause rests on.
    Failed(SecurityCause, CauseBasis),
}

/// What the driver reports to its handle.
#[derive(Debug)]
pub enum DriverEvent {
    /// The handshake completed and the peer is authenticated. The driver
    /// no longer reads the media socket.
    Connected {
        /// SRTP master keys and salts (RFC 5764 §4.2); wiped on drop.
        keys: SrtpKeyingMaterial,
    },
    /// The handshake failed, with what the cause rests on. The driver has
    /// exited.
    Failed(SecurityCause, CauseBasis),
    /// After `Connected`: the peer closed the association or sent a fatal
    /// alert. The driver has exited.
    Terminated(SecurityCause),
}

/// Result of [`DriverHandle::poll`].
#[derive(Debug)]
pub enum DriverPoll {
    /// Nothing new.
    Pending,
    /// The next event.
    Event(DriverEvent),
    /// The driver task has ended and every event was taken.
    Gone,
}

/// Commands from the handle to the driver.
enum Command {
    /// Close the association (one `close_notify`) and exit.
    Close,
}

/// Who ended a handshake when it was not the driver: the `origin` field of
/// the record the owner writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerOrigin {
    /// The owner's deadline passed with the driver still silent.
    Deadline,
    /// The driver task ended without reporting.
    DriverGone,
}

impl OwnerOrigin {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "call-manager-deadline",
            Self::DriverGone => "driver-gone",
        }
    }
}

/// State the handle and the driver task share. No protocol state.
struct Shared {
    /// Set by whoever writes the handshake's outcome record
    /// (`connected`, `failed` or `cancelled`).
    ///
    /// NIST 800-53 Rev5: AU-3 / AU-12 -- exactly one outcome record per
    /// handshake, also when the driver's owner ends it. One of the
    /// `OUTCOME_*` values: it also says whether the record written was
    /// `connected`.
    outcome: AtomicU8,
    /// At most one `dtls.association.closed` record, whoever writes it.
    closed_recorded: AtomicBool,
    /// The newest forward ring the driver has not taken yet. One slot: a
    /// newer ring replaces an older one that was never taken, so attaching
    /// cannot fail for want of room (the audio pipeline that owned the
    /// older ring's producer is gone by then).
    forward_slot: Mutex<Option<DtlsForwardRx>>,
    /// Wakes the driver when `forward_slot` was filled.
    forward_attached: Notify,
}

/// No outcome record has been written.
const OUTCOME_NONE: u8 = 0;
/// `dtls.handshake.connected` was (or is being) written.
const OUTCOME_CONNECTED: u8 = 1;
/// `dtls.handshake.failed` or `.cancelled` was (or is being) written.
const OUTCOME_ENDED: u8 = 2;

impl Shared {
    /// Claims the right to write a `failed` or `cancelled` outcome record.
    /// True for the first claim of any kind only.
    fn claim_outcome(&self) -> bool {
        self.claim(OUTCOME_ENDED).is_ok()
    }

    /// Claims the right to write the `connected` outcome record. True for
    /// the first claim of any kind only.
    fn claim_connected(&self) -> bool {
        self.claim(OUTCOME_CONNECTED).is_ok()
    }

    /// `Err` carries the kind of the claim that came first.
    fn claim(&self, kind: u8) -> Result<u8, u8> {
        self.outcome
            .compare_exchange(OUTCOME_NONE, kind, Ordering::AcqRel, Ordering::Acquire)
    }

    /// Claims the right to write the `dtls.association.closed` record.
    /// True for the first caller only.
    fn claim_closed(&self) -> bool {
        !self.closed_recorded.swap(true, Ordering::AcqRel)
    }

    fn take_forward(&self) -> Option<DtlsForwardRx> {
        self.forward_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("outcome", &self.outcome)
            .field("closed_recorded", &self.closed_recorded)
            .finish_non_exhaustive()
    }
}

/// What [`spawn`] needs.
pub struct DriverParams {
    /// Call identifier, for log records only.
    pub call_id: String,
    /// The association's configuration: role, credentials, the peer
    /// fingerprints from this dialog's SDP, timers and `peer_binding`.
    pub config: AssociationConfig,
    /// The one remote transport address this association serves.
    pub remote: SocketAddr,
    /// Tokio view of the media socket. The driver must hold the only
    /// reference: it drops it before reporting `Connected`, which is what
    /// hands the read side to the audio I/O thread.
    pub socket: Arc<UdpSocket>,
    /// A std clone of the same socket for sends after the handshake.
    pub send_socket: std::net::UdpSocket,
    /// DTLS datagrams from `remote` that were read off the socket before
    /// the driver started (during ICE checks), in arrival order.
    pub early: Vec<Vec<u8>>,
}

impl std::fmt::Debug for DriverParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriverParams")
            .field("call_id", &self.call_id)
            .field("remote", &self.remote)
            .field("early", &self.early.len())
            .finish_non_exhaustive()
    }
}

/// The owner's side of a running driver.
///
/// Dropping the handle closes the command channel, on which the driver
/// closes its association and exits: no path leaks the task.
#[derive(Debug)]
pub struct DriverHandle {
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<DriverEvent>,
    task: JoinHandle<()>,
    shared: Arc<Shared>,
    /// For the records the owner writes; see [`DriverHandle::abandon`].
    call_id: String,
    role: DtlsRole,
    remote: SocketAddr,
    started: Instant,
}

impl DriverHandle {
    /// Takes the next event, if any. Never blocks.
    pub fn poll(&mut self) -> DriverPoll {
        match self.events.try_recv() {
            Ok(event) => DriverPoll::Event(event),
            Err(mpsc::error::TryRecvError::Empty) => DriverPoll::Pending,
            Err(mpsc::error::TryRecvError::Disconnected) => DriverPoll::Gone,
        }
    }

    /// Asks the driver to close the association and exit. Never blocks;
    /// if the command queue is full the driver still exits when the handle
    /// is dropped.
    pub fn close(&self) {
        let _ = self.commands.try_send(Command::Close);
    }

    /// Gives the driver the consumer half of a new forward ring; the last
    /// one given wins. Never blocks and cannot fail for want of room: the
    /// ring goes into a one-entry slot, replacing a ring the driver has
    /// not taken yet. Returns `false` only if the driver has exited.
    pub fn attach_forward(&self, ring: DtlsForwardRx) -> bool {
        if self.task.is_finished() {
            return false;
        }
        *self
            .shared
            .forward_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(ring);
        self.shared.forward_attached.notify_one();
        true
    }

    /// The owner gives up on a handshake the driver has not ended (the
    /// owner's own deadline passed). Writes the `dtls.handshake.failed`
    /// record with `origin="call-manager-deadline"`, unless the driver
    /// wrote the outcome record in the meantime, and closes the driver,
    /// which then writes no `cancelled` record.
    ///
    /// If the outcome the driver wrote in the meantime is `connected` (the
    /// handshake completed between the owner's last poll and this call),
    /// the owner still ends the call as a timeout and drops the keys. The
    /// trail then is `connected` followed by one `dtls.association.closed`
    /// with `reason="local-error"` and `origin="call-manager-deadline"`,
    /// written here; the driver's own `local-close` record is not written.
    ///
    /// NIST 800-53 Rev5: AU-2 / AU-3 / AU-12 -- a security failure decided
    /// outside the driver leaves the same structured record as one
    /// decided inside it.
    pub fn abandon(&self) {
        if !self.record_owner_failure(OwnerOrigin::Deadline, SecurityCause::Timeout)
            && self.shared.outcome.load(Ordering::Acquire) == OUTCOME_CONNECTED
            && self.shared.claim_closed()
        {
            warn!(
                event = "dtls.association.closed",
                call_id = %self.call_id,
                role = role_name(self.role),
                remote = %self.remote,
                reason = "local-error",
                cause = SecurityCause::Timeout.as_str(),
                cause_basis = CauseBasis::Local.as_str(),
                origin = OwnerOrigin::Deadline.as_str(),
                "DTLS association given up by its owner: the handshake completed after the owner's deadline"
            );
        }
        self.close();
    }

    /// The driver task ended without reporting an outcome (it panicked or
    /// was aborted). Writes the record for that with
    /// `origin="driver-gone"`: `dtls.handshake.failed` if no outcome
    /// record exists yet, `dtls.association.closed` otherwise (the
    /// handshake had completed).
    pub fn record_gone(&self) {
        if !self.record_owner_failure(OwnerOrigin::DriverGone, SecurityCause::Internal) {
            warn!(
                event = "dtls.association.closed",
                call_id = %self.call_id,
                role = role_name(self.role),
                remote = %self.remote,
                reason = "local-error",
                cause = SecurityCause::Internal.as_str(),
                cause_basis = CauseBasis::Local.as_str(),
                origin = OwnerOrigin::DriverGone.as_str(),
                "DTLS association is no longer serviced"
            );
        }
    }

    /// Writes `dtls.handshake.failed` on the owner's behalf if no outcome
    /// record was written yet. Returns whether it was written.
    fn record_owner_failure(&self, origin: OwnerOrigin, cause: SecurityCause) -> bool {
        if !self.shared.claim_outcome() {
            return false;
        }
        warn!(
            event = "dtls.handshake.failed",
            call_id = %self.call_id,
            role = role_name(self.role),
            remote = %self.remote,
            duration_ms = milliseconds(now().saturating_duration_since(self.started)),
            cause = cause.as_str(),
            cause_basis = CauseBasis::Local.as_str(),
            origin = origin.as_str(),
            "DTLS-SRTP handshake failed"
        );
        true
    }

    /// True once the driver task has ended.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Bytes identifying `remote` for the association's stateless cookie
/// (RFC 6347 §4.2.1): the IP address octets followed by the port, 6 or 18
/// bytes.
#[must_use]
pub fn peer_binding(remote: SocketAddr) -> Vec<u8> {
    let mut binding = Vec::with_capacity(18);
    match remote.ip() {
        std::net::IpAddr::V4(ip) => binding.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => binding.extend_from_slice(&ip.octets()),
    }
    binding.extend_from_slice(&remote.port().to_be_bytes());
    binding
}

/// Where a datagram read during the handshake goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Demux {
    /// DTLS class from the association's remote.
    Association,
    /// DTLS class from any other address.
    WrongSource,
    /// STUN class.
    Stun,
    /// RTP/RTCP class: media before the handshake completed.
    MediaEarly,
    /// Anything else, including empty and oversized datagrams.
    Other,
}

/// RFC 7983 §7 demultiplexing by first byte, plus the source check.
///
/// NIST 800-53 Rev5: SI-10 / SC-23 -- decided before any parsing; only
/// DTLS-class datagrams from exactly `remote` reach the association.
fn demux(datagram: &[u8], from: SocketAddr, remote: SocketAddr) -> Demux {
    if datagram.len() > MAX_FORWARD_DATAGRAM {
        return Demux::Other;
    }
    match datagram.first() {
        Some(20..=63) if from == remote => Demux::Association,
        Some(20..=63) => Demux::WrongSource,
        Some(0..=3) => Demux::Stun,
        Some(128..=191) => Demux::MediaEarly,
        _ => Demux::Other,
    }
}

/// Datagrams the driver read during the handshake and did not pass on.
/// All saturate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DemuxCounters {
    stun: u32,
    media_early: u32,
    wrong_source: u32,
    other: u32,
}

impl DemuxCounters {
    const fn count(&mut self, class: Demux) {
        let counter = match class {
            Demux::Association => return,
            Demux::WrongSource => &mut self.wrong_source,
            Demux::Stun => &mut self.stun,
            Demux::MediaEarly => &mut self.media_early,
            Demux::Other => &mut self.other,
        };
        *counter = counter.saturating_add(1);
    }
}

/// DTLS datagrams read off the media socket before the driver existed.
///
/// While the ICE check loop is the reader of the socket, DTLS-class
/// datagrams are kept here so that an early `ClientHello` is not lost
/// (RFC 5763 §5: the offerer must be ready for one before it has the
/// answer).
///
/// NIST 800-53 Rev5: SC-5 -- at most [`EarlyDtls::MAX_DATAGRAMS`] datagrams
/// of at most 1,500 bytes, oldest dropped first.
#[derive(Debug, Default)]
pub struct EarlyDtls {
    entries: VecDeque<(SocketAddr, Vec<u8>)>,
    evicted: u32,
}

impl EarlyDtls {
    /// Datagrams kept.
    pub const MAX_DATAGRAMS: usize = 4;

    /// An empty stash.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps `datagram` if it is of the DTLS class (first byte 20..=63)
    /// and not oversized. Returns whether it was kept.
    pub fn offer(&mut self, datagram: &[u8], from: SocketAddr) -> bool {
        if !matches!(datagram.first(), Some(20..=63)) || datagram.len() > MAX_FORWARD_DATAGRAM {
            return false;
        }
        if self.entries.len() >= Self::MAX_DATAGRAMS {
            self.entries.pop_front();
            self.evicted = self.evicted.saturating_add(1);
        }
        self.entries.push_back((from, datagram.to_vec()));
        true
    }

    /// Datagrams currently kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Datagrams dropped to make room.
    #[must_use]
    pub const fn evicted(&self) -> u32 {
        self.evicted
    }

    /// Empties the stash and returns the datagrams that came from
    /// `remote`, in arrival order. The others are dropped.
    pub fn take_from(&mut self, remote: SocketAddr) -> Vec<Vec<u8>> {
        self.entries
            .drain(..)
            .filter(|(from, _)| *from == remote)
            .map(|(_, datagram)| datagram)
            .collect()
    }
}

/// The driver's clock. tokio's, so tests can pause time; the association
/// takes `std::time::Instant`.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Lower-case hex of a fingerprint. Computed locally from the certificate
/// bytes, so it is safe to log.
fn fingerprint_hex(fingerprint: &CertificateFingerprint) -> String {
    use std::fmt::Write;
    let bytes = fingerprint.bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

const fn role_name(role: DtlsRole) -> &'static str {
    match role {
        DtlsRole::Client => "client",
        DtlsRole::Server => "server",
    }
}

/// Starts the driver task for one call.
///
/// The association is created here, so its handshake budget starts now:
/// call this when the path to `params.remote` is ready (after ICE, with
/// the peer's fingerprint known).
///
/// Must be called from within a tokio runtime.
///
/// # Errors
/// Returns [`SipUaError::DtlsError`] if the association refuses its
/// configuration (no fingerprint, timers or MTU out of range) or random
/// generation fails.
pub fn spawn(params: DriverParams) -> SipUaResult<DriverHandle> {
    let started = now();
    let role = params.config.role;
    let budget = params.config.handshake_budget;
    // Fixed text: the library's message is not reflected.
    let association = DtlsAssociation::new(params.config, started)
        .map_err(|_| SipUaError::DtlsError("DTLS association could not be created".to_string()))?;
    let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE);
    let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE);
    let shared = Arc::new(Shared {
        outcome: AtomicU8::new(OUTCOME_NONE),
        closed_recorded: AtomicBool::new(false),
        forward_slot: Mutex::new(None),
        forward_attached: Notify::new(),
    });
    let driver = Driver {
        call_id: params.call_id.clone(),
        role,
        remote: params.remote,
        association,
        send_socket: params.send_socket,
        commands: command_rx,
        events: event_tx,
        shared: Arc::clone(&shared),
        forward: None,
        forward_wakeup: None,
        started,
        // NIST 800-53 Rev5: SC-5 -- bound that does not depend on the
        // association ending itself.
        watchdog: started + budget + WATCHDOG_MARGIN,
        connected_at: None,
        demux: DemuxCounters::default(),
        early_datagrams: 0,
        send_failures: 0,
        send_would_block: 0,
        buffer: vec![0u8; RECV_BUFFER],
    };
    let task = tokio::spawn(driver.run(params.socket, params.early));
    Ok(DriverHandle {
        commands: command_tx,
        events: event_rx,
        task,
        shared,
        call_id: params.call_id,
        role,
        remote: params.remote,
        started,
    })
}

/// A terminal or state-changing event of the association.
enum Outcome {
    Connected(SrtpKeyingMaterial),
    Failed(FailureCause),
    PeerClosed,
}

/// Why the handshake phase ended.
enum HandshakeEnd {
    /// Keys exported; go on to servicing.
    Connected(SrtpKeyingMaterial),
    /// Reported and done.
    Finished,
}

struct Driver {
    call_id: String,
    role: DtlsRole,
    remote: SocketAddr,
    association: DtlsAssociation,
    /// For sends after the handshake (shares the media socket).
    send_socket: std::net::UdpSocket,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<DriverEvent>,
    /// Shared with the handle: the outcome-record latch and the slot for
    /// a new forward ring.
    shared: Arc<Shared>,
    /// Post-handshake datagrams from the audio I/O thread.
    forward: Option<DtlsForwardRx>,
    /// The wake-up of `forward`.
    forward_wakeup: Option<Arc<Notify>>,
    started: Instant,
    watchdog: Instant,
    connected_at: Option<Instant>,
    demux: DemuxCounters,
    /// Datagrams fed from the early stash.
    early_datagrams: u32,
    /// Datagrams of ours the socket did not take (including the next).
    send_failures: u32,
    /// Of those, the ones refused because the send would have blocked.
    send_would_block: u32,
    /// The one receive buffer, reused for every datagram.
    buffer: Vec<u8>,
}

impl Driver {
    async fn run(mut self, socket: Arc<UdpSocket>, early: Vec<Vec<u8>>) {
        match self.handshake(socket, early).await {
            HandshakeEnd::Connected(keys) => {
                self.connected_at = Some(now());
                if !self.shared.claim_connected() {
                    // The owner gave up on this handshake and recorded
                    // that (`DriverHandle::abandon`). The keys are dropped
                    // (and wiped) here; nobody learns of them.
                    // The reverse order (this claim first, then the
                    // owner's deadline before it saw `Connected`) leaves
                    // `connected` followed by the owner's
                    // `dtls.association.closed` with
                    // `origin="call-manager-deadline"`; see `abandon`.
                    self.association.close();
                    self.send_queued_std();
                    return;
                }
                self.record_connected();
                // Bounded, never waits. If the handle is gone the keys are
                // dropped (and wiped) right here.
                if self
                    .events
                    .try_send(DriverEvent::Connected { keys })
                    .is_ok()
                {
                    self.service().await;
                } else {
                    self.close_locally();
                }
            }
            HandshakeEnd::Finished => {}
        }
    }

    /// Takes the forward ring the handle left in the slot, if any; the
    /// last one attached wins. What the ring it replaces still holds is
    /// fed to the association first, so a pipeline restart loses nothing
    /// the old audio thread had already forwarded.
    fn take_attached_forward(&mut self) {
        let Some(ring) = self.shared.take_forward() else {
            return;
        };
        self.drain_forward();
        self.forward_wakeup = Some(ring.wakeup());
        self.forward = Some(ring);
    }

    /// Takes the next terminal or state-changing event of the association.
    fn next_outcome(&mut self) -> Option<Outcome> {
        self.association.poll_event().map(|event| match event {
            AssociationEvent::Connected { keys } => Outcome::Connected(keys),
            AssociationEvent::Failed { cause } => Outcome::Failed(cause),
            AssociationEvent::PeerClosed => Outcome::PeerClosed,
        })
    }

    // ----- handshake phase ----------------------------------------------

    /// Runs the handshake as the only reader of the media socket. Takes
    /// the tokio view by value: it is dropped on every way out, and before
    /// `Connected` is reported.
    async fn handshake(&mut self, socket: Arc<UdpSocket>, early: Vec<Vec<u8>>) -> HandshakeEnd {
        // RFC 5763 §5: a ClientHello that arrived before the driver existed.
        for datagram in early {
            self.association.handle_datagram(&datagram, now());
            self.early_datagrams = self.early_datagrams.saturating_add(1);
        }
        let mut read_errors = 0u32;
        loop {
            // RFC 6347 §4.2.4 / NIST 800-53 Rev5: SC-5 -- a due timer of
            // the association (retransmission, handshake budget) is
            // handled here, on every pass, and not only in the `select!`
            // below: that one is biased towards the socket, so while
            // datagrams keep arriving its timer arm is never polled.
            let at = now();
            if self.association.poll_timeout().is_some_and(|due| due <= at) {
                self.association.handle_timeout(at);
            }
            self.send_queued(&socket).await;
            match self.next_outcome() {
                Some(Outcome::Connected(keys)) => {
                    // RFC 5764 §5.1.2: hand the read side over. The audio
                    // I/O thread must be the only reader from here on, so
                    // the tokio registration goes before anyone can learn
                    // that keys exist.
                    drop(socket);
                    return HandshakeEnd::Connected(keys);
                }
                Some(Outcome::Failed(cause)) => {
                    self.fail_handshake(cause, false);
                    return HandshakeEnd::Finished;
                }
                // Not possible before completion; fail closed if it happens.
                Some(Outcome::PeerClosed) => {
                    self.fail_handshake(FailureCause::ProtocolViolation, false);
                    return HandshakeEnd::Finished;
                }
                None => {}
            }
            // NIST 800-53 Rev5: SC-5 -- outer bound on the handshake.
            if now() >= self.watchdog {
                self.fail_handshake(FailureCause::Timeout, true);
                return HandshakeEnd::Finished;
            }
            let deadline = self
                .association
                .poll_timeout()
                .map_or(self.watchdog, |at| at.min(self.watchdog));
            tokio::select! {
                biased;
                // `Close`, or the handle was dropped.
                _ = self.commands.recv() => {
                    // RFC 5246 §7.2.1: one close_notify, best effort.
                    self.association.close();
                    self.send_queued(&socket).await;
                    self.record_cancelled();
                    return HandshakeEnd::Finished;
                }
                received = socket.recv_from(&mut self.buffer) => {
                    if let Ok((len, from)) = received {
                        read_errors = 0;
                        self.on_handshake_datagram(len, from);
                        self.read_more(&socket).await;
                    } else {
                        read_errors += 1;
                        if read_errors >= MAX_CONSECUTIVE_READ_ERRORS {
                            self.fail_handshake(FailureCause::Internal, false);
                            return HandshakeEnd::Finished;
                        }
                        tokio::time::sleep(READ_ERROR_PAUSE).await;
                    }
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    self.association.handle_timeout(now());
                }
            }
        }
    }

    /// Classifies the datagram in `buffer[..len]` and feeds the association
    /// if it is DTLS from the remote. No reply and no log line for
    /// anything else.
    fn on_handshake_datagram(&mut self, len: usize, from: SocketAddr) {
        let Some(datagram) = self.buffer.get(..len) else {
            return;
        };
        let class = demux(datagram, from, self.remote);
        if class == Demux::Association {
            self.association.handle_datagram(datagram, now());
        } else {
            self.demux.count(class);
        }
    }

    /// Reads what is already queued on the socket, up to the per-wake-up
    /// limit, then yields. Stops as soon as the association is no longer
    /// handshaking: datagrams behind that point belong to the audio thread.
    async fn read_more(&mut self, socket: &UdpSocket) {
        for _ in 1..MAX_DATAGRAMS_PER_WAKEUP {
            self.send_queued(socket).await;
            if self.association.is_connected() || self.association.is_terminated() {
                return;
            }
            let Ok((len, from)) = socket.try_recv_from(&mut self.buffer) else {
                return;
            };
            self.on_handshake_datagram(len, from);
        }
        // NIST 800-53 Rev5: SC-5 -- a flood must not starve the worker.
        tokio::task::yield_now().await;
    }

    /// Sends everything the association queued, through the tokio view.
    async fn send_queued(&mut self, socket: &UdpSocket) {
        while let Some(datagram) = self.association.poll_transmit() {
            if socket.send_to(&datagram, self.remote).await.is_err() {
                // The peer's or our own retransmission recovers.
                self.send_failures = self.send_failures.saturating_add(1);
            }
        }
    }

    /// Reports a failed handshake: one record, one event. The alert the
    /// association queued for the peer, if any, was sent by the caller's
    /// loop before the event was taken.
    fn fail_handshake(&self, cause: FailureCause, watchdog: bool) {
        self.record_failed(cause, watchdog);
        let _ = self.events.try_send(DriverEvent::Failed(
            SecurityCause::from_failure(cause),
            CauseBasis::of_handshake_failure(cause),
        ));
    }

    // ----- servicing phase ----------------------------------------------

    /// Services the association for the rest of the call. Input comes from
    /// the forward ring; output goes through the std clone of the socket.
    async fn service(&mut self) {
        loop {
            // The newest ring of the audio pipeline, if one was attached
            // since the last pass.
            self.take_attached_forward();
            // As in the handshake loop: a due timer does not wait for the
            // `select!`. (Its other arms cannot be kept busy from the
            // network: the forward ring is fed at 4 datagrams per second
            // at most.)
            let at = now();
            if self.association.poll_timeout().is_some_and(|due| due <= at) {
                self.association.handle_timeout(at);
            }
            self.send_queued_std();
            match self.next_outcome() {
                // The call ends (user decision). A fatal alert from the
                // peer is an epoch-1 record, authenticated and
                // replay-checked by the association; any other failure of
                // a connected association is a local one.
                Some(Outcome::Failed(failure)) => {
                    let cause = SecurityCause::from_failure(failure);
                    let reason = if cause.alert().is_some() {
                        "peer-alert"
                    } else {
                        "local-error"
                    };
                    self.record_closed(reason, Some((cause, failure)));
                    let _ = self.events.try_send(DriverEvent::Terminated(cause));
                    return;
                }
                Some(Outcome::PeerClosed) => {
                    self.record_closed("peer-close-notify", None);
                    let _ = self
                        .events
                        .try_send(DriverEvent::Terminated(SecurityCause::ClosedByPeer));
                    return;
                }
                // Emitted once by the association; nothing to do twice.
                Some(Outcome::Connected(_)) | None => {}
            }
            // As server: until the final flight's retention time is over
            // (RFC 6347 §4.2.4). Afterwards there is no timer.
            let linger = self.association.poll_timeout();
            tokio::select! {
                biased;
                // `Close`, or the handle was dropped.
                _ = self.commands.recv() => {
                    self.close_locally();
                    return;
                }
                // Taken at the top of the next pass.
                () = self.shared.forward_attached.notified() => {}
                () = forwarded(self.forward_wakeup.as_deref()) => self.drain_forward(),
                () = sleep_until_opt(linger) => self.association.handle_timeout(now()),
            }
        }
    }

    /// Feeds every whole frame in the forward ring to the association. The
    /// audio thread already checked the source address and the rate; the
    /// ring bounds how many there can be.
    fn drain_forward(&mut self) {
        let Some(ring) = self.forward.as_mut() else {
            return;
        };
        while let Some(len) = ring.pop(&mut self.buffer) {
            if let Some(datagram) = self.buffer.get(..len) {
                self.association.handle_datagram(datagram, now());
            }
        }
    }

    /// Sends everything the association queued, through the std clone.
    ///
    /// The driver runs on a tokio worker, and after the handoff the audio
    /// pipeline has cleared `O_NONBLOCK` on the shared socket, so each
    /// send asks for non-blocking behaviour itself ([`send_nonblocking`]).
    /// There are only a handful per call (answers to a retransmitted final
    /// flight, one alert, one `close_notify`). A datagram the socket does
    /// not take at once is counted and dropped; the peer's retransmission
    /// recovers.
    fn send_queued_std(&mut self) {
        while let Some(datagram) = self.association.poll_transmit() {
            if let Err(e) = send_nonblocking(&self.send_socket, &datagram, self.remote) {
                self.send_failures = self.send_failures.saturating_add(1);
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    self.send_would_block = self.send_would_block.saturating_add(1);
                }
            }
        }
    }

    /// Local close after the handshake: one `close_notify`
    /// (RFC 5246 §7.2.1), not waiting for the peer's.
    fn close_locally(&mut self) {
        self.association.close();
        self.send_queued_std();
        self.record_closed("local-close", None);
    }

    // ----- records (NIST 800-53 Rev5: AU-2 / AU-3) ------------------------

    const fn stats(&self) -> AssociationStats {
        self.association.stats()
    }

    fn record_connected(&self) {
        let stats = self.stats();
        // After `Connected` the presented certificate is the verified one.
        let peer_fingerprint = self
            .association
            .presented_fingerprint()
            .map(fingerprint_hex);
        info!(
            event = "dtls.handshake.connected",
            call_id = %self.call_id,
            role = role_name(self.role),
            remote = %self.remote,
            duration_ms = milliseconds(now().saturating_duration_since(self.started)),
            srtp_profile = SRTP_PROFILE_NAME,
            peer_fingerprint = peer_fingerprint.as_deref(),
            peer_authenticated = true,
            // NIST 800-53 Rev5: IA-3 -- stated only when the client was
            // asked for its certificate.
            mutual_authentication = self.association.client_certificate_requested(),
            retransmits = stats.retransmits,
            records_discarded = stats.records_discarded,
            replays = stats.replays,
            fragments_rejected = stats.fragments_rejected,
            early_datagrams = self.early_datagrams,
            "DTLS-SRTP handshake completed"
        );
    }

    fn record_failed(&self, cause: FailureCause, watchdog: bool) {
        if !self.shared.claim_outcome() {
            // The owner recorded the failure (`DriverHandle::abandon`).
            return;
        }
        let stats = self.stats();
        let security_cause = SecurityCause::from_failure(cause);
        let presented = self
            .association
            .presented_fingerprint()
            .map(fingerprint_hex);
        warn!(
            event = "dtls.handshake.failed",
            call_id = %self.call_id,
            role = role_name(self.role),
            remote = %self.remote,
            duration_ms = milliseconds(now().saturating_duration_since(self.started)),
            cause = security_cause.as_str(),
            failure = failure_name(cause),
            alert = security_cause.alert(),
            cause_basis = CauseBasis::of_handshake_failure(cause).as_str(),
            presented_fingerprint_unauthenticated = presented.as_deref(),
            watchdog,
            retransmits = stats.retransmits,
            records_discarded = stats.records_discarded,
            replays = stats.replays,
            fragments_rejected = stats.fragments_rejected,
            early_datagrams = self.early_datagrams,
            dropped_stun = self.demux.stun,
            dropped_media_early = self.demux.media_early,
            dropped_wrong_source = self.demux.wrong_source,
            dropped_other = self.demux.other,
            "DTLS-SRTP handshake failed"
        );
    }

    fn record_cancelled(&self) {
        if !self.shared.claim_outcome() {
            // The owner ended the handshake as a failure and recorded it
            // (`DriverHandle::abandon`): no second outcome record.
            return;
        }
        info!(
            event = "dtls.handshake.cancelled",
            call_id = %self.call_id,
            role = role_name(self.role),
            remote = %self.remote,
            duration_ms = milliseconds(now().saturating_duration_since(self.started)),
            "DTLS-SRTP handshake cancelled by local close"
        );
    }

    /// `failed` is the association's failure, when that is what ended it.
    fn record_closed(&self, reason: &'static str, failed: Option<(SecurityCause, FailureCause)>) {
        if !self.shared.claim_closed() {
            // The owner gave the association up and recorded that
            // (`DriverHandle::abandon`): no second `closed` record.
            return;
        }
        let since = self.connected_at.unwrap_or(self.started);
        let duration_ms = milliseconds(now().saturating_duration_since(since));
        let transmit_dropped = self
            .stats()
            .transmit_dropped
            .saturating_add(self.send_failures);
        if reason == "local-close" {
            info!(
                event = "dtls.association.closed",
                call_id = %self.call_id,
                role = role_name(self.role),
                remote = %self.remote,
                reason,
                duration_ms,
                transmit_dropped,
                transmit_would_block = self.send_would_block,
                "DTLS association closed"
            );
            return;
        }
        let cause = failed.map_or(SecurityCause::ClosedByPeer, |(cause, _)| cause);
        warn!(
            event = "dtls.association.closed",
            call_id = %self.call_id,
            role = role_name(self.role),
            remote = %self.remote,
            reason,
            cause = cause.as_str(),
            failure = failed.map(|(_, failure)| failure_name(failure)),
            alert = cause.alert(),
            cause_basis = CauseBasis::of_termination(cause).as_str(),
            duration_ms,
            transmit_dropped,
            transmit_would_block = self.send_would_block,
            "DTLS association ended"
        );
    }
}

/// Sends one datagram without ever blocking the calling thread, whatever
/// the socket's `O_NONBLOCK` state (which the audio pipeline owns after
/// the handoff: it is a property of the shared file description).
///
/// NIST 800-53 Rev5: SC-5 -- a full send buffer cannot park a runtime
/// worker.
#[cfg(unix)]
fn send_nonblocking(
    socket: &std::net::UdpSocket,
    datagram: &[u8],
    remote: SocketAddr,
) -> std::io::Result<usize> {
    use nix::sys::socket::{MsgFlags, SockaddrStorage, sendto};
    use std::os::fd::AsRawFd;
    // `MSG_DONTWAIT` applies to this one call only.
    sendto(
        socket.as_raw_fd(),
        datagram,
        &SockaddrStorage::from(remote),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(std::io::Error::from)
}

/// On targets without `MSG_DONTWAIT` the send is a plain one: a UDP send
/// there returns at once unless the send buffer is full.
#[cfg(not(unix))]
fn send_nonblocking(
    socket: &std::net::UdpSocket,
    datagram: &[u8],
    remote: SocketAddr,
) -> std::io::Result<usize> {
    socket.send_to(datagram, remote)
}

/// Waits for the forward ring's producer; forever when there is no ring.
async fn forwarded(wakeup: Option<&Notify>) {
    match wakeup {
        Some(wakeup) => wakeup.notified().await,
        None => std::future::pending().await,
    }
}

/// Sleeps until `deadline`; forever when there is none.
async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// RFC 7983 §7 first-byte ranges crossed with the source address.
    #[test]
    fn demux_table() {
        let remote = addr("192.0.2.1:4000");
        let same_ip_other_port = addr("192.0.2.1:4001");
        let stranger = addr("198.51.100.7:4000");
        for first in 0..=255u8 {
            let datagram = [first, 0xFE, 0xFD];
            let from_remote = demux(&datagram, remote, remote);
            let expected = match first {
                0..=3 => Demux::Stun,
                20..=63 => Demux::Association,
                128..=191 => Demux::MediaEarly,
                _ => Demux::Other,
            };
            assert_eq!(from_remote, expected, "first byte {first}");
            for other in [same_ip_other_port, stranger] {
                let from_other = demux(&datagram, other, remote);
                let expected = match first {
                    0..=3 => Demux::Stun,
                    20..=63 => Demux::WrongSource,
                    128..=191 => Demux::MediaEarly,
                    _ => Demux::Other,
                };
                assert_eq!(from_other, expected, "first byte {first} from {other}");
            }
        }
        assert_eq!(demux(&[], remote, remote), Demux::Other);
        assert_eq!(
            demux(&[22; MAX_FORWARD_DATAGRAM], remote, remote),
            Demux::Association
        );
        assert_eq!(
            demux(&[22; MAX_FORWARD_DATAGRAM + 1], remote, remote),
            Demux::Other
        );
    }

    #[test]
    fn demux_counters_count_by_class_and_saturate() {
        let mut counters = DemuxCounters::default();
        counters.count(Demux::Association);
        assert_eq!(counters, DemuxCounters::default());
        counters.count(Demux::Stun);
        counters.count(Demux::MediaEarly);
        counters.count(Demux::MediaEarly);
        counters.count(Demux::WrongSource);
        counters.count(Demux::Other);
        assert_eq!(
            (
                counters.stun,
                counters.media_early,
                counters.wrong_source,
                counters.other
            ),
            (1, 2, 1, 1)
        );
        counters.other = u32::MAX;
        counters.count(Demux::Other);
        assert_eq!(counters.other, u32::MAX);
    }

    #[test]
    fn early_stash_keeps_dtls_only_and_drops_oldest() {
        let remote = addr("192.0.2.1:4000");
        let stranger = addr("198.51.100.7:4000");
        let mut stash = EarlyDtls::new();
        assert!(stash.is_empty());
        // Not DTLS class, empty, oversized: not kept.
        assert!(!stash.offer(&[0x80, 0, 0], remote));
        assert!(!stash.offer(&[0, 1, 0], remote));
        assert!(!stash.offer(&[], remote));
        assert!(!stash.offer(&[22; MAX_FORWARD_DATAGRAM + 1], remote));
        assert!(stash.is_empty());

        assert!(stash.offer(&[22, 1], remote));
        assert!(stash.offer(&[22, 2], stranger));
        assert!(stash.offer(&[22, 3], remote));
        assert!(stash.offer(&[22, 4], remote));
        assert_eq!((stash.len(), stash.evicted()), (4, 0));
        // The fifth evicts the oldest.
        assert!(stash.offer(&[22, 5], remote));
        assert_eq!((stash.len(), stash.evicted()), (4, 1));

        // Only the remote's, in arrival order; the stash is emptied.
        assert_eq!(
            stash.take_from(remote),
            vec![vec![22, 3], vec![22, 4], vec![22, 5]]
        );
        assert!(stash.is_empty());
    }

    #[test]
    fn peer_binding_covers_address_and_port() {
        assert_eq!(
            peer_binding(addr("192.0.2.1:4000")),
            vec![192, 0, 2, 1, 0x0F, 0xA0]
        );
        let v6 = peer_binding(addr("[2001:db8::1]:4000"));
        assert_eq!(v6.len(), 18);
        assert_eq!(&v6[16..], &[0x0F, 0xA0]);
        assert_ne!(
            peer_binding(addr("192.0.2.1:4000")),
            peer_binding(addr("192.0.2.1:4001"))
        );
    }

    #[test]
    fn causes_map_to_fixed_tokens() {
        let table = [
            (FailureCause::Timeout, "dtls-timeout", "local"),
            (
                FailureCause::FingerprintMismatch,
                "dtls-fingerprint-mismatch",
                "unauthenticated-input",
            ),
            (
                FailureCause::BadCertificate,
                "dtls-peer-authentication",
                "unauthenticated-input",
            ),
            (
                FailureCause::BadSignature,
                "dtls-peer-authentication",
                "unauthenticated-input",
            ),
            (
                FailureCause::FinishedMismatch,
                "dtls-peer-authentication",
                "peer-authenticated",
            ),
            (
                FailureCause::UnsupportedParameters,
                "dtls-unsupported-parameters",
                "unauthenticated-input",
            ),
            (
                FailureCause::NoExtendedMasterSecret,
                "dtls-unsupported-parameters",
                "unauthenticated-input",
            ),
            (
                FailureCause::NoSrtpProfile,
                "dtls-no-srtp-profile",
                "unauthenticated-input",
            ),
            (
                FailureCause::PeerAlert(40),
                "dtls-alert",
                "unauthenticated-input",
            ),
            (
                FailureCause::ProtocolViolation,
                "dtls-protocol-violation",
                "unauthenticated-input",
            ),
            (FailureCause::Internal, "dtls-internal", "local"),
        ];
        for (failure, token, basis) in table {
            let cause = SecurityCause::from_failure(failure);
            assert_eq!(cause.as_str(), token, "{failure:?}");
            assert_eq!(cause.to_string(), token);
            assert_eq!(
                CauseBasis::of_handshake_failure(failure).as_str(),
                basis,
                "{failure:?}"
            );
            assert_ne!(failure_name(failure), "Unknown", "{failure:?}");
        }
        // The alert number is carried, but never in the token.
        assert_eq!(SecurityCause::Alert(40).alert(), Some(40));
        assert_eq!(SecurityCause::Timeout.alert(), None);
        assert_eq!(SecurityCause::ClosedByPeer.as_str(), "dtls-closed-by-peer");
    }

    #[test]
    fn default_timings_are_the_decided_ones() {
        let timings = DriverTimings::default();
        assert_eq!(timings.mtu, 1200);
        assert_eq!(timings.initial_rto, Duration::from_secs(1));
        assert_eq!(timings.handshake_budget, Duration::from_secs(10));
    }
}
