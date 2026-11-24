//! gRPC client for the sbc-announcement-server pod.
//!
//! When `SBC_ANNOUNCEMENT_URL` is set, the SIP stack delegates
//! announcement media to the external pod instead of binding an RTP
//! socket in-process: the pod binds the socket, reports the IP/port to
//! advertise in the 200 OK SDP, streams the PCMU audio, and reports
//! completion so the daemon can send the BYE. The daemon remains the
//! SIP UAS for the announcement call either way; only the media work
//! moves out of process.
//!
//! The channel is mTLS (`SBC_ANNOUNCEMENT_TLS_{CA,CERT,KEY}_FILE`, optional
//! `SBC_ANNOUNCEMENT_TLS_DOMAIN`) with an `https://` URL; plaintext is only
//! for a pod on loopback. `main` checks this at startup and exits 2 on a bad
//! setting ([`check_announcement_startup`]).
//!
//! When the pod is unreachable before TLS (DNS failure, TCP connect
//! refused/reset) or the setup times out, the SIP stack falls back to the
//! in-process engine (itself capped, see `announcement_local`). When the
//! pod refuses (cap, destination policy, client certificate) or the TLS
//! handshake / certificate check fails, there is no fallback: playing
//! in-process would bypass the pod's controls ([`fallback_allowed`]).
//!
//! All plays share one lazy channel (HTTP/2 streams on one mTLS
//! connection), rebuilt after a transport failure or when a client PEM
//! file's mtime changes.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, SC-5, SC-7

use sbc_grpc_api::mtls::{ClientTls, check_client_url, client_channel, is_pre_tls_failure};
use sbc_grpc_api::sbc::announcement_service_client::AnnouncementServiceClient;
use sbc_grpc_api::sbc::play_announcement_event::Event;
use sbc_grpc_api::sbc::{AnnouncementKind, PlayAnnouncementEvent, PlayAnnouncementRequest};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};
use tonic::transport::Channel;
use tracing::{info, warn};

#[cfg(test)]
mod tests;
// SR-41 fix round 1: TLS / certificate failures are refusals.
#[cfg(test)]
mod tls_fallback_tests;

/// Env var holding the announcement pod's gRPC URL
/// (e.g. `https://sbc-announcement:9095`). Unset = in-process playback.
pub const ANNOUNCEMENT_URL_ENV: &str = "SBC_ANNOUNCEMENT_URL";

/// Prefix of the client mTLS variables
/// (`SBC_ANNOUNCEMENT_TLS_{CA,CERT,KEY}_FILE`, `SBC_ANNOUNCEMENT_TLS_DOMAIN`).
const ANNOUNCEMENT_TLS_PREFIX: &str = "SBC_ANNOUNCEMENT_TLS";

/// Client mTLS material for the announcement channel (PEM file paths).
pub type AnnouncementTls = ClientTls;

/// Client TLS validated at startup by `main` ([`init_announcement_tls`]).
static ANNOUNCEMENT_TLS: OnceLock<Option<AnnouncementTls>> = OnceLock::new();

/// `SBC_ANNOUNCEMENT_TLS_{CA,CERT,KEY}_FILE`: all three or none;
/// `SBC_ANNOUNCEMENT_TLS_DOMAIN` only with them.
///
/// # Errors
/// A message naming the variables.
pub fn announcement_tls_from(
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    domain: Option<String>,
) -> Result<Option<AnnouncementTls>, String> {
    ClientTls::from_parts(ANNOUNCEMENT_TLS_PREFIX, ca, cert, key, domain)
}

/// `https://` with client TLS; plaintext only to a loopback pod.
///
/// # Errors
/// A message naming the URL and `SBC_ANNOUNCEMENT_TLS_*`.
pub fn check_announcement_url(url: &str, tls: Option<&AnnouncementTls>) -> Result<(), String> {
    check_client_url(ANNOUNCEMENT_TLS_PREFIX, url, tls)
        .map_err(|e| format!("{ANNOUNCEMENT_URL_ENV}: {e}"))
}

/// The startup check `main` runs when the daemon starts (exit 2 on `Err`):
/// with `SBC_ANNOUNCEMENT_URL` set, the TLS variables must be complete and
/// match the URL scheme. TLS variables without a URL are refused rather
/// than ignored.
///
/// # Errors
/// A message naming the offending variable.
///
/// ## NIST 800-53 Rev5: CM-6, SC-8
pub fn check_announcement_startup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<AnnouncementTls>, String> {
    let var = |suffix: &str| lookup(&format!("{ANNOUNCEMENT_TLS_PREFIX}_{suffix}"));
    let tls = announcement_tls_from(
        var("CA_FILE"),
        var("CERT_FILE"),
        var("KEY_FILE"),
        var("DOMAIN"),
    )?;
    match lookup(ANNOUNCEMENT_URL_ENV).filter(|u| !u.trim().is_empty()) {
        Some(url) => {
            check_announcement_url(&url, tls.as_ref())?;
            Ok(tls)
        }
        None if tls.is_some() => Err(format!(
            "{ANNOUNCEMENT_TLS_PREFIX}_* is set but {ANNOUNCEMENT_URL_ENV} is not"
        )),
        None => Ok(None),
    }
}

/// Runs [`check_announcement_startup`] on the process environment and keeps
/// the result for [`start_remote_announcement`].
///
/// # Errors
/// As [`check_announcement_startup`].
pub fn init_announcement_tls() -> Result<(), String> {
    let tls = check_announcement_startup(|k: &str| std::env::var(k).ok())?;
    // A second call keeps the first (identical) value.
    let _ = ANNOUNCEMENT_TLS.set(tls);
    Ok(())
}

/// Whether a failed Play with this status code may fall back to in-process
/// playback: the setup timed out (`DEADLINE_EXCEEDED` / `CANCELLED` from the
/// request deadline) or the pod was unreachable (`UNAVAILABLE`). For
/// `UNAVAILABLE` the cause must also be before TLS (DNS failure, refused or
/// reset TCP connect; see [`RemoteAnnouncementError`]): a TLS or
/// certificate failure is a refusal. Any other code is the pod's decision
/// (cap, destination policy, client certificate, bad request) and is final,
/// or in-process playback would bypass the pod's controls.
///
/// ## NIST 800-53 Rev5: SC-5, SC-7, IA-3
#[must_use]
pub const fn fallback_allowed(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
    )
}

/// Why a remote announcement did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAnnouncementError {
    /// The pod refused, or the channel failed at or after TLS (handshake,
    /// certificate, client PEM/config); no in-process fallback.
    Refused {
        /// gRPC status code (the pod's, or the transport's).
        code: tonic::Code,
        /// Status message (no caller data).
        message: String,
    },
    /// DNS failure, a TCP connect refused/reset/unreachable before TLS, or
    /// the setup timeout; in-process fallback is allowed.
    Unavailable(String),
}

impl RemoteAnnouncementError {
    /// Classifies a failed RPC: fallback only for a timeout, or for
    /// `UNAVAILABLE` caused before TLS ([`is_pre_tls_failure`]).
    fn from_status(context: &str, status: &tonic::Status) -> Self {
        let code = status.code();
        let pre_tls = is_pre_tls_failure(status);
        let fallback = fallback_allowed(code) && (code != tonic::Code::Unavailable || pre_tls);
        if fallback {
            Self::Unavailable(format!("{context}: {status}"))
        } else {
            Self::Refused {
                code,
                message: status.message().to_string(),
            }
        }
    }

    /// Whether the caller may play the announcement in-process instead.
    #[must_use]
    pub const fn fallback_allowed(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    /// The status code of a refusal.
    #[must_use]
    pub const fn refused_code(&self) -> Option<tonic::Code> {
        match self {
            Self::Refused { code, .. } => Some(*code),
            Self::Unavailable(_) => None,
        }
    }

    /// Whether the cached channel should be rebuilt: anything but an
    /// application-level answer from the pod.
    const fn transport_failure(&self) -> bool {
        !matches!(
            self.refused_code(),
            Some(
                tonic::Code::ResourceExhausted
                    | tonic::Code::InvalidArgument
                    | tonic::Code::PermissionDenied
            )
        )
    }

    fn refused(code: tonic::Code, message: impl Into<String>) -> Self {
        Self::Refused {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RemoteAnnouncementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { code, message } => {
                write!(f, "announcement Play refused ({code:?}): {message}")
            }
            Self::Unavailable(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for RemoteAnnouncementError {}

/// How long to wait for connect, TLS and the Bound event before falling
/// back to in-process playback. Announcement calls are already failure
/// handling; a slow pod must not stall the 200 OK.
const REMOTE_SETUP_TIMEOUT: Duration = Duration::from_secs(2);

/// What the cached channel was built from; a change (URL, TLS paths, or a
/// PEM file's mtime after a renewal) rebuilds it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelKey {
    url: String,
    tls: Option<AnnouncementTls>,
    mtimes: [Option<SystemTime>; 3],
}

/// One lazy channel to the pod, shared by every Play (HTTP/2 streams on one
/// mTLS connection) instead of a TCP + TLS handshake per announcement.
/// Locked only to clone or replace it, never across an await.
static CHANNEL: Mutex<Option<(ChannelKey, Channel)>> = Mutex::new(None);

fn cached() -> MutexGuard<'static, Option<(ChannelKey, Channel)>> {
    CHANNEL.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn channel_key(url: &str, tls: Option<&AnnouncementTls>) -> ChannelKey {
    let mut mtimes = [None; 3];
    if let Some(t) = tls {
        for (slot, p) in mtimes.iter_mut().zip([&t.ca, &t.cert, &t.key]) {
            *slot = tokio::fs::metadata(p)
                .await
                .ok()
                .and_then(|m| m.modified().ok());
        }
    }
    ChannelKey {
        url: url.to_string(),
        tls: tls.cloned(),
        mtimes,
    }
}

/// The cached channel for `url`, rebuilt when the key changed. A client
/// PEM or TLS configuration error is a refusal (no fallback).
async fn channel_for(
    url: &str,
    tls: Option<&AnnouncementTls>,
) -> Result<Channel, RemoteAnnouncementError> {
    let key = channel_key(url, tls).await;
    let hit = cached()
        .as_ref()
        .filter(|(k, _)| *k == key)
        .map(|(_, ch)| ch.clone());
    if let Some(ch) = hit {
        return Ok(ch);
    }
    // NIST 800-53 Rev5: IA-3, SC-8 -- mTLS; the PEM files are read when the
    // channel is (re)built, so rotated certificates are picked up.
    let channel = client_channel(url, tls, REMOTE_SETUP_TIMEOUT, REMOTE_SETUP_TIMEOUT)
        .await
        .map_err(|e| {
            RemoteAnnouncementError::refused(
                tonic::Code::FailedPrecondition,
                format!("client TLS configuration: {e}"),
            )
        })?;
    *cached() = Some((key, channel.clone()));
    Ok(channel)
}

/// Drops the cached channel so the next Play reconnects from scratch.
fn invalidate_channel() {
    *cached() = None;
}

/// A remote announcement session: the pod has bound an RTP socket and
/// will start streaming shortly.
pub struct RemoteAnnouncement {
    /// IP to advertise in the SDP `c=` line (the pod's media IP).
    pub advertised_ip: String,
    /// RTP port for the SDP `m=audio` line.
    pub rtp_port: u16,
    /// Remaining event stream; yields Completed when playback ends.
    stream: tonic::Streaming<PlayAnnouncementEvent>,
}

impl RemoteAnnouncement {
    /// Waits for playback to finish (the pod's Completed event). Returns
    /// an error string when the stream ends abnormally; playback may
    /// have partially run in that case, so callers should still BYE.
    pub async fn wait_complete(mut self) -> Result<u64, String> {
        loop {
            match self.stream.message().await {
                Ok(Some(PlayAnnouncementEvent {
                    event: Some(Event::Completed(done)),
                })) => return Ok(done.packets_sent),
                Ok(Some(_)) => {} // ignore unexpected/duplicate events
                Ok(None) => return Err("announcement stream closed before Completed".to_string()),
                Err(e) => return Err(format!("announcement stream error: {e}")),
            }
        }
    }
}

const fn to_proto_kind(kind: crate::announcement::AnnouncementType) -> AnnouncementKind {
    match kind {
        crate::announcement::AnnouncementType::NumberNotInService => {
            AnnouncementKind::NumberNotInService
        }
        crate::announcement::AnnouncementType::AllCircuitsBusy => AnnouncementKind::AllCircuitsBusy,
        crate::announcement::AnnouncementType::Silence => AnnouncementKind::Silence,
    }
}

/// Asks the announcement pod to play `kind` toward `rtp_destination`.
/// Returns once the pod has bound its RTP socket (Bound event), so the
/// caller can put the returned IP/port in the 200 OK SDP. Uses the client
/// TLS checked at startup.
///
/// # Errors
/// [`RemoteAnnouncementError::Refused`] when the pod refuses the request,
/// the TLS handshake or certificate check fails, the client PEM/config is
/// bad, or the pod answers with an invalid Bound (no fallback);
/// [`RemoteAnnouncementError::Unavailable`] on a DNS failure, a TCP connect
/// refused/reset before TLS, or no Bound within [`REMOTE_SETUP_TIMEOUT`]
/// (callers fall back to in-process playback).
pub async fn start_remote_announcement(
    url: &str,
    kind: crate::announcement::AnnouncementType,
    rtp_destination: std::net::SocketAddr,
    ssrc: u32,
    call_id: &str,
) -> Result<RemoteAnnouncement, RemoteAnnouncementError> {
    let tls = match ANNOUNCEMENT_TLS.get() {
        Some(tls) => tls.clone(),
        None => check_announcement_startup(|k: &str| std::env::var(k).ok())
            .map_err(|e| RemoteAnnouncementError::refused(tonic::Code::FailedPrecondition, e))?,
    };
    start_remote_announcement_with(url, tls.as_ref(), kind, rtp_destination, ssrc, call_id).await
}

/// [`start_remote_announcement`] with explicit client TLS.
///
/// # Errors
/// As [`start_remote_announcement`].
pub async fn start_remote_announcement_with(
    url: &str,
    tls: Option<&AnnouncementTls>,
    kind: crate::announcement::AnnouncementType,
    rtp_destination: std::net::SocketAddr,
    ssrc: u32,
    call_id: &str,
) -> Result<RemoteAnnouncement, RemoteAnnouncementError> {
    use RemoteAnnouncementError::Unavailable;
    check_announcement_url(url, tls)
        .map_err(|e| RemoteAnnouncementError::refused(tonic::Code::FailedPrecondition, e))?;

    let setup = async {
        let mut client = AnnouncementServiceClient::new(channel_for(url, tls).await?);

        let request = PlayAnnouncementRequest {
            kind: to_proto_kind(kind) as i32,
            rtp_destination: rtp_destination.to_string(),
            ssrc,
            initial_delay_ms: 0, // pod default (200ms)
            call_id: call_id.to_string(),
        };

        let mut stream = client
            .play(request)
            .await
            .map_err(|e| RemoteAnnouncementError::from_status("Play RPC failed", &e))?
            .into_inner();

        // An authenticated pod answering with a bad Bound is misbehaving:
        // fail closed (refusal) rather than fall back.
        match stream.message().await {
            Ok(Some(PlayAnnouncementEvent {
                event: Some(Event::Bound(bound)),
            })) => {
                if bound.advertised_ip.parse::<std::net::IpAddr>().is_err() {
                    return Err(RemoteAnnouncementError::refused(
                        tonic::Code::Internal,
                        "announcement pod returned an invalid advertised_ip",
                    ));
                }
                let Ok(rtp_port) = u16::try_from(bound.rtp_port) else {
                    return Err(RemoteAnnouncementError::refused(
                        tonic::Code::Internal,
                        "announcement pod returned an out-of-range rtp_port",
                    ));
                };
                Ok(RemoteAnnouncement {
                    advertised_ip: bound.advertised_ip,
                    rtp_port,
                    stream,
                })
            }
            Ok(_) => Err(RemoteAnnouncementError::refused(
                tonic::Code::Internal,
                "announcement pod did not send Bound first",
            )),
            Err(e) => Err(RemoteAnnouncementError::from_status(
                "announcement stream error",
                &e,
            )),
        }
    };

    let result = tokio::time::timeout(REMOTE_SETUP_TIMEOUT, setup)
        .await
        .unwrap_or_else(|_| {
            warn!(call_id, url, "Remote announcement setup timed out");
            Err(Unavailable(
                "remote announcement setup timed out".to_string(),
            ))
        });
    match result {
        Ok(session) => {
            info!(
                call_id,
                advertised_ip = %session.advertised_ip,
                rtp_port = session.rtp_port,
                "Remote announcement session established"
            );
            Ok(session)
        }
        Err(e) => {
            if e.transport_failure() {
                invalidate_channel();
            }
            Err(e)
        }
    }
}
