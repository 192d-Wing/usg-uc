//! gRPC client for the sbc-announcement-server pod.
//!
//! When `SBC_ANNOUNCEMENT_URL` is set, the SIP stack delegates
//! announcement media to the external pod instead of binding an RTP
//! socket in-process: the pod binds the socket, reports the IP/port to
//! advertise in the 200 OK SDP, streams the PCMU audio, and reports
//! completion so the daemon can send the BYE. The daemon remains the
//! SIP UAS for the announcement call either way; only the media work
//! moves out of process. On any error here the SIP stack falls back to
//! the in-process engine, so a missing/crashed announcement pod
//! degrades to pre-split behavior rather than dropping the
//! announcement.

use sbc_grpc_api::sbc::announcement_service_client::AnnouncementServiceClient;
use sbc_grpc_api::sbc::play_announcement_event::Event;
use sbc_grpc_api::sbc::{AnnouncementKind, PlayAnnouncementEvent, PlayAnnouncementRequest};
use std::time::Duration;
use tracing::{info, warn};

/// Env var holding the announcement pod's gRPC URL
/// (e.g. `http://sbc-announcement:9095`). Unset = in-process playback.
pub const ANNOUNCEMENT_URL_ENV: &str = "SBC_ANNOUNCEMENT_URL";

/// How long to wait for connect + the Bound event before falling back
/// to in-process playback. Announcement calls are already failure
/// handling; a slow pod must not stall the 200 OK.
const REMOTE_SETUP_TIMEOUT: Duration = Duration::from_secs(2);

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
/// caller can put the returned IP/port in the 200 OK SDP.
///
/// # Errors
/// Returns an error when the pod is unreachable, rejects the request,
/// or does not report Bound within [`REMOTE_SETUP_TIMEOUT`]. Callers
/// fall back to in-process playback.
pub async fn start_remote_announcement(
    url: &str,
    kind: crate::announcement::AnnouncementType,
    rtp_destination: std::net::SocketAddr,
    ssrc: u32,
    call_id: &str,
) -> Result<RemoteAnnouncement, String> {
    let setup = async {
        let mut client = AnnouncementServiceClient::connect(url.to_string())
            .await
            .map_err(|e| format!("connect {url} failed: {e}"))?;

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
            .map_err(|e| format!("Play RPC failed: {e}"))?
            .into_inner();

        match stream.message().await {
            Ok(Some(PlayAnnouncementEvent {
                event: Some(Event::Bound(bound)),
            })) => {
                if bound.advertised_ip.parse::<std::net::IpAddr>().is_err() {
                    return Err(format!(
                        "announcement pod returned invalid advertised_ip: {:?}",
                        bound.advertised_ip
                    ));
                }
                if bound.rtp_port > u32::from(u16::MAX) {
                    return Err(format!(
                        "announcement pod returned out-of-range rtp_port: {}",
                        bound.rtp_port
                    ));
                }
                #[allow(clippy::cast_possible_truncation)]
                Ok(RemoteAnnouncement {
                    advertised_ip: bound.advertised_ip,
                    rtp_port: bound.rtp_port as u16,
                    stream,
                })
            }
            Ok(other) => Err(format!("expected Bound event, got {other:?}")),
            Err(e) => Err(format!("announcement stream error: {e}")),
        }
    };

    match tokio::time::timeout(REMOTE_SETUP_TIMEOUT, setup).await {
        Ok(Ok(session)) => {
            info!(
                call_id,
                advertised_ip = %session.advertised_ip,
                rtp_port = session.rtp_port,
                "Remote announcement session established"
            );
            Ok(session)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            warn!(call_id, url, "Remote announcement setup timed out");
            Err("remote announcement setup timed out".to_string())
        }
    }
}
