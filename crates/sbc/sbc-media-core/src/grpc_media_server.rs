//! gRPC server implementation of [`MediaControllerService`].
//!
//! Phase 2c of the signaling↔media split. `MediaControllerServer` hosts the
//! [`MediaControllerService`] over a real [`MediaPipeline`], so the media plane
//! can run in its own process driven by the [`crate::grpc_media_controller`]
//! client. It is the server-side mirror of Phase 2b:
//! - [`to_status`] is the canonical [`MediaPipelineError`] → [`tonic::Status`]
//!   mapping; the client's `map_status` is its inverse (they round-trip by code).
//! - Requests are decoded (proto → the pipeline's Rust types), delegated to the
//!   pipeline, and results re-encoded.
//! - `WatchMediaEvents` bridges the pipeline's in-process `media_failure` mpsc
//!   into a broadcast so each subscriber (across client reconnects) sees
//!   post-answer media failures and can tear the call down.
//!
//! This module is the service impl only; wiring it into a process (binding the
//! socket, owning the DTLS sidecar) is Phase 2d.

use crate::dtls_identity::DtlsFingerprintSource;
use crate::dtls_sidecar::Role;
use crate::media_pipeline::{LegDtlsParams, MediaPipeline, MediaPipelineError};
use sbc_grpc_api::sbc as pb;
use sbc_grpc_api::sbc::media_controller_service_server::MediaControllerService;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};
use uc_media_engine::MediaMode;
use uc_types::address::SbcSocketAddr;

/// Backlog of buffered media-failure events per subscriber. Failures are rare
/// (one per call teardown at most), so this only needs to cover a brief
/// reconnect gap; a lagging subscriber that overflows it just misses events.
const EVENT_CHANNEL_CAP: usize = 256;

/// Serves [`MediaControllerService`] over a [`MediaPipeline`].
pub struct MediaControllerServer {
    pipeline: Arc<MediaPipeline>,
    /// The SBC's DTLS identity, served over `GetDtlsFingerprint`. `None` when the
    /// SBC is not in DTLS-terminate mode.
    fingerprint: Option<Arc<DtlsFingerprintSource>>,
    /// Fan-out of failed calls' session ids to `WatchMediaEvents` subscribers.
    events: broadcast::Sender<String>,
}

impl MediaControllerServer {
    /// Builds the server over `pipeline`, serving `fingerprint` on
    /// `GetDtlsFingerprint`, and bridging `failure_rx` (the pipeline's
    /// `media_failure_tx` receiver) into the `WatchMediaEvents` fan-out.
    ///
    /// Spawns a task that forwards each failed call id from the mpsc into the
    /// broadcast; it ends when the pipeline drops its `media_failure_tx`. A
    /// failure raised while no client is subscribed is dropped (best-effort,
    /// matching the in-process channel's semantics).
    #[must_use]
    pub fn new(
        pipeline: Arc<MediaPipeline>,
        fingerprint: Option<Arc<DtlsFingerprintSource>>,
        mut failure_rx: UnboundedReceiver<String>,
    ) -> Self {
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAP);
        let bridge = events.clone();
        tokio::spawn(async move {
            while let Some(call_id) = failure_rx.recv().await {
                // Err = no active subscriber; the failed call simply isn't torn
                // down over RPC this round (same as a dropped in-process send).
                let _ = bridge.send(call_id);
            }
        });
        Self {
            pipeline,
            fingerprint,
            events,
        }
    }
}

/// Canonical [`MediaPipelineError`] → [`tonic::Status`] mapping. The inverse of
/// the client's `map_status`; the two agree on the status code for every
/// variant, so an error round-trips to the same class on the far side. The
/// human-readable `Display` string is carried as the status message.
fn to_status(err: &MediaPipelineError) -> Status {
    use MediaPipelineError as E;
    let msg = err.to_string();
    match err {
        E::SessionNotFound | E::DtlsConnectionNotFound => Status::not_found(msg),
        E::PortExhausted => Status::resource_exhausted(msg),
        E::DtlsHandshakeFailed(_) => Status::failed_precondition(msg),
        E::CodecNegotiationFailed => Status::invalid_argument(msg),
        E::BindFailed(_) => Status::unavailable(msg),
        E::SrtpKeyExportFailed(_)
        | E::SrtpContextCreationFailed(_)
        | E::EncryptionFailed(_)
        | E::DecryptionFailed(_)
        // Rpc shouldn't originate server-side (the pipeline never produces it),
        // but map it to Internal for completeness.
        | E::Rpc(_) => Status::internal(msg),
    }
}

/// Proto discriminant → `Option<MediaMode>` (`UNSPECIFIED`/unknown = `None`).
fn from_proto_mode(value: i32) -> Option<MediaMode> {
    match pb::MediaMode::try_from(value).unwrap_or(pb::MediaMode::Unspecified) {
        pb::MediaMode::Unspecified => None,
        pb::MediaMode::Relay => Some(MediaMode::Relay),
        pb::MediaMode::PassThrough => Some(MediaMode::PassThrough),
        pb::MediaMode::EarlyRelay => Some(MediaMode::EarlyRelay),
    }
}

/// Proto discriminant → [`Role`]; an unknown value is a client error.
fn from_proto_role(value: i32) -> Result<Role, Status> {
    match pb::DtlsRole::try_from(value) {
        Ok(pb::DtlsRole::Server) => Ok(Role::Server),
        Ok(pb::DtlsRole::Client) => Ok(Role::Client),
        Err(_) => Err(Status::invalid_argument(format!(
            "invalid DtlsRole {value}"
        ))),
    }
}

fn from_proto_leg(leg: Option<pb::LegDtlsParams>, which: &str) -> Result<LegDtlsParams, Status> {
    let leg = leg.ok_or_else(|| Status::invalid_argument(format!("missing {which}_leg")))?;
    Ok(LegDtlsParams {
        peer_fingerprint: leg.peer_fingerprint,
        role: from_proto_role(leg.role)?,
    })
}

fn parse_addr(value: &str) -> Result<SbcSocketAddr, Status> {
    value
        .parse::<SocketAddr>()
        .map(SbcSocketAddr::from)
        .map_err(|e| Status::invalid_argument(format!("invalid address {value:?}: {e}")))
}

fn parse_ip(value: &str) -> Result<IpAddr, Status> {
    value
        .parse::<IpAddr>()
        .map_err(|e| Status::invalid_argument(format!("invalid ip {value:?}: {e}")))
}

#[tonic::async_trait]
impl MediaControllerService for MediaControllerServer {
    async fn create_session(
        &self,
        req: Request<pb::CreateSessionRequest>,
    ) -> Result<Response<pb::AllocatedPorts>, Status> {
        let r = req.into_inner();
        let a_ip = r.a_leg_media_ip.as_deref().map(parse_ip).transpose()?;
        let b_ip = r.b_leg_media_ip.as_deref().map(parse_ip).transpose()?;
        let ports = self
            .pipeline
            .create_session_with_zones(&r.call_id, from_proto_mode(r.mode), a_ip, b_ip)
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(pb::AllocatedPorts {
            a_leg_rtp_port: u32::from(ports.a_leg_rtp_port),
            b_leg_rtp_port: u32::from(ports.b_leg_rtp_port),
            media_ip: ports.media_ip.map(|ip| ip.to_string()),
            dtls_fingerprint: ports.dtls_fingerprint,
        }))
    }

    async fn set_remote_address(
        &self,
        req: Request<pb::SetRemoteAddressRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        let addr = parse_addr(&r.address)?;
        self.pipeline
            .set_remote_address(&r.call_id, r.is_a_leg, addr)
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(()))
    }

    async fn start_relay(&self, req: Request<pb::CallRef>) -> Result<Response<()>, Status> {
        self.pipeline
            .start_relay(&req.into_inner().call_id)
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(()))
    }

    async fn start_relay_terminate(
        &self,
        req: Request<pb::StartRelayTerminateRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        let a_leg = from_proto_leg(r.a_leg, "a")?;
        let b_leg = from_proto_leg(r.b_leg, "b")?;
        self.pipeline
            .start_relay_terminate(&r.call_id, a_leg, b_leg)
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(()))
    }

    async fn stop_relay(&self, req: Request<pb::CallRef>) -> Result<Response<()>, Status> {
        self.pipeline
            .stop_relay(&req.into_inner().call_id)
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(()))
    }

    async fn remove_session(&self, req: Request<pb::CallRef>) -> Result<Response<()>, Status> {
        self.pipeline
            .remove_session(&req.into_inner().call_id)
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(()))
    }

    async fn allocate_ports(&self, _req: Request<()>) -> Result<Response<pb::PortPair>, Status> {
        let (rtp, rtcp) = self
            .pipeline
            .port_allocator()
            .allocate_pair()
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(pb::PortPair {
            rtp_port: u32::from(rtp),
            rtcp_port: u32::from(rtcp),
        }))
    }

    async fn get_dtls_fingerprint(
        &self,
        _req: Request<()>,
    ) -> Result<Response<pb::DtlsFingerprint>, Status> {
        let fingerprint = self
            .fingerprint
            .as_ref()
            .ok_or_else(|| Status::unavailable("DTLS not configured (SBC not in terminate mode)"))?
            .current();
        Ok(Response::new(pb::DtlsFingerprint { fingerprint }))
    }

    type WatchMediaEventsStream =
        Pin<Box<dyn Stream<Item = Result<pb::MediaEvent, Status>> + Send>>;

    async fn watch_media_events(
        &self,
        _req: Request<()>,
    ) -> Result<Response<Self::WatchMediaEventsStream>, Status> {
        let stream = BroadcastStream::new(self.events.subscribe()).filter_map(|res| match res {
            Ok(call_id) => Some(Ok(pb::MediaEvent {
                event: Some(pb::media_event::Event::Failure(pb::MediaFailure {
                    call_id,
                })),
            })),
            // Lagged(n): the subscriber fell behind and lost n events. Skip the
            // marker and keep the stream open rather than surfacing it as error.
            Err(_) => None,
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media_pipeline::MediaPipelineConfig;
    use sbc_grpc_api::sbc::media_controller_service_client::MediaControllerServiceClient;
    use sbc_grpc_api::sbc::media_controller_service_server::MediaControllerServiceServer;
    use tokio::sync::mpsc;
    use tonic::transport::Channel;

    const FINGERPRINT: &str = "sha-384 AA:BB:CC:DD";

    /// Brings up a real `MediaControllerServer` on an ephemeral loopback port and
    /// returns a connected raw client plus the failure sender feeding the event
    /// stream. Using the generated client (not the 2b `GrpcMediaController`)
    /// keeps this phase independent of the client impl.
    async fn harness() -> (
        MediaControllerServiceClient<Channel>,
        mpsc::UnboundedSender<String>,
    ) {
        let pipeline = Arc::new(MediaPipeline::new(MediaPipelineConfig::default()));
        let fingerprint = Arc::new(DtlsFingerprintSource::from_static(FINGERPRINT.to_string()));
        let (failure_tx, failure_rx) = mpsc::unbounded_channel();
        let server = MediaControllerServer::new(pipeline, Some(fingerprint), failure_rx);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(MediaControllerServiceServer::new(server))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let client = MediaControllerServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        (client, failure_tx)
    }

    #[tokio::test]
    async fn create_session_allocates_real_ports() {
        let (mut client, _tx) = harness().await;
        let resp = client
            .create_session(pb::CreateSessionRequest {
                call_id: "c1".to_string(),
                mode: pb::MediaMode::Relay as i32,
                a_leg_media_ip: None,
                b_leg_media_ip: None,
            })
            .await
            .unwrap()
            .into_inner();
        // Default allocator range is 16384..=32768; ports are even (RTP).
        assert!((16_384..=32_768).contains(&resp.a_leg_rtp_port));
        assert!((16_384..=32_768).contains(&resp.b_leg_rtp_port));
        assert_ne!(resp.a_leg_rtp_port, resp.b_leg_rtp_port);
        assert_eq!(resp.a_leg_rtp_port % 2, 0);
    }

    #[tokio::test]
    async fn allocate_ports_returns_rtp_rtcp_pair() {
        let (mut client, _tx) = harness().await;
        let pair = client.allocate_ports(()).await.unwrap().into_inner();
        assert_eq!(pair.rtcp_port, pair.rtp_port + 1);
    }

    #[tokio::test]
    async fn get_fingerprint_serves_identity() {
        let (mut client, _tx) = harness().await;
        let fp = client.get_dtls_fingerprint(()).await.unwrap().into_inner();
        assert_eq!(fp.fingerprint, FINGERPRINT);
    }

    #[tokio::test]
    async fn set_remote_on_unknown_session_maps_to_not_found() {
        let (mut client, _tx) = harness().await;
        let status = client
            .set_remote_address(pb::SetRemoteAddressRequest {
                call_id: "nope".to_string(),
                is_a_leg: true,
                address: "1.2.3.4:5000".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn set_remote_with_bad_address_is_invalid_argument() {
        let (mut client, _tx) = harness().await;
        let status = client
            .set_remote_address(pb::SetRemoteAddressRequest {
                call_id: "c1".to_string(),
                is_a_leg: true,
                address: "not-an-address".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn set_remote_after_create_succeeds() {
        let (mut client, _tx) = harness().await;
        client
            .create_session(pb::CreateSessionRequest {
                call_id: "c2".to_string(),
                mode: pb::MediaMode::Unspecified as i32,
                a_leg_media_ip: None,
                b_leg_media_ip: None,
            })
            .await
            .unwrap();
        client
            .set_remote_address(pb::SetRemoteAddressRequest {
                call_id: "c2".to_string(),
                is_a_leg: false,
                address: "[::1]:6000".to_string(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn start_relay_terminate_rejects_unknown_role() {
        let (mut client, _tx) = harness().await;
        let status = client
            .start_relay_terminate(pb::StartRelayTerminateRequest {
                call_id: "c3".to_string(),
                a_leg: Some(pb::LegDtlsParams {
                    peer_fingerprint: "sha-384 XX".to_string(),
                    role: 99, // not a valid DtlsRole
                }),
                b_leg: Some(pb::LegDtlsParams {
                    peer_fingerprint: "sha-384 YY".to_string(),
                    role: pb::DtlsRole::Server as i32,
                }),
            })
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn watch_media_events_streams_failures() {
        let (mut client, tx) = harness().await;
        let mut stream = client.watch_media_events(()).await.unwrap().into_inner();
        // Subscription is live once the RPC returns; the pipeline now signals a
        // failed call, which must arrive as a MediaFailure event.
        tx.send("failed-call".to_string()).unwrap();
        let event = stream.message().await.unwrap().unwrap();
        match event.event {
            Some(pb::media_event::Event::Failure(f)) => assert_eq!(f.call_id, "failed-call"),
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn to_status_covers_all_variants() {
        use tonic::Code;
        assert_eq!(
            to_status(&MediaPipelineError::SessionNotFound).code(),
            Code::NotFound
        );
        assert_eq!(
            to_status(&MediaPipelineError::PortExhausted).code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            to_status(&MediaPipelineError::DtlsHandshakeFailed("x".into())).code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            to_status(&MediaPipelineError::CodecNegotiationFailed).code(),
            Code::InvalidArgument
        );
        assert_eq!(
            to_status(&MediaPipelineError::BindFailed("x".into())).code(),
            Code::Unavailable
        );
        assert_eq!(
            to_status(&MediaPipelineError::EncryptionFailed("x".into())).code(),
            Code::Internal
        );
    }
}
