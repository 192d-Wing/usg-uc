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
use crate::media_pipeline::{LegDtlsParams, MediaKind, MediaPipeline, MediaPipelineError};
use sbc_grpc_api::sbc as pb;
use sbc_grpc_api::sbc::media_controller_service_server::MediaControllerService;
use std::net::SocketAddr;
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
        // No recording RPC exists (POA&M-301); mapped for completeness so a
        // future one reports "cannot record", never success.
        E::RecordingUnsupported => Status::unimplemented(msg),
        E::RecordingFork(_) => Status::failed_precondition(msg),
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

/// Proto discriminant → [`MediaKind`]. `UNSPECIFIED` and unknown values
/// (proto3 enums are open) are rejected: fail closed.
// NIST 800-53 Rev5: SI-10 (Information Input Validation)
fn from_proto_kind(value: i32) -> Result<MediaKind, Status> {
    match pb::MediaKind::try_from(value) {
        Ok(pb::MediaKind::Audio) => Ok(MediaKind::Audio),
        Ok(pb::MediaKind::Image) => Ok(MediaKind::Image),
        Ok(pb::MediaKind::Unspecified) | Err(_) => Err(Status::invalid_argument(format!(
            "invalid MediaKind {value}"
        ))),
    }
}

fn parse_addr(value: &str) -> Result<SbcSocketAddr, Status> {
    value
        .parse::<SocketAddr>()
        .map(SbcSocketAddr::from)
        .map_err(|e| Status::invalid_argument(format!("invalid address {value:?}: {e}")))
}

/// Leg remotes and kind decoded from an `UpdateRelayRequest`.
type DecodedUpdate = ([Option<(bool, SbcSocketAddr)>; 2], Option<MediaKind>);

/// Decodes an `UpdateRelayRequest` without touching any state: at most two
/// remotes on distinct legs, each a parseable `ip:port`; kind UNSPECIFIED
/// means unchanged, any other non-{AUDIO,IMAGE} value is refused.
fn decode_update_relay(r: &pb::UpdateRelayRequest) -> Result<DecodedUpdate, Status> {
    if r.remotes.len() > 2 {
        return Err(Status::invalid_argument(format!(
            "at most 2 remotes, got {}",
            r.remotes.len()
        )));
    }
    let mut remotes = [None, None];
    for (slot, remote) in remotes.iter_mut().zip(&r.remotes) {
        *slot = Some((remote.is_a_leg, parse_addr(&remote.address)?));
    }
    if let [Some((a, _)), Some((b, _))] = remotes
        && a == b
    {
        return Err(Status::invalid_argument("duplicate leg in remotes"));
    }
    let kind = if r.kind == pb::MediaKind::Unspecified as i32 {
        None
    } else {
        Some(from_proto_kind(r.kind)?)
    };
    Ok((remotes, kind))
}

#[tonic::async_trait]
impl MediaControllerService for MediaControllerServer {
    async fn create_session(
        &self,
        req: Request<pb::CreateSessionRequest>,
    ) -> Result<Response<pb::AllocatedPorts>, Status> {
        let r = req.into_inner();
        // A media NODE binds its relay sockets on ITS OWN interface, not the
        // signaling daemon's zone media IP (which the request carries but which
        // isn't assigned on this host — binding it fails with EADDRNOTAVAIL).
        // Use this node's advertised IP, or wildcard (0.0.0.0) when unset
        // (co-located, where the daemon and node share the pod IP).
        let bind = self.pipeline.advertised_media_ip();
        let ports = self
            .pipeline
            .create_session_with_zones(&r.call_id, from_proto_mode(r.mode), bind, bind)
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

    async fn set_media_kind(
        &self,
        req: Request<pb::SetMediaKindRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        let kind = from_proto_kind(r.kind)?;
        self.pipeline
            .set_media_kind(&r.call_id, kind)
            .await
            .map_err(|e| to_status(&e))?;
        Ok(Response::new(()))
    }

    /// Validate every field, then apply under one session lock, then start
    /// (rolled back if the start fails).
    // NIST 800-53 Rev5: SI-10 (validate-all-then-apply), SC-24 (no partial update)
    async fn update_relay(
        &self,
        req: Request<pb::UpdateRelayRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        let (remotes, kind) = decode_update_relay(&r)?;
        // SEC-2: with start_relay the pipeline rolls the update back if the
        // start fails, so an Err leaves no half-applied state.
        let applied = if r.start_relay {
            self.pipeline
                .update_and_start_relay(&r.call_id, remotes, kind)
                .await
        } else {
            self.pipeline.update_relay(&r.call_id, remotes, kind).await
        };
        applied.map_err(|e| to_status(&e))?;
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
        let (client, tx, _) = harness_with_pipeline().await;
        (client, tx)
    }

    async fn harness_with_pipeline() -> (
        MediaControllerServiceClient<Channel>,
        mpsc::UnboundedSender<String>,
        Arc<MediaPipeline>,
    ) {
        let pipeline = Arc::new(MediaPipeline::new(MediaPipelineConfig::default()));
        let fingerprint = Arc::new(DtlsFingerprintSource::from_static(FINGERPRINT.to_string()));
        let (failure_tx, failure_rx) = mpsc::unbounded_channel();
        let server =
            MediaControllerServer::new(Arc::clone(&pipeline), Some(fingerprint), failure_rx);

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
        (client, failure_tx, pipeline)
    }

    async fn create(
        client: &mut MediaControllerServiceClient<Channel>,
        id: &str,
    ) -> Result<(), Status> {
        client
            .create_session(pb::CreateSessionRequest {
                call_id: id.to_string(),
                mode: pb::MediaMode::Relay as i32,
                a_leg_media_ip: None,
                b_leg_media_ip: None,
            })
            .await?;
        Ok(())
    }

    fn remote(is_a_leg: bool, address: &str) -> pb::LegRemote {
        pb::LegRemote {
            is_a_leg,
            address: address.to_string(),
        }
    }

    /// SI-10: a bad second address leaves kind and the first remote unchanged.
    #[tokio::test]
    async fn update_relay_rpc_applies_all_or_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, _tx, pipeline) = harness_with_pipeline().await;
        create(&mut client, "u1").await?;
        let err = client
            .update_relay(pb::UpdateRelayRequest {
                call_id: "u1".into(),
                remotes: vec![remote(true, "192.0.2.1:5000"), remote(false, "not-an-addr")],
                kind: pb::MediaKind::Image as i32,
                start_relay: false,
            })
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(pipeline.media_kind("u1").await, Some(MediaKind::Audio));
        assert_eq!(pipeline.leg_remote("u1", true).await, None);

        client
            .update_relay(pb::UpdateRelayRequest {
                call_id: "u1".into(),
                remotes: vec![
                    remote(true, "192.0.2.1:5000"),
                    remote(false, "192.0.2.2:6000"),
                ],
                kind: pb::MediaKind::Image as i32,
                start_relay: false,
            })
            .await?;
        assert_eq!(pipeline.media_kind("u1").await, Some(MediaKind::Image));
        assert_eq!(
            pipeline.leg_remote("u1", false).await,
            Some(SbcSocketAddr::from("192.0.2.2:6000".parse::<SocketAddr>()?))
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_relay_rejects_three_remotes_and_duplicate_leg()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, _tx, pipeline) = harness_with_pipeline().await;
        create(&mut client, "u2").await?;
        for remotes in [
            vec![
                remote(true, "192.0.2.1:5000"),
                remote(false, "192.0.2.2:5000"),
                remote(true, "192.0.2.3:5000"),
            ],
            vec![
                remote(true, "192.0.2.1:5000"),
                remote(true, "192.0.2.3:5000"),
            ],
        ] {
            let err = client
                .update_relay(pb::UpdateRelayRequest {
                    call_id: "u2".into(),
                    remotes,
                    kind: pb::MediaKind::Image as i32,
                    start_relay: true,
                })
                .await
                .err()
                .ok_or("expected an error")?;
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        assert_eq!(pipeline.media_kind("u2").await, Some(MediaKind::Audio));
        assert_eq!(pipeline.leg_remote("u2", true).await, None);
        Ok(())
    }

    #[tokio::test]
    async fn update_relay_unspecified_kind_is_noop_but_unknown_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, _tx, pipeline) = harness_with_pipeline().await;
        create(&mut client, "u3").await?;
        client
            .update_relay(pb::UpdateRelayRequest {
                call_id: "u3".into(),
                remotes: vec![remote(true, "192.0.2.1:5000")],
                kind: pb::MediaKind::Unspecified as i32,
                start_relay: false,
            })
            .await?;
        assert_eq!(pipeline.media_kind("u3").await, Some(MediaKind::Audio));
        for bad in [-1, 3, i32::MAX] {
            let err = client
                .update_relay(pb::UpdateRelayRequest {
                    call_id: "u3".into(),
                    remotes: vec![remote(true, "192.0.2.9:5000")],
                    kind: bad,
                    start_relay: false,
                })
                .await
                .err()
                .ok_or("expected an error")?;
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{bad}");
        }
        assert_eq!(
            pipeline.leg_remote("u3", true).await,
            Some(SbcSocketAddr::from("192.0.2.1:5000".parse::<SocketAddr>()?))
        );
        let err = client
            .update_relay(pb::UpdateRelayRequest {
                call_id: "missing".into(),
                ..Default::default()
            })
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.code(), tonic::Code::NotFound);
        Ok(())
    }

    #[tokio::test]
    async fn update_relay_start_flag_starts_relay() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, _tx, pipeline) = harness_with_pipeline().await;
        create(&mut client, "u4").await?;
        client
            .update_relay(pb::UpdateRelayRequest {
                call_id: "u4".into(),
                remotes: vec![
                    remote(true, "127.0.0.1:5000"),
                    remote(false, "127.0.0.1:6000"),
                ],
                kind: pb::MediaKind::Image as i32,
                start_relay: true,
            })
            .await?;
        assert_eq!(pipeline.media_kind("u4").await, Some(MediaKind::Image));
        // Relay running: stopping it succeeds.
        client
            .stop_relay(pb::CallRef {
                call_id: "u4".into(),
            })
            .await?;
        Ok(())
    }

    /// SEC-2: a start failure after the update rolls the update back.
    #[tokio::test]
    async fn update_relay_start_failure_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, _tx, pipeline) = harness_with_pipeline().await;
        create(&mut client, "u5").await?;
        // B-leg remote never set, so start_relay fails after the update.
        let err = client
            .update_relay(pb::UpdateRelayRequest {
                call_id: "u5".into(),
                remotes: vec![remote(true, "127.0.0.1:5000")],
                kind: pb::MediaKind::Image as i32,
                start_relay: true,
            })
            .await
            .err()
            .ok_or("start must fail")?;
        assert!(!err.message().contains("start_relay after update"));
        assert_eq!(pipeline.media_kind("u5").await, Some(MediaKind::Audio));
        assert_eq!(pipeline.leg_remote("u5", true).await, None);
        Ok(())
    }

    /// POA&M-294: SetMediaKind reaches the pipeline; UNSPECIFIED and unknown
    /// enum values are refused with INVALID_ARGUMENT (fail closed).
    #[tokio::test]
    async fn set_media_kind_updates_pipeline_and_rejects_bad_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, _tx, pipeline) = harness_with_pipeline().await;
        client
            .create_session(pb::CreateSessionRequest {
                call_id: "k1".to_string(),
                mode: pb::MediaMode::Relay as i32,
                a_leg_media_ip: None,
                b_leg_media_ip: None,
            })
            .await?;
        assert_eq!(pipeline.media_kind("k1").await, Some(MediaKind::Audio));
        client
            .set_media_kind(pb::SetMediaKindRequest {
                call_id: "k1".into(),
                kind: pb::MediaKind::Image as i32,
            })
            .await?;
        assert_eq!(pipeline.media_kind("k1").await, Some(MediaKind::Image));

        for bad in [pb::MediaKind::Unspecified as i32, 7] {
            let err = client
                .set_media_kind(pb::SetMediaKindRequest {
                    call_id: "k1".into(),
                    kind: bad,
                })
                .await
                .err()
                .ok_or("expected an error")?;
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{bad}");
        }
        assert_eq!(pipeline.media_kind("k1").await, Some(MediaKind::Image));

        let err = client
            .set_media_kind(pb::SetMediaKindRequest {
                call_id: "nope".into(),
                kind: pb::MediaKind::Audio as i32,
            })
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.code(), tonic::Code::NotFound);
        Ok(())
    }

    /// QA: proto3 open enums deliver arbitrary i32s; every value outside
    /// {AUDIO, IMAGE} is refused and leaves the pipeline kind unchanged.
    #[tokio::test]
    async fn set_media_kind_rejects_every_out_of_range_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, _tx, pipeline) = harness_with_pipeline().await;
        client
            .create_session(pb::CreateSessionRequest {
                call_id: "k2".to_string(),
                mode: pb::MediaMode::Relay as i32,
                a_leg_media_ip: None,
                b_leg_media_ip: None,
            })
            .await?;
        for bad in [-1, 3, 255, i32::MIN, i32::MAX] {
            let err = client
                .set_media_kind(pb::SetMediaKindRequest {
                    call_id: "k2".into(),
                    kind: bad,
                })
                .await
                .err()
                .ok_or("expected an error")?;
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{bad}");
            assert_eq!(pipeline.media_kind("k2").await, Some(MediaKind::Audio));
        }
        // Validation precedes lookup: a bad kind on an unknown call is still
        // INVALID_ARGUMENT or NOT_FOUND, never OK.
        let err = client
            .set_media_kind(pb::SetMediaKindRequest {
                call_id: "missing".into(),
                kind: 0,
            })
            .await
            .err()
            .ok_or("expected an error")?;
        assert_ne!(err.code(), tonic::Code::Ok);
        // Image then back to Audio round-trips.
        for kind in [pb::MediaKind::Image, pb::MediaKind::Audio] {
            client
                .set_media_kind(pb::SetMediaKindRequest {
                    call_id: "k2".into(),
                    kind: kind as i32,
                })
                .await?;
        }
        assert_eq!(pipeline.media_kind("k2").await, Some(MediaKind::Audio));
        Ok(())
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
