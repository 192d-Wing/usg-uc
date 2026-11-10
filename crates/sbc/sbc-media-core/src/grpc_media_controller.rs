//! gRPC client implementation of [`MediaController`].
//!
//! Phase 2b of the signaling↔media split. `GrpcMediaController` lets the SIP
//! signaling layer drive a media plane that runs in a separate process: it
//! implements the same [`MediaController`] trait the in-process
//! [`crate::media_pipeline::MediaPipeline`] does, translating each call into a
//! [`MediaControllerService`](sbc_grpc_api::sbc::media_controller_service_server)
//! RPC. Because the trait is `Arc<dyn MediaController>` on the `SipStack`
//! (see #99), swapping the in-process pipeline for this client is a
//! construction-time choice — the call flow does not change.
//!
//! Two capabilities live here that are NOT on the trait, because they only
//! exist once the plane is out of process:
//! - [`GrpcMediaController::fetch_dtls_fingerprint`] — the media process owns
//!   the DTLS identity, so signaling fetches the fingerprint over RPC to stamp
//!   SDP `a=fingerprint` (in-process it reads `DtlsFingerprintSource` directly).
//! - [`GrpcMediaController::watch_media_events`] — the media→signaling reverse
//!   channel that is an in-process `mpsc` today (`media_failure_tx`).

use crate::dtls_sidecar::Role;
use crate::media_pipeline::{
    AllocatedPorts, LegDtlsParams, MediaController, MediaKind, MediaPipelineError,
};
use sbc_grpc_api::sbc as pb;
use sbc_grpc_api::sbc::media_controller_service_client::MediaControllerServiceClient;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};
use uc_media_engine::MediaMode;
use uc_types::address::SbcSocketAddr;

/// Time allowed to (re)establish the control connection to a media node.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Deadline for one media-control RPC. Well under the INVITE's Timer B, so a
/// dead node is marked down and the call placed on another node in time.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// A [`MediaController`] backed by a gRPC connection to an out-of-process media
/// plane. Cheap to clone-per-call: the inner tonic client shares one HTTP/2
/// channel, so the `&self` trait methods clone it to obtain the `&mut` each RPC
/// needs without serializing calls. `Clone` is likewise cheap (shares the
/// channel) — used to hand one connection to both the pool and its event drain.
#[derive(Clone)]
pub struct GrpcMediaController {
    client: MediaControllerServiceClient<Channel>,
    /// `SetMediaKind` came back UNIMPLEMENTED (media node older than this
    /// daemon) and was logged once.
    kind_unimplemented_logged: Arc<AtomicBool>,
    /// `UpdateRelay` came back UNIMPLEMENTED (media node older than this
    /// daemon). Cached per node so later updates skip the doomed RPC: a kind
    /// change then fails closed, an audio-only update uses the legacy RPCs.
    update_relay_unimplemented: Arc<AtomicBool>,
}

impl GrpcMediaController {
    /// Connects to the media process at `url` (e.g. `http://sbc-media:9096`).
    ///
    /// # Errors
    /// Returns [`MediaPipelineError::Rpc`] if the connection cannot be
    /// established.
    pub async fn connect(url: String) -> Result<Self, MediaPipelineError> {
        let rpc_err = |e: tonic::transport::Error| {
            MediaPipelineError::Rpc(format!("connect {url} failed: {e}"))
        };
        // Without deadlines an RPC to a node that died without closing its
        // socket hangs instead of failing, so the pool never routes away from
        // it (NIST 800-53 Rev5: SC-5, CP-10). The request timeout covers a
        // streaming RPC only until its response headers arrive, so the
        // long-lived event stream is unaffected.
        let channel = Endpoint::from_shared(url.clone())
            .map_err(rpc_err)?
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .connect()
            .await
            .map_err(rpc_err)?;
        Ok(Self::new(MediaControllerServiceClient::new(channel)))
    }

    /// Wraps an already-connected client (used by tests and by callers that
    /// build the channel themselves, e.g. with custom TLS).
    #[must_use]
    pub fn new(client: MediaControllerServiceClient<Channel>) -> Self {
        Self {
            client,
            kind_unimplemented_logged: Arc::new(AtomicBool::new(false)),
            update_relay_unimplemented: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Sends `UpdateRelay`, or, on a node that answered UNIMPLEMENTED,
    /// falls back to the legacy per-field RPCs for an audio-only update.
    ///
    /// A kind change on such a node is refused without any RPC: there is no
    /// fallback to `SetMediaKind`, so T.38 on an old node is declined
    /// (`RelayUpdateFailed`) rather than half-applied.
    // NIST 800-53 Rev5: SC-24 (fail closed), SI-10. POA&M-294.
    async fn send_update_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
        start_relay: bool,
    ) -> Result<(), MediaPipelineError> {
        if !self.update_relay_unimplemented.load(Ordering::Relaxed) {
            let req = pb::UpdateRelayRequest {
                call_id: call_id.to_string(),
                remotes: remotes
                    .iter()
                    .flatten()
                    .map(|(is_a_leg, address)| pb::LegRemote {
                        is_a_leg: *is_a_leg,
                        address: address.as_std().to_string(),
                    })
                    .collect(),
                kind: kind.map_or(pb::MediaKind::Unspecified as i32, to_proto_kind),
                start_relay,
            };
            let mut client = self.client.clone();
            match client.update_relay(req).await {
                Ok(_) => return Ok(()),
                Err(status) if status.code() == tonic::Code::Unimplemented => {
                    if !self
                        .update_relay_unimplemented
                        .swap(true, Ordering::Relaxed)
                    {
                        tracing::warn!(
                            "media node does not implement UpdateRelay; T.38 on it fails \
                             closed and audio updates use the legacy RPCs until it is upgraded"
                        );
                    }
                }
                Err(status) => return Err(map_status(status)),
            }
        }
        if kind.is_some() {
            return Err(MediaPipelineError::Rpc(
                "media node does not implement UpdateRelay; media kind change refused".into(),
            ));
        }
        let mut result = Ok(());
        for (is_a_leg, address) in remotes.into_iter().flatten() {
            if let Err(e) = self.set_remote_address(call_id, is_a_leg, address).await {
                result = Err(e);
            }
        }
        if start_relay {
            self.start_relay(call_id).await?;
        }
        result
    }

    /// Fetches the SBC's current DTLS fingerprint (RFC 8122 form) from the media
    /// process. Not a [`MediaController`] method: signaling calls this to stamp
    /// SDP `a=fingerprint`. Callers should cache the result and refresh it when
    /// the control connection re-establishes (the cert is otherwise stable).
    ///
    /// # Errors
    /// Returns a mapped [`MediaPipelineError`] on RPC failure.
    pub async fn fetch_dtls_fingerprint(&self) -> Result<String, MediaPipelineError> {
        let mut client = self.client.clone();
        let resp = client
            .get_dtls_fingerprint(())
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(resp.fingerprint)
    }

    /// Opens the media-event stream (media process → signaling). The caller
    /// drains it and tears down calls named by a [`pb::MediaFailure`]. Replaces
    /// the in-process `media_failure_tx` mpsc.
    ///
    /// # Errors
    /// Returns a mapped [`MediaPipelineError`] if the stream cannot be opened.
    pub async fn watch_media_events(
        &self,
    ) -> Result<tonic::Streaming<pb::MediaEvent>, MediaPipelineError> {
        let mut client = self.client.clone();
        let stream = client
            .watch_media_events(())
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(stream)
    }
}

/// Maps a gRPC [`tonic::Status`] back to a [`MediaPipelineError`].
///
/// Best-effort by status code — the wire loses the exact source variant, but
/// [`tonic::Status::message`] (the server's original error `Display`) is
/// preserved verbatim in the message-carrying variants, so logs stay faithful.
/// The canonical forward mapping (error → status) lives on the server side
/// (Phase 2c). Codes with no closer variant fall to [`MediaPipelineError::Rpc`].
fn map_status(status: tonic::Status) -> MediaPipelineError {
    use tonic::Code;
    let msg = status.message().to_string();
    match status.code() {
        Code::NotFound => MediaPipelineError::SessionNotFound,
        Code::ResourceExhausted => MediaPipelineError::PortExhausted,
        Code::FailedPrecondition => MediaPipelineError::DtlsHandshakeFailed(msg),
        Code::InvalidArgument => MediaPipelineError::CodecNegotiationFailed,
        _ => MediaPipelineError::Rpc(msg),
    }
}

/// `Option<MediaMode>` → proto enum discriminant (`None` = `UNSPECIFIED`).
const fn to_proto_mode(mode: Option<MediaMode>) -> i32 {
    let m = match mode {
        None => pb::MediaMode::Unspecified,
        Some(MediaMode::Relay) => pb::MediaMode::Relay,
        Some(MediaMode::PassThrough) => pb::MediaMode::PassThrough,
        Some(MediaMode::EarlyRelay) => pb::MediaMode::EarlyRelay,
    };
    m as i32
}

/// [`MediaKind`] → proto `MediaKind` discriminant.
pub(crate) const fn to_proto_kind(kind: MediaKind) -> i32 {
    match kind {
        MediaKind::Audio => pb::MediaKind::Audio as i32,
        MediaKind::Image => pb::MediaKind::Image as i32,
    }
}

/// [`Role`] → proto `DtlsRole` discriminant.
const fn to_proto_role(role: Role) -> i32 {
    match role {
        Role::Server => pb::DtlsRole::Server as i32,
        Role::Client => pb::DtlsRole::Client as i32,
    }
}

fn to_proto_leg(leg: LegDtlsParams) -> pb::LegDtlsParams {
    pb::LegDtlsParams {
        peer_fingerprint: leg.peer_fingerprint,
        role: to_proto_role(leg.role),
    }
}

/// Narrows a proto `u32` port to `u16`, surfacing an out-of-range value as an
/// RPC error rather than silently truncating.
fn port_from_u32(value: u32, what: &str) -> Result<u16, MediaPipelineError> {
    u16::try_from(value)
        .map_err(|_| MediaPipelineError::Rpc(format!("{what} out of u16 range: {value}")))
}

#[async_trait::async_trait]
impl MediaController for GrpcMediaController {
    async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
        a_leg_media_ip: Option<IpAddr>,
        b_leg_media_ip: Option<IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        let mut client = self.client.clone();
        let req = pb::CreateSessionRequest {
            call_id: call_id.to_string(),
            mode: to_proto_mode(mode),
            a_leg_media_ip: a_leg_media_ip.map(|ip| ip.to_string()),
            b_leg_media_ip: b_leg_media_ip.map(|ip| ip.to_string()),
        };
        let resp = client
            .create_session(req)
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(AllocatedPorts {
            a_leg_rtp_port: port_from_u32(resp.a_leg_rtp_port, "a_leg_rtp_port")?,
            b_leg_rtp_port: port_from_u32(resp.b_leg_rtp_port, "b_leg_rtp_port")?,
            media_ip: resp
                .media_ip
                .as_deref()
                .map(str::parse::<IpAddr>)
                .transpose()
                .map_err(|e| {
                    MediaPipelineError::Rpc(format!("invalid media_ip from media node: {e}"))
                })?,
            dtls_fingerprint: resp.dtls_fingerprint,
        })
    }

    async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        let mut client = self.client.clone();
        let req = pb::SetRemoteAddressRequest {
            call_id: call_id.to_string(),
            is_a_leg,
            address: address.as_std().to_string(),
        };
        client.set_remote_address(req).await.map_err(map_status)?;
        Ok(())
    }

    /// POA&M-294: tells the media node what the anchored stream carries.
    /// Fails closed: an UNIMPLEMENTED answer (node older than this daemon)
    /// is an error, so a T.38 switch is refused (`RelayUpdateFailed`) rather
    /// than relayed with UDPTL counted as RTP. Logged once per node at warn.
    // NIST 800-53 Rev5: SC-24 (fail closed), AU-2 (warn-once log)
    async fn set_media_kind(
        &self,
        call_id: &str,
        kind: MediaKind,
    ) -> Result<(), MediaPipelineError> {
        let mut client = self.client.clone();
        let req = pb::SetMediaKindRequest {
            call_id: call_id.to_string(),
            kind: to_proto_kind(kind),
        };
        match client.set_media_kind(req).await {
            Ok(_) => Ok(()),
            Err(status) => {
                if status.code() == tonic::Code::Unimplemented
                    && !self.kind_unimplemented_logged.swap(true, Ordering::Relaxed)
                {
                    tracing::warn!(
                        "media node does not implement SetMediaKind; T.38 switchovers on it \
                         fail closed until it is upgraded"
                    );
                }
                Err(map_status(status))
            }
        }
    }

    /// Remote relay update as one `UpdateRelay` RPC (no relay start), so the
    /// node applies the kind and both remotes under one session lock.
    async fn update_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        self.send_update_relay(call_id, remotes, kind, false).await
    }

    /// One `UpdateRelay` RPC with `start_relay = true`: PERF-001 / SEC-1 from
    /// the #200 gate. Replaces the SetMediaKind + SetRemoteAddress + StartRelay
    /// sequence, during which the node could latch a half-applied state.
    async fn update_and_start_relay(
        &self,
        call_id: &str,
        remotes: [Option<(bool, SbcSocketAddr)>; 2],
        kind: Option<MediaKind>,
    ) -> Result<(), MediaPipelineError> {
        self.send_update_relay(call_id, remotes, kind, true).await
    }

    async fn start_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut client = self.client.clone();
        client
            .start_relay(pb::CallRef {
                call_id: call_id.to_string(),
            })
            .await
            .map_err(map_status)?;
        Ok(())
    }

    async fn start_relay_terminate(
        &self,
        call_id: &str,
        a_leg: LegDtlsParams,
        b_leg: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        let mut client = self.client.clone();
        let req = pb::StartRelayTerminateRequest {
            call_id: call_id.to_string(),
            a_leg: Some(to_proto_leg(a_leg)),
            b_leg: Some(to_proto_leg(b_leg)),
        };
        client
            .start_relay_terminate(req)
            .await
            .map_err(map_status)?;
        Ok(())
    }

    async fn stop_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut client = self.client.clone();
        client
            .stop_relay(pb::CallRef {
                call_id: call_id.to_string(),
            })
            .await
            .map_err(map_status)?;
        Ok(())
    }

    async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut client = self.client.clone();
        client
            .remove_session(pb::CallRef {
                call_id: call_id.to_string(),
            })
            .await
            .map_err(map_status)?;
        Ok(())
    }

    async fn allocate_ports(&self) -> Result<(u16, u16), MediaPipelineError> {
        let mut client = self.client.clone();
        let resp = client
            .allocate_ports(())
            .await
            .map_err(map_status)?
            .into_inner();
        Ok((
            port_from_u32(resp.rtp_port, "rtp_port")?,
            port_from_u32(resp.rtcp_port, "rtcp_port")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbc_grpc_api::sbc::media_controller_service_server::{
        MediaControllerService, MediaControllerServiceServer,
    };
    use tonic::{Request, Response, Status};

    /// Fake media server. Canned responses per method; a few `call_id` sentinels
    /// drive the error-mapping paths, and `start_relay_terminate` asserts the
    /// legs round-tripped so the role/fingerprint conversion is exercised.
    struct FakeServer;

    #[tonic::async_trait]
    impl MediaControllerService for FakeServer {
        async fn create_session(
            &self,
            req: Request<pb::CreateSessionRequest>,
        ) -> Result<Response<pb::AllocatedPorts>, Status> {
            let r = req.into_inner();
            match r.call_id.as_str() {
                "missing" => Err(Status::not_found("no such session")),
                "exhausted" => Err(Status::resource_exhausted("ports gone")),
                _ => Ok(Response::new(pb::AllocatedPorts {
                    a_leg_rtp_port: 40000,
                    b_leg_rtp_port: 40002,
                    ..Default::default()
                })),
            }
        }

        async fn set_remote_address(
            &self,
            req: Request<pb::SetRemoteAddressRequest>,
        ) -> Result<Response<()>, Status> {
            let r = req.into_inner();
            // The client is expected to send a parseable "ip:port".
            if r.address.parse::<std::net::SocketAddr>().is_err() {
                return Err(Status::invalid_argument(format!(
                    "bad address {}",
                    r.address
                )));
            }
            Ok(Response::new(()))
        }

        async fn set_media_kind(
            &self,
            req: Request<pb::SetMediaKindRequest>,
        ) -> Result<Response<()>, Status> {
            let r = req.into_inner();
            // "old" models a media node that predates SetMediaKind.
            if r.call_id == "old" {
                return Err(Status::unimplemented("SetMediaKind"));
            }
            if r.kind != pb::MediaKind::Image as i32 && r.kind != pb::MediaKind::Audio as i32 {
                return Err(Status::invalid_argument("bad kind"));
            }
            Ok(Response::new(()))
        }

        async fn start_relay(&self, _req: Request<pb::CallRef>) -> Result<Response<()>, Status> {
            Ok(Response::new(()))
        }

        async fn start_relay_terminate(
            &self,
            req: Request<pb::StartRelayTerminateRequest>,
        ) -> Result<Response<()>, Status> {
            let r = req.into_inner();
            let a = r
                .a_leg
                .ok_or_else(|| Status::invalid_argument("missing a_leg"))?;
            let b = r
                .b_leg
                .ok_or_else(|| Status::invalid_argument("missing b_leg"))?;
            // Roles must survive the Role -> proto conversion.
            if a.role != pb::DtlsRole::Client as i32 {
                return Err(Status::failed_precondition(format!(
                    "a_leg role {} != Client",
                    a.role
                )));
            }
            if b.role != pb::DtlsRole::Server as i32 {
                return Err(Status::failed_precondition(format!(
                    "b_leg role {} != Server",
                    b.role
                )));
            }
            if a.peer_fingerprint != "sha-384 AA" {
                return Err(Status::failed_precondition("a_leg fingerprint lost"));
            }
            Ok(Response::new(()))
        }

        async fn stop_relay(&self, _req: Request<pb::CallRef>) -> Result<Response<()>, Status> {
            Ok(Response::new(()))
        }

        async fn remove_session(&self, _req: Request<pb::CallRef>) -> Result<Response<()>, Status> {
            Ok(Response::new(()))
        }

        async fn allocate_ports(
            &self,
            _req: Request<()>,
        ) -> Result<Response<pb::PortPair>, Status> {
            Ok(Response::new(pb::PortPair {
                rtp_port: 41000,
                rtcp_port: 41001,
            }))
        }

        async fn update_relay(
            &self,
            req: Request<pb::UpdateRelayRequest>,
        ) -> Result<Response<()>, Status> {
            let r = req.into_inner();
            // "old" models a media node that predates UpdateRelay.
            if r.call_id == "old" {
                return Err(Status::unimplemented("UpdateRelay"));
            }
            if r.remotes.len() > 2
                || r.remotes
                    .iter()
                    .any(|l| l.address.parse::<std::net::SocketAddr>().is_err())
            {
                return Err(Status::invalid_argument("bad remotes"));
            }
            // "nostart" models a start failure after a committed update.
            if r.call_id == "nostart" && r.start_relay {
                return Err(Status::internal("start failed"));
            }
            Ok(Response::new(()))
        }

        async fn get_dtls_fingerprint(
            &self,
            _req: Request<()>,
        ) -> Result<Response<pb::DtlsFingerprint>, Status> {
            Ok(Response::new(pb::DtlsFingerprint {
                fingerprint: "sha-384 AA:BB:CC".to_string(),
            }))
        }

        type WatchMediaEventsStream = std::pin::Pin<
            Box<dyn tokio_stream::Stream<Item = Result<pb::MediaEvent, Status>> + Send>,
        >;

        async fn watch_media_events(
            &self,
            _req: Request<()>,
        ) -> Result<Response<Self::WatchMediaEventsStream>, Status> {
            let event = pb::MediaEvent {
                event: Some(pb::media_event::Event::Failure(pb::MediaFailure {
                    call_id: "call-1".to_string(),
                })),
            };
            let stream = tokio_stream::iter(vec![Ok(event)]);
            Ok(Response::new(Box::pin(stream)))
        }
    }

    /// Binds the fake server on an ephemeral loopback port and returns its URL.
    async fn spawn_fake() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(MediaControllerServiceServer::new(FakeServer))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    async fn connect() -> GrpcMediaController {
        GrpcMediaController::connect(spawn_fake().await)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn unresponsive_node_fails_within_deadline() {
        // A node that accepts TCP but never answers (hung, or its socket left
        // half-open) must surface as an Rpc error, not hang the call setup.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let result = tokio::time::timeout(
            CONNECT_TIMEOUT + REQUEST_TIMEOUT + Duration::from_secs(2),
            async {
                let mc = GrpcMediaController::connect(url).await?;
                mc.create_session_with_zones("hang", Some(MediaMode::Relay), None, None)
                    .await
            },
        )
        .await
        .expect("bounded by the connect/request deadlines");
        assert!(
            matches!(result, Err(MediaPipelineError::Rpc(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn set_media_kind_sends_valid_enum() -> Result<(), Box<dyn std::error::Error>> {
        let mc = connect().await;
        mc.set_media_kind("c", MediaKind::Image).await?;
        mc.set_media_kind("c", MediaKind::Audio).await?;
        assert_eq!(to_proto_kind(MediaKind::Audio), pb::MediaKind::Audio as i32);
        assert_eq!(to_proto_kind(MediaKind::Image), pb::MediaKind::Image as i32);
        Ok(())
    }

    /// Q2 (fail closed): an old media node answers UNIMPLEMENTED; the switch
    /// errors (the daemon reports RelayUpdateFailed) instead of succeeding.
    #[tokio::test]
    async fn set_media_kind_unimplemented_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mc = connect().await;
        let err = mc
            .set_media_kind("old", MediaKind::Image)
            .await
            .err()
            .ok_or("expected an error")?;
        assert!(matches!(err, MediaPipelineError::Rpc(_)), "{err:?}");
        let addr = SbcSocketAddr::new("192.0.2.1".parse()?, 5000);
        let res = mc
            .update_relay("old", [Some((true, addr)), None], Some(MediaKind::Image))
            .await;
        assert!(res.is_err());
        // A pure address update does not need the new RPC.
        mc.update_relay("old", [Some((true, addr)), None], None)
            .await?;
        Ok(())
    }

    /// QA: the warn-once latch only suppresses logging; every later call to
    /// an UNIMPLEMENTED node still fails closed.
    #[tokio::test]
    async fn set_media_kind_unimplemented_fails_closed_every_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let mc = connect().await;
        for _ in 0..3 {
            assert!(mc.set_media_kind("old", MediaKind::Image).await.is_err());
            assert!(mc.set_media_kind("old", MediaKind::Audio).await.is_err());
        }
        // A clone shares the node and keeps failing closed too.
        let mc2 = mc.clone();
        assert!(mc2.set_media_kind("old", MediaKind::Image).await.is_err());
        // Other calls on the same node are unaffected.
        mc2.set_media_kind("new", MediaKind::Image).await?;
        Ok(())
    }

    #[tokio::test]
    async fn update_relay_unimplemented_with_kind_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mc = connect().await;
        let addr = SbcSocketAddr::new("192.0.2.1".parse()?, 5000);
        // Every call, before and after the UNIMPLEMENTED answer is cached.
        for _ in 0..3 {
            assert!(
                mc.update_and_start_relay(
                    "old",
                    [Some((false, addr)), None],
                    Some(MediaKind::Image)
                )
                .await
                .is_err()
            );
            assert!(
                mc.update_relay("old", [None, None], Some(MediaKind::Audio))
                    .await
                    .is_err()
            );
        }
        assert!(mc.update_relay_unimplemented.load(Ordering::Relaxed));
        Ok(())
    }

    #[tokio::test]
    async fn update_relay_unimplemented_without_kind_falls_back_to_legacy()
    -> Result<(), Box<dyn std::error::Error>> {
        let mc = connect().await;
        let addr = SbcSocketAddr::new("192.0.2.1".parse()?, 5000);
        mc.update_and_start_relay("old", [Some((true, addr)), Some((false, addr))], None)
            .await?;
        assert!(mc.update_relay_unimplemented.load(Ordering::Relaxed));
        mc.update_relay("old", [Some((true, addr)), None], None)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn update_and_start_relay_start_failure_is_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let mc = connect().await;
        let addr = SbcSocketAddr::new("192.0.2.1".parse()?, 5000);
        mc.update_relay(
            "nostart",
            [Some((true, addr)), None],
            Some(MediaKind::Image),
        )
        .await?;
        assert!(
            mc.update_and_start_relay(
                "nostart",
                [Some((true, addr)), None],
                Some(MediaKind::Image)
            )
            .await
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_session_maps_ports() {
        let mc = connect().await;
        let ports = mc
            .create_session_with_zones("ok", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();
        assert_eq!(ports.a_leg_rtp_port, 40000);
        assert_eq!(ports.b_leg_rtp_port, 40002);
    }

    #[tokio::test]
    async fn not_found_maps_to_session_not_found() {
        let mc = connect().await;
        let err = mc
            .create_session_with_zones("missing", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, MediaPipelineError::SessionNotFound));
    }

    #[tokio::test]
    async fn resource_exhausted_maps_to_port_exhausted() {
        let mc = connect().await;
        let err = mc
            .create_session_with_zones("exhausted", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, MediaPipelineError::PortExhausted));
    }

    #[tokio::test]
    async fn allocate_ports_roundtrip() {
        let mc = connect().await;
        assert_eq!(mc.allocate_ports().await.unwrap(), (41000, 41001));
    }

    #[tokio::test]
    async fn fetch_fingerprint_roundtrip() {
        let mc = connect().await;
        assert_eq!(
            mc.fetch_dtls_fingerprint().await.unwrap(),
            "sha-384 AA:BB:CC"
        );
    }

    #[tokio::test]
    async fn set_remote_address_sends_parseable_ipport() {
        let mc = connect().await;
        let addr = SbcSocketAddr::new("1.2.3.4".parse().unwrap(), 5000);
        // Server returns InvalidArgument if the "ip:port" it received won't parse.
        mc.set_remote_address("c", true, addr).await.unwrap();
    }

    #[tokio::test]
    async fn start_relay_terminate_preserves_role_and_fingerprint() {
        let mc = connect().await;
        let a = LegDtlsParams {
            peer_fingerprint: "sha-384 AA".to_string(),
            role: Role::Client,
        };
        let b = LegDtlsParams {
            peer_fingerprint: "sha-384 BB".to_string(),
            role: Role::Server,
        };
        // Server asserts a=Client, b=Server, a_fingerprint="sha-384 AA".
        mc.start_relay_terminate("c", a, b).await.unwrap();
    }

    #[tokio::test]
    async fn watch_media_events_yields_failure() {
        let mc = connect().await;
        let mut stream = mc.watch_media_events().await.unwrap();
        let msg = stream.message().await.unwrap().unwrap();
        match msg.event {
            Some(pb::media_event::Event::Failure(f)) => assert_eq!(f.call_id, "call-1"),
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn map_status_unknown_falls_to_rpc() {
        let err = map_status(Status::internal("boom"));
        assert!(matches!(err, MediaPipelineError::Rpc(m) if m == "boom"));
    }

    #[test]
    fn map_status_covers_known_codes() {
        assert!(matches!(
            map_status(Status::failed_precondition("x")),
            MediaPipelineError::DtlsHandshakeFailed(_)
        ));
        assert!(matches!(
            map_status(Status::invalid_argument("x")),
            MediaPipelineError::CodecNegotiationFailed
        ));
    }
}
