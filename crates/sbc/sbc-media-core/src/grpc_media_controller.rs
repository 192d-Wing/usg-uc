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
use crate::media_pipeline::{AllocatedPorts, LegDtlsParams, MediaController, MediaPipelineError};
use sbc_grpc_api::sbc as pb;
use sbc_grpc_api::sbc::media_controller_service_client::MediaControllerServiceClient;
use std::net::IpAddr;
use tonic::transport::Channel;
use uc_media_engine::MediaMode;
use uc_types::address::SbcSocketAddr;

/// A [`MediaController`] backed by a gRPC connection to an out-of-process media
/// plane. Cheap to clone-per-call: the inner tonic client shares one HTTP/2
/// channel, so the `&self` trait methods clone it to obtain the `&mut` each RPC
/// needs without serializing calls.
pub struct GrpcMediaController {
    client: MediaControllerServiceClient<Channel>,
}

impl GrpcMediaController {
    /// Connects to the media process at `url` (e.g. `http://sbc-media:9096`).
    ///
    /// # Errors
    /// Returns [`MediaPipelineError::Rpc`] if the connection cannot be
    /// established.
    pub async fn connect(url: String) -> Result<Self, MediaPipelineError> {
        let client = MediaControllerServiceClient::connect(url.clone())
            .await
            .map_err(|e| MediaPipelineError::Rpc(format!("connect {url} failed: {e}")))?;
        Ok(Self { client })
    }

    /// Wraps an already-connected client (used by tests and by callers that
    /// build the channel themselves, e.g. with custom TLS).
    #[must_use]
    pub const fn new(client: MediaControllerServiceClient<Channel>) -> Self {
        Self { client }
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
                .map(|s| s.parse::<IpAddr>())
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
