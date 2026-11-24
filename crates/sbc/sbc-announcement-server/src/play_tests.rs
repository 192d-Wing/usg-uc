//! SR-41 QA: Play request policy, caps and lifetime, in-process on
//! 127.0.0.1 with `SBC_ANN_ALLOW_LOOPBACK_DEST=true` and a UDP receiver.
//!
//! ## NIST 800-53 Rev5: SC-5, SC-7, SI-10

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sbc_grpc_api::sbc::announcement_service_client::AnnouncementServiceClient;
use sbc_grpc_api::sbc::announcement_service_server::{
    AnnouncementService, AnnouncementServiceServer,
};
use sbc_grpc_api::sbc::play_announcement_event::Event;
use sbc_grpc_api::sbc::{AnnouncementKind, PlayAnnouncementEvent, PlayAnnouncementRequest};
use tokio_stream::StreamExt;
use tonic::{Code, Request, Status};

use crate::AnnouncementServiceImpl;
use crate::config::Config;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Loopback lab configuration with `extra` overrides.
fn config(extra: &[(&str, &str)]) -> Result<Config, String> {
    let mut m: HashMap<String, String> = [
        ("SBC_ANN_GRPC_LISTEN", "127.0.0.1:0"),
        ("SBC_ANN_ADVERTISED_IP", "127.0.0.1"),
        ("SBC_ANN_BIND_IP", "127.0.0.1"),
        ("SBC_ANN_ALLOW_LOOPBACK_DEST", "true"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        m.insert((*k).to_string(), (*v).to_string());
    }
    Config::from_lookup(|k: &str| m.get(k).cloned())
}

fn req(dest: &str, delay_ms: u32) -> PlayAnnouncementRequest {
    PlayAnnouncementRequest {
        kind: AnnouncementKind::Silence as i32,
        rtp_destination: dest.to_string(),
        ssrc: 0x5eed,
        initial_delay_ms: delay_ms,
        call_id: "qa-call".to_string(),
    }
}

/// A UDP sink that counts the datagrams it receives.
struct Sink {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Sink {
    async fn new() -> std::io::Result<Self> {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = sock.local_addr()?;
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while sock.recv_from(&mut buf).await.is_ok() {
                c.fetch_add(1, Ordering::Relaxed);
            }
        });
        Ok(Self { addr, count, task })
    }

    fn seen(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a Play and waits for its Bound event; returns the open stream.
async fn bound(
    svc: &AnnouncementServiceImpl,
    r: PlayAnnouncementRequest,
) -> Result<<AnnouncementServiceImpl as AnnouncementService>::PlayStream, Status> {
    let mut stream = svc.play(Request::new(r)).await?.into_inner();
    match stream.next().await {
        Some(Ok(PlayAnnouncementEvent {
            event: Some(Event::Bound(_)),
        })) => Ok(stream),
        other => Err(Status::internal(format!("expected Bound, got {other:?}"))),
    }
}

async fn play_code(svc: &AnnouncementServiceImpl, r: PlayAnnouncementRequest) -> Option<Code> {
    svc.play(Request::new(r)).await.err().map(|s| s.code())
}

/// Polls `f` every 20 ms until it holds or `within` passes.
async fn eventually(within: Duration, f: impl Fn() -> bool) -> bool {
    let end = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < end {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}

#[tokio::test]
async fn qa_play_refuses_unspecified_destination() -> TestResult {
    let svc = AnnouncementServiceImpl::new(config(&[])?);
    for d in [
        "0.0.0.0:40000",
        "[::]:40000",
        "[::ffff:0.0.0.0]:40000",
        "255.255.255.255:40000",
    ] {
        assert_eq!(
            play_code(&svc, req(d, 1)).await,
            Some(Code::InvalidArgument),
            "{d}"
        );
    }
    // Port 0 is refused too.
    assert_eq!(
        play_code(&svc, req("127.0.0.1:0", 1)).await,
        Some(Code::InvalidArgument)
    );
    assert_eq!(svc.limits().active(), 0, "refusals hold no slot");
    Ok(())
}

#[tokio::test]
async fn qa_play_refuses_destination_outside_allow_list() -> TestResult {
    let svc =
        AnnouncementServiceImpl::new(config(&[("SBC_ANN_ALLOWED_DEST_CIDRS", "127.0.0.1/32")])?);
    let st = svc
        .play(Request::new(req("198.18.0.9:40000", 1)))
        .await
        .err()
        .ok_or("outside the allow-list must be refused")?;
    assert_eq!(st.code(), Code::InvalidArgument);
    assert!(
        !st.message().contains("198.18.0.9"),
        "refusal must not echo the destination: {}",
        st.message()
    );
    // Inside the list: accepted.
    let sink = Sink::new().await?;
    let s = bound(&svc, req(&sink.addr.to_string(), 1)).await?;
    drop(s);
    Ok(())
}

#[tokio::test]
async fn qa_play_refuses_initial_delay_over_max() -> TestResult {
    let svc = AnnouncementServiceImpl::new(config(&[])?);
    let sink = Sink::new().await?;
    let d = sink.addr.to_string();
    for delay in [2001, u32::MAX] {
        assert_eq!(
            play_code(&svc, req(&d, delay)).await,
            Some(Code::InvalidArgument),
            "delay {delay}"
        );
    }
    let s = bound(&svc, req(&d, 2000)).await?;
    drop(s);
    Ok(())
}

#[tokio::test]
async fn qa_play_resource_exhausted_over_global_cap() -> TestResult {
    let svc = AnnouncementServiceImpl::new(config(&[
        ("SBC_ANN_MAX_PLAYS", "2"),
        ("SBC_ANN_MAX_PLAYS_PER_DEST", "2"),
    ])?);
    let a = Sink::new().await?;
    let b = Sink::new().await?;
    let c = Sink::new().await?;
    // Two plays held in their initial delay.
    let s1 = bound(&svc, req(&a.addr.to_string(), 2000)).await?;
    let s2 = bound(&svc, req(&b.addr.to_string(), 2000)).await?;
    assert_eq!(svc.limits().active(), 2);
    assert_eq!(
        play_code(&svc, req(&c.addr.to_string(), 1)).await,
        Some(Code::ResourceExhausted)
    );
    // Over-cap refusal is immediate and binds nothing.
    drop((s1, s2));
    let limits = svc.limits().clone();
    assert!(
        eventually(Duration::from_millis(500), || limits.active() == 0).await,
        "slots released after the streams dropped"
    );
    let s3 = bound(&svc, req(&c.addr.to_string(), 1)).await?;
    drop(s3);
    Ok(())
}

#[tokio::test]
async fn qa_play_resource_exhausted_over_per_dest_cap() -> TestResult {
    let svc = AnnouncementServiceImpl::new(config(&[
        ("SBC_ANN_MAX_PLAYS", "8"),
        ("SBC_ANN_MAX_PLAYS_PER_DEST", "1"),
    ])?);
    let a = Sink::new().await?;
    let b = Sink::new().await?;
    let s1 = bound(&svc, req(&a.addr.to_string(), 2000)).await?;
    // Same IP, different port: same destination.
    assert_eq!(
        play_code(&svc, req(&b.addr.to_string(), 1)).await,
        Some(Code::ResourceExhausted)
    );
    // Another loopback address is a different destination.
    let other = format!("127.0.0.2:{}", b.addr.port());
    let s2 = bound(&svc, req(&other, 2000)).await?;
    drop((s1, s2));
    Ok(())
}

/// Dropping the client stream after Bound stops RTP within a tick and
/// releases the slot (over a real HTTP/2 connection).
#[tokio::test]
async fn qa_play_stops_when_stream_dropped() -> TestResult {
    let svc = AnnouncementServiceImpl::new(config(&[])?);
    let limits = svc.limits().clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let listen = SocketAddr::from(([127, 0, 0, 1], port));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AnnouncementServiceServer::new(svc))
            .serve_with_shutdown(listen, async {
                let _ = stop_rx.await;
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let sink = Sink::new().await?;
    let mut client = AnnouncementServiceClient::connect(format!("http://127.0.0.1:{port}")).await?;
    let mut stream = client
        .play(req(&sink.addr.to_string(), 1))
        .await?
        .into_inner();
    let first = stream.message().await?;
    assert!(
        matches!(
            first,
            Some(PlayAnnouncementEvent {
                event: Some(Event::Bound(_))
            })
        ),
        "{first:?}"
    );
    // Let a few packets flow (Silence is 2 s = 100 packets).
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(stream);
    drop(client);
    assert!(
        eventually(Duration::from_millis(500), || limits.active() == 0).await,
        "slot released after the client dropped the stream"
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    let at_stop = sink.seen();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let later = sink.seen();
    assert_eq!(at_stop, later, "RTP continued after the stream was dropped");
    assert!(later < 100, "whole announcement was sent: {later} packets");

    let _ = stop_tx.send(());
    let _ = srv.await;
    Ok(())
}

#[tokio::test]
async fn qa_play_stops_on_drop_during_initial_delay() -> TestResult {
    let svc = AnnouncementServiceImpl::new(config(&[])?);
    let limits = svc.limits().clone();
    let sink = Sink::new().await?;
    let s = bound(&svc, req(&sink.addr.to_string(), 2000)).await?;
    assert_eq!(limits.active(), 1);
    drop(s);
    assert!(
        eventually(Duration::from_millis(300), || limits.active() == 0).await,
        "slot held through the initial delay after the stream dropped"
    );
    // Past the delay: nothing is ever sent.
    tokio::time::sleep(Duration::from_millis(2300)).await;
    assert_eq!(sink.seen(), 0, "RTP sent after the stream was dropped");
    Ok(())
}

#[tokio::test]
async fn qa_play_deadline_exceeded_after_max_duration() -> TestResult {
    // Silence is 2 s; the bound is 1 s (delay included).
    let svc = AnnouncementServiceImpl::new(config(&[("SBC_ANN_MAX_PLAY_SECS", "1")])?);
    let limits = svc.limits().clone();
    let sink = Sink::new().await?;
    let started = tokio::time::Instant::now();
    let mut s = bound(&svc, req(&sink.addr.to_string(), 1)).await?;
    let end = tokio::time::timeout(Duration::from_secs(3), s.next())
        .await
        .map_err(|_| "stream did not end within 3 s")?;
    match end {
        Some(Err(st)) => assert_eq!(st.code(), Code::DeadlineExceeded, "{st:?}"),
        other => panic!("expected DEADLINE_EXCEEDED, got {other:?}"),
    }
    let took = started.elapsed();
    assert!(took < Duration::from_millis(1800), "ended after {took:?}");
    assert!(
        eventually(Duration::from_millis(300), || limits.active() == 0).await,
        "slot released at the deadline"
    );
    assert!(sink.seen() < 100, "full announcement sent past the bound");
    Ok(())
}
