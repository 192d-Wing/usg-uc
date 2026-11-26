//! WebSocket control-frame accounting.
//!
//! Supports POA&M-458 (SC-5); no control is enforced yet.
#![cfg(feature = "websocket")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use futures_util::SinkExt;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message;
use uc_transport::Transport;
use uc_transport::websocket::{WebSocketListener, WebSocketListenerOptions};
use uc_types::address::SbcSocketAddr;

// Ping frames read by recv are counted; take_control_frames resets.
#[tokio::test]
async fn ws_control_frames_are_counted() {
    let bind = SbcSocketAddr::from("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap());
    let l = WebSocketListener::bind(&bind, false)
        .await
        .unwrap()
        .with_options(WebSocketListenerOptions {
            require_sip_subprotocol: true,
        });
    let addr = l.bound_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, peer) = l.accept_tcp().await.unwrap();
        l.complete_handshake(tcp, peer).await.unwrap()
    });
    let mut req = format!("ws://{addr}/").into_client_request().unwrap();
    req.headers_mut()
        .insert("sec-websocket-protocol", HeaderValue::from_static("sip"));
    let (mut client, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let server = server.await.unwrap();
    for _ in 0..3 {
        client
            .send(Message::Ping(b"p".to_vec().into()))
            .await
            .unwrap();
    }
    client.send(Message::text("OPTIONS")).await.unwrap();
    let m = tokio::time::timeout(Duration::from_secs(1), server.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&m.data[..], b"OPTIONS");
    assert_eq!(server.take_control_frames(), 3);
    assert_eq!(server.take_control_frames(), 0);
}
