//! SBC media plane.
//!
//! Extracted from `sbc-daemon` (signaling↔media split, Phase 2d) so the media
//! plane can run in its own `sbc-media` process while `sbc-daemon` keeps the SIP
//! signaling. The crate is a self-contained subgraph — the RTP/SRTP relay, the
//! DTLS-SRTP terminating relay + sidecar client, the SBC's DTLS identity, and
//! (behind the `grpc` feature) the [`MediaController`](media_pipeline::MediaController)
//! gRPC client and server. It has no dependency back on `sbc-daemon`.
//!
//! `sbc-daemon` links this crate for the shared boundary types (the
//! `MediaController` trait, `LegDtlsParams`, `MediaPipelineError`,
//! `DtlsFingerprintSource`, `Role`) and the `GrpcMediaController` client; the
//! `sbc-media` binary links it for `MediaControllerServer` + the concrete
//! `MediaPipeline`.

// Lint posture carried over verbatim from the sbc-daemon binary crate this code
// came from, so the move is behaviour- and diagnostic-neutral.
#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::future_not_send)]
#![allow(clippy::unused_async)]
#![allow(clippy::needless_pass_by_ref_mut)]
#![allow(clippy::unused_self)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss
)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::cast_sign_loss)]

pub mod dtls_identity;
pub mod dtls_relay;
pub mod dtls_sidecar;
pub mod media_pipeline;
pub mod srtp_relay;

#[cfg(feature = "grpc")]
pub mod grpc_media_controller;
#[cfg(feature = "grpc")]
pub mod grpc_media_server;
