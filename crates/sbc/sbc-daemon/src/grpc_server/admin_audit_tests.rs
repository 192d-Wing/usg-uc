//! QA: destructive admin RPCs on the daemon gRPC API emit a
//! `ConfigurationChange` audit record naming the authenticated caller, the
//! RPC, the (sanitized) target and the outcome.
//!
//! Exercised through the service implementations, so the tests do not
//! depend on how the audit helper is factored.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use sbc_grpc_api::sbc::call_service_server::CallService;
use sbc_grpc_api::sbc::registration_service_server::RegistrationService;
use sbc_grpc_api::sbc::sbc_sync_service_server::SbcSyncService;
use sbc_grpc_api::sbc::system_service_server::SystemService;
use sbc_grpc_api::sbc::trunk_health_service_server::TrunkHealthService;
use sbc_grpc_api::sbc::trunk_sync_service_server::TrunkSyncService;
use sbc_grpc_api::sbc::{
    DeleteRegistrationRequest, RegisterTrunkRequest, ReloadTlsRequest, RemoveRoutePatternRequest,
    RemoveTrunkGroupRequest, ShutdownRequest, TerminateCallRequest,
};
use tonic::Request;
use uc_audit::event::{ConfigChangeType, ConfigurationChange};
use uc_metrics::SbcMetrics;

use super::{
    CallServiceImpl, PeerPrincipal, RegistrationServiceImpl, SbcSyncServiceImpl, SystemServiceImpl,
    TrunkHealthServiceImpl, TrunkSyncServiceImpl,
};
use crate::api_server::AppState;
use crate::server::ServerStats;

const CERT: &str = "cert:rel-sbc-api";

fn state() -> Arc<AppState> {
    Arc::new(AppState::new(
        SbcMetrics::standard(),
        Arc::new(ServerStats::default()),
    ))
}

/// A state with a live `SbcRouter`, so removals are applied (`outcome=ok`).
fn state_with_router() -> Arc<AppState> {
    let mut state = AppState::new(SbcMetrics::standard(), Arc::new(ServerStats::default()));
    state.sbc_router = Some(Arc::new(tokio::sync::RwLock::new(
        uc_routing::SbcRouter::new(),
    )));
    Arc::new(state)
}

fn with_cert<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.extensions_mut().insert(PeerPrincipal(CERT.into()));
    req
}

fn config_changes(capture: &uc_audit::capture::CaptureGuard) -> Vec<ConfigurationChange> {
    capture
        .events()
        .into_iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::ConfigurationChange(c) => Some(c),
            _ => None,
        })
        .collect()
}

/// Exactly one admin-RPC record whose description names `rpc`.
fn one_record(capture: &uc_audit::capture::CaptureGuard, rpc: &str) -> ConfigurationChange {
    let all = config_changes(capture);
    let hits: Vec<_> = all
        .iter()
        .filter(|c| c.description.contains(rpc))
        .cloned()
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected one audit record for {rpc}, got {all:?}"
    );
    hits.into_iter().next().unwrap()
}

#[tokio::test]
async fn qa_remove_route_pattern_audited_with_cert_principal() {
    let svc = SbcSyncServiceImpl::new(state_with_router());
    let capture = uc_audit::capture::start();
    svc.remove_route_pattern(with_cert(RemoveRoutePatternRequest {
        pattern_id: "rp-42".into(),
    }))
    .await
    .expect("remove succeeds without a router");
    let c = one_record(&capture, "SbcSyncService/RemoveRoutePattern");
    assert!(c.admin.starts_with("cert:"), "{c:?}");
    assert!(c.admin.contains("rel-sbc-api"), "{c:?}");
    assert_eq!(c.change_type, ConfigChangeType::Modified);
    assert!(c.description.contains("target=rp-42"), "{c:?}");
    assert!(c.description.contains("outcome=ok"), "{c:?}");
}

#[tokio::test]
async fn qa_remove_trunk_group_audited_with_cert_principal() {
    let svc = TrunkSyncServiceImpl::new(state_with_router());
    let capture = uc_audit::capture::start();
    svc.remove_trunk_group(with_cert(RemoveTrunkGroupRequest {
        group_id: "tg-carrier-a".into(),
    }))
    .await
    .expect("remove succeeds without a router");
    let c = one_record(&capture, "TrunkSyncService/RemoveTrunkGroup");
    assert!(c.admin.starts_with("cert:"), "{c:?}");
    assert!(c.description.contains("target=tg-carrier-a"), "{c:?}");
    assert!(c.description.contains("outcome=ok"), "{c:?}");
}

#[tokio::test]
async fn qa_delete_registration_failure_audited() {
    // No SIP stack in this state: the RPC fails, and the failure is audited.
    let svc = RegistrationServiceImpl::new(state());
    let capture = uc_audit::capture::start();
    let err = svc
        .delete_registration(with_cert(DeleteRegistrationRequest {
            aor: "sip:1001@example.com".into(),
            contact_uri: String::new(),
            reason: "qa".into(),
        }))
        .await
        .expect_err("no SIP stack");
    let c = one_record(&capture, "RegistrationService/DeleteRegistration");
    assert!(c.admin.starts_with("cert:"), "{c:?}");
    assert!(c.description.contains("sip:1001@example.com"), "{c:?}");
    assert!(!c.description.contains("outcome=ok"), "{c:?}");
    let code = format!("{:?}", err.code());
    assert!(
        c.description.to_lowercase().contains(&code.to_lowercase()),
        "outcome should carry the gRPC code {code}: {c:?}"
    );
}

#[tokio::test]
async fn qa_terminate_call_audited_with_failure_outcome() {
    let svc = CallServiceImpl::new(state());
    let capture = uc_audit::capture::start();
    let _ = svc
        .terminate_call(with_cert(TerminateCallRequest {
            call_id: "call-abc".into(),
            reason: "qa".into(),
            cause_code: 200,
        }))
        .await;
    let c = one_record(&capture, "CallService/TerminateCall");
    assert!(c.admin.starts_with("cert:"), "{c:?}");
    assert!(c.description.contains("target=call-abc"), "{c:?}");
    assert!(c.description.contains("outcome="), "{c:?}");
}

#[tokio::test]
async fn qa_shutdown_rpc_audited() {
    let svc = SystemServiceImpl::new(state());
    let capture = uc_audit::capture::start();
    let _ = svc
        .shutdown(with_cert(ShutdownRequest {
            timeout_secs: 5,
            reason: "qa".into(),
            drain_only: false,
        }))
        .await;
    let c = one_record(&capture, "SystemService/Shutdown");
    assert!(c.admin.starts_with("cert:"), "{c:?}");
    assert!(c.description.contains("outcome="), "{c:?}");
}

#[tokio::test]
async fn qa_admin_audit_unauthenticated_caller_named() {
    // Loopback plaintext listener: no PeerPrincipal; the record still names
    // the caller as unauthenticated.
    let svc = SbcSyncServiceImpl::new(state());
    let capture = uc_audit::capture::start();
    svc.remove_route_pattern(Request::new(RemoveRoutePatternRequest {
        pattern_id: "rp-1".into(),
    }))
    .await
    .unwrap();
    let c = one_record(&capture, "SbcSyncService/RemoveRoutePattern");
    assert!(c.admin.starts_with("unauthenticated@"), "{c:?}");
}

#[tokio::test]
async fn qa_admin_audit_target_sanitized() {
    let svc = SbcSyncServiceImpl::new(state());
    let capture = uc_audit::capture::start();
    let id = format!("rp-x\r\nforged=1\u{0}{}", "z".repeat(4000));
    svc.remove_route_pattern(with_cert(RemoveRoutePatternRequest { pattern_id: id }))
        .await
        .unwrap();
    let c = one_record(&capture, "SbcSyncService/RemoveRoutePattern");
    assert!(
        !c.description.chars().any(char::is_control),
        "control characters must be stripped: {c:?}"
    );
    assert!(c.description.contains("rp-xforged=1"), "{c:?}");
    // The target is capped (256 bytes); the description adds only the RPC
    // name and the outcome.
    assert!(
        c.description.len() < 256 + 128,
        "target must be capped, description is {} bytes",
        c.description.len()
    );
}

/// Without a router or SIP stack nothing is removed: the record says
/// `noop`, never `ok`.
#[tokio::test]
async fn removal_without_backing_router_audited_as_noop() {
    let capture = uc_audit::capture::start();
    SbcSyncServiceImpl::new(state())
        .remove_route_pattern(with_cert(RemoveRoutePatternRequest {
            pattern_id: "rp-7".into(),
        }))
        .await
        .unwrap();
    TrunkSyncServiceImpl::new(state())
        .remove_trunk_group(with_cert(RemoveTrunkGroupRequest {
            group_id: "tg-7".into(),
        }))
        .await
        .unwrap();
    for rpc in [
        "SbcSyncService/RemoveRoutePattern",
        "TrunkSyncService/RemoveTrunkGroup",
    ] {
        let c = one_record(&capture, rpc);
        assert!(c.description.contains("outcome=noop"), "{c:?}");
        assert!(!c.description.contains("outcome=ok"), "{c:?}");
    }
}

#[tokio::test]
async fn register_trunk_audited_with_caller() {
    let svc = TrunkHealthServiceImpl::new(state());
    let capture = uc_audit::capture::start();
    let resp = svc
        .register_trunk(with_cert(RegisterTrunkRequest {
            trunk_id: "trunk-x\r\n".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.success, "unknown trunk");
    let c = one_record(&capture, "TrunkHealthService/RegisterTrunk");
    assert!(c.admin.starts_with("cert:"), "{c:?}");
    assert!(c.description.contains("target=trunk-x"), "{c:?}");
    assert!(c.description.contains("outcome=noop"), "{c:?}");
    assert!(!c.description.chars().any(char::is_control), "{c:?}");
}

#[tokio::test]
async fn reload_tls_records_caller() {
    let svc = SystemServiceImpl::new(state());
    let capture = uc_audit::capture::start();
    let _ = svc.reload_tls(with_cert(ReloadTlsRequest::default())).await;
    let c = one_record(&capture, "SystemService/ReloadTls");
    assert!(c.admin.starts_with("cert:"), "{c:?}");
    // TLS is not configured in this state: nothing was reloaded.
    assert!(c.description.contains("outcome=noop"), "{c:?}");
}
