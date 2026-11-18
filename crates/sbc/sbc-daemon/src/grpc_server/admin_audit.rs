//! Audit of destructive admin RPCs on the daemon gRPC API.
//!
//! Each removal, registration delete, call termination, shutdown, TLS
//! reload, trunk registration and (cluster) node drain emits one
//! `ConfigurationChange` record naming the caller (the certificate
//! principal under mTLS, `unauthenticated` on the loopback listener), the
//! RPC, the target and the outcome (`ok`, `noop` when nothing was changed,
//! or the gRPC code). The target comes from the request, so
//! it is stripped of control characters and capped before it is recorded.
//!
//! Refresh notifications (`Sync*`) are not audited here: the writer
//! (sbc-api) audits the change itself.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12 (event logging, content, generation)

use tonic::Status;
use uc_audit::event::{ConfigChangeType, ConfigurationChange};

use crate::signaling_audit::audit_field;

/// What an admin RPC did, as recorded in `outcome=`.
#[derive(Debug, Clone, Copy)]
pub enum AdminOutcome<'a> {
    /// The change was applied (`ok`).
    Applied,
    /// Accepted, but nothing was changed because the backing router or SIP
    /// stack is not configured on this daemon (`noop`).
    NoOp,
    /// The RPC failed; the gRPC code is recorded.
    Failed(&'a Status),
}

impl<'a> AdminOutcome<'a> {
    /// `Applied` when the change reached a backing store, else `NoOp`.
    #[must_use]
    pub const fn applied(applied: bool) -> Self {
        if applied { Self::Applied } else { Self::NoOp }
    }

    /// `Applied` for `Ok`, `Failed` with the status otherwise.
    #[must_use]
    pub const fn from_result(result: Result<(), &'a Status>) -> Self {
        match result {
            Ok(()) => Self::Applied,
            Err(status) => Self::Failed(status),
        }
    }
}

/// Records one admin RPC. `admin` comes from
/// [`super::peer_identity::caller_principal`], taken before the request is
/// consumed; `rpc` is `<Service>/<Rpc>`.
pub fn audit_admin_rpc(admin: String, rpc: &'static str, target: &str, outcome: AdminOutcome<'_>) {
    let outcome = match outcome {
        AdminOutcome::Applied => "ok".to_string(),
        AdminOutcome::NoOp => "noop".to_string(),
        AdminOutcome::Failed(status) => format!("{:?}", status.code()),
    };
    let description = format!(
        "grpc {rpc} target={} outcome={outcome}",
        audit_field(target)
    );
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        ConfigurationChange {
            admin,
            change_type: ConfigChangeType::Modified,
            description,
        },
    ));
}
