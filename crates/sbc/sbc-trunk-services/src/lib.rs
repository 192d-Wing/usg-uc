//! Outbound trunk maintenance loops for the USG SBC.
//!
//! Two self-contained subsystems, extracted from `sbc-daemon` so they can
//! run either in-process (single-pod deploys) or inside the dedicated
//! `sbc-trunk-agent` pod (multi-pod deploys, where running them in every
//! daemon replica would double-REGISTER to carriers and double-ping
//! trunks):
//!
//! - [`monitor`] — periodic SIP OPTIONS health probing per trunk.
//! - [`registrar`] — outbound carrier REGISTER with digest auth and
//!   re-registration at 80% of the granted expiry.
//!
//! Both keep their status in `Arc<RwLock<HashMap>>` snapshots that the
//! host process exposes (daemon: gRPC `TrunkHealthService`; agent:
//! pushed to the daemon via gRPC `TrunkStatusPublishService`).

pub mod monitor;
pub mod registrar;
