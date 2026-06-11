//! `sbc-cli trunk` subcommand — trunk health and registration via daemon gRPC.

#[cfg(feature = "grpc")]
use sbc_grpc_api::sbc::trunk_health_service_client::TrunkHealthServiceClient;
#[cfg(feature = "grpc")]
use sbc_grpc_api::sbc::{ListTrunkHealthRequest, ListTrunkRegistrationsRequest};

use crate::args::{Args, TrunkCommand};
use crate::commands::{CommandError, CommandResult};

pub fn run(args: &Args, cmd: TrunkCommand) -> CommandResult {
    #[cfg(feature = "grpc")]
    {
        run_grpc(args, cmd)
    }
    #[cfg(not(feature = "grpc"))]
    {
        let _ = (args, cmd);
        Err(CommandError::new(
            "trunk subcommand requires the `grpc` feature; \
             rebuild with: cargo build --features grpc",
        ))
    }
}

#[cfg(feature = "grpc")]
fn run_grpc(args: &Args, cmd: TrunkCommand) -> CommandResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CommandError::new(format!("tokio init failed: {e}")))?
        .block_on(async { run_async(args, cmd).await })
}

#[cfg(feature = "grpc")]
async fn run_async(args: &Args, cmd: TrunkCommand) -> CommandResult {
    let mut client = TrunkHealthServiceClient::connect(args.grpc_url.clone())
        .await
        .map_err(|e| CommandError::new(format!("cannot connect to {}: {e}", args.grpc_url)))?;

    match cmd {
        TrunkCommand::List => {
            let resp = client
                .list_trunk_health(ListTrunkHealthRequest {})
                .await
                .map_err(|e| CommandError::new(format!("ListTrunkHealth: {e}")))?
                .into_inner();

            print_staleness_indicator(resp.trunk_services_external, resp.snapshot_age_secs);

            if resp.trunks.is_empty() {
                println!("No trunks configured.");
                return Ok(());
            }

            println!(
                "{:<30}  {:<10}  {:>8}  {:>8}  {:>7}  {:>7}  {:>9}",
                "TRUNK", "STATUS", "LAST_MS", "UPTIME%", "OK_RUN", "FAIL_RUN", "TOTAL_OK"
            );
            println!("{}", "-".repeat(90));
            for t in &resp.trunks {
                let status = if t.reachable { "up" } else { "down" };
                println!(
                    "{:<30}  {:<10}  {:>8}  {:>8.1}  {:>7}  {:>7}  {:>9}",
                    t.trunk_id,
                    status,
                    t.last_response_ms,
                    t.uptime_pct,
                    t.consecutive_success,
                    t.consecutive_failures,
                    t.total_success,
                );
            }
        }

        TrunkCommand::Registrations => {
            let resp = client
                .list_trunk_registrations(ListTrunkRegistrationsRequest {})
                .await
                .map_err(|e| CommandError::new(format!("ListTrunkRegistrations: {e}")))?
                .into_inner();

            print_staleness_indicator(resp.trunk_services_external, resp.snapshot_age_secs);

            if resp.trunks.is_empty() {
                println!("No trunks configured.");
                return Ok(());
            }

            println!(
                "{:<30}  {:<12}  {:<14}  {:<20}  {:>8}  {:>8}",
                "TRUNK", "STATE", "REGISTERED", "REGISTRAR", "ATTEMPTS", "OK"
            );
            println!("{}", "-".repeat(100));
            for t in &resp.trunks {
                let reg = if t.registered { "yes" } else { "no" };
                println!(
                    "{:<30}  {:<12}  {:<14}  {:<20}  {:>8}  {:>8}",
                    t.trunk_id, t.state, reg, t.registrar, t.attempts, t.successes,
                );
                if !t.last_error.is_empty() {
                    println!("  last error: {}", t.last_error);
                }
            }
        }
    }

    Ok(())
}

/// Prints a staleness banner when trunk services run in an external pod.
#[cfg(feature = "grpc")]
fn print_staleness_indicator(external: bool, age_secs: u32) {
    if !external {
        return;
    }
    if age_secs == 0 {
        eprintln!(
            "WARNING  No snapshot received yet from sbc-trunk-agent \
             (agent may not be running)"
        );
    } else if age_secs <= 30 {
        eprintln!("OK       Snapshot from sbc-trunk-agent {age_secs}s ago");
    } else if age_secs <= 120 {
        eprintln!(
            "WARNING  Snapshot from sbc-trunk-agent {age_secs}s ago \
             (agent may be slow or backlogged)"
        );
    } else {
        eprintln!(
            "STALE    Snapshot from sbc-trunk-agent {age_secs}s ago \
             (agent may be down — data unreliable)"
        );
    }
}
