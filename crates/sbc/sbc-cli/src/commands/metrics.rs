//! Metrics command implementation.
//!
//! Fetches the daemon's real Prometheus metrics from
//! `GET /api/v1/system/metrics`; nothing is generated locally.

use super::CommandResult;
use crate::api::ApiClient;
use crate::args::{Args, OutputFormat};
use crate::output;
use serde_json::json;

/// Runs the metrics command.
///
/// # Errors
///
/// Returns a [`super::CommandError`] when the daemon cannot be reached or
/// authentication fails.
pub fn run(args: &Args) -> CommandResult {
    let client = ApiClient::from_args(args)?;
    let resp = client.get("/api/v1/system/metrics")?;

    match args.format {
        // The endpoint returns Prometheus text exposition format; wrap it
        // so --json still emits exactly one JSON document.
        OutputFormat::Json => output::print_json(&json!({ "metrics": resp.body })),
        OutputFormat::Text | OutputFormat::Table => {
            print!("{}", resp.body);
            if !resp.body.ends_with('\n') {
                println!();
            }
        }
    }
    Ok(())
}
