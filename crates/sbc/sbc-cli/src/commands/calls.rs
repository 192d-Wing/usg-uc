//! Calls command implementation.
//!
//! All call data comes from the daemon's REST API (`GET /api/v1/calls`,
//! `GET /api/v1/system/stats`); nothing is simulated. Operations the
//! daemon does not expose yet (terminate) fail loudly instead of
//! pretending to succeed.

use super::{CommandError, CommandResult};
use crate::api::ApiClient;
use crate::args::{Args, CallsCommand, OutputFormat};
use crate::output;
use serde_json::Value;

/// Runs the calls command.
///
/// # Errors
///
/// Returns a [`CommandError`] when the daemon cannot be reached,
/// authentication fails, the response cannot be parsed, the requested call
/// does not exist, or the operation is not supported by the daemon API.
pub fn run(args: &Args, cmd: CallsCommand) -> CommandResult {
    match cmd {
        CallsCommand::List => list_calls(args),
        CallsCommand::Show { call_id } => show_call(args, &call_id),
        CallsCommand::Terminate { call_id } => terminate_call(&call_id),
        CallsCommand::Stats => show_stats(args),
    }
}

/// Lists active calls reported by the daemon.
fn list_calls(args: &Args) -> CommandResult {
    let client = ApiClient::from_args(args)?;
    let response = client.get("/api/v1/calls")?.json()?;

    match args.format {
        OutputFormat::Json => output::print_json(&response),
        OutputFormat::Text | OutputFormat::Table => render_call_list(&response),
    }
    Ok(())
}

/// Renders the call list as a text table.
fn render_call_list(response: &Value) {
    let calls = response["calls"].as_array().cloned().unwrap_or_default();

    println!("Active Calls");
    println!("============");
    println!();

    if calls.is_empty() {
        println!("No active calls");
        return;
    }

    println!(
        "{:<40} {:<14} {:<30} {:<30} {:>12}",
        "Call ID", "State", "From", "To", "Duration (s)"
    );
    println!("{}", "-".repeat(130));
    for call in &calls {
        println!(
            "{:<40} {:<14} {:<30} {:<30} {:>12}",
            output::scalar_to_string(&call["call_id"]),
            output::scalar_to_string(&call["state"]),
            output::scalar_to_string(&call["from"]),
            output::scalar_to_string(&call["to"]),
            output::scalar_to_string(&call["duration_secs"]),
        );
    }

    println!();
    println!(
        "Total: {} (active: {})",
        output::scalar_to_string(&response["total"]),
        output::scalar_to_string(&response["active"]),
    );
}

/// Shows details for a single call from the daemon's call list.
fn show_call(args: &Args, call_id: &str) -> CommandResult {
    let client = ApiClient::from_args(args)?;
    let response = client.get("/api/v1/calls")?.json()?;

    let call = response["calls"]
        .as_array()
        .and_then(|calls| {
            calls
                .iter()
                .find(|c| c["call_id"].as_str() == Some(call_id))
        })
        .cloned()
        .ok_or_else(|| {
            CommandError::new(format!(
                "call '{call_id}' not found among active calls on {}",
                args.api_url
            ))
        })?;

    match args.format {
        OutputFormat::Json => output::print_json(&call),
        OutputFormat::Text => {
            println!("Call Details: {call_id}");
            println!("=============");
            println!();
            println!(
                "{}",
                output::format_pairs_text(&output::object_to_pairs(&call))
            );
        }
        OutputFormat::Table => {
            println!(
                "{}",
                output::format_pairs_table(&output::object_to_pairs(&call))
            );
        }
    }
    Ok(())
}

/// Rejects call termination: the daemon API has no terminate endpoint yet.
fn terminate_call(call_id: &str) -> CommandResult {
    Err(CommandError::new(format!(
        "'calls terminate' is not supported by the daemon API yet; \
         call '{call_id}' was NOT terminated"
    )))
}

/// Shows call statistics from the daemon's stats endpoint.
fn show_stats(args: &Args) -> CommandResult {
    let client = ApiClient::from_args(args)?;
    let stats = client.get("/api/v1/system/stats")?.json()?;

    match args.format {
        OutputFormat::Json => output::print_json(&stats),
        OutputFormat::Text => {
            println!("Call Statistics ({})", args.api_url);
            println!("===============");
            println!();
            println!(
                "{}",
                output::format_pairs_text(&output::object_to_pairs(&stats))
            );
        }
        OutputFormat::Table => {
            println!(
                "{}",
                output::format_pairs_table(&output::object_to_pairs(&stats))
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminate_is_unsupported() {
        // There is no terminate endpoint on the daemon yet; the command
        // must fail rather than fabricate a success message.
        let result = terminate_call("call-001");
        let err = match result {
            Ok(()) => unreachable!("terminate must not succeed"),
            Err(e) => e,
        };
        assert!(err.message.contains("not supported by the daemon API"));
        assert!(err.message.contains("NOT terminated"));
    }
}
