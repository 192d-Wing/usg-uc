//! Calls command implementation.

use super::{CommandError, CommandResult};
use crate::args::{Args, CallsCommand};
use crate::output::OutputFormatter;
use std::collections::HashMap;

/// Runs the calls command.
pub fn run(args: &Args, cmd: CallsCommand) -> CommandResult {
    match cmd {
        CallsCommand::List => {
            list_calls(args);
        }
        CallsCommand::Show { call_id } => show_call(args, &call_id)?,
        CallsCommand::Terminate { call_id } => terminate_call(args, &call_id)?,
        CallsCommand::Stats => {
            show_stats(args);
        }
    }
    Ok(())
}

/// Lists active calls.
fn list_calls(_args: &Args) {
    println!("Active Calls");
    println!("============\n");

    // Simulated call list
    let calls = vec![
        (
            "call-001",
            "sip:alice@example.com",
            "sip:bob@example.com",
            "00:05:23",
        ),
        (
            "call-002",
            "sip:charlie@example.com",
            "sip:dave@example.com",
            "00:12:45",
        ),
        (
            "call-003",
            "sip:eve@example.com",
            "sip:frank@example.com",
            "00:01:12",
        ),
    ];

    if calls.is_empty() {
        println!("No active calls");
        return;
    }

    println!(
        "{:<12} {:<30} {:<30} {:>10}",
        "Call ID", "From", "To", "Duration"
    );
    println!("{}", "-".repeat(85));

    for (id, from, to, duration) in calls {
        println!("{id:<12} {from:<30} {to:<30} {duration:>10}");
    }

    println!();
    println!("Total: 3 active calls");
}

/// Shows call details.
fn show_call(args: &Args, call_id: &str) -> CommandResult {
    let formatter = OutputFormatter::new(args.format);

    if call_id.is_empty() {
        return Err(CommandError::new("Call ID required"));
    }

    println!("Call Details: {call_id}");
    println!("======================\n");

    // Simulated call details
    let mut details = HashMap::new();
    details.insert("Call ID".to_string(), call_id.to_string());
    details.insert("State".to_string(), "Confirmed".to_string());
    details.insert("From".to_string(), "sip:alice@example.com".to_string());
    details.insert("To".to_string(), "sip:bob@example.com".to_string());
    details.insert(
        "Start Time".to_string(),
        "2024-01-15 10:30:45 UTC".to_string(),
    );
    details.insert("Duration".to_string(), "00:05:23".to_string());
    details.insert("Codec".to_string(), "Opus".to_string());
    details.insert("SRTP".to_string(), "Enabled (AES-256-GCM)".to_string());

    println!("{}", formatter.format_map(&details));
    println!();

    println!("Media Streams");
    println!("-------------");
    let mut media = HashMap::new();
    media.insert("Audio RTP Port".to_string(), "16384".to_string());
    media.insert("Audio RTCP Port".to_string(), "16385".to_string());
    media.insert("Packets Sent".to_string(), "15,234".to_string());
    media.insert("Packets Received".to_string(), "15,189".to_string());
    media.insert("Jitter (ms)".to_string(), "12.5".to_string());
    media.insert("Packet Loss (%)".to_string(), "0.02".to_string());

    println!("{}", formatter.format_map(&media));

    Ok(())
}

/// Terminates a call.
fn terminate_call(args: &Args, call_id: &str) -> CommandResult {
    let formatter = OutputFormatter::new(args.format);

    if call_id.is_empty() {
        return Err(CommandError::new("Call ID required"));
    }

    println!("Terminating call: {call_id}");

    // In production, would send BYE via API
    // Simulated success
    println!();
    println!(
        "{}",
        formatter.format_status(&format!("Call {call_id} terminated"), true)
    );

    Ok(())
}

/// Shows call statistics.
fn show_stats(args: &Args) {
    let formatter = OutputFormatter::new(args.format);

    println!("Call Statistics");
    println!("===============\n");

    println!("Current");
    println!("-------");
    let mut current = HashMap::new();
    current.insert("Active Calls".to_string(), "42".to_string());
    current.insert("Pending Calls".to_string(), "3".to_string());
    current.insert("Active Registrations".to_string(), "1,234".to_string());
    println!("{}", formatter.format_map(&current));
    println!();

    println!("Last 24 Hours");
    println!("-------------");
    let mut daily = HashMap::new();
    daily.insert("Total Calls".to_string(), "5,678".to_string());
    daily.insert("Successful".to_string(), "5,532".to_string());
    daily.insert("Failed".to_string(), "146".to_string());
    daily.insert("Success Rate".to_string(), "97.4%".to_string());
    daily.insert("Avg Duration".to_string(), "4m 32s".to_string());
    daily.insert("Peak Concurrent".to_string(), "89".to_string());
    println!("{}", formatter.format_map(&daily));
    println!();

    println!("By Codec");
    println!("--------");
    let mut codecs = HashMap::new();
    codecs.insert("Opus".to_string(), "3,456 (60.9%)".to_string());
    codecs.insert("G.722".to_string(), "1,234 (21.7%)".to_string());
    codecs.insert("G.711 μ-law".to_string(), "678 (11.9%)".to_string());
    codecs.insert("G.711 A-law".to_string(), "310 (5.5%)".to_string());
    println!("{}", formatter.format_map(&codecs));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::OutputFormat;

    #[test]
    fn test_list_calls() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        list_calls(&args);
        // No assertions needed - just verify it runs without panic
    }

    #[test]
    fn test_show_call() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = show_call(&args, "call-001");
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_call_empty_id() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = show_call(&args, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_terminate_call() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = terminate_call(&args, "call-001");
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_stats() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        show_stats(&args);
        // No assertions needed - just verify it runs without panic
    }
}
