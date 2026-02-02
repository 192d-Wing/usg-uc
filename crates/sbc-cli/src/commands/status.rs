//! Status command implementation.

use super::CommandResult;
use crate::args::Args;
use crate::output::OutputFormatter;
use std::collections::HashMap;

/// Runs the status command.
pub fn run(args: &Args) -> CommandResult {
    let formatter = OutputFormatter::new(args.format);

    // In production, would query the SBC API
    // For now, show simulated status

    println!("SBC Status");
    println!("==========\n");

    let mut status = HashMap::new();
    status.insert("Instance".to_string(), "sbc-01".to_string());
    status.insert("State".to_string(), "Running".to_string());
    status.insert("Uptime".to_string(), "12h 34m 56s".to_string());
    status.insert("Version".to_string(), env!("CARGO_PKG_VERSION").to_string());

    println!("{}", formatter.format_map(&status));
    println!();

    println!("Call Statistics");
    println!("---------------");
    let mut call_stats = HashMap::new();
    call_stats.insert("Active Calls".to_string(), "42".to_string());
    call_stats.insert("Total Calls (24h)".to_string(), "1,234".to_string());
    call_stats.insert("Failed Calls (24h)".to_string(), "23".to_string());
    call_stats.insert("Success Rate".to_string(), "98.1%".to_string());

    println!("{}", formatter.format_map(&call_stats));
    println!();

    println!("Resource Usage");
    println!("--------------");
    let mut resources = HashMap::new();
    resources.insert("CPU".to_string(), "15%".to_string());
    resources.insert("Memory".to_string(), "512 MB (25%)".to_string());
    resources.insert("Connections".to_string(), "156".to_string());
    resources.insert("RTP Streams".to_string(), "84".to_string());

    println!("{}", formatter.format_map(&resources));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::OutputFormat;

    #[test]
    fn test_status_command() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = run(&args);
        assert!(result.is_ok());
    }
}
