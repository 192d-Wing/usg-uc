//! Health command implementation.

use super::CommandResult;
use crate::args::Args;
use crate::output::OutputFormatter;
use uc_health::{HealthChecker, HealthCheckerConfig, HealthStatus};

/// Runs the health command.
pub fn run(args: &Args) -> CommandResult {
    let formatter = OutputFormatter::new(args.format);

    println!("Health Check");
    println!("============\n");

    // Create a health checker with simulated checks
    let mut checker =
        HealthChecker::new(HealthCheckerConfig::default()).with_version(env!("CARGO_PKG_VERSION"));

    // Add checks
    checker.register(Box::new(uc_health::check::AlwaysHealthyCheck::new(
        "sbc_core",
    )));
    checker.register(Box::new(uc_health::check::MemoryCheck::new()));
    checker.register(Box::new(uc_health::check::DiskCheck::new("/")));

    // Perform health check
    let health = checker.check();

    // Overall status
    let status_str = health.status.as_str();
    let is_healthy = health.is_healthy();
    println!(
        "Overall Status: {}",
        formatter.format_status(status_str, is_healthy)
    );
    println!();

    // Component statuses
    println!("Components");
    println!("----------");
    for component in &health.components {
        let healthy = component.status == HealthStatus::Healthy;
        println!("  {}", formatter.format_status(&component.name, healthy));
        if let Some(ref msg) = component.message {
            println!("    Message: {msg}");
        }
    }
    println!();

    // Summary
    println!("Summary");
    println!("-------");
    println!("  Healthy:   {}", health.healthy_count());
    println!("  Unhealthy: {}", health.unhealthy_count());
    println!("  Total:     {}", health.components.len());

    if let Some(version) = &health.version {
        println!("\nVersion: {version}");
    }

    if let Some(uptime) = health.uptime_secs {
        println!("Uptime:  {uptime}s");
    }

    // Liveness and readiness
    println!();
    println!("Probes");
    println!("------");
    println!(
        "  Liveness:  {}",
        formatter.format_status("alive", checker.is_alive())
    );
    println!(
        "  Readiness: {}",
        formatter.format_status("ready", checker.is_ready())
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::OutputFormat;

    #[test]
    fn test_health_command() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = run(&args);
        assert!(result.is_ok());
    }
}
