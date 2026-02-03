//! Metrics command implementation.

use super::CommandResult;
use crate::args::Args;
use uc_metrics::SbcMetrics;

/// Runs the metrics command.
pub fn run(_args: &Args) -> CommandResult {
    println!("SBC Metrics (Prometheus Format)");
    println!("===============================\n");

    // Create standard SBC metrics with some values
    let registry = SbcMetrics::standard();

    // Note: In production, would fetch actual metrics from the running daemon
    // The registry.counter/gauge methods return references that can be used
    // to observe values. Here we just show the registered metrics.

    // Simulate metric increments using the counters directly
    if let Some(counter) = registry.counter("calls_total") {
        counter.inc_by(5678_u64);
    }
    if let Some(counter) = registry.counter("calls_failed_total") {
        counter.inc_by(146_u64);
    }
    if let Some(gauge) = registry.gauge("calls_active") {
        gauge.set(42_i64);
    }
    if let Some(gauge) = registry.gauge("rtp_streams_active") {
        gauge.set(84_i64);
    }
    if let Some(counter) = registry.counter("sip_requests_total") {
        counter.inc_by(123_456_u64);
    }
    if let Some(counter) = registry.counter("sip_responses_total") {
        counter.inc_by(123_400_u64);
    }

    // Observe some histogram values
    if let Some(histogram) = registry.histogram("call_setup_duration_seconds") {
        histogram.observe(0.5_f64);
        histogram.observe(1.2_f64);
        histogram.observe(0.8_f64);
    }
    if let Some(histogram) = registry.histogram("sip_request_duration_seconds") {
        histogram.observe(0.01_f64);
        histogram.observe(0.02_f64);
        histogram.observe(0.005_f64);
    }

    // Export in Prometheus text format
    let output = registry.export();
    println!("{output}");

    // List registered metrics
    println!("\nRegistered Metrics");
    println!("------------------");
    for metric in registry.list_metrics() {
        println!(
            "  {} ({}) - {}",
            metric.name,
            metric.metric_type.as_str(),
            metric.help
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::OutputFormat;

    #[test]
    fn test_metrics_command() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = run(&args);
        assert!(result.is_ok());
    }
}
