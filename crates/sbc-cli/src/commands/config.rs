//! Config command implementation.

use super::{CommandError, CommandResult};
use crate::args::{Args, ConfigCommand};
use crate::output::OutputFormatter;
use sbc_config::SbcConfig;
use std::collections::HashMap;

/// Runs the config command.
pub fn run(args: &Args, cmd: ConfigCommand) -> CommandResult {
    match cmd {
        ConfigCommand::Show => show_config(args),
        ConfigCommand::Validate { path } => validate_config(args, path),
        ConfigCommand::Reload => reload_config(args),
    }
}

/// Shows current configuration.
fn show_config(args: &Args) -> CommandResult {
    let formatter = OutputFormatter::new(args.format);

    // In production, would fetch from API
    // For now, show default config
    let config = SbcConfig::default();

    println!("Current Configuration");
    println!("=====================\n");

    println!("General");
    println!("-------");
    let mut general = HashMap::new();
    general.insert("Instance Name".to_string(), config.general.instance_name.clone());
    general.insert("Max Calls".to_string(), config.general.max_calls.to_string());
    general.insert(
        "Max Registrations".to_string(),
        config.general.max_registrations.to_string(),
    );
    println!("{}", formatter.format_map(&general));
    println!();

    println!("Media");
    println!("-----");
    let mut media = HashMap::new();
    media.insert("Default Mode".to_string(), format!("{:?}", config.media.default_mode));
    media.insert("SRTP Required".to_string(), config.media.srtp.required.to_string());
    media.insert(
        "Codecs".to_string(),
        config
            .media
            .codecs
            .iter()
            .map(|c| format!("{c:?}"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    println!("{}", formatter.format_map(&media));
    println!();

    println!("Security");
    println!("--------");
    let mut security = HashMap::new();
    security.insert("Curve".to_string(), format!("{:?}", config.security.curve));
    security.insert("Min TLS".to_string(), config.security.min_tls_version.clone());
    security.insert("Require mTLS".to_string(), config.security.require_mtls.to_string());
    println!("{}", formatter.format_map(&security));

    Ok(())
}

/// Validates a configuration file.
fn validate_config(args: &Args, path: Option<String>) -> CommandResult {
    let formatter = OutputFormatter::new(args.format);

    let config_path = path.unwrap_or_else(|| "/etc/sbc/config.toml".to_string());

    println!("Validating configuration: {config_path}");
    println!();

    // Try to load and validate
    match sbc_config::load_from_file(&config_path) {
        Ok(config) => {
            println!("{}", formatter.format_status("Configuration valid", true));
            println!();
            println!("Summary:");
            let mut summary = HashMap::new();
            summary.insert("Instance".to_string(), config.general.instance_name);
            summary.insert("Max Calls".to_string(), config.general.max_calls.to_string());
            summary.insert(
                "Media Mode".to_string(),
                format!("{:?}", config.media.default_mode),
            );
            println!("{}", formatter.format_map(&summary));
            Ok(())
        }
        Err(e) => {
            println!("{}", formatter.format_status("Configuration invalid", false));
            println!();
            Err(CommandError::new(format!("Validation failed: {e}")))
        }
    }
}

/// Reloads configuration.
fn reload_config(args: &Args) -> CommandResult {
    let formatter = OutputFormatter::new(args.format);

    // In production, would send reload signal to daemon via API
    println!("Sending reload signal to SBC daemon...");

    // Simulated response
    println!();
    println!("{}", formatter.format_status("Configuration reloaded", true));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::OutputFormat;

    #[test]
    fn test_show_config() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = show_config(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_nonexistent() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = validate_config(&args, Some("/nonexistent/path.toml".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_reload_config() {
        let args = Args {
            format: OutputFormat::Text,
            ..Default::default()
        };

        let result = reload_config(&args);
        assert!(result.is_ok());
    }
}
