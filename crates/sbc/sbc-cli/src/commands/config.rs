//! Config command implementation.
//!
//! `config validate` performs real local validation via `sbc-config`.
//! `config show` and `config reload` require daemon API endpoints that do
//! not exist yet, so they fail loudly instead of printing fabricated
//! defaults or fake success messages.

use super::{CommandError, CommandResult};
use crate::args::{Args, ConfigCommand, OutputFormat};
use crate::output;
use serde_json::json;

/// Runs the config command.
///
/// # Errors
///
/// Returns a [`CommandError`] when validation fails or when the requested
/// operation is not supported by the daemon API.
pub fn run(args: &Args, cmd: ConfigCommand) -> CommandResult {
    match cmd {
        ConfigCommand::Show => show_config(),
        ConfigCommand::Validate { path } => validate_config(args, path),
        ConfigCommand::Reload => reload_config(),
    }
}

/// Rejects `config show`: the daemon does not expose its running
/// configuration yet, and printing compiled-in defaults as the "current
/// configuration" would be misleading.
fn show_config() -> CommandResult {
    Err(CommandError::new(
        "'config show' is not supported by the daemon API yet; \
         use 'config validate <PATH>' to inspect a local configuration file",
    ))
}

/// Validates a configuration file on the local filesystem.
fn validate_config(args: &Args, path: Option<String>) -> CommandResult {
    let config_path = path.unwrap_or_else(|| "/etc/sbc/config.toml".to_string());

    match sbc_config::load_from_file(&config_path) {
        Ok(config) => {
            let summary = json!({
                "valid": true,
                "path": config_path,
                "instance": config.general.instance_name,
                "max_calls": config.general.max_calls,
                "media_mode": format!("{:?}", config.media.default_mode),
            });
            match args.format {
                OutputFormat::Json => output::print_json(&summary),
                OutputFormat::Text => {
                    println!("Configuration valid: {config_path}");
                    println!();
                    println!(
                        "{}",
                        output::format_pairs_text(&output::object_to_pairs(&summary))
                    );
                }
                OutputFormat::Table => {
                    println!(
                        "{}",
                        output::format_pairs_table(&output::object_to_pairs(&summary))
                    );
                }
            }
            Ok(())
        }
        Err(e) => Err(CommandError::new(format!(
            "validation failed for {config_path}: {e}"
        ))),
    }
}

/// Rejects `config reload`: the daemon API has no reload endpoint yet.
fn reload_config() -> CommandResult {
    Err(CommandError::new(
        "'config reload' is not supported by the daemon API yet; \
         the configuration was NOT reloaded",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_nonexistent() {
        let args = Args::default();
        let result = validate_config(&args, Some("/nonexistent/path.toml".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_show_is_unsupported() {
        let err = match show_config() {
            Ok(()) => unreachable!("config show must not succeed"),
            Err(e) => e,
        };
        assert!(err.message.contains("not supported by the daemon API"));
    }

    #[test]
    fn test_reload_is_unsupported() {
        // No reload endpoint exists; the command must never claim success.
        let err = match reload_config() {
            Ok(()) => unreachable!("config reload must not succeed"),
            Err(e) => e,
        };
        assert!(err.message.contains("not supported by the daemon API"));
        assert!(err.message.contains("NOT reloaded"));
    }
}
