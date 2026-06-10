//! Health command implementation.
//!
//! Queries `GET /api/v1/system/health` on the daemon and renders the real
//! component statuses. The daemon answers 200 for healthy/degraded and 503
//! (with the same JSON body) when unhealthy, so the body is rendered for
//! both and the exit code reflects the result.

use super::{CommandError, CommandResult};
use crate::api::ApiClient;
use crate::args::{Args, OutputFormat};
use crate::output;
use serde_json::Value;

/// Runs the health command.
///
/// # Errors
///
/// Returns a [`CommandError`] when the daemon cannot be reached,
/// authentication fails, the response cannot be parsed, or the daemon
/// reports itself unhealthy (non-2xx status).
pub fn run(args: &Args) -> CommandResult {
    let client = ApiClient::from_args(args)?;
    let path = "/api/v1/system/health";
    let resp = client.get_any_status(path)?;

    // 401 or a non-JSON error page should be reported as errors, not
    // rendered as if they were health documents.
    if resp.status == 401 {
        return Err(client.status_error(path, &resp).into());
    }
    let Ok(health) = resp.json() else {
        return Err(client.status_error(path, &resp).into());
    };

    render(args, &health);

    if resp.is_success() {
        Ok(())
    } else {
        Err(CommandError::new(format!(
            "daemon reports unhealthy (HTTP {})",
            resp.status
        )))
    }
}

/// Renders the health document in the requested format.
fn render(args: &Args, health: &Value) {
    match args.format {
        OutputFormat::Json => output::print_json(health),
        OutputFormat::Text => render_text(health),
        OutputFormat::Table => {
            let mut pairs = vec![
                (
                    "status".to_string(),
                    output::scalar_to_string(&health["status"]),
                ),
                (
                    "version".to_string(),
                    output::scalar_to_string(&health["version"]),
                ),
                (
                    "uptime_secs".to_string(),
                    output::scalar_to_string(&health["uptime_secs"]),
                ),
            ];
            pairs.extend(component_pairs(health));
            println!("{}", output::format_pairs_table(&pairs));
        }
    }
}

/// Renders the health document as human-readable text.
fn render_text(health: &Value) {
    println!("Daemon Health");
    println!("=============");
    println!();
    println!(
        "Overall Status: {}",
        output::scalar_to_string(&health["status"])
    );
    println!("Version:        {}", output::scalar_to_string(&health["version"]));
    println!(
        "Uptime:         {}s",
        output::scalar_to_string(&health["uptime_secs"])
    );

    let components = component_pairs(health);
    if !components.is_empty() {
        println!();
        println!("Components");
        println!("----------");
        println!("{}", output::format_pairs_text(&components));
    }
}

/// Extracts `component name -> status (message)` pairs.
fn component_pairs(health: &Value) -> Vec<(String, String)> {
    health["components"]
        .as_array()
        .map_or_else(Vec::new, |components| {
            components
                .iter()
                .map(|c| {
                    let name = output::scalar_to_string(&c["name"]);
                    let mut status = output::scalar_to_string(&c["status"]);
                    if let Some(message) = c["message"].as_str() {
                        status = format!("{status} ({message})");
                    }
                    (name, status)
                })
                .collect()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_component_pairs() {
        let health = json!({
            "status": "healthy",
            "components": [
                {"name": "sip", "status": "healthy", "message": null},
                {"name": "media", "status": "degraded", "message": "high jitter"},
            ],
        });
        let pairs = component_pairs(&health);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("sip".to_string(), "healthy".to_string()));
        assert_eq!(
            pairs[1],
            ("media".to_string(), "degraded (high jitter)".to_string())
        );
    }

    #[test]
    fn test_component_pairs_missing() {
        assert!(component_pairs(&json!({"status": "healthy"})).is_empty());
    }
}
