//! Status command implementation.
//!
//! Queries `GET /api/v1/system/stats` on the daemon and renders the real
//! statistics. No data is synthesized client-side.

use super::CommandResult;
use crate::api::ApiClient;
use crate::args::{Args, OutputFormat};
use crate::output;

/// Runs the status command.
///
/// # Errors
///
/// Returns a [`super::CommandError`] when the daemon cannot be reached,
/// authentication fails, or the response cannot be parsed.
pub fn run(args: &Args) -> CommandResult {
    let client = ApiClient::from_args(args)?;
    let stats = client.get("/api/v1/system/stats")?.json()?;

    match args.format {
        OutputFormat::Json => output::print_json(&stats),
        OutputFormat::Text => {
            println!("SBC Status ({})", args.api_url);
            println!("==========");
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
