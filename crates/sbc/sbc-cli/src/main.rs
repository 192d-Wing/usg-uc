//! Command-line interface for SBC management.
//!
//! This binary provides CLI tools for configuring, monitoring,
//! and troubleshooting the SBC. All state-reporting commands query the
//! daemon's REST API; the CLI never fabricates results.
//!
//! ## Usage
//!
//! ```text
//! sbc-cli [OPTIONS] <COMMAND>
//!
//! Commands:
//!     status          Show SBC status (from the daemon API)
//!     config          Configuration management
//!     calls           Call management
//!     health          Query daemon health
//!     metrics         Show daemon Prometheus metrics
//!     login           Authenticate and obtain an API token
//!     version         Show version information
//!     help            Print help information
//! ```
//!
//! ## Exit codes
//!
//! - `0` success
//! - `1` runtime failure (connection, HTTP, validation, unsupported operation)
//! - `2` usage error (unknown command/subcommand/option, missing arguments)

#![forbid(unsafe_code)]
#![deny(warnings)]

mod api;
mod args;
mod commands;
mod output;

use args::{Args, Command, OutputFormat};

/// Exit code for usage errors.
const EXIT_USAGE: i32 = 2;
/// Exit code for runtime failures.
const EXIT_FAILURE: i32 = 1;

fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!();
            eprintln!("{}", Args::help_text());
            std::process::exit(EXIT_USAGE);
        }
    };

    if args.help {
        Args::print_help();
        return;
    }

    if args.version {
        print_version(&args);
        return;
    }

    let result = match &args.command {
        Command::Status => commands::status::run(&args),
        Command::Config(cmd) => commands::config::run(&args, cmd.clone()),
        Command::Calls(cmd) => commands::calls::run(&args, cmd.clone()),
        Command::Health => commands::health::run(&args),
        Command::Metrics => commands::metrics::run(&args),
        Command::Login => commands::login::run(&args),
        Command::Version => {
            print_version(&args);
            Ok(())
        }
        Command::Help => {
            Args::print_help();
            Ok(())
        }
        Command::None => {
            eprintln!("error: no command specified");
            eprintln!();
            eprintln!("{}", Args::help_text());
            std::process::exit(EXIT_USAGE);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(EXIT_FAILURE);
    }
}

/// Prints version information in the requested output format.
fn print_version(args: &Args) {
    if args.format == OutputFormat::Json {
        output::print_json(&serde_json::json!({
            "name": "sbc-cli",
            "version": env!("CARGO_PKG_VERSION"),
        }));
    } else {
        println!("sbc-cli {}", env!("CARGO_PKG_VERSION"));
    }
}
