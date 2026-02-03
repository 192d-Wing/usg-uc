//! Command-line interface for SBC management.
//!
//! This binary provides CLI tools for configuring, monitoring,
//! and troubleshooting the SBC.
//!
//! ## Usage
//!
//! ```text
//! sbc-cli <COMMAND> [OPTIONS]
//!
//! Commands:
//!     status          Show SBC status
//!     config          Configuration management
//!     calls           Call management
//!     health          Health check operations
//!     metrics         Metrics display
//!     version         Show version information
//!     help            Print help information
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
// Allow dead code for methods that will be used in future integration
#![allow(dead_code)]

mod args;
mod commands;
mod output;

use args::{Args, Command};

fn main() {
    let args = Args::parse();

    if args.help {
        Args::print_help();
        return;
    }

    if args.version {
        println!("sbc-cli {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let result = match &args.command {
        Command::Status => commands::status::run(&args),
        Command::Config(cmd) => commands::config::run(&args, cmd.clone()),
        Command::Calls(cmd) => commands::calls::run(&args, cmd.clone()),
        Command::Health => commands::health::run(&args),
        Command::Metrics => commands::metrics::run(&args),
        Command::Version => {
            println!("sbc-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Help => {
            Args::print_help();
            Ok(())
        }
        Command::None => {
            Args::print_help();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
