//! Main SBC daemon process.
//!
//! This binary runs the Session Border Controller daemon, coordinating
//! all SBC components for SIP signaling and media processing.
//!
//! ## Usage
//!
//! ```text
//! sbc-daemon [OPTIONS]
//!
//! Options:
//!     -c, --config <FILE>    Configuration file path
//!     -v, --verbose          Increase verbosity
//!     --version              Print version information
//!     --help                 Print help information
//! ```
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging - All significant events are logged
//! - **CM-2**: Baseline Configuration - Configuration loaded at startup
//! - **SC-5**: DoS Protection - Rate limiting enabled

#![forbid(unsafe_code)]
#![deny(warnings)]
// Allow dead code for methods that will be used in future integration
#![allow(dead_code)]

mod args;
mod runtime;
mod server;
mod shutdown;

use args::Args;
use runtime::Runtime;

fn main() {
    let args = Args::parse();

    if args.version {
        println!("sbc-daemon {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if args.help {
        Args::print_help();
        return;
    }

    match Runtime::new(args) {
        Ok(mut runtime) => {
            if let Err(e) = runtime.run() {
                eprintln!("Fatal error: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Initialization failed: {e}");
            std::process::exit(1);
        }
    }
}
