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
//! - **SC-5**: `DoS` Protection - Rate limiting enabled

#![forbid(unsafe_code)]
#![deny(warnings)]
// Allow dead code for methods that will be used in future integration
#![allow(dead_code)]

mod api_server;
mod args;
mod ice_agent;
mod media_pipeline;
mod runtime;
mod server;
mod shutdown;
mod sip_stack;

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

    // Initialize tracing subscriber
    init_tracing(args.verbose);

    // Create tokio runtime and run the daemon
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sbc-worker")
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async {
        match Runtime::new(args).await {
            Ok(mut runtime) => {
                if let Err(e) = runtime.run().await {
                    tracing::error!("Fatal error: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                tracing::error!("Initialization failed: {e}");
                std::process::exit(1);
            }
        }
    });
}

/// Initializes the tracing subscriber with appropriate log level.
fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;

    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("sbc={level},warn")));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}
