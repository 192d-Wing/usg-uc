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
// Allow significant_drop_tightening for async RwLock guards that are legitimately held
#![allow(clippy::significant_drop_tightening)]
// Allow future_not_send for async functions that don't need Send bounds
#![allow(clippy::future_not_send)]
// Allow unused_async for functions that are part of async trait implementations
#![allow(clippy::unused_async)]
// Allow needless_pass_by_ref_mut for async methods that may need mutation in future
#![allow(clippy::needless_pass_by_ref_mut)]
// Allow unused_self for methods that are part of trait implementations or future use
#![allow(clippy::unused_self)]

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
        .unwrap_or_else(|e| {
            eprintln!("Failed to create tokio runtime: {e}");
            std::process::exit(1);
        });

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
