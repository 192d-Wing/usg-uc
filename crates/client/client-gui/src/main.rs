//! USG SIP Soft Client - Windows GUI Application.
//!
//! A CNSA 2.0 compliant SIP soft client for enterprise/government use.
//! Authentication is via smart card (CAC/PIV/SIPR token) only.

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![allow(clippy::must_use_candidate)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    tracing::info!("USG SIP Soft Client starting...");

    // TODO: Initialize application
    // TODO: Start GUI event loop

    tracing::info!("USG SIP Soft Client shutting down.");
}
