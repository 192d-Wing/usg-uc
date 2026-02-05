//! USG SIP Soft Client - Windows GUI Application.
//!
//! A CNSA 2.0 compliant SIP soft client for enterprise/government use.
//! Authentication is via smart card (CAC/PIV/SIPR token) only.
//!
//! This crate is Windows-only using native Win32 controls via native-windows-gui.
//! Other platforms have separate UI crates:
//! - `client-gui-macos` (planned)
//! - `client-gui-linux` (planned)
//! - `client-gui-android` (planned)
//! - `client-gui-ios` (planned)

// This crate only compiles on Windows
#![cfg(target_os = "windows")]
// Use deny instead of forbid to allow platform-specific unsafe code in modal dialogs
// The unsafe transmute pattern is needed for event handlers since NWG controls don't implement Clone
#![deny(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![allow(clippy::must_use_candidate)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]
// Hide console window in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod dialogs;
mod notifications;
mod style;
mod tray;
mod views;

use app::SipClientApp;
use tracing::{error, info};

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    info!("USG SIP Soft Client starting...");

    // Enable High DPI awareness
    native_windows_gui::enable_visual_styles();
    if let Err(e) = native_windows_gui::init() {
        error!("Failed to initialize native-windows-gui: {}", e);
        return;
    }

    // Build and run the application
    // Note: System tray is now created inside the app after the window is built
    match SipClientApp::build() {
        Ok(app) => {
            info!("Application window created");
            native_windows_gui::dispatch_thread_events();
            drop(app);
        }
        Err(e) => {
            error!("Failed to create application: {}", e);
            native_windows_gui::error_message("USG SIP Client", &format!("Failed to start: {}", e));
        }
    }

    info!("Application shutting down");
}
