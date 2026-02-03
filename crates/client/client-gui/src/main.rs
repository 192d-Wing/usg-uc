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
// Windows: hide console window in release builds
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod app;
mod notifications;
mod tray;
mod views;

use app::SipClientApp;
use tracing::{error, info};

fn main() -> eframe::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    info!("USG SIP Soft Client starting...");

    // Initialize system tray
    let tray_action_rx = match tray::SystemTray::new() {
        Ok((tray, rx)) => {
            info!("System tray initialized");
            // Keep tray alive by storing in a static or passing to app
            // For now, we leak it intentionally to keep it alive
            Box::leak(Box::new(tray));
            Some(rx)
        }
        Err(e) => {
            error!("Failed to create system tray: {}", e);
            None
        }
    };

    // Configure native options
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([400.0, 600.0])
            .with_min_inner_size([350.0, 500.0])
            .with_title("USG SIP Client")
            .with_icon(load_icon()),
        ..Default::default()
    };

    // Run the application
    eframe::run_native(
        "USG SIP Client",
        options,
        Box::new(move |cc| Ok(Box::new(SipClientApp::new(cc, tray_action_rx)))),
    )
}

/// Loads the application icon.
fn load_icon() -> eframe::egui::IconData {
    // In production, load from embedded resource
    // For now, return a simple placeholder
    let size = 32;
    let pixels: Vec<u8> = (0..size * size)
        .flat_map(|i| {
            let x = i % size;
            let y = i / size;
            // Simple phone icon pattern
            let is_icon = (x >= 8 && x < 24 && y >= 4 && y < 28)
                || (x >= 4 && x < 28 && y >= 10 && y < 22);
            if is_icon {
                [0, 150, 0, 255] // Green
            } else {
                [30, 30, 35, 255] // Dark background
            }
        })
        .collect();

    eframe::egui::IconData {
        rgba: pixels,
        width: size as u32,
        height: size as u32,
    }
}
