//! System tray integration for the SIP soft client.
//!
//! Provides a tray icon with a context menu for common operations.

use std::sync::mpsc::{self, Receiver, Sender};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIcon, TrayIconBuilder,
};
use tracing::{error, info};

/// Actions that can be triggered from the system tray.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TrayAction {
    /// Show the main window.
    ShowWindow,
    /// Hide the main window (minimize to tray).
    HideWindow,
    /// Exit the application.
    Exit,
}

/// System tray manager.
#[allow(dead_code)]
pub struct SystemTray {
    /// The tray icon (kept alive to prevent drop).
    _tray_icon: TrayIcon,
    /// Menu item IDs for matching events.
    show_id: tray_icon::menu::MenuId,
    exit_id: tray_icon::menu::MenuId,
    /// Sender for tray actions.
    action_tx: Sender<TrayAction>,
}

impl SystemTray {
    /// Creates a new system tray instance.
    ///
    /// Returns the tray manager and a receiver for tray actions.
    pub fn new() -> Result<(Self, Receiver<TrayAction>), TrayError> {
        // Create the icon
        let icon = create_tray_icon()?;

        // Create menu items
        let show_item = MenuItem::new("Show USG SIP Client", true, None);
        let exit_item = MenuItem::new("Exit", true, None);

        let show_id = show_item.id().clone();
        let exit_id = exit_item.id().clone();

        // Build the menu
        let menu = Menu::new();
        if let Err(e) = menu.append(&show_item) {
            error!("Failed to add show menu item: {}", e);
        }
        if let Err(e) = menu.append(&PredefinedMenuItem::separator()) {
            error!("Failed to add separator: {}", e);
        }
        if let Err(e) = menu.append(&exit_item) {
            error!("Failed to add exit menu item: {}", e);
        }

        // Create the tray icon
        let tray_icon = TrayIconBuilder::new()
            .with_tooltip("USG SIP Client")
            .with_icon(icon)
            .with_menu(Box::new(menu))
            .build()
            .map_err(|e| TrayError::Build(e.to_string()))?;

        // Set up channels
        let (action_tx, action_rx) = mpsc::channel();

        info!("System tray initialized");

        Ok((
            Self {
                _tray_icon: tray_icon,
                show_id,
                exit_id,
                action_tx,
            },
            action_rx,
        ))
    }

    /// Polls for menu events and sends corresponding actions.
    ///
    /// This should be called periodically from the main loop.
    #[allow(dead_code)]
    pub fn poll_events(&self) {
        // MenuEvent::receiver() returns a crossbeam_channel::Receiver
        // We need to poll it and forward to our std::sync::mpsc channel
        let menu_rx = MenuEvent::receiver();
        while let Ok(event) = menu_rx.try_recv() {
            let action = if event.id == self.show_id {
                TrayAction::ShowWindow
            } else if event.id == self.exit_id {
                TrayAction::Exit
            } else {
                continue;
            };

            if let Err(e) = self.action_tx.send(action.clone()) {
                error!("Failed to send tray action: {}", e);
            } else {
                info!("Tray action: {:?}", action);
            }
        }
    }

    /// Updates the tray tooltip with the current status.
    #[allow(dead_code)]
    pub fn set_tooltip(&self, _tooltip: &str) {
        // Note: tray-icon doesn't support updating tooltip after creation
        // This would require recreating the tray icon
    }
}

/// Creates the tray icon image.
fn create_tray_icon() -> Result<Icon, TrayError> {
    // Create a simple 32x32 icon with a phone symbol
    let size = 32_u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;

            // Simple phone icon pattern (green on transparent)
            let is_phone_body = (x >= 8 && x < 24 && y >= 4 && y < 28)
                || (x >= 4 && x < 28 && y >= 10 && y < 22);

            if is_phone_body {
                // Green color
                rgba[idx] = 0;     // R
                rgba[idx + 1] = 150; // G
                rgba[idx + 2] = 0;   // B
                rgba[idx + 3] = 255; // A
            } else {
                // Transparent
                rgba[idx] = 0;
                rgba[idx + 1] = 0;
                rgba[idx + 2] = 0;
                rgba[idx + 3] = 0;
            }
        }
    }

    Icon::from_rgba(rgba, size, size).map_err(|e| TrayError::Icon(e.to_string()))
}

/// Errors that can occur with the system tray.
#[derive(Debug, Clone)]
pub enum TrayError {
    /// Failed to create the icon.
    Icon(String),
    /// Failed to build the tray.
    Build(String),
}

impl std::fmt::Display for TrayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrayError::Icon(e) => write!(f, "Failed to create tray icon: {}", e),
            TrayError::Build(e) => write!(f, "Failed to build system tray: {}", e),
        }
    }
}

impl std::error::Error for TrayError {}
