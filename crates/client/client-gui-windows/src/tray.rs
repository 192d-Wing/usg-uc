//! System tray integration for the SIP soft client using native Windows controls.
//!
//! Provides a tray icon with a context menu for common operations.

use native_windows_gui as nwg;
use std::sync::mpsc::{self, Receiver, Sender};
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

/// System tray manager using native Windows controls.
pub struct SystemTray {
    /// Icon resource for the tray.
    _icon: nwg::Icon,
    /// The tray notification icon.
    tray_icon: nwg::TrayNotification,
    /// Context menu for the tray.
    tray_menu: nwg::Menu,
    /// Show menu item.
    show_item: nwg::MenuItem,
    /// Hide menu item.
    hide_item: nwg::MenuItem,
    /// Exit menu item.
    exit_item: nwg::MenuItem,
    /// Sender for tray actions.
    #[allow(dead_code)]
    action_tx: Sender<TrayAction>,
    /// Receiver for tray actions (returned to caller).
    _action_rx: Option<Receiver<TrayAction>>,
}

impl SystemTray {
    /// Creates a new system tray instance.
    ///
    /// Returns the tray manager and a receiver for tray actions.
    pub fn new(parent: &nwg::Window) -> Result<(Self, Receiver<TrayAction>), TrayError> {
        // Create an icon for the tray (using a built-in system icon)
        let mut icon = Default::default();
        nwg::Icon::builder()
            .source_system(Some(nwg::OemIcon::WinLogo))
            .build(&mut icon)
            .map_err(|e| TrayError::Icon(e.to_string()))?;

        // Create the tray icon
        let mut tray_icon = Default::default();
        nwg::TrayNotification::builder()
            .parent(parent)
            .icon(Some(&icon))
            .tip(Some("USG SIP Client"))
            .build(&mut tray_icon)
            .map_err(|e| TrayError::Build(e.to_string()))?;

        // Create the context menu
        let mut tray_menu = Default::default();
        nwg::Menu::builder()
            .popup(true)
            .parent(parent)
            .build(&mut tray_menu)
            .map_err(|e| TrayError::Build(e.to_string()))?;

        // Show menu item
        let mut show_item = Default::default();
        nwg::MenuItem::builder()
            .parent(&tray_menu)
            .text("Show USG SIP Client")
            .build(&mut show_item)
            .map_err(|e| TrayError::Build(e.to_string()))?;

        // Hide menu item
        let mut hide_item = Default::default();
        nwg::MenuItem::builder()
            .parent(&tray_menu)
            .text("Hide")
            .build(&mut hide_item)
            .map_err(|e| TrayError::Build(e.to_string()))?;

        // Separator
        let mut separator = Default::default();
        nwg::MenuSeparator::builder()
            .parent(&tray_menu)
            .build(&mut separator)
            .map_err(|e| TrayError::Build(e.to_string()))?;

        // Exit menu item
        let mut exit_item = Default::default();
        nwg::MenuItem::builder()
            .parent(&tray_menu)
            .text("Exit")
            .build(&mut exit_item)
            .map_err(|e| TrayError::Build(e.to_string()))?;

        // Set up channels
        let (action_tx, action_rx) = mpsc::channel();

        info!("System tray initialized with native Windows controls");

        Ok((
            Self {
                _icon: icon,
                tray_icon,
                tray_menu,
                show_item,
                hide_item,
                exit_item,
                action_tx,
                _action_rx: None,
            },
            action_rx,
        ))
    }

    /// Returns a reference to the tray icon for event handling.
    #[allow(dead_code)]
    pub fn tray_icon(&self) -> &nwg::TrayNotification {
        &self.tray_icon
    }

    /// Returns a reference to the tray menu.
    #[allow(dead_code)]
    pub fn tray_menu(&self) -> &nwg::Menu {
        &self.tray_menu
    }

    /// Returns a reference to the show menu item.
    #[allow(dead_code)]
    pub fn show_item(&self) -> &nwg::MenuItem {
        &self.show_item
    }

    /// Returns a reference to the hide menu item.
    #[allow(dead_code)]
    pub fn hide_item(&self) -> &nwg::MenuItem {
        &self.hide_item
    }

    /// Returns a reference to the exit menu item.
    #[allow(dead_code)]
    pub fn exit_item(&self) -> &nwg::MenuItem {
        &self.exit_item
    }

    /// Sends a show window action.
    #[allow(dead_code)]
    pub fn send_show(&self) {
        if let Err(e) = self.action_tx.send(TrayAction::ShowWindow) {
            error!("Failed to send show action: {}", e);
        } else {
            info!("Tray action: ShowWindow");
        }
    }

    /// Sends a hide window action.
    #[allow(dead_code)]
    pub fn send_hide(&self) {
        if let Err(e) = self.action_tx.send(TrayAction::HideWindow) {
            error!("Failed to send hide action: {}", e);
        } else {
            info!("Tray action: HideWindow");
        }
    }

    /// Sends an exit action.
    #[allow(dead_code)]
    pub fn send_exit(&self) {
        if let Err(e) = self.action_tx.send(TrayAction::Exit) {
            error!("Failed to send exit action: {}", e);
        } else {
            info!("Tray action: Exit");
        }
    }

    /// Updates the tray tooltip with the current status.
    #[allow(dead_code)]
    pub fn set_tooltip(&self, tooltip: &str) {
        self.tray_icon.set_tip(tooltip);
    }

    /// Shows a balloon notification from the tray.
    #[allow(dead_code)]
    pub fn show_balloon(&self, title: &str, text: &str, flags: Option<nwg::TrayNotificationFlags>) {
        self.tray_icon.show(
            text,
            Some(title),
            flags,
            None, // Use default icon
        );
    }

    /// Shows the context menu at the current cursor position.
    #[allow(dead_code)]
    pub fn show_menu(&self) {
        let (x, y) = nwg::GlobalCursor::position();
        self.tray_menu.popup(x, y);
    }
}

/// Errors that can occur with the system tray.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
