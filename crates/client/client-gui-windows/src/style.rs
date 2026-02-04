//! UI styling constants for native Windows controls.
//!
//! Provides a centralized location for colors and sizes.
//! Note: Many styling options are handled by Windows themes automatically.

// ============================================================================
// Color Constants (as RGB tuples for reference)
// Windows native controls use system colors by default.
// ============================================================================

/// Primary action color (green) - RGB values for reference.
pub const COLOR_PRIMARY_RGB: (u8, u8, u8) = (0, 150, 0);

/// Danger/destructive action color (red).
pub const COLOR_DANGER_RGB: (u8, u8, u8) = (200, 50, 50);

/// Warning/attention color (orange).
pub const COLOR_WARNING_RGB: (u8, u8, u8) = (255, 165, 0);

/// Info/neutral action color (blue).
pub const COLOR_INFO_RGB: (u8, u8, u8) = (100, 149, 237);

/// Success indicator color (green).
pub const COLOR_SUCCESS_RGB: (u8, u8, u8) = (34, 139, 34);

// ============================================================================
// Size Constants
// ============================================================================

/// Standard button width.
pub const BUTTON_WIDTH: u32 = 90;

/// Standard button height.
pub const BUTTON_HEIGHT: u32 = 30;

/// Large button height.
pub const BUTTON_HEIGHT_LARGE: u32 = 45;

/// Dialpad button size.
pub const DIALPAD_BUTTON_SIZE: u32 = 60;

/// Standard spacing.
pub const SPACING: i32 = 10;

/// Large spacing.
pub const SPACING_LARGE: i32 = 16;

/// Input field height.
pub const INPUT_HEIGHT: u32 = 22;

/// Standard control width.
pub const CONTROL_WIDTH: u32 = 200;

// ============================================================================
// Window Dimensions
// ============================================================================

/// Default window width.
pub const WINDOW_WIDTH: u32 = 420;

/// Default window height.
pub const WINDOW_HEIGHT: u32 = 640;

/// Minimum window width.
pub const WINDOW_MIN_WIDTH: u32 = 350;

/// Minimum window height.
pub const WINDOW_MIN_HEIGHT: u32 = 500;
