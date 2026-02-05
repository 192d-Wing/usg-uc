//! UI styling constants for native Windows controls.
//!
//! Provides a centralized location for colors and sizes.
//! Note: Many styling options are handled by Windows themes automatically.

// ============================================================================
// Color Constants (as RGB tuples for reference)
// Windows native controls use system colors by default.
// ============================================================================

/// Primary action color (green) - RGB values for reference.
#[allow(dead_code)]
pub const COLOR_PRIMARY_RGB: (u8, u8, u8) = (0, 150, 0);

/// Danger/destructive action color (red).
#[allow(dead_code)]
pub const COLOR_DANGER_RGB: (u8, u8, u8) = (200, 50, 50);

/// Warning/attention color (orange).
#[allow(dead_code)]
pub const COLOR_WARNING_RGB: (u8, u8, u8) = (255, 165, 0);

/// Info/neutral action color (blue).
#[allow(dead_code)]
pub const COLOR_INFO_RGB: (u8, u8, u8) = (100, 149, 237);

/// Success indicator color (green).
#[allow(dead_code)]
pub const COLOR_SUCCESS_RGB: (u8, u8, u8) = (34, 139, 34);

// ============================================================================
// Size Constants
// ============================================================================

/// Standard button width.
#[allow(dead_code)]
pub const BUTTON_WIDTH: u32 = 90;

/// Standard button height.
#[allow(dead_code)]
pub const BUTTON_HEIGHT: u32 = 30;

/// Large button height.
#[allow(dead_code)]
pub const BUTTON_HEIGHT_LARGE: u32 = 45;

/// Dialpad button size.
#[allow(dead_code)]
pub const DIALPAD_BUTTON_SIZE: u32 = 60;

/// Standard spacing.
#[allow(dead_code)]
pub const SPACING: i32 = 10;

/// Large spacing.
#[allow(dead_code)]
pub const SPACING_LARGE: i32 = 16;

/// Input field height.
#[allow(dead_code)]
pub const INPUT_HEIGHT: u32 = 22;

/// Standard control width.
#[allow(dead_code)]
pub const CONTROL_WIDTH: u32 = 200;

// ============================================================================
// Window Dimensions
// ============================================================================

/// Default window width.
#[allow(dead_code)]
pub const WINDOW_WIDTH: u32 = 420;

/// Default window height.
#[allow(dead_code)]
pub const WINDOW_HEIGHT: u32 = 640;

/// Minimum window width.
#[allow(dead_code)]
pub const WINDOW_MIN_WIDTH: u32 = 350;

/// Minimum window height.
#[allow(dead_code)]
pub const WINDOW_MIN_HEIGHT: u32 = 500;
