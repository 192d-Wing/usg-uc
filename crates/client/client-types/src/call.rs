//! Call-related types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Call state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallState {
    /// No active call.
    Idle,
    /// Sending INVITE, waiting for response.
    Dialing,
    /// Received 180 Ringing.
    Ringing,
    /// Received 183 Session Progress with SDP (early media).
    EarlyMedia,
    /// Received 200 OK, sending ACK.
    Connecting,
    /// Call established, media flowing.
    Connected,
    /// Call is on hold (local or remote).
    OnHold,
    /// Transfer in progress (REFER sent).
    Transferring,
    /// Sending BYE.
    Terminating,
    /// Call ended normally or due to error.
    Terminated,
}

impl std::fmt::Display for CallState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Dialing => write!(f, "Dialing"),
            Self::Ringing => write!(f, "Ringing"),
            Self::EarlyMedia => write!(f, "Early Media"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Connected => write!(f, "Connected"),
            Self::OnHold => write!(f, "On Hold"),
            Self::Transferring => write!(f, "Transferring"),
            Self::Terminating => write!(f, "Terminating"),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

impl CallState {
    /// Returns true if the call is in an active state.
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Dialing
                | Self::Ringing
                | Self::EarlyMedia
                | Self::Connecting
                | Self::Connected
                | Self::OnHold
                | Self::Transferring
                | Self::Terminating
        )
    }

    /// Returns true if media should be flowing.
    pub const fn has_media(&self) -> bool {
        matches!(self, Self::EarlyMedia | Self::Connected)
    }
}

/// Call focus state for multi-call scenarios.
///
/// In multi-call mode (call waiting), one call is "focused" (has active
/// media and UI focus), while others are held in the background.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallFocus {
    /// This is the currently active/focused call with live media.
    #[default]
    Active,
    /// This call is held in the background (on hold).
    Held,
    /// This call is ringing (incoming, not yet answered).
    Ringing,
}

impl std::fmt::Display for CallFocus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Held => write!(f, "Held"),
            Self::Ringing => write!(f, "Ringing"),
        }
    }
}

/// Reason for call failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallFailureReason {
    /// Remote party rejected with status code.
    Rejected {
        /// SIP status code.
        status_code: u16,
        /// Reason phrase.
        reason: String,
    },
    /// Transaction timed out.
    Timeout,
    /// Network error.
    NetworkError(String),
    /// Media setup failed.
    MediaError(String),
    /// Authentication failed.
    AuthenticationFailed,
    /// Cancelled by local user.
    Cancelled,
}

impl std::fmt::Display for CallFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected {
                status_code,
                reason,
            } => {
                write!(f, "Rejected: {status_code} {reason}")
            }
            Self::Timeout => write!(f, "Timeout"),
            Self::NetworkError(e) => write!(f, "Network error: {e}"),
            Self::MediaError(e) => write!(f, "Media error: {e}"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// Reason for call ending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallEndReason {
    /// Normal hangup by local user.
    LocalHangup,
    /// Normal hangup by remote user.
    RemoteHangup,
    /// Call was rejected.
    Rejected {
        /// SIP status code.
        status_code: u16,
    },
    /// Local user rejected an incoming call.
    LocalReject,
    /// Call timed out.
    Timeout,
    /// Network error.
    NetworkError,
    /// Call failed to establish.
    Failed,
    /// Call was transferred.
    Transferred,
    /// Unknown reason.
    Unknown,
}

impl std::fmt::Display for CallEndReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalHangup => write!(f, "Ended by you"),
            Self::RemoteHangup => write!(f, "Ended by remote"),
            Self::Rejected { status_code } => write!(f, "Rejected ({status_code})"),
            Self::LocalReject => write!(f, "Rejected by you"),
            Self::Timeout => write!(f, "Timed out"),
            Self::NetworkError => write!(f, "Network error"),
            Self::Failed => write!(f, "Failed"),
            Self::Transferred => write!(f, "Transferred"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Call direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallDirection {
    /// Outgoing call (we initiated).
    Outbound,
    /// Incoming call (they initiated).
    Inbound,
}

impl std::fmt::Display for CallDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Outbound => write!(f, "Outbound"),
            Self::Inbound => write!(f, "Inbound"),
        }
    }
}

/// Information about an active call.
#[derive(Debug, Clone)]
pub struct CallInfo {
    /// Unique call identifier.
    pub id: String,
    /// Current call state.
    pub state: CallState,
    /// Call direction.
    pub direction: CallDirection,
    /// Remote party URI.
    pub remote_uri: String,
    /// Remote party display name (if available).
    pub remote_display_name: Option<String>,
    /// When the call was initiated.
    pub start_time: DateTime<Utc>,
    /// When the call was connected (if connected).
    pub connect_time: Option<DateTime<Utc>>,
    /// Whether local audio is muted.
    pub is_muted: bool,
    /// Whether the call is on hold.
    pub is_on_hold: bool,
    /// Failure reason (if failed).
    pub failure_reason: Option<CallFailureReason>,
}

impl CallInfo {
    /// Returns the call duration if connected.
    pub fn duration(&self) -> Option<Duration> {
        self.connect_time.map(|ct| {
            let now = Utc::now();
            let diff = now.signed_duration_since(ct);
            Duration::from_secs(diff.num_seconds().max(0).cast_unsigned())
        })
    }

    /// Returns a formatted duration string (MM:SS or HH:MM:SS).
    pub fn duration_string(&self) -> String {
        self.duration().map_or_else(
            || "0:00".to_string(),
            |d| {
                let total_secs = d.as_secs();
                let hours = total_secs / 3600;
                let minutes = (total_secs % 3600) / 60;
                let seconds = total_secs % 60;

                if hours > 0 {
                    format!("{hours}:{minutes:02}:{seconds:02}")
                } else {
                    format!("{minutes}:{seconds:02}")
                }
            },
        )
    }
}

/// Call history entry for persistent storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallHistoryEntry {
    /// Unique identifier.
    pub id: String,
    /// Remote party URI.
    pub remote_uri: String,
    /// Remote party display name (if available).
    pub remote_display_name: Option<String>,
    /// Call direction.
    pub direction: CallDirection,
    /// When the call was initiated.
    pub start_time: DateTime<Utc>,
    /// When the call was connected (if it was).
    pub connect_time: Option<DateTime<Utc>>,
    /// When the call ended.
    pub end_time: DateTime<Utc>,
    /// How the call ended.
    pub end_reason: CallEndReason,
    /// Call duration in seconds (if connected).
    pub duration_secs: Option<u64>,
}

impl CallHistoryEntry {
    /// Creates a new call history entry from a completed call.
    pub fn from_call_info(info: &CallInfo, end_reason: CallEndReason) -> Self {
        let now = Utc::now();
        let duration_secs = info.connect_time.map(|ct| {
            let diff = now.signed_duration_since(ct);
            diff.num_seconds().max(0).cast_unsigned()
        });

        Self {
            id: info.id.clone(),
            remote_uri: info.remote_uri.clone(),
            remote_display_name: info.remote_display_name.clone(),
            direction: info.direction,
            start_time: info.start_time,
            connect_time: info.connect_time,
            end_time: now,
            end_reason,
            duration_secs,
        }
    }

    /// Returns a formatted duration string.
    pub fn duration_string(&self) -> String {
        self.duration_secs.map_or_else(
            || "0:00".to_string(),
            |total_secs| {
                let hours = total_secs / 3600;
                let minutes = (total_secs % 3600) / 60;
                let seconds = total_secs % 60;

                if hours > 0 {
                    format!("{hours}:{minutes:02}:{seconds:02}")
                } else {
                    format!("{minutes}:{seconds:02}")
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_state_display() {
        assert_eq!(CallState::Idle.to_string(), "Idle");
        assert_eq!(CallState::Connected.to_string(), "Connected");
    }

    #[test]
    fn test_call_state_is_active() {
        assert!(!CallState::Idle.is_active());
        assert!(CallState::Dialing.is_active());
        assert!(CallState::Connected.is_active());
        assert!(!CallState::Terminated.is_active());
    }

    #[test]
    fn test_call_state_has_media() {
        assert!(!CallState::Dialing.has_media());
        assert!(CallState::EarlyMedia.has_media());
        assert!(CallState::Connected.has_media());
        assert!(!CallState::OnHold.has_media());
    }
}
