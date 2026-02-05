//! Windows toast notifications for incoming calls and events.
//!
//! Uses winrt-notification for native Windows toast support.

use tracing::{error, info};
use winrt_notification::{Duration, Sound, Toast};

/// Notification types for the SIP client.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum NotificationType {
    /// Incoming call notification.
    IncomingCall {
        /// Caller's display name (if available).
        caller_name: Option<String>,
        /// Caller's SIP URI.
        caller_uri: String,
    },
    /// Missed call notification.
    MissedCall {
        /// Caller's display name (if available).
        caller_name: Option<String>,
        /// Caller's SIP URI.
        caller_uri: String,
    },
    /// Registration state change notification.
    RegistrationChanged {
        /// Whether registration succeeded.
        registered: bool,
        /// Account identifier.
        account_id: String,
    },
    /// Call ended notification.
    CallEnded {
        /// Remote party name.
        remote_name: Option<String>,
        /// Call duration in seconds.
        duration_secs: Option<u64>,
    },
    /// Error notification.
    Error {
        /// Error title.
        title: String,
        /// Error message.
        message: String,
    },
}

/// Notification manager for Windows toast notifications.
#[allow(dead_code)]
pub struct NotificationManager {
    /// Application name for notifications.
    app_name: String,
    /// Whether notifications are enabled.
    enabled: bool,
}

impl NotificationManager {
    /// Creates a new notification manager.
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            enabled: true,
        }
    }

    /// Enables or disables notifications.
    #[allow(dead_code)]
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Shows a notification.
    pub fn show(&self, notification: NotificationType) {
        if !self.enabled {
            return;
        }

        let result = match notification {
            NotificationType::IncomingCall {
                caller_name,
                caller_uri,
            } => {
                let title = "Incoming Call";
                let body = if let Some(name) = caller_name {
                    format!("{}\n{}", name, caller_uri)
                } else {
                    caller_uri
                };

                Toast::new(&self.app_name)
                    .title(title)
                    .text1(&body)
                    .sound(Some(Sound::IM))
                    .duration(Duration::Long)
                    .show()
            }
            NotificationType::MissedCall {
                caller_name,
                caller_uri,
            } => {
                let title = "Missed Call";
                let body = if let Some(name) = caller_name {
                    format!("{}\n{}", name, caller_uri)
                } else {
                    caller_uri
                };

                Toast::new(&self.app_name)
                    .title(title)
                    .text1(&body)
                    .sound(Some(Sound::SMS))
                    .duration(Duration::Short)
                    .show()
            }
            NotificationType::RegistrationChanged {
                registered,
                account_id,
            } => {
                let title = if registered {
                    "Registered"
                } else {
                    "Registration Failed"
                };
                let body = format!("Account: {}", account_id);

                Toast::new(&self.app_name)
                    .title(title)
                    .text1(&body)
                    .duration(Duration::Short)
                    .show()
            }
            NotificationType::CallEnded {
                remote_name,
                duration_secs,
            } => {
                let title = "Call Ended";
                let body = match (remote_name, duration_secs) {
                    (Some(name), Some(duration)) => {
                        let mins = duration / 60;
                        let secs = duration % 60;
                        format!("{} - {}:{:02}", name, mins, secs)
                    }
                    (Some(name), None) => name,
                    (None, Some(duration)) => {
                        let mins = duration / 60;
                        let secs = duration % 60;
                        format!("Duration: {}:{:02}", mins, secs)
                    }
                    (None, None) => String::new(),
                };

                Toast::new(&self.app_name)
                    .title(title)
                    .text1(&body)
                    .duration(Duration::Short)
                    .show()
            }
            NotificationType::Error { title, message } => Toast::new(&self.app_name)
                .title(&title)
                .text1(&message)
                .duration(Duration::Short)
                .show(),
        };

        if let Err(e) = result {
            error!("Failed to show notification: {}", e);
        } else {
            info!("Notification shown");
        }
    }

    /// Shows an incoming call notification.
    #[allow(dead_code)]
    pub fn notify_incoming_call(&self, caller_name: Option<String>, caller_uri: String) {
        self.show(NotificationType::IncomingCall {
            caller_name,
            caller_uri,
        });
    }

    /// Shows a missed call notification.
    #[allow(dead_code)]
    pub fn notify_missed_call(&self, caller_name: Option<String>, caller_uri: String) {
        self.show(NotificationType::MissedCall {
            caller_name,
            caller_uri,
        });
    }

    /// Shows a registration state notification.
    #[allow(dead_code)]
    pub fn notify_registration(&self, registered: bool, account_id: String) {
        self.show(NotificationType::RegistrationChanged {
            registered,
            account_id,
        });
    }

    /// Shows a call ended notification.
    #[allow(dead_code)]
    pub fn notify_call_ended(&self, remote_name: Option<String>, duration_secs: Option<u64>) {
        self.show(NotificationType::CallEnded {
            remote_name,
            duration_secs,
        });
    }

    /// Shows an error notification.
    #[allow(dead_code)]
    pub fn notify_error(&self, title: &str, message: &str) {
        self.show(NotificationType::Error {
            title: title.to_string(),
            message: message.to_string(),
        });
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new("USG SIP Client")
    }
}
