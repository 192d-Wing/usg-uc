//! SIP dialog management.

use crate::error::{DialogError, DialogResult};
use crate::session_timer::SessionTimer;
use std::time::Instant;

/// Dialog state per RFC 3261.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    /// Early dialog (provisional response received).
    Early,
    /// Confirmed dialog (2xx received/sent).
    Confirmed,
    /// Dialog is being terminated.
    Terminating,
    /// Dialog has been terminated.
    Terminated,
}

impl std::fmt::Display for DialogState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Early => write!(f, "Early"),
            Self::Confirmed => write!(f, "Confirmed"),
            Self::Terminating => write!(f, "Terminating"),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

/// Dialog identifier per RFC 3261.
///
/// A dialog is uniquely identified by Call-ID, local tag, and remote tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    /// Call-ID header value.
    pub call_id: String,
    /// Local tag (from/to tag depending on role).
    pub local_tag: String,
    /// Remote tag (from/to tag depending on role).
    pub remote_tag: String,
}

impl DialogId {
    /// Creates a new dialog ID.
    pub fn new(
        call_id: impl Into<String>,
        local_tag: impl Into<String>,
        remote_tag: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            local_tag: local_tag.into(),
            remote_tag: remote_tag.into(),
        }
    }

    /// Creates a dialog ID for an early dialog (no remote tag yet).
    pub fn early(call_id: impl Into<String>, local_tag: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            local_tag: local_tag.into(),
            remote_tag: String::new(),
        }
    }

    /// Returns true if this is an early dialog ID (no remote tag).
    pub fn is_early(&self) -> bool {
        self.remote_tag.is_empty()
    }

    /// Updates the remote tag.
    pub fn set_remote_tag(&mut self, tag: impl Into<String>) {
        self.remote_tag = tag.into();
    }
}

impl std::fmt::Display for DialogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.remote_tag.is_empty() {
            write!(f, "{}:{}", self.call_id, self.local_tag)
        } else {
            write!(f, "{}:{}:{}", self.call_id, self.local_tag, self.remote_tag)
        }
    }
}

/// Dialog role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogRole {
    /// UAC (caller).
    Uac,
    /// UAS (callee).
    Uas,
}

impl std::fmt::Display for DialogRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uac => write!(f, "UAC"),
            Self::Uas => write!(f, "UAS"),
        }
    }
}

/// SIP dialog.
#[derive(Debug)]
pub struct Dialog {
    /// Dialog ID.
    id: DialogId,
    /// Current state.
    state: DialogState,
    /// Role in the dialog.
    role: DialogRole,
    /// Local CSeq number.
    local_cseq: u32,
    /// Remote CSeq number.
    remote_cseq: Option<u32>,
    /// Local URI.
    local_uri: String,
    /// Remote URI.
    remote_uri: String,
    /// Remote target (Contact URI).
    remote_target: Option<String>,
    /// Route set.
    route_set: Vec<String>,
    /// Session timer.
    session_timer: Option<SessionTimer>,
    /// When the dialog was created.
    created_at: Instant,
    /// When the dialog was confirmed.
    confirmed_at: Option<Instant>,
}

impl Dialog {
    /// Creates a new dialog.
    pub fn new(
        id: DialogId,
        role: DialogRole,
        local_uri: impl Into<String>,
        remote_uri: impl Into<String>,
        local_cseq: u32,
    ) -> Self {
        Self {
            id,
            state: DialogState::Early,
            role,
            local_cseq,
            remote_cseq: None,
            local_uri: local_uri.into(),
            remote_uri: remote_uri.into(),
            remote_target: None,
            route_set: Vec::new(),
            session_timer: None,
            created_at: Instant::now(),
            confirmed_at: None,
        }
    }

    /// Returns the dialog ID.
    pub fn id(&self) -> &DialogId {
        &self.id
    }

    /// Returns the current state.
    pub fn state(&self) -> DialogState {
        self.state
    }

    /// Returns the role.
    pub fn role(&self) -> DialogRole {
        self.role
    }

    /// Returns the local CSeq.
    pub fn local_cseq(&self) -> u32 {
        self.local_cseq
    }

    /// Returns the remote CSeq.
    pub fn remote_cseq(&self) -> Option<u32> {
        self.remote_cseq
    }

    /// Returns the local URI.
    pub fn local_uri(&self) -> &str {
        &self.local_uri
    }

    /// Returns the remote URI.
    pub fn remote_uri(&self) -> &str {
        &self.remote_uri
    }

    /// Returns the remote target.
    pub fn remote_target(&self) -> Option<&str> {
        self.remote_target.as_deref()
    }

    /// Returns the route set.
    pub fn route_set(&self) -> &[String] {
        &self.route_set
    }

    /// Returns when the dialog was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns when the dialog was confirmed.
    pub fn confirmed_at(&self) -> Option<Instant> {
        self.confirmed_at
    }

    /// Returns the session timer.
    pub fn session_timer(&self) -> Option<&SessionTimer> {
        self.session_timer.as_ref()
    }

    /// Sets the remote tag, completing the dialog ID.
    pub fn set_remote_tag(&mut self, tag: impl Into<String>) {
        self.id.set_remote_tag(tag);
    }

    /// Sets the remote target (Contact URI).
    pub fn set_remote_target(&mut self, target: impl Into<String>) {
        self.remote_target = Some(target.into());
    }

    /// Sets the route set.
    pub fn set_route_set(&mut self, routes: Vec<String>) {
        self.route_set = routes;
    }

    /// Sets the session timer.
    pub fn set_session_timer(&mut self, timer: SessionTimer) {
        self.session_timer = Some(timer);
    }

    /// Confirms the dialog (2xx received/sent).
    pub fn confirm(&mut self) -> DialogResult<()> {
        match self.state {
            DialogState::Early => {
                self.state = DialogState::Confirmed;
                self.confirmed_at = Some(Instant::now());
                Ok(())
            }
            DialogState::Confirmed => Ok(()), // Already confirmed
            _ => Err(DialogError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Confirmed".to_string(),
            }),
        }
    }

    /// Terminates the dialog.
    pub fn terminate(&mut self) -> DialogResult<()> {
        match self.state {
            DialogState::Terminated => Ok(()), // Already terminated
            _ => {
                self.state = DialogState::Terminated;
                Ok(())
            }
        }
    }

    /// Gets the next local CSeq and increments.
    pub fn next_local_cseq(&mut self) -> u32 {
        self.local_cseq += 1;
        self.local_cseq
    }

    /// Updates the remote CSeq.
    ///
    /// Returns error if CSeq is lower than expected (possible replay).
    pub fn update_remote_cseq(&mut self, cseq: u32) -> DialogResult<()> {
        if let Some(current) = self.remote_cseq {
            if cseq < current {
                return Err(DialogError::InvalidCSeq {
                    expected: current,
                    actual: cseq,
                });
            }
        }
        self.remote_cseq = Some(cseq);
        Ok(())
    }

    /// Checks if the dialog has been established.
    pub fn is_confirmed(&self) -> bool {
        self.state == DialogState::Confirmed
    }

    /// Checks if the dialog is terminated.
    pub fn is_terminated(&self) -> bool {
        self.state == DialogState::Terminated
    }

    /// Returns how long the dialog has been running.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Refreshes the session timer.
    pub fn refresh_session(&mut self) {
        if let Some(ref mut timer) = self.session_timer {
            timer.refresh();
        }
    }

    /// Checks if the session timer has expired.
    pub fn is_session_expired(&self) -> bool {
        self.session_timer
            .as_ref()
            .map(|t| t.is_expired())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dialog() -> Dialog {
        let id = DialogId::new("call-123", "local-tag", "remote-tag");
        Dialog::new(
            id,
            DialogRole::Uac,
            "sip:alice@example.com",
            "sip:bob@example.com",
            1,
        )
    }

    #[test]
    fn test_dialog_id() {
        let id = DialogId::new("call-123", "local-tag", "remote-tag");
        assert_eq!(id.call_id, "call-123");
        assert!(!id.is_early());

        let early_id = DialogId::early("call-456", "local-tag");
        assert!(early_id.is_early());
    }

    #[test]
    fn test_dialog_creation() {
        let dialog = test_dialog();
        assert_eq!(dialog.state(), DialogState::Early);
        assert_eq!(dialog.role(), DialogRole::Uac);
        assert_eq!(dialog.local_cseq(), 1);
    }

    #[test]
    fn test_dialog_confirm() {
        let mut dialog = test_dialog();

        dialog.confirm().unwrap();
        assert_eq!(dialog.state(), DialogState::Confirmed);
        assert!(dialog.confirmed_at().is_some());
        assert!(dialog.is_confirmed());
    }

    #[test]
    fn test_dialog_terminate() {
        let mut dialog = test_dialog();
        dialog.confirm().unwrap();

        dialog.terminate().unwrap();
        assert_eq!(dialog.state(), DialogState::Terminated);
        assert!(dialog.is_terminated());
    }

    #[test]
    fn test_cseq_management() {
        let mut dialog = test_dialog();

        // First remote CSeq
        dialog.update_remote_cseq(100).unwrap();
        assert_eq!(dialog.remote_cseq(), Some(100));

        // Higher CSeq OK
        dialog.update_remote_cseq(101).unwrap();
        assert_eq!(dialog.remote_cseq(), Some(101));

        // Lower CSeq should fail
        assert!(dialog.update_remote_cseq(99).is_err());
    }

    #[test]
    fn test_next_local_cseq() {
        let mut dialog = test_dialog();

        assert_eq!(dialog.local_cseq(), 1);
        assert_eq!(dialog.next_local_cseq(), 2);
        assert_eq!(dialog.next_local_cseq(), 3);
        assert_eq!(dialog.local_cseq(), 3);
    }

    #[test]
    fn test_route_set() {
        let mut dialog = test_dialog();

        let routes = vec![
            "<sip:proxy1.example.com;lr>".to_string(),
            "<sip:proxy2.example.com;lr>".to_string(),
        ];
        dialog.set_route_set(routes.clone());

        assert_eq!(dialog.route_set(), &routes);
    }

    #[test]
    fn test_dialog_role_display() {
        assert_eq!(DialogRole::Uac.to_string(), "UAC");
        assert_eq!(DialogRole::Uas.to_string(), "UAS");
    }
}
