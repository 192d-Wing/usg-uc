//! Dialog forking support per RFC 3261 Section 12.2.2.
//!
//! When a UAC sends an INVITE that is forked by a proxy, it may receive
//! multiple provisional responses with different To tags, creating
//! multiple early dialogs. This module manages these parallel dialogs.
//!
//! ## RFC 3261 Compliance
//!
//! Per RFC 3261 Section 12.2.2:
//! - Each provisional response with a different To tag creates a new early dialog
//! - The UAC MUST be prepared to receive multiple final responses
//! - When a 2xx is received, only that dialog is confirmed; others are terminated
//! - When a non-2xx final response is received, that early dialog is terminated

use crate::dialog::{Dialog, DialogId, DialogRole};
use crate::error::{DialogError, DialogResult};
use std::collections::HashMap;

/// Key for matching forked responses to the originating request.
///
/// Before the remote tag is known, responses are matched by Call-ID and local tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForkKey {
    /// Call-ID.
    pub call_id: String,
    /// Local tag (From tag for UAC).
    pub local_tag: String,
}

impl ForkKey {
    /// Creates a new fork key.
    pub fn new(call_id: impl Into<String>, local_tag: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            local_tag: local_tag.into(),
        }
    }

    /// Creates a fork key from a dialog ID.
    pub fn from_dialog_id(id: &DialogId) -> Self {
        Self {
            call_id: id.call_id.clone(),
            local_tag: id.local_tag.clone(),
        }
    }
}

impl std::fmt::Display for ForkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.call_id, self.local_tag)
    }
}

/// Manages a set of forked early dialogs from a single INVITE.
///
/// Per RFC 3261 Section 12.2.2, a UAC that sends an INVITE may receive
/// responses from multiple UASes (via forking proxy). Each response with
/// a different To tag creates a separate early dialog.
#[derive(Debug)]
pub struct ForkedDialogSet {
    /// The fork key (Call-ID + local tag).
    key: ForkKey,
    /// Early dialogs indexed by remote tag.
    early_dialogs: HashMap<String, Dialog>,
    /// The confirmed dialog (if any).
    confirmed_dialog: Option<Dialog>,
    /// Terminated dialogs (for tracking).
    terminated_count: usize,
    /// Local URI for creating dialogs.
    local_uri: String,
    /// Remote URI (Request-URI of INVITE).
    remote_uri: String,
    /// Initial CSeq of the INVITE.
    initial_cseq: u32,
}

impl ForkedDialogSet {
    /// Creates a new forked dialog set.
    ///
    /// # Arguments
    ///
    /// * `call_id` - Call-ID of the INVITE
    /// * `local_tag` - From tag of the UAC
    /// * `local_uri` - From URI
    /// * `remote_uri` - To URI / Request-URI
    /// * `initial_cseq` - CSeq of the INVITE
    pub fn new(
        call_id: impl Into<String>,
        local_tag: impl Into<String>,
        local_uri: impl Into<String>,
        remote_uri: impl Into<String>,
        initial_cseq: u32,
    ) -> Self {
        Self {
            key: ForkKey::new(call_id, local_tag),
            early_dialogs: HashMap::new(),
            confirmed_dialog: None,
            terminated_count: 0,
            local_uri: local_uri.into(),
            remote_uri: remote_uri.into(),
            initial_cseq,
        }
    }

    /// Returns the fork key.
    pub fn key(&self) -> &ForkKey {
        &self.key
    }

    /// Returns the number of active early dialogs.
    pub fn early_dialog_count(&self) -> usize {
        self.early_dialogs.len()
    }

    /// Returns the number of terminated dialogs.
    pub fn terminated_count(&self) -> usize {
        self.terminated_count
    }

    /// Returns true if a dialog has been confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_dialog.is_some()
    }

    /// Returns true if all early dialogs have been resolved.
    pub fn is_resolved(&self) -> bool {
        self.early_dialogs.is_empty()
    }

    /// Returns the confirmed dialog, if any.
    pub fn confirmed_dialog(&self) -> Option<&Dialog> {
        self.confirmed_dialog.as_ref()
    }

    /// Returns a mutable reference to the confirmed dialog.
    pub fn confirmed_dialog_mut(&mut self) -> Option<&mut Dialog> {
        self.confirmed_dialog.as_mut()
    }

    /// Returns an iterator over early dialogs.
    pub fn early_dialogs(&self) -> impl Iterator<Item = &Dialog> {
        self.early_dialogs.values()
    }

    /// Gets an early dialog by remote tag.
    pub fn get_early_dialog(&self, remote_tag: &str) -> Option<&Dialog> {
        self.early_dialogs.get(remote_tag)
    }

    /// Gets a mutable reference to an early dialog by remote tag.
    pub fn get_early_dialog_mut(&mut self, remote_tag: &str) -> Option<&mut Dialog> {
        self.early_dialogs.get_mut(remote_tag)
    }

    /// Processes a provisional response (1xx).
    ///
    /// Per RFC 3261 Section 12.2.2, a provisional response with a new To tag
    /// creates a new early dialog. Returns a reference to the dialog.
    ///
    /// # Arguments
    ///
    /// * `remote_tag` - The To tag from the response
    /// * `remote_target` - The Contact URI from the response (if present)
    /// * `route_set` - The Record-Route headers from the response
    pub fn receive_provisional(
        &mut self,
        remote_tag: impl Into<String>,
        remote_target: Option<String>,
        route_set: Vec<String>,
    ) -> DialogResult<&Dialog> {
        let remote_tag = remote_tag.into();

        // If dialog already confirmed, reject
        if self.confirmed_dialog.is_some() {
            return Err(DialogError::InvalidStateTransition {
                from: "Confirmed".to_string(),
                to: "new early dialog".to_string(),
            });
        }

        // Check if we already have this early dialog
        if !self.early_dialogs.contains_key(&remote_tag) {
            // Create new early dialog
            let dialog_id = DialogId::new(
                self.key.call_id.clone(),
                self.key.local_tag.clone(),
                remote_tag.clone(),
            );

            let mut dialog = Dialog::new(
                dialog_id,
                DialogRole::Uac,
                self.local_uri.clone(),
                self.remote_uri.clone(),
                self.initial_cseq,
            );

            if let Some(target) = remote_target {
                dialog.set_remote_target(target);
            }

            dialog.set_route_set(route_set);

            self.early_dialogs.insert(remote_tag.clone(), dialog);
        }

        // Return reference to the dialog
        self.early_dialogs
            .get(&remote_tag)
            .ok_or_else(|| DialogError::NotFound {
                dialog_id: format!("{}:{}", self.key.call_id, remote_tag),
            })
    }

    /// Processes a 2xx final response.
    ///
    /// Per RFC 3261 Section 12.2.2, when a 2xx response is received:
    /// - The dialog with that To tag is confirmed
    /// - All other early dialogs SHOULD be terminated (with BYE or CANCEL)
    ///
    /// Returns the confirmed dialog and the list of early dialogs to terminate.
    pub fn receive_2xx(
        &mut self,
        remote_tag: impl Into<String>,
        remote_target: Option<String>,
        route_set: Vec<String>,
    ) -> DialogResult<Vec<Dialog>> {
        let remote_tag = remote_tag.into();

        if self.confirmed_dialog.is_some() {
            // Already confirmed - this is a retransmission or late response
            return Ok(Vec::new());
        }

        // Get or create the dialog for this To tag
        let dialog = if let Some(mut d) = self.early_dialogs.remove(&remote_tag) {
            // Existing early dialog
            d.confirm()?;
            if let Some(target) = remote_target {
                d.set_remote_target(target);
            }
            if !route_set.is_empty() {
                d.set_route_set(route_set);
            }
            d
        } else {
            // New dialog (no provisional received for this tag)
            let dialog_id = DialogId::new(
                self.key.call_id.clone(),
                self.key.local_tag.clone(),
                remote_tag.clone(),
            );

            let mut dialog = Dialog::new(
                dialog_id,
                DialogRole::Uac,
                self.local_uri.clone(),
                self.remote_uri.clone(),
                self.initial_cseq,
            );

            if let Some(target) = remote_target {
                dialog.set_remote_target(target);
            }

            dialog.set_route_set(route_set);
            dialog.confirm()?;
            dialog
        };

        self.confirmed_dialog = Some(dialog);

        // Collect remaining early dialogs for termination
        let to_terminate: Vec<Dialog> = self.early_dialogs.drain().map(|(_, d)| d).collect();
        self.terminated_count += to_terminate.len();

        Ok(to_terminate)
    }

    /// Processes a non-2xx final response (3xx-6xx).
    ///
    /// Per RFC 3261 Section 12.2.2, a non-2xx final response terminates
    /// only the specific early dialog identified by the To tag.
    ///
    /// Returns true if there are still other early dialogs pending.
    pub fn receive_error(
        &mut self,
        remote_tag: impl Into<String>,
        _status_code: u16,
    ) -> DialogResult<bool> {
        let remote_tag = remote_tag.into();

        // If no remote tag, this terminates the entire fork set
        if remote_tag.is_empty() {
            let count = self.early_dialogs.len();
            self.early_dialogs.clear();
            self.terminated_count += count;
            return Ok(false);
        }

        // Remove the specific early dialog
        if self.early_dialogs.remove(&remote_tag).is_some() {
            self.terminated_count += 1;
        }

        Ok(!self.early_dialogs.is_empty())
    }

    /// Terminates all remaining early dialogs.
    ///
    /// Call this when the UAC cancels the INVITE or times out.
    pub fn terminate_all(&mut self) -> Vec<Dialog> {
        let dialogs: Vec<Dialog> = self.early_dialogs.drain().map(|(_, d)| d).collect();
        self.terminated_count += dialogs.len();
        dialogs
    }

    /// Takes ownership of the confirmed dialog.
    ///
    /// After calling this, the ForkedDialogSet no longer manages the dialog.
    pub fn take_confirmed_dialog(&mut self) -> Option<Dialog> {
        self.confirmed_dialog.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DialogState;

    fn test_fork_set() -> ForkedDialogSet {
        ForkedDialogSet::new(
            "call-123@example.com",
            "from-tag-abc",
            "sip:alice@example.com",
            "sip:bob@example.com",
            1,
        )
    }

    #[test]
    fn test_fork_key() {
        let key = ForkKey::new("call-123", "tag-abc");
        assert_eq!(key.call_id, "call-123");
        assert_eq!(key.local_tag, "tag-abc");
        assert_eq!(key.to_string(), "call-123:tag-abc");
    }

    #[test]
    fn test_forked_dialog_set_creation() {
        let set = test_fork_set();
        assert_eq!(set.early_dialog_count(), 0);
        assert!(!set.is_confirmed());
        assert!(set.is_resolved());
    }

    #[test]
    fn test_receive_provisional_creates_early_dialog() {
        let mut set = test_fork_set();

        // First provisional with tag "branch1"
        set.receive_provisional("branch1", Some("sip:bob@host1".to_string()), vec![])
            .unwrap();
        assert_eq!(set.early_dialog_count(), 1);
        assert!(!set.is_resolved());

        // Second provisional with different tag "branch2"
        set.receive_provisional("branch2", Some("sip:bob@host2".to_string()), vec![])
            .unwrap();
        assert_eq!(set.early_dialog_count(), 2);

        // Same tag should not create new dialog
        set.receive_provisional("branch1", None, vec![]).unwrap();
        assert_eq!(set.early_dialog_count(), 2);
    }

    #[test]
    fn test_receive_2xx_confirms_one_terminates_others() {
        let mut set = test_fork_set();

        // Create two early dialogs
        set.receive_provisional("branch1", Some("sip:bob@host1".to_string()), vec![])
            .unwrap();
        set.receive_provisional("branch2", Some("sip:bob@host2".to_string()), vec![])
            .unwrap();
        assert_eq!(set.early_dialog_count(), 2);

        // Receive 2xx for branch1
        let to_terminate = set
            .receive_2xx("branch1", Some("sip:bob@host1".to_string()), vec![])
            .unwrap();

        assert!(set.is_confirmed());
        assert_eq!(set.early_dialog_count(), 0);
        assert_eq!(to_terminate.len(), 1); // branch2 should be terminated

        // Check confirmed dialog
        let confirmed = set.confirmed_dialog().unwrap();
        assert_eq!(confirmed.state(), DialogState::Confirmed);
        assert_eq!(confirmed.id().remote_tag, "branch1");
    }

    #[test]
    fn test_receive_2xx_without_prior_provisional() {
        let mut set = test_fork_set();

        // Receive 2xx directly without provisional
        let to_terminate = set
            .receive_2xx("new-tag", Some("sip:bob@host".to_string()), vec![])
            .unwrap();

        assert!(set.is_confirmed());
        assert!(to_terminate.is_empty());

        let confirmed = set.confirmed_dialog().unwrap();
        assert_eq!(confirmed.id().remote_tag, "new-tag");
    }

    #[test]
    fn test_receive_error_terminates_one_dialog() {
        let mut set = test_fork_set();

        // Create two early dialogs
        set.receive_provisional("branch1", None, vec![]).unwrap();
        set.receive_provisional("branch2", None, vec![]).unwrap();
        assert_eq!(set.early_dialog_count(), 2);

        // Receive 486 for branch1
        let has_more = set.receive_error("branch1", 486).unwrap();
        assert!(has_more);
        assert_eq!(set.early_dialog_count(), 1);

        // Receive 503 for branch2
        let has_more = set.receive_error("branch2", 503).unwrap();
        assert!(!has_more);
        assert_eq!(set.early_dialog_count(), 0);
        assert!(set.is_resolved());
    }

    #[test]
    fn test_receive_error_without_tag_terminates_all() {
        let mut set = test_fork_set();

        set.receive_provisional("branch1", None, vec![]).unwrap();
        set.receive_provisional("branch2", None, vec![]).unwrap();

        // Error without tag terminates all
        let has_more = set.receive_error("", 408).unwrap();
        assert!(!has_more);
        assert_eq!(set.early_dialog_count(), 0);
        assert_eq!(set.terminated_count(), 2);
    }

    #[test]
    fn test_terminate_all() {
        let mut set = test_fork_set();

        set.receive_provisional("branch1", None, vec![]).unwrap();
        set.receive_provisional("branch2", None, vec![]).unwrap();
        set.receive_provisional("branch3", None, vec![]).unwrap();

        let terminated = set.terminate_all();
        assert_eq!(terminated.len(), 3);
        assert_eq!(set.early_dialog_count(), 0);
        assert_eq!(set.terminated_count(), 3);
    }

    #[test]
    fn test_take_confirmed_dialog() {
        let mut set = test_fork_set();

        set.receive_2xx("tag", None, vec![]).unwrap();
        assert!(set.confirmed_dialog().is_some());

        let dialog = set.take_confirmed_dialog();
        assert!(dialog.is_some());
        assert!(set.confirmed_dialog().is_none());
    }

    #[test]
    fn test_provisional_after_confirmed_fails() {
        let mut set = test_fork_set();

        // Confirm a dialog
        set.receive_2xx("tag1", None, vec![]).unwrap();

        // Trying to add a new early dialog should fail
        let result = set.receive_provisional("tag2", None, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_early_dialog_access() {
        let mut set = test_fork_set();

        set.receive_provisional(
            "branch1",
            Some("sip:bob@host1".to_string()),
            vec!["<sip:proxy;lr>".to_string()],
        )
        .unwrap();

        let dialog = set.get_early_dialog("branch1").unwrap();
        assert_eq!(dialog.remote_target(), Some("sip:bob@host1"));
        assert_eq!(dialog.route_set().len(), 1);

        // Non-existent tag
        assert!(set.get_early_dialog("nonexistent").is_none());
    }
}
