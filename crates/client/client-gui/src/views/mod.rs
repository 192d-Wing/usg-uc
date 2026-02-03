//! GUI views for the SIP soft client.

mod call;
mod contacts;
mod dialer;
mod settings;

pub use call::{CallAction, CallView};
pub use contacts::{ContactsAction, ContactsView};
pub use dialer::{DialerAction, DialerView};
pub use settings::{SettingsAction, SettingsView};
