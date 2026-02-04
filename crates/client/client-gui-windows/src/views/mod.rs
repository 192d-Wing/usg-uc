//! GUI views for the SIP soft client using native Windows controls.

mod call;
mod contacts;
mod dialer;
mod settings;

pub use call::CallView;
pub use contacts::ContactsView;
pub use dialer::DialerView;
pub use settings::SettingsView;
