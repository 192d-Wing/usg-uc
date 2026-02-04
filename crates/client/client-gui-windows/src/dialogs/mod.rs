//! Custom dialog windows for the SIP soft client.

mod contact_dialog;
mod dtmf_dialog;
mod pin_dialog;
mod transfer_dialog;

pub use contact_dialog::{ContactDialog, ContactDialogResult};
pub use dtmf_dialog::{DtmfAction, DtmfDialog};
pub use pin_dialog::{PinDialog, PinDialogResult};
pub use transfer_dialog::{TransferDialog, TransferDialogResult};
