//! FFI mirror types.
//!
//! These flatten the `client-types`/`client-core` types into shapes UniFFI can
//! lower into Swift/Kotlin/C#. They are deliberately decoupled from the core
//! crates so the core API can evolve without breaking the foreign-language ABI;
//! conversions live next to each type.

use client_core::AppError;

/// SIP registration state for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RegistrationState {
    /// Not registered.
    Unregistered,
    /// Waiting for smart card PIN entry.
    WaitingForPin,
    /// Registration in progress.
    Registering,
    /// Successfully registered.
    Registered,
    /// Registration refresh pending.
    RefreshPending,
    /// Registration failed.
    Failed,
    /// Smart card not present.
    SmartCardNotPresent,
    /// Certificate expired or invalid.
    CertificateInvalid,
}

impl From<client_types::RegistrationState> for RegistrationState {
    fn from(value: client_types::RegistrationState) -> Self {
        use client_types::RegistrationState as Core;
        match value {
            Core::Unregistered => Self::Unregistered,
            Core::WaitingForPin => Self::WaitingForPin,
            Core::Registering => Self::Registering,
            Core::Registered => Self::Registered,
            Core::RefreshPending => Self::RefreshPending,
            Core::Failed => Self::Failed,
            Core::SmartCardNotPresent => Self::SmartCardNotPresent,
            Core::CertificateInvalid => Self::CertificateInvalid,
        }
    }
}

/// Call lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
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

impl From<client_types::CallState> for CallState {
    fn from(value: client_types::CallState) -> Self {
        use client_types::CallState as Core;
        match value {
            Core::Idle => Self::Idle,
            Core::Dialing => Self::Dialing,
            Core::Ringing => Self::Ringing,
            Core::EarlyMedia => Self::EarlyMedia,
            Core::Connecting => Self::Connecting,
            Core::Connected => Self::Connected,
            Core::OnHold => Self::OnHold,
            Core::Transferring => Self::Transferring,
            Core::Terminating => Self::Terminating,
            Core::Terminated => Self::Terminated,
        }
    }
}

/// Which side initiated the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CallDirection {
    /// Outgoing call (we initiated).
    Outbound,
    /// Incoming call (they initiated).
    Inbound,
}

impl From<client_types::CallDirection> for CallDirection {
    fn from(value: client_types::CallDirection) -> Self {
        match value {
            client_types::CallDirection::Outbound => Self::Outbound,
            client_types::CallDirection::Inbound => Self::Inbound,
        }
    }
}

/// Snapshot of an active call.
#[derive(Debug, Clone, uniffi::Record)]
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
    /// When the call was initiated (Unix epoch, milliseconds).
    pub start_time_unix_ms: i64,
    /// When the call was connected (Unix epoch, milliseconds), if connected.
    pub connect_time_unix_ms: Option<i64>,
    /// Whether local audio is muted.
    pub is_muted: bool,
    /// Whether the call is on hold.
    pub is_on_hold: bool,
    /// Failure description (if the call failed).
    pub failure_reason: Option<String>,
}

impl From<client_types::CallInfo> for CallInfo {
    fn from(value: client_types::CallInfo) -> Self {
        Self {
            id: value.id,
            state: value.state.into(),
            direction: value.direction.into(),
            remote_uri: value.remote_uri,
            remote_display_name: value.remote_display_name,
            start_time_unix_ms: value.start_time.timestamp_millis(),
            connect_time_unix_ms: value.connect_time.map(|t| t.timestamp_millis()),
            is_muted: value.is_muted,
            is_on_hold: value.is_on_hold,
            failure_reason: value.failure_reason.map(|r| format!("{r:?}")),
        }
    }
}

/// Operation that requires a smart card PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PinOperation {
    /// Certificate selection for authentication.
    CertificateSelection,
    /// SIP registration.
    Registration,
    /// Call establishment (DTLS signing).
    CallEstablishment,
}

impl From<client_core::PinOperationType> for PinOperation {
    fn from(value: client_core::PinOperationType) -> Self {
        use client_core::PinOperationType as Core;
        match value {
            Core::CertificateSelection => Self::CertificateSelection,
            Core::Registration => Self::Registration,
            Core::CallEstablishment => Self::CallEstablishment,
        }
    }
}

/// Application events pushed to the shell's [`crate::EventListener`].
///
/// Mirrors `client_core::AppEvent`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum AppEvent {
    /// Registration state changed.
    RegistrationStateChanged {
        /// Account ID.
        account_id: String,
        /// New state.
        state: RegistrationState,
    },
    /// Call state changed.
    CallStateChanged {
        /// Call ID.
        call_id: String,
        /// New state.
        state: CallState,
        /// Call info snapshot.
        info: CallInfo,
    },
    /// Incoming call.
    IncomingCall {
        /// Call ID.
        call_id: String,
        /// Remote party URI.
        remote_uri: String,
        /// Remote party display name.
        remote_display_name: Option<String>,
    },
    /// Incoming call cancelled by remote party before answer.
    IncomingCallCancelled {
        /// Call ID.
        call_id: String,
    },
    /// Call ended.
    CallEnded {
        /// Call ID.
        call_id: String,
        /// Duration in seconds (if connected).
        duration_secs: Option<u64>,
    },
    /// Error occurred.
    Error {
        /// Error message.
        message: String,
    },
    /// Settings changed.
    SettingsChanged,
    /// Contacts changed.
    ContactsChanged,
    /// PIN required for smart card operation.
    PinRequired {
        /// Operation that requires the PIN.
        operation: PinOperation,
        /// Certificate thumbprint (if applicable).
        thumbprint: Option<String>,
    },
    /// PIN entry completed.
    PinCompleted {
        /// Whether the PIN was accepted.
        success: bool,
        /// Error message if failed.
        error: Option<String>,
    },
    /// Transfer progress update (RFC 3515 REFER NOTIFY).
    TransferProgress {
        /// Call ID being transferred.
        call_id: String,
        /// Transfer target URI.
        target_uri: String,
        /// SIP status code (100=Trying, 180=Ringing, 200=Success, ...).
        status_code: u16,
        /// Whether the transfer succeeded.
        is_success: bool,
        /// Whether this is the final status.
        is_final: bool,
    },
    /// DTMF digit received via SIP INFO.
    DtmfReceived {
        /// Call ID.
        call_id: String,
        /// DTMF digit (one of `0-9 * # A-D`).
        digit: String,
        /// Duration in timestamp units.
        duration: u16,
    },
}

impl From<client_core::AppEvent> for AppEvent {
    fn from(value: client_core::AppEvent) -> Self {
        use client_core::AppEvent as Core;
        match value {
            Core::RegistrationStateChanged { account_id, state } => {
                Self::RegistrationStateChanged {
                    account_id,
                    state: state.into(),
                }
            }
            Core::CallStateChanged {
                call_id,
                state,
                info,
            } => Self::CallStateChanged {
                call_id,
                state: state.into(),
                info: info.into(),
            },
            Core::IncomingCall {
                call_id,
                remote_uri,
                remote_display_name,
            } => Self::IncomingCall {
                call_id,
                remote_uri,
                remote_display_name,
            },
            Core::IncomingCallCancelled { call_id } => Self::IncomingCallCancelled { call_id },
            Core::CallEnded {
                call_id,
                duration_secs,
            } => Self::CallEnded {
                call_id,
                duration_secs,
            },
            Core::Error { message } => Self::Error { message },
            Core::SettingsChanged => Self::SettingsChanged,
            Core::ContactsChanged => Self::ContactsChanged,
            Core::PinRequired {
                operation,
                thumbprint,
            } => Self::PinRequired {
                operation: operation.into(),
                thumbprint,
            },
            Core::PinCompleted { success, error } => Self::PinCompleted { success, error },
            Core::TransferProgress {
                call_id,
                target_uri,
                status_code,
                is_success,
                is_final,
            } => Self::TransferProgress {
                call_id,
                target_uri,
                status_code,
                is_success,
                is_final,
            },
            Core::DtmfReceived {
                call_id,
                digit,
                duration,
            } => Self::DtmfReceived {
                call_id,
                digit: digit.to_string(),
                duration,
            },
        }
    }
}

/// Audio device kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AudioDeviceKind {
    /// Input (microphone).
    Input,
    /// Output (speaker/headphone).
    Output,
}

impl From<client_types::audio::AudioDeviceType> for AudioDeviceKind {
    fn from(value: client_types::audio::AudioDeviceType) -> Self {
        match value {
            client_types::audio::AudioDeviceType::Input => Self::Input,
            client_types::audio::AudioDeviceType::Output => Self::Output,
        }
    }
}

/// Detected device category (selects the audio-processing profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AudioDeviceCategory {
    /// Built-in speakers.
    BuiltInSpeaker,
    /// Built-in microphone.
    BuiltInMic,
    /// USB headset.
    UsbHeadset,
    /// Bluetooth HFP/A2DP device.
    Bluetooth,
    /// Conference speakerphone.
    Speakerphone,
    /// Unknown or unrecognized device.
    Unknown,
}

impl From<client_types::audio::DeviceCategory> for AudioDeviceCategory {
    fn from(value: client_types::audio::DeviceCategory) -> Self {
        use client_types::audio::DeviceCategory as Core;
        match value {
            Core::BuiltInSpeaker => Self::BuiltInSpeaker,
            Core::BuiltInMic => Self::BuiltInMic,
            Core::UsbHeadset => Self::UsbHeadset,
            Core::Bluetooth => Self::Bluetooth,
            Core::Speakerphone => Self::Speakerphone,
            Core::Unknown => Self::Unknown,
        }
    }
}

/// An audio capture or playback device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AudioDevice {
    /// Device name/identifier (pass back to `switch_*_device`).
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Whether this is the system default device.
    pub is_default: bool,
    /// Device kind (input/output).
    pub kind: AudioDeviceKind,
    /// Detected category.
    pub category: AudioDeviceCategory,
    /// Number of channels supported.
    pub channels: u16,
    /// Supported sample rates.
    pub sample_rates: Vec<u32>,
}

impl From<client_types::AudioDevice> for AudioDevice {
    fn from(value: client_types::AudioDevice) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            is_default: value.is_default,
            kind: value.device_type.into(),
            category: value.category.into(),
            channels: value.channels,
            sample_rates: value.sample_rates,
        }
    }
}

/// Errors surfaced across the FFI boundary.
#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
pub enum ClientError {
    /// SIP signaling error.
    #[error("SIP error: {message}")]
    Sip {
        /// Error detail.
        message: String,
    },
    /// Audio subsystem error.
    #[error("audio error: {message}")]
    Audio {
        /// Error detail.
        message: String,
    },
    /// Settings/contacts/filesystem error.
    #[error("storage error: {message}")]
    Storage {
        /// Error detail.
        message: String,
    },
    /// Smart card error.
    #[error("smart card error: {message}")]
    SmartCard {
        /// Error detail.
        message: String,
    },
    /// Caller passed an invalid argument.
    #[error("invalid argument: {message}")]
    InvalidArgument {
        /// Error detail.
        message: String,
    },
    /// Internal error (lock poisoning, runtime failure).
    #[error("internal error: {message}")]
    Internal {
        /// Error detail.
        message: String,
    },
}

impl From<AppError> for ClientError {
    fn from(value: AppError) -> Self {
        match value {
            AppError::Sip(message) => Self::Sip { message },
            AppError::Audio(message) => Self::Audio { message },
            AppError::Settings(message)
            | AppError::Contact(message)
            | AppError::Serialization(message) => Self::Storage { message },
            AppError::SmartCard(message) => Self::SmartCard { message },
            AppError::Io(e) => Self::Storage {
                message: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_state_maps_all_variants() {
        assert_eq!(
            RegistrationState::from(client_types::RegistrationState::Registered),
            RegistrationState::Registered
        );
        assert_eq!(
            RegistrationState::from(client_types::RegistrationState::WaitingForPin),
            RegistrationState::WaitingForPin
        );
    }

    #[test]
    fn app_event_dtmf_digit_becomes_string() {
        let event = AppEvent::from(client_core::AppEvent::DtmfReceived {
            call_id: "abc".to_string(),
            digit: '#',
            duration: 160,
        });
        match event {
            AppEvent::DtmfReceived { digit, .. } => assert_eq!(digit, "#"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn app_error_maps_to_storage_for_io() {
        let err = ClientError::from(AppError::Io(std::io::Error::other("disk gone")));
        assert!(matches!(err, ClientError::Storage { .. }));
    }
}
