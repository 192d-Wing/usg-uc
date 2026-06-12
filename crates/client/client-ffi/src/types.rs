//! FFI mirror types.
//!
//! These flatten the `client-types`/`client-core` types into shapes `UniFFI` can
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
    /// The registrar rejected the OIDC Bearer token (RFC 8898); the host
    /// should refresh the access token and re-register.
    TokenRefreshRequired {
        /// Account ID whose token needs refreshing.
        account_id: String,
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
            Core::TokenRefreshRequired { account_id } => Self::TokenRefreshRequired { account_id },
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

/// Phone number type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PhoneNumberKind {
    /// Work phone.
    Work,
    /// Mobile phone.
    Mobile,
    /// Home phone.
    Home,
    /// Fax number.
    Fax,
    /// Other type.
    Other,
}

impl From<client_types::PhoneNumberType> for PhoneNumberKind {
    fn from(value: client_types::PhoneNumberType) -> Self {
        use client_types::PhoneNumberType as Core;
        match value {
            Core::Work => Self::Work,
            Core::Mobile => Self::Mobile,
            Core::Home => Self::Home,
            Core::Fax => Self::Fax,
            Core::Other => Self::Other,
        }
    }
}

impl From<PhoneNumberKind> for client_types::PhoneNumberType {
    fn from(value: PhoneNumberKind) -> Self {
        match value {
            PhoneNumberKind::Work => Self::Work,
            PhoneNumberKind::Mobile => Self::Mobile,
            PhoneNumberKind::Home => Self::Home,
            PhoneNumberKind::Fax => Self::Fax,
            PhoneNumberKind::Other => Self::Other,
        }
    }
}

/// A contact's phone number with its type.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PhoneNumber {
    /// The phone number (E.164 format preferred).
    pub number: String,
    /// Type of phone number.
    pub kind: PhoneNumberKind,
    /// Custom label overriding the type name (optional).
    pub label: Option<String>,
}

impl From<client_types::PhoneNumber> for PhoneNumber {
    fn from(value: client_types::PhoneNumber) -> Self {
        Self {
            number: value.number,
            kind: value.number_type.into(),
            label: value.label,
        }
    }
}

impl From<PhoneNumber> for client_types::PhoneNumber {
    fn from(value: PhoneNumber) -> Self {
        Self {
            number: value.number,
            number_type: value.kind.into(),
            label: value.label,
        }
    }
}

/// A directory contact.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Contact {
    /// Unique identifier (generated by `add_contact`; pass back unchanged to
    /// `update_contact`/`remove_contact`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Primary SIP URI.
    pub sip_uri: String,
    /// Additional phone numbers.
    pub phone_numbers: Vec<PhoneNumber>,
    /// Whether this is a favorite contact.
    pub favorite: bool,
    /// Path to avatar image (optional).
    pub avatar_path: Option<String>,
    /// Organization/company name.
    pub organization: Option<String>,
    /// Notes about the contact.
    pub notes: Option<String>,
}

impl From<client_types::Contact> for Contact {
    fn from(value: client_types::Contact) -> Self {
        Self {
            id: value.id,
            name: value.name,
            sip_uri: value.sip_uri,
            phone_numbers: value.phone_numbers.into_iter().map(Into::into).collect(),
            favorite: value.favorite,
            avatar_path: value.avatar_path.map(|p| p.to_string_lossy().into_owned()),
            organization: value.organization,
            notes: value.notes,
        }
    }
}

impl From<Contact> for client_types::Contact {
    fn from(value: Contact) -> Self {
        Self {
            id: value.id,
            name: value.name,
            sip_uri: value.sip_uri,
            phone_numbers: value.phone_numbers.into_iter().map(Into::into).collect(),
            favorite: value.favorite,
            avatar_path: value.avatar_path.map(std::path::PathBuf::from),
            organization: value.organization,
            notes: value.notes,
        }
    }
}

/// Why a call ended (for call history).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CallEndReason {
    /// Normal hangup by local user.
    LocalHangup,
    /// Normal hangup by remote user.
    RemoteHangup,
    /// Call was rejected by the remote side.
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

impl From<client_types::CallEndReason> for CallEndReason {
    fn from(value: client_types::CallEndReason) -> Self {
        use client_types::CallEndReason as Core;
        match value {
            Core::LocalHangup => Self::LocalHangup,
            Core::RemoteHangup => Self::RemoteHangup,
            Core::Rejected { status_code } => Self::Rejected { status_code },
            Core::LocalReject => Self::LocalReject,
            Core::Timeout => Self::Timeout,
            Core::NetworkError => Self::NetworkError,
            Core::Failed => Self::Failed,
            Core::Transferred => Self::Transferred,
            Core::Unknown => Self::Unknown,
        }
    }
}

/// A completed call in the persisted call history.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CallHistoryEntry {
    /// Unique identifier.
    pub id: String,
    /// Remote party URI.
    pub remote_uri: String,
    /// Remote party display name (if available).
    pub remote_display_name: Option<String>,
    /// Call direction.
    pub direction: CallDirection,
    /// When the call was initiated (Unix epoch, milliseconds).
    pub start_time_unix_ms: i64,
    /// When the call was connected (Unix epoch, milliseconds), if it was.
    pub connect_time_unix_ms: Option<i64>,
    /// When the call ended (Unix epoch, milliseconds).
    pub end_time_unix_ms: i64,
    /// How the call ended.
    pub end_reason: CallEndReason,
    /// Call duration in seconds (if connected).
    pub duration_secs: Option<u64>,
}

impl From<client_types::CallHistoryEntry> for CallHistoryEntry {
    fn from(value: client_types::CallHistoryEntry) -> Self {
        Self {
            id: value.id,
            remote_uri: value.remote_uri,
            remote_display_name: value.remote_display_name,
            direction: value.direction.into(),
            start_time_unix_ms: value.start_time.timestamp_millis(),
            connect_time_unix_ms: value.connect_time.map(|t| t.timestamp_millis()),
            end_time_unix_ms: value.end_time.timestamp_millis(),
            end_reason: value.end_reason.into(),
            duration_secs: value.duration_secs,
        }
    }
}

/// SIP signaling transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TransportKind {
    /// TLS 1.3 only (CNSA 2.0 compliant, required for production).
    Tls,
    /// UDP transport (testing with commercial providers only).
    Udp,
    /// TCP transport (testing with commercial providers only).
    Tcp,
}

impl From<client_types::TransportPreference> for TransportKind {
    fn from(value: client_types::TransportPreference) -> Self {
        use client_types::TransportPreference as Core;
        match value {
            Core::TlsOnly => Self::Tls,
            Core::Udp => Self::Udp,
            Core::Tcp => Self::Tcp,
        }
    }
}

impl From<TransportKind> for client_types::TransportPreference {
    fn from(value: TransportKind) -> Self {
        match value {
            TransportKind::Tls => Self::TlsOnly,
            TransportKind::Udp => Self::Udp,
            TransportKind::Tcp => Self::Tcp,
        }
    }
}

/// SIP account configuration (the subset a shell edits).
///
/// Returned by `get_account` and accepted by `update_account`. Fields the
/// shell does not manage (outbound proxy, STUN/TURN, certificate selection)
/// are preserved across `update_account` round-trips.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SipAccountConfig {
    /// Unique account identifier (e.g. `"default"`).
    pub id: String,
    /// Display name for outgoing calls.
    pub display_name: String,
    /// SIP URI (e.g., `"sips:user@domain.com"`).
    pub sip_uri: String,
    /// Registrar URI (e.g., `"sips:registrar.domain.com"`).
    pub registrar_uri: String,
    /// Transport preference.
    pub transport: TransportKind,
    /// Registration expiry in seconds.
    pub register_expiry: u32,
    /// Whether this account is enabled (auto-registers on startup).
    pub enabled: bool,
    /// Caller ID / DN for outgoing calls (E.164 or digits), if set.
    pub caller_id: Option<String>,
    /// Digest authentication username. Only meaningful when the crate is
    /// built with the `digest-auth` feature; ignored (and returned as `None`)
    /// otherwise. The password is never returned; supply it separately via
    /// `update_account`.
    pub digest_username: Option<String>,
}

impl From<&client_types::SipAccount> for SipAccountConfig {
    fn from(value: &client_types::SipAccount) -> Self {
        #[cfg(feature = "digest-auth")]
        let digest_username = value
            .digest_credentials
            .as_ref()
            .map(|c| c.username.clone());
        #[cfg(not(feature = "digest-auth"))]
        let digest_username = None;

        Self {
            id: value.id.clone(),
            display_name: value.display_name.clone(),
            sip_uri: value.sip_uri.clone(),
            registrar_uri: value.registrar_uri.clone(),
            transport: value.transport.into(),
            register_expiry: value.register_expiry,
            enabled: value.enabled,
            caller_id: value.caller_id.clone(),
            digest_username,
        }
    }
}

impl SipAccountConfig {
    /// Applies the mirrored fields onto a core account, leaving fields not in
    /// the mirror (outbound proxy, STUN/TURN, certificates, digest
    /// credentials) untouched.
    pub(crate) fn apply_to(&self, account: &mut client_types::SipAccount) {
        account.id.clone_from(&self.id);
        account.display_name.clone_from(&self.display_name);
        account.sip_uri.clone_from(&self.sip_uri);
        account.registrar_uri.clone_from(&self.registrar_uri);
        account.transport = self.transport.into();
        account.register_expiry = self.register_expiry;
        account.enabled = self.enabled;
        account.caller_id = self.caller_id.clone().filter(|s| !s.is_empty());
    }
}

/// Preferred codec for outgoing calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CodecKind {
    /// Opus (best quality, modern).
    Opus,
    /// G.722 (wideband, good compatibility).
    G722,
    /// G.711 mu-law (narrowband, maximum compatibility).
    G711Ulaw,
    /// G.711 A-law (narrowband, Europe/International).
    G711Alaw,
}

impl From<client_types::CodecPreference> for CodecKind {
    fn from(value: client_types::CodecPreference) -> Self {
        use client_types::CodecPreference as Core;
        match value {
            Core::Opus => Self::Opus,
            Core::G722 => Self::G722,
            Core::G711Ulaw => Self::G711Ulaw,
            Core::G711Alaw => Self::G711Alaw,
        }
    }
}

impl From<CodecKind> for client_types::CodecPreference {
    fn from(value: CodecKind) -> Self {
        match value {
            CodecKind::Opus => Self::Opus,
            CodecKind::G722 => Self::G722,
            CodecKind::G711Ulaw => Self::G711Ulaw,
            CodecKind::G711Alaw => Self::G711Alaw,
        }
    }
}

/// Persisted audio preferences (the subset a shell edits).
///
/// Other audio options (volumes, jitter buffer, DTMF tuning) keep their
/// stored values across `update_audio_settings` round-trips. Use
/// `switch_input_device`/`switch_output_device` to also retarget a live call.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AudioSettings {
    /// Input (microphone) device name, or `None` for the system default.
    pub input_device: Option<String>,
    /// Output (speaker) device name, or `None` for the system default.
    pub output_device: Option<String>,
    /// Preferred codec for outgoing calls.
    pub preferred_codec: CodecKind,
}

impl From<&client_types::AudioConfig> for AudioSettings {
    fn from(value: &client_types::AudioConfig) -> Self {
        Self {
            input_device: value.input_device.clone(),
            output_device: value.output_device.clone(),
            preferred_codec: value.preferred_codec.into(),
        }
    }
}

/// DoD-standard classification banner configuration (read-only).
///
/// Shells render this as a full-width strip across the top of the window,
/// e.g. `CUI` or `TOP SECRET//SI/TK//NOFORN` per banner marking conventions.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ClassificationBanner {
    /// Canonical upper-case classification level, e.g. `"CUI"`,
    /// `"UNCLASSIFIED"`, `"TOP SECRET"`.
    pub level: String,
    /// SCI caveats (e.g. `SI`, `TK`), joined after the level with `//`.
    pub caveats: Vec<String>,
    /// Dissemination controls (e.g. `NOFORN`), joined last with `//`.
    pub dissem: Vec<String>,
}

impl From<&client_core::settings::UiSettings> for ClassificationBanner {
    fn from(value: &client_core::settings::UiSettings) -> Self {
        Self {
            level: canonical_classification_level(&value.classification_level),
            caveats: value.classification_caveats.clone(),
            dissem: value.classification_dissem.clone(),
        }
    }
}

/// Maps the stored classification level (`"cui"`, `"top-secret"`, ...) to the
/// canonical upper-case banner form. Unrecognized values are upper-cased with
/// hyphens replaced by spaces so the shell still renders something sensible.
fn canonical_classification_level(level: &str) -> String {
    match level.trim().to_ascii_lowercase().as_str() {
        "u" | "unclassified" => "UNCLASSIFIED".to_string(),
        "cui" => "CUI".to_string(),
        "c" | "confidential" => "CONFIDENTIAL".to_string(),
        "s" | "secret" => "SECRET".to_string(),
        // SCI ("top-secret-sci") is conveyed by the caveats, not the level.
        "ts" | "topsecret" | "top-secret" | "sci" | "tssci" | "topsecretsci" | "top-secret-sci" => {
            "TOP SECRET".to_string()
        }
        other => other.to_ascii_uppercase().replace('-', " "),
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
#[allow(clippy::panic)]
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

    #[test]
    fn classification_levels_canonicalize() {
        assert_eq!(
            canonical_classification_level("unclassified"),
            "UNCLASSIFIED"
        );
        assert_eq!(canonical_classification_level("cui"), "CUI");
        assert_eq!(
            canonical_classification_level("confidential"),
            "CONFIDENTIAL"
        );
        assert_eq!(canonical_classification_level("secret"), "SECRET");
        assert_eq!(canonical_classification_level("top-secret"), "TOP SECRET");
        assert_eq!(
            canonical_classification_level("top-secret-sci"),
            "TOP SECRET"
        );
        assert_eq!(canonical_classification_level(" CUI "), "CUI");
        // Unrecognized values still render sensibly.
        assert_eq!(
            canonical_classification_level("nato-restricted"),
            "NATO RESTRICTED"
        );
    }

    #[test]
    fn classification_banner_mirrors_ui_settings() {
        let ui = client_core::settings::UiSettings {
            classification_level: "top-secret-sci".to_string(),
            classification_caveats: vec!["SI".to_string(), "TK".to_string()],
            classification_dissem: vec!["NOFORN".to_string()],
            ..Default::default()
        };
        let banner = ClassificationBanner::from(&ui);
        assert_eq!(banner.level, "TOP SECRET");
        assert_eq!(banner.caveats, vec!["SI", "TK"]);
        assert_eq!(banner.dissem, vec!["NOFORN"]);
    }

    #[test]
    fn contact_round_trips_through_core() {
        let ffi = Contact {
            id: "contact-1".to_string(),
            name: "Ada Lovelace".to_string(),
            sip_uri: "sip:ada@example.com".to_string(),
            phone_numbers: vec![PhoneNumber {
                number: "+1-555-0100".to_string(),
                kind: PhoneNumberKind::Mobile,
                label: Some("Desk".to_string()),
            }],
            favorite: true,
            avatar_path: Some("/tmp/ada.png".to_string()),
            organization: Some("Analytical Engines".to_string()),
            notes: None,
        };

        let core: client_types::Contact = ffi.clone().into();
        assert_eq!(core.id, "contact-1");
        assert_eq!(
            core.phone_numbers[0].number_type,
            client_types::PhoneNumberType::Mobile
        );
        assert_eq!(
            core.avatar_path,
            Some(std::path::PathBuf::from("/tmp/ada.png"))
        );

        let back = Contact::from(core);
        assert_eq!(back.name, ffi.name);
        assert_eq!(back.phone_numbers.len(), 1);
        assert_eq!(back.phone_numbers[0].kind, PhoneNumberKind::Mobile);
        assert_eq!(back.phone_numbers[0].label.as_deref(), Some("Desk"));
        assert!(back.favorite);
    }

    #[test]
    fn call_history_entry_maps_times_and_reason() {
        let Some(start) = chrono::DateTime::from_timestamp_millis(1_700_000_000_000) else {
            panic!("valid timestamp")
        };
        let core = client_types::CallHistoryEntry {
            id: "call-1".to_string(),
            remote_uri: "sip:bob@example.com".to_string(),
            remote_display_name: Some("Bob".to_string()),
            direction: client_types::CallDirection::Inbound,
            start_time: start,
            connect_time: None,
            end_time: start + chrono::Duration::seconds(30),
            end_reason: client_types::CallEndReason::Rejected { status_code: 486 },
            duration_secs: None,
        };

        let ffi = CallHistoryEntry::from(core);
        assert_eq!(ffi.start_time_unix_ms, 1_700_000_000_000);
        assert_eq!(ffi.connect_time_unix_ms, None);
        assert_eq!(ffi.end_time_unix_ms, 1_700_000_030_000);
        assert_eq!(ffi.direction, CallDirection::Inbound);
        assert_eq!(ffi.end_reason, CallEndReason::Rejected { status_code: 486 });
    }

    #[test]
    fn transport_kind_round_trips() {
        for kind in [TransportKind::Tls, TransportKind::Udp, TransportKind::Tcp] {
            let core: client_types::TransportPreference = kind.into();
            assert_eq!(TransportKind::from(core), kind);
        }
    }

    #[test]
    fn codec_kind_round_trips() {
        for kind in [
            CodecKind::Opus,
            CodecKind::G722,
            CodecKind::G711Ulaw,
            CodecKind::G711Alaw,
        ] {
            let core: client_types::CodecPreference = kind.into();
            assert_eq!(CodecKind::from(core), kind);
        }
    }

    #[test]
    fn sip_account_config_apply_preserves_unmirrored_fields() {
        let mut core = client_types::SipAccount::new(
            "default",
            "Old Name",
            "sips:old@example.com",
            "sips:registrar.example.com",
        );
        core.outbound_proxy = Some("sips:proxy.example.com".to_string());
        core.stun_server = Some("stun:stun.example.com:3478".to_string());

        let ffi = SipAccountConfig {
            id: "default".to_string(),
            display_name: "New Name".to_string(),
            sip_uri: "sip:new@example.com".to_string(),
            registrar_uri: "sip:registrar.example.com".to_string(),
            transport: TransportKind::Udp,
            register_expiry: 600,
            enabled: true,
            caller_id: Some(String::new()),
            digest_username: None,
        };
        ffi.apply_to(&mut core);

        assert_eq!(core.display_name, "New Name");
        assert_eq!(core.transport, client_types::TransportPreference::Udp);
        assert_eq!(core.register_expiry, 600);
        // Empty caller ID strings are normalized to None.
        assert_eq!(core.caller_id, None);
        // Fields outside the mirror are preserved.
        assert_eq!(
            core.outbound_proxy.as_deref(),
            Some("sips:proxy.example.com")
        );
        assert_eq!(
            core.stun_server.as_deref(),
            Some("stun:stun.example.com:3478")
        );
    }

    #[test]
    fn audio_settings_mirrors_core_config() {
        let core = client_types::AudioConfig {
            input_device: Some("MacBook Pro Microphone".to_string()),
            output_device: None,
            preferred_codec: client_types::CodecPreference::G711Ulaw,
            ..client_types::AudioConfig::default()
        };

        let ffi = AudioSettings::from(&core);
        assert_eq!(ffi.input_device.as_deref(), Some("MacBook Pro Microphone"));
        assert_eq!(ffi.output_device, None);
        assert_eq!(ffi.preferred_codec, CodecKind::G711Ulaw);
    }

    #[cfg(feature = "digest-auth")]
    #[test]
    fn sip_account_config_exposes_digest_username() {
        let mut core = client_types::SipAccount::new(
            "default",
            "Test",
            "sip:test@example.com",
            "sip:registrar.example.com",
        );
        core.digest_credentials = Some(client_types::DigestAuthCredentials::new(
            "auth-user",
            "secret",
        ));

        let ffi = SipAccountConfig::from(&core);
        assert_eq!(ffi.digest_username.as_deref(), Some("auth-user"));
    }
}
