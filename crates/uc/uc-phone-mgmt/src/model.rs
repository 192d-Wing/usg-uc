//! Phone device model types and data structures.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A managed phone device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phone {
    /// Unique identifier for this phone.
    pub id: String,
    /// MAC address (colon-separated, lowercase).
    pub mac_address: String,
    /// Phone hardware model.
    pub model: PhoneModel,
    /// Currently running firmware version.
    pub firmware_version: Option<String>,
    /// Target firmware version for upgrade.
    pub target_firmware: Option<String>,
    /// Human-readable name for the phone.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Owner user ID.
    pub owner_id: Option<String>,
    /// Line appearances configured on this phone.
    pub lines: Vec<PhoneLine>,
    /// Device pool assignment.
    pub device_pool: Option<String>,
    /// Calling search space.
    pub calling_search_space: Option<String>,
    /// Current registration/provisioning status.
    pub status: PhoneStatus,
    /// IP address if known.
    pub ip_address: Option<String>,
    /// Epoch timestamp of last registration.
    pub registered_at: Option<i64>,
    /// Epoch timestamp of last contact.
    pub last_seen: Option<i64>,
    /// Configuration version counter.
    pub config_version: u32,
}

impl Phone {
    /// Create a new phone with a generated UUID.
    #[must_use]
    pub fn new(mac: &str, model: PhoneModel, name: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            mac_address: mac.to_lowercase(),
            model,
            firmware_version: None,
            target_firmware: None,
            name: name.to_string(),
            description: None,
            owner_id: None,
            lines: Vec::new(),
            device_pool: None,
            calling_search_space: None,
            status: PhoneStatus::Unprovisioned,
            ip_address: None,
            registered_at: None,
            last_seen: None,
            config_version: 1,
        }
    }
}

/// Supported phone hardware models.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PhoneModel {
    // Polycom VVX
    /// Polycom VVX 150
    PolycomVVX150,
    /// Polycom VVX 250
    PolycomVVX250,
    /// Polycom VVX 350
    PolycomVVX350,
    /// Polycom VVX 450
    PolycomVVX450,
    /// Polycom VVX 501
    PolycomVVX501,
    /// Polycom VVX 601
    PolycomVVX601,

    // Polycom Trio
    /// Polycom Trio 8300
    PolycomTrio8300,
    /// Polycom Trio 8500
    PolycomTrio8500,
    /// Polycom Trio 8800
    PolycomTrio8800,

    // Poly Edge
    /// Poly Edge E100
    PolyEdgeE100,
    /// Poly Edge E220
    PolyEdgeE220,
    /// Poly Edge E300
    PolyEdgeE300,
    /// Poly Edge E320
    PolyEdgeE320,
    /// Poly Edge E350
    PolyEdgeE350,
    /// Poly Edge E400
    PolyEdgeE400,
    /// Poly Edge E450
    PolyEdgeE450,
    /// Poly Edge E500
    PolyEdgeE500,
    /// Poly Edge E550
    PolyEdgeE550,
    /// Poly Edge B10
    PolyEdgeB10,
    /// Poly Edge B20
    PolyEdgeB20,
    /// Poly Edge B30
    PolyEdgeB30,

    // Cisco MPP 6800/7800/8800
    /// Cisco MPP 6821
    CiscoMPP6821,
    /// Cisco MPP 6841
    CiscoMPP6841,
    /// Cisco MPP 6851
    CiscoMPP6851,
    /// Cisco MPP 6861
    CiscoMPP6861,
    /// Cisco MPP 6871
    CiscoMPP6871,
    /// Cisco MPP 7811
    CiscoMPP7811,
    /// Cisco MPP 7821
    CiscoMPP7821,
    /// Cisco MPP 7841
    CiscoMPP7841,
    /// Cisco MPP 7861
    CiscoMPP7861,
    /// Cisco MPP 8811
    CiscoMPP8811,
    /// Cisco MPP 8841
    CiscoMPP8841,
    /// Cisco MPP 8851
    CiscoMPP8851,
    /// Cisco MPP 8861
    CiscoMPP8861,

    // Cisco 9800
    /// Cisco 9841
    Cisco9841,
    /// Cisco 9851
    Cisco9851,
    /// Cisco 9861
    Cisco9861,
    /// Cisco 9871
    Cisco9871,

    /// Generic / unknown model.
    Generic(String),
}

impl PhoneModel {
    /// Return the model family identifier string.
    #[must_use]
    pub fn family(&self) -> &str {
        match self {
            Self::PolycomVVX150
            | Self::PolycomVVX250
            | Self::PolycomVVX350
            | Self::PolycomVVX450
            | Self::PolycomVVX501
            | Self::PolycomVVX601 => "polycom_vvx",

            Self::PolycomTrio8300 | Self::PolycomTrio8500 | Self::PolycomTrio8800 => {
                "polycom_trio"
            }

            Self::PolyEdgeE100
            | Self::PolyEdgeE220
            | Self::PolyEdgeE300
            | Self::PolyEdgeE320
            | Self::PolyEdgeE350
            | Self::PolyEdgeE400
            | Self::PolyEdgeE450
            | Self::PolyEdgeE500
            | Self::PolyEdgeE550
            | Self::PolyEdgeB10
            | Self::PolyEdgeB20
            | Self::PolyEdgeB30 => "poly_edge",

            Self::CiscoMPP6821
            | Self::CiscoMPP6841
            | Self::CiscoMPP6851
            | Self::CiscoMPP6861
            | Self::CiscoMPP6871
            | Self::CiscoMPP7811
            | Self::CiscoMPP7821
            | Self::CiscoMPP7841
            | Self::CiscoMPP7861
            | Self::CiscoMPP8811
            | Self::CiscoMPP8841
            | Self::CiscoMPP8851
            | Self::CiscoMPP8861 => "cisco_mpp",

            Self::Cisco9841 | Self::Cisco9851 | Self::Cisco9861 | Self::Cisco9871 => "cisco_9800",

            Self::Generic(_) => "generic",
        }
    }

    /// Return the maximum number of line appearances supported.
    #[must_use]
    pub fn max_lines(&self) -> u8 {
        match self {
            // VVX entry-level
            Self::PolycomVVX150 => 2,
            Self::PolycomVVX250 => 4,
            Self::PolycomVVX350 => 6,
            Self::PolycomVVX450 => 12,
            Self::PolycomVVX501 => 12,
            Self::PolycomVVX601 => 16,

            // Trio
            Self::PolycomTrio8300 => 1,
            Self::PolycomTrio8500 => 1,
            Self::PolycomTrio8800 => 1,

            // Poly Edge E-series
            Self::PolyEdgeE100 => 2,
            Self::PolyEdgeE220 => 4,
            Self::PolyEdgeE300 => 8,
            Self::PolyEdgeE320 => 8,
            Self::PolyEdgeE350 => 8,
            Self::PolyEdgeE400 => 12,
            Self::PolyEdgeE450 => 16,
            Self::PolyEdgeE500 => 24,
            Self::PolyEdgeE550 => 34,
            // B-series (expansion modules)
            Self::PolyEdgeB10 => 0,
            Self::PolyEdgeB20 => 0,
            Self::PolyEdgeB30 => 0,

            // Cisco MPP 6800
            Self::CiscoMPP6821 => 2,
            Self::CiscoMPP6841 => 4,
            Self::CiscoMPP6851 => 4,
            Self::CiscoMPP6861 => 4,
            Self::CiscoMPP6871 => 6,
            // Cisco MPP 7800
            Self::CiscoMPP7811 => 1,
            Self::CiscoMPP7821 => 2,
            Self::CiscoMPP7841 => 4,
            Self::CiscoMPP7861 => 4,
            // Cisco MPP 8800
            Self::CiscoMPP8811 => 5,
            Self::CiscoMPP8841 => 5,
            Self::CiscoMPP8851 => 5,
            Self::CiscoMPP8861 => 5,

            // Cisco 9800
            Self::Cisco9841 => 4,
            Self::Cisco9851 => 6,
            Self::Cisco9861 => 10,
            Self::Cisco9871 => 12,

            Self::Generic(_) => 4,
        }
    }

    /// Return a human-readable display name for the model.
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            Self::PolycomVVX150 => "Polycom VVX 150",
            Self::PolycomVVX250 => "Polycom VVX 250",
            Self::PolycomVVX350 => "Polycom VVX 350",
            Self::PolycomVVX450 => "Polycom VVX 450",
            Self::PolycomVVX501 => "Polycom VVX 501",
            Self::PolycomVVX601 => "Polycom VVX 601",

            Self::PolycomTrio8300 => "Polycom Trio 8300",
            Self::PolycomTrio8500 => "Polycom Trio 8500",
            Self::PolycomTrio8800 => "Polycom Trio 8800",

            Self::PolyEdgeE100 => "Poly Edge E100",
            Self::PolyEdgeE220 => "Poly Edge E220",
            Self::PolyEdgeE300 => "Poly Edge E300",
            Self::PolyEdgeE320 => "Poly Edge E320",
            Self::PolyEdgeE350 => "Poly Edge E350",
            Self::PolyEdgeE400 => "Poly Edge E400",
            Self::PolyEdgeE450 => "Poly Edge E450",
            Self::PolyEdgeE500 => "Poly Edge E500",
            Self::PolyEdgeE550 => "Poly Edge E550",
            Self::PolyEdgeB10 => "Poly Edge B10",
            Self::PolyEdgeB20 => "Poly Edge B20",
            Self::PolyEdgeB30 => "Poly Edge B30",

            Self::CiscoMPP6821 => "Cisco MPP 6821",
            Self::CiscoMPP6841 => "Cisco MPP 6841",
            Self::CiscoMPP6851 => "Cisco MPP 6851",
            Self::CiscoMPP6861 => "Cisco MPP 6861",
            Self::CiscoMPP6871 => "Cisco MPP 6871",
            Self::CiscoMPP7811 => "Cisco MPP 7811",
            Self::CiscoMPP7821 => "Cisco MPP 7821",
            Self::CiscoMPP7841 => "Cisco MPP 7841",
            Self::CiscoMPP7861 => "Cisco MPP 7861",
            Self::CiscoMPP8811 => "Cisco MPP 8811",
            Self::CiscoMPP8841 => "Cisco MPP 8841",
            Self::CiscoMPP8851 => "Cisco MPP 8851",
            Self::CiscoMPP8861 => "Cisco MPP 8861",

            Self::Cisco9841 => "Cisco 9841",
            Self::Cisco9851 => "Cisco 9851",
            Self::Cisco9861 => "Cisco 9861",
            Self::Cisco9871 => "Cisco 9871",

            Self::Generic(name) => name.as_str(),
        }
    }
}

impl fmt::Display for PhoneModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// A line appearance on a phone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoneLine {
    /// Line index (1-based).
    pub index: u8,
    /// Directory number / extension.
    pub directory_number: String,
    /// Display name shown on the phone.
    pub display_name: String,
    /// Associated user ID.
    pub user_id: Option<String>,
    /// SIP authentication username.
    pub sip_username: String,
    /// SIP authentication password.
    pub sip_password: String,
    /// SIP registrar/proxy server address.
    pub sip_server: String,
    /// SIP server port.
    pub sip_port: u16,
    /// Transport protocol: "udp", "tcp", or "tls".
    pub transport: String,
    /// Voicemail URI for message waiting indication.
    pub voicemail_uri: Option<String>,
    /// Call forwarding settings.
    pub call_forward: Option<CallForward>,
}

/// Call forwarding configuration for a line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallForward {
    /// Forward all calls to this destination.
    pub all: Option<String>,
    /// Forward on busy to this destination.
    pub busy: Option<String>,
    /// Forward on no answer to this destination.
    pub no_answer: Option<String>,
    /// Seconds to wait before forwarding on no answer.
    pub no_answer_timeout: u32,
}

/// Registration and provisioning status of a phone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PhoneStatus {
    /// Not yet provisioned.
    Unprovisioned,
    /// Provisioning in progress.
    Provisioning,
    /// Successfully registered.
    Registered,
    /// Phone is offline / unreachable.
    Offline,
    /// Phone is in an error state.
    Error(String),
}

/// Filter criteria for listing phones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoneFilter {
    /// Filter by model family (e.g. "polycom_vvx").
    pub model_family: Option<String>,
    /// Filter by status.
    pub status: Option<PhoneStatus>,
    /// Filter by owner user ID.
    pub owner_id: Option<String>,
    /// Filter by calling search space.
    pub css: Option<String>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_phone_model_family() {
        assert_eq!(PhoneModel::PolycomVVX450.family(), "polycom_vvx");
        assert_eq!(PhoneModel::PolycomTrio8800.family(), "polycom_trio");
        assert_eq!(PhoneModel::PolyEdgeE450.family(), "poly_edge");
        assert_eq!(PhoneModel::CiscoMPP8851.family(), "cisco_mpp");
        assert_eq!(PhoneModel::Cisco9861.family(), "cisco_9800");
        assert_eq!(
            PhoneModel::Generic("Custom".to_string()).family(),
            "generic"
        );
    }

    #[test]
    fn test_phone_model_max_lines() {
        assert_eq!(PhoneModel::PolycomVVX150.max_lines(), 2);
        assert_eq!(PhoneModel::PolycomVVX601.max_lines(), 16);
        assert_eq!(PhoneModel::PolyEdgeE550.max_lines(), 34);
        assert_eq!(PhoneModel::CiscoMPP7811.max_lines(), 1);
        assert_eq!(PhoneModel::CiscoMPP6871.max_lines(), 6);
        assert_eq!(PhoneModel::Cisco9871.max_lines(), 12);
    }

    #[test]
    fn test_phone_model_display_name() {
        assert_eq!(PhoneModel::PolyEdgeE450.display_name(), "Poly Edge E450");
        assert_eq!(PhoneModel::Cisco9861.display_name(), "Cisco 9861");
        assert_eq!(PhoneModel::PolycomVVX350.display_name(), "Polycom VVX 350");
        assert_eq!(
            PhoneModel::Generic("Acme Phone".to_string()).display_name(),
            "Acme Phone"
        );
    }

    #[test]
    fn test_phone_model_display_trait() {
        let model = PhoneModel::Cisco9861;
        assert_eq!(format!("{model}"), "Cisco 9861");
    }

    #[test]
    fn test_phone_new() {
        let phone = Phone::new("aa:bb:cc:dd:ee:ff", PhoneModel::PolyEdgeE450, "Lobby Phone");
        assert!(!phone.id.is_empty());
        assert_eq!(phone.mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(phone.model, PhoneModel::PolyEdgeE450);
        assert_eq!(phone.name, "Lobby Phone");
        assert_eq!(phone.status, PhoneStatus::Unprovisioned);
        assert_eq!(phone.config_version, 1);
        assert!(phone.lines.is_empty());
    }
}
