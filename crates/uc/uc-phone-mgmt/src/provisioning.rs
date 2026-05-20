//! Provisioning server that generates configs for any supported phone model.

use crate::cisco_9800;
use crate::cisco_mpp;
use crate::error::PhoneMgmtError;
use crate::model::{Phone, PhoneModel};
use crate::poly_edge;
use crate::polycom_vvx;
use crate::teo;

/// Provisioning server that generates phone-specific configurations.
pub struct ProvisioningServer {
    sbc_host: String,
    #[allow(dead_code)]
    sbc_port: u16,
}

impl ProvisioningServer {
    /// Create a new provisioning server instance.
    #[must_use]
    pub fn new(sbc_host: &str, sbc_port: u16) -> Self {
        Self {
            sbc_host: sbc_host.to_string(),
            sbc_port,
        }
    }

    /// Generate a provisioning configuration for the given phone.
    ///
    /// Dispatches to the appropriate config generator based on the phone's
    /// model family.
    ///
    /// # Errors
    ///
    /// Returns [`PhoneMgmtError::ConfigGenerationFailed`] if the model family
    /// is not supported for auto-provisioning.
    pub fn generate_config(&self, phone: &Phone) -> Result<String, PhoneMgmtError> {
        match phone.model.family() {
            "polycom_vvx" | "polycom_trio" => {
                Ok(polycom_vvx::generate_vvx_config(phone, &self.sbc_host))
            }
            "poly_edge" => Ok(poly_edge::generate_edge_config(phone, &self.sbc_host)),
            "cisco_mpp" => Ok(cisco_mpp::generate_mpp_config(phone, &self.sbc_host)),
            "cisco_9800" => Ok(cisco_9800::generate_9800_config(phone, &self.sbc_host)),
            "teo" => Ok(teo::generate_teo_config(phone, &self.sbc_host)),
            other => Err(PhoneMgmtError::ConfigGenerationFailed(format!(
                "unsupported model family: {other}"
            ))),
        }
    }

    /// Get the provisioning URL path for a phone identified by MAC address.
    ///
    /// Returns the path component (without scheme/host) used to fetch the
    /// phone's config.
    #[must_use]
    pub fn config_path(&self, mac: &str, model: &PhoneModel) -> String {
        // Teo spec p.19 mandates UPPERCASE MAC for the filename. Other vendors
        // accept either; we keep them lowercase for consistency with their docs.
        if model.family() == "teo" {
            return format!("/provision/{}", teo::teo_config_filename(mac));
        }
        let clean_mac = mac.replace(':', "").to_lowercase();
        let ext = match model.family() {
            "cisco_mpp" | "cisco_9800" => "xml",
            _ => "cfg",
        };
        format!("/provision/{clean_mac}.{ext}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{Phone, PhoneLine, PhoneModel};

    fn test_phone(model: PhoneModel) -> Phone {
        let mut phone = Phone::new("aa:bb:cc:dd:ee:ff", model, "Test Phone");
        phone.lines.push(PhoneLine {
            index: 1,
            directory_number: "1001".to_string(),
            display_name: "Test User".to_string(),
            user_id: None,
            sip_username: "1001".to_string(),
            sip_password: "password".to_string(),
            sip_server: "sbc.example.com".to_string(),
            sip_port: 5060,
            transport: "udp".to_string(),
            voicemail_uri: None,
            call_forward: None,
        });
        phone
    }

    #[test]
    fn test_config_path_polycom() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let path = server.config_path("aa:bb:cc:dd:ee:ff", &PhoneModel::PolycomVVX450);
        assert_eq!(path, "/provision/aabbccddeeff.cfg");
    }

    #[test]
    fn test_config_path_cisco_mpp() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let path = server.config_path("11:22:33:44:55:66", &PhoneModel::CiscoMPP8851);
        assert_eq!(path, "/provision/112233445566.xml");
    }

    #[test]
    fn test_config_path_cisco_9800() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let path = server.config_path("AA:BB:CC:DD:EE:FF", &PhoneModel::Cisco9861);
        assert_eq!(path, "/provision/aabbccddeeff.xml");
    }

    #[test]
    fn test_config_path_poly_edge() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let path = server.config_path("aa:bb:cc:dd:ee:ff", &PhoneModel::PolyEdgeE450);
        assert_eq!(path, "/provision/aabbccddeeff.cfg");
    }

    #[test]
    fn test_config_path_teo_uppercases_mac() {
        let server = ProvisioningServer::new("sbc.example.mil", 443);
        // Lowercase, colon-separated input → UPPERCASE filename per Teo spec.
        let path = server.config_path("00:04:8d:00:00:f5", &PhoneModel::Teo7810);
        assert_eq!(path, "/provision/00048D0000F5.xml");
    }

    #[test]
    fn test_generate_config_teo() {
        let server = ProvisioningServer::new("sbc.example.mil", 443);
        let phone = test_phone(PhoneModel::Teo7810);
        let config = server.generate_config(&phone).unwrap();
        assert!(config.contains("<TEO_settings schema_vers=\"2.0\">"));
        assert!(config.contains("<TEO_phone model=\"7810\">"));
    }

    #[test]
    fn test_generate_config_polycom() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let phone = test_phone(PhoneModel::PolycomVVX450);
        let config = server.generate_config(&phone).unwrap();
        assert!(config.contains("<polycomConfig"));
    }

    #[test]
    fn test_generate_config_poly_edge() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let phone = test_phone(PhoneModel::PolyEdgeE450);
        let config = server.generate_config(&phone).unwrap();
        assert!(config.contains("<phone>"));
    }

    #[test]
    fn test_generate_config_cisco_mpp() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let phone = test_phone(PhoneModel::CiscoMPP8851);
        let config = server.generate_config(&phone).unwrap();
        assert!(config.contains("<flat-profile>"));
    }

    #[test]
    fn test_generate_config_cisco_9800() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let phone = test_phone(PhoneModel::Cisco9861);
        let config = server.generate_config(&phone).unwrap();
        assert!(config.contains("<device>"));
    }

    #[test]
    fn test_generate_config_generic_fails() {
        let server = ProvisioningServer::new("sbc.example.com", 443);
        let phone = test_phone(PhoneModel::Generic("Custom".to_string()));
        let result = server.generate_config(&phone);
        assert!(result.is_err());
    }
}
