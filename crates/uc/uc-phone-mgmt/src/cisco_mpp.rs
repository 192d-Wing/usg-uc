//! Cisco MPP (6800/7800/8800) series provisioning configuration generator.

use crate::model::Phone;

/// Generate a Cisco MPP provisioning XML configuration.
///
/// Produces a `<flat-profile>` XML config with per-line settings,
/// SIP transport configuration, codec preferences, and provisioning rules.
#[must_use]
pub fn generate_mpp_config(phone: &Phone, sbc_host: &str) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<flat-profile>
"#,
    );

    // Per-line configuration
    for line in &phone.lines {
        let i = line.index;
        xml.push_str(&format!(
            "  <!-- Line {i} -->\n"
        ));
        xml.push_str(&format!(
            "  <Line{i}_Proxy>{sbc_host}</Line{i}_Proxy>\n"
        ));
        xml.push_str(&format!(
            "  <Line{i}_Port>{}</Line{i}_Port>\n",
            line.sip_port
        ));
        xml.push_str(&format!(
            "  <Line{i}_User_ID>{}</Line{i}_User_ID>\n",
            line.sip_username
        ));
        xml.push_str(&format!(
            "  <Line{i}_Password>{}</Line{i}_Password>\n",
            line.sip_password
        ));
        xml.push_str(&format!(
            "  <Line{i}_Display_Name>{}</Line{i}_Display_Name>\n",
            line.display_name
        ));
        xml.push_str(&format!(
            "  <Line{i}_Auth_ID>{}</Line{i}_Auth_ID>\n",
            line.sip_username
        ));
        xml.push_str(&format!(
            "  <Line{i}_Enabled>Yes</Line{i}_Enabled>\n"
        ));

        if let Some(vm) = &line.voicemail_uri {
            xml.push_str(&format!(
                "  <Line{i}_Voice_Mail>{vm}</Line{i}_Voice_Mail>\n"
            ));
        }

        if let Some(cf) = &line.call_forward {
            if let Some(all) = &cf.all {
                xml.push_str(&format!(
                    "  <Line{i}_Cfwd_All>{all}</Line{i}_Cfwd_All>\n"
                ));
            }
            if let Some(busy) = &cf.busy {
                xml.push_str(&format!(
                    "  <Line{i}_Cfwd_Busy>{busy}</Line{i}_Cfwd_Busy>\n"
                ));
            }
            if let Some(na) = &cf.no_answer {
                xml.push_str(&format!(
                    "  <Line{i}_Cfwd_No_Answer>{na}</Line{i}_Cfwd_No_Answer>\n"
                ));
                xml.push_str(&format!(
                    "  <Line{i}_Cfwd_No_Answer_Delay>{}</Line{i}_Cfwd_No_Answer_Delay>\n",
                    cf.no_answer_timeout
                ));
            }
        }
        xml.push('\n');
    }

    // SIP section
    let transport = phone
        .lines
        .first()
        .map_or("UDP", |l| match l.transport.as_str() {
            "tls" => "TLS",
            "tcp" => "TCP",
            _ => "UDP",
        });

    xml.push_str("  <!-- SIP Settings -->\n");
    xml.push_str(&format!(
        "  <SIP_Transport>{transport}</SIP_Transport>\n"
    ));
    xml.push_str("  <SIP_Preferred_Codec>G722</SIP_Preferred_Codec>\n");
    xml.push_str("  <SIP_Second_Preferred_Codec>G711u</SIP_Second_Preferred_Codec>\n");
    xml.push_str("  <SIP_Third_Preferred_Codec>G711a</SIP_Third_Preferred_Codec>\n\n");

    // Provisioning section
    xml.push_str("  <!-- Provisioning -->\n");
    xml.push_str(&format!(
        "  <Upgrade_Rule>https://{sbc_host}/provisioning/$MA.xml</Upgrade_Rule>\n"
    ));
    xml.push_str("  <Resync_Periodic>3600</Resync_Periodic>\n");

    xml.push_str("</flat-profile>\n");
    xml
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{Phone, PhoneLine, PhoneModel};

    fn test_phone() -> Phone {
        let mut phone = Phone::new("aa:bb:cc:dd:ee:ff", PhoneModel::CiscoMPP8851, "Test MPP");
        phone.lines.push(PhoneLine {
            index: 1,
            directory_number: "3001".to_string(),
            display_name: "Bob Jones".to_string(),
            user_id: None,
            sip_username: "3001".to_string(),
            sip_password: "mpppass".to_string(),
            sip_server: "sbc.example.com".to_string(),
            sip_port: 5060,
            transport: "udp".to_string(),
            voicemail_uri: Some("*97".to_string()),
            call_forward: None,
        });
        phone
    }

    #[test]
    fn test_generate_mpp_config_flat_profile() {
        let phone = test_phone();
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<flat-profile>"));
        assert!(config.contains("</flat-profile>"));
    }

    #[test]
    fn test_generate_mpp_config_line_entries() {
        let phone = test_phone();
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<Line1_Proxy>sbc.example.com</Line1_Proxy>"));
        assert!(config.contains("<Line1_User_ID>3001</Line1_User_ID>"));
        assert!(config.contains("<Line1_Password>mpppass</Line1_Password>"));
        assert!(config.contains("<Line1_Display_Name>Bob Jones</Line1_Display_Name>"));
        assert!(config.contains("<Line1_Auth_ID>3001</Line1_Auth_ID>"));
    }

    #[test]
    fn test_generate_mpp_config_sip_settings() {
        let phone = test_phone();
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<SIP_Transport>UDP</SIP_Transport>"));
        assert!(config.contains("<SIP_Preferred_Codec>G722</SIP_Preferred_Codec>"));
    }

    #[test]
    fn test_generate_mpp_config_voicemail() {
        let phone = test_phone();
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<Line1_Voice_Mail>*97</Line1_Voice_Mail>"));
    }
}
