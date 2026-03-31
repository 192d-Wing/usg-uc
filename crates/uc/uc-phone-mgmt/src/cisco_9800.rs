//! Cisco 9800 series provisioning configuration generator.

use crate::model::Phone;

/// Generate a Cisco 9800 series provisioning XML configuration.
///
/// Produces a `<device>` XML config similar to MPP but with enhanced
/// features for 9800 hardware including Wi-Fi, USB headset, and presence.
#[must_use]
pub fn generate_9800_config(phone: &Phone, sbc_host: &str) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<device>
"#,
    );

    // Device info
    xml.push_str(&format!(
        "  <deviceName>{}</deviceName>\n",
        phone.name
    ));
    xml.push_str(&format!(
        "  <macAddress>{}</macAddress>\n",
        phone.mac_address
    ));
    xml.push_str(&format!(
        "  <model>{}</model>\n\n",
        phone.model.display_name()
    ));

    // Per-line configuration
    for line in &phone.lines {
        let i = line.index;
        xml.push_str(&format!("  <line index=\"{i}\">\n"));
        xml.push_str(&format!(
            "    <proxy>{sbc_host}</proxy>\n"
        ));
        xml.push_str(&format!(
            "    <port>{}</port>\n",
            line.sip_port
        ));
        xml.push_str(&format!(
            "    <userId>{}</userId>\n",
            line.sip_username
        ));
        xml.push_str(&format!(
            "    <password>{}</password>\n",
            line.sip_password
        ));
        xml.push_str(&format!(
            "    <displayName>{}</displayName>\n",
            line.display_name
        ));
        xml.push_str(&format!(
            "    <authId>{}</authId>\n",
            line.sip_username
        ));
        xml.push_str("    <enabled>true</enabled>\n");

        if let Some(vm) = &line.voicemail_uri {
            xml.push_str(&format!("    <voiceMail>{vm}</voiceMail>\n"));
        }

        if let Some(cf) = &line.call_forward {
            xml.push_str("    <callForward>\n");
            if let Some(all) = &cf.all {
                xml.push_str(&format!("      <all>{all}</all>\n"));
            }
            if let Some(busy) = &cf.busy {
                xml.push_str(&format!("      <busy>{busy}</busy>\n"));
            }
            if let Some(na) = &cf.no_answer {
                xml.push_str(&format!("      <noAnswer>{na}</noAnswer>\n"));
                xml.push_str(&format!(
                    "      <noAnswerTimeout>{}</noAnswerTimeout>\n",
                    cf.no_answer_timeout
                ));
            }
            xml.push_str("    </callForward>\n");
        }

        xml.push_str("  </line>\n");
    }
    xml.push('\n');

    // SIP settings
    let transport = phone
        .lines
        .first()
        .map_or("UDP", |l| match l.transport.as_str() {
            "tls" => "TLS",
            "tcp" => "TCP",
            _ => "UDP",
        });

    xml.push_str("  <sipSettings>\n");
    xml.push_str(&format!(
        "    <transport>{transport}</transport>\n"
    ));
    xml.push_str("    <preferredCodec>G722</preferredCodec>\n");
    xml.push_str("    <secondPreferredCodec>G711u</secondPreferredCodec>\n");
    xml.push_str("    <thirdPreferredCodec>G711a</thirdPreferredCodec>\n");
    xml.push_str("  </sipSettings>\n\n");

    // Wi-Fi settings
    xml.push_str("  <wifi>\n");
    xml.push_str("    <enabled>false</enabled>\n");
    xml.push_str("    <ssid></ssid>\n");
    xml.push_str("    <securityMode>WPA2-Enterprise</securityMode>\n");
    xml.push_str("  </wifi>\n\n");

    // USB headset configuration
    xml.push_str("  <usbHeadset>\n");
    xml.push_str("    <enabled>true</enabled>\n");
    xml.push_str("    <wideband>true</wideband>\n");
    xml.push_str("  </usbHeadset>\n\n");

    // Enhanced presence settings
    xml.push_str("  <presence>\n");
    xml.push_str("    <enabled>true</enabled>\n");
    xml.push_str(&format!(
        "    <server>{sbc_host}</server>\n"
    ));
    xml.push_str("    <protocol>SIP</protocol>\n");
    xml.push_str("  </presence>\n\n");

    // Provisioning
    xml.push_str("  <provisioning>\n");
    xml.push_str(&format!(
        "    <upgradeRule>https://{sbc_host}/provisioning/$MA.xml</upgradeRule>\n"
    ));
    xml.push_str("    <resyncPeriodic>3600</resyncPeriodic>\n");
    xml.push_str("  </provisioning>\n");

    xml.push_str("</device>\n");
    xml
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{Phone, PhoneLine, PhoneModel};

    fn test_phone() -> Phone {
        let mut phone = Phone::new("aa:bb:cc:dd:ee:ff", PhoneModel::Cisco9861, "Test 9800");
        phone.lines.push(PhoneLine {
            index: 1,
            directory_number: "4001".to_string(),
            display_name: "Alice Green".to_string(),
            user_id: None,
            sip_username: "4001".to_string(),
            sip_password: "cisco9800".to_string(),
            sip_server: "sbc.example.com".to_string(),
            sip_port: 5061,
            transport: "tls".to_string(),
            voicemail_uri: None,
            call_forward: None,
        });
        phone
    }

    #[test]
    fn test_generate_9800_config_device_root() {
        let phone = test_phone();
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<device>"));
        assert!(config.contains("</device>"));
        assert!(config.contains("<deviceName>Test 9800</deviceName>"));
        assert!(config.contains("<model>Cisco 9861</model>"));
    }

    #[test]
    fn test_generate_9800_config_line_entries() {
        let phone = test_phone();
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<line index=\"1\">"));
        assert!(config.contains("<proxy>sbc.example.com</proxy>"));
        assert!(config.contains("<userId>4001</userId>"));
        assert!(config.contains("<displayName>Alice Green</displayName>"));
    }

    #[test]
    fn test_generate_9800_config_wifi() {
        let phone = test_phone();
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<wifi>"));
        assert!(config.contains("<securityMode>WPA2-Enterprise</securityMode>"));
    }

    #[test]
    fn test_generate_9800_config_usb_headset() {
        let phone = test_phone();
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<usbHeadset>"));
        assert!(config.contains("<wideband>true</wideband>"));
    }

    #[test]
    fn test_generate_9800_config_presence() {
        let phone = test_phone();
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<presence>"));
        assert!(config.contains("<server>sbc.example.com</server>"));
    }

    #[test]
    fn test_generate_9800_config_transport_tls() {
        let phone = test_phone();
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<transport>TLS</transport>"));
    }
}
