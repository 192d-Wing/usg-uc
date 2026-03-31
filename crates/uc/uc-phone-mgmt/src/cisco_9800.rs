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

    // Speed dials
    if !phone.speed_dials.is_empty() {
        xml.push_str("  <speedDials>\n");
        for sd in &phone.speed_dials {
            xml.push_str(&format!(
                "    <speedDial index=\"{}\" label=\"{}\" number=\"{}\" />\n",
                sd.index, sd.label, sd.number
            ));
        }
        xml.push_str("  </speedDials>\n\n");
    }

    // BLF entries
    if !phone.blf_entries.is_empty() {
        xml.push_str("  <blfEntries>\n");
        for blf in &phone.blf_entries {
            xml.push_str(&format!(
                "    <blf index=\"{}\" label=\"{}\" address=\"{}\" />\n",
                blf.index, blf.label, blf.address
            ));
        }
        xml.push_str("  </blfEntries>\n\n");
    }

    // Features
    if phone.features.auto_answer
        || phone.features.dnd
        || phone.features.intercom
        || phone.features.call_recording
    {
        xml.push_str("  <features>\n");
        if phone.features.auto_answer {
            xml.push_str("    <autoAnswer>true</autoAnswer>\n");
        }
        if phone.features.dnd {
            xml.push_str("    <dnd>true</dnd>\n");
        }
        if phone.features.intercom {
            xml.push_str("    <intercom>true</intercom>\n");
        }
        if phone.features.call_recording {
            xml.push_str("    <callRecording>true</callRecording>\n");
        }
        xml.push_str("  </features>\n\n");
    }

    // Network
    if phone.network.vlan_id.is_some()
        || phone.network.dot1x_enabled
        || phone.network.qos_dscp.is_some()
    {
        xml.push_str("  <network>\n");
        if let Some(vlan) = phone.network.vlan_id {
            xml.push_str(&format!("    <vlan>{vlan}</vlan>\n"));
        }
        if let Some(dscp) = phone.network.qos_dscp {
            xml.push_str(&format!("    <qosDscp>{dscp}</qosDscp>\n"));
        }
        if phone.network.dot1x_enabled {
            xml.push_str("    <dot1x>true</dot1x>\n");
        }
        xml.push_str("  </network>\n\n");
    }

    // Time
    if phone.display.timezone.is_some() || phone.display.ntp_server.is_some() {
        xml.push_str("  <time>\n");
        if let Some(tz) = &phone.display.timezone {
            xml.push_str(&format!("    <timezone>{tz}</timezone>\n"));
        }
        if let Some(ntp) = &phone.display.ntp_server {
            xml.push_str(&format!("    <ntpServer>{ntp}</ntpServer>\n"));
        }
        xml.push_str(&format!(
            "    <format24hr>{}</format24hr>\n",
            phone.display.time_24hr
        ));
        xml.push_str("  </time>\n\n");
    }

    // Display
    if phone.display.brightness.is_some()
        || phone.display.language.is_some()
        || phone.display.ringtone.is_some()
    {
        xml.push_str("  <display>\n");
        if let Some(brightness) = phone.display.brightness {
            xml.push_str(&format!("    <brightness>{brightness}</brightness>\n"));
        }
        if let Some(lang) = &phone.display.language {
            xml.push_str(&format!("    <language>{lang}</language>\n"));
        }
        if let Some(ringtone) = &phone.display.ringtone {
            xml.push_str(&format!("    <ringtone>{ringtone}</ringtone>\n"));
        }
        xml.push_str("  </display>\n\n");
    }

    // Directory (LDAP)
    if phone.directory.enabled {
        xml.push_str("  <directory>\n");
        if let Some(server) = &phone.directory.ldap_server {
            xml.push_str(&format!("    <ldapServer>{server}</ldapServer>\n"));
        }
        if let Some(port) = phone.directory.ldap_port {
            xml.push_str(&format!("    <ldapPort>{port}</ldapPort>\n"));
        }
        if let Some(base_dn) = &phone.directory.ldap_base_dn {
            xml.push_str(&format!("    <ldapBaseDN>{base_dn}</ldapBaseDN>\n"));
        }
        if let Some(bind_dn) = &phone.directory.ldap_bind_dn {
            xml.push_str(&format!("    <ldapBindDN>{bind_dn}</ldapBindDN>\n"));
        }
        if phone.directory.ldap_tls {
            xml.push_str("    <ldapTLS>true</ldapTLS>\n");
        }
        xml.push_str("  </directory>\n\n");
    }

    // Emergency
    if phone.emergency.emergency_number.is_some() {
        xml.push_str("  <emergency>\n");
        if let Some(num) = &phone.emergency.emergency_number {
            xml.push_str(&format!("    <number>{num}</number>\n"));
        }
        if let Some(loc) = &phone.emergency.location_id {
            xml.push_str(&format!("    <locationId>{loc}</locationId>\n"));
        }
        if let Some(elin) = &phone.emergency.elin {
            xml.push_str(&format!("    <elin>{elin}</elin>\n"));
        }
        xml.push_str("  </emergency>\n\n");
    }

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
    if phone.audio.noise_reduction {
        xml.push_str("    <noiseReduction>true</noiseReduction>\n");
    }
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
    use crate::model::{BlfEntry, Phone, PhoneLine, PhoneModel, SpeedDial};

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

    #[test]
    fn test_generate_9800_config_speed_dials() {
        let mut phone = test_phone();
        phone.speed_dials.push(SpeedDial {
            index: 1,
            label: "IT Support".to_string(),
            number: "9000".to_string(),
        });
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<speedDials>"));
        assert!(config.contains("label=\"IT Support\""));
        assert!(config.contains("number=\"9000\""));
    }

    #[test]
    fn test_generate_9800_config_blf() {
        let mut phone = test_phone();
        phone.blf_entries.push(BlfEntry {
            index: 1,
            label: "Helpdesk".to_string(),
            address: "5001@sbc.example.com".to_string(),
        });
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<blfEntries>"));
        assert!(config.contains("label=\"Helpdesk\""));
    }

    #[test]
    fn test_generate_9800_config_features() {
        let mut phone = test_phone();
        phone.features.auto_answer = true;
        phone.features.dnd = true;
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<features>"));
        assert!(config.contains("<autoAnswer>true</autoAnswer>"));
        assert!(config.contains("<dnd>true</dnd>"));
    }

    #[test]
    fn test_generate_9800_config_network() {
        let mut phone = test_phone();
        phone.network.vlan_id = Some(400);
        phone.network.qos_dscp = Some(46);
        phone.network.dot1x_enabled = true;
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<network>"));
        assert!(config.contains("<vlan>400</vlan>"));
        assert!(config.contains("<qosDscp>46</qosDscp>"));
        assert!(config.contains("<dot1x>true</dot1x>"));
    }

    #[test]
    fn test_generate_9800_config_time() {
        let mut phone = test_phone();
        phone.display.timezone = Some("US/Pacific".to_string());
        phone.display.ntp_server = Some("ntp.example.com".to_string());
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<time>"));
        assert!(config.contains("<timezone>US/Pacific</timezone>"));
        assert!(config.contains("<ntpServer>ntp.example.com</ntpServer>"));
    }

    #[test]
    fn test_generate_9800_config_display() {
        let mut phone = test_phone();
        phone.display.brightness = Some(80);
        phone.display.language = Some("en".to_string());
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<display>"));
        assert!(config.contains("<brightness>80</brightness>"));
        assert!(config.contains("<language>en</language>"));
    }

    #[test]
    fn test_generate_9800_config_directory() {
        let mut phone = test_phone();
        phone.directory.enabled = true;
        phone.directory.ldap_server = Some("ldap.example.com".to_string());
        phone.directory.ldap_base_dn = Some("dc=corp,dc=com".to_string());
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<directory>"));
        assert!(config.contains("<ldapServer>ldap.example.com</ldapServer>"));
        assert!(config.contains("<ldapBaseDN>dc=corp,dc=com</ldapBaseDN>"));
    }

    #[test]
    fn test_generate_9800_config_emergency() {
        let mut phone = test_phone();
        phone.emergency.emergency_number = Some("911".to_string());
        phone.emergency.location_id = Some("LOC-001".to_string());
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<emergency>"));
        assert!(config.contains("<number>911</number>"));
        assert!(config.contains("<locationId>LOC-001</locationId>"));
    }

    #[test]
    fn test_generate_9800_config_noise_reduction() {
        let mut phone = test_phone();
        phone.audio.noise_reduction = true;
        let config = generate_9800_config(&phone, "sbc.example.com");
        assert!(config.contains("<noiseReduction>true</noiseReduction>"));
    }
}
