//! Poly Edge series provisioning configuration generator.

use crate::model::Phone;

/// Generate a Poly Edge series provisioning XML configuration.
///
/// Produces an XML config with `<phone>` root element containing SIP settings,
/// line appearances, provisioning server URL, and codec preferences.
#[must_use]
pub fn generate_edge_config(phone: &Phone, sbc_host: &str) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<phone>
"#,
    );

    // SIP section
    xml.push_str("  <sip>\n");
    if let Some(line) = phone.lines.first() {
        xml.push_str(&format!(
            "    <server>{sbc_host}</server>\n"
        ));
        xml.push_str(&format!("    <port>{}</port>\n", line.sip_port));
        xml.push_str(&format!(
            "    <transport>{}</transport>\n",
            line.transport.to_uppercase()
        ));
        xml.push_str("    <expires>3600</expires>\n");
    }

    // Line entries within SIP section
    for line in &phone.lines {
        xml.push_str(&format!("    <line index=\"{}\">\n", line.index));
        xml.push_str(&format!(
            "      <address>{}</address>\n",
            line.directory_number
        ));
        xml.push_str(&format!(
            "      <displayName>{}</displayName>\n",
            line.display_name
        ));
        xml.push_str(&format!(
            "      <authUser>{}</authUser>\n",
            line.sip_username
        ));
        xml.push_str(&format!(
            "      <authPassword>{}</authPassword>\n",
            line.sip_password
        ));
        xml.push_str(&format!(
            "      <label>{}</label>\n",
            line.display_name
        ));
        if let Some(vm) = &line.voicemail_uri {
            xml.push_str(&format!("      <voicemail>{vm}</voicemail>\n"));
        }
        if let Some(cf) = &line.call_forward {
            xml.push_str("      <callForward>\n");
            if let Some(all) = &cf.all {
                xml.push_str(&format!("        <all>{all}</all>\n"));
            }
            if let Some(busy) = &cf.busy {
                xml.push_str(&format!("        <busy>{busy}</busy>\n"));
            }
            if let Some(na) = &cf.no_answer {
                xml.push_str(&format!("        <noAnswer>{na}</noAnswer>\n"));
                xml.push_str(&format!(
                    "        <noAnswerTimeout>{}</noAnswerTimeout>\n",
                    cf.no_answer_timeout
                ));
            }
            xml.push_str("      </callForward>\n");
        }
        xml.push_str("    </line>\n");
    }

    xml.push_str("  </sip>\n\n");

    // Speed dials
    if !phone.speed_dials.is_empty() {
        xml.push_str("  <speedDial>\n");
        for sd in &phone.speed_dials {
            xml.push_str(&format!(
                "    <entry index=\"{}\" label=\"{}\" number=\"{}\" />\n",
                sd.index, sd.label, sd.number
            ));
        }
        xml.push_str("  </speedDial>\n\n");
    }

    // BLF entries
    if !phone.blf_entries.is_empty() {
        xml.push_str("  <blf>\n");
        for blf in &phone.blf_entries {
            xml.push_str(&format!(
                "    <entry index=\"{}\" label=\"{}\" address=\"{}\" />\n",
                blf.index, blf.label, blf.address
            ));
        }
        xml.push_str("  </blf>\n\n");
    }

    // Features
    if phone.features.auto_answer
        || phone.features.dnd
        || phone.features.intercom
        || phone.paging.enabled
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
        if phone.paging.enabled {
            xml.push_str("    <paging>true</paging>\n");
        }
        xml.push_str("  </features>\n\n");
    }

    // Network
    if phone.network.vlan_id.is_some()
        || phone.network.cdp_enabled
        || phone.network.lldp_enabled
        || phone.network.dot1x_enabled
    {
        xml.push_str("  <network>\n");
        if let Some(vlan) = phone.network.vlan_id {
            xml.push_str(&format!("    <vlan>{vlan}</vlan>\n"));
        }
        if phone.network.cdp_enabled {
            xml.push_str("    <cdp>true</cdp>\n");
        }
        if phone.network.lldp_enabled {
            xml.push_str("    <lldp>true</lldp>\n");
        }
        if phone.network.dot1x_enabled {
            xml.push_str("    <dot1x>true</dot1x>\n");
        }
        xml.push_str("  </network>\n\n");
    }

    // Time
    if phone.display.timezone.is_some()
        || phone.display.ntp_server.is_some()
    {
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

    // Audio
    if phone.audio.noise_reduction || phone.audio.headset_mode != crate::model::HeadsetMode::Wired {
        xml.push_str("  <audio>\n");
        xml.push_str(&format!(
            "    <headset>{:?}</headset>\n",
            phone.audio.headset_mode
        ));
        if phone.audio.noise_reduction {
            xml.push_str("    <noiseReduction>true</noiseReduction>\n");
        }
        xml.push_str("  </audio>\n\n");
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

    // Provisioning section
    xml.push_str("  <provisioning>\n");
    xml.push_str(&format!(
        "    <serverUrl>https://{sbc_host}/provisioning</serverUrl>\n"
    ));
    xml.push_str("    <interval>3600</interval>\n");
    xml.push_str("  </provisioning>\n\n");

    // Codec settings
    xml.push_str("  <codecs>\n");
    xml.push_str("    <codec priority=\"1\">G722</codec>\n");
    xml.push_str("    <codec priority=\"2\">G711u</codec>\n");
    xml.push_str("    <codec priority=\"3\">G711a</codec>\n");
    xml.push_str("  </codecs>\n");

    xml.push_str("</phone>\n");
    xml
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{BlfEntry, Phone, PhoneLine, PhoneModel, SpeedDial};

    fn test_phone() -> Phone {
        let mut phone = Phone::new("11:22:33:44:55:66", PhoneModel::PolyEdgeE450, "Test Edge");
        phone.lines.push(PhoneLine {
            index: 1,
            directory_number: "2001".to_string(),
            display_name: "Jane Smith".to_string(),
            user_id: None,
            sip_username: "2001".to_string(),
            sip_password: "pass456".to_string(),
            sip_server: "sbc.example.com".to_string(),
            sip_port: 5060,
            transport: "tls".to_string(),
            voicemail_uri: Some("*97".to_string()),
            call_forward: None,
        });
        phone
    }

    #[test]
    fn test_generate_edge_config_structure() {
        let phone = test_phone();
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<phone>"));
        assert!(config.contains("</phone>"));
        assert!(config.contains("<sip>"));
        assert!(config.contains("<provisioning>"));
        assert!(config.contains("<codecs>"));
    }

    #[test]
    fn test_generate_edge_config_server() {
        let phone = test_phone();
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<server>sbc.example.com</server>"));
        assert!(config.contains("<port>5060</port>"));
        assert!(config.contains("<transport>TLS</transport>"));
    }

    #[test]
    fn test_generate_edge_config_line() {
        let phone = test_phone();
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<line index=\"1\">"));
        assert!(config.contains("<address>2001</address>"));
        assert!(config.contains("<authUser>2001</authUser>"));
        assert!(config.contains("<displayName>Jane Smith</displayName>"));
        assert!(config.contains("<voicemail>*97</voicemail>"));
    }

    #[test]
    fn test_generate_edge_config_speed_dials() {
        let mut phone = test_phone();
        phone.speed_dials.push(SpeedDial {
            index: 1,
            label: "Reception".to_string(),
            number: "1000".to_string(),
        });
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<speedDial>"));
        assert!(config.contains("label=\"Reception\""));
        assert!(config.contains("number=\"1000\""));
    }

    #[test]
    fn test_generate_edge_config_blf() {
        let mut phone = test_phone();
        phone.blf_entries.push(BlfEntry {
            index: 1,
            label: "Manager".to_string(),
            address: "1005@sbc.example.com".to_string(),
        });
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<blf>"));
        assert!(config.contains("label=\"Manager\""));
    }

    #[test]
    fn test_generate_edge_config_features() {
        let mut phone = test_phone();
        phone.features.auto_answer = true;
        phone.features.dnd = true;
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<features>"));
        assert!(config.contains("<autoAnswer>true</autoAnswer>"));
        assert!(config.contains("<dnd>true</dnd>"));
    }

    #[test]
    fn test_generate_edge_config_network() {
        let mut phone = test_phone();
        phone.network.vlan_id = Some(200);
        phone.network.lldp_enabled = true;
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<network>"));
        assert!(config.contains("<vlan>200</vlan>"));
        assert!(config.contains("<lldp>true</lldp>"));
    }

    #[test]
    fn test_generate_edge_config_time() {
        let mut phone = test_phone();
        phone.display.timezone = Some("America/New_York".to_string());
        phone.display.ntp_server = Some("pool.ntp.org".to_string());
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<time>"));
        assert!(config.contains("<timezone>America/New_York</timezone>"));
        assert!(config.contains("<ntpServer>pool.ntp.org</ntpServer>"));
    }

    #[test]
    fn test_generate_edge_config_directory() {
        let mut phone = test_phone();
        phone.directory.enabled = true;
        phone.directory.ldap_server = Some("ldap.example.com".to_string());
        phone.directory.ldap_base_dn = Some("dc=example,dc=com".to_string());
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<directory>"));
        assert!(config.contains("<ldapServer>ldap.example.com</ldapServer>"));
        assert!(config.contains("<ldapBaseDN>dc=example,dc=com</ldapBaseDN>"));
    }

    #[test]
    fn test_generate_edge_config_emergency() {
        let mut phone = test_phone();
        phone.emergency.emergency_number = Some("911".to_string());
        let config = generate_edge_config(&phone, "sbc.example.com");
        assert!(config.contains("<emergency>"));
        assert!(config.contains("<number>911</number>"));
    }
}
