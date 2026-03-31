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

    // Speed dials
    if !phone.speed_dials.is_empty() {
        xml.push_str("  <!-- Speed Dials -->\n");
        for sd in &phone.speed_dials {
            xml.push_str(&format!(
                "  <Speed_Dial_{}_Name>{}</Speed_Dial_{}_Name>\n",
                sd.index, sd.label, sd.index
            ));
            xml.push_str(&format!(
                "  <Speed_Dial_{}_Number>{}</Speed_Dial_{}_Number>\n",
                sd.index, sd.number, sd.index
            ));
        }
        xml.push('\n');
    }

    // BLF entries (Extended Function keys)
    if !phone.blf_entries.is_empty() {
        xml.push_str("  <!-- BLF Entries -->\n");
        for blf in &phone.blf_entries {
            xml.push_str(&format!(
                "  <Extended_Function_{}_>fnc=blf+sd;sub={};nme={}</Extended_Function_{}_>\n",
                blf.index, blf.address, blf.label, blf.index
            ));
        }
        xml.push('\n');
    }

    // Auto-answer
    if phone.features.auto_answer {
        xml.push_str("  <Auto_Answer_Page>Yes</Auto_Answer_Page>\n");
    }

    // DND
    if phone.features.dnd {
        xml.push_str("  <DND_Setting>Yes</DND_Setting>\n");
    }

    if phone.features.auto_answer || phone.features.dnd {
        xml.push('\n');
    }

    // Network settings
    if phone.network.vlan_id.is_some()
        || phone.network.cdp_enabled
        || phone.network.lldp_enabled
    {
        xml.push_str("  <!-- Network -->\n");
        if let Some(vlan) = phone.network.vlan_id {
            xml.push_str(&format!("  <VLAN_ID_>{vlan}</VLAN_ID_>\n"));
        }
        if phone.network.cdp_enabled {
            xml.push_str("  <CDP_Enable>Yes</CDP_Enable>\n");
        }
        if phone.network.lldp_enabled {
            xml.push_str("  <LLDP_Enable>Yes</LLDP_Enable>\n");
        }
        xml.push('\n');
    }

    // NTP / Timezone
    if phone.display.ntp_server.is_some() || phone.display.timezone.is_some() {
        xml.push_str("  <!-- Time -->\n");
        if let Some(ntp) = &phone.display.ntp_server {
            xml.push_str(&format!(
                "  <Primary_NTP_Server>{ntp}</Primary_NTP_Server>\n"
            ));
        }
        if let Some(tz) = &phone.display.timezone {
            xml.push_str(&format!("  <Time_Zone>{tz}</Time_Zone>\n"));
        }
        xml.push('\n');
    }

    // Directory (LDAP)
    if phone.directory.enabled {
        xml.push_str("  <!-- Directory -->\n");
        xml.push_str("  <LDAP_Dir_Enable>Yes</LDAP_Dir_Enable>\n");
        if let Some(server) = &phone.directory.ldap_server {
            xml.push_str(&format!(
                "  <LDAP_Corp_Dir_Server>{server}</LDAP_Corp_Dir_Server>\n"
            ));
        }
        if let Some(base_dn) = &phone.directory.ldap_base_dn {
            xml.push_str(&format!(
                "  <LDAP_Search_Base>{base_dn}</LDAP_Search_Base>\n"
            ));
        }
        if let Some(bind_dn) = &phone.directory.ldap_bind_dn {
            xml.push_str(&format!(
                "  <LDAP_Bind_DN>{bind_dn}</LDAP_Bind_DN>\n"
            ));
        }
        if let Some(pw) = &phone.directory.ldap_password {
            xml.push_str(&format!(
                "  <LDAP_Password>{pw}</LDAP_Password>\n"
            ));
        }
        xml.push('\n');
    }

    // Emergency
    if let Some(num) = &phone.emergency.emergency_number {
        xml.push_str(&format!(
            "  <Emergency_Number>{num}</Emergency_Number>\n\n"
        ));
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
    use crate::model::{BlfEntry, Phone, PhoneLine, PhoneModel, SpeedDial};

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

    #[test]
    fn test_generate_mpp_config_speed_dials() {
        let mut phone = test_phone();
        phone.speed_dials.push(SpeedDial {
            index: 1,
            label: "Help Desk".to_string(),
            number: "5000".to_string(),
        });
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<Speed_Dial_1_Name>Help Desk</Speed_Dial_1_Name>"));
        assert!(config.contains("<Speed_Dial_1_Number>5000</Speed_Dial_1_Number>"));
    }

    #[test]
    fn test_generate_mpp_config_blf() {
        let mut phone = test_phone();
        phone.blf_entries.push(BlfEntry {
            index: 1,
            label: "Boss".to_string(),
            address: "1002@sbc.example.com".to_string(),
        });
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("fnc=blf+sd;sub=1002@sbc.example.com;nme=Boss"));
    }

    #[test]
    fn test_generate_mpp_config_features() {
        let mut phone = test_phone();
        phone.features.auto_answer = true;
        phone.features.dnd = true;
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<Auto_Answer_Page>Yes</Auto_Answer_Page>"));
        assert!(config.contains("<DND_Setting>Yes</DND_Setting>"));
    }

    #[test]
    fn test_generate_mpp_config_network() {
        let mut phone = test_phone();
        phone.network.vlan_id = Some(300);
        phone.network.cdp_enabled = true;
        phone.network.lldp_enabled = true;
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<VLAN_ID_>300</VLAN_ID_>"));
        assert!(config.contains("<CDP_Enable>Yes</CDP_Enable>"));
        assert!(config.contains("<LLDP_Enable>Yes</LLDP_Enable>"));
    }

    #[test]
    fn test_generate_mpp_config_time() {
        let mut phone = test_phone();
        phone.display.ntp_server = Some("time.example.com".to_string());
        phone.display.timezone = Some("EST".to_string());
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<Primary_NTP_Server>time.example.com</Primary_NTP_Server>"));
        assert!(config.contains("<Time_Zone>EST</Time_Zone>"));
    }

    #[test]
    fn test_generate_mpp_config_directory() {
        let mut phone = test_phone();
        phone.directory.enabled = true;
        phone.directory.ldap_server = Some("ldap.example.com".to_string());
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<LDAP_Dir_Enable>Yes</LDAP_Dir_Enable>"));
        assert!(config.contains("<LDAP_Corp_Dir_Server>ldap.example.com</LDAP_Corp_Dir_Server>"));
    }

    #[test]
    fn test_generate_mpp_config_emergency() {
        let mut phone = test_phone();
        phone.emergency.emergency_number = Some("911".to_string());
        let config = generate_mpp_config(&phone, "sbc.example.com");
        assert!(config.contains("<Emergency_Number>911</Emergency_Number>"));
    }
}
