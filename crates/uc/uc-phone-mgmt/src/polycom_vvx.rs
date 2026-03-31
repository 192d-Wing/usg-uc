//! Polycom VVX series provisioning configuration generator.

use crate::model::Phone;

/// Generate a Polycom VVX provisioning XML configuration.
///
/// Produces a valid Polycom UC Software XML config with SIP registration,
/// line appearances, voicemail, call forwarding, and codec preferences.
#[must_use]
pub fn generate_vvx_config(phone: &Phone, sbc_host: &str) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<polycomConfig xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
"#,
    );

    // SIP server configuration
    xml.push_str("  <sipServerConfig>\n");
    if let Some(line) = phone.lines.first() {
        xml.push_str(&format!(
            "    <sipServer.1.address>{sbc_host}</sipServer.1.address>\n"
        ));
        xml.push_str(&format!(
            "    <sipServer.1.port>{}</sipServer.1.port>\n",
            line.sip_port
        ));
        xml.push_str(&format!(
            "    <sipServer.1.transport>{}</sipServer.1.transport>\n",
            line.transport.to_uppercase()
        ));
        xml.push_str("    <sipServer.1.expires>3600</sipServer.1.expires>\n");
    }
    xml.push_str("  </sipServerConfig>\n\n");

    // Line registrations
    for line in &phone.lines {
        let i = line.index;
        xml.push_str(&format!("  <reg reg.{i}.displayName=\"{}\" reg.{i}.label=\"{}\" reg.{i}.address=\"{}\" reg.{i}.auth.userId=\"{}\" reg.{i}.auth.password=\"{}\" />\n",
            line.display_name, line.display_name, line.directory_number,
            line.sip_username, line.sip_password));
    }
    if !phone.lines.is_empty() {
        xml.push('\n');
    }

    // Voicemail configuration
    let has_voicemail = phone
        .lines
        .iter()
        .any(|l| l.voicemail_uri.is_some());
    if has_voicemail {
        xml.push_str("  <voiceMailConfig>\n");
        for line in &phone.lines {
            if let Some(vm) = &line.voicemail_uri {
                xml.push_str(&format!(
                    "    <msg.mwi.{}.subscribe=\"{}\" msg.mwi.{}.callBackMode=\"contact\" msg.mwi.{}.callBack=\"{}\" />\n",
                    line.index, vm, line.index, line.index, vm
                ));
            }
        }
        xml.push_str("  </voiceMailConfig>\n\n");
    }

    // Call forward configuration
    let has_cf = phone
        .lines
        .iter()
        .any(|l| l.call_forward.is_some());
    if has_cf {
        xml.push_str("  <callForwardConfig>\n");
        for line in &phone.lines {
            if let Some(cf) = &line.call_forward {
                let i = line.index;
                if let Some(all) = &cf.all {
                    xml.push_str(&format!(
                        "    <divert.{i}.autoOnSpecificCaller=\"1\" divert.{i}.contact=\"{all}\" />\n"
                    ));
                }
                if let Some(busy) = &cf.busy {
                    xml.push_str(&format!(
                        "    <divert.{i}.busy.contact=\"{busy}\" />\n"
                    ));
                }
                if let Some(na) = &cf.no_answer {
                    xml.push_str(&format!(
                        "    <divert.{i}.noanswer.contact=\"{na}\" divert.{i}.noanswer.timeout=\"{}\" />\n",
                        cf.no_answer_timeout
                    ));
                }
            }
        }
        xml.push_str("  </callForwardConfig>\n\n");
    }

    // Codec preferences
    xml.push_str("  <codecPref>\n");
    xml.push_str(
        "    <voice.codecPref.G722=\"1\" voice.codecPref.G711Mu=\"2\" voice.codecPref.G711A=\"3\" />\n",
    );
    xml.push_str("  </codecPref>\n\n");

    // Basic phone settings
    xml.push_str("  <phoneSettings>\n");
    xml.push_str("    <lcl.datetime.time.24HourClock=\"1\" />\n");
    xml.push_str("    <device.set=\"1\" device.auth.localAdminPassword=\"\" />\n");
    xml.push_str("  </phoneSettings>\n");

    xml.push_str("</polycomConfig>\n");
    xml
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{CallForward, Phone, PhoneLine, PhoneModel};

    fn test_phone() -> Phone {
        let mut phone = Phone::new("aa:bb:cc:dd:ee:ff", PhoneModel::PolycomVVX450, "Test VVX");
        phone.lines.push(PhoneLine {
            index: 1,
            directory_number: "1001".to_string(),
            display_name: "John Doe".to_string(),
            user_id: None,
            sip_username: "1001".to_string(),
            sip_password: "secret123".to_string(),
            sip_server: "sbc.example.com".to_string(),
            sip_port: 5060,
            transport: "udp".to_string(),
            voicemail_uri: Some("*97".to_string()),
            call_forward: Some(CallForward {
                all: None,
                busy: Some("1099".to_string()),
                no_answer: Some("1099".to_string()),
                no_answer_timeout: 20,
            }),
        });
        phone
    }

    #[test]
    fn test_generate_vvx_config_contains_server() {
        let phone = test_phone();
        let config = generate_vvx_config(&phone, "sbc.example.com");
        assert!(config.contains("<sipServer.1.address>sbc.example.com</sipServer.1.address>"));
        assert!(config.contains("<sipServer.1.port>5060</sipServer.1.port>"));
    }

    #[test]
    fn test_generate_vvx_config_contains_line() {
        let phone = test_phone();
        let config = generate_vvx_config(&phone, "sbc.example.com");
        assert!(config.contains("reg.1.address=\"1001\""));
        assert!(config.contains("reg.1.auth.userId=\"1001\""));
        assert!(config.contains("reg.1.displayName=\"John Doe\""));
    }

    #[test]
    fn test_generate_vvx_config_contains_voicemail() {
        let phone = test_phone();
        let config = generate_vvx_config(&phone, "sbc.example.com");
        assert!(config.contains("msg.mwi.1.subscribe=\"*97\""));
    }

    #[test]
    fn test_generate_vvx_config_contains_call_forward() {
        let phone = test_phone();
        let config = generate_vvx_config(&phone, "sbc.example.com");
        assert!(config.contains("divert.1.busy.contact=\"1099\""));
        assert!(config.contains("divert.1.noanswer.contact=\"1099\""));
    }

    #[test]
    fn test_generate_vvx_config_contains_codecs() {
        let phone = test_phone();
        let config = generate_vvx_config(&phone, "sbc.example.com");
        assert!(config.contains("voice.codecPref.G722"));
        assert!(config.contains("voice.codecPref.G711Mu"));
    }
}
