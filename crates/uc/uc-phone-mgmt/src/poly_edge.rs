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
    use crate::model::{Phone, PhoneLine, PhoneModel};

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
}
