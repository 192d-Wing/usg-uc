//! Teo / Tone Commander 7810, 7810-TSG, 4104, 4101 provisioning XML.
//!
//! Generates configuration files conforming to the Teo IP Telephone XML schema
//! (`TEO_settings schema_vers="2.0"`), served from the SBC's update server at
//! `<update_server>/<UPPERCASE_MAC>.xml`. See `13-280132 Rev. R` for the full
//! schema reference.

use std::fmt::Write as _;

use crate::model::{Phone, PhoneModel};

/// Generate a Teo phone XML configuration.
///
/// `sbc_host` is used for both the SIP proxy/registrar and the update server
/// self-reference (so the phone keeps polling the SBC for config refreshes).
#[must_use]
pub fn generate_teo_config(phone: &Phone, sbc_host: &str) -> String {
    let model_attr = teo_model_attr(&phone.model);
    let mut xml = String::with_capacity(2048);

    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        xml,
        "<!-- SBC-generated config for {} (MAC {}) -->",
        xml_escape(&phone.name),
        xml_escape(&phone.mac_address),
    );
    xml.push_str("<TEO_settings schema_vers=\"2.0\">\n");
    let _ = writeln!(xml, "  <TEO_phone model=\"{model_attr}\">");

    write_update_server(&mut xml, sbc_host);
    write_sip_settings(&mut xml, phone, sbc_host);
    write_dial_plan(&mut xml, phone);
    write_line_keys(&mut xml, phone);

    xml.push_str("  </TEO_phone>\n");
    xml.push_str("</TEO_settings>\n");
    xml
}

/// Path component for the phone's config download.
///
/// Teo spec p.19: "all capital letters must be used for the name of the
/// MAC.xml file". We also strip `:` and `-` separators.
#[must_use]
pub fn teo_config_filename(mac: &str) -> String {
    let clean = mac.replace([':', '-'], "").to_uppercase();
    format!("{clean}.xml")
}

const fn teo_model_attr(model: &PhoneModel) -> &'static str {
    match model {
        PhoneModel::Teo7810 => "7810",
        PhoneModel::Teo7810TSG => "7810-TSG",
        PhoneModel::Teo4104 => "4104",
        PhoneModel::Teo4101 => "4101",
        // Fallback to ALL for unexpected models — shouldn't happen in practice
        // because the dispatcher only routes "teo" family here.
        _ => "ALL",
    }
}

fn write_update_server(xml: &mut String, sbc_host: &str) {
    // Pin the update server to ourselves so the phone keeps polling for
    // config changes after first boot. STATIC source overrides any DHCP
    // Option 66/125 the phone may have received.
    xml.push_str("    <update>\n");
    let _ = writeln!(
        xml,
        "      <update_server source=\"STATIC\">http://{}/provision</update_server>",
        xml_escape(sbc_host),
    );
    xml.push_str("      <protocol>HTTP</protocol>\n");
    xml.push_str("      <config_auto>ON</config_auto>\n");
    xml.push_str("      <config_time>2</config_time>\n");
    xml.push_str("      <config_window>3</config_window>\n");
    xml.push_str("    </update>\n");
    // MAC.xml naming (default, but explicit here so a future global file can't
    // silently switch us to LINE-based naming).
    xml.push_str("    <config_file_name_base>MAC</config_file_name_base>\n");
}

fn write_sip_settings(xml: &mut String, phone: &Phone, sbc_host: &str) {
    // Use the first line's SIP server/port as the proxy; if no lines are
    // configured, fall back to the SBC host on 5060/UDP.
    let (sip_host, sip_port, transport) = phone.lines.first().map_or_else(
        || (sbc_host.to_string(), 5060u16, "udp".to_string()),
        |l| (l.sip_server.clone(), l.sip_port, l.transport.clone()),
    );

    let sip_transport = match transport.to_lowercase().as_str() {
        "tcp" => "TCP",
        "tls" => "TLS",
        _ => "UDP",
    };

    let _ = writeln!(xml, "    <sip_transport>{sip_transport}</sip_transport>");
    let _ = writeln!(
        xml,
        "    <sip_proxy_addr source=\"STATIC\">{}</sip_proxy_addr>",
        xml_escape(&sip_host),
    );
    let _ = writeln!(xml, "    <sip_proxy_port>{sip_port}</sip_proxy_port>");
    let _ = writeln!(
        xml,
        "    <sip_registrar>{}</sip_registrar>",
        xml_escape(&sip_host),
    );
    let _ = writeln!(xml, "    <sip_reg_port>{sip_port}</sip_reg_port>");
    xml.push_str("    <sip_registration>ON</sip_registration>\n");
}

fn write_dial_plan(xml: &mut String, phone: &Phone) {
    let emergency = phone.emergency.emergency_number.as_deref().unwrap_or("911");
    let _ = writeln!(
        xml,
        "    <emergency_number>{}</emergency_number>",
        xml_escape(emergency),
    );
}

fn write_line_keys(xml: &mut String, phone: &Phone) {
    if phone.lines.is_empty() {
        return;
    }
    xml.push_str("    <multi_function_key_list>\n");
    let max = phone.model.max_lines();
    for line in &phone.lines {
        if line.index == 0 || line.index > max {
            // Skip out-of-range line indices rather than producing invalid XML.
            continue;
        }
        let _ = writeln!(xml, "      <key num=\"{}\">LINE", line.index);
        let _ = writeln!(
            xml,
            "        <line_id>{}</line_id>",
            xml_escape(&teo_line_id(&line.directory_number)),
        );
        let _ = writeln!(
            xml,
            "        <sip_name>{}</sip_name>",
            xml_escape(&line.display_name),
        );
        let _ = writeln!(
            xml,
            "        <sip_auth_id>{}</sip_auth_id>",
            xml_escape(&line.sip_username),
        );
        let _ = writeln!(
            xml,
            "        <sip_password>{}</sip_password>",
            xml_escape(&line.sip_password),
        );
        let _ = writeln!(
            xml,
            "        <label>{}</label>",
            xml_escape(&line.display_name),
        );
        // Codec order: G.711μ-law primary, G.722 wideband secondary, G.729A as last
        // resort. Matches the SBC's default media negotiation order.
        xml.push_str("        <codec1>G711</codec1>\n");
        xml.push_str("        <codec2>G722</codec2>\n");
        xml.push_str("        <codec3>G729A</codec3>\n");
        xml.push_str("        <ptime>20</ptime>\n");
        xml.push_str("        <jitter_buffer_adaptive>ON</jitter_buffer_adaptive>\n");
        xml.push_str("      </key>\n");
    }
    xml.push_str("    </multi_function_key_list>\n");
}

/// Normalize a directory number for use in TEO `<line_id>`. Strips an E.164
/// NANP prefix (`+1`) so a stored `+12139160002` renders as `2139160002`,
/// which is what TEO firmware expects for the on-screen line label. Plain
/// extensions (`2001`) pass through unchanged.
fn teo_line_id(dn: &str) -> String {
    dn.strip_prefix("+1")
        .or_else(|| dn.strip_prefix('+'))
        .unwrap_or(dn)
        .to_string()
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{Phone, PhoneLine, PhoneModel};

    fn phone_with_one_line(model: PhoneModel) -> Phone {
        let mut phone = Phone::new("00:04:8d:00:00:f5", model, "Front Desk");
        phone.lines.push(PhoneLine {
            index: 1,
            directory_number: "2001".into(),
            display_name: "Alex G".into(),
            user_id: None,
            sip_username: "alex".into(),
            sip_password: "s3cret".into(),
            sip_server: "sbc.example.mil".into(),
            sip_port: 5060,
            transport: "udp".into(),
            voicemail_uri: None,
            call_forward: None,
        });
        phone
    }

    #[test]
    fn filename_uppercases_mac_and_strips_separators() {
        assert_eq!(teo_config_filename("00:04:8d:00:00:f5"), "00048D0000F5.xml");
        assert_eq!(teo_config_filename("aa-bb-cc-dd-ee-ff"), "AABBCCDDEEFF.xml");
        assert_eq!(teo_config_filename("AABBCCDDEEFF"), "AABBCCDDEEFF.xml");
    }

    #[test]
    fn generates_well_formed_root_for_7810() {
        let phone = phone_with_one_line(PhoneModel::Teo7810);
        let xml = generate_teo_config(&phone, "sbc.example.mil");
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<TEO_settings schema_vers=\"2.0\">"));
        assert!(xml.contains("<TEO_phone model=\"7810\">"));
        assert!(xml.contains("</TEO_phone>"));
        assert!(xml.contains("</TEO_settings>"));
    }

    #[test]
    fn model_attr_matches_spec_strings() {
        assert!(
            generate_teo_config(&phone_with_one_line(PhoneModel::Teo7810TSG), "h")
                .contains("model=\"7810-TSG\"")
        );
        assert!(
            generate_teo_config(&phone_with_one_line(PhoneModel::Teo4104), "h")
                .contains("model=\"4104\"")
        );
        assert!(
            generate_teo_config(&phone_with_one_line(PhoneModel::Teo4101), "h")
                .contains("model=\"4101\"")
        );
    }

    #[test]
    fn embeds_sip_credentials_inside_line_key() {
        let xml = generate_teo_config(&phone_with_one_line(PhoneModel::Teo7810), "sbc.lab");
        assert!(xml.contains("<key num=\"1\">LINE"));
        assert!(xml.contains("<line_id>2001</line_id>"));
        assert!(xml.contains("<sip_auth_id>alex</sip_auth_id>"));
        assert!(xml.contains("<sip_password>s3cret</sip_password>"));
        assert!(xml.contains("<sip_proxy_addr source=\"STATIC\">sbc.example.mil</sip_proxy_addr>"));
        assert!(xml.contains("<sip_proxy_port>5060</sip_proxy_port>"));
    }

    #[test]
    fn line_id_strips_e164_nanp_prefix() {
        let mut phone = phone_with_one_line(PhoneModel::Teo7810TSG);
        phone.lines[0].directory_number = "+12139160002".into();
        let xml = generate_teo_config(&phone, "sbc.lab");
        assert!(xml.contains("<line_id>2139160002</line_id>"));
        assert!(!xml.contains("+12139160002"));
    }

    #[test]
    fn update_server_points_at_sbc_for_refresh() {
        let xml = generate_teo_config(&phone_with_one_line(PhoneModel::Teo7810), "sbc.lab");
        assert!(xml
            .contains("<update_server source=\"STATIC\">http://sbc.lab/provision</update_server>"));
        assert!(xml.contains("<config_file_name_base>MAC</config_file_name_base>"));
    }

    #[test]
    fn xml_escapes_special_chars_in_user_values() {
        let mut phone = phone_with_one_line(PhoneModel::Teo7810);
        phone.lines[0].display_name = "A & B <test>".into();
        phone.lines[0].sip_password = "p\"ass'word".into();
        let xml = generate_teo_config(&phone, "h");
        assert!(xml.contains("<sip_name>A &amp; B &lt;test&gt;</sip_name>"));
        assert!(xml.contains("<sip_password>p&quot;ass&apos;word</sip_password>"));
        assert!(!xml.contains("A & B <test>"));
    }

    #[test]
    fn transport_attr_maps_correctly() {
        let mut phone = phone_with_one_line(PhoneModel::Teo7810);
        phone.lines[0].transport = "tls".into();
        assert!(generate_teo_config(&phone, "h").contains("<sip_transport>TLS</sip_transport>"));

        phone.lines[0].transport = "tcp".into();
        assert!(generate_teo_config(&phone, "h").contains("<sip_transport>TCP</sip_transport>"));

        phone.lines[0].transport = "udp".into();
        assert!(generate_teo_config(&phone, "h").contains("<sip_transport>UDP</sip_transport>"));
    }

    #[test]
    fn skips_lines_outside_max_index() {
        let mut phone = phone_with_one_line(PhoneModel::Teo4101);
        phone.lines.push(PhoneLine {
            index: 5, // out of range for 4101 (max_lines = 1)
            ..phone.lines[0].clone()
        });
        let xml = generate_teo_config(&phone, "h");
        assert!(xml.contains("<key num=\"1\">LINE"));
        assert!(!xml.contains("<key num=\"5\">LINE"));
    }

    #[test]
    fn no_lines_omits_multifunction_block() {
        let phone = Phone::new("00:04:8d:00:00:f5", PhoneModel::Teo7810, "Lobby");
        let xml = generate_teo_config(&phone, "h");
        assert!(!xml.contains("<multi_function_key_list>"));
        // SIP block still emitted with SBC defaults.
        assert!(xml.contains("<sip_proxy_addr source=\"STATIC\">h</sip_proxy_addr>"));
    }
}
