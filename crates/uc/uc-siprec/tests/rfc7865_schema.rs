//! Property tests: attacker-chosen display names and AORs either serialize
//! to well-formed, round-trippable XML or are rejected; never a panic.

use proptest::prelude::*;
use uc_siprec::{Participant, RecordingMetadata, SiprecError};

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#9;", "\t")
        .replace("&#10;", "\n")
        .replace("&#13;", "\r")
        .replace("&amp;", "&")
}

fn between<'a>(hay: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = hay.find(start)? + start.len();
    let j = hay.get(i..)?.find(end)? + i;
    hay.get(i..j)
}

proptest! {
    #[test]
    fn display_name_and_aor_round_trip(name in any::<String>(), aor in any::<String>()) {
        prop_assume!(name.len() <= 1024 && aor.len() <= 1024);
        let mut m = RecordingMetadata::new("c");
        m.add_participant(Participant::new("p", aor.clone()).with_display_name(name.clone()));
        match m.to_rfc7865_xml() {
            Err(SiprecError::InvalidMetadata { .. }) => {}
            Err(e) => prop_assert!(false, "unexpected error {e}"),
            Ok(xml) => {
                let text = between(&xml, "<name>", "</name>").unwrap_or("");
                prop_assert!(!text.contains('<'));
                prop_assert_eq!(unescape(text), name);
                let attr = between(&xml, "aor=\"", "\"").unwrap_or("");
                prop_assert!(!attr.contains('<') && !attr.contains('\n'));
                prop_assert_eq!(unescape(attr), aor);
                prop_assert_eq!(xml.matches("<participant ").count(), 1);
            }
        }
    }
}
