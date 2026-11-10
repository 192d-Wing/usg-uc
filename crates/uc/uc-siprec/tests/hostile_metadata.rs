//! QA: hostile/malformed metadata input, cap boundaries, and multipart
//! boundary handling for the RFC 7865 serializer and RFC 7866 builder.

use proto_sdp::SessionDescription;
use uc_siprec::metadata::{MAX_FIELD_BYTES, MAX_PARTICIPANTS, MAX_STREAMS};
use uc_siprec::{
    MediaStream, Participant, RecordingMetadata, SdesKey, SiprecError, build_rs_offer,
};

fn two_keys() -> Result<Vec<SdesKey>, SiprecError> {
    Ok(vec![SdesKey::generate()?, SdesKey::generate()?])
}

type R = Result<(), Box<dyn std::error::Error>>;
type Mutator = Box<dyn Fn(&mut RecordingMetadata)>;

fn full_house() -> RecordingMetadata {
    let mut m = RecordingMetadata::new("c");
    for i in 0..MAX_PARTICIPANTS {
        m.add_participant(Participant::new(format!("p{i}"), "sip:a@example.com"));
    }
    for i in 0..MAX_STREAMS {
        m.add_stream(MediaStream::audio(format!("s{i}")).with_participant(format!("p{}", i % 16)));
    }
    m
}

#[test]
fn caps_exactly_at_limit_are_accepted() -> R {
    let xml = full_house().to_rfc7865_xml()?;
    assert_eq!(xml.matches("<participant ").count(), MAX_PARTICIPANTS);
    assert_eq!(xml.matches("<stream ").count(), MAX_STREAMS);
    Ok(())
}

#[test]
fn field_cap_is_inclusive_and_counts_bytes() -> R {
    // 1024 bytes exactly: accepted, for every capped field.
    let mut m = RecordingMetadata::new("c");
    m.session.sip_session_id = Some("a".repeat(MAX_FIELD_BYTES));
    m.add_participant(
        Participant::new("p", "b".repeat(MAX_FIELD_BYTES))
            .with_display_name("\u{e9}".repeat(MAX_FIELD_BYTES / 2)),
    );
    m.add_stream(MediaStream::audio("x".repeat(MAX_FIELD_BYTES)).with_participant("p"));
    m.to_rfc7865_xml()?;

    // One byte over, per field (multibyte counts as bytes, not chars).
    let over: [Mutator; 4] = [
        Box::new(|m| m.session.sip_session_id = Some("a".repeat(MAX_FIELD_BYTES + 1))),
        Box::new(|m| {
            m.add_participant(
                Participant::new("q", "sip:q@x").with_display_name("\u{e9}".repeat(513)),
            );
        }),
        Box::new(|m| m.add_participant(Participant::new("q", "b".repeat(MAX_FIELD_BYTES + 1)))),
        Box::new(|m| m.add_stream(MediaStream::audio("y".repeat(MAX_FIELD_BYTES + 1)))),
    ];
    for (i, f) in over.iter().enumerate() {
        let mut m = RecordingMetadata::new("c");
        f(&mut m);
        assert!(
            matches!(
                m.to_rfc7865_xml(),
                Err(SiprecError::LimitExceeded {
                    what: "metadata field bytes",
                    limit: MAX_FIELD_BYTES
                })
            ),
            "case {i}"
        );
    }
    Ok(())
}

#[test]
fn hostile_sip_session_id_is_escaped_or_rejected() -> R {
    let mut m = RecordingMetadata::new("c");
    m.session.sip_session_id = Some("]]></sipSessionID><x a='1'>&".into());
    let xml = m.to_rfc7865_xml()?;
    assert!(xml.contains(
        "<sipSessionID>]]&gt;&lt;/sipSessionID&gt;&lt;x a=&apos;1&apos;&gt;&amp;</sipSessionID>"
    ));
    assert_eq!(xml.matches("</sipSessionID>").count(), 1);

    for bad in ["a\0b", "a\u{1B}b", "\u{FFFE}", "\u{FFFF}", "x\u{8}"] {
        let mut m = RecordingMetadata::new("c");
        m.session.sip_session_id = Some(bad.into());
        assert!(
            matches!(m.to_rfc7865_xml(), Err(SiprecError::InvalidMetadata { .. })),
            "{bad:?}"
        );
    }
    Ok(())
}

#[test]
fn illegal_code_points_rejected_in_aor_and_name() {
    for bad in ["\0", "\u{7}", "\u{C}", "\u{FFFF}"] {
        let mut m = RecordingMetadata::new("c");
        m.add_participant(Participant::new("p", format!("sip:{bad}@x")));
        assert!(matches!(
            m.to_rfc7865_xml(),
            Err(SiprecError::InvalidMetadata { .. })
        ));
        let mut m = RecordingMetadata::new("c");
        m.add_participant(Participant::new("p", "sip:a@x").with_display_name(bad));
        assert!(matches!(
            m.to_rfc7865_xml(),
            Err(SiprecError::InvalidMetadata { .. })
        ));
    }
}

#[test]
fn legal_but_unusual_code_points_are_preserved() -> R {
    // C1 controls, DEL, U+FFFD and astral chars are legal XML 1.0 Char.
    let name = "\u{7F}\u{85}\u{9F}\u{FFFD}\u{1F600}";
    let mut m = RecordingMetadata::new("c");
    m.add_participant(Participant::new("p", "sip:a@x").with_display_name(name));
    let xml = m.to_rfc7865_xml()?;
    assert!(xml.contains(&format!("<name>{name}</name>")));
    Ok(())
}

#[test]
fn crlf_in_aor_attribute_is_char_referenced() -> R {
    let mut m = RecordingMetadata::new("c");
    m.add_participant(Participant::new("p", "sip:a@x\r\nX-Evil: 1"));
    let xml = m.to_rfc7865_xml()?;
    assert!(xml.contains("aor=\"sip:a@x&#13;&#10;X-Evil: 1\""));
    Ok(())
}

#[test]
fn labels_must_be_tokens() {
    for bad in ["", "a<b", "a\"b", "a\r\nb", "a/b", "\u{e9}"] {
        let mut m = RecordingMetadata::new("c");
        m.add_stream(MediaStream::audio(bad));
        assert!(
            matches!(m.to_rfc7865_xml(), Err(SiprecError::InvalidMetadata { .. })),
            "{bad:?}"
        );
    }
}

const SDP2: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
    m=audio 10000 RTP/AVP 0\r\na=sendonly\r\nm=audio 10002 RTP/AVP 0\r\na=sendonly\r\n";

fn two_party(name: &str) -> RecordingMetadata {
    let mut m = RecordingMetadata::new("c");
    m.add_participant(Participant::new("a", "sip:a@x").with_display_name(name));
    m.add_participant(Participant::new("b", "sip:b@x"));
    m.add_stream(MediaStream::audio("1").with_participant("a"));
    m.add_stream(MediaStream::audio("2").with_participant("b"));
    m
}

#[test]
fn multipart_boundary_never_collides_with_hostile_content() -> R {
    let sdp: SessionDescription = SDP2.parse()?;
    // Attacker plants things that look like our boundary prefix and a closing
    // delimiter inside the metadata.
    let meta = two_party("--uc-siprec-AAAAAAAAAAAAAAAAAAAAAA--\r\n--uc-siprec-");
    let mut seen = std::collections::HashSet::new();
    for _ in 0..256 {
        let parts = build_rs_offer(&sdp, &meta, &two_keys()?)?;
        let boundary = parts
            .content_type
            .strip_prefix("multipart/mixed;boundary=")
            .ok_or("no boundary")?
            .to_string();
        // RFC 2046 bchars, <= 70 chars, >= 128 bits of base64 entropy.
        assert!(boundary.len() <= 70);
        assert!(boundary.len() >= "uc-siprec-".len() + 22);
        assert!(
            boundary
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        let body = std::str::from_utf8(&parts.body)?;
        let delim = format!("\r\n--{boundary}");
        // Exactly: opening, middle, closing delimiter.
        assert!(body.starts_with(&format!("--{boundary}\r\n")));
        assert_eq!(body.matches(&delim).count(), 2);
        assert!(body.ends_with(&format!("\r\n--{boundary}--\r\n")));
        assert_eq!(body.matches(boundary.as_str()).count(), 3);
        assert!(seen.insert(boundary), "boundary repeated");
    }
    Ok(())
}

#[test]
fn builder_propagates_metadata_rejection() -> R {
    let sdp: SessionDescription = SDP2.parse()?;
    assert!(matches!(
        build_rs_offer(&sdp, &two_party("a\0b"), &two_keys()?),
        Err(SiprecError::InvalidMetadata { .. })
    ));
    Ok(())
}

#[test]
fn builder_with_no_streams_has_no_labels() -> R {
    let sdp: SessionDescription = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n".parse()?;
    let parts = build_rs_offer(&sdp, &RecordingMetadata::new("c"), &[])?;
    let body = std::str::from_utf8(&parts.body)?;
    assert!(!body.contains("a=label"));
    assert!(body.contains("Content-Disposition: recording-session\r\n"));
    Ok(())
}
