//! Fuzz: structured header value parsers never panic on arbitrary UTF-8.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_sip::{CSeqHeader, DigestChallenge, DigestCredentials, NameAddr, SipUri, ViaHeader};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = s.parse::<SipUri>();
    let _ = s.parse::<ViaHeader>();
    let _ = s.parse::<NameAddr>();
    let _ = s.parse::<CSeqHeader>();
    let _ = s.parse::<DigestChallenge>();
    let _ = s.parse::<DigestCredentials>();
});
