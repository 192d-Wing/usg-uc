//! Fuzz: the SIP message parser must never panic (NIST 800-53 Rev5: SA-11(8)).
#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_sip::{Framing, SipMessage};

fuzz_target!(|data: &[u8]| {
    let _ = SipMessage::parse_with(data, Framing::Datagram);
    let _ = SipMessage::parse_with(data, Framing::Stream);
});
