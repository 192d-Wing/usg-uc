//! Fuzz: parse -> serialize -> parse is structurally stable and
//! serialization is idempotent (NIST 800-53 Rev5: SA-11(8), SC-8).
#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_sip::{Framing, SipMessage};

fuzz_target!(|data: &[u8]| {
    for framing in [Framing::Datagram, Framing::Stream] {
        let Ok(m1) = SipMessage::parse_with(data, framing) else {
            continue;
        };
        let out1 = m1.to_bytes();
        let m2 = match SipMessage::parse_with(&out1, framing) {
            Ok(m) => m,
            Err(e) => panic!("re-parse of serialized message failed: {e}"),
        };
        assert_eq!(m1.headers().len(), m2.headers().len(), "header count");
        for (a, b) in m1.headers().iter().zip(m2.headers().iter()) {
            assert_eq!(a.name, b.name, "header name/order");
            assert_eq!(a.value, b.value, "header value");
        }
        assert_eq!(m1.body(), m2.body(), "body bytes");
        assert_eq!(m2.to_bytes(), out1, "serialization not idempotent");
    }
});
