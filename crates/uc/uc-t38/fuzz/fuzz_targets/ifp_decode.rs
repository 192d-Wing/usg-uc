//! Fuzz: the IFP decoder must never panic (NIST 800-53 Rev5: SA-11(8), POA&M-203).
#![no_main]

use libfuzzer_sys::fuzz_target;
use uc_t38::IfpPacket;

fuzz_target!(|data: &[u8]| {
    let _ = IfpPacket::decode(bytes::Bytes::copy_from_slice(data));
});
