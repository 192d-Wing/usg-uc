//! Fuzz: the UDPTL decoder must never panic (NIST 800-53 Rev5: SA-11(8), POA&M-202).
#![no_main]

use libfuzzer_sys::fuzz_target;
use uc_t38::UdptlPacket;

fuzz_target!(|data: &[u8]| {
    let _ = UdptlPacket::decode(bytes::Bytes::copy_from_slice(data));
});
