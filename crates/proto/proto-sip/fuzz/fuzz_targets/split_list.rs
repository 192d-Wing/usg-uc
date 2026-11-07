//! Fuzz: the header list splitter never panics, every element is a
//! substring, and elements appear in input order.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_sip::split_list;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut cursor = 0usize;
    for elem in split_list(s) {
        let Ok(elem) = elem else { break };
        assert!(!elem.is_empty());
        let found = s[cursor..].find(elem).expect("element not in input order");
        cursor += found + elem.len();
    }
});
