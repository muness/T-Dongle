//! The RegisterResponse reader and the JSON scanner on arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_control::json;
use tdongle_tailnet_control::requests::parse_register_response;

fuzz_target!(|data: &[u8]| {
    let _ = parse_register_response(data);
    let mut v = [None; 3];
    let _ = json::scan_top(data, 16, true, &["a", "b", "c"], &mut v);
    let _ = json::nesting_within(data, 4);
    let mut out = [0u8; 64];
    let _ = json::unescape(data, &mut out);
});
