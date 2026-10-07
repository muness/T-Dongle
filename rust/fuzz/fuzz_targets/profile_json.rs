//! The `profile JSON` command's parser (the cJSON-compatible subset) on arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tdongle_nvs_format::profile_json::profile_parse_json(data);
});
