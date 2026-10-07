//! The per-peer path state machine driven by a byte script (time steps, endpoint updates, pings, pongs with real and invented ids, CallMeMaybes, ticks): the probe table stays bounded per peer and overall, a direct route always has a trusted usable best address, and every WireGuard endpoint action is a usable IPv4 address.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_disco::fuzz::path(data);
});
