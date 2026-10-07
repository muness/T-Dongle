//! One packet relayed by DERP (a claimed sender key, then DISCO, WireGuard or garbage) delivered to an engine that already has sessions: the first byte picks the node and the membership and, with its top bit set, a real peer's key as the sender. Nothing may panic, every packet ends in one counted outcome, and the pool invariants hold.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_engine::fuzz::derp(data);
});
