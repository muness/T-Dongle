//! One datagram on a membership's UDP socket (DISCO, WireGuard, STUN or garbage) delivered to an engine that already has sessions: the first byte picks the node and the membership. Nothing may panic, every datagram ends in one counted outcome, and the pool and receiver-index invariants hold.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_engine::fuzz::udp(data);
});
