//! A byte script driving two engines back to back through an adversarial network: host packets, deliveries with flipped, truncated, duplicated and dropped datagrams, replays, garbage, time jumps, membership and netmap churn, DNS, heap pressure and refused outputs. After every step the identities (every packet one counted outcome, pool and receiver-index invariants) hold and the wake deadline makes progress.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_engine::fuzz::script(data);
});
