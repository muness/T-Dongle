//! Random event sequences against two engines wired back to back: malformed UDP/DERP payloads, wrong keys, replays, flipped bits, duplicated and dropped
//! packets, member and netmap churn, heap pressure, refused outputs and time jumps. No panic; after every step every packet has ended in exactly one
//! counted outcome and the pool and receiver-index invariants hold (`Engine::check_identities`); the wake deadline always makes progress.

use proptest::prelude::*;
use tdongle_tailnet_engine::fuzz::{self, Chaos, WARM_UP};
use tdongle_tailnet_engine::{HostFate, RxFate, TxFate};
use tdongle_tailnet_types::Entropy;
use tdongle_tailnet_types::test_util::TestRng;

proptest! {
    #![proptest_config(ProptestConfig { cases: 40, ..ProptestConfig::default() })]

    #[test]
    fn random_scripts_keep_the_identities(script in proptest::collection::vec(any::<u8>(), 0..1500)) {
        let mut c = Chaos::new();
        c.run(WARM_UP);
        c.run(&script);
    }

    #[test]
    fn single_datagrams_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1700)) {
        fuzz::udp(&data);
        fuzz::derp(&data);
    }
}

#[test]
fn warm_up_establishes_sessions_both_ways() {
    let mut c = Chaos::new();
    c.run(WARM_UP);
    let st = c.engine(0).stats();
    assert!(st.host_count(HostFate::Forwarded) >= 1);
    assert!(st.rx_count(RxFate::DiscoOk) + st.rx_count(RxFate::WgInitiation) + st.rx_count(RxFate::WgResponse) > 0);
    assert!(st.tx_count(TxFate::SentDerp) + st.tx_count(TxFate::SentDirect) + st.tx_count(TxFate::Parked) > 0);
}

/// Deterministic mini-fuzz that runs in plain `cargo test`: many random scripts, many mutated ones.
#[test]
fn mini_fuzz_scripts() {
    let mut rng = TestRng(0xfeed_beef);
    for n in 0..60 {
        let len = 100 + (n * 37) % 1200;
        let mut s = std::vec![0u8; len];
        rng.fill(&mut s);
        // bias towards deliveries and time so sessions form and expire
        for i in (0..len).step_by(7) {
            s[i] = [0u8, 4, 4, 7, 8, 5, 2][(s[i] % 7) as usize];
        }
        fuzz::script(&s);
    }
}

#[test]
fn mini_fuzz_single_datagrams() {
    let mut rng = TestRng(0x0bad_cafe);
    for n in 0..150usize {
        let len = [0, 1, 4, 32, 33, 64, 92, 148, 149, 300, 1300, 1600][n % 12];
        let mut d = std::vec![0u8; len];
        rng.fill(&mut d);
        if n % 3 == 0 && len > 4 {
            d[1] = n as u8 % 6; // a header byte that selects members and keys
        }
        fuzz::udp(&d);
        fuzz::derp(&d);
    }
}

/// Found by the property test (shrunk): a keepalive sent from the timer pass finds its session due for rekeying, which arms a handshake after the
/// timers were polled; the wake deadline then lay in the past right after the tick (a runtime would spin). `service_peer` now re-polls what it armed.
#[test]
fn regression_keepalive_arms_a_rekey_and_the_wake_still_moves_on() {
    const SCRIPT: &[u8] = &[
        63, 0, 0, 0, 9, 187, 0, 14, 140, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 1, 7, 0, 0, 0, 98, 0, 0, 0, 0, 0, 9, 0, 90, 0, 1, 60, 0, 0, 120, 0, 0, 96, 203, 0,
        0, 173, 103, 0, 0, 0, 0, 0, 133, 0, 0, 0, 24, 0, 0, 13, 0, 0, 224, 63, 0, 0, 0, 133, 0, 0, 125, 98, 0, 0, 0, 0, 0, 72, 0, 0, 0, 187, 0, 0, 1, 200, 0,
        0, 35, 0, 0, 0, 14, 0, 199, 30, 12, 0, 1, 0, 188, 41, 1, 70, 90, 150, 0, 0, 0, 1, 0, 44, 1, 1, 68, 0, 0, 4, 32, 0, 0, 4, 0, 0, 14, 182, 0, 0, 0, 0, 0,
        0, 0, 0, 29, 0, 0, 0, 0, 0, 61, 0, 0, 0, 0, 0, 5, 0, 0, 0, 2, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 0, 0, 0, 0, 0, 7, 0, 0, 0, 78, 0, 0, 10,
    ];
    let mut c = Chaos::new();
    c.run(WARM_UP);
    c.run(SCRIPT);
}
