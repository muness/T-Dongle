//! Every case of `alternative/tailnet/tests/test_wifi_policy.c` and the policy / retry parts of `tests/test_core.c`.
use tdongle_nvs_format::legacy::{CFG_VERSION, LegacyProfile, LegacySettings};
use tdongle_wifi_policy::retry::{TrialDecision, policy_next, retry_delay_ms, trial_decision};
use tdongle_wifi_policy::{
    HEALTHY_DBM, HYSTERESIS_DB, PIN_MAX_ATTEMPTS, PRIORITY_DEFAULT, PRIORITY_MAX, Pin, Rank,
    USABLE_DBM, pick, pick_ranked, rank_order,
};

const NS: i16 = -127;

#[test]
fn constants_are_the_c_constants() {
    assert_eq!((USABLE_DBM, HEALTHY_DBM, HYSTERESIS_DB), (-85, -75, 12));
    assert_eq!(PIN_MAX_ATTEMPTS, 3);
    assert_eq!((PRIORITY_DEFAULT, PRIORITY_MAX), (50, 100));
    assert_eq!(tdongle_wifi_policy::PROFILE_LIMIT, 8);
}

/// `main()` of test_wifi_policy.c.
#[test]
fn pick_unranked() {
    let mut s: [i16; 8] = [-80, -60, NS, -65, -90, -50, -72, -40];
    assert_eq!(pick(&s, 8, None, false), Some(7));
    assert_eq!(pick(&s, 8, Some(7), true), None);
    assert_eq!(pick(&s, 8, Some(0), true), Some(7));
    s[7] = -70;
    s[5] = -72;
    s[1] = -73;
    s[3] = -75;
    assert_eq!(pick(&s, 8, Some(0), true), None);
    s = [NS; 8];
    assert_eq!(pick(&s, 8, None, false), None);
}

/// `pin_tests()`.
#[test]
fn pinned_selection() {
    let mut s: [i16; 8] = [-80, -60, NS, -65, -90, -50, -72, -40];
    let mut p = Pin::NONE;
    assert_eq!(p.pick(&s, 8, None, false), Some(7));
    assert_eq!(p.pick(&s, 8, Some(7), true), None); // no pin: wifi_pick
    p.set(0);
    assert_eq!(p.pick(&s, 8, Some(0), true), None); // connected to the pin: stay, even at -80
    assert_eq!(p.attempts, 0);
    s[0] = NS;
    assert_eq!(p.pick(&s, 8, Some(0), true), None); // signal not seen in this scan: still stay
    assert_eq!(p.pick(&s, 8, Some(3), true), Some(0)); // on another network: go to the pin
    assert_eq!(p.attempts, 1);
    assert_eq!(p.pick(&s, 8, None, false), Some(0));
    assert_eq!(p.pick(&s, 8, None, false), Some(0));
    assert_eq!(p.attempts, 3);
    assert_eq!(p.pick(&s, 8, None, false), Some(7)); // gave up: strongest, failure recorded
    assert_eq!((p.slot, p.failed_slot), (None, Some(0))); // C failed_slot == 1 (1-based)
    p.set(9);
    assert_eq!(p.pick(&s, 8, None, false), Some(7));
    assert_eq!(p.slot, None); // slot beyond the list drops the pin
    p.set(2);
    assert_eq!(p.failed_slot, None);
    p.clear();
    assert_eq!((p.slot, p.failed_slot), (None, None));
    assert_eq!(Pin::default(), Pin::NONE);
}

/// `rank_tests()`.
#[test]
fn priority_and_the_preferred_slot() {
    let mut s: [i16; 8] = [-60, -50, -70, NS, NS, NS, NS, NS];
    // Defaults: no priorities and no preferred slot behave exactly like wifi_pick.
    let none = Rank::NONE;
    assert_eq!(pick_ranked(&s, 3, None, false, &none), Some(1));
    assert_eq!(
        pick_ranked(&s, 3, None, false, &none),
        pick(&s, 3, None, false)
    );
    let flat = Rank {
        priority: Some([50; 8]),
        preferred: None,
    };
    assert_eq!(pick_ranked(&s, 3, None, false, &flat), Some(1));
    // A higher priority beats a stronger signal.
    let pr = [50, 50, 80, 50, 50, 50, 50, 50];
    let prio = Rank {
        priority: Some(pr),
        preferred: None,
    };
    assert_eq!(pick_ranked(&s, 3, None, false, &prio), Some(2));
    // The preferred slot beats a higher priority.
    let mut pref = Rank {
        priority: Some(pr),
        preferred: Some(0),
    };
    assert_eq!(pick_ranked(&s, 3, None, false, &pref), Some(0));
    // ... unless it is not usable (below WIFI_USABLE_DBM): a barely visible preferred network does not outrank a good one.
    s[0] = -90;
    assert_eq!(pick_ranked(&s, 3, None, false, &pref), Some(2));
    // Nothing usable: everything seen is ranked, so a weak network is still joined, preferred first.
    s[1] = -92;
    s[2] = -95;
    assert_eq!(pick_ranked(&s, 3, None, false, &pref), Some(0));
    s[0] = -86;
    s[1] = -86;
    s[2] = -86;
    assert_eq!(pick_ranked(&s, 3, None, false, &pref), Some(0)); // equal signals: preferred, then priority, then slot
    pref.preferred = None;
    assert_eq!(pick_ranked(&s, 3, None, false, &pref), Some(2));
    pref.priority.as_mut().unwrap()[2] = 50;
    assert_eq!(pick_ranked(&s, 3, None, false, &pref), Some(0)); // every key equal: the lower slot
    // Connected: a healthy link is never left, whatever is preferred (v0.1.1: never oscillate a healthy link).
    let mut t: [i16; 8] = [-70, -40, NS, NS, NS, NS, NS, NS];
    let tp = [50, 99, 50, 50, 50, 50, 50, 50];
    let higher = Rank {
        priority: Some(tp),
        preferred: Some(1),
    };
    assert_eq!(pick_ranked(&t, 2, Some(0), true, &higher), None);
    // A weak one is left for a candidate 12 dB stronger, by the ranking.
    t[0] = -80;
    t[1] = -70;
    assert_eq!(pick_ranked(&t, 2, Some(0), true, &higher), None); // only 10 dB better
    t[1] = -68;
    assert_eq!(pick_ranked(&t, 2, Some(0), true, &higher), Some(1));
    t[1] = -60;
    let other = Rank {
        priority: Some(tp),
        preferred: Some(0),
    };
    assert_eq!(pick_ranked(&t, 2, Some(0), true, &other), None); // the current network is the best: stay
    // Unseen networks (hidden SSIDs) while offline: preferred first, then priority, then slot.
    let orank = Rank {
        priority: Some([50, 50, 70, 50, 90, 50, 50, 50]),
        preferred: Some(3),
    };
    let order = rank_order(&orank, 5);
    assert_eq!(&order[..5], &[3, 4, 2, 0, 1]);
    let order = rank_order(&Rank::NONE, 4);
    assert_eq!(&order[..4], &[0, 1, 2, 3]);
    assert_eq!(rank_order(&orank, 0), [0; 8]);
    // A pin outranks all of it; the ranked pick applies once the pin is given up.
    let mut p = Pin::NONE;
    let u: [i16; 8] = [-70, -40, NS, NS, NS, NS, NS, NS];
    let pinned_rank = Rank {
        priority: Some([50; 8]),
        preferred: Some(0),
    };
    p.set(1);
    assert_eq!(p.pick_ranked(&u, 2, None, false, &pinned_rank), Some(1));
    p.set(1);
    p.attempts = PIN_MAX_ATTEMPTS;
    assert_eq!(p.pick_ranked(&u, 2, None, false, &pinned_rank), Some(0));
    assert_eq!((p.slot, p.failed_slot), (None, Some(1))); // C failed_slot == 2
}

fn legacy(entries: &[(&str, u8)], preferred: u8) -> LegacySettings {
    let mut s = LegacySettings {
        version: CFG_VERSION,
        p: [LegacyProfile::EMPTY; 8],
        preferred,
        brightness: 60,
        rotation: 0,
        dim_seconds: 60,
    };
    for (i, (ssid, prio)) in entries.iter().enumerate() {
        s.p[i].ssid[..ssid.len()].copy_from_slice(ssid.as_bytes());
        s.p[i].priority = *prio;
    }
    s
}

/// `profiles()` of tests/test_core.c.
#[test]
fn policy_next_cases() {
    let mut s = legacy(&[], 0);
    assert!(s.valid());
    assert_eq!(policy_next(&s, 0), None);
    s = legacy(&[("test", 20), ("hotspot", 99), ("test", 50)], 0);
    assert_eq!(policy_next(&s, 0), Some(0));
    assert_eq!(policy_next(&s, 1), Some(1));
    assert_eq!(policy_next(&s, 3), Some(2));
    assert_eq!(policy_next(&s, 7), None);
    s.preferred = 2;
    assert_eq!(policy_next(&s, 0), Some(2));
    // Beyond the table, tried preferred, ties.
    s.preferred = 8;
    assert_eq!(policy_next(&s, 0), Some(1)); // C would index out of bounds here; settings_valid refuses preferred >= 8
    s.preferred = 2;
    assert_eq!(policy_next(&s, 0b100), Some(1));
    let ties = legacy(&[("a", 10), ("b", 10), ("c", 10)], 5);
    assert_eq!(policy_next(&ties, 0), Some(0));
    assert_eq!(policy_next(&ties, 1), Some(1));
}

#[test]
fn retry_delays() {
    assert_eq!(retry_delay_ms(0), 1000);
    assert_eq!([1, 2, 3, 4].map(retry_delay_ms), [2000, 4000, 8000, 16000]);
    assert_eq!(retry_delay_ms(5), 30000);
    assert_eq!(retry_delay_ms(1000), 30000);
    assert_eq!(retry_delay_ms(u32::MAX), 30000);
}

#[test]
fn trial_decisions() {
    use TrialDecision::{Commit, TimedOut, Waiting};
    assert_eq!(trial_decision(44000, 0, 35000, true), Waiting);
    assert_eq!(trial_decision(45000, 0, 35000, true), Commit);
    assert_eq!(trial_decision(45000, 0, 35001, true), TimedOut);
    assert_eq!(trial_decision(46000, 0, 36000, true), TimedOut);
    assert_eq!(trial_decision(45000, 0, 0, false), TimedOut);
    // An association epoch changes even if a disconnect happens between polls.
    assert_eq!(trial_decision(12000, 1000, 1000, true), Commit);
    assert_eq!(trial_decision(12000, 1000, 11900, true), Waiting);
    assert_eq!(trial_decision(46000, 1000, 45900, true), TimedOut);
    // Extra edges: a clock that went backwards, an association older than the trial or in the future.
    assert_eq!(trial_decision(100, 200, 0, false), TimedOut);
    assert_eq!(trial_decision(20000, 5000, 4999, true), Waiting);
    assert_eq!(trial_decision(20000, 5000, 20001, true), Waiting);
    assert_eq!(trial_decision(0, 0, 0, false), Waiting);
    assert_eq!(trial_decision(u64::MAX, 0, 0, true), Commit);
}
