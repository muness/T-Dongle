//! Randomized differential tests: the crate against naive reference implementations written from the rules documented in the C comments
//! (`wifi_policy.h`, `core.c`) in a deliberately different shape (sort keys and decision lists instead of pairwise comparison).
use std::cmp::Reverse;
use tdongle_nvs_format::legacy::{CFG_VERSION, LegacyProfile, LegacySettings};
use tdongle_wifi_policy::retry::{TrialDecision, policy_next, retry_delay_ms, trial_decision};
use tdongle_wifi_policy::{Pin, Rank, pick_ranked, rank_order};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, from: &[T]) -> T {
        from[self.below(from.len() as u64) as usize]
    }
}

const SIGNALS: [i16; 14] = [
    -127, -127, -100, -90, -86, -85, -84, -76, -75, -74, -63, -60, -50, -40,
];

/// The documented rule: choose by (usable, preferred, priority, signal) lexicographically, the lower slot on a complete tie.
fn reference_best(
    signal: &[i16; 8],
    count: usize,
    priority: &[u8; 8],
    preferred: Option<usize>,
) -> Option<usize> {
    let key = |i: usize| {
        (
            signal[i] >= -85,
            preferred == Some(i),
            priority[i],
            signal[i],
        )
    };
    (0..count)
        .filter(|&i| signal[i] > -127)
        .min_by_key(|&i| (Reverse(key(i)), i))
}

/// The documented roaming rule on top of it.
fn reference_pick(
    signal: &[i16; 8],
    count: usize,
    current: Option<usize>,
    connected: bool,
    priority: &[u8; 8],
    preferred: Option<usize>,
) -> Option<usize> {
    let best = reference_best(signal, count, priority, preferred)?;
    if !connected {
        return Some(best);
    }
    if current == Some(best) {
        return None; // already on the best network
    }
    if let Some(cur) = current {
        if i32::from(signal[cur]) > -75 {
            return None; // a healthy link is kept whatever else is in range
        }
        if i32::from(signal[best]) < i32::from(signal[cur]) + 12 {
            return None; // not enough better to leave
        }
    }
    Some(best)
}

fn flat() -> [u8; 8] {
    [50; 8]
}

#[test]
fn pick_matches_the_reference_exhaustively_for_three_slots() {
    let sigs = [-127, -90, -85, -80, -75, -70, -60];
    let prios = [40u8, 50, 60];
    let mut checked = 0u32;
    for a in sigs {
        for b in sigs {
            for c in sigs {
                for &pa in &prios {
                    for &pb in &prios {
                        for &pc in &prios {
                            for preferred in [None, Some(0), Some(1), Some(2)] {
                                for current in [None, Some(0), Some(1), Some(2)] {
                                    for connected in [false, true] {
                                        let signal = [a, b, c, -127, -127, -127, -127, -127];
                                        let mut priority = flat();
                                        priority[..3].copy_from_slice(&[pa, pb, pc]);
                                        let rank = Rank {
                                            priority: Some(priority),
                                            preferred,
                                        };
                                        let got =
                                            pick_ranked(&signal, 3, current, connected, &rank);
                                        let want = reference_pick(
                                            &signal, 3, current, connected, &priority, preferred,
                                        );
                                        assert_eq!(
                                            got, want,
                                            "{signal:?} {priority:?} {preferred:?} {current:?} {connected}"
                                        );
                                        checked += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 7 * 7 * 7 * 27 * 4 * 4 * 2);
}

#[test]
fn pick_matches_the_reference_on_random_scans() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..400_000 {
        let count = rng.below(9) as usize;
        let mut signal = [-127i16; 8];
        for s in &mut signal {
            *s = if rng.below(4) == 0 {
                -(rng.below(128) as i16)
            } else {
                rng.pick(&SIGNALS)
            };
        }
        let mut priority = flat();
        for p in &mut priority {
            *p = if rng.below(3) == 0 {
                rng.below(101) as u8
            } else {
                rng.pick(&[0, 50, 50, 100])
            };
        }
        let preferred = if rng.below(3) == 0 {
            None
        } else {
            Some(rng.below(9) as usize)
        };
        let current = if rng.below(4) == 0 {
            None
        } else {
            Some(rng.below(8) as usize)
        };
        let connected = rng.below(2) == 0;
        let uniform = rng.below(5) == 0;
        let rank = if uniform {
            Rank::NONE
        } else {
            Rank {
                priority: Some(priority),
                preferred,
            }
        };
        let (ref_priority, ref_preferred) = if uniform {
            (flat(), None)
        } else {
            (priority, preferred)
        };
        assert_eq!(
            pick_ranked(&signal, count, current, connected, &rank),
            reference_pick(
                &signal,
                count,
                current,
                connected,
                &ref_priority,
                ref_preferred
            ),
            "{signal:?} count {count} {rank:?} current {current:?} connected {connected}"
        );
    }
}

#[test]
fn rank_order_matches_a_sort() {
    let mut rng = Rng(0x1357_9bdf_2468_ace0);
    for _ in 0..100_000 {
        let count = rng.below(9) as usize;
        let mut priority = flat();
        for p in &mut priority {
            *p = rng.pick(&[0, 10, 50, 50, 90, 100]);
        }
        let preferred = if rng.below(3) == 0 {
            None
        } else {
            Some(rng.below(9) as usize)
        };
        let rank = Rank {
            priority: Some(priority),
            preferred,
        };
        let mut want: Vec<u8> = (0..count as u8).collect();
        want.sort_by_key(|&i| {
            (
                Reverse(preferred == Some(usize::from(i))),
                Reverse(priority[usize::from(i)]),
                i,
            )
        });
        let got = rank_order(&rank, count);
        assert_eq!(&got[..count], &want[..], "{rank:?} {count}");
        assert!(got[count..].iter().all(|&b| b == 0));
        // Without priorities the default applies to every slot.
        let plain = Rank {
            priority: None,
            preferred,
        };
        let mut want: Vec<u8> = (0..count as u8).collect();
        want.sort_by_key(|&i| (Reverse(preferred == Some(usize::from(i))), i));
        assert_eq!(&rank_order(&plain, count)[..count], &want[..]);
    }
}

/// The pin as a plain tuple state machine, from the C comment: "stay while connected to the pinned network, otherwise retry it regardless
/// of signal until it gives up (three failed passes in a row)".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RefPin {
    slot: Option<usize>,
    failures: u32,
    gave_up_on: Option<usize>,
}

impl RefPin {
    fn step(
        &mut self,
        signal: &[i16; 8],
        count: usize,
        current: Option<usize>,
        connected: bool,
        rank: &Rank,
    ) -> Option<usize> {
        if self.slot.is_some_and(|s| s >= count) {
            *self = Self {
                slot: None,
                failures: 0,
                gave_up_on: None,
            };
        }
        let priority = rank.priority.unwrap_or_else(flat);
        let Some(slot) = self.slot else {
            return reference_pick(signal, count, current, connected, &priority, rank.preferred);
        };
        if connected && current == Some(slot) {
            self.failures = 0;
            return None;
        }
        self.failures += 1;
        if self.failures <= 3 {
            return Some(slot);
        }
        self.gave_up_on = Some(slot);
        self.slot = None;
        self.failures = 0;
        reference_pick(signal, count, current, connected, &priority, rank.preferred)
    }
}

#[test]
fn pin_matches_the_reference_over_random_histories() {
    let mut rng = Rng(0x0dd_ba11_cafe_f00d);
    for _ in 0..20_000 {
        let mut pin = Pin::NONE;
        let mut model = RefPin {
            slot: None,
            failures: 0,
            gave_up_on: None,
        };
        for step in 0..40 {
            match rng.below(8) {
                0 => {
                    let slot = rng.below(10) as usize;
                    pin.set(slot);
                    model = RefPin {
                        slot: Some(slot),
                        failures: 0,
                        gave_up_on: None,
                    };
                }
                1 => {
                    pin.clear();
                    model = RefPin {
                        slot: None,
                        failures: 0,
                        gave_up_on: None,
                    };
                }
                _ => {
                    let count = rng.below(9) as usize;
                    let signal: [i16; 8] = core::array::from_fn(|_| rng.pick(&SIGNALS));
                    let current = if rng.below(3) == 0 {
                        None
                    } else {
                        Some(rng.below(8) as usize)
                    };
                    let connected = rng.below(2) == 0;
                    let rank = if rng.below(2) == 0 {
                        Rank::NONE
                    } else {
                        Rank {
                            priority: Some(core::array::from_fn(|_| rng.pick(&[0, 50, 100]))),
                            preferred: Some(rng.below(8) as usize),
                        }
                    };
                    let got = pin.pick_ranked(&signal, count, current, connected, &rank);
                    let want = model.step(&signal, count, current, connected, &rank);
                    assert_eq!(got, want, "step {step}");
                }
            }
            assert_eq!(
                (pin.slot, pin.attempts, pin.failed_slot),
                (model.slot, model.failures, model.gave_up_on),
                "step {step}"
            );
        }
    }
}

#[test]
fn retry_delay_matches_the_doubling_rule() {
    for failures in 0..200u32 {
        let doubling = 1000u64 << failures.min(20);
        assert_eq!(
            u64::from(retry_delay_ms(failures)),
            doubling.min(30_000),
            "{failures}"
        );
    }
}

#[test]
fn trial_decision_matches_the_interval_rule() {
    let mut rng = Rng(0xfeed_face_dead_beef);
    let edges: [i128; 9] = [0, 1, 9_999, 10_000, 10_001, 34_999, 35_000, 35_001, 45_000];
    let mut counts = [0u32; 3];
    for _ in 0..500_000 {
        let started = i128::from(rng.below(2000));
        let near = |rng: &mut Rng| started + rng.pick(&edges) + i128::from(rng.below(3)) - 1;
        let now = if rng.below(8) == 0 {
            i128::from(rng.below(100_000))
        } else {
            near(&mut rng)
        };
        let since = if rng.below(8) == 0 {
            i128::from(rng.below(100_000))
        } else {
            near(&mut rng)
        };
        let associated = rng.below(5) != 0;
        let (now, since) = (now.max(0), since.max(0));
        // The rule in words: a clock that went back is a timeout; a link that associated within 35 s of the start (never before it, never in the
        // future) and has held 10 s commits; otherwise 45 s after the start is a timeout; otherwise wait.
        let want = if now < started {
            TrialDecision::TimedOut
        } else if associated
            && (started..=now).contains(&since)
            && now - since >= 10_000
            && since - started <= 35_000
        {
            TrialDecision::Commit
        } else if now - started >= 45_000 {
            TrialDecision::TimedOut
        } else {
            TrialDecision::Waiting
        };
        assert_eq!(
            trial_decision(now as u64, started as u64, since as u64, associated),
            want,
            "{now} {started} {since} {associated}"
        );
        counts[match want {
            TrialDecision::Waiting => 0,
            TrialDecision::Commit => 1,
            TrialDecision::TimedOut => 2,
        }] += 1;
    }
    assert!(
        counts.iter().all(|&c| c > 5_000),
        "all three outcomes must be well exercised: {counts:?}"
    );
}

fn settings_with(priority: [u8; 8], present: u8, preferred: u8) -> LegacySettings {
    let mut s = LegacySettings {
        version: CFG_VERSION,
        p: [LegacyProfile::EMPTY; 8],
        preferred,
        brightness: 60,
        rotation: 0,
        dim_seconds: 60,
    };
    for (i, p) in s.p.iter_mut().enumerate() {
        p.priority = priority[i];
        if present & (1 << i) != 0 {
            p.ssid[0] = b'a' + i as u8;
        }
    }
    s
}

#[test]
fn policy_next_matches_a_sorted_walk() {
    let mut rng = Rng(0x5eed_0000_0000_0001);
    for _ in 0..200_000 {
        let priority: [u8; 8] = core::array::from_fn(|_| rng.pick(&[0, 10, 50, 50, 99, 100]));
        let (present, tried, preferred) = (
            rng.below(256) as u8,
            rng.below(256) as u8,
            rng.below(10) as u8,
        );
        let s = settings_with(priority, present, preferred);
        // Reference: the networks still to try, in the order the C comment describes (the preferred one first, then higher priority, then
        // lower slot); the answer is the head of that list.
        let mut todo: Vec<usize> = (0..8)
            .filter(|&i| present & (1 << i) != 0 && tried & (1 << i) == 0)
            .collect();
        todo.sort_by_key(|&i| {
            (
                Reverse(usize::from(preferred) == i),
                Reverse(priority[i]),
                i,
            )
        });
        assert_eq!(
            policy_next(&s, tried),
            todo.first().copied(),
            "{priority:?} present {present:08b} tried {tried:08b} preferred {preferred}"
        );
    }
}
