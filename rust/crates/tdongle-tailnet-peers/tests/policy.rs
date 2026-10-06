//! Port of tests/test_peer_policy.c: which peer gives up its slot, and the two-membership pool simulation.

use tdongle_tailnet_peers::policy::{VictimCandidate, pick_victim};

fn c(last_used_ms: u64, owner_slots: u32, pinned: bool, trial: bool) -> VictimCandidate {
    VictimCandidate { last_used_ms, owner_slots, pinned, trial }
}

#[test]
fn picks() {
    let mut cands = [c(1000, 4, false, false), c(500, 2, false, false), c(200, 4, true, false), c(100, 4, false, true), c(90_000, 2, false, false)];
    // now=100000, 10 s idle window: the oldest ELIGIBLE one (index 1); pinned and trial peers are never victims.
    assert_eq!(pick_victim(&cands, 100_000, 10_000), Some(1));
    // Recent traffic is protected: a 20 s window excludes the one used at 90000 and nothing else changes.
    assert_eq!(pick_victim(&cands, 100_000, 20_000), Some(1));
    // Nothing idle long enough: the request is refused, never a recent peer evicted.
    for x in &mut cands {
        x.last_used_ms = 99_000;
    }
    assert_eq!(pick_victim(&cands, 100_000, 10_000), None);
    // Tie on idle time: the membership holding the most slots pays.
    let t = [c(10, 2, false, false), c(10, 6, false, false), c(10, 3, false, false)];
    assert_eq!(pick_victim(&t, 100_000, 10_000), Some(1));
    // A claim on an unauthenticated sender uses a 60 s window, so warm peers of other memberships are safe.
    let w = [c(50_000, 3, false, false)];
    assert!(pick_victim(&w, 100_000, 10_000) == Some(0) && pick_victim(&w, 100_000, 60_000).is_none());
    assert_eq!(pick_victim(&[], 1, 1), None);
    // The first of equal candidates wins (strict comparisons, as in the C).
    let eq = [c(5, 3, false, false), c(5, 3, false, false)];
    assert_eq!(pick_victim(&eq, 1_000_000, 1), Some(0));
    // Not-yet-idle and clock skew: a peer "used in the future" is recent.
    assert_eq!(pick_victim(&[c(200_000, 1, false, false)], 100_000, 10_000), None);
}

#[derive(Clone, Copy, Default)]
struct Peer {
    used: u64,
    resident: bool,
}

fn simulate(step_ms: u64, expect_rejections: bool) {
    const CAP: u32 = 12;
    const M: usize = 2;
    const PEERS: usize = 20;
    let mut peer = [[Peer::default(); PEERS]; M];
    let (mut used, mut evictions, mut rejected, mut activations) = (0u32, 0u32, 0u32, 0u32);
    let mut seed = 7u32;
    let mut now = 100_000u64;
    for _ in 0..20_000 {
        now += step_ms;
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let m = ((seed >> 16) as usize) % M;
        let mut p = ((seed >> 8) as usize) % PEERS;
        if m == 1 && p >= 4 {
            p %= 4; // membership 1 is busy on few peers, 0 roams widely
        }
        if peer[m][p].resident {
            peer[m][p].used = now;
            continue;
        }
        if used >= CAP {
            let mut cands = Vec::new();
            let mut who = Vec::new();
            for (a, member) in peer.iter().enumerate() {
                let slots = member.iter().filter(|x| x.resident).count() as u32;
                for (b, x) in member.iter().enumerate() {
                    if x.resident {
                        cands.push(VictimCandidate { last_used_ms: x.used, owner_slots: slots, pinned: false, trial: false });
                        who.push((a, b));
                    }
                }
            }
            let Some(v) = pick_victim(&cands, now, 10_000) else {
                rejected += 1;
                continue;
            };
            let (a, b) = who[v];
            assert!(now - peer[a][b].used >= 10_000, "never evicts recent traffic");
            peer[a][b].resident = false;
            used -= 1;
            evictions += 1;
        }
        peer[m][p] = Peer { used: now, resident: true };
        used += 1;
        activations += 1;
        assert!(used <= CAP);
    }
    assert!(evictions <= activations && evictions > 0);
    assert!(if expect_rejections { rejected > 0 } else { evictions > 10 });
}

#[test]
fn pool_simulation() {
    simulate(2000, false); // sparse traffic: idle peers rotate through the pool
    simulate(50, true); // dense traffic: everything is recent, so requests are refused instead
}
