//! Property tests and deterministic mini-fuzzing (no panic, invariants) of the pure pieces.

#![allow(clippy::assertions_on_constants)]

use proptest::prelude::*;
use std::string::String;
use std::vec::Vec;
use tdongle_tailnet_admission::adm::*;
use tdongle_tailnet_admission::json::{JsonWriter, SliceSink};
use tdongle_tailnet_admission::ledger::{Ledger, Owner};
use tdongle_tailnet_admission::negotiation::*;

#[derive(Debug, Clone)]
enum Op {
    Request { dt: u16, key: u8, prio: u8, phase: u8 },
    Release { dt: u16, key: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u16..3000, 1u8..10, 0u8..3, 1u8..4).prop_map(|(dt, key, prio, phase)| Op::Request { dt, key, prio, phase }),
        1 => (0u16..3000, 1u8..10).prop_map(|(dt, key)| Op::Release { dt, key }),
    ]
}

fn apply(n: &mut Negotiation, now: &mut u64, op: &Op) {
    match *op {
        Op::Request { dt, key, prio, phase } => {
            *now += u64::from(dt);
            let p = [Prio::Start, Prio::Rejoin, Prio::Relay][usize::from(prio)];
            let ph = [Phase::None, Phase::Start, Phase::Control, Phase::Derp][usize::from(phase)];
            let _ = n.request(*now, Key::from_raw(u32::from(key)).unwrap(), p, ph);
        }
        Op::Release { dt, key } => {
            *now += u64::from(dt);
            let _ = n.release(*now, Key::from_raw(u32::from(key)).unwrap());
        }
    }
}

proptest! {
    /// Mutual exclusion and bounded queue under arbitrary traffic, counters only grow, the holder never also waits.
    #[test]
    fn negotiation_invariants(ops in prop::collection::vec(op(), 1..300), lease in 0u32..100_000, stale in 0u32..5000, aging in 0u32..30_000) {
        let mut n = Negotiation::new(lease, stale, aging);
        let mut now = 0u64;
        let mut last = n.status(now);
        for o in &ops {
            apply(&mut n, &mut now, o);
            let s = n.status(now);
            prop_assert!(s.waiting as usize <= ML_NEG_MAX_WAITERS);
            prop_assert!(s.grants >= last.grants && s.timeouts >= last.timeouts && s.lease_expired >= last.lease_expired);
            prop_assert!(s.stale_dropped >= last.stale_dropped && s.refused_full >= last.refused_full);
            prop_assert!(s.max_hold_ms >= last.max_hold_ms && s.max_wait_ms >= last.max_wait_ms);
            prop_assert_eq!(s.holder != 0, n.busy());
            if s.holder != 0 {
                let holder = Key::from_raw(s.holder).unwrap();
                prop_assert!(n.holds(holder));
                for k in 1..10u32 {
                    let key = Key::from_raw(k).unwrap();
                    prop_assert_eq!(n.holds(key), k == s.holder);
                }
            }
            // every grant is either the current holder or was released/expired since
            prop_assert!(u64::from(s.grants) >= u64::from(s.releases) + u64::from(s.lease_expired) + u64::from(s.holder != 0));
            last = s;
        }
        // Releasing every key empties the token and the queue.
        for k in 1..10u32 {
            let _ = n.release(now, Key::from_raw(k).unwrap());
        }
        let s = n.status(now);
        prop_assert!(s.holder == 0 && s.waiting == 0);
    }

    /// A release is idempotent and harmless: a second one changes nothing.
    #[test]
    fn negotiation_release_is_idempotent(ops in prop::collection::vec(op(), 1..100), key in 1u32..10) {
        let mut n = Negotiation::new(0, 0, 0);
        let mut now = 0u64;
        for o in &ops {
            apply(&mut n, &mut now, o);
        }
        let k = Key::from_raw(key).unwrap();
        let _ = n.release(now, k);
        let before = n.status(now);
        prop_assert!(!n.release(now, k));
        prop_assert_eq!(before, n.status(now));
    }

    /// With aging out of the way, equal-priority waiters that keep polling are granted in the order they first asked (FIFO).
    #[test]
    fn negotiation_fifo_within_a_priority(order in Just(()).prop_perturb(|_, mut rng| {
        use proptest::prelude::RngCore;
        let mut keys: Vec<u32> = (2..2 + ML_NEG_MAX_WAITERS as u32).collect();
        for i in (1..keys.len()).rev() { let j = (rng.next_u32() as usize) % (i + 1); keys.swap(i, j); }
        keys
    }), prio in 0u8..3) {
        let mut n = Negotiation::new(0, 0, 1_000_000);
        let mut now = 100u64;
        let first = Key::from_raw(1).unwrap();
        prop_assert_eq!(n.request(now, first, Prio::Start, Phase::Start), Grant::Granted);
        let p = [Prio::Start, Prio::Rejoin, Prio::Relay][usize::from(prio)];
        for k in &order {
            now += 7;
            prop_assert_eq!(n.request(now, Key::from_raw(*k).unwrap(), p, Phase::Control), Grant::Queued);
        }
        let mut holder = first;
        for want in &order {
            let _ = n.release(now, holder);
            let mut granted = None;
            for k in &order {
                now += 1;
                if n.request(now, Key::from_raw(*k).unwrap(), p, Phase::Control) == Grant::Granted { granted = Some(*k); }
            }
            prop_assert_eq!(granted, Some(*want));
            holder = Key::from_raw(*want).unwrap();
        }
    }

    /// Liveness: waiters that poll within the stale window while holders release within the lease are all eventually served,
    /// each exactly once per request, and the queue drains.
    #[test]
    fn negotiation_every_waiter_is_served(prios in prop::collection::vec(0u8..3, 1..6), work in prop::collection::vec(1u32..500, 6)) {
        let mut n = Negotiation::new(60_000, 2000, 20_000);
        let mut now = 0u64;
        let keys: Vec<Key> = (0..prios.len()).map(|i| Key::from_raw(i as u32 + 1).unwrap()).collect();
        let mut served = std::vec![false; keys.len()];
        let mut holding: Option<(usize, u64)> = None;
        for step in 0..100_000u64 {
            now += 10;
            if let Some((i, until)) = holding
                && now >= until
            {
                let _ = n.release(now, keys[i]);
                served[i] = true;
                holding = None;
            }
            for (i, k) in keys.iter().enumerate() {
                if served[i] || holding.is_some_and(|(h, _)| h == i) { continue; }
                let p = [Prio::Start, Prio::Rejoin, Prio::Relay][usize::from(prios[i])];
                if n.request(now, *k, p, Phase::Control) == Grant::Granted {
                    holding = Some((i, now + u64::from(work[i % work.len()])));
                }
            }
            if served.iter().all(|s| *s) { break; }
            prop_assert!(step < 99_999, "starved: {served:?}");
        }
        prop_assert_eq!(n.status(now).grants as usize, keys.len());
    }

    /// Bounded acquire: a deadline always ends in Granted or Failed within timeout (+ one poll), never leaves the key queued.
    #[test]
    fn acquire_terminates_without_trace(timeout in 0u32..2000, holder_key in 1u32..4, my_key in 4u32..8) {
        let mut n = Negotiation::new(0, 0, 0);
        let _ = n.request(0, Key::from_raw(holder_key).unwrap(), Prio::Start, Phase::Start);
        let mut a = Acquire::new(0, timeout, Key::from_raw(my_key).unwrap(), Prio::Start, Phase::Start);
        let mut t = 0u64;
        loop {
            match a.poll(&mut n, t) {
                AcquirePoll::Pending { retry_at } => { prop_assert!(retry_at > t && retry_at <= u64::from(timeout)); t = retry_at; }
                AcquirePoll::Failed(why) => { prop_assert_eq!(why, AcquireFailure::TimedOut); break; }
                AcquirePoll::Granted => prop_assert!(false, "cannot be granted while held"),
            }
        }
        prop_assert!(t >= u64::from(timeout) && t <= u64::from(timeout) + u64::from(ACQUIRE_POLL_MS));
        prop_assert_eq!(n.status(t).waiting, 0);
        prop_assert_eq!(n.status(t).timeouts, 1);
    }

    /// Admission arithmetic: monotone in every size, the first membership costs exactly the shared runtime more, `decide` is consistent.
    #[test]
    fn admission_monotone_and_consistent(
        base in (0usize..30_000, 0usize..12_000, 0usize..700, 0usize..5000, 0usize..800, 0usize..2500, 0usize..50_000, 0u32..5, 0usize..7000),
        bump in (0usize..6, 1usize..5000),
        free in 0usize..300_000, largest in 0usize..60_000,
    ) {
        let mut p = Params::c_reference();
        (p.context, p.coord_stack, p.task_tcb, p.queues, p.wg_device, p.wg_slot, p.shared_stacks, p.shared_tasks, p.route_queue_min) = base;
        let (first, next) = (p.budget(false), p.budget(true));
        prop_assert_eq!(first.required - next.required, first.shared_runtime);
        prop_assert_eq!(next.member_steady, next.member_start + next.member_growth);
        prop_assert_eq!(next.required, next.member_steady + next.negotiation + next.recovery + next.router);
        let mut q = p;
        match bump.0 { 0 => q.context += bump.1, 1 => q.coord_stack += bump.1, 2 => q.queues += bump.1, 3 => q.wg_device += bump.1, 4 => q.wg_slot += bump.1, _ => q.route_queue_min += bump.1 }
        prop_assert!(q.budget(true).required >= next.required);
        prop_assert_eq!(first.decide(free, largest) == Verdict::Ok, free >= first.required && largest >= first.largest_block);
        if free < first.required { prop_assert_eq!(first.decide(free, largest), Verdict::RefusedBudget); }
    }

    /// The slot guards: at the guaranteed count only the recovery reserve is kept; beyond it, a negotiation peak more.
    #[test]
    fn slot_guards(live in 0u32..13, free in 0usize..80_000, bytes in 0usize..3000, before in 0usize..60_000, shrink in 0usize..3000) {
        prop_assert_eq!(slot_heap_ok(live, free, bytes), free >= elastic_floor(live >= ML_ADM_PEER_SLOTS) + bytes);
        let after = before.saturating_sub(shrink);
        let ok = slot_alloc_ok(before, after, ML_ADM_TLS_BLOCK_FLOOR);
        prop_assert_eq!(ok, !(before >= ML_ADM_TLS_BLOCK_FLOOR && after < ML_ADM_TLS_BLOCK_FLOOR));
        if before < ML_ADM_TLS_BLOCK_FLOOR { prop_assert!(ok, "already below: not this allocation's doing"); }
    }

    /// The ledger equals a model with saturating subtraction; every over-free is one underflow; peak is the running maximum.
    #[test]
    fn ledger_matches_model(ops in prop::collection::vec((0usize..7, any::<bool>(), 0usize..5000), 0..400)) {
        let l = Ledger::new();
        let (mut live, mut peak, mut under) = ([0u32; 7], [0u32; 7], 0u32);
        for (o, is_alloc, bytes) in ops {
            let owner = Owner::ALL[o];
            if is_alloc {
                l.alloc(owner, bytes);
                live[o] += bytes as u32;
                peak[o] = peak[o].max(live[o]);
            } else {
                l.free(owner, bytes);
                if live[o] < bytes as u32 { under += 1; }
                live[o] = live[o].saturating_sub(bytes as u32);
            }
        }
        for (i, o) in Owner::ALL.iter().enumerate() {
            let s = l.owner(*o);
            prop_assert_eq!((s.live, s.peak), (live[i], peak[i]));
        }
        prop_assert_eq!(l.underflows(), under);
        prop_assert_eq!(l.total().live, live.iter().sum::<u32>());
    }

    /// Strings are escaped so that the output is a valid JSON string that decodes back to the input; the writer never writes past its buffer.
    #[test]
    fn json_string_roundtrip(s in "\\PC{0,40}|[\\x00-\\x1f\"\\\\a-z]{0,40}") {
        let mut buf = [0u8; 512];
        let mut w = JsonWriter::new(SliceSink::new(&mut buf));
        prop_assert!(w.string(&s));
        let out = String::from_utf8(w.sink().written().to_vec()).unwrap();
        prop_assert!(out.starts_with('"') && out.ends_with('"'));
        // decode
        let inner = &out[1..out.len() - 1];
        let mut dec = String::new();
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next().unwrap() {
                    '"' => dec.push('"'),
                    '\\' => dec.push('\\'),
                    'u' => { let h: String = it.by_ref().take(4).collect(); dec.push(char::from_u32(u32::from_str_radix(&h, 16).unwrap()).unwrap()); }
                    other => prop_assert!(false, "unexpected escape {other}"),
                }
            } else {
                prop_assert!(c as u32 >= 32 && c != '"');
                dec.push(c);
            }
        }
        prop_assert_eq!(dec, s);
    }

    /// A too-small buffer latches the failure and never overruns; later writes are no-ops.
    #[test]
    fn json_writer_latches_on_overflow(cap in 0usize..40, n in 0u64..u64::MAX) {
        let mut buf = std::vec![0u8; cap];
        let mut w = JsonWriter::new(SliceSink::new(&mut buf));
        w.raw("{\"k\":");
        w.number(n);
        w.ch(b'}');
        let want = std::format!("{{\"k\":{n}}}");
        if cap >= want.len() {
            prop_assert!(!w.failed());
            prop_assert_eq!(w.sink().written(), want.as_bytes());
        } else {
            prop_assert!(w.failed());
            prop_assert!(!w.ch(b'x'));
            prop_assert!(w.sink().written().len() <= cap);
        }
    }
}

/// Deterministic mini-fuzz: random bytes drive the token through every entry point; nothing panics and the invariants hold.
#[test]
fn negotiation_minifuzz_from_bytes() {
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..200 {
        let mut n = Negotiation::new((next() % 90_000) as u32, (next() % 3000) as u32, (next() % 25_000) as u32);
        let mut now = 0u64;
        let mut acquires: Vec<(Acquire, bool)> = Vec::new();
        for _ in 0..500 {
            now += next() % 3000;
            let key = Key::from_raw((next() % 12 + 1) as u32).unwrap();
            match next() % 5 {
                0 | 1 => {
                    let _ = n.request(now, key, [Prio::Start, Prio::Rejoin, Prio::Relay][(next() % 3) as usize], Phase::Control);
                }
                2 => {
                    let _ = n.release(now, key);
                }
                3 => acquires.push((Acquire::new(now, (next() % 500) as u32, key, Prio::Relay, Phase::Derp), true)),
                _ => {
                    for (a, live) in acquires.iter_mut().filter(|(_, l)| *l) {
                        if !matches!(a.poll(&mut n, now), AcquirePoll::Pending { .. }) {
                            *live = false;
                        }
                    }
                }
            }
            let s = n.status(now);
            assert!(s.waiting as usize <= ML_NEG_MAX_WAITERS, "round {round}");
            assert_eq!(s.holder != 0, n.busy());
            let _ = n.next_deadline();
        }
    }
}

#[test]
fn state_sizes_for_the_adr() {
    use tdongle_tailnet_admission::{ledger, negotiation, rx_stats, usb_rx, wg_rx};
    std::println!(
        "STATE_BYTES (host 64-bit; the token is 264 on the ESP32-S3, the rest equal): Negotiation {} | Ledger {} | RxStats {} | usb_rx::Budget {} | wg_rx::Budget {} | HbRefused {}",
        negotiation::Negotiation::<negotiation::NoObserver>::STATE_BYTES,
        ledger::Ledger::STATE_BYTES,
        rx_stats::RxStats::STATE_BYTES,
        core::mem::size_of::<usb_rx::Budget>(),
        core::mem::size_of::<wg_rx::Budget>(),
        core::mem::size_of::<tdongle_tailnet_admission::heap::HbRefused>(),
    );
    assert!(negotiation::Negotiation::<negotiation::NoObserver>::STATE_BYTES < 600);
}
