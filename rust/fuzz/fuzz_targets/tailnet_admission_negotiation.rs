//! The negotiation token driven by arbitrary operation bytes: no panic, exclusion and the queue bound hold.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_admission::negotiation::{Acquire, AcquirePoll, Key, Negotiation, Phase, Prio, ML_NEG_MAX_WAITERS};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let mut n = Negotiation::new(u32::from(data[0]) * 400, u32::from(data[1]) * 20, u32::from(data[2]) * 150);
    let mut now = 0u64;
    let mut acquires: Vec<Acquire> = Vec::new();
    for c in data[3..].chunks(4) {
        let b = |i: usize| c.get(i).copied().unwrap_or(0);
        now += u64::from(b(1)) * u64::from(b(2));
        let key = Key::from_raw(u32::from(b(3) % 12) + 1).unwrap();
        let prio = [Prio::Start, Prio::Rejoin, Prio::Relay][usize::from(b(0) >> 4) % 3];
        let phase = [Phase::Start, Phase::Control, Phase::Derp][usize::from(b(0) >> 6) % 3];
        match b(0) & 7 {
            0..=2 => {
                let _ = n.request(now, key, prio, phase);
            }
            3 | 4 => {
                let _ = n.release(now, key);
            }
            5 => acquires.push(Acquire::new(now, u32::from(b(1)) * 10, key, prio, phase)),
            _ => {
                acquires.retain_mut(|a| matches!(a.poll(&mut n, now), AcquirePoll::Pending { .. }));
            }
        }
        let s = n.status(now);
        assert!(s.waiting as usize <= ML_NEG_MAX_WAITERS);
        assert_eq!(s.holder != 0, n.busy());
    }
});
