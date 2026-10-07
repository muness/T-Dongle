//! The whole link under arbitrary event streams: bytes in any state, events out of order, clock jumps. No panic, no unbounded state.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_derp::{Action, Event, Link, Target, Timing};
use tdongle_tailnet_types::{Entropy, Key32};

struct Rng(u64);
impl Entropy for Rng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut link: Link<2048> = Link::new(Key32([7; 32]), Target::new(1, "derp.fuzz", 443), Timing::DEFAULT);
    let mut rng = Rng(1);
    let mut sink = |a: Action<'_>| {
        if let Action::Send(b) = a {
            assert!(!b.is_empty());
        }
    };
    let mut now = 1_000u64;
    let mut at = 0;
    while at < data.len() {
        let op = data[at];
        at += 1;
        now += (op as u64 & 0x0f) * 700;
        let ev = match op >> 4 {
            0 => Event::Connect,
            1 => Event::Reconnect,
            2 => Event::ClockValid(op & 1 == 0),
            3 => Event::TokenGranted,
            4 => Event::Dns(op & 1 == 0),
            5 => Event::Connected(op & 1 == 0),
            6 => Event::TlsDone(op & 1 == 0),
            7 => Event::TxDone,
            8 => Event::TxProgress,
            9 => Event::Timer,
            10 => Event::Close,
            _ => {
                let n = (data.get(at).copied().unwrap_or(0) as usize).min(data.len().saturating_sub(at + 1));
                let s = &data[(at + 1).min(data.len())..(at + 1 + n).min(data.len())];
                at += 1 + n;
                Event::Bytes(s)
            }
        };
        link.handle(now, ev, &mut rng, &mut sink);
        let _ = link.next_deadline_ms(now);
    }
});
