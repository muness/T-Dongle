//! The bounded JSON tokenizer on arbitrary bytes: never panics, never exceeds its depth, and gives the same events and verdict however the input is split.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_map::json::{Event, MAX_DEPTH, Policy, TokenSink, Tokenizer};

#[derive(Default)]
struct Digest {
    hash: u64,
    events: u32,
    depth: usize,
    max_depth: usize,
}

impl Digest {
    fn mix(&mut self, v: u64) {
        self.hash = (self.hash ^ v).wrapping_mul(0x100_0000_01b3);
    }
}

impl TokenSink for Digest {
    type Error = ();
    fn event(&mut self, e: Event<'_>) -> Result<(), ()> {
        self.events += 1;
        match e {
            Event::StartObject | Event::StartArray => {
                self.depth += 1;
                self.max_depth = self.max_depth.max(self.depth);
                self.mix(1);
            }
            Event::EndObject | Event::EndArray => {
                self.depth -= 1;
                self.mix(2);
            }
            Event::Key(t) | Event::Str(t) => {
                self.mix(3 + t.flags as u64);
                for b in t.bytes {
                    self.mix(*b as u64);
                }
                self.mix(t.decoded_len as u64 ^ ((t.raw_len as u64) << 32));
            }
            Event::Number(n) => {
                self.mix(4);
                for b in n {
                    self.mix(*b as u64);
                }
            }
            Event::Bool(b) => self.mix(5 + b as u64),
            Event::Null => self.mix(7),
        }
        Ok(())
    }
}

fn run(policy: Policy, pieces: &[&[u8]]) -> (bool, Digest) {
    let mut t = Tokenizer::new(policy);
    let mut d = Digest::default();
    for p in pieces {
        if t.feed(p, &mut d).is_err() {
            return (false, d);
        }
    }
    (t.finish(&mut d).is_ok(), d)
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, doc)) = data.split_first() else { return };
    let policy = if sel & 1 == 0 { Policy::CCompat } else { Policy::Strict };
    let cut = if doc.is_empty() { 0 } else { (sel as usize >> 1) * doc.len() / 128 };
    let (ok_whole, whole) = run(policy, &[doc]);
    assert!(whole.max_depth <= MAX_DEPTH);
    let (ok_split, split) = run(policy, &[&doc[..cut], &doc[cut..]]);
    assert_eq!((ok_whole, whole.hash, whole.events), (ok_split, split.hash, split.events));
    let singles: Vec<&[u8]> = doc.chunks(1).collect();
    let (ok_single, single) = run(policy, &singles);
    assert_eq!((ok_whole, whole.hash, whole.events), (ok_single, single.hash, single.events));
});
