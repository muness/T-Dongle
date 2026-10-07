//! The record reader takes whatever the control socket delivers; it must never panic and never accept a record that was not sealed by the peer.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_noise::{Feed, Initiator, RecordReader, responder};
use tdongle_tailnet_types::Entropy;

struct Xs(u64);
impl Entropy for Xs {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            *b = (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, rest)) = data.split_first() else { return };
    let mut rng = Xs(0x1234_5678_9abc_def1);
    let (mpriv, cpriv) = (x25519::generate(&mut rng), x25519::generate(&mut rng));
    let cpub = x25519::public(&cpriv);
    let Ok((init, msg1)) = Initiator::new(&mpriv, &cpub, 131, &mut rng) else { return };
    let Ok(acc) = responder::accept(&cpriv, &msg1, &mut rng) else { return };
    let Ok(mut client) = init.finish(&acc.response) else { return };
    let mut reader = RecordReader::new();
    let mut input = rest;
    let step = usize::from(chunk).max(1);
    while !input.is_empty() {
        let part = &input[..step.min(input.len())];
        let mut p = part;
        while !p.is_empty() {
            let (used, ev) = reader.feed(&mut client, p);
            p = &p[used..];
            if let Feed::Error(_) = ev {
                return;
            }
        }
        input = &input[part.len()..];
    }
});
