//! Deterministic mini-fuzz that runs in plain `cargo test`: the libfuzzer entry points of `tdongle_tailnet_disco::fuzz` on random and mutated inputs
//! (seeded, so a failure reproduces). The libfuzzer targets in `rust/fuzz/fuzz_targets/tailnet_disco_*.rs` call the same functions.

use hex_literal::hex;
use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_disco::envelope::{self, PeerId, PeerResolver, RxCounters, RxOutcome, process};
use tdongle_tailnet_disco::fuzz;
use tdongle_tailnet_disco::msg::{Ping, Pong};
use tdongle_tailnet_disco::{Ep, stun};
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_types::{Entropy, Key32};

fn mutate(rng: &mut TestRng, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    let mut r = [0u8; 4];
    rng.fill(&mut r);
    match r[0] % 8 {
        0 => {
            if !v.is_empty() {
                let i = usize::from(r[1]) * 7 % v.len();
                v[i] ^= 1 << (r[2] % 8);
            }
        }
        1 => v.truncate(usize::from(r[1]) % (v.len() + 1)),
        2 => {
            let at = usize::from(r[1]) % (v.len() + 1);
            v.insert(at, r[2]);
        }
        3 => {
            let n = usize::from(r[1]) % 40;
            let mut extra = vec![0u8; n];
            rng.fill(&mut extra);
            v.extend_from_slice(&extra);
        }
        4 => {
            if !v.is_empty() {
                let i = usize::from(r[1]) * 3 % v.len();
                v[i] = r[2];
                let j = usize::from(r[3]) * 5 % v.len();
                v[j] = r[0];
            }
        }
        5 => {
            if !v.is_empty() {
                let at = usize::from(r[1]) % v.len();
                v.remove(at);
            }
        }
        6 => {
            let mut x = vec![0u8; usize::from(r[1]) % 200];
            rng.fill(&mut x);
            return x;
        }
        _ => {
            for b in v.iter_mut().take(usize::from(r[1]) % 24) {
                *b = !*b;
            }
        }
    }
    v
}

fn rand_bytes(rng: &mut TestRng, max: usize) -> Vec<u8> {
    let mut l = [0u8; 2];
    rng.fill(&mut l);
    let n = usize::from(u16::from_le_bytes(l)) % (max + 1);
    let mut v = vec![0u8; n];
    rng.fill(&mut v);
    v
}

struct Fixed {
    sender: Key32,
    shared: Key32,
}
impl PeerResolver for Fixed {
    fn resident(&mut self, s: &[u8; 32]) -> Option<(PeerId, Key32)> {
        (s == self.sender.as_bytes()).then(|| (1, self.shared.clone()))
    }
    fn candidate(&mut self, _: &[u8; 32]) -> Option<(u32, Key32)> {
        None
    }
    fn activate(&mut self, _: u32) -> Option<PeerId> {
        None
    }
}

#[test]
fn mutated_disco_packets_are_never_accepted_and_never_panic() {
    let a_sec = Key32([0x31; 32]);
    let b_sec = Key32([0x77; 32]);
    let (a_pub, b_pub) = (x25519::public(&a_sec), x25519::public(&b_sec));
    let shared_ab = nacl::precompute(&a_sec, &b_pub).unwrap();
    let shared_ba = nacl::precompute(&b_sec, &a_pub).unwrap();
    let mut rng = TestRng(0xd15c0);
    let nk = [5u8; 32];
    let mut corpus: Vec<Vec<u8>> = vec![];
    let mut buf = [0u8; 300];
    let n = envelope::seal_ping(&mut buf, &a_pub, &shared_ab, &[1; 24], &Ping { txid: [2; 12], node_key: Some(&nk), padding: 9 }).unwrap();
    corpus.push(buf[..n].to_vec());
    let n = envelope::seal_pong(&mut buf, &a_pub, &shared_ab, &[2; 24], &Pong { txid: [3; 12], src: Ep::v4([1, 2, 3, 4], 5) }).unwrap();
    corpus.push(buf[..n].to_vec());
    let n = envelope::seal_call_me_maybe(&mut buf, &a_pub, &shared_ab, &[3; 24], &[Ep::v4([1, 2, 3, 4], 5), Ep::v4([5, 6, 7, 8], 9)]).unwrap();
    corpus.push(buf[..n].to_vec());
    let mut counters = RxCounters::new();
    let mut calls = 0u64;
    let mut accepted = 0u64;
    for round in 0..60_000u32 {
        let base = &corpus[round as usize % corpus.len()];
        let m = mutate(&mut rng, base);
        let mut work = m.clone();
        let mut r = Fixed { sender: a_pub.clone(), shared: shared_ba.clone() };
        let res = process(&mut work, &mut r);
        counters.record_result(&res);
        calls += 1;
        if res.is_ok() {
            accepted += 1;
            // the only accepted datagram is a byte-identical authentic one
            assert_eq!(&m, base, "round {round}: a modified packet was accepted");
        }
        // the pipeline's entry point for the fuzzer on the same bytes
        let mut f = vec![0u8];
        f.extend_from_slice(&m);
        fuzz::envelope(&f);
    }
    assert_eq!(counters.total(), calls);
    assert!(accepted > 100, "unmodified packets still pass ({accepted})");
    for o in [RxOutcome::OpenFailed, RxOutcome::UnknownSender, RxOutcome::NotDisco, RxOutcome::NoBox] {
        assert!(counters.get(o) > 0, "{}", o.name());
    }
}

#[test]
fn random_bytes_through_every_entry_point() {
    let mut rng = TestRng(0xf00d);
    for _ in 0..40_000 {
        let v = rand_bytes(&mut rng, 1700);
        fuzz::message(&v);
        fuzz::envelope(&v);
        fuzz::stun_response(&v);
        fuzz::stun_request(&v);
    }
    for _ in 0..3_000 {
        let v = rand_bytes(&mut rng, 4000);
        fuzz::path(&v);
    }
}

#[test]
fn sealed_random_plaintexts_always_open_and_only_the_parse_may_refuse() {
    let mut rng = TestRng(0xbeef);
    for _ in 0..20_000 {
        let mut v = rand_bytes(&mut rng, 300);
        v.insert(0, 1);
        fuzz::envelope(&v); // panics if a sealed packet is refused for any reason but Short / UnknownType
    }
}

#[test]
fn mutated_stun_messages() {
    let mut rng = TestRng(0x57a1);
    let tx = [9u8; 12];
    let mut req = [0u8; stun::REQUEST_LEN];
    stun::build_request(&tx, &mut req);
    let mut r4 = [0u8; 64];
    let n4 = stun::build_response(&tx, &Ep::v4([203, 0, 113, 9], 51820), &mut r4).unwrap();
    let mut r6 = [0u8; 64];
    let n6 = stun::build_response(&tx, &Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2], 4), &mut r6).unwrap();
    let corpus: [&[u8]; 5] = [
        &req,
        &r4[..n4],
        &r6[..n6],
        &hex!("0101000c2112a4422360b11e3ec68ffa93e08007002000080001c786695785 6f"),
        &hex!("010100182112a4424fd5d202dcb37d31fc773306002000140002cd3d2112a4424fd5d202dcb382ce2dc3fcc7"),
    ];
    let mut ok_requests = 0;
    for round in 0..60_000usize {
        let base = corpus[round % corpus.len()];
        let m = mutate(&mut rng, base);
        fuzz::stun_response(&m);
        fuzz::stun_request(&m);
        if let Ok(t) = stun::parse_binding_request(&m) {
            ok_requests += 1;
            assert_eq!(&t[..], &m[8..20]);
        }
    }
    assert!(ok_requests > 100);
    // every single bit of a request is protected by the fingerprint or the header checks
    for i in 0..req.len() {
        for bit in 0..8 {
            let mut m = req;
            m[i] ^= 1 << bit;
            assert!(stun::parse_binding_request(&m).is_err(), "byte {i} bit {bit}");
        }
    }
}
