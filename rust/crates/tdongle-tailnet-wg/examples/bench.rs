//! Host micro-benchmark of the crypto path for 1,400 byte packets (the size ADR 0018 of the C tree uses): `cargo run --release --example bench -p tdongle-tailnet-wg`.
//! Only the *ratios* mean anything off the device; the layers show what each step of the packet path costs on top of raw ChaCha20-Poly1305.

use std::hint::black_box;
use std::time::Instant;
use tdongle_tailnet_crypto::aead::{open_detached, seal_detached};
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_wg::msg::{TransportHeader, transport_len};
use tdongle_tailnet_wg::*;

const N: usize = 1400;

fn time(name: &str, base: Option<f64>, iters: u64, mut f: impl FnMut()) -> f64 {
    for _ in 0..iters / 10 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t.elapsed().as_nanos() as f64 / iters as f64;
    let mbps = N as f64 / ns * 1000.0;
    let rel = base.map_or(String::new(), |b| format!("  ({:.2}x raw)", ns / b));
    println!("{name:<44} {ns:>9.0} ns/pkt  {mbps:>8.1} MB/s{rel}");
    ns
}

struct Idx(u32);
impl IndexAllocator for Idx {
    fn allocate(&mut self) -> Option<u32> {
        self.0 += 1;
        Some(self.0)
    }
}

fn main() {
    let key = [7u8; 32];
    let iters = 200_000;
    println!("1,400 byte payloads, {iters} iterations each\n");
    let mut buf = vec![0u8; transport_len(N)];
    let raw_seal = time("raw ChaCha20-Poly1305 seal (1408 B padded)", None, iters, || {
        black_box(seal_detached(&key, 1, &[], black_box(&mut buf[16..16 + 1408])));
    });
    let mut ct = buf[16..16 + 1408].to_vec();
    let tag = seal_detached(&key, 1, &[], &mut ct);
    let raw_open = time("raw ChaCha20-Poly1305 open (1408 B)", None, iters, || {
        let mut c = ct.clone();
        black_box(open_detached(&key, 1, &[], &mut c, &tag).is_ok());
    });
    let clone_cost = time("  (the clone the open loop pays)", None, iters, || {
        black_box(ct.clone());
    });
    println!("  -> raw open without the clone: {:.0} ns\n", raw_open - clone_cost);

    let mut s_tx = Session::from_keys(key, key, true, 1, 2, 0);
    time("Session::tx_reserve + TxTicket::seal", Some(raw_seal), iters, || {
        let t = s_tx.tx_reserve(0).unwrap();
        black_box(t.seal(black_box(&mut buf), N).unwrap());
    });

    // a peer with a confirmed session on both ends
    let (ida, idb) = (Identity::new(&Key32([1; 32])).unwrap(), Identity::new(&Key32([2; 32])).unwrap());
    let (ca, cb) = (PeerCold::new(&ida, idb.public().clone(), None).unwrap(), PeerCold::new(&idb, ida.public().clone(), None).unwrap());
    let (mut a, mut b) = (PeerHot::new(), PeerHot::new());
    let (mut ra, mut rb) = (TestRng(1), TestRng(2));
    let (mut ia, mut ib) = (Idx(0x100), Idx(0x200));
    let w = WallClock { unix_secs: 1_700_000_000, nanos: 0 };
    let init = a.create_initiation(&ida, &ca, 0, w, &mut ra, &mut ia).unwrap();
    let st = idb.consume_initiation_stage1(&msg::Initiation::parse(&init).unwrap()).unwrap();
    b.consume_initiation(&st, &cb, 0).unwrap();
    let resp = b.create_response(&idb, &cb, 0, &mut rb, &mut ib).unwrap();
    a.consume_response(&ida, &ca, &msg::Response::parse(&resp).unwrap(), 0).unwrap();
    let mut ka = vec![0u8; 32];
    a.encrypt(&mut ka, 0, 0).unwrap();
    b.decrypt(&mut ka, 0).unwrap();

    time("PeerHot::encrypt (tx_prepare + seal + timers)", Some(raw_seal), iters, || {
        black_box(a.encrypt(black_box(&mut buf), N, 0).unwrap());
    });
    // receive: one datagram, rx_begin + open + commit; a fresh counter each time needs fresh datagrams, so pre-seal a batch
    let batch = 10_000usize;
    let mut tx = Session::from_keys(key, key, true, 1, 2, 0);
    let mut pkts: Vec<Vec<u8>> = (0..batch)
        .map(|_| {
            let mut p = vec![0u8; transport_len(N)];
            tx.tx_reserve(0).unwrap().seal(&mut p, N).unwrap();
            p
        })
        .collect();
    let mut rx_session = Session::from_keys(key, key, false, 2, 1, 0);
    let reps = iters as usize / batch;
    let mut work = pkts.clone();
    let t = Instant::now();
    let mut done = 0u64;
    for _ in 0..reps {
        // fresh window each pass: counters repeat across passes
        rx_session = Session::from_keys(key, key, false, 2, 1, 0);
        for (w, p) in work.iter_mut().zip(&pkts) {
            w.copy_from_slice(p);
        }
        for w in work.iter_mut() {
            let h = TransportHeader::parse(w).unwrap();
            let tk = rx_session.rx_peek(h.counter, 0).unwrap();
            let n = tk.open(w).unwrap();
            rx_session.rx_commit(h.counter).unwrap();
            black_box(n);
            done += 1;
        }
    }
    let ns = t.elapsed().as_nanos() as f64 / done as f64;
    println!(
        "{:<44} {ns:>9.0} ns/pkt  {:>8.1} MB/s  ({:.2}x raw open, copy of the batch included)",
        "Session rx_peek + RxTicket::open + commit",
        N as f64 / ns * 1000.0,
        ns / raw_open
    );
    pkts.clear();
    let _ = rx_session;

    println!();
    let mut rng = TestRng(9);
    let t = Instant::now();
    let reps = 50u64;
    let mut hs = PeerHot::new();
    for i in 0..reps {
        let mut idx = Idx(0x300);
        black_box(hs.create_initiation(&ida, &ca, i * 10_000, WallClock { unix_secs: 1_700_000_000 + i, nanos: 0 }, &mut rng, &mut idx).unwrap());
    }
    println!("create_initiation (2 x X25519, blake2s, aead)  {:>9.0} us", t.elapsed().as_micros() as f64 / reps as f64);
}
