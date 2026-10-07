//! ADR measurement: heap behaviour (allocation counts, live and peak bytes) and CPU of this crate against `snow`, same handshake, same records.
//! Run with `cargo test -p tdongle-tailnet-noise --release --test adr_measure -- --nocapture`. The assertions are the crate's contract: zero
//! allocations in the handshake and in the record path. The `snow` rows are printed, not asserted.
mod common;
use snow::{Builder, params::NoiseParams};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_noise::{Initiator, responder};
use tdongle_tailnet_types::test_util::TestRng;

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to `System` unchanged; only counters are added.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        TOTAL.fetch_add(l.size(), Relaxed);
        let live = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(live, Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        // SAFETY: `p` came from `alloc` above with `l`.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        TOTAL.fetch_add(new, Relaxed);
        if new >= l.size() {
            let live = LIVE.fetch_add(new - l.size(), Relaxed) + new - l.size();
            PEAK.fetch_max(live, Relaxed);
        } else {
            LIVE.fetch_sub(l.size() - new, Relaxed);
        }
        // SAFETY: forwarded.
        unsafe { System.realloc(p, l, new) }
    }
}
#[global_allocator]
static A: Counting = Counting;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // fields are read through Debug
struct Heap {
    allocs: usize,
    total: usize,
    peak_over_start: usize,
}
fn measure<R>(f: impl FnOnce() -> R) -> (R, Heap) {
    let start_live = LIVE.load(Relaxed);
    ALLOCS.store(0, Relaxed);
    TOTAL.store(0, Relaxed);
    PEAK.store(start_live, Relaxed);
    let r = f();
    (r, Heap { allocs: ALLOCS.load(Relaxed), total: TOTAL.load(Relaxed), peak_over_start: PEAK.load(Relaxed) - start_live })
}

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn snow_handshake(mpriv: &[u8], cpriv: &[u8], cpub: &[u8]) -> (snow::TransportState, snow::TransportState) {
    let params: NoiseParams = PATTERN.parse().unwrap();
    let mut i = Builder::new(params.clone())
        .prologue(b"Tailscale Control Protocol v131")
        .unwrap()
        .local_private_key(mpriv)
        .unwrap()
        .remote_public_key(cpub)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut r = Builder::new(params).prologue(b"Tailscale Control Protocol v131").unwrap().local_private_key(cpriv).unwrap().build_responder().unwrap();
    let (mut m, mut t) = ([0u8; 128], [0u8; 128]);
    let n = i.write_message(&[], &mut m).unwrap();
    r.read_message(&m[..n], &mut t).unwrap();
    let n = r.write_message(&[], &mut m).unwrap();
    i.read_message(&m[..n], &mut t).unwrap();
    (i.into_transport_mode().unwrap(), r.into_transport_mode().unwrap())
}

#[test]
fn heap_and_cpu_ours_vs_snow() {
    let mut rng = TestRng(42);
    let mpriv = x25519::generate(&mut rng);
    let cpriv = x25519::generate(&mut rng);
    let cpub = x25519::public(&cpriv);

    // ours: initiator half only (what the device runs), then the responder half
    let ((init, msg1), h_init) = measure(|| Initiator::new(&mpriv, &cpub, 131, &mut rng).unwrap());
    let (acc, h_accept) = measure(|| responder::accept(&cpriv, &msg1, &mut rng).unwrap());
    let (mut client, h_finish) = measure(|| init.finish(&acc.response).unwrap());
    let mut server = acc.session;
    let mut buf = vec![0u8; 4096];
    let plain = [0x42u8; 1000];
    let (n, h_seal) = measure(|| client.seal_in_place_1000(&mut buf, &plain));
    let (_, h_open) = measure(|| server.open_record(&mut buf[..n]).unwrap());
    println!("ours  initiator.new   : {h_init:?}");
    println!("ours  responder.accept: {h_accept:?}");
    println!("ours  initiator.finish: {h_finish:?}");
    println!("ours  seal 1000 B     : {h_seal:?}");
    println!("ours  open 1000 B     : {h_open:?}");
    for h in [h_init, h_accept, h_finish, h_seal, h_open] {
        assert_eq!(h.allocs, 0, "the crate must not allocate");
    }

    // snow, same handshake (both halves in one call, as a host test would; the device would run only the initiator half)
    let (pair, h_snow_hs) = measure(|| snow_handshake(&mpriv.0, &cpriv.0, &cpub.0));
    let (mut ti, mut tr) = pair;
    let mut wire = vec![0u8; 1100];
    let (n, h_snow_seal) = measure(|| ti.write_message(&plain, &mut wire).unwrap());
    let mut out = vec![0u8; 1100];
    let (_, h_snow_open) = measure(|| tr.read_message(&wire[..n], &mut out).unwrap());
    println!("snow  full handshake (both halves, build to transport): {h_snow_hs:?}");
    println!("snow  seal 1000 B     : {h_snow_seal:?}");
    println!("snow  open 1000 B     : {h_snow_open:?}");

    // CPU: 300 full handshakes (both halves), 3000 records each way
    let t = Instant::now();
    for k in 0..300u64 {
        let mut r = TestRng(k + 1);
        let (i, m1) = Initiator::new(&mpriv, &cpub, 131, &mut r).unwrap();
        let a = responder::accept(&cpriv, &m1, &mut r).unwrap();
        std::hint::black_box(i.finish(&a.response).unwrap());
    }
    let ours_hs = t.elapsed();
    let t = Instant::now();
    for _ in 0..300 {
        std::hint::black_box(snow_handshake(&mpriv.0, &cpriv.0, &cpub.0));
    }
    let snow_hs = t.elapsed();
    let t = Instant::now();
    for _ in 0..3000 {
        let n = client.seal_in_place_1000(&mut buf, &plain);
        server.open_record(&mut buf[..n]).unwrap();
    }
    let ours_rec = t.elapsed();
    let t = Instant::now();
    for _ in 0..3000 {
        let n = ti.write_message(&plain, &mut wire).unwrap();
        tr.read_message(&wire[..n], &mut out).unwrap();
    }
    let snow_rec = t.elapsed();
    println!("cpu   handshake x300: ours {ours_hs:?}  snow {snow_hs:?}  (snow/ours {:.2})", snow_hs.as_secs_f64() / ours_hs.as_secs_f64());
    println!("cpu   record x3000  : ours {ours_rec:?}  snow {snow_rec:?}  (snow/ours {:.2})", snow_rec.as_secs_f64() / ours_rec.as_secs_f64());
}

trait SealHelper {
    fn seal_in_place_1000(&mut self, buf: &mut [u8], plain: &[u8; 1000]) -> usize;
}
impl SealHelper for tdongle_tailnet_noise::Session {
    fn seal_in_place_1000(&mut self, buf: &mut [u8], plain: &[u8; 1000]) -> usize {
        buf[3..1003].copy_from_slice(plain);
        self.seal_record(buf, 1000).unwrap()
    }
}
