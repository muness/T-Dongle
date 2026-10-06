use s4_model::meter::Meter;
use s4_model::scenario::{bring_up, Cfg};
use s4_model::{coord, disco, tls, wg};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static MAXA: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let c = CUR.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(c, Relaxed);
        COUNT.fetch_add(1, Relaxed);
        MAXA.fetch_max(l.size(), Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CUR.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if n >= l.size() {
            let c = CUR.fetch_add(n - l.size(), Relaxed) + n - l.size();
            PEAK.fetch_max(c, Relaxed);
            MAXA.fetch_max(n, Relaxed);
        } else {
            CUR.fetch_sub(l.size() - n, Relaxed);
        }
        COUNT.fetch_add(1, Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;

struct Host {
    name: std::cell::Cell<&'static str>,
    base: std::cell::Cell<usize>,
    count0: std::cell::Cell<usize>,
}
impl Meter for Host {
    fn begin(&self, name: &'static str) {
        self.name.set(name);
        let c = CUR.load(Relaxed);
        self.base.set(c);
        PEAK.store(c, Relaxed);
        MAXA.store(0, Relaxed);
        self.count0.set(COUNT.load(Relaxed));
    }
    fn end(&self) {
        let cur = CUR.load(Relaxed) as i64 - self.base.get() as i64;
        let peak = PEAK.load(Relaxed) as i64 - self.base.get() as i64;
        println!("S4 PHASE {} base={} retained={} peak={} allocs={} maxalloc={} stack=na", self.name.get(), self.base.get(), cur, peak, COUNT.load(Relaxed) - self.count0.get(), MAXA.load(Relaxed));
    }
    fn size(&self, name: &'static str, bytes: usize) {
        println!("S4 SIZE {} {}", name, bytes);
    }
}

pub fn run() {
    let m = Host { name: std::cell::Cell::new(""), base: std::cell::Cell::new(0), count0: std::cell::Cell::new(0) };
    println!("S4 HOST 64-bit {} (requested bytes, no allocator overhead)", std::env::consts::ARCH);
    coord::print_sizes(&m);
    wg::print_sizes(&m);
    disco::print_sizes(&m);
    tls::print_sizes(&m);

    let variants: [(&str, Cfg); 4] = [
        ("SMALL-TCP(streaming coord, 16640/4096 TLS, 2 wg slots, pointer queues, tcp 2880/1440 + 4320/2880)", Cfg { tcp: s4_model::disco::NetCfg::SMALL, ..Cfg::DEFAULT }),
        ("DEFAULT(streaming coord, 16640/4096 TLS, 2 wg slots, pointer queues)", Cfg::DEFAULT),
        ("C-FIGURE-PRIVATE coord buffers (20496+16384), inline queues, 8 wg slots", Cfg { coord: coord::CoordCfg::C_FIGURE_PRIVATE, resident_peers: 8, inline_queues: true, ..Cfg::DEFAULT }),
        ("SHARED coord workspace (0 per membership), 2 wg slots", Cfg { coord: coord::CoordCfg::SHARED, ..Cfg::DEFAULT }),
    ];
    for (name, cfg) in variants {
        println!("S4 VARIANT {}", name);
        let mut keep = Vec::new();
        for n in 1..=3 {
            let before = CUR.load(Relaxed);
            println!("S4 MEMBERSHIP {} begin heap_now={}", n, before);
            let mem = embassy_futures::block_on(bring_up(&m, &cfg));
            let after = CUR.load(Relaxed);
            println!("S4 MEMBERSHIP {} retained={} ok={}", n, after - before, mem.ok);
            keep.push(mem);
        }
        drop(keep);
    }
}
