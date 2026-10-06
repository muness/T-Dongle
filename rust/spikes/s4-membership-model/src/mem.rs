//! Counting global allocator over esp_alloc::HEAP, heap high-water per phase, and stack painting.
use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::sync::atomic::{AtomicIsize, AtomicUsize, Ordering::Relaxed};
use esp_alloc::HEAP;
use s4_model::meter::Meter;

pub struct Counting;
pub const NTAGS: usize = 9;
pub const TAG_NAMES: [&str; NTAGS] = ["other/main", "coord", "derp+negotiator", "wireguard", "disco+stun", "-", "mbedtls-client", "mbedtls-server", "tag8"];
pub const T_COORD: u8 = 1;
pub const T_DERP: u8 = 2;
pub const T_WG: u8 = 3;
pub const T_DISCO: u8 = 4;
pub const T_MBED_CLIENT: u8 = 6;
pub const T_MBED_SERVER: u8 = 7;
static TAG: AtomicUsize = AtomicUsize::new(0);
static TAG_CUR: [AtomicIsize; NTAGS] = [const { AtomicIsize::new(0) }; NTAGS];
static TAG_PEAK: [AtomicIsize; NTAGS] = [const { AtomicIsize::new(0) }; NTAGS];
static TAG_STACK: [AtomicUsize; NTAGS] = [const { AtomicUsize::new(0) }; NTAGS];
static PEAK: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static MAXA: AtomicUsize = AtomicUsize::new(0);
static FAILS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let u0 = HEAP.used();
        let p = unsafe { HEAP.alloc(l) };
        if p.is_null() {
            FAILS.fetch_add(1, Relaxed);
        } else {
            let u1 = HEAP.used();
            COUNT.fetch_add(1, Relaxed);
            MAXA.fetch_max(l.size(), Relaxed);
            PEAK.fetch_max(u1, Relaxed);
            let t = TAG.load(Relaxed);
            let c = TAG_CUR[t].fetch_add(u1 as isize - u0 as isize, Relaxed) + (u1 as isize - u0 as isize);
            TAG_PEAK[t].fetch_max(c, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let u0 = HEAP.used();
        unsafe { HEAP.dealloc(p, l) };
        let u1 = HEAP.used();
        TAG_CUR[TAG.load(Relaxed)].fetch_sub(u0 as isize - u1 as isize, Relaxed);
    }
}
#[global_allocator]
static A: Counting = Counting;

pub fn used() -> usize {
    HEAP.used()
}
pub fn free() -> usize {
    HEAP.free()
}
pub fn fails() -> usize {
    FAILS.load(Relaxed)
}
pub fn reset_peak() {
    PEAK.store(HEAP.used(), Relaxed);
}
pub fn peak() -> usize {
    PEAK.load(Relaxed)
}

unsafe extern "C" {
    static _stack_end_cpu0: u8;
    static _stack_start_cpu0: u8;
    pub static _data_start: u8;
    pub static _data_end: u8;
    pub static _bss_start: u8;
    pub static _bss_end: u8;
}
pub fn stack_bounds() -> (usize, usize) {
    unsafe { (&raw const _stack_end_cpu0 as usize, &raw const _stack_start_cpu0 as usize) }
}

#[inline(always)]
fn sp() -> usize {
    // Address of a local: within one frame of SP, no inline asm needed.
    let marker = 0u32;
    core::hint::black_box(&marker) as *const u32 as usize
}

const PAT: u32 = 0xA5C3_5A3C;
const MARGIN_TOP: usize = 64; // our own paint() frame sits above this; interrupts run to completion before painting resumes
const MARGIN_BOTTOM: usize = 1024; // never paint the guard region

/// Paint everything below the current SP down to the guard. Returns (sp, lowest painted address) or None if SP is not on the main stack.
#[inline(never)]
fn paint() -> Option<(usize, usize)> {
    let (lo, hi) = stack_bounds();
    let s = sp();
    if s <= lo + MARGIN_BOTTOM + MARGIN_TOP || s > hi {
        return None;
    }
    let from = lo + MARGIN_BOTTOM;
    let to = (s - MARGIN_TOP) & !3;
    let mut a = from;
    while a < to {
        unsafe { (a as *mut u32).write_volatile(PAT) };
        a += 4;
    }
    Some((s, from))
}
#[inline(never)]
fn paint_win(window: usize) -> Option<(usize, usize, usize)> {
    let (lo, hi) = stack_bounds();
    let s = sp();
    if s <= lo + MARGIN_BOTTOM + MARGIN_TOP || s > hi {
        return None;
    }
    let from = core::cmp::max(lo + MARGIN_BOTTOM, s.saturating_sub(window));
    let to = (s - MARGIN_TOP) & !3;
    let mut a = from;
    while a < to {
        unsafe { (a as *mut u32).write_volatile(PAT) };
        a += 4;
    }
    Some((s, from, to))
}
/// Lowest address below `to` that no longer holds the pattern.
#[inline(never)]
fn scan(from: usize, to: usize) -> usize {
    let mut a = from;
    while a < to {
        if unsafe { (a as *const u32).read_volatile() } != PAT {
            return a;
        }
        a += 4;
    }
    to
}

pub struct M {
    name: Cell<&'static str>,
    base: Cell<usize>,
    count0: Cell<usize>,
    paint: Cell<Option<(usize, usize)>>,
}
unsafe impl Sync for M {}
pub static METER: M = M { name: Cell::new(""), base: Cell::new(0), count0: Cell::new(0), paint: Cell::new(None) };

impl Meter for M {
    fn begin(&self, name: &'static str) {
        self.name.set(name);
        let u = HEAP.used();
        self.base.set(u);
        PEAK.store(u, Relaxed);
        MAXA.store(0, Relaxed);
        self.count0.set(COUNT.load(Relaxed));
        self.paint.set(paint());
    }
    fn end(&self) {
        let (lo, hi) = stack_bounds();
        let (depth, below) = match self.paint.get() {
            Some((s, from)) => {
                let low = scan(from, (s - MARGIN_TOP) & !3);
                (s.saturating_sub(low) as isize, (hi - s) as isize)
            }
            None => (-1, -1),
        };
        let _ = lo;
        let used = HEAP.used();
        esp_println::println!(
            "S4 PHASE {} base={} retained={} peak={} allocs={} maxalloc={} stack_below_call={} stack_above_call={}",
            self.name.get(),
            self.base.get(),
            used as isize - self.base.get() as isize,
            PEAK.load(Relaxed) as isize - self.base.get() as isize,
            COUNT.load(Relaxed) - self.count0.get(),
            MAXA.load(Relaxed),
            depth,
            below
        );
    }
    fn size(&self, name: &'static str, bytes: usize) {
        esp_println::println!("S4 SIZE {} {}", name, bytes);
    }
}


// ---- per-task accounting: every task's top-level future runs inside `Tagged`, which (1) attributes allocations made while it
// is polled to its tag and (2) paints the stack window below its poll frame before each poll and scans it after, keeping the
// deepest excursion. The executor runs all tasks on the one main stack, so a task's "stack" is the depth of its poll chain.
const WINDOW: usize = 48 * 1024;
pub struct Tagged<F> {
    tag: u8,
    f: F,
}
pub fn tagged<F: core::future::Future>(tag: u8, f: F) -> Tagged<F> {
    Tagged { tag, f }
}
impl<F: core::future::Future> core::future::Future for Tagged<F> {
    type Output = F::Output;
    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<F::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let prev = TAG.swap(this.tag as usize, Relaxed);
        // paint_win is inline(never): its marker lies below this frame, so no live local of this (possibly large, inlined) frame is painted.
        let pw = paint_win(WINDOW);
        let r = unsafe { core::pin::Pin::new_unchecked(&mut this.f) }.poll(cx);
        if let Some((s, from, to)) = pw {
            let low = scan(from, to);
            TAG_STACK[this.tag as usize].fetch_max(s - low, Relaxed);
        }
        TAG.store(prev, Relaxed);
        r
    }
}
/// Run a closure with allocations attributed to `tag`.
pub fn with_tag<R>(tag: u8, f: impl FnOnce() -> R) -> R {
    let prev = TAG.swap(tag as usize, Relaxed);
    let r = f();
    TAG.store(prev, Relaxed);
    r
}
pub fn tag_cur(t: u8) -> isize {
    TAG_CUR[t as usize].load(Relaxed)
}
pub fn tag_peak(t: u8) -> isize {
    TAG_PEAK[t as usize].load(Relaxed)
}
pub fn report_tags() {
    for t in 0..NTAGS {
        let (c, p, st) = (TAG_CUR[t].load(Relaxed), TAG_PEAK[t].load(Relaxed), TAG_STACK[t].load(Relaxed));
        if c != 0 || p != 0 || st != 0 {
            esp_println::println!("S4 TAG {} heap_now={} heap_peak={} poll_stack_max={}", TAG_NAMES[t], c, p, st);
        }
    }
}
