//! The host stand-in for FreeRTOS, TinyUSB and ESP-IDF: port of `tests/mocks/net.h`.
//!
//! The mocks are strict on purpose, like the C ones: the lock is a real lock, and everything that must never happen inside it (allocation,
//! free, task calls, TinyUSB calls) or in the producer (waiting, deferring, allocating) is an assertion here. The heap is a test-controlled
//! number minus what the code holds; freed memory is poisoned so a read after free shows up even without a sanitizer.

use std::prelude::v1::*;

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::ptr::NonNull;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicUsize,
    Ordering::{Acquire, Relaxed, Release, SeqCst},
};
use std::sync::{Arc, Mutex, Weak};

use crate::{CHUNK_BYTES, Config, Ring, RingEnv, SLAB_BYTES, Wait};

std::thread_local! {
    /// Inside the ring's critical section (`in_crit`).
    pub static IN_CRIT: Cell<bool> = const { Cell::new(false) };
    /// A case that models the lwIP core lock holder: it may never wait (`in_producer`).
    pub static IN_PRODUCER: Cell<bool> = const { Cell::new(false) };
}

pub fn in_crit() -> bool {
    IN_CRIT.with(Cell::get)
}
pub fn in_producer() -> bool {
    IN_PRODUCER.with(Cell::get)
}
/// Run `f` as the producer: the mocks assert it never waits, defers or allocates.
pub fn as_producer<R>(f: impl FnOnce() -> R) -> R {
    IN_PRODUCER.with(|p| p.set(true));
    let r = f();
    IN_PRODUCER.with(|p| p.set(false));
    r
}

/// A hook run from inside a mock call, with the ring that called it.
pub type Hook = Arc<dyn Fn(&Ring<World>) + Send + Sync>;

/// The records the USB-side observer sees: every accepted frame carries a sequence number and a length-derived fill pattern.
#[derive(Debug, Default)]
pub struct Observer {
    pub delivered_seq: u32,
    pub delivered_frames: u32,
    /// Multiplier of the sequence number in the pattern: 1 for the cases, 7 for the threads test.
    pub mul: u32,
    pub active: bool,
    /// Frames may be flushed between deliveries: only require that a sequence number never repeats or goes back, and count the gaps.
    pub monotonic: bool,
    pub gaps: u64,
    /// Keep a copy of every delivered frame for the model test to compare (`log`), instead of requiring a sequence.
    pub record: bool,
    pub log: Vec<Vec<u8>>,
}

pub fn pattern_byte(seq: u32, mul: u32, n: usize, i: usize) -> u8 {
    seq.wrapping_mul(mul).wrapping_add(n as u32).wrapping_add(i as u32) as u8
}

/// Build the test frame of `n` bytes with sequence number `seq`.
pub fn build_frame(seq: u32, mul: u32, n: usize) -> Vec<u8> {
    let mut f = vec![0u8; n];
    f[..4].copy_from_slice(&seq.to_le_bytes());
    for (i, b) in f.iter_mut().enumerate().skip(4) {
        *b = pattern_byte(seq, mul, n, i);
    }
    f
}

pub struct World {
    // lock
    locked: AtomicBool,
    pub crit_total: AtomicUsize,
    // time
    pub tick: AtomicU32,
    pub us: AtomicU32,
    // USB
    pub usb_ready: AtomicBool,
    /// TinyUSB's free NTB count: -1 unlimited, 0 every NTB in flight, n frames.
    pub ntb_credit: AtomicI32,
    pub allow_tx: AtomicBool,
    pending: Mutex<VecDeque<()>>,
    pub notify_count: AtomicU32,
    // heap
    pub heap_total: AtomicI64,
    pub heap_live_bytes: AtomicI64,
    pub heap_live_blocks: AtomicI64,
    pub mock_largest: AtomicUsize,
    /// The next allocation leaves this as the largest block (0: none).
    pub frag_next: AtomicUsize,
    pub malloc_fail: AtomicBool,
    pub malloc_calls: AtomicUsize,
    pub largest_calls: AtomicUsize,
    chunks: Mutex<HashMap<usize, Vec<u8>>>,
    // policy
    pub gate_busy: AtomicBool,
    // PM hold
    pub pm_held: AtomicI32,
    pub pm_acquires: AtomicI32,
    pub pm_releases: AtomicI32,
    pub prio_sets: AtomicU32,
    pub prio_cur: AtomicI32,
    // hooks
    pub malloc_hook: Mutex<Option<Hook>>,
    pub delay_hook: Mutex<Option<Hook>>,
    pub pre_copy_hook: Mutex<Option<Hook>>,
    /// Runs (once) inside `now_us`: the producer calls it between reserve and commit.
    pub now_hook: Mutex<Option<Hook>>,
    pub pm_begin_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub pm_end_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub obs: Mutex<Observer>,
    ring: Mutex<Weak<Ring<World>>>,
}

impl std::fmt::Debug for World {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("World").finish_non_exhaustive()
    }
}

impl World {
    pub fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            crit_total: AtomicUsize::new(0),
            tick: AtomicU32::new(0),
            us: AtomicU32::new(0),
            usb_ready: AtomicBool::new(true),
            ntb_credit: AtomicI32::new(-1),
            allow_tx: AtomicBool::new(true),
            pending: Mutex::new(VecDeque::new()),
            notify_count: AtomicU32::new(0),
            heap_total: AtomicI64::new(200_000),
            heap_live_bytes: AtomicI64::new(0),
            heap_live_blocks: AtomicI64::new(0),
            mock_largest: AtomicUsize::new(100_000),
            frag_next: AtomicUsize::new(0),
            malloc_fail: AtomicBool::new(false),
            malloc_calls: AtomicUsize::new(0),
            largest_calls: AtomicUsize::new(0),
            chunks: Mutex::new(HashMap::new()),
            gate_busy: AtomicBool::new(false),
            pm_held: AtomicI32::new(0),
            pm_acquires: AtomicI32::new(0),
            pm_releases: AtomicI32::new(0),
            prio_sets: AtomicU32::new(0),
            prio_cur: AtomicI32::new(-1),
            malloc_hook: Mutex::new(None),
            delay_hook: Mutex::new(None),
            pre_copy_hook: Mutex::new(None),
            now_hook: Mutex::new(None),
            pm_begin_hook: Mutex::new(None),
            pm_end_hook: Mutex::new(None),
            obs: Mutex::new(Observer { mul: 1, active: true, ..Observer::default() }),
            ring: Mutex::new(Weak::new()),
        }
    }

    /// Account the permanent base block like the C's `heap_caps_malloc` of it.
    pub fn account_base(&self, bytes: usize) {
        self.heap_live_bytes.fetch_add(bytes as i64, SeqCst);
        self.heap_live_blocks.fetch_add(1, SeqCst);
    }

    /// Pop one deferred TinyUSB callback if there is one (the TinyUSB task's `run_deferred`, one step).
    pub fn take_pending(&self) -> bool {
        self.pending.lock().unwrap().pop_front().is_some()
    }

    /// Pending deferred TinyUSB callbacks (`pending`).
    pub fn pending(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    fn run_hook(&self, slot: &Mutex<Option<Hook>>, one_shot: bool) {
        let hook = {
            let mut g = slot.lock().unwrap();
            if one_shot { g.take() } else { g.clone() }
        };
        if let Some(h) = hook {
            let ring = self.ring.lock().unwrap().upgrade().expect("the ring outlives its hooks");
            h(&ring);
        }
    }

    pub fn free_size(&self) -> usize {
        (self.heap_total.load(SeqCst) - self.heap_live_bytes.load(SeqCst)) as usize
    }
}

// SAFETY: `lock`/`unlock` are a real spin lock (acquire/release on one atomic flag), so they are mutually exclusive across threads;
// `alloc_chunk` returns the start of a zero-initialised `Vec<u8>` of exactly `CHUNK_BYTES` bytes that stays owned by the `chunks` map, unmoved
// and not touched by the world, until `free_chunk` removes it.
unsafe impl RingEnv for World {
    fn lock(&self) {
        while self.locked.compare_exchange_weak(false, true, Acquire, Relaxed).is_err() {
            std::thread::yield_now();
        }
        assert!(!in_crit());
        IN_CRIT.with(|c| c.set(true));
        self.crit_total.fetch_add(1, SeqCst);
    }

    fn unlock(&self) {
        assert!(in_crit());
        IN_CRIT.with(|c| c.set(false));
        self.locked.store(false, Release);
    }

    fn now_us(&self) -> u32 {
        self.run_hook(&self.now_hook, true);
        self.us.load(SeqCst)
    }

    fn now_ms(&self) -> u32 {
        self.tick.load(SeqCst)
    }

    fn usb_ready(&self) -> bool {
        assert!(!in_crit());
        self.usb_ready.load(SeqCst)
    }

    fn can_xmit(&self, len: u16) -> bool {
        assert!(!in_crit() && !in_producer());
        self.allow_tx.load(SeqCst) && len <= 1518 && self.ntb_credit.load(SeqCst) != 0
    }

    fn xmit(&self, frame: &[u8]) {
        assert!(!in_crit() && !in_producer());
        self.run_hook(&self.pre_copy_hook, false); // "the consumer is mid-copy"
        let copy = frame.to_vec(); // tud_network_xmit_cb: the synchronous copy out of the slab
        self.observe(&copy);
        if self.ntb_credit.load(SeqCst) > 0 {
            self.ntb_credit.fetch_sub(1, SeqCst);
        }
    }

    fn defer_drain(&self) {
        assert!(!in_producer() && !in_crit());
        let mut q = self.pending.lock().unwrap();
        assert!(q.len() < 8);
        q.push_back(());
    }

    fn alloc_chunk(&self) -> Option<NonNull<u8>> {
        assert!(!in_crit() && !in_producer());
        self.run_hook(&self.malloc_hook, true); // "something else happens during a growth"
        self.malloc_calls.fetch_add(1, SeqCst);
        if self.malloc_fail.load(SeqCst) {
            return None;
        }
        let mut block = vec![0u8; CHUNK_BYTES];
        let p = NonNull::new(block.as_mut_ptr()).unwrap();
        self.heap_live_bytes.fetch_add(CHUNK_BYTES as i64, SeqCst);
        self.heap_live_blocks.fetch_add(1, SeqCst);
        let frag = self.frag_next.swap(0, SeqCst);
        if frag != 0 {
            self.mock_largest.store(frag, SeqCst);
        }
        self.chunks.lock().unwrap().insert(p.as_ptr() as usize, block);
        Some(p)
    }

    fn free_chunk(&self, chunk: NonNull<u8>) {
        assert!(!in_crit() && !in_producer());
        let mut block = self.chunks.lock().unwrap().remove(&(chunk.as_ptr() as usize)).expect("freeing a chunk this world allocated");
        block.fill(0xdd); // a read after free sees poison even without a sanitizer
        self.heap_live_bytes.fetch_sub(CHUNK_BYTES as i64, SeqCst);
        self.heap_live_blocks.fetch_sub(1, SeqCst);
    }

    fn free_internal_heap(&self) -> usize {
        assert!(!in_crit());
        self.free_size()
    }

    fn largest_free_block(&self) -> usize {
        assert!(!in_crit());
        self.largest_calls.fetch_add(1, SeqCst);
        self.mock_largest.load(SeqCst)
    }

    fn notify_worker(&self) {
        assert!(!in_crit());
        self.notify_count.fetch_add(1, SeqCst);
    }

    fn delay_ms(&self, ms: u32) {
        assert!(!in_producer() && !in_crit());
        self.tick.fetch_add(ms, SeqCst);
        self.run_hook(&self.delay_hook, false);
    }

    fn set_worker_priority(&self, priority: u32) {
        assert!(!in_crit() && !in_producer());
        self.prio_sets.fetch_add(1, SeqCst);
        self.prio_cur.store(priority as i32, SeqCst);
    }

    fn worker_stack_free(&self) -> u32 {
        777
    }

    fn gate(&self) -> bool {
        self.gate_busy.load(SeqCst)
    }

    fn pm_begin(&self) {
        assert!(!in_crit() && !in_producer());
        let hook = self.pm_begin_hook.lock().unwrap().clone();
        if let Some(h) = hook {
            h();
            return;
        }
        assert_eq!(self.pm_held.swap(1, SeqCst), 0, "pm begin while held");
        self.pm_acquires.fetch_add(1, SeqCst);
    }

    fn pm_end(&self) {
        assert!(!in_crit() && !in_producer());
        let hook = self.pm_end_hook.lock().unwrap().clone();
        if let Some(h) = hook {
            h();
            return;
        }
        assert_eq!(self.pm_held.swap(0, SeqCst), 1, "pm end while not held");
        self.pm_releases.fetch_add(1, SeqCst);
    }
}

impl World {
    /// The observer: every accepted frame arrives in order, once, with its bytes intact (`observe`).
    fn observe(&self, p: &[u8]) {
        let mut o = self.obs.lock().unwrap();
        if !o.active {
            return;
        }
        if o.record {
            o.log.push(p.to_vec());
            o.delivered_frames += 1;
            return;
        }
        let n = p.len();
        let seq = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
        if o.monotonic {
            assert!(seq >= o.delivered_seq, "a frame was repeated or reordered: {seq} after {}", o.delivered_seq);
            o.gaps += u64::from(seq - o.delivered_seq);
            o.delivered_seq = seq;
        } else {
            assert_eq!(seq, o.delivered_seq, "in order, none skipped, none repeated");
        }
        for (i, &b) in p.iter().enumerate().skip(4) {
            assert_eq!(b, pattern_byte(seq, o.mul, n, i), "payload byte {i} of frame {seq}");
        }
        o.delivered_seq = o.delivered_seq.wrapping_add(1);
        o.delivered_frames += 1;
    }
}

/// A ring with its world, its base memory and the C test fixtures' helper functions.
pub struct Rig {
    pub ring: Arc<Ring<World>>,
    pub next_seq: Cell<u32>,
    /// The wait `step` used for its notification take (`last_notify_wait`).
    pub last_wait: Cell<Wait>,
    /// The permanent slab memory: declared after `ring` so the ring is dropped first.
    _base: Vec<u8>,
}

pub const FLOOR_FREE: usize = 30_000;
pub const FLOOR_LARGEST: usize = 20_000;
pub const IDLE_MS: u32 = 2000;

/// `cfg_with(base, chunks)` of the C cases: priority 5, the test floors, a 2 s idle period and the PM hold.
pub fn cfg_with(base: u32, chunks: u32) -> Config {
    Config {
        base_frames: base,
        max_chunks: chunks,
        priority: 5,
        work_priority: 0,
        floor_free: FLOOR_FREE,
        floor_largest: FLOOR_LARGEST,
        idle_ms: IDLE_MS,
        pm: true,
    }
}

impl Rig {
    /// `ring_reset`: a fresh ring with a fresh world around it.
    pub fn new(cfg: Config) -> Self {
        Self::with_world(cfg, World::new())
    }

    pub fn with_world(cfg: Config, world: World) -> Self {
        let mut base = vec![0u8; cfg.base_frames as usize * SLAB_BYTES];
        let p = NonNull::new(base.as_mut_ptr()).unwrap();
        world.account_base(base.len());
        // SAFETY: `base` is a live `Vec` of `base_frames * SLAB_BYTES` bytes owned by the returned `Rig`, which drops the ring first (field
        // order) and never touches the vector otherwise.
        let ring = unsafe { Ring::new_with_base(world, cfg, p) }.expect("valid configuration");
        let ring = Arc::new(ring);
        *ring.env().ring.lock().unwrap() = Arc::downgrade(&ring);
        let rig = Self { ring, next_seq: Cell::new(0), last_wait: Cell::new(Wait::Forever), _base: base };
        rig.check_invariants();
        rig
    }

    pub fn w(&self) -> &World {
        self.ring.env()
    }

    pub fn stats(&self) -> crate::TxStats {
        self.ring.stats()
    }

    /// A frame of `n` bytes with the next sequence number; the sequence advances only when the ring accepts it (a refused frame never reaches
    /// USB, so it does not consume one).
    pub fn send_len(&self, n: usize) -> Result<(), crate::SendError> {
        let seq = self.next_seq.get();
        let f = build_frame(seq, self.w().obs.lock().unwrap().mul, n);
        let r = as_producer(|| self.ring.send(&f));
        if r.is_ok() {
            self.next_seq.set(seq + 1);
        }
        r
    }

    pub fn delivered(&self) -> u32 {
        self.w().obs.lock().unwrap().delivered_frames
    }

    /// Frames the observer must never see again after a flush: the stale ones are not delivered, so the expected sequence skips them.
    pub fn skip_to_next(&self) {
        self.w().obs.lock().unwrap().delivered_seq = self.next_seq.get();
    }

    /// The host took an NTB (`in_complete`).
    pub fn in_complete(&self) {
        self.ring.on_in_complete(64);
    }

    pub fn complete_bytes(&self, bytes: u32) {
        self.ring.on_in_complete(bytes);
    }

    /// `tx_worker_step()` of the C: the take, then the step; remembers the wait the take used (`last_notify_wait`).
    pub fn step(&self) -> Wait {
        let wait = self.ring.worker_wait();
        self.w().notify_count.store(0, SeqCst);
        self.last_wait.set(wait);
        self.ring.worker_step();
        wait
    }

    /// The TinyUSB task runs what the worker deferred (`run_deferred`).
    pub fn run_deferred(&self) {
        loop {
            let one = self.w().pending.lock().unwrap().pop_front();
            if one.is_none() {
                return;
            }
            self.ring.do_drain();
        }
    }

    /// One worker wakeup, the TinyUSB callbacks it queued, and the wakeup the consumer's "queue emptied" edge causes (`pump`).
    pub fn pump(&self) {
        self.step();
        self.run_deferred();
        self.step();
    }

    pub fn credit(&self, v: i32) {
        self.w().ntb_credit.store(v, SeqCst);
    }

    pub fn queued(&self) -> u32 {
        self.ring.with_state(|st| st.frames_queued)
    }

    pub fn advance_ms(&self, ms: u32) {
        self.w().tick.fetch_add(ms, SeqCst);
    }

    pub fn drain_all(&self) {
        self.credit(-1);
        for _ in 0..64 {
            if self.queued() == 0 {
                break;
            }
            self.pump();
            self.in_complete();
        }
        self.pump();
        assert_eq!(self.queued(), 0);
    }
}
