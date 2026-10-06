//! The ring itself.
//!
//! Port of the "Non-blocking, elastic transmit ring" section of `components/esp_tinyusb/tinyusb_net.c`, which stays the specification. The
//! C file-level comment is the design document; its invariants are kept and restated where the code enforces them:
//!
//! * **Exactly once.** A record is handed to the NTB by exactly one `advance`, which is the single release of that record; a flush between
//!   `peek` and `advance` moves `rd` and the advance is skipped (the consumer then counts the frame it was copying itself).
//! * **A slab in the FIFO is never freed.** A chunk is freed only when none of its slabs is in the FIFO (`used == 0`), and a retiring chunk's
//!   slabs are never handed out again. This is what makes the copies outside the lock sound.
//! * **A retiring chunk is freed only when empty**, and detached under the lock, freed outside it.
//! * **A growth that raced a reclaim is discarded** (`epoch`).
//! * **Short critical sections.** Everything under `RingEnv::lock` is a few dozen instructions: no copy, no allocation, no free, no environment
//!   call except `now_ms`.
//!
//! Who runs where (as in the C): `send` is the producer (any single, serialized context, never waits, never allocates); `drain`, `do_drain`
//! and `on_in_complete` are the consumer (the TinyUSB task); `worker_step` is the worker task (growth, shrink, reclaim, the PM hold, the
//! drain relay); `link_down`, `flush`, `elastic_kick`, `elastic_reclaim`, `set_max_chunks`, `stats` and `deinit` are callable from any task.

use core::cell::UnsafeCell;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering::{AcqRel, Acquire, Relaxed, Release, SeqCst}};

use crate::config::{Config, ConfigError, RestartError, SendError, SetMaxChunksError, TxStats, Wait};
use crate::consts::{
    CHUNK_BYTES, CHUNK_SLABS, FIFO_MASK, FRAME_MAX, FRAME_MIN, GROW_RETRY_MAX_MS, GROW_RETRY_MS, HEAP_BLOCK_SLACK, HOUSEKEEP_MS,
    IDLE_DEFAULT_MS, LINK_POLL_MS, MAX_CHUNKS, MAX_SLABS, REC_HDR, SLAB_BYTES, align4,
};
use crate::env::RingEnv;
use crate::mem;

/// Why a chunk is being retired (`TX_WHY_RECLAIM`, `TX_WHY_IDLE`): decides which counter the later free increments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    Reclaim,
    Idle,
}

/// One slab's offsets (`tx_slab_t`): committed end, consumed offset, reserved end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Slab {
    pub(crate) fill: u16,
    pub(crate) rd: u16,
    pub(crate) resv: u16,
}

/// One elastic chunk's slot (`tx_chunk_t`). `mem` null: the slot is free.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Chunk {
    pub(crate) mem: *mut u8,
    pub(crate) used: u8,
    why: Why,
    pub(crate) retiring: bool,
    last_use: u32,
}

impl Chunk {
    const EMPTY: Self = Self { mem: ptr::null_mut(), used: 0, why: Why::Reclaim, retiring: false, last_use: 0 };
}

/// The record the consumer peeked (`tx_rec_t`).
#[derive(Clone, Copy, Debug)]
struct Rec {
    slab: u8,
    rd: u16,
    len: u16,
    gen_: u16,
    /// The record's header, inside its slab.
    at: *const u8,
}

/// Everything protected by the lock (`s_tx` under "under the lock").
#[derive(Debug)]
pub(crate) struct State {
    base: *mut u8,
    pub(crate) base_slabs: u32,
    /// Elastic cap now: starts as `cfg.max_chunks`, `set_max_chunks` moves it.
    pub(crate) max_chunks: u32,
    pub(crate) chunk: [Chunk; MAX_CHUNKS],
    pub(crate) slab: [Slab; MAX_SLABS],
    /// Slab ids, oldest (consumer) first, newest (open, producer) last.
    pub(crate) fifo: [u8; MAX_SLABS],
    pub(crate) fifo_head: u32,
    pub(crate) fifo_n: u32,
    /// Free slabs that may be handed to the producer.
    pub(crate) alloc_mask: u32,
    pub(crate) frames_queued: u32,
    pub(crate) used_bytes: u32,
    /// Chunks allocated, and of those the ones not retiring.
    pub(crate) chunks_present: u32,
    pub(crate) chunks_live: u32,
    /// Bumped by every reclaim.
    epoch: u32,
    /// Slab the consumer peeked and has not advanced past, or -1.
    pub(crate) reading: i32,
    /// Offset of that record: it is the consumer's, a flush must not count it.
    reading_rd: u16,
    /// Producer between reserve and commit.
    resv_open: bool,
    /// The queue went empty to non-empty and that first frame has not been handed over.
    cold_pending: bool,
    cold_edge_us: u32,
    cold_starts: u32,
    cold_us_sum: u32,
    cold_us_max: u32,
    high_water_bytes: u32,
    high_water_slabs: u32,
}

impl State {
    fn new(base: *mut u8, base_slabs: u32, max_chunks: u32) -> Self {
        Self {
            base,
            base_slabs,
            max_chunks,
            chunk: [Chunk::EMPTY; MAX_CHUNKS],
            slab: [Slab::default(); MAX_SLABS],
            fifo: [0; MAX_SLABS],
            fifo_head: 0,
            fifo_n: 0,
            alloc_mask: (1u32 << base_slabs) - 1,
            frames_queued: 0,
            used_bytes: 0,
            chunks_present: 0,
            chunks_live: 0,
            epoch: 0,
            reading: -1,
            reading_rd: 0,
            resv_open: false,
            cold_pending: false,
            cold_edge_us: 0,
            cold_starts: 0,
            cold_us_sum: 0,
            cold_us_max: 0,
            high_water_bytes: 0,
            high_water_slabs: 0,
        }
    }

    /// First byte of slab `s` (`tx_slab_ptr`). Pure pointer arithmetic: no access is made here.
    pub(crate) fn slab_ptr(&self, s: u32) -> *mut u8 {
        if s < self.base_slabs {
            return self.base.wrapping_add(s as usize * SLAB_BYTES);
        }
        let k = (s - self.base_slabs) as usize;
        self.chunk[k / CHUNK_SLABS].mem.wrapping_add((k % CHUNK_SLABS) * SLAB_BYTES)
    }

    /// Allocation-mask bits of chunk `c` (`tx_chunk_mask`).
    pub(crate) fn chunk_mask(&self, c: u32) -> u32 {
        ((1u32 << CHUNK_SLABS) - 1) << (self.base_slabs + c * CHUNK_SLABS as u32)
    }
}

/// All the counters that live outside the lock (`_Atomic uint32_t` of `s_tx`).
#[derive(Debug, Default)]
struct Counters {
    gap_count: AtomicU32,
    gap_us_sum: AtomicU32,
    gap_us_max: AtomicU32,
    gap_hist: [AtomicU32; 5],
    drains_sent: [AtomicU32; 5],
    ntb_xfers: AtomicU32,
    ntb_zlp: AtomicU32,
    ntb_bytes: AtomicU32,
    ntb_max_bytes: AtomicU32,
    enq_frames: AtomicU32,
    enq_bytes: AtomicU32,
    sent_frames: AtomicU32,
    sent_bytes: AtomicU32,
    drop_full: AtomicU32,
    drop_down: AtomicU32,
    drop_invalid: AtomicU32,
    flushed: AtomicU32,
    blocked_events: AtomicU32,
    xfer_events: AtomicU32,
    grow_events: AtomicU32,
    shrink_events: AtomicU32,
    reclaim_events: AtomicU32,
    reclaimed_chunks: AtomicU32,
    deny_gate: AtomicU32,
    deny_heap: AtomicU32,
    deny_largest: AtomicU32,
    deny_nomem: AtomicU32,
    grow_raced: AtomicU32,
    pm_acquired: AtomicU32,
    pm_released: AtomicU32,
    demotions: AtomicU32,
}

fn bump(counter: &AtomicU32) {
    counter.fetch_add(1, Relaxed);
}

/// Clears a flag when dropped: single-producer and single-consumer entry guards.
struct Entered<'a>(&'a AtomicBool);

impl Drop for Entered<'_> {
    fn drop(&mut self) {
        self.0.store(false, Release);
    }
}

/// Leaves the critical section when dropped, so that a panic inside a closure (a failed assertion in a test) cannot leave the lock held.
struct Unlock<'a, E: RingEnv>(&'a E);

impl<E: RingEnv> Drop for Unlock<'_, E> {
    fn drop(&mut self) {
        self.0.unlock();
    }
}

/// The USB transmit ring (`s_tx`): a FIFO of slabs with permanent base slabs and elastic chunks, between one producer (the Wi-Fi to host
/// path), one consumer (the TinyUSB task) and the worker task.
///
/// All methods take `&self`; share it between the contexts with a reference or an `Arc`. See the module documentation for who calls what.
#[derive(Debug)]
pub struct Ring<E: RingEnv> {
    env: E,
    cfg: Config,
    state: UnsafeCell<State>,
    c: Counters,
    /// Link generation.
    gen_: AtomicU16,
    /// USB was not ready on the last look.
    down_seen: AtomicBool,
    enabled: AtomicBool,
    /// A `do_drain` callback is queued in TinyUSB.
    drain_pending: AtomicBool,
    /// Frames are queued (set and cleared under the lock).
    pm_want: AtomicBool,
    /// Worker only writes.
    pm_held: AtomicBool,
    grow_wanted: AtomicBool,
    reap_pending: AtomicBool,
    /// `chunks_present`, for the worker's wait without the lock.
    present_mirror: AtomicU32,
    /// Last drain stopped on `can_xmit() == false` (TinyUSB task only).
    blocked: AtomicBool,
    /// Previous IN completion while frames were queued, 0 when the queue was empty then (TinyUSB task only).
    last_comp_us: AtomicU32,
    /// Tick (ms) before which a refused growth is not retried (worker only).
    grow_retry: AtomicU32,
    /// Milliseconds of the last refusal's back-off, 0 after a growth (worker only).
    grow_backoff: AtomicU32,
    /// A `send` is between its first and last step: the single-producer contract, enforced.
    producing: AtomicBool,
    /// A drain is running: the single-consumer contract, enforced.
    draining: AtomicBool,
}

// SAFETY: the only non-thread-safe parts are the raw pointers and the `UnsafeCell` inside `State`. The `UnsafeCell` is accessed only through
// `locked`, i.e. under `RingEnv::lock`, whose mutual exclusion is a requirement of the `unsafe trait RingEnv`. The raw pointers refer to the
// base block (owned by the ring for its whole life, by the contract of `new_with_base`) and to chunks (owned by the ring from `alloc_chunk`
// to `free_chunk`); the record bytes behind them are accessed only under the ownership protocol described in the module documentation.
unsafe impl<E: RingEnv + Send> Send for Ring<E> {}
// SAFETY: as above; every other field is an atomic or immutable after construction.
unsafe impl<E: RingEnv + Sync> Sync for Ring<E> {}

impl<E: RingEnv> Ring<E> {
    // ------------------------------------------------------------------------------------------------------------------------------
    // construction
    // ------------------------------------------------------------------------------------------------------------------------------

    /// Build the ring over its permanent memory and enable it (`tinyusb_net_tx_ring_start`, first call, minus the task creation, which the
    /// firmware does: spawn a task running `loop { notify_take(wait); wait = ring.worker_step(); }` starting from `ring.worker_wait()`).
    ///
    /// `base` is the permanent slab memory, at least `base_frames * SLAB_BYTES` bytes (the C allocated it with `heap_caps_malloc`).
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when `cfg` is out of range or `base` is too small.
    pub fn new(env: E, cfg: Config, base: &'static mut [u8]) -> Result<Self, ConfigError> {
        cfg.validate()?;
        if base.len() < cfg.base_frames as usize * SLAB_BYTES {
            return Err(ConfigError::BaseTooSmall);
        }
        // SAFETY: `base` is a unique `'static` slice of at least `base_frames * SLAB_BYTES` bytes, so it is valid for reads and writes, owned by
        // nobody else, and outlives the ring.
        unsafe { Self::new_with_base(env, cfg, NonNull::from(base).cast::<u8>()) }
    }

    /// [`new`](Self::new) over a raw block, for firmware that allocates the base from the heap and for tests.
    ///
    /// # Safety
    ///
    /// `base` must be valid for reads and writes of `cfg.base_frames * SLAB_BYTES` bytes, must not be accessed by anything else, and must stay
    /// allocated until the returned ring is dropped.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when `cfg` is out of range.
    pub unsafe fn new_with_base(env: E, cfg: Config, base: NonNull<u8>) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self {
            env,
            cfg,
            state: UnsafeCell::new(State::new(base.as_ptr(), cfg.base_frames, cfg.max_chunks)),
            c: Counters::default(),
            gen_: AtomicU16::new(0),
            down_seen: AtomicBool::new(false),
            enabled: AtomicBool::new(true),
            drain_pending: AtomicBool::new(false),
            pm_want: AtomicBool::new(false),
            pm_held: AtomicBool::new(false),
            grow_wanted: AtomicBool::new(false),
            reap_pending: AtomicBool::new(false),
            present_mirror: AtomicU32::new(0),
            blocked: AtomicBool::new(false),
            last_comp_us: AtomicU32::new(0),
            grow_retry: AtomicU32::new(0),
            grow_backoff: AtomicU32::new(0),
            producing: AtomicBool::new(false),
            draining: AtomicBool::new(false),
        })
    }

    /// `tinyusb_net_tx_ring_start` called again after `deinit`: the same configuration re-enables the ring, nothing is reallocated; another
    /// configuration is refused.
    ///
    /// # Errors
    ///
    /// [`RestartError::Invalid`] for an out-of-range `cfg`, [`RestartError::Mismatch`] when `cfg` differs from the one the ring was built with.
    pub fn restart(&self, cfg: &Config) -> Result<(), RestartError> {
        cfg.validate().map_err(RestartError::Invalid)?;
        if *cfg != self.cfg {
            return Err(RestartError::Mismatch);
        }
        self.enabled.store(true, SeqCst);
        Ok(())
    }

    /// The environment (for the firmware's own glue and the tests).
    #[must_use]
    pub fn env(&self) -> &E {
        &self.env
    }

    /// The configuration the ring was built with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Whether the ring accepts frames (`s_tx.enabled`).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Acquire)
    }

    /// Run `f` with the lock held (`TX_ENTER` ... `TX_EXIT`). `f` must not call anything that locks.
    fn locked<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        self.env.lock();
        let _unlock = Unlock(&self.env);
        // SAFETY: `lock` has returned, so by the contract of `RingEnv` no other context holds the lock, and the `UnsafeCell` is touched only
        // here; the reference is dropped before `_unlock` runs `unlock`. `f` receives the only reference and cannot re-enter `locked`.
        let st = unsafe { &mut *self.state.get() };
        f(st)
    }

    /// Test access to the locked bookkeeping.
    #[cfg(test)]
    pub(crate) fn with_state<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        self.locked(f)
    }

    // ------------------------------------------------------------------------------------------------------------------------------
    // pool, under the lock
    // ------------------------------------------------------------------------------------------------------------------------------

    /// Take the lowest free slab (`tx_pop_slab_locked`).
    fn pop_slab_locked(st: &mut State) -> Option<u32> {
        if st.alloc_mask == 0 {
            return None;
        }
        let s = st.alloc_mask.trailing_zeros();
        st.alloc_mask &= !(1u32 << s);
        if s >= st.base_slabs {
            st.chunk[(s - st.base_slabs) as usize / CHUNK_SLABS].used += 1;
        }
        Some(s)
    }

    /// Give a slab back (`tx_release_slab_locked`): a retiring chunk's slabs are never handed out again.
    fn release_slab_locked(&self, st: &mut State, s: u32) {
        if s >= st.base_slabs {
            let ch = &mut st.chunk[(s - st.base_slabs) as usize / CHUNK_SLABS];
            ch.used -= 1;
            ch.last_use = self.env.now_ms();
            if ch.retiring {
                if ch.used == 0 {
                    self.reap_pending.store(true, Relaxed);
                }
                return;
            }
        }
        st.alloc_mask |= 1u32 << s;
    }

    fn drop_front_locked(&self, st: &mut State) {
        let s = u32::from(st.fifo[st.fifo_head as usize]);
        st.fifo_head = (st.fifo_head + 1) & FIFO_MASK as u32;
        st.fifo_n -= 1;
        self.release_slab_locked(st, s);
    }

    /// Nothing queued and nobody writing: give the open slab back so the next frame starts in the lowest slab and the chunk that held it can
    /// go idle. Never the slab the consumer is reading (`tx_compact_locked`).
    fn compact_locked(&self, st: &mut State) {
        while st.fifo_n > 0 && st.frames_queued == 0 && !st.resv_open && i32::from(st.fifo[st.fifo_head as usize]) != st.reading {
            self.drop_front_locked(st);
        }
    }

    /// Producer, under the lock: find room for `need` bytes (`tx_reserve_locked`). Returns the slab and the offset in it.
    fn reserve_locked(&self, st: &mut State, need: u32) -> Option<(u32, u32)> {
        self.compact_locked(st);
        if st.fifo_n > 0 {
            let b = u32::from(st.fifo[((st.fifo_head + st.fifo_n - 1) & FIFO_MASK as u32) as usize]);
            let resv = u32::from(st.slab[b as usize].resv);
            if resv + need <= SLAB_BYTES as u32 {
                st.slab[b as usize].resv = (resv + need) as u16;
                st.resv_open = true;
                return Some((b, resv));
            }
        }
        let s = Self::pop_slab_locked(st)?;
        st.slab[s as usize] = Slab { fill: 0, rd: 0, resv: need as u16 };
        st.fifo[((st.fifo_head + st.fifo_n) & FIFO_MASK as u32) as usize] = s as u8;
        st.fifo_n += 1;
        st.resv_open = true;
        Some((s, 0))
    }

    fn commit_locked(&self, st: &mut State, s: u32, need: u32, now_us: u32) {
        st.slab[s as usize].fill = st.slab[s as usize].resv;
        st.resv_open = false;
        if st.frames_queued == 0 {
            st.cold_pending = true; // the consumer measures how long this frame waited for the first hand-over
            st.cold_edge_us = now_us;
        }
        st.frames_queued += 1;
        st.used_bytes += need;
        if st.used_bytes > st.high_water_bytes {
            st.high_water_bytes = st.used_bytes;
        }
        if st.fifo_n > st.high_water_slabs {
            st.high_water_slabs = st.fifo_n;
        }
        self.pm_want.store(true, Release);
    }

    /// Few free slabs and room for another chunk: ask the worker to grow (`tx_pressure_locked`).
    fn pressure_locked(st: &State) -> bool {
        // popcount(mask) <= 1: clearing the lowest set bit leaves nothing (`TX_GROW_HEADROOM == 1`, asserted in `consts`)
        st.chunks_present < st.max_chunks && (st.alloc_mask & st.alloc_mask.wrapping_sub(1)) == 0
    }

    /// Consumer, under the lock: the oldest committed record, or `None` (`tx_peek_locked`).
    fn peek_locked(&self, st: &mut State) -> Option<Rec> {
        while st.fifo_n > 0 {
            let s = u32::from(st.fifo[st.fifo_head as usize]);
            let sl = st.slab[s as usize];
            if sl.rd < sl.fill {
                let at = st.slab_ptr(s).wrapping_add(usize::from(sl.rd)).cast_const();
                // SAFETY: `rd < fill`: the record at `rd` is committed (the producer wrote and published it under the lock, and never writes
                // below `fill` again), and its slab is in the FIFO, so it and its chunk are allocated.
                let (len, gen_) = unsafe { mem::read_header(at) };
                st.reading = s as i32;
                st.reading_rd = sl.rd;
                return Some(Rec { slab: s as u8, rd: sl.rd, len, gen_, at });
            }
            if st.fifo_n == 1 {
                return None; // the open slab, nothing committed in it
            }
            self.drop_front_locked(st); // sealed and fully consumed
        }
        None
    }

    /// Consumer, under the lock: the record returned by peek has been handed over (or discarded). True when the queue just became empty. A
    /// flush that ran in between moved `rd`: then there is nothing to advance (`tx_advance_locked`).
    fn advance_locked(&self, st: &mut State, r: &Rec, sent: bool, now_us: u32) -> bool {
        st.reading = -1;
        let slab = r.slab as usize;
        if st.slab[slab].rd != r.rd {
            self.compact_locked(st);
            return false;
        }
        let need = (REC_HDR + align4(usize::from(r.len))) as u32;
        st.slab[slab].rd += need as u16;
        st.used_bytes -= need;
        st.frames_queued -= 1;
        if st.cold_pending {
            st.cold_pending = false;
            if sent {
                let waited = now_us.wrapping_sub(st.cold_edge_us);
                st.cold_starts += 1;
                st.cold_us_sum = st.cold_us_sum.wrapping_add(waited);
                if waited > st.cold_us_max {
                    st.cold_us_max = waited;
                }
            }
        }
        let emptied = st.frames_queued == 0;
        if emptied {
            self.pm_want.store(false, Release);
        }
        let sl = st.slab[slab];
        if st.fifo_n > 1 && st.fifo[st.fifo_head as usize] == r.slab && sl.rd == sl.fill {
            self.drop_front_locked(st);
        }
        emptied
    }

    /// Under the lock: forget every committed record (link loss at teardown or a damaged record). Returns how many (`tx_discard_locked`).
    fn discard_locked(&self, st: &mut State) -> u32 {
        let mut count = 0;
        for i in 0..st.fifo_n {
            let id = u32::from(st.fifo[((st.fifo_head + i) & FIFO_MASK as u32) as usize]);
            let base = st.slab_ptr(id);
            let mut inflight = id as i32 == st.reading && st.slab[id as usize].rd == st.reading_rd; // the consumer is copying this one out
            while st.slab[id as usize].rd < st.slab[id as usize].fill {
                let rd = st.slab[id as usize].rd;
                // SAFETY: `rd < fill`: a committed record of a slab that is in the FIFO (allocated); only its header is read.
                let (len, _) = unsafe { mem::read_header(base.wrapping_add(usize::from(rd)).cast_const()) };
                if inflight {
                    // Not ours to count: the consumer finishes it (and counts it as sent or flushed).
                    inflight = false;
                    st.slab[id as usize].rd = rd + (REC_HDR + align4(usize::from(len))) as u16;
                    continue;
                }
                count += 1;
                if usize::from(len) < FRAME_MIN || usize::from(len) > FRAME_MAX {
                    st.slab[id as usize].rd = st.slab[id as usize].fill; // damaged (cannot happen): never read past it
                    break;
                }
                st.slab[id as usize].rd = rd + (REC_HDR + align4(usize::from(len))) as u16;
            }
        }
        st.frames_queued = 0;
        st.used_bytes = 0;
        st.cold_pending = false;
        self.pm_want.store(false, Release);
        while st.fifo_n > 1 && i32::from(st.fifo[st.fifo_head as usize]) != st.reading {
            self.drop_front_locked(st);
        }
        self.compact_locked(st);
        count
    }

    // ------------------------------------------------------------------------------------------------------------------------------
    // elastic chunks
    // ------------------------------------------------------------------------------------------------------------------------------

    /// Under the lock: stop handing out a chunk's slabs; it is freed once none is in the FIFO (`tx_retire_chunk_locked`).
    fn retire_chunk_locked(st: &mut State, c: usize, why: Why) {
        let mask = st.chunk_mask(c as u32);
        let ch = &mut st.chunk[c];
        ch.retiring = true;
        ch.why = why;
        st.alloc_mask &= !mask;
        st.chunks_live -= 1;
    }

    fn retire_all_locked(&self, st: &mut State, why: Why) -> u32 {
        self.compact_locked(st);
        let mut n = 0;
        for c in 0..MAX_CHUNKS {
            if !st.chunk[c].mem.is_null() && !st.chunk[c].retiring {
                Self::retire_chunk_locked(st, c, why);
                n += 1;
            }
        }
        n
    }

    fn set_present_locked(&self, st: &State) {
        self.present_mirror.store(st.chunks_present, Relaxed);
    }

    /// Free retiring chunks that no slab of is in the FIFO. Detach under the lock, free outside it (`tx_reap`).
    fn reap(&self) -> u32 {
        let mut mem = [(ptr::null_mut::<u8>(), Why::Reclaim); MAX_CHUNKS];
        self.reap_pending.store(false, Relaxed);
        let n = self.locked(|st| {
            let mut n = 0;
            for c in 0..MAX_CHUNKS {
                let ch = st.chunk[c];
                if !ch.mem.is_null() && ch.retiring && ch.used == 0 {
                    mem[n] = (ch.mem, ch.why);
                    n += 1;
                    st.chunk[c] = Chunk::EMPTY;
                    st.chunks_present -= 1;
                }
            }
            self.set_present_locked(st);
            n
        });
        for &(chunk, why) in &mem[..n] {
            if let Some(chunk) = NonNull::new(chunk) {
                self.env.free_chunk(chunk);
            }
            bump(if why == Why::Idle { &self.c.shrink_events } else { &self.c.reclaimed_chunks });
        }
        n as u32
    }

    /// Worker. Retire when the gate is closed, free chunks that sat idle, then free whatever is retired and empty (`tx_housekeeping`).
    fn housekeeping(&self) {
        if self.present_mirror.load(Relaxed) == 0 {
            return; // no elastic chunk exists: nothing to retire, nothing to shrink (the common case)
        }
        let busy = self.env.gate();
        let now = self.env.now_ms();
        let idle = if self.cfg.idle_ms != 0 { self.cfg.idle_ms } else { IDLE_DEFAULT_MS };
        let retired = self.locked(|st| {
            if busy {
                return self.retire_all_locked(st, Why::Reclaim);
            }
            self.compact_locked(st);
            // Staged: one idle chunk per pass, highest index first (the one the lowest-first allocator touched last), so a chunk that was just
            // given back is not followed by nine more frees in the same instant. With the long idle period this keeps bursty traffic from
            // cycling the heap.
            for c in (0..MAX_CHUNKS).rev() {
                let ch = st.chunk[c];
                if !ch.mem.is_null() && !ch.retiring && ch.used == 0 && (now.wrapping_sub(ch.last_use) as i32) >= idle as i32 {
                    Self::retire_chunk_locked(st, c, Why::Idle);
                    break;
                }
            }
            0
        });
        if retired != 0 {
            bump(&self.c.reclaim_events);
        }
        self.reap();
    }

    /// A refusal backs off exponentially (100 ms, 200, ... 1.6 s), reset by the next successful growth: while the heap is the problem, a
    /// sustained burst must not make the worker walk the heap ten times a second (`tx_deny`).
    fn deny(&self, counter: &AtomicU32, now: u32) {
        bump(counter);
        let backoff = self.grow_backoff.load(Relaxed);
        let backoff = if backoff == 0 {
            GROW_RETRY_MS
        } else if backoff < GROW_RETRY_MAX_MS {
            backoff * 2
        } else {
            backoff
        };
        self.grow_backoff.store(backoff, Relaxed);
        self.grow_retry.store(now.wrapping_add(backoff), Relaxed);
    }

    /// Worker. Add chunks while the producer is close to running out of slabs and the heap can afford it (`tx_try_grow`).
    fn try_grow(&self) {
        if !self.grow_wanted.swap(false, AcqRel) {
            return;
        }
        loop {
            let (need, epoch) = self.locked(|st| (Self::pressure_locked(st), st.epoch));
            let now = self.env.now_ms();
            if !need || (now.wrapping_sub(self.grow_retry.load(Relaxed)) as i32) < 0 {
                return;
            }
            if self.env.gate() {
                self.deny(&self.c.deny_gate, now);
                return;
            }
            // The O(1) total first; the largest-block query walks the heap with its lock held, so it only runs when the total already allows
            // a growth.
            if self.env.free_internal_heap() < CHUNK_BYTES + HEAP_BLOCK_SLACK + self.cfg.floor_free {
                self.deny(&self.c.deny_heap, now);
                return;
            }
            if self.env.largest_free_block() < self.cfg.floor_largest {
                self.deny(&self.c.deny_largest, now);
                return;
            }
            let Some(mem) = self.env.alloc_chunk() else {
                self.deny(&self.c.deny_nomem, now);
                return;
            };
            // The same rule as `ml_adm_slot_alloc_ok()`: this allocation must not be the one that takes the largest free block below what
            // admission needs.
            if self.env.largest_free_block() < self.cfg.floor_largest {
                self.env.free_chunk(mem);
                self.deny(&self.c.deny_largest, now);
                return;
            }
            if self.env.gate() {
                self.env.free_chunk(mem);
                self.deny(&self.c.deny_gate, now);
                return;
            }
            let published = self.locked(|st| {
                if epoch != st.epoch || st.chunks_present >= st.max_chunks {
                    return false;
                }
                for c in 0..MAX_CHUNKS {
                    if st.chunk[c].mem.is_null() {
                        st.chunk[c] = Chunk { mem: mem.as_ptr(), used: 0, why: Why::Reclaim, retiring: false, last_use: now };
                        st.alloc_mask |= st.chunk_mask(c as u32);
                        st.chunks_present += 1;
                        st.chunks_live += 1;
                        self.set_present_locked(st);
                        return true;
                    }
                }
                false
            });
            if !published {
                self.env.free_chunk(mem); // a reclaim started while we allocated
                bump(&self.c.grow_raced);
                return;
            }
            self.grow_backoff.store(0, Relaxed);
            bump(&self.c.grow_events);
        }
    }

    /// Give the elastic memory back now (membership admission): `tinyusb_net_tx_elastic_reclaim`.
    ///
    /// Retires every elastic chunk: idle ones are freed at once, chunks that still hold queued frames stop receiving new frames and are freed
    /// when the last frame in them has been handed to USB (frames in flight are never dropped or freed under the consumer). Waits up to
    /// `wait_ms` for those chunks to drain. Call it AFTER the negotiation token is held (the gate then keeps the worker from growing again)
    /// and BEFORE measuring free heap. Not for the producer or the TinyUSB task: it may sleep.
    ///
    /// Returns the bytes of elastic memory still held when it returns (0 when the whole elastic part is back in the heap).
    pub fn elastic_reclaim(&self, wait_ms: u32) -> usize {
        // (The C reads `max_chunks` without the lock; a plain read of a field the lock protects is a data race in Rust, so it is read under it.)
        if !self.enabled.load(Acquire) || self.max_chunks() == 0 {
            return 0;
        }
        let retired = self.locked(|st| {
            st.epoch = st.epoch.wrapping_add(1);
            self.retire_all_locked(st, Why::Reclaim)
        });
        if retired != 0 {
            bump(&self.c.reclaim_events);
        }
        self.reap();
        // Chunks still holding frames drain at USB speed (23 frames take about 40 ms at 7 Mbit/s).
        let mut waited = 0;
        while waited < wait_ms && self.present_mirror.load(Relaxed) != 0 {
            self.env.delay_ms(1);
            self.locked(|st| self.compact_locked(st));
            self.reap();
            waited += 1;
        }
        self.present_mirror.load(Relaxed) as usize * CHUNK_BYTES
    }

    /// Move the elastic cap at run time, a tuning knob that is not persisted (`tinyusb_net_tx_ring_set_max_chunks`).
    ///
    /// Raising lets the worker grow further; lowering retires chunks above the new cap (frames in them drain first, nothing is dropped).
    ///
    /// # Errors
    ///
    /// [`SetMaxChunksError::NotStarted`] when the ring is stopped, [`SetMaxChunksError::TooMany`] above 12.
    pub fn set_max_chunks(&self, chunks: u32) -> Result<(), SetMaxChunksError> {
        if !self.enabled.load(Acquire) {
            return Err(SetMaxChunksError::NotStarted);
        }
        if chunks as usize > MAX_CHUNKS {
            return Err(SetMaxChunksError::TooMany);
        }
        let retired = self.locked(|st| {
            st.max_chunks = chunks;
            st.epoch = st.epoch.wrapping_add(1); // a growth that allocated against the old cap and publishes after this is discarded
            let mut retired = 0;
            for c in chunks as usize..MAX_CHUNKS {
                if !st.chunk[c].mem.is_null() && !st.chunk[c].retiring {
                    Self::retire_chunk_locked(st, c, Why::Reclaim);
                    retired += 1;
                }
            }
            retired
        });
        if retired != 0 {
            bump(&self.c.reclaim_events);
        }
        self.reap();
        Ok(())
    }

    /// The elastic cap now (`tinyusb_net_tx_ring_max_chunks`).
    #[must_use]
    pub fn max_chunks(&self) -> u32 {
        self.locked(|st| st.max_chunks)
    }

    /// Wake the worker so it re-evaluates the gate and retires idle chunks (`tinyusb_net_tx_elastic_kick`). Never blocks; any task context.
    pub fn elastic_kick(&self) {
        self.env.notify_worker();
    }

    // ------------------------------------------------------------------------------------------------------------------------------
    // link generation
    // ------------------------------------------------------------------------------------------------------------------------------

    /// The first look after the link was up bumps the generation: everything queued so far is stale (`tx_note_link_down`).
    fn note_link_down(&self) {
        if !self.down_seen.swap(true, AcqRel) {
            self.gen_.fetch_add(1, Release);
        }
    }

    /// The USB link went away (detach): frames queued so far are stale and are flushed by the next drain
    /// (`tinyusb_net_tx_ring_link_down`). Any task context; a stopped ring ignores it.
    pub fn link_down(&self) {
        if self.enabled.load(Acquire) {
            self.note_link_down();
            self.env.notify_worker(); // the worker queues a drain, which discards the stale frames
        }
    }

    /// The source of the queued frames changed (the bridge's Wi-Fi link dropped or came back): discard what is queued
    /// (`tinyusb_net_tx_ring_flush`).
    ///
    /// Bumps the link generation (the mechanism a USB detach uses): frames committed before this call are discarded by the next drain, counted
    /// in `flushed_link_down`, and never reach the host; frames committed after it are unaffected. Never blocks, any task context. A frame
    /// being committed concurrently with the call may fall on either side, which is the right answer for a frame that was received while the
    /// link was changing. A stopped ring ignores it.
    pub fn flush(&self) {
        if self.enabled.load(Acquire) {
            self.gen_.fetch_add(1, Release);
            self.env.notify_worker();
        }
    }

    /// The link generation (`s_tx.gen`): the number of USB outages seen plus producer flushes, modulo 2^16.
    #[must_use]
    pub fn generation(&self) -> u16 {
        self.gen_.load(Relaxed)
    }

    // ------------------------------------------------------------------------------------------------------------------------------
    // producer
    // ------------------------------------------------------------------------------------------------------------------------------

    /// Queue a frame for transmission without blocking (`tinyusb_net_tx_ring_send`).
    ///
    /// The frame is copied: the caller keeps ownership in every case. Calls must be serialized by the caller (single producer); a concurrent
    /// call is refused with [`SendError::Busy`]. Never waits for a task, never allocates: it takes the critical section twice (reserve and commit
    /// a slab range) and copies outside it. On `Ok` the frame will be handed to USB exactly once or flushed on link loss.
    ///
    /// # Errors
    ///
    /// See [`SendError`]; each refusal except `NotStarted` and `Busy` is counted.
    pub fn send(&self, frame: &[u8]) -> Result<(), SendError> {
        if !self.enabled.load(Acquire) {
            return Err(SendError::NotStarted);
        }
        let len = frame.len();
        if !(FRAME_MIN..=FRAME_MAX).contains(&len) {
            bump(&self.c.drop_invalid);
            return Err(SendError::InvalidLength);
        }
        if !self.env.usb_ready() {
            self.note_link_down();
            bump(&self.c.drop_down);
            if self.pm_want.load(Relaxed) {
                self.env.notify_worker(); // stale frames are queued: let the worker flush them and drop the PM lock
            }
            return Err(SendError::LinkDown);
        }
        self.down_seen.store(false, Relaxed);
        if self.producing.swap(true, Acquire) {
            return Err(SendError::Busy);
        }
        let _producing = Entered(&self.producing);
        let need = (REC_HDR + align4(len)) as u32;
        let reserved = self.locked(|st| {
            let r = self.reserve_locked(st, need);
            if Self::pressure_locked(st) {
                self.grow_wanted.store(true, Relaxed);
            }
            r.map(|(slab, off)| (slab, st.slab_ptr(slab).wrapping_add(off as usize)))
        });
        let Some((slab, dst)) = reserved else {
            bump(&self.c.drop_full);
            self.env.notify_worker(); // pressure: let the worker grow (nothing else will wake it)
            return Err(SendError::Full);
        };
        // SAFETY: `dst` is the start of the range `reserve` just gave this producer: `need >= REC_HDR + len` bytes inside a slab that is in
        // the FIFO (so its memory is allocated and cannot be freed), above `fill` and `resv`-protected, so the consumer and the flush never
        // read or write it until `commit` publishes it; `_producing` makes this the only producer; `frame` is the caller's, so it cannot
        // overlap a slab.
        unsafe { mem::write_record(dst, len as u16, self.gen_.load(Relaxed), frame) };
        let now_us = self.env.now_us(); // outside the section: a register read, but not ours to hold it for
        self.locked(|st| self.commit_locked(st, slab, need, now_us));
        self.c.enq_frames.fetch_add(1, Relaxed);
        self.c.enq_bytes.fetch_add(len as u32, Relaxed);
        self.env.notify_worker(); // never blocks
        Ok(())
    }

    // ------------------------------------------------------------------------------------------------------------------------------
    // consumer
    // ------------------------------------------------------------------------------------------------------------------------------

    /// Hand every queued frame the NTBs can take to USB, discarding stale ones (`tx_drain`). TinyUSB task only; idempotent: a duplicate call
    /// finds the ring drained. A call that overlaps another drain returns at once (the contract is a single consumer).
    pub fn drain(&self) {
        if self.draining.swap(true, Acquire) {
            return;
        }
        let _draining = Entered(&self.draining);
        let ready = self.env.usb_ready();
        let mut notify = false;
        let mut handed = 0u32;
        loop {
            let Some(r) = self.locked(|st| self.peek_locked(st)) else {
                self.blocked.store(false, Relaxed);
                break;
            };
            if usize::from(r.len) < FRAME_MIN || usize::from(r.len) > FRAME_MAX {
                // Cannot happen (the producer validates); never read past a damaged record.
                let n = self.locked(|st| {
                    st.reading = -1;
                    self.discard_locked(st)
                });
                self.c.flushed.fetch_add(n, Relaxed);
                notify = true;
                continue;
            }
            // The generation was stored before the record was committed (lock): never newer than the one seen here.
            let stale = !ready || r.gen_ != self.gen_.load(Acquire);
            if stale {
                bump(&self.c.flushed);
            } else {
                if !self.env.can_xmit(r.len) {
                    // every NTB is in flight; keep the frame, the next IN completion drains again
                    self.locked(|st| st.reading = -1);
                    if !self.blocked.swap(true, Relaxed) {
                        bump(&self.c.blocked_events);
                    }
                    break;
                }
                // SAFETY: `r` was peeked and not yet advanced: the record is committed and ours until `advance_locked`; a concurrent flush only
                // moves `rd`, it never writes the bytes, and `reading` keeps its slab in the FIFO (compaction, discard and `drop_front` skip
                // it), so neither the slab nor its chunk is released or reused; `len` was validated above.
                let payload = unsafe { mem::payload(r.at, usize::from(r.len)) };
                self.env.xmit(payload); // copies synchronously, outside the lock: the slab is still ours
                self.c.sent_frames.fetch_add(1, Relaxed);
                self.c.sent_bytes.fetch_add(u32::from(r.len), Relaxed);
                handed += 1;
            }
            let now_us = self.env.now_us();
            let emptied = self.locked(|st| self.advance_locked(st, &r, !stale, now_us));
            notify |= emptied;
        }
        if handed != 0 {
            bump(&self.c.drains_sent[handed.min(5) as usize - 1]);
        }
        if notify || self.reap_pending.load(Relaxed) {
            self.env.notify_worker(); // queue became empty (drop the PM lock) or a retiring chunk emptied
        }
    }

    /// The deferred callback the worker queued with `RingEnv::defer_drain` (`do_drain`). TinyUSB task only.
    pub fn do_drain(&self) {
        self.drain_pending.store(false, SeqCst); // before reading the queue: a frame committed after this point makes the worker queue another call
        self.drain();
    }

    /// An IN transfer completed (`__wrap_netd_xfer_cb`, IN endpoint branch, after the real class driver returned the NTB): record the
    /// evidence and refill. `xferred_bytes` is the transfer's length, 0 for a zero-length packet. TinyUSB task only; ignored when stopped.
    pub fn on_in_complete(&self, xferred_bytes: u32) {
        if !self.enabled.load(Acquire) {
            return;
        }
        let now_us = self.env.now_us(); // only with the ring on: the legacy bridge's IN path makes no extra call
        bump(&self.c.xfer_events);
        if xferred_bytes != 0 {
            bump(&self.c.ntb_xfers);
            self.c.ntb_bytes.fetch_add(xferred_bytes, Relaxed);
            if xferred_bytes > self.c.ntb_max_bytes.load(Relaxed) {
                self.c.ntb_max_bytes.store(xferred_bytes, Relaxed);
            }
        } else {
            bump(&self.c.ntb_zlp);
        }
        if self.pm_want.load(Relaxed) {
            // frames are queued: this gap is the bus, not idleness
            let last = self.last_comp_us.load(Relaxed);
            if last != 0 {
                let gap = now_us.wrapping_sub(last);
                bump(&self.c.gap_count);
                self.c.gap_us_sum.fetch_add(gap, Relaxed);
                if gap > self.c.gap_us_max.load(Relaxed) {
                    self.c.gap_us_max.store(gap, Relaxed);
                }
                let bucket = match gap {
                    0..1000 => 0,
                    1000..2000 => 1,
                    2000..4000 => 2,
                    4000..8000 => 3,
                    _ => 4,
                };
                bump(&self.c.gap_hist[bucket]);
            }
            self.last_comp_us.store(if now_us != 0 { now_us } else { 1 }, Relaxed);
        } else {
            self.last_comp_us.store(0, Relaxed);
        }
        self.drain();
    }

    /// The last drain stopped because every NTB was in flight (`s_tx.blocked`).
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.blocked.load(Relaxed)
    }

    // ------------------------------------------------------------------------------------------------------------------------------
    // worker
    // ------------------------------------------------------------------------------------------------------------------------------

    /// The worker is the only context that acquires or releases the CPU-frequency hold, so the pair cannot interleave. Both edges of
    /// `pm_want` notify it (`tx_pm_reconcile`).
    fn pm_reconcile(&self) {
        if !self.cfg.pm {
            return; // no power management in this build or caller: nothing to hold
        }
        let want = self.pm_want.load(Acquire);
        let held = self.pm_held.load(Relaxed);
        if want && !held {
            self.env.pm_begin();
            self.pm_held.store(true, Relaxed);
            bump(&self.c.pm_acquired);
        } else if !want && held {
            self.env.pm_end();
            self.pm_held.store(false, Relaxed);
            bump(&self.c.pm_released);
        }
    }

    /// How long the worker waits for a notification before its next step (`tx_worker_wait`).
    #[must_use]
    pub fn worker_wait(&self) -> Wait {
        if self.pm_want.load(Relaxed) {
            return Wait::Ms(LINK_POLL_MS); // frames queued: also notice a link that went away silently
        }
        if self.present_mirror.load(Relaxed) != 0 {
            return Wait::Ms(HOUSEKEEP_MS); // elastic chunks exist: idle check
        }
        Wait::Forever // nothing to do until a producer publishes
    }

    /// One worker wake-up, everything `tx_worker_step` does after its `ulTaskNotifyTake`: reconcile the PM hold, relay a drain request to the
    /// TinyUSB task, housekeeping (retire when the gate is closed, one idle free, reap), growth, and the PM hold again. Returns how long to wait
    /// for the next notification, i.e. `worker_wait()` after this step.
    pub fn worker_step(&self) -> Wait {
        self.pm_reconcile();
        if self.pm_want.load(Acquire) {
            if !self.env.usb_ready() {
                self.note_link_down(); // silent link loss: the drain below discards what was queued
            }
            if !self.drain_pending.swap(true, AcqRel) {
                self.env.defer_drain(); // may wait for TinyUSB; we hold no lock
            }
        }
        // Growth (the largest-block walk, the allocation, the gate's mutex) runs below the producers: the relay above must outrank them, this
        // must not delay the TinyUSB task or the forwarding task. Only a pass that is about to grow demotes. Housekeeping (retire, one idle free
        // per pass) stays at the relay priority: it is a few microseconds inside a critical section, which no priority changes, and a demotion
        // costs more than that (ADR 0022). An idle pass with elastic chunks present is therefore not demoted.
        let heap_work = self.cfg.work_priority != 0 && self.cfg.work_priority != self.cfg.priority && self.grow_wanted.load(Relaxed);
        self.housekeeping();
        if heap_work {
            self.env.set_worker_priority(self.cfg.work_priority);
            bump(&self.c.demotions);
        }
        self.try_grow();
        if heap_work {
            self.env.set_worker_priority(self.cfg.priority);
        }
        self.pm_reconcile(); // a drain that ran meanwhile may have emptied the queue
        self.worker_wait()
    }

    // ------------------------------------------------------------------------------------------------------------------------------
    // teardown and statistics
    // ------------------------------------------------------------------------------------------------------------------------------

    /// Stop accepting frames, drop what is queued, give the elastic chunks back and let the worker release the PM hold: the ring's part of
    /// `tinyusb_net_deinit`. The permanent slabs and the worker live on; [`restart`](Self::restart) re-enables the ring.
    pub fn deinit(&self) {
        self.enabled.store(false, SeqCst);
        let n = self.locked(|st| {
            let n = self.discard_locked(st);
            st.epoch = st.epoch.wrapping_add(1); // a growth that allocated before this and publishes after it is discarded
            self.retire_all_locked(st, Why::Reclaim);
            n
        });
        self.c.flushed.fetch_add(n, Relaxed);
        self.reap();
        self.env.notify_worker();
    }

    /// Snapshot the counters (`tinyusb_net_tx_ring_stats`).
    #[must_use]
    pub fn stats(&self) -> TxStats {
        let (cold_n, cold_sum, cold_max, chunks, present, hw_bytes, hw_slabs, max_chunks_now, base_slabs) = self.locked(|st| {
            (
                st.cold_starts,
                st.cold_us_sum,
                st.cold_us_max,
                st.chunks_live,
                st.chunks_present,
                st.high_water_bytes,
                st.high_water_slabs,
                st.max_chunks,
                st.base_slabs,
            )
        });
        let slab = SLAB_BYTES as u32;
        let chunk_slabs = CHUNK_SLABS as u32;
        let load = |a: &AtomicU32| a.load(Relaxed);
        let c = &self.c;
        TxStats {
            ring_bytes: (base_slabs + chunks * chunk_slabs) * slab,
            base_bytes: base_slabs * slab,
            max_bytes: (base_slabs + max_chunks_now * chunk_slabs) * slab,
            elastic_held_bytes: present * CHUNK_BYTES as u32,
            chunks,
            high_water_bytes: hw_bytes,
            high_water_slabs: hw_slabs,
            enqueued_frames: load(&c.enq_frames),
            enqueued_bytes: load(&c.enq_bytes),
            sent_frames: load(&c.sent_frames),
            sent_bytes: load(&c.sent_bytes),
            dropped_full: load(&c.drop_full),
            dropped_link_down: load(&c.drop_down),
            dropped_invalid: load(&c.drop_invalid),
            flushed_link_down: load(&c.flushed),
            ntb_blocked: load(&c.blocked_events),
            xfer_events: load(&c.xfer_events),
            worker_stack_free: self.env.worker_stack_free(),
            grow_events: load(&c.grow_events),
            shrink_events: load(&c.shrink_events),
            reclaim_events: load(&c.reclaim_events),
            reclaimed_chunks: load(&c.reclaimed_chunks),
            grow_denied_gate: load(&c.deny_gate),
            grow_denied_heap: load(&c.deny_heap),
            grow_denied_largest: load(&c.deny_largest),
            grow_denied_nomem: load(&c.deny_nomem),
            grow_raced: load(&c.grow_raced),
            pm_acquired: load(&c.pm_acquired),
            pm_released: load(&c.pm_released),
            pm_held: u32::from(self.pm_held.load(Relaxed)),
            ntb_xfers: load(&c.ntb_xfers),
            ntb_zlp: load(&c.ntb_zlp),
            ntb_bytes: load(&c.ntb_bytes),
            ntb_max_bytes: load(&c.ntb_max_bytes),
            drains_sent: core::array::from_fn(|i| load(&c.drains_sent[i])),
            gap_count: load(&c.gap_count),
            gap_us_sum: load(&c.gap_us_sum),
            gap_us_max: load(&c.gap_us_max),
            gap_hist: core::array::from_fn(|i| load(&c.gap_hist[i])),
            cold_starts: cold_n,
            cold_us_sum: cold_sum,
            cold_us_max: cold_max,
            worker_demotions: load(&c.demotions),
        }
    }
}

/// Test-only view of the flags that live outside the lock.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Probe {
    pub(crate) pm_want: bool,
    pub(crate) present_mirror: u32,
    pub(crate) reap_pending: bool,
    pub(crate) grow_wanted: bool,
}

#[cfg(test)]
impl<E: RingEnv> Ring<E> {
    pub(crate) fn probe(&self) -> Probe {
        Probe {
            pm_want: self.pm_want.load(Relaxed),
            present_mirror: self.present_mirror.load(Relaxed),
            reap_pending: self.reap_pending.load(Relaxed),
            grow_wanted: self.grow_wanted.load(Relaxed),
        }
    }
}

impl<E: RingEnv> Drop for Ring<E> {
    /// Give back every chunk still allocated. (The C ring lives for the life of the firmware and never frees; the host tests build many.)
    fn drop(&mut self) {
        let st = self.state.get_mut();
        for ch in &mut st.chunk {
            if let Some(chunk) = NonNull::new(ch.mem) {
                self.env.free_chunk(chunk);
            }
            *ch = Chunk::EMPTY;
        }
    }
}
