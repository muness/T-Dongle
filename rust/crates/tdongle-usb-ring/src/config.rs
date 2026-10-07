//! Configuration, errors and the statistics snapshot.
//!
//! C origin: `tinyusb_net_tx_config_t` and `tinyusb_net_tx_stats_t` in `components/esp_tinyusb/include/tinyusb_net.h`.

use crate::consts::{MAX_BASE_SLABS, MAX_CHUNKS};

/// Transmit-ring and elastic-buffer configuration (`tinyusb_net_tx_config_t`).
///
/// Capacity is `base_frames` full frames that are always present plus up to `max_chunks` elastic chunks of
/// [`CHUNK_SLABS`](crate::CHUNK_SLABS) frames each, allocated on demand by the worker task (never by the producer) and released when idle or
/// when admission needs the heap. What the C passes as function pointers (`gate`, `pm_begin`, `pm_end`) is in [`RingEnv`](crate::RingEnv);
/// the worker's task parameters other than its priorities (core, stack) belong to the firmware that spawns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Permanent slabs, `2..=MAX_BASE_SLABS` (`base_frames`).
    pub base_frames: u32,
    /// Elastic chunks, `0..=MAX_CHUNKS`; 0 is a fixed ring (`max_chunks`).
    pub max_chunks: u32,
    /// Worker task priority: the relay (notify, defer) runs here (`priority`).
    pub priority: u32,
    /// Priority for a growth pass (heap walks); 0: the same as `priority`. Retire and idle shrink stay at `priority` (`work_priority`).
    pub work_priority: u32,
    /// Free internal heap that must remain after a growth, bytes (`floor_free`).
    pub floor_free: usize,
    /// Largest free internal block that must exist before AND after a growth, bytes (`floor_largest`).
    pub floor_largest: usize,
    /// A chunk unused this long is freed, one chunk per housekeeping pass, highest first; 0: 2000 ms (`idle_ms`).
    pub idle_ms: u32,
    /// The environment supplies a CPU-frequency hold (`pm_begin`/`pm_end` both non-NULL in the C). `false`: no hold, the reconcile does nothing.
    pub pm: bool,
}

impl Config {
    /// The transparent bridge's ring (ADR 0023): 8 permanent slabs and at most 10 chunks, so at most 28 slabs. The floors and priorities are
    /// the firmware's to set.
    #[must_use]
    pub const fn bridge(priority: u32, floor_free: usize, floor_largest: usize) -> Self {
        Self {
            base_frames: crate::BRIDGE_BASE_SLABS as u32,
            max_chunks: crate::BRIDGE_MAX_CHUNKS as u32,
            priority,
            work_priority: 0,
            floor_free,
            floor_largest,
            idle_ms: 0,
            pm: true,
        }
    }

    /// The range checks of `tinyusb_net_tx_ring_start`: `base_frames` in `2..=8`, `max_chunks` at most 12.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the offending field.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.base_frames < 2 || self.base_frames > MAX_BASE_SLABS as u32 {
            return Err(ConfigError::BaseFrames);
        }
        if self.max_chunks > MAX_CHUNKS as u32 {
            return Err(ConfigError::MaxChunks);
        }
        Ok(())
    }
}

/// Why a [`Config`] was refused (`ESP_ERR_INVALID_ARG` from `tinyusb_net_tx_ring_start`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `base_frames` outside `2..=8`.
    BaseFrames,
    /// `max_chunks` above 12.
    MaxChunks,
    /// The base memory handed to [`Ring::new`](crate::Ring::new) holds fewer than `base_frames * SLAB_BYTES` bytes. (Rust-only: the C
    /// allocated the base itself.)
    BaseTooSmall,
}

/// Why [`Ring::restart`](crate::Ring::restart) refused (the two failing branches of the second `tinyusb_net_tx_ring_start`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartError {
    /// The configuration is out of range (`ESP_ERR_INVALID_ARG`).
    Invalid(ConfigError),
    /// The ring was started with another configuration (`ESP_ERR_INVALID_STATE`, "TX ring already configured differently").
    Mismatch,
}

/// Why [`Ring::send`](crate::Ring::send) did not queue a frame (the `esp_err_t` of `tinyusb_net_tx_ring_send`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The ring is not started or has been stopped (`ESP_ERR_INVALID_STATE`); nothing is counted.
    NotStarted,
    /// Length outside `14..=1518` (`ESP_ERR_INVALID_ARG`); counted in `dropped_invalid`.
    InvalidLength,
    /// USB is not ready (`ESP_ERR_INVALID_STATE`); counted in `dropped_link_down`.
    LinkDown,
    /// No free slab and no room in the open one: backpressure, tail drop (`ESP_ERR_NO_MEM`); counted in `dropped_full`.
    Full,
    /// Another `send` was still running: the contract is a single serialized producer (as in the C, where this was undefined behaviour).
    /// Nothing is counted and nothing is queued. Rust-only: it keeps a misuse of the safe API from becoming a data race on a slab.
    Busy,
}

/// Why [`Ring::set_max_chunks`](crate::Ring::set_max_chunks) refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetMaxChunksError {
    /// The ring is not started (`ESP_ERR_INVALID_STATE`).
    NotStarted,
    /// More than 12 chunks (`ESP_ERR_INVALID_ARG`).
    TooMany,
}

/// How long the worker should wait for a notification before calling [`Ring::worker_step`](crate::Ring::worker_step) again (`tx_worker_wait`'s `TickType_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// `portMAX_DELAY`: nothing to do until a producer publishes.
    Forever,
    /// A timeout in milliseconds: 200 while frames are queued (link poll), 500 while elastic chunks exist (idle check).
    Ms(u32),
}

/// Transmit-ring counters (`tinyusb_net_tx_stats_t`), field for field. Monotonic except the sizes, `chunks` and `pm_held`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxStats {
    /// Capacity now: permanent slabs plus live elastic chunks, bytes.
    pub ring_bytes: u32,
    /// Permanent capacity (always allocated), bytes.
    pub base_bytes: u32,
    /// Capacity with every elastic chunk present: the cap, bytes.
    pub max_bytes: u32,
    /// Heap held by elastic chunks, including chunks still draining before they are freed, bytes.
    pub elastic_held_bytes: u32,
    /// Live elastic chunks (not counting ones being retired).
    pub chunks: u32,
    /// Most record bytes ever queued at once.
    pub high_water_bytes: u32,
    /// Most slabs ever in the queue at once.
    pub high_water_slabs: u32,
    /// Frames accepted into the ring.
    pub enqueued_frames: u32,
    /// Bytes of those frames (payload, without record overhead).
    pub enqueued_bytes: u32,
    /// Frames handed to an NTB (each exactly once).
    pub sent_frames: u32,
    /// Bytes of those frames.
    pub sent_bytes: u32,
    /// No free slab and no room in the open one: backpressure, frame dropped.
    pub dropped_full: u32,
    /// Refused because USB was not ready.
    pub dropped_link_down: u32,
    /// Length outside 14..1518.
    pub dropped_invalid: u32,
    /// Queued frames discarded when USB went away (or the producer flushed).
    pub flushed_link_down: u32,
    /// Times a drain stopped with every NTB in flight.
    pub ntb_blocked: u32,
    /// IN transfer completions that drained the ring (no polling).
    pub xfer_events: u32,
    /// Worker stack high-water mark, bytes never used.
    pub worker_stack_free: u32,
    /// Elastic chunks added.
    pub grow_events: u32,
    /// Elastic chunks freed after sitting idle.
    pub shrink_events: u32,
    /// Times chunks were retired because admission/negotiation needed the heap.
    pub reclaim_events: u32,
    /// Chunks freed by those reclaims.
    pub reclaimed_chunks: u32,
    /// Growth refused: admission or a negotiation is in progress.
    pub grow_denied_gate: u32,
    /// Growth refused: free heap would fall below the floor.
    pub grow_denied_heap: u32,
    /// Growth refused: largest free block below the floor, before or after the allocation.
    pub grow_denied_largest: u32,
    /// Growth refused: the allocator returned nothing.
    pub grow_denied_nomem: u32,
    /// A chunk was allocated and discarded because a reclaim started meanwhile.
    pub grow_raced: u32,
    /// CPU-frequency hold begins.
    pub pm_acquired: u32,
    /// CPU-frequency hold ends.
    pub pm_released: u32,
    /// 1 while the hold is in place.
    pub pm_held: u32,
    /// IN completions that carried data (one NTB each).
    pub ntb_xfers: u32,
    /// Zero-length IN completions (ZLP after an NTB that was a multiple of 64 B).
    pub ntb_zlp: u32,
    /// Bytes carried by those NTBs, summed.
    pub ntb_bytes: u32,
    /// Largest NTB completed.
    pub ntb_max_bytes: u32,
    /// Drain passes that handed 1, 2, 3, 4, 5 or more frames to the NTBs.
    pub drains_sent: [u32; 5],
    /// Completions with a backlog, measured since the previous completion.
    pub gap_count: u32,
    /// Sum of those gaps, microseconds.
    pub gap_us_sum: u32,
    /// Largest gap, microseconds.
    pub gap_us_max: u32,
    /// Gap histogram: < 1 ms, < 2 ms, < 4 ms, < 8 ms, >= 8 ms.
    pub gap_hist: [u32; 5],
    /// Empty to non-empty transitions that were later handed to an NTB.
    pub cold_starts: u32,
    /// Commit of the first frame to its hand-over, summed: worker wake + deferral + TinyUSB task, microseconds.
    pub cold_us_sum: u32,
    /// Largest such wait, microseconds.
    pub cold_us_max: u32,
    /// Times the worker ran heap work at `work_priority`.
    pub worker_demotions: u32,
}
