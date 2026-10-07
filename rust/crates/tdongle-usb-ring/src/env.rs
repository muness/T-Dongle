//! The environment the ring runs in: everything that is hardware or operating system in the C original, behind one trait.
//!
//! C origin: the FreeRTOS, TinyUSB and ESP-IDF calls made from the ring section of `components/esp_tinyusb/tinyusb_net.c`
//! (`portENTER_CRITICAL`, `esp_timer_get_time`, `xTaskGetTickCount`, `tud_ready`, `tud_network_can_xmit`, `tud_network_xmit`,
//! `heap_caps_malloc`/`heap_caps_free`, `heap_caps_get_free_size`, `heap_caps_get_largest_free_block`, `xTaskNotifyGive`, `usbd_defer_func`,
//! `tinyusb_net_tx_config_t::{gate, pm_begin, pm_end}`, `vTaskDelay`, `vTaskPrioritySet`, `uxTaskGetStackHighWaterMark`).

use core::ptr::NonNull;

/// What the ring needs from the platform.
///
/// # Safety
///
/// The ring keeps all of its bookkeeping in plain memory that is protected only by [`lock`](Self::lock), and it hands out and reads memory
/// that [`alloc_chunk`](Self::alloc_chunk) returned. An implementation must therefore uphold, for as long as the ring exists:
///
/// * `lock` / `unlock` form a mutual-exclusion lock across **all** contexts that call into the ring (tasks on both cores and, on the target,
///   interrupts that can preempt them): between a `lock` that returned and the matching `unlock`, no other context returns from `lock`.
///   The ring never nests it and never calls any other method of this trait while holding it, except [`now_ms`](Self::now_ms).
/// * `alloc_chunk` returns either `None` or a pointer to [`CHUNK_BYTES`](crate::CHUNK_BYTES) bytes that are valid for reads and writes,
///   not aliased by anything else, and stay valid until the same pointer is passed to `free_chunk`.
///
/// Every method takes `&self` and may be called from any task concurrently (the ring is shared between the producer, the TinyUSB task and
/// the worker), so implementations are `Sync` in practice; [`Ring`](crate::Ring) is `Sync` exactly when its environment is.
pub unsafe trait RingEnv {
    // ---- the lock ----

    /// Enter the ring's critical section (`portENTER_CRITICAL(&s_tx_mux)`). Must not be reentrant; the ring never nests it.
    fn lock(&self);
    /// Leave the critical section (`portEXIT_CRITICAL`). Called exactly once per `lock`, by the same context.
    fn unlock(&self);

    // ---- clocks ----

    /// Microsecond clock (`esp_timer_get_time`), truncated to 32 bits: wraps after 71.6 minutes, every use is a wrapping difference.
    /// Never called with the lock held.
    fn now_us(&self) -> u32;
    /// Millisecond tick clock (`xTaskGetTickCount() * portTICK_PERIOD_MS`), wrapping `u32`. The C counts FreeRTOS ticks; the ring is written
    /// in milliseconds, which is identical at the 1 ms tick of the host tests and exact at the firmware's 10 ms tick up to that granularity.
    /// Must be callable with the lock held (the consumer stamps a chunk's `last_use` inside its critical section): a register or counter read.
    fn now_ms(&self) -> u32;

    // ---- USB (TinyUSB) ----

    /// The USB link is up and configured (`tud_ready`). Never called with the lock held.
    fn usb_ready(&self) -> bool;
    /// A free NTB can take a frame of `len` bytes right now (`tud_network_can_xmit`). TinyUSB task only.
    fn can_xmit(&self, len: u16) -> bool;
    /// Hand one frame to the NTB (`tud_network_xmit`). The implementation must copy `frame` before it returns: the slab behind it is
    /// released as soon as the call comes back. TinyUSB task only, no lock held.
    fn xmit(&self, frame: &[u8]);
    /// Ask the TinyUSB task to call [`Ring::do_drain`](crate::Ring::do_drain) (`usbd_defer_func(do_drain, NULL, false)`). May block on
    /// TinyUSB's event queue; it is called from the worker only, which holds no lock.
    fn defer_drain(&self);

    // ---- heap ----

    /// Allocate one elastic chunk: [`CHUNK_BYTES`](crate::CHUNK_BYTES) bytes of internal, byte-addressable memory
    /// (`heap_caps_malloc(TX_CHUNK_BYTES, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)`), or `None` when the allocator refuses.
    /// Worker only, never with the lock held.
    fn alloc_chunk(&self) -> Option<NonNull<u8>>;
    /// Give a chunk back (`heap_caps_free`). `chunk` is a pointer `alloc_chunk` returned and has not freed yet. Never with the lock held.
    fn free_chunk(&self, chunk: NonNull<u8>);
    /// Total free internal heap (`heap_caps_get_free_size(MALLOC_CAP_INTERNAL)`): O(1).
    fn free_internal_heap(&self) -> usize;
    /// Largest free internal block (`heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)`). Walks the heap with its lock held: the ring
    /// asks only when the total already allows a growth.
    fn largest_free_block(&self) -> usize;

    // ---- tasks ----

    /// Wake the worker task (`xTaskNotifyGive(s_tx.worker)`): never blocks, any task context, coalescing. The worker's loop is
    /// `wait = ring.worker_wait(); loop { notify_take(wait); wait = ring.worker_step(); }`.
    fn notify_worker(&self);
    /// Sleep `ms` milliseconds (`vTaskDelay(1)` per millisecond in `tinyusb_net_tx_elastic_reclaim`). Never with the lock held and never from
    /// the producer or the TinyUSB task.
    fn delay_ms(&self, ms: u32);
    /// Set the worker's own task priority (`vTaskPrioritySet(NULL, prio)`), called around a growth pass when
    /// [`Config::work_priority`](crate::Config::work_priority) differs from [`Config::priority`](crate::Config::priority). Default: nothing.
    fn set_worker_priority(&self, _priority: u32) {}
    /// Worker stack high-water mark, bytes never used (`uxTaskGetStackHighWaterMark`), for the statistics. Default: 0.
    fn worker_stack_free(&self) -> u32 {
        0
    }

    // ---- policy ----

    /// True while growth is forbidden and idle chunks must go: a negotiation or admission is in progress
    /// (`tinyusb_net_tx_config_t::gate`; the bridge has none and returns `false`). Worker only; may take a mutex.
    fn gate(&self) -> bool;

    // ---- power management ----

    /// Begin the CPU-frequency hold (`tinyusb_net_tx_config_t::pm_begin`). Called from the worker only, strictly alternating with
    /// [`pm_end`](Self::pm_end), with no lock of the ring held. Only called when [`Config::pm`](crate::Config::pm) is set.
    fn pm_begin(&self);
    /// End the hold (`pm_end`). Same rules as [`pm_begin`](Self::pm_begin).
    fn pm_end(&self);
}
