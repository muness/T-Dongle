//! The environment of `tdongle-usb-ring` and its worker task: the Wi-Fi -> host transmit ring (`tinyusb_net_tx_ring_*`).

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use std::sync::OnceLock;

use esp_idf_svc::hal::cpu::Core;
use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
use esp_idf_svc::sys;
use tdongle_usb_ring::{Config, Ring, RingEnv, TxStats, Wait};

use super::prio;
use crate::board::{USB_TX_FLOOR_FREE, USB_TX_FLOOR_LARGEST, USB_TX_WORKER_STACK};
use crate::sys::critical::Mux;
use crate::sys::task::{Notified, WAIT_FOREVER, ms_to_ticks, notify_take};
use crate::sys::{heap, now_us};

/// `tinyusb_net_tx_config_t`'s hardware half for the ring: the one critical section, the heap, TinyUSB, the worker's wake-up, the CPU clock hold.
#[derive(Debug)]
pub struct UsbRingEnv {
    mux: Mux,
    worker: Notified,
}

impl UsbRingEnv {
    const fn new() -> Self {
        Self { mux: Mux::new(), worker: Notified::new() }
    }
}

// SAFETY: see the trait's contract. `lock`/`unlock` are the ESP-IDF critical section (a spinlock that masks interrupts on the calling core),
// which excludes every task on both cores and every interrupt that could call into the ring; `alloc_chunk` returns `CHUNK_BYTES` of internal
// heap from `heap_caps_malloc`, exclusively ours until `free_chunk`.
unsafe impl RingEnv for UsbRingEnv {
    fn lock(&self) {
        self.mux.lock();
    }

    fn unlock(&self) {
        self.mux.unlock();
    }

    fn now_us(&self) -> u32 {
        now_us()
    }

    fn now_ms(&self) -> u32 {
        // xTaskGetTickCount() * portTICK_PERIOD_MS: a counter read, callable inside the critical section.
        // SAFETY: reads the tick count; no preconditions.
        unsafe { sys::xTaskGetTickCount() }.wrapping_mul(1000 / sys::configTICK_RATE_HZ)
    }

    fn usb_ready(&self) -> bool {
        super::task::ready()
    }

    fn can_xmit(&self, len: u16) -> bool {
        // SAFETY: TinyUSB task only (the ring calls this from `drain`).
        unsafe { sys::tud_network_can_xmit(len) }
    }

    fn xmit(&self, frame: &[u8]) {
        // SAFETY: TinyUSB task only. `tud_network_xmit` calls `tud_network_xmit_cb` synchronously, which copies `frame.len()` bytes from the
        // pointer into the NTB, so the slab behind `frame` is not needed after this returns. The pointer is only read through.
        unsafe { sys::tud_network_xmit(frame.as_ptr().cast_mut().cast(), frame.len() as u16) };
    }

    fn defer_drain(&self) {
        // SAFETY: `do_drain` is a valid TinyUSB task function; no context. Called from the worker, which holds no lock and may wait for the
        // TinyUSB event queue.
        unsafe { sys::usbd_defer_func(Some(do_drain), core::ptr::null_mut(), false) };
    }

    fn alloc_chunk(&self) -> Option<NonNull<u8>> {
        heap::alloc_internal(tdongle_usb_ring::CHUNK_BYTES)
    }

    fn free_chunk(&self, chunk: NonNull<u8>) {
        // SAFETY: the ring only frees pointers `alloc_chunk` returned, once.
        unsafe { heap::free_internal_block(chunk) }
    }

    fn free_internal_heap(&self) -> usize {
        heap::free_internal()
    }

    fn largest_free_block(&self) -> usize {
        heap::largest_free_block()
    }

    fn notify_worker(&self) {
        self.worker.give();
    }

    fn delay_ms(&self, ms: u32) {
        std::thread::sleep(std::time::Duration::from_millis(u64::from(ms)));
    }

    fn set_worker_priority(&self, priority: u32) {
        crate::sys::task::set_current_priority(priority);
    }

    fn worker_stack_free(&self) -> u32 {
        self.worker.stack_free()
    }

    fn gate(&self) -> bool {
        false // the bridge has no negotiation to yield to
    }

    fn pm_begin(&self) {
        crate::pm::usb_tx_begin();
    }

    fn pm_end(&self) {
        crate::pm::usb_tx_end();
    }
}

extern "C" fn do_drain(_context: *mut core::ffi::c_void) {
    if let Some(ring) = RING.get() {
        ring.do_drain();
    }
}

/// The permanent slab memory (8 x 1,524 B), 4-byte aligned: ring records are `[len:2][gen:2][payload padded to 4]`.
#[repr(align(4))]
struct Base(UnsafeCell<[u8; tdongle_usb_ring::BRIDGE_BASE_SLABS * tdongle_usb_ring::SLAB_BYTES]>);

// SAFETY: handed to the ring once (`start`) as its exclusive permanent memory; nothing else touches it.
unsafe impl Sync for Base {}

static BASE: Base = Base(UnsafeCell::new([0; tdongle_usb_ring::BRIDGE_BASE_SLABS * tdongle_usb_ring::SLAB_BYTES]));

static RING: OnceLock<Ring<UsbRingEnv>> = OnceLock::new();

/// Create the ring over its permanent memory and start its worker (`tinyusb_net_tx_ring_start`). Once, after `usb::start`, before Wi-Fi starts.
///
/// # Errors
/// The configuration was refused or the worker could not be spawned.
pub fn start() -> Result<(), &'static str> {
    // SAFETY: `BASE` is a static used by nothing else, and `start` runs once (guarded by the OnceLock below).
    let base: NonNull<u8> = unsafe { NonNull::new_unchecked(BASE.0.get().cast()) };
    let config = Config { work_priority: prio::USB_TX_WORK, ..Config::bridge(prio::USB_TX, USB_TX_FLOOR_FREE, USB_TX_FLOOR_LARGEST) };
    // SAFETY: `base` is valid for `base_frames * SLAB_BYTES` bytes (the static is exactly that for the bridge's configuration), exclusively
    // ours, and 'static.
    let ring = unsafe { Ring::new_with_base(UsbRingEnv::new(), config, base) }.map_err(|_| "the transmit ring configuration was refused")?;
    if RING.set(ring).is_err() {
        return Err("the transmit ring was started twice");
    }
    ThreadSpawnConfiguration {
        name: Some(c"usb_txq"),
        stack_size: USB_TX_WORKER_STACK,
        priority: prio::USB_TX as u8,
        pin_to_core: Some(Core::Core1),
        ..Default::default()
    }
    .set()
    .map_err(|_| "could not configure the worker")?;
    let spawned = std::thread::Builder::new().name("usb_txq".into()).stack_size(USB_TX_WORKER_STACK).spawn(worker);
    crate::sys::reset_thread_spawn_defaults();
    spawned.map_err(|_| "could not start the transmit ring worker")?;
    Ok(())
}

/// The ring's worker task: `loop { notify_take(wait); wait = ring.worker_step(); }`.
fn worker() {
    let Some(ring) = RING.get() else { return };
    ring.env().worker.register_current_task();
    let mut wait = ring.worker_wait();
    loop {
        let ticks = match wait {
            Wait::Forever => WAIT_FOREVER,
            Wait::Ms(ms) => ms_to_ticks(ms),
        };
        notify_take(ticks);
        wait = ring.worker_step();
    }
}

/// Whether the ring is started and accepting frames (`s_tx.enabled`).
pub fn enabled() -> bool {
    RING.get().is_some_and(Ring::is_enabled)
}

/// `tinyusb_net_tx_ring_send`: one frame from the Wi-Fi task, never blocking.
pub fn send(frame: &[u8]) -> Result<(), tdongle_usb_ring::SendError> {
    match RING.get() {
        Some(ring) => ring.send(frame),
        None => Err(tdongle_usb_ring::SendError::NotStarted),
    }
}

/// `tinyusb_net_tx_ring_flush`: the source of the queued frames changed.
pub fn flush() {
    if let Some(ring) = RING.get() {
        ring.flush();
    }
}

/// `tinyusb_net_tx_ring_link_down`: the USB host went away.
pub fn link_down() {
    if let Some(ring) = RING.get() {
        ring.link_down();
    }
}

/// The IN-completion hook (`__wrap_netd_xfer_cb`): refill the NTB that just came back.
pub fn on_in_complete(xferred_bytes: u32) {
    if let Some(ring) = RING.get() {
        ring.on_in_complete(xferred_bytes);
    }
}

/// The ring's counters (`tinyusb_net_tx_ring_stats`).
pub fn stats() -> Option<TxStats> {
    RING.get().map(Ring::stats)
}
