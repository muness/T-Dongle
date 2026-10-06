//! The transparent bridge's firmware glue: `tdongle-bridge` (the forwarding logic) wired to the real USB ring, Wi-Fi driver, clock and tasks.
//!
//! Port of the platform half of `l2.c` (`tdongle_l2_start`, the esp_timer retry wait, the worker task) and of `start_wifi`'s bridge branch in
//! `gateway_main.c`. The two callbacks that run in other tasks never wait, allocate or call the Wi-Fi driver (ADR 0023); that rule is
//! `tdongle-bridge`'s test suite, and this file adds nothing that breaks it.

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use esp_idf_svc::hal::cpu::Core;
use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
use esp_idf_svc::sys;
use tdongle_bridge::{Bridge, Env, HostOutcome, Producer, RingSend, SOJOURN_MS_MAX, Stats, TaskContext, TxError};
use tdongle_usb_ring::SendError;

use crate::board::BRIDGE_TASK_STACK;
use crate::sys::now_us;
use crate::sys::single::SingleContext;
use crate::sys::task::{Notified, WAIT_FOREVER, ms_to_ticks, notify_take};
use crate::usb::prio;
use crate::{usb, wifi};

/// What `tdongle-bridge` needs from the world, on the board.
#[derive(Debug)]
pub struct FwEnv {
    worker: Notified,
    retry_timer: AtomicPtr<sys::esp_timer>,
}

impl FwEnv {
    const fn new() -> Self {
        Self { worker: Notified::new(), retry_timer: AtomicPtr::new(core::ptr::null_mut()) }
    }
}

impl Env for FwEnv {
    fn now_us(&self) -> u32 {
        now_us()
    }

    fn usb_ring_send(&self, frame: &[u8]) -> RingSend {
        match usb::ring::send(frame) {
            Ok(()) => RingSend::Accepted,
            Err(SendError::Full) => RingSend::Full,                                 // ESP_ERR_NO_MEM
            Err(SendError::NotStarted | SendError::LinkDown) => RingSend::NotReady, // ESP_ERR_INVALID_STATE
            Err(SendError::InvalidLength | SendError::Busy) => RingSend::Invalid,   // ESP_ERR_INVALID_ARG; Busy is a single-producer misuse
        }
    }

    fn usb_ring_flush(&self) {
        usb::ring::flush();
    }

    fn usb_link_state(&self, up: bool) {
        usb::net::link_state(up);
    }

    fn wifi_rx_register(&self, on: bool) {
        // SAFETY: registers (or clears) the RX callback for the STA interface; `wifi_rx` is a valid callback with the driver's signature.
        let code = unsafe { sys::esp_wifi_internal_reg_rxcb(sys::wifi_interface_t_WIFI_IF_STA, if on { Some(wifi_rx) } else { None }) };
        debug_assert_eq!(code, sys::ESP_OK);
    }

    fn notify_worker(&self) {
        self.worker.give();
    }

    fn wifi_tx(&self, frame: &[u8], _context: &TaskContext) -> Result<(), TxError> {
        wifi::pins::tx(frame)
    }

    fn wifi_room(&self) -> bool {
        wifi::pins::room()
    }

    /// Wait for the next chance: a retry period, or earlier if a notification arrives (a new frame: the loop re-attempts at once, harmlessly).
    /// A refusal for buffers clears as frames leave the antenna, about every 0.3 to 1 ms at the Wi-Fi rate, so the wait is an `esp_timer`, not the
    /// RTOS tick: at `CONFIG_FREERTOS_HZ=100` a tick sleep is 10 ms, long enough for the whole 16-buffer pool to drain and the radio to idle
    /// (measured: 590 retries, 101 frames lost, upload below what the link carries).
    fn wait_retry(&self, _context: &TaskContext) {
        let timer = self.retry_timer.load(Ordering::Acquire);
        if !timer.is_null() {
            // SAFETY: a handle created in `start`, never deleted. Already armed: ESP_ERR_INVALID_STATE, nothing to do.
            unsafe { sys::esp_timer_start_once(timer, u64::from(tdongle_bridge::RETRY_US)) };
        }
        notify_take(ms_to_ticks(SOJOURN_MS_MAX) + 1);
    }

    fn rx_resume(&self, _context: &TaskContext) {
        usb::net::rx_resume();
    }

    fn note_activity(&self) {
        crate::pm::note_activity();
    }

    fn worker_stack_free(&self) -> u32 {
        self.worker.stack_free()
    }
}

static BRIDGE: OnceLock<Bridge<FwEnv>> = OnceLock::new();

/// The TinyUSB task's handle on the host queue.
static PRODUCER: SingleContext<Producer<'static, FwEnv>> = SingleContext::new();

/// The Wi-Fi RX callback: the driver hands a frame, the bridge copies it into the USB ring, and the driver's buffer is freed here exactly once,
/// before returning, on every path (the driver's pool is not ours to hold).
unsafe extern "C" fn wifi_rx(buffer: *mut c_void, len: u16, driver_buffer: *mut c_void) -> sys::esp_err_t {
    if let Some(bridge) = BRIDGE.get() {
        // SAFETY: the driver passes `len` readable bytes at `buffer`, valid until the buffer is freed below.
        let frame = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), usize::from(len)) };
        // The outcome is already counted by the bridge; the RX callback has nothing else to do with it.
        let _outcome = bridge.wifi_rx(frame);
    }
    // SAFETY: `driver_buffer` is the RX buffer the driver gave this callback; it is freed exactly once, here.
    unsafe { sys::esp_wifi_internal_free_rx_buffer(driver_buffer) };
    sys::ESP_OK
}

extern "C" fn retry_fire(_argument: *mut c_void) {
    if let Some(bridge) = BRIDGE.get() {
        bridge.env().worker.give();
    }
}

/// The TinyUSB receive callback's entry (`tdongle_l2_host`): copy into the bridge's queue and return, or say HOLD.
///
/// Only the TinyUSB task calls this.
pub fn host_frame(frame: &[u8]) -> HostOutcome {
    // SAFETY: the sole caller is `usb::net::tud_network_recv_cb`, which runs in the TinyUSB task only and does not recurse.
    match unsafe { PRODUCER.get_mut() } {
        Some(producer) => producer.host(frame),
        None => HostOutcome::LinkDown, // not started: consumed, nothing counted
    }
}

/// The STA associated or lost its association (event task): the bridge's `tdongle_l2_link`, and the Wi-Fi TX charges the driver cleared.
pub fn link(connected: bool, context: &TaskContext) {
    if let Some(bridge) = BRIDGE.get() {
        bridge.link(connected, context);
    }
}

/// The counters (`tdongle_l2_stats`).
pub fn stats() -> Option<Stats> {
    BRIDGE.get().map(Bridge::stats)
}

/// Create the bridge for the STA MAC and start its worker (`tdongle_l2_start`). Once, after the USB ring is started and before Wi-Fi starts.
///
/// # Errors
/// Started twice, or the worker/timer could not be created.
pub fn start(mac: [u8; 6]) -> Result<(), &'static str> {
    let bridge = BRIDGE.get_or_init(|| Bridge::new(FwEnv::new(), mac));
    let Some(producer) = bridge.producer() else { return Err("the bridge was started twice") };
    let Some(worker) = bridge.worker() else { return Err("the bridge was started twice") };
    // SAFETY: still in the boot sequence; the TinyUSB task has not been given a callback that reaches PRODUCER before `usb::net` runs, and the
    // network class only offers datagrams once the host configures the device, which is after this returns.
    unsafe { PRODUCER.install(producer) };

    let args = sys::esp_timer_create_args_t {
        callback: Some(retry_fire),
        arg: core::ptr::null_mut(),
        dispatch_method: sys::esp_timer_dispatch_t_ESP_TIMER_TASK,
        name: c"l2_retry".as_ptr(),
        skip_unhandled_events: false,
    };
    let mut timer: sys::esp_timer_handle_t = core::ptr::null_mut();
    // SAFETY: `args` is valid for the call; `timer` is a valid out pointer.
    if unsafe { sys::esp_timer_create(&args, &mut timer) } != sys::ESP_OK {
        return Err("could not create the retry timer");
    }
    bridge.env().retry_timer.store(timer, Ordering::Release);

    ThreadSpawnConfiguration {
        name: Some(c"l2_wifi"),
        stack_size: BRIDGE_TASK_STACK,
        priority: prio::BRIDGE as u8,
        pin_to_core: Some(Core::Core1),
        ..Default::default()
    }
    .set()
    .map_err(|_| "could not configure the forwarder")?;
    let spawned = std::thread::Builder::new().name("l2_wifi".into()).stack_size(BRIDGE_TASK_STACK).spawn(move || forward(worker));
    crate::sys::reset_thread_spawn_defaults();
    spawned.map_err(|_| "could not start the forwarder")?;
    Ok(())
}

/// The forwarder task: `loop { wait for notify; drain }`. A notification that arrives during `drain` is kept: no lost wake-up.
fn forward(mut worker: tdongle_bridge::Worker<'static, FwEnv>) {
    if let Some(bridge) = BRIDGE.get() {
        bridge.env().worker.register_current_task();
    }
    loop {
        notify_take(WAIT_FOREVER);
        worker.drain();
    }
}
