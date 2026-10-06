//! The Wi-Fi data path, as the C firmware has it (`components/tdongle_runtime/l2.c`): frames go to the driver with `esp_wifi_internal_tx` and come back through
//! `esp_wifi_internal_reg_rxcb`, not through esp-radio's `Interface::receive()/transmit()` tokens.
//!
//! Why (S3 on the board wedged within a second): esp-radio's tokens gate BOTH directions on one TX credit counter that only the driver's tx-done callback gives back and that
//! nothing resets, so a frame the driver drops on a link change (and any frame sent while not Connected) leaks a credit for good, and once the credits are gone
//! `receive()` yields nothing either. See `tdongle-wifi-budget/tests/coupled_credit.rs`. Here:
//!
//! * RX is a callback in the Wi-Fi task: it copies the frame into the bridge (`Bridge::wifi_rx`) and frees the driver's buffer; it never waits and needs no TX credit.
//! * TX is charged to `WifiPins` (the C budget: limit 6 in flight, a heap floor past the band), released by the tx-done callback, flushed on every link change, and healed by a
//!   3 s lease if a completion is ever lost.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::Instant;
use esp_wifi_sys_esp32s3::include as sys;
use tdongle_bridge::{Bridge, TxError};
use tdongle_serial::wifi_link::{AP_AX, AP_B, AP_G, AP_N, Info, PHY_UNKNOWN, PS_UNKNOWN, SECOND_UNKNOWN};
use tdongle_wifi_budget::{RawLock, WifiPins, WifiPinsStats};

use crate::FwEnv;

/// The TX FIFO's critical section: `critical_section` with the restore state kept in the lock (`lock` and `unlock` are called in pairs by one context).
pub struct CsLock(UnsafeCell<Option<critical_section::RestoreState>>);

// SAFETY: the cell is only written between `acquire` and `release`, i.e. while the critical section is held by the writer.
unsafe impl Sync for CsLock {}

impl RawLock for CsLock {
    fn lock(&self) {
        // SAFETY: paired with `unlock`; the state is stored while the section is held.
        let state = unsafe { critical_section::acquire() };
        // SAFETY: we hold the critical section.
        unsafe { *self.0.get() = Some(state) };
    }
    fn unlock(&self) {
        // SAFETY: we hold the critical section taken in `lock`.
        let state = unsafe { (*self.0.get()).take() };
        if let Some(state) = state {
            // SAFETY: `state` came from the matching `acquire`.
            unsafe { critical_section::release(state) };
        }
    }
}

/// `gateway_wifi_pins`.
pub static PINS: WifiPins<CsLock> = WifiPins::new(CsLock(UnsafeCell::new(None)));

static TX_DONE_OK: AtomicBool = AtomicBool::new(false);
static BRIDGE: AtomicPtr<Bridge<FwEnv>> = AtomicPtr::new(core::ptr::null_mut());
/// The bridge wants Wi-Fi frames (`Env::wifi_rx_register`).
pub static RX_ON: AtomicBool = AtomicBool::new(false);
/// Frames the driver handed to the callback / that were dropped because the bridge was not listening.
pub static RX_CALLBACKS: AtomicU32 = AtomicU32::new(0);
pub static RX_IGNORED: AtomicU32 = AtomicU32::new(0);
/// `esp_wifi_internal_tx` refusals by the driver (not budget refusals).
pub static TX_DRIVER_ERR: AtomicU32 = AtomicU32::new(0);
pub static TX_LAST_ERR: AtomicU32 = AtomicU32::new(0);
/// The lowest free heap seen at a TX admission (the budget refuses past its band when free heap minus the frame would fall under 29,884 B): shows whether `refused_heap` is the heap or the threshold.
pub static HEAP_MIN: AtomicU32 = AtomicU32::new(u32::MAX);
/// Woken by every tx-done: the worker waits on it for room.
pub static TX_DONE_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();

fn now_ms() -> u32 {
    Instant::now().as_millis() as u32
}

/// The driver hands us a received frame (Wi-Fi task). Always frees the driver's buffer; returns `ESP_OK`.
unsafe extern "C" fn rx_cb(buffer: *mut c_void, len: u16, eb: *mut c_void) -> sys::esp_err_t {
    RX_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    let bridge = BRIDGE.load(Ordering::Acquire);
    if !buffer.is_null() && len != 0 && !bridge.is_null() && RX_ON.load(Ordering::Acquire) {
        // SAFETY: the driver guarantees `buffer` is readable for `len` bytes until `esp_wifi_internal_free_rx_buffer(eb)`; `bridge` is the 'static bridge set in `start`.
        let frame = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), usize::from(len)) };
        // SAFETY: as above; `wifi_rx` is the callback entry of the bridge and takes `&self`.
        let _ = unsafe { &*bridge }.wifi_rx(frame); // every outcome is counted inside the bridge
    } else {
        RX_IGNORED.fetch_add(1, Ordering::Relaxed);
    }
    if !eb.is_null() {
        // SAFETY: `eb` is the driver's handle for this buffer; it is freed exactly once, here.
        unsafe { sys::esp_wifi_internal_free_rx_buffer(eb) };
    }
    sys::ESP_OK as sys::esp_err_t
}

/// A frame completed (sent or failed): its buffer is free. Wi-Fi task, so IRAM (it can run while the flash cache is off).
#[esp_hal::ram]
unsafe extern "C" fn tx_done(_ifidx: u8, _data: *mut u8, _len: *mut u16, _ok: bool) {
    PINS.done();
    TX_DONE_SIG.signal(());
}

/// After the radio driver is initialised: take over both directions and set the TX limit (`wifi_pins_start`).
pub fn start(bridge: &'static Bridge<FwEnv>) {
    BRIDGE.store(core::ptr::from_ref(bridge).cast_mut(), Ordering::Release);
    PINS.set_tx_limit(crate::WIFI_TX_QUEUE as u32);
    register();
}

/// Register (or re-register) the two callbacks. Called after the radio driver is initialised and again once it is started and associated: `esp_wifi_set_tx_done_cb`
/// is documented to need a started driver, and esp-radio registers its own at init, so the last registration must be ours.
pub fn register() {
    // SAFETY: `tx_done` and `rx_cb` are valid callbacks of the types the driver expects; both registrations replace esp-radio's (whose token API this image does not use).
    let code = unsafe { sys::esp_wifi_set_tx_done_cb(Some(tx_done)) };
    TX_DONE_OK.store(code == sys::ESP_OK as sys::esp_err_t, Ordering::Release);
    // SAFETY: as above.
    let rx = unsafe { sys::esp_wifi_internal_reg_rxcb(sys::wifi_interface_t_WIFI_IF_STA, Some(rx_cb)) };
    if rx != sys::ESP_OK as sys::esp_err_t {
        crate::init_note("rx callback not registered");
    }
}

/// Send one frame on the STA interface, charged to the budget (`wifi_pins_tx`). `NoMem`: refused for buffers; the bridge retries for a few milliseconds.
pub fn tx(frame: &[u8]) -> Result<(), TxError> {
    let length = frame.len() as u16;
    HEAP_MIN.fetch_min(esp_alloc::HEAP.free() as u32, Ordering::Relaxed);
    let sent = PINS.tx(TX_DONE_OK.load(Ordering::Acquire), u32::from(length), esp_alloc::HEAP.free(), now_ms(), || {
        // SAFETY: `frame` is readable for `length` bytes; the driver copies it into its own buffer before returning.
        let code = unsafe { sys::esp_wifi_internal_tx(sys::wifi_interface_t_WIFI_IF_STA, frame.as_ptr().cast_mut().cast(), length) };
        if code == sys::ESP_OK as i32 { Ok(()) } else { Err(code) }
    });
    match sent {
        Ok(()) => Ok(()),
        Err(tdongle_wifi_budget::TxError::NoMem) => Err(TxError::NoMem),
        Err(tdongle_wifi_budget::TxError::Driver(code)) => {
            TX_DRIVER_ERR.fetch_add(1, Ordering::Relaxed);
            TX_LAST_ERR.store(code as u32, Ordering::Relaxed);
            Err(if code == sys::ESP_ERR_NO_MEM as i32 { TxError::NoMem } else { TxError::Other(code) })
        }
    }
}

/// Room for one more charge (`wifi_pins_tx_room`).
pub fn room() -> bool {
    PINS.room(now_ms())
}

/// The driver clears its queues when the link drops or comes up, without completing the frames in them (`wifi_pins_link_changed`).
pub fn link_changed() {
    PINS.flush();
}

pub fn tx_done_registered() -> bool {
    TX_DONE_OK.load(Ordering::Acquire)
}

pub fn pins_stats() -> WifiPinsStats {
    PINS.stats()
}

/// `wifi_link_read` of the C firmware (`wifi_link.inc`): the driver's view of the link; a call that fails leaves its field "unknown" instead of zero.
pub fn link_read() -> Info {
    let mut l = Info { phy: PHY_UNKNOWN, ps: PS_UNKNOWN, secondary: SECOND_UNKNOWN, ..Info::default() };
    // SAFETY: plain driver queries into zeroed, correctly sized out-parameters.
    unsafe {
        let mut ap: sys::wifi_ap_record_t = core::mem::zeroed();
        if sys::esp_wifi_sta_get_ap_info(&mut ap) != sys::ESP_OK as i32 {
            return l; // not associated
        }
        l.connected = true;
        l.rssi = ap.rssi;
        l.rssi_valid = true;
        let mut average: i32 = 0;
        if sys::esp_wifi_sta_get_rssi(&mut average) == sys::ESP_OK as i32 && (-128..=127).contains(&average) {
            l.rssi = average as i8;
        }
        l.channel = ap.primary;
        l.secondary = ap.second as u8;
        l.ap_bw_mhz = if ap.bandwidth == sys::wifi_bandwidth_t_WIFI_BW40 { 40 } else if ap.bandwidth == sys::wifi_bandwidth_t_WIFI_BW20 { 20 } else { 0 };
        l.ap_modes = (if ap.phy_11b() != 0 { AP_B } else { 0 })
            | (if ap.phy_11g() != 0 { AP_G } else { 0 })
            | (if ap.phy_11n() != 0 { AP_N } else { 0 })
            | (if ap.phy_11ax() != 0 { AP_AX } else { 0 });
        let mut phy: sys::wifi_phy_mode_t = 0;
        if sys::esp_wifi_sta_get_negotiated_phymode(&mut phy) == sys::ESP_OK as i32 && (phy as u32) < tdongle_serial::wifi_link::PHY_COUNT {
            l.phy = phy as u8;
        }
        let mut bw: sys::wifi_bandwidth_t = 0;
        if sys::esp_wifi_get_bandwidth(sys::wifi_interface_t_WIFI_IF_STA, &mut bw) == sys::ESP_OK as i32 {
            l.bw_cfg_mhz = if bw == sys::wifi_bandwidth_t_WIFI_BW40 { 40 } else if bw == sys::wifi_bandwidth_t_WIFI_BW20 { 20 } else { 0 };
        }
        let mut ps: sys::wifi_ps_type_t = 0;
        if sys::esp_wifi_get_ps(&mut ps) == sys::ESP_OK as i32 {
            l.ps = ps as u8;
        }
        let mut power: i8 = 0;
        if sys::esp_wifi_get_max_tx_power(&mut power) == sys::ESP_OK as i32 {
            l.tx_power_valid = true;
            l.tx_power_qdbm = power;
        }
    }
    l
}

/// The access point the driver joined (`esp_wifi_sta_get_ap_info`), for comparison with the one the scan said was strongest.
pub fn joined_bss() -> Option<tdongle_saved::Bss> {
    // SAFETY: a plain driver query into a zeroed, correctly sized out-parameter.
    unsafe {
        let mut ap: sys::wifi_ap_record_t = core::mem::zeroed();
        if sys::esp_wifi_sta_get_ap_info(&mut ap) != sys::ESP_OK as i32 {
            return None;
        }
        Some(tdongle_saved::Bss { bssid: ap.bssid, channel: ap.primary, rssi: ap.rssi })
    }
}

/// Bridge mode turns 802.11k and v on (`c->sta.rm_enabled = c->sta.btm_enabled = wifi_roaming_assist()`): esp-radio zeroes those bitfields, so set them on the
/// station configuration it applied (the C sets them in the same `wifi_config_t` before `esp_wifi_set_config`).
pub fn roaming_assist() {
    // SAFETY: plain driver calls with a zeroed, correctly sized `wifi_config_t`.
    unsafe {
        let mut c: sys::wifi_config_t = core::mem::zeroed();
        if sys::esp_wifi_get_config(sys::wifi_interface_t_WIFI_IF_STA, &mut c) == sys::ESP_OK as i32 {
            c.sta.set_rm_enabled(1);
            c.sta.set_btm_enabled(1);
            let _ = sys::esp_wifi_set_config(sys::wifi_interface_t_WIFI_IF_STA, &mut c); // a failure leaves roaming assist off, which only costs roaming
        }
    }
}
