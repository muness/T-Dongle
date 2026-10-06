//! The Wi-Fi event handler (`wifi_event` of gateway_main.c, bridge branch): association and loss drive the bridge.
//!
//! The event task must not block: the handler takes no long locks (the selection state it needs is atomic) and everything it calls into is a
//! few instructions or a non-blocking hand-over (`bridge::link` flushes the USB ring and tells the host the carrier changed).

use core::ffi::c_void;
use core::sync::atomic::Ordering;

use esp_idf_svc::sys::{self, EspError};

use super::{Wifi, pins};
use crate::sys::now_ms;

/// How long a network that just dropped us is left alone before the worker tries it again (`60000` in C), unless the user pinned it.
const RETRY_AFTER_LOSS_MS: u32 = 60_000;

/// Register the handler for every Wi-Fi event.
pub fn register() -> Result<(), EspError> {
    // SAFETY: `on_event` is a valid handler; the context is unused; the registration lives for the life of the firmware.
    unsafe { sys::esp!(sys::esp_event_handler_register(sys::WIFI_EVENT, sys::ESP_EVENT_ANY_ID, Some(on_event), core::ptr::null_mut())) }
}

unsafe extern "C" fn on_event(_argument: *mut c_void, base: sys::esp_event_base_t, event: i32, data: *mut c_void) {
    if base != unsafe { sys::WIFI_EVENT } {
        return;
    }
    let Some(wifi) = super::get() else { return };
    match event as u32 {
        sys::wifi_event_t_WIFI_EVENT_STA_DISCONNECTED => {
            // SAFETY: for this event the driver passes a `wifi_event_sta_disconnected_t`, valid for the call.
            let (reason, rssi) =
                unsafe { data.cast::<sys::wifi_event_sta_disconnected_t>().as_ref() }.map_or((0, 0), |d| (u32::from(d.reason), i32::from(d.rssi)));
            on_disconnected(wifi, reason, rssi);
        }
        sys::wifi_event_t_WIFI_EVENT_STA_CONNECTED => {
            // SAFETY: for this event the driver passes a `wifi_event_sta_connected_t`, valid for the call.
            let bssid = unsafe { data.cast::<sys::wifi_event_sta_connected_t>().as_ref() }.map(|c| c.bssid);
            on_connected(wifi, bssid);
        }
        _ => {}
    }
}

fn on_disconnected(wifi: &Wifi, reason: u32, rssi: i32) {
    wifi.online.store(false, Ordering::Release);
    wifi.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).note_disconnect(reason, rssi, now_ms());
    // First: nothing new is submitted, then the driver's cleared queues are accounted.
    // SAFETY: the Wi-Fi event handler runs in the system event task, a FreeRTOS task that may block.
    crate::bridge::link(false, &unsafe { tdongle_bridge::TaskContext::assume() });
    pins::link_changed();
    let current = wifi.current.load(Ordering::Relaxed);
    if !wifi.scan_pauses_reconnect.load(Ordering::Relaxed) && current >= 0 && !wifi.is_pinned(current as usize) {
        wifi.retry_after[current as usize].store(now_ms().wrapping_add(RETRY_AFTER_LOSS_MS), Ordering::Relaxed);
    }
    // The worker rescans with backoff; never reconnect recursively here.
}

fn on_connected(wifi: &Wifi, bssid: Option<[u8; 6]>) {
    wifi.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).note_association(bssid.as_ref(), now_ms());
    pins::link_changed(); // the driver cleared its TX queues
    wifi.online.store(true, Ordering::Release);
    // SAFETY: as in `on_disconnected`: the system event task.
    crate::bridge::link(true, &unsafe { tdongle_bridge::TaskContext::assume() });
}
