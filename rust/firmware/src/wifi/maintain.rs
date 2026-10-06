//! Scanning, choosing and joining: the manager's periodic `wifi_maintain`, and `use N` (`wifi_use_profile`).
//!
//! Scanning and reconnecting run on the existing manager, never on event callbacks. One AP record at a time bounds our SRAM, regardless of nearby
//! AP count. The choice itself is `tdongle-wifi-policy` (preferred slot, priority, signal with hysteresis, the `use N` pin).

use core::sync::atomic::Ordering;
use std::sync::TryLockError;

use esp_idf_svc::sys;
use tdongle_wifi_policy::rank::{NOT_SEEN_DBM, Rank, rank_order};

use super::{Selection, Wifi, driver};
use crate::sys::now_ms;

/// The signal above which a connected network is kept whatever else is in range, and a scan is not even forced (`ap.rssi > -75` in C).
const KEEP_DBM: i32 = -75;

/// The manager's scan state: when the next scan is due, and where the walk over unseen (hidden or out of range) networks stands.
#[derive(Debug, Default)]
pub struct Maintainer {
    hidden_cursor: usize,
    next_scan_ms: u32,
}

impl Maintainer {
    /// A maintainer whose first pass runs at once.
    pub const fn new() -> Self {
        Self { hidden_cursor: 0, next_scan_ms: 0 }
    }

    /// One pass of `wifi_maintain`: cheap when nothing is due (the C returns before taking any lock).
    pub fn tick(&mut self, wifi: &Wifi) {
        let tick = now_ms();
        if !wifi.rescan.load(Ordering::Acquire) && (self.next_scan_ms.wrapping_sub(tick) as i32) > 0 {
            return;
        }
        if !wifi.ready.load(Ordering::Acquire) {
            return;
        }
        let guard = match wifi.scan_lock.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        let forced = wifi.rescan.swap(false, Ordering::AcqRel);
        self.next_scan_ms = tick.wrapping_add(if wifi.online() { 60_000 } else { 10_000 });
        self.pass(wifi, forced);
        drop(guard);
    }

    fn pass(&mut self, wifi: &Wifi, forced: bool) {
        // Snapshot the list under the lock; the scan runs without it.
        let (count, revision, mut profiles, rank, pinned_slot) = {
            let selection = wifi.lock();
            let mut priority = [0u8; 8];
            for (p, slot) in priority.iter_mut().zip(selection.meta.slot.iter()) {
                *p = slot.priority;
            }
            (
                selection.saved.count,
                selection.revision,
                selection.saved.profiles,
                Rank { priority: Some(priority), preferred: selection.meta.preferred },
                selection.pin.slot,
            )
        };
        wifi.scan_pauses_reconnect.store(true, Ordering::Release);
        let finish = |wifi: &Wifi| wifi.scan_pauses_reconnect.store(false, Ordering::Release);

        let ap = driver::ap_info();
        let connected = ap.is_some();
        let mut current = None;
        let mut signal = [NOT_SEEN_DBM; 8];
        if let Some(ap) = &ap {
            for (i, profile) in profiles.iter().enumerate().take(count) {
                if same_ssid(profile.ssid_bytes(), &ap.ssid) {
                    current = Some(i);
                    signal[i] = i16::from(ap.rssi);
                }
            }
        }
        if let Some(ap) = &ap
            && let Some(c) = current
            && i32::from(ap.rssi) > KEEP_DBM
            && !forced
            && pinned_slot.is_none_or(|p| p == c)
        {
            // Staying put. A save forgets which network is in use (current = -1) and this is the only place that ever finds out again while the link
            // stays up, so the screen's active network and `list`'s star would read "none" until the next reconnect.
            let selection = wifi.lock();
            if revision == selection.revision {
                wifi.current.store(c as i32, Ordering::Relaxed);
            }
            drop(selection);
            zeroize(&mut profiles);
            finish(wifi);
            return;
        }
        if count == 0 {
            // SAFETY: a plain driver call.
            unsafe { sys::esp_wifi_disconnect() };
            finish(wifi);
            return;
        }
        if !connected {
            // SAFETY: a plain driver call.
            unsafe { sys::esp_wifi_disconnect() };
        }
        scan_into(&profiles, count, &mut signal);
        let now = now_ms();
        for (i, s) in signal.iter_mut().enumerate().take(count) {
            if (wifi.retry_after[i].load(Ordering::Relaxed).wrapping_sub(now) as i32) > 0 {
                *s = NOT_SEEN_DBM; // a network that failed lately is left alone for a while
            }
        }
        // The pin belongs to the selection lock; a `use` that raced the scan bumped the revision.
        let mut selection = wifi.lock();
        if revision != selection.revision {
            drop(selection);
            zeroize(&mut profiles);
            finish(wifi);
            wifi.rescan.store(true, Ordering::Release);
            return;
        }
        let mut selected = selection.pin.pick_ranked(&signal, count, current, connected, &rank);
        wifi.pinned.store(selection.pin.slot.map_or(-1, |s| s as i32), Ordering::Relaxed);
        if selected.is_none()
            && connected
            && let Some(c) = current
        {
            wifi.current.store(c as i32, Ordering::Relaxed); // staying on the network in use
        }
        // Hidden/unseen networks get bounded attempts when offline, one per pass, walking the list in rank order (preferred, then priority, then slot).
        if selected.is_none() && !connected && count > 0 {
            let order = rank_order(&rank, count);
            for _ in 0..count {
                let i = usize::from(order[self.hidden_cursor % count]);
                self.hidden_cursor = self.hidden_cursor.wrapping_add(1);
                if (wifi.retry_after[i].load(Ordering::Relaxed).wrapping_sub(now) as i32) <= 0 {
                    selected = Some(i);
                    break;
                }
            }
        }
        if let Some(i) = selected {
            let mut candidate = driver::fill_station(&profiles[i]);
            // SAFETY: plain driver calls; `candidate` is a valid configuration for the call (the driver copies it).
            unsafe {
                sys::esp_wifi_disconnect();
                if sys::esp_wifi_set_config(sys::wifi_interface_t_WIFI_IF_STA, &mut candidate) == sys::ESP_OK {
                    wifi.current.store(i as i32, Ordering::Relaxed);
                    sys::esp_wifi_connect();
                }
            }
            zeroize_config(&mut candidate);
        }
        drop(selection);
        zeroize(&mut profiles);
        finish(wifi);
    }
}

/// An SSID in a saved profile (a C string) against the driver's 33-byte record: equal up to the first NUL, at most 32 bytes (`strncmp(.., 32)`).
fn same_ssid(saved: &[u8], seen: &[u8; 33]) -> bool {
    let seen_len = seen.iter().position(|&b| b == 0).unwrap_or(32).min(32);
    saved.len().min(32) == seen_len && saved[..seen_len] == seen[..seen_len]
}

/// A blocking active scan (every channel, hidden networks included); the strongest signal seen for each saved network goes into `signal`.
fn scan_into(profiles: &[tdongle_nvs_format::wifi_profiles::SavedProfile; 8], count: usize, signal: &mut [i16; 8]) {
    // SAFETY: the scan configuration is a valid struct for the call; records are read one at a time into a zeroed `wifi_ap_record_t`, which the
    // driver fills; the list is cleared afterwards so the driver frees its copy.
    unsafe {
        let mut scan: sys::wifi_scan_config_t = core::mem::zeroed();
        scan.show_hidden = true;
        scan.scan_type = sys::wifi_scan_type_t_WIFI_SCAN_TYPE_ACTIVE;
        scan.scan_time.active.min = 40;
        scan.scan_time.active.max = 100;
        let result = sys::esp_wifi_scan_start(&scan, true);
        crate::diag::note_memory(crate::diag::OP_WIFI_PROFILES, 0, result != sys::ESP_OK);
        if result == sys::ESP_OK {
            let mut record: sys::wifi_ap_record_t = core::mem::zeroed();
            while sys::esp_wifi_scan_get_ap_record(&mut record) == sys::ESP_OK {
                for (i, profile) in profiles.iter().enumerate().take(count) {
                    if same_ssid(profile.ssid_bytes(), &record.ssid) && i16::from(record.rssi) > signal[i] {
                        signal[i] = i16::from(record.rssi);
                    }
                }
            }
            sys::esp_wifi_clear_ap_list();
        }
    }
}

fn zeroize(profiles: &mut [tdongle_nvs_format::wifi_profiles::SavedProfile; 8]) {
    for profile in profiles.iter_mut() {
        *profile = tdongle_nvs_format::wifi_profiles::SavedProfile::EMPTY;
    }
    core::hint::black_box(&profiles);
}

fn zeroize_config(config: &mut sys::wifi_config_t) {
    // SAFETY: an all-zero configuration is valid; this overwrites the password the copy held.
    unsafe { core::ptr::write_volatile(config, core::mem::zeroed()) };
}

/// `use N`: see [`Wifi::use_profile`].
pub fn use_profile(wifi: &Wifi, selection: &mut Selection, slot: i64) -> i32 {
    if slot < 1 || slot > selection.saved.count as i64 || !wifi.ready.load(Ordering::Acquire) {
        return -1;
    }
    let index = (slot - 1) as usize;
    let mut candidate = driver::fill_station(&selection.saved.profiles[index]);
    wifi.scan_pauses_reconnect.store(true, Ordering::Release);
    // SAFETY: plain driver calls; `candidate` is valid for the call.
    let mut result = -2;
    unsafe {
        sys::esp_wifi_disconnect();
        if sys::esp_wifi_set_config(sys::wifi_interface_t_WIFI_IF_STA, &mut candidate) == sys::ESP_OK {
            wifi.current.store(index as i32, Ordering::Relaxed);
            selection.pin.set(index);
            wifi.pinned.store(index as i32, Ordering::Relaxed);
            wifi.retry_after[index].store(0, Ordering::Relaxed);
            selection.revision = selection.revision.wrapping_add(1); // a scan already in flight must not override this choice
            sys::esp_wifi_connect();
            result = 0;
        }
    }
    wifi.scan_pauses_reconnect.store(false, Ordering::Release);
    zeroize_config(&mut candidate);
    result
}
