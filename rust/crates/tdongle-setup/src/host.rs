//! Everything the portal needs from the outside world, as traits, so the whole portal runs on the host with fakes.

use crate::scan::ScanList;

/// A monotonic millisecond clock (`esp_timer_get_time() / 1000` truncated to 32 bits; every comparison here is wrap safe).
pub trait Clock {
    /// Milliseconds since boot, modulo 2^32.
    fn now_ms(&self) -> u32;
}

/// The settings store, the radio and the restart machinery, as the C handlers use them.
pub trait SetupHost {
    /// `wifi_ready`: the access point is up, so the Wi-Fi pages may scan and save. Also what the session timer reads as "access point up".
    fn wifi_ready(&self) -> bool;
    /// `!settings_ok || gateway_boot_recovery()`: the store is unreadable or this boot is a crash-loop recovery.
    fn recovery(&self) -> bool;
    /// `xSemaphoreTake(members_lock, wait_ms)`: false when it timed out (the C waits 100 ms for the list, 1000 ms for `/command`).
    fn lock_settings(&mut self, wait_ms: u32) -> bool;
    /// `xSemaphoreGive(members_lock)`.
    fn unlock_settings(&mut self);

    /// `setup_scan_kick(again)`: start a scan unless one runs (`again` forces a new one even when a result exists).
    fn scan_kick(&mut self, again: bool);
    /// `setup_scan_result`: copy of the last complete scan into `out`; returns whether a scan is running.
    fn scan_result(&mut self, out: &mut ScanList) -> bool;

    /// `wifi_saved.count`.
    fn saved_count(&self) -> usize;
    /// SSID of saved network `i` (0-based).
    fn saved_ssid(&self, i: usize) -> &[u8];
    /// Name of saved network `i` (`wifi_meta.slot[i].name`).
    fn saved_name(&self, i: usize) -> &[u8];
    /// Priority of saved network `i`.
    fn saved_priority(&self, i: usize) -> u8;
    /// `wifi_meta.preferred` (0-based).
    fn saved_preferred(&self) -> Option<usize>;

    /// `wifi_save_with(ssid, password, name, priority, false, slot)`: `name` is `None` for the default name, `priority` -1 for the
    /// default, `slot` -1 for the next free one (0-based otherwise). False when it could not be saved.
    fn save_wifi(&mut self, ssid: &[u8], password: &[u8], name: Option<&[u8]>, priority: i32, slot: i32) -> bool;
    /// `wifi_save_profile(ssid, "", true)`: delete a saved network.
    fn remove_wifi(&mut self, ssid: &[u8]) -> bool;
    /// `control_submit("cancel")`: leave setup (restart into normal mode) after the response has been sent. False if it could not be queued.
    fn request_leave(&mut self) -> bool;
}
