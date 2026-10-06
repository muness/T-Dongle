//! The station: radio bring-up, the saved-network state, joining, and the link readings the serial `status` reports.
//!
//! In bridge mode the station has no lwIP netif: frames go through the bridge (`crate::bridge`), not through a network stack, and the link counts
//! as up at association (`WIFI_EVENT_STA_CONNECTED`), not at an IP address. Port of `start_wifi` (bridge branch), `wifi_event`, `wifi_fill_station`,
//! `wifi_maintain`, `wifi_use_profile` and `wifi_link_read` of `alternative/tailnet/main/`.
//!
//! The decisions (ranking, hysteresis, the pin, the order hidden networks are tried in) are `tdongle-wifi-policy`; the saved list and its metadata
//! are `tdongle-nvs-format`. This module is the driver calls and the locking around them.

mod driver;
mod events;
mod maintain;
pub mod pins;

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, TryLockError};
use std::time::{Duration, Instant};

use esp_idf_svc::sys::{self, EspError};
use tdongle_nvs_format::wifi_meta::MetaSet;
use tdongle_nvs_format::wifi_profiles::{LIMIT, SavedNetworks};
use tdongle_serial::wifi_link::{Events, Info};
use tdongle_wifi_policy::pin::Pin;

use crate::board::WIFI_TX_INFLIGHT;
use crate::settings::Settings;

pub use maintain::Maintainer;

/// The saved networks and which one is in use: what the C guards with `members_lock`.
#[derive(Debug)]
pub struct Selection {
    /// The saved list (SSIDs and passwords).
    pub saved: SavedNetworks,
    /// Names, priorities and the preferred network, parallel to `saved`.
    pub meta: MetaSet,
    /// Bumped by every change of the list or a `use`: a scan already in flight must not override a newer choice.
    pub revision: u32,
    /// The network `use N` chose and keeps against roaming.
    pub pin: Pin,
}

/// The one Wi-Fi station of the image.
#[derive(Debug)]
pub struct Wifi {
    selection: Mutex<Selection>,
    /// `wifi_scan_lock`: one scan or join operation at a time (taken with `try_lock`, as the C takes it with a zero timeout).
    scan_lock: Mutex<()>,
    /// The saved network in use, 0-based, or -1 (`wifi_current`): written under `selection`, read lock-free by `status` and the event task.
    current: AtomicI32,
    /// The pinned network (`use N`), 0-based, or -1: a lock-free mirror of `Selection::pin.slot` for the event task.
    pinned: AtomicI32,
    /// Associated (`online`).
    online: AtomicBool,
    /// The radio is up and joins may start (`wifi_ready`).
    ready: AtomicBool,
    /// A scan was asked for (`wifi_rescan`).
    rescan: AtomicBool,
    /// A scan or `use` is running: a disconnect it causes is not a failed network (`wifi_scan_pauses_reconnect`).
    scan_pauses_reconnect: AtomicBool,
    /// A network that failed is not tried again before this uptime (ms), per slot (`wifi_retry_after`): lock-free, the event task writes it.
    retry_after: [AtomicU32; LIMIT],
    /// Association and disconnect counters (`wifi_link_stats`): written by the event task only.
    events: Mutex<Events>,
}

static WIFI: OnceLock<Wifi> = OnceLock::new();

/// The station, once started.
pub fn get() -> Option<&'static Wifi> {
    WIFI.get()
}

impl Wifi {
    fn new(settings: &Settings) -> Self {
        Self {
            selection: Mutex::new(Selection { saved: settings.saved, meta: settings.meta, revision: 0, pin: Pin::NONE }),
            scan_lock: Mutex::new(()),
            current: AtomicI32::new(-1),
            pinned: AtomicI32::new(-1),
            online: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            rescan: AtomicBool::new(true),
            scan_pauses_reconnect: AtomicBool::new(false),
            retry_after: [const { AtomicU32::new(0) }; LIMIT],
            events: Mutex::new(Events::default()),
        }
    }

    /// Whether the station is associated.
    pub fn online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    /// Whether `slot` is the network the user pinned with `use N`.
    fn is_pinned(&self, slot: usize) -> bool {
        usize::try_from(self.pinned.load(Ordering::Relaxed)).is_ok_and(|pinned| pinned == slot)
    }

    /// The saved network in use (0-based), if any.
    pub fn current(&self) -> Option<usize> {
        usize::try_from(self.current.load(Ordering::Relaxed)).ok()
    }

    /// `members_lock` with the C's 100 ms timeout (`xSemaphoreTake(members_lock, pdMS_TO_TICKS(100))`): `None` is the serial `ERR Settings busy`.
    pub fn lock_selection(&self, timeout: Duration) -> Option<MutexGuard<'_, Selection>> {
        let start = Instant::now();
        loop {
            match self.selection.try_lock() {
                Ok(guard) => return Some(guard),
                Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {
                    if start.elapsed() >= timeout {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, Selection> {
        self.selection.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The association and disconnect counters.
    pub fn events(&self) -> Events {
        *self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The link as the serial `status` reports it (`wifi_link_read`): every field whose driver call fails stays "unknown" instead of reading as a
    /// real zero.
    pub fn link_info(&self) -> Info {
        driver::read_link_info(self)
    }

    /// `use N` (`wifi_use_profile`): switch to saved network `slot` (1-based) and keep it. The join itself is asynchronous (`status` reports
    /// join=joining/connected/failed). The caller holds the selection lock.
    ///
    /// Returns 0 when the switch was started, -1 for a bad slot or no Wi-Fi, -2 when the driver refused the configuration (the previous pin and
    /// network are left as they were).
    pub fn use_profile(&self, selection: &mut Selection, slot: i64) -> i32 {
        maintain::use_profile(self, selection, slot)
    }
}

/// Everything the Wi-Fi stage does (`start_network` and `start_wifi`, bridge branch): the network interface layer and the event loop the driver
/// needs, the bridge, the radio, the station profile of v0.1.1.
///
/// # Errors
/// A driver call failed. The stage stops there (the C's `START_TRY`), and management stays available over USB.
pub fn start(_network: &crate::boot::UsbNetwork, settings: &Settings, mac: [u8; 6]) -> Result<(), EspError> {
    // SAFETY: plain ESP-IDF initialisation calls, once, from the main task.
    unsafe {
        sys::esp!(sys::esp_netif_init())?;
        sys::esp!(sys::esp_event_loop_create_default())?;
    }
    let wifi = WIFI.get_or_init(|| Wifi::new(settings));
    // The bridge's worker and callbacks exist before the radio starts; the radio's allowance is the bridge's (ADR 0023 amendment 2).
    pins::set_tx_limit(WIFI_TX_INFLIGHT);
    crate::bridge::start(mac).map_err(|reason| {
        log::error!("bridge: {reason}");
        EspError::from_infallible::<{ sys::ESP_FAIL }>()
    })?;
    driver::init()?;
    events::register()?;
    driver::start_radio()?;
    pins::start();
    driver::power_save_off();
    driver::radio_profile();
    wifi.ready.store(true, Ordering::Release);
    wifi.rescan.store(true, Ordering::Release);
    Ok(())
}
