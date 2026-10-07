//! Persistent settings: the NVS store (`tdongle-nvs-write` over `esp-storage`, the C's keys and write order) and the commands that change it (`profile`, `del`, `use N`,
//! `display`, `mode`, `reset` / `confirm-reset`). The pure decisions are `tdongle_saved::edit` (the C `wifi_save_with`, `wifi_set_preferred`) and `tdongle_ui::reset`; this file
//! only sequences them: compute the new state, write it, and replace the in-memory copy only if the write succeeded (as in C: a failed save changes nothing).
//!
//! A flash erase stalls the cache for tens of milliseconds, like the IDF's own NVS: a save may hiccup the bridge once.

use alloc::string::String;
use core::sync::atomic::Ordering;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::Instant;
use esp_storage::FlashStorage;
use tdongle_nvs_format::load::Loaded;
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_write::{NorPartition, Store};
use tdongle_serial::reply;
use tdongle_ui::reset::{Confirm, ResetArm};

/// The C package's layout (`partitions.csv`): `nvs, data, nvs, 0x9000, 0x10000`.
pub const NVS_OFFSET: u32 = 0x9000;
/// Size of the `nvs` partition.
pub const NVS_SIZE: u32 = 0x1_0000;

type Flash = NorPartition<FlashStorage<'static>>;

/// The T-Dongle-S3's flash (W25Q128, JEDEC 0x1840ef).
pub const EXPECTED_CAPACITY: usize = 16 * 1024 * 1024;
/// The capacity the NVS's `FlashStorage` decoded when it was made (0 until mounted); `selftest flash` prints it.
pub static NVS_CAPACITY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The mounted store; `None` until the init task has mounted it (or when it could not).
pub static STORE: Mutex<CriticalSectionRawMutex, Option<Store<Flash>>> = Mutex::new(None);
static RESET_ARM: critical_section::Mutex<core::cell::Cell<ResetArm>> = critical_section::Mutex::new(core::cell::Cell::new(ResetArm::new()));

/// What the init task read: the mode and display settings (the list goes to `SAVED`).
#[derive(Clone, Copy, Debug)]
pub struct Stored {
    /// The stored mode, `Err(raw)` for a value the C firmware refuses.
    pub mode: Result<Mode, u8>,
    /// The display settings.
    pub display: UiSettings,
}

/// Mount the NVS and read every setting (`Store::load_all`: the C load rules, v0.1.x import included, writes nothing). `Err` is the text for the `init` command.
pub async fn mount(flash: esp_hal::peripherals::FLASH<'static>) -> Result<Stored, &'static str> {
    let fs = FlashStorage::new(flash);
    // esp-storage bounds every operation by the capacity it decoded from a JEDEC read at construction; keep it so a bad read (0 or 4 MB on this 16 MB chip) shows
    NVS_CAPACITY.store(fs.capacity() as u32, Ordering::Relaxed);
    if fs.capacity() != EXPECTED_CAPACITY {
        esp_println::println!("nvs: esp-storage capacity {} B, expected {} B (bad JEDEC read?)", fs.capacity(), EXPECTED_CAPACITY);
    }
    let part = NorPartition::new(fs, NVS_OFFSET);
    let mut store = Store::mount(part, NVS_SIZE).map_err(|_| "nvs mount failed")?;
    let loaded = store.load_all();
    *STORE.lock().await = Some(store);
    match loaded {
        Ok(s) => {
            // Publish the profiles here; returning their 5 KB value through the
            // async init task created several copies on its stack.
            publish_boot(s.networks);
            Ok(Stored { mode: s.mode.map_err(|e| match e { tdongle_nvs_format::mode::ModeError::InvalidStored(v) => v }), display: s.display })
        },
        Err(tdongle_nvs_write::LoadError::Profiles(_)) => Err("saved networks invalid (not overwritten)"),
        Err(_) => Err("saved networks unreadable"),
    }
}

#[inline(never)]
fn publish_boot(loaded: Loaded) {
    crate::SAVED.lock(|c| *c.borrow_mut() = Some(loaded));
}

fn publish(loaded: Loaded) {
    crate::SAVED.lock(|c| *c.borrow_mut() = Some(loaded));
    // the list changed: forget the pin and the current choice, and let the link task scan and join again (C: `wifi_rescan`, `wifi_pin_clear`)
    crate::PINNED.store(-1, Ordering::Relaxed);
    crate::USE_REQ.signal(());
}

fn current() -> Option<Loaded> {
    crate::SAVED.lock(|c| *c.borrow())
}

fn set_stored_display(d: UiSettings) {
    critical_section::with(|cs| {
        let c = crate::STORED.borrow(cs);
        let mut s = c.get();
        if let Some(s) = s.as_mut() {
            s.display = d;
        }
        c.set(s);
    });
}

fn now_ms() -> u32 {
    Instant::now().as_millis() as u32
}

/// `profile JSON`.
pub async fn profile(json: &str) -> String {
    let mut out = String::new();
    let cur = current().unwrap_or(Loaded { saved: Default::default(), meta: tdongle_nvs_format::wifi_meta::MetaSet::defaults(&[]) });
    let parsed = match tdongle_nvs_format::profile_json::profile_parse_json(json.as_bytes()) {
        Ok(p) if p.slot <= cur.saved.count => p,
        _ => return String::from(reply::PROFILE_REFRESH),
    };
    let p = parsed.profile;
    let name = (!p.name.starts_with(&[0])).then_some(&p.name[..]);
    let Some((list, meta)) = tdongle_saved::edit::save_with(&cur.saved, &cur.meta, &p.ssid, &p.pass, name, i32::from(p.priority), false, parsed.slot as i32) else {
        return String::from(reply::PROFILE_SAVE_FAILED);
    };
    match save_networks(&list, &meta).await {
        true => {
            publish(Loaded { saved: list, meta });
            let _ = reply::write_profile_saved(&mut out, parsed.slot as i32);
        }
        false => out.push_str(reply::PROFILE_SAVE_FAILED),
    }
    out
}

async fn save_networks(list: &tdongle_nvs_format::wifi_profiles::SavedNetworks, meta: &tdongle_nvs_format::wifi_meta::MetaSet) -> bool {
    let mut g = STORE.lock().await;
    let Some(store) = g.as_mut() else { return false };
    crate::guard::op("nvs_write");
    let r = store.save_profiles(list, meta);
    crate::guard::op("");
    if r.is_err() {
        let _ = store.remount();
    }
    r.is_ok()
}

/// `del N`.
pub async fn del(slot: i32) -> &'static str {
    let Some(cur) = current() else { return reply::DEL_FAILED };
    if slot < 1 || slot > cur.saved.count as i32 {
        return reply::DEL_FAILED;
    }
    let ssid = cur.saved.list()[(slot - 1) as usize].ssid;
    let Some((list, meta)) = tdongle_saved::edit::save_with(&cur.saved, &cur.meta, &ssid, b"", None, -1, true, -1) else { return reply::DEL_FAILED };
    if save_networks(&list, &meta).await {
        publish(Loaded { saved: list, meta });
        reply::DEL_OK
    } else {
        reply::DEL_FAILED
    }
}

/// `use N` after the link task was told: make N the preferred network (v0.1.1) and report whether that was kept.
pub async fn make_preferred(slot0: i32) -> bool {
    let Some(cur) = current() else { return false };
    let Some(meta) = tdongle_saved::edit::set_preferred(&cur.saved, &cur.meta, slot0) else { return false };
    if meta == cur.meta {
        return true;
    }
    let mut g = STORE.lock().await;
    let Some(store) = g.as_mut() else { return false };
    let r = store.save_meta(&cur.saved, &meta);
    if r.is_err() {
        let _ = store.remount();
        return false;
    }
    crate::SAVED.lock(|c| *c.borrow_mut() = Some(Loaded { saved: cur.saved, meta }));
    true
}

/// `metadata JSON` (companion `control.c`): compare-and-set of one saved network's name and priority, and optionally the preference. SSID and password are not
/// touched and nothing reassociates (the list is not republished: the link task keeps its network); a failed write leaves everything as it was.
pub async fn metadata(json: &str) -> &'static str {
    let Some(cur) = current() else { return reply::METADATA_INVALID };
    let Some(meta) = tdongle_nvs_format::metadata_json::metadata_parse_json(json.as_bytes()).ok().and_then(|e| e.apply(&cur.saved, &cur.meta)) else {
        return reply::METADATA_INVALID;
    };
    let mut g = STORE.lock().await;
    let Some(store) = g.as_mut() else { return reply::METADATA_NOT_SAVED };
    crate::guard::op("nvs_write");
    let r = store.save_meta(&cur.saved, &meta);
    crate::guard::op("");
    if r.is_err() {
        let _ = store.remount();
        return reply::METADATA_NOT_SAVED;
    }
    crate::SAVED.lock(|c| *c.borrow_mut() = Some(Loaded { saved: cur.saved, meta }));
    reply::METADATA_SAVED
}

#[cfg(feature = "tailnet")]
/// `POST /command` `{"action":"wifi",...}` (tailnet mode's USB page): C `wifi_save_with(ssid, password, name, priority, false, slot)`, the same edit the setup
/// page makes. False where the C returns false (list full, the SSID in another slot, a bad name or priority, or the write failed).
pub async fn save_wifi(w: &WifiSave) -> bool {
    let Some(cur) = current() else { return false };
    let Some((list, meta)) = tdongle_saved::edit::save_with(&cur.saved, &cur.meta, &w.ssid, &w.password, w.name.as_deref(), w.priority, false, w.slot) else {
        return false;
    };
    if save_networks(&list, &meta).await {
        publish(Loaded { saved: list, meta });
        true
    } else {
        false
    }
}

#[cfg(feature = "tailnet")]
/// `POST /command` `{"action":"wifi_remove","ssid":...}`: C `wifi_save_profile(ssid, "", true)`, by SSID (not by a slot number that could have moved).
pub async fn remove_wifi(ssid: &[u8]) -> bool {
    let Some(cur) = current() else { return false };
    let Some((list, meta)) = tdongle_saved::edit::save_with(&cur.saved, &cur.meta, ssid, b"", None, -1, true, -1) else { return false };
    if save_networks(&list, &meta).await {
        publish(Loaded { saved: list, meta });
        true
    } else {
        false
    }
}

#[cfg(feature = "tailnet")]
/// A Wi-Fi network to save from `POST /command`. The password is wiped when it is dropped.
pub struct WifiSave {
    /// SSID bytes (1 to 32).
    pub ssid: alloc::vec::Vec<u8>,
    /// Password bytes (0 to 63).
    pub password: alloc::vec::Vec<u8>,
    /// Display name, `None` for the default (or the slot's current one).
    pub name: Option<alloc::vec::Vec<u8>>,
    /// Priority 0 to 100, or -1 to keep the current or default one.
    pub priority: i32,
    /// 0-based slot, or -1 for the network's own slot or the next free one.
    pub slot: i32,
}

#[cfg(feature = "tailnet")]
impl Drop for WifiSave {
    fn drop(&mut self) {
        self.password.iter_mut().for_each(|b| *b = 0);
    }
}

/// `display B R D` (already parsed).
pub async fn display(settings: UiSettings) -> &'static str {
    let mut g = STORE.lock().await;
    let Some(store) = g.as_mut() else { return reply::STORAGE_SAVE_FAILED };
    if store.save_display(&settings).is_err() {
        let _ = store.remount();
        return reply::STORAGE_SAVE_FAILED;
    }
    set_stored_display(settings);
    reply::DISPLAY_SAVED
}

/// `mode NAME` (the caller restarts after a good save).
pub async fn mode(mode: Mode) -> bool {
    let mut g = STORE.lock().await;
    let Some(store) = g.as_mut() else { return false };
    if store.save_mode(mode).is_err() {
        let _ = store.remount();
        return false;
    }
    true
}

/// `reset`: arm the 10 second window.
pub fn reset() -> &'static str {
    critical_section::with(|cs| {
        let c = RESET_ARM.borrow(cs);
        let mut a = c.get();
        a.reset(now_ms());
        c.set(a);
    });
    reply::RESET_ARMED
}

/// `confirm-reset`: the reply, and whether the board must restart (into setup).
pub async fn confirm_reset() -> (&'static str, bool) {
    let verdict = critical_section::with(|cs| {
        let c = RESET_ARM.borrow(cs);
        let mut a = c.get();
        let v = a.confirm(now_ms());
        c.set(a);
        v
    });
    if verdict == Confirm::Expired {
        return (reply::RESET_EXPIRED, false);
    }
    let mut g = STORE.lock().await;
    let Some(store) = g.as_mut() else { return (reply::RESET_FAILED, false) };
    crate::guard::op("nvs_erase");
    let r = store.factory_reset();
    crate::guard::op("");
    if r.is_err() {
        let _ = store.remount();
        return (reply::RESET_FAILED, false);
    }
    drop(g);
    let (list, meta) = tdongle_saved::edit::factory_reset();
    publish(Loaded { saved: list, meta });
    set_stored_display(UiSettings::default());
    (reply::RESET_DONE, true)
}

/// A settings command, run by [`task`] in the thread executor: the console runs in the interrupt executor, whose stack and latency are no place for a flash erase and a
/// 2.5 KB blob buffer.
pub enum Req {
    /// `profile JSON`
    Profile(String),
    /// `del N`
    Del(i32),
    /// `use N`: make it the preferred network (the pin was already set).
    Use(i32),
    /// `display B R D`
    Display(UiSettings),
    /// `mode wifi_bridge`
    Mode(Mode),
    /// `reset`
    Reset,
    /// `confirm-reset`
    ConfirmReset,
    /// `tn force-derp on|off`, kept in flash.
    ForceDerp(bool),
    /// `metadata JSON`
    Metadata(String),
    #[cfg(feature = "tailnet")]
    /// `POST /command` `wifi` (reply text `OK` or empty for a failure).
    Wifi(alloc::boxed::Box<WifiSave>),
    #[cfg(feature = "tailnet")]
    /// `POST /command` `wifi_remove`: the SSID (reply text `OK` or empty).
    WifiRemove(alloc::vec::Vec<u8>),
}

/// The reply text and whether to restart after sending it.
pub type Resp = (String, bool);

static REQ: embassy_sync::channel::Channel<CriticalSectionRawMutex, Req, 1> = embassy_sync::channel::Channel::new();
static RESP: embassy_sync::signal::Signal<CriticalSectionRawMutex, Resp> = embassy_sync::signal::Signal::new();
static CALL: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

/// Run `req` in the thread executor and wait for the reply.
pub async fn call(req: Req) -> Resp {
    let _one_at_a_time = CALL.lock().await;
    RESP.reset();
    REQ.send(req).await;
    RESP.wait().await
}

/// The settings worker (thread executor).
#[embassy_executor::task]
pub async fn task() -> ! {
    loop {
        let req = REQ.receive().await;
        let resp: Resp = match req {
            Req::Profile(j) => (profile(&j).await, false),
            Req::Del(n) => (String::from(del(n).await), false),
            Req::Use(n) => {
                let kept = make_preferred(n - 1).await;
                crate::PINNED.store(n - 1, Ordering::Relaxed); // making it preferred must not drop the pin the switch just set
                let mut t = String::new();
                let _ = reply::write_use_ok(&mut t, n, kept);
                (t, false)
            }
            Req::Display(d) => (String::from(display(d).await), false),
            Req::Mode(m) => {
                if mode(m).await {
                    (String::from(reply::MODE_SAVED), true)
                } else {
                    (String::from(reply::MODE_NOT_SAVED), false)
                }
            }
            Req::ForceDerp(on) => {
                set_force_derp(on).await;
                (String::new(), false)
            }
            Req::Reset => (String::from(reset()), false),
            Req::Metadata(j) => (String::from(metadata(&j).await), false),
            #[cfg(feature = "tailnet")]
            Req::Wifi(w) => (String::from(if save_wifi(&w).await { "OK" } else { "" }), false),
            #[cfg(feature = "tailnet")]
            Req::WifiRemove(ssid) => (String::from(if remove_wifi(&ssid).await { "OK" } else { "" }), false),
            Req::ConfirmReset => {
                let (t, restart) = confirm_reset().await;
                (String::from(t), restart)
            }
        };
        RESP.signal(resp);
    }
}

/// `tn force-derp` (a diagnostic, in `rust_diag/force_derp`): kept until `off`, so that a reset does not turn a relay measurement into a direct one.
pub async fn set_force_derp(on: bool) {
    let mut g = STORE.lock().await;
    if let Some(store) = g.as_mut()
        && store.nvs().set_str("rust_diag", "force_derp", if on { "1" } else { "0" }).is_err()
    {
        let _ = store.remount();
    }
}

/// The last recorded failure, kept in flash (`rust_diag/last`) because the RTC record does not survive a power cycle or a trip through ROM download mode: what the previous boot
/// died of (`previous_hang`, `previous_op`, panic), written once at the next boot when there is one, and printed by `status` (`last_diag`) until a newer one replaces it.
pub static LAST_DIAG: embassy_sync::blocking_mutex::Mutex<CriticalSectionRawMutex, core::cell::RefCell<String>> = embassy_sync::blocking_mutex::Mutex::new(core::cell::RefCell::new(String::new()));

/// Persist this boot's view of the previous failure (if it was one) and load the one on flash for `status`.
pub async fn persist_diagnosis(state: &crate::guard::State) {
    use core::fmt::Write;
    let p = &state.boot.previous;
    let mut now = String::new();
    if !p.hang.as_str().is_empty() || !p.op.as_str().is_empty() || !p.panic_text().is_empty() {
        let _ = write!(
            now,
            "reset={} stage={} hang={} op={} panic={} unstable={}",
            state.reset.as_str(),
            p.stage.map_or("none", tdongle_boot_guard::Stage::name),
            p.hang.as_str(),
            p.op.as_str(),
            p.panic_text(),
            p.unstable_boots
        );
        now.truncate(240);
    }
    let mut g = STORE.lock().await;
    let Some(store) = g.as_mut() else { return };
    if !now.is_empty() {
        let mut old = [0u8; 256];
        let same = matches!(store.nvs().get_str("rust_diag", "last", &mut old), Ok(Some(n)) if &old[..n.min(256)] == now.as_bytes());
        if !same && store.nvs().set_str("rust_diag", "last", &now).is_err() {
            let _ = store.remount();
        }
    }
    let mut buf = [0u8; 256];
    if let Ok(Some(n)) = store.nvs().get_str("rust_diag", "last", &mut buf) {
        let text = core::str::from_utf8(&buf[..n.min(256)]).unwrap_or("").trim_end_matches('\0');
        LAST_DIAG.lock(|c| *c.borrow_mut() = String::from(text));
    }
    // `tn force-derp on` is a diagnostic that survives a reset until `off`: a reset must not silently turn a relay measurement into a direct one
    #[cfg(feature = "tailnet")]
    {
        let mut b = [0u8; 4];
        if matches!(store.nvs().get_str("rust_diag", "force_derp", &mut b), Ok(Some(n)) if n >= 1 && b[0] == b'1') {
            tdongle_tailnet_engine::shared::FORCE_DERP.store(true, core::sync::atomic::Ordering::Relaxed);
        }
    }
}
