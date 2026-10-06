//! T-Dongle-S3 firmware, Rust port (ADR 0001): phase 1, the transparent Wi-Fi bridge.
//!
//! Boot order follows the C firmware's `app_main` (`gateway_startup_sequence`): power management, USB (descriptors, TinyUSB, the transmit
//! ring, the serial console), the saved settings, the network layer and the radio, then the main task becomes the manager (`manager`).

mod alloc;
mod board;
mod boot;
mod bridge;
mod console;
mod diag;
mod guard;
mod pm;
mod report;
mod settings;
mod sys;
mod usb;
mod wifi;

use std::sync::OnceLock;
use std::time::Duration;

use tdongle_nvs_format::mode::Mode;

/// The version `status` reports as `firmware=`: the workspace version, which tracks the project's `VERSION`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[global_allocator]
static ALLOCATOR: alloc::Accounting = alloc::Accounting;

static STORED_MODE: OnceLock<Mode> = OnceLock::new();

/// The mode the saved settings ask for (which may be one this phase cannot run).
pub fn stored_mode() -> Mode {
    STORED_MODE.get().copied().unwrap_or(Mode::WifiBridge)
}

/// The manager's period (`vTaskDelay(pdMS_TO_TICKS(10000))`).
const MANAGER_PERIOD: Duration = Duration::from_secs(10);

/// The main task must report in at least this often (every stage, and every manager period) or the task watchdog resets the chip.
const WATCHDOG_MS: u32 = 30_000;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    log::info!("T-Dongle-S3 {VERSION} (Rust port, phase 1: bridge)");

    // Rule 13 (ADR 0001): the record of what the last boot was doing, the panic hook and the task watchdog come before anything that can block. Two
    // boots in a row that did not stay up make this one a safe-mode boot: console only, no saved settings, no Wi-Fi.
    let state = guard::begin();
    if let Err(error) = sys::watchdog_start(WATCHDOG_MS) {
        log::error!("task watchdog for the main task did not start: {error}");
    }
    if state.boot.safe_mode {
        log::error!(
            "safe mode: the last {} boots did not stay up (stage {:?}, panic {:?}): no saved settings, no Wi-Fi",
            state.boot.previous.unstable_boots,
            state.boot.previous.stage,
            state.boot.previous.panic_text()
        );
    }

    // The settings are read only (see `settings`). Until the setup boot exists (phase 2) the boot decision, and with it the USB identity, depends on
    // them, so they are read before USB; the step is recorded, the watchdog bounds it, and safe mode skips it. (The no_std images, whose
    // descriptors do not depend on the mode, bring USB up first.)
    guard::stage(tdongle_boot_guard::Stage::Settings);
    let settings = if guard::safe_mode() { settings::Settings::empty(false) } else { settings::load() };
    if STORED_MODE.set(settings.mode).is_err() || report::DISPLAY.set(settings.display).is_err() {
        log::warn!("settings were published twice");
    }
    let boot = boot::Boot::decide(&settings);

    // Frequency scaling (ADR 0016, 0023): 240 MHz while forwarding work is pending, 80 MHz when idle. A failure leaves the fixed boot frequency.
    pm::start();

    let boot::Boot::Bridge(bridge_boot) = boot else {
        log::error!("this image has no setup or tailnet boot yet");
        return;
    };
    guard::stage(tdongle_boot_guard::Stage::Usb);
    let mac = sys::read_sta_mac();
    let identity = usb::Identity { station_mac: mac, product: tdongle_usb_descriptors::PRODUCT_BRIDGE };
    if let Err(error) = usb::start(identity) {
        log::error!("USB did not start: {error}");
    }
    if let Err(reason) = usb::ring::start() {
        log::error!("USB transmit ring: {reason}");
    }
    if let Err(reason) = console::start() {
        log::error!("console: {reason}");
    }

    let network = bridge_boot.usb_network();
    guard::stage(tdongle_boot_guard::Stage::RadioInit);
    if settings.ok {
        if let Err(error) = wifi::start(&network, &settings, mac) {
            log::error!("Wi-Fi did not start: {error}; management stays available over USB");
        }
    } else {
        log::error!("settings stage failed; the Wi-Fi stage does not start");
    }
    guard::stage(tdongle_boot_guard::Stage::Running);
    manage();
}

/// `manager`: every ten seconds sample the chip temperature, note the heap, let the Wi-Fi worker scan and join, and supervise the clock.
fn manage() -> ! {
    let mut maintainer = wifi::Maintainer::new();
    loop {
        sys::watchdog_feed();
        if u64::from(sys::now_ms()) >= tdongle_boot_guard::STABLE_AFTER_MS {
            guard::mark_stable();
        }
        diag::sample_temperature();
        diag::note_memory(diag::OP_TICK, 0, false);
        if let Some(wifi) = wifi::get() {
            maintainer.tick(wifi);
            // The SNTP supervisor of the C firmware runs in bridge mode too (it only counts: there is no lwIP to restart SNTP in).
            let mut clock = report::CLOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let _restart_requested = clock.poll(sys::now_us64() / 1000, false, wifi.online());
        }
        std::thread::sleep(MANAGER_PERIOD);
    }
}
