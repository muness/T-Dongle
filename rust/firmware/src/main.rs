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

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    log::info!("T-Dongle-S3 {VERSION} (Rust port, phase 1: bridge)");

    // The settings are read first and only read: see `settings`.
    let settings = settings::load();
    let _ = STORED_MODE.set(settings.mode);
    let _ = report::DISPLAY.set(settings.display);
    let boot = boot::Boot::decide(&settings);

    // Frequency scaling (ADR 0016, 0023): 240 MHz while forwarding work is pending, 80 MHz when idle. A failure leaves the fixed boot frequency.
    pm::start();

    let boot::Boot::Bridge(bridge_boot) = boot else {
        log::error!("this image has no setup or tailnet boot yet");
        return;
    };
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
    if settings.ok {
        if let Err(error) = wifi::start(&network, &settings, mac) {
            log::error!("Wi-Fi did not start: {error}; management stays available over USB");
        }
    } else {
        log::error!("settings stage failed; the Wi-Fi stage does not start");
    }
    manage();
}

/// `manager`: every ten seconds sample the chip temperature, note the heap, let the Wi-Fi worker scan and join, and supervise the clock.
fn manage() -> ! {
    let mut maintainer = wifi::Maintainer::new();
    loop {
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
