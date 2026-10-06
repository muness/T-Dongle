//! USB device: one CDC-ACM serial console and one CDC-NCM network interface on the ESP32-S3's OTG controller, through TinyUSB.
//!
//! This is the Rust replacement for the C firmware's `components/esp_tinyusb` (descriptors, task, CDC, `tinyusb_net.c`'s callbacks and
//! transmit ring). TinyUSB itself (the `espressif/tinyusb` component, pinned to the C firmware's version) stays C: it is a third-party driver
//! library like lwIP. The glue is Rust:
//!
//! * [`descriptors`]: the TinyUSB descriptor callbacks over the byte-exact tables of `tdongle-usb-descriptors`;
//! * [`task`]: the USB PHY, the TinyUSB task, mount/unmount;
//! * [`net`]: the NCM callbacks (receive with hold/resume, transmit copy, the IN/OUT completion hook), traffic and class statistics;
//! * [`ring`]: the environment of `tdongle-usb-ring` and its worker task;
//! * [`cdc`]: the serial console's byte stream.

pub mod cdc;
pub mod descriptors;
pub mod net;
pub mod ring;
pub mod task;

use esp_idf_svc::sys::EspError;

/// The task scheme of ADR 0022/0023 on core 1: `usb_txq` relay 10 > TinyUSB 9 > forwarder 8 > `usb_txq` heap work 6 (all below the IDF system
/// tasks: esp_timer 22, Wi-Fi 23, ipc 24).
pub mod prio {
    /// The ring's worker: the relay (notify, then defer into TinyUSB) must outrank the producers on its core.
    pub const USB_TX: u32 = 10;
    /// The TinyUSB task: the IN pipe must not wait behind forwarding work.
    pub const TINYUSB: u32 = 9;
    /// The bridge's host -> Wi-Fi forwarder (`GATEWAY_TASK_BRIDGE_PRIO`).
    pub const BRIDGE: u32 = 8;
    /// The ring worker's priority while it grows (heap walks), so it never delays the tasks it serves.
    pub const USB_TX_WORK: u32 = 6;
}

const _: () = assert!(prio::USB_TX > prio::TINYUSB && prio::TINYUSB > prio::BRIDGE && prio::BRIDGE > prio::USB_TX_WORK);
const _: () = assert!(prio::USB_TX < 22, "below the IDF system tasks");

/// What the USB stack needs to know about this device.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    /// The Wi-Fi station MAC: the NCM MAC the host adopts, the serial number, and the address the bridge speaks for.
    pub station_mac: [u8; 6],
    /// The product string (`tdongle_usb_descriptors::PRODUCT_BRIDGE` in bridge mode).
    pub product: &'static str,
}

/// Bring up the USB device: descriptors, PHY, the TinyUSB task. The transmit ring and the console are started by their own modules once this
/// returns (the network callbacks tolerate arriving before them).
///
/// # Errors
/// The PHY or the TinyUSB stack could not be initialised.
pub fn start(identity: Identity) -> Result<(), EspError> {
    descriptors::install(identity);
    task::start()
}
