//! The seam between the firmware image (`rust/firmware`) and the tailnet gateway (`tdongle-tailnet-runtime`).
//!
//! The firmware image owns the hardware and everything that exists in every mode (boot guard and rescue, the USB device, the Wi-Fi radio, the
//! console, the setup access point and its HTTP server, NVS, the LCD and button). Tailnet mode is *one more mode* of that image. The two sides meet
//! here and nowhere else, so the image can change without touching the tailnet crates and the other way round:
//!
//! ```text
//!  firmware image                                   tailnet runtime
//!  --------------                                   ---------------
//!  implements  Platform, Storage, UsbFrames,   -->  Shared::new(platform, storage, ..) in a StaticCell, then
//!              WifiLink (embassy-net-driver)        tdongle_tailnet_runtime::run(shared, net, usb, wifi)  (one async fn: spawn it on the thread executor)
//!  calls       dyn TailnetApi  <------------------  registered by the runtime (`Registry::api()`), usable from the HTTP server and the console
//! ```
//!
//! # What the image does when the stored mode is tailnet
//!
//! 1. Boot exactly as for bridge mode (rule 13: USB and console first, rescue `arm()` first, watchdogs, safe mode). Tailnet mode must not be reachable
//!    from safe mode.
//! 2. `Mode::Tailnet` replaces `Mode::WifiBridge` in the mode enum; the NVS `mode` byte is the C's (`tn_settings/mode`), see [`Mode`].
//! 3. Build the pieces below. `Platform` and `Storage` are moved into `Shared` (so the synchronous `TailnetApi` can reach them from any task), then `spawn(tdongle_tailnet_runtime::run(shared, net, usb, wifi))`. The runtime never blocks the executor
//!    and never calls a radio function from interrupt context; the Wi-Fi driver's own task keeps running in the image.
//! 4. The setup page's member actions and `/status` go through [`TailnetApi`], serial lines through [`TailnetApi::serial_command`]; the image only
//!    carries bytes.
//!
//! The traits are deliberately small and synchronous where the image's own code is (a flash write is not `async`), `async` where the image already
//! awaits (USB endpoints). Nothing here allocates.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub use tdongle_tailnet_admission::probe::{HeapProbe, HeapSnapshot};
pub use tdongle_tailnet_members::{MemberAction, Reply};
pub use tdongle_tailnet_status::ChunkSink;
use tdongle_tailnet_types::Millis;

/// The firmware's run mode as the `tn_settings/mode` NVS byte stores it (kept byte-compatible with the C: `tdongle_mode_t`). The image owns the real
/// enum; this one documents the values tailnet mode depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The transparent Wi-Fi bridge (phase 1).
    WifiBridge,
    /// The tailnet gateway (this crate's consumer).
    Tailnet,
}

/// What the image can tell the runtime about the board. All methods are cheap and callable from any task.
pub trait Platform {
    /// Monotonic milliseconds since boot.
    fn now_ms(&self) -> Millis;
    /// Wall-clock Unix seconds, or `None` until SNTP (or any source) has set it. The runtime refuses TLS and WireGuard timestamps before it is valid
    /// (the C's `clock_sync.h` rule: valid means above 1,700,000,000).
    fn unix_seconds(&self) -> Option<u64>;
    /// Cryptographically strong random bytes (the hardware RNG with the radio or SAR ADC enabled; the C's `ml_rng.c` requirement).
    fn fill_random(&self, buf: &mut [u8]);
    /// The station MAC (the USB serial number and the NCM MAC are derived from it by the image).
    fn sta_mac(&self) -> [u8; 6];
    /// The internal heap (free, largest block, minimum since boot) for admission and the heap budget.
    fn heap(&self) -> &dyn HeapProbe;
    /// One serial console line (without the newline); the image owns line discipline and the ACM writer. Used for the C-compatible `tailnet`/`route`
    /// lines the Android app parses.
    fn console_line(&self, line: &str);
}

/// A storage failure. The runtime treats every variant as "not saved" and reports it in `/status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// Key not found.
    NotFound,
    /// The buffer is too small for the stored blob.
    TooSmall,
    /// The partition is unavailable or full.
    Failed,
}

/// NVS as the image provides it: blobs and strings by (namespace, key). Byte-compatible with the C: namespace `tn_settings` holds the string `members`
/// (JSON, see `tdongle-tailnet-members`) and each membership has its own namespace `tn_%08x` with the 96-byte blob `identity_v1`
/// (machine, WireGuard, DISCO private keys) and `wg_tai_base`, plus the peer cache blob (`tdongle-tailnet-peers`).
///
/// Writes must commit before returning (the C commits after every set). The image must make writes crash-safe (NVS pages do) and must never erase the
/// partition (rule: the Rust image never calls `nvs_flash_erase`).
pub trait Storage {
    /// Read a blob/string into `out`; returns its length.
    fn get(&mut self, namespace: &str, key: &str, out: &mut [u8]) -> Result<usize, StorageError>;
    /// Write and commit a blob/string.
    fn set(&mut self, namespace: &str, key: &str, data: &[u8]) -> Result<(), StorageError>;
    /// Erase one namespace (a removed membership's identity). Other namespaces are untouched.
    fn erase_namespace(&mut self, namespace: &str) -> Result<(), StorageError>;
}

/// The USB side as Ethernet frames (the NCM data interface). The image owns the NCM framing (NTBs); the runtime sees one frame per call.
///
/// Backpressure contract (ADR 0023): `recv` is not called while the runtime cannot take a frame, and the image then does not read the OUT endpoint,
/// so the host's driver NAKs; the runtime never drops silently, it counts.
#[allow(async_fn_in_trait)]
pub trait UsbFrames {
    /// Wait for the next frame from the host into `buf` (at least 1,514 bytes) and return its length. Cancel-safe.
    async fn recv(&mut self, buf: &mut [u8]) -> usize;
    /// Queue a frame for the host. Returns false if it was refused (ring full, host not configured): counted by the caller.
    fn send(&mut self, frame: &[u8]) -> bool;
    /// True while the host has the data interface configured (alternate setting 1). The runtime holds the carrier state of its own netif to this.
    fn host_ready(&self) -> bool;
    /// A number that changes whenever the USB link comes up again (the C's link generation; flows of an older generation are dropped).
    fn link_generation(&self) -> u32;
    /// Tell the host the carrier is up or down (the NCM notification), as the C does when the first membership is routing.
    fn set_carrier(&mut self, up: bool);
    /// A frame from the host that the dongle's own TCP stack should see: an ARP reply, or TCP to the dongle's own address (192.168.77.1: the `/status` page the
    /// Android app reads). The runtime still handles the frame as before; an image without such a stack ignores this (the default).
    fn local_frame(&mut self, _frame: &[u8]) {}
}

/// **Documentation of the Wi-Fi contract; the runtime does not bound on it.** The runtime consumes the radio through its own `net_embassy::LinkGen` (the
/// association generation) and `wifi::WifiRaw` (`tdongle-tailnet-wifimux`, the NAPT passthrough); implement this trait on the firmware's driver wrapper
/// if it helps, then adapt it to those two.
///
/// The Wi-Fi station as an Ethernet-medium `embassy-net-driver` (frames in and out with the STA MAC), plus the link facts the runtime needs. The image
/// owns association, roaming, ranking and the saved networks; the runtime only uses the data path.
pub trait WifiLink: embassy_net_driver::Driver {
    /// True while associated (the runtime holds control, DERP and WireGuard sockets down otherwise).
    fn associated(&self) -> bool;
    /// A number that changes on every (re)association, so the runtime can restart sockets and NAPT state.
    fn association_generation(&self) -> u32;
}

/// What tailnet mode offers the image. The runtime registers one implementation; the image's setup HTTP server and console call it. All methods are
/// non-blocking (short critical sections) and callable from any task. Object safe, so the image holds a `&'static dyn TailnetApi`.
pub trait TailnetApi: Sync {
    /// The setup page's `add`/`enable`/`disable`/`remove` (`POST` handlers of the C's `gateway_main.c`). Persists the member list, applies the change to
    /// the running gateway asynchronously, and answers with the C's exact reply. Refused on the setup access point by the image (the reply text for
    /// that case is `tdongle_tailnet_members::command::text`).
    fn member_action(&self, action: &MemberAction) -> Reply;
    /// The `/status` JSON body, byte-compatible with the C, in chunks of at most 256 bytes. False if the sink refused a chunk (client went away).
    fn render_status(&self, sink: &mut dyn ChunkSink) -> bool;
    /// A serial command the tailnet mode owns (`route`, `members`, `memory`, `inbound`, ... and the extra lines of `status`). Returns false if the line
    /// is not one of its commands, so the image's own dispatcher continues.
    fn serial_command(&self, line: &str, out: &mut dyn core::fmt::Write) -> bool;
    /// The serial `status` lines the tailnet mode appends (new lines only; the Android parser's first block belongs to the image).
    fn serial_status_extra(&self, out: &mut dyn core::fmt::Write);
    /// The number of memberships that are enabled and the number that have a working tunnel, for the LCD and the status light.
    fn counts(&self) -> MemberCounts;
}

/// Summary for the front panel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberCounts {
    /// Memberships stored.
    pub configured: u8,
    /// Memberships enabled.
    pub enabled: u8,
    /// Memberships with control up and a netmap applied.
    pub connected: u8,
    /// Peers with a live WireGuard session, all memberships.
    pub tunnels: u8,
}
