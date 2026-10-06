//! The bridge's sizing constants: the values `alternative/tailnet/main/gateway_main.c` (bridge mode) and `gateway.h` set, with the compile-time
//! assertions that tie them together written down again, so a change to one that breaks the argument of ADR 0022/0023 does not build.

use tdongle_bridge::{HOST_QUEUE_LIMIT, HOST_SLOTS, SLOT_BYTES};
use tdongle_usb_ring::{BRIDGE_BASE_SLABS, BRIDGE_MAX_CHUNKS, CHUNK_SLABS, SLAB_BYTES};
use tdongle_wifi_budget::{GATEWAY_WIFI_TX_BAND_MAX, GATEWAY_WIFI_TX_POOL, ML_HB_FLOOR};

/// Free internal heap that must remain after the USB ring grows (`GATEWAY_USB_TX_FLOOR_FREE` = `ML_HB_FLOOR`): the one elastic floor.
pub const USB_TX_FLOOR_FREE: usize = ML_HB_FLOOR;
/// Largest free block that must exist before and after a growth (`GATEWAY_USB_TX_FLOOR_LARGEST` = `ML_ADM_LARGEST_BLOCK`): the steady largest
/// block measured 24,576 B; the TLS record buffer is about 16.7 KB.
pub const USB_TX_FLOOR_LARGEST: usize = 24_000;

/// Frames the radio is given at once in bridge mode (`GATEWAY_BRIDGE_WIFI_TX_INFLIGHT`): the TX block-ack window is 6, so 6 in flight is one full
/// aggregate; every frame beyond is queueing delay in front of every other packet (ADR 0023 amendment 2).
pub const WIFI_TX_INFLIGHT: u32 = 6;
/// `CONFIG_ESP_WIFI_TX_BA_WIN` in `sdkconfig.defaults`.
pub const WIFI_TX_BA_WIN: u32 = 6;

/// The ring worker's stack (`TX_WORKER_STACK` is 1,536 in C; Rust frames are larger, so this one is measured: the high-water mark is the
/// `bridge_usb_ring` / `worker_stack_free` evidence on the board).
pub const USB_TX_WORKER_STACK: usize = 3072;
/// The bridge forwarder's stack (`GATEWAY_BRIDGE_TASK_STACK`).
pub const BRIDGE_TASK_STACK: usize = 4096;

/// A full bridge ring may hold at most this much USB time (`GATEWAY_BRIDGE_RING_MAX_DRAIN_MS`): anything more is queueing delay on every packet.
const RING_MAX_DRAIN_MS: usize = 50;
/// What the USB bus carries in bytes per millisecond at the full-speed limit the C asserts against (7 Mbit/s).
const USB_BYTES_PER_MS: usize = 875;

const BRIDGE_TX_MAX_FRAMES: usize = BRIDGE_BASE_SLABS + BRIDGE_MAX_CHUNKS * CHUNK_SLABS;

const _: () = assert!(
    WIFI_TX_INFLIGHT as usize >= GATEWAY_WIFI_TX_BAND_MAX as usize
        && WIFI_TX_INFLIGHT as usize <= GATEWAY_WIFI_TX_POOL as usize
        && WIFI_TX_INFLIGHT >= WIFI_TX_BA_WIN,
    "the bridge's Wi-Fi TX allowance must hold the band and a full block-ack aggregate, within the pool"
);
const _: () = assert!(BRIDGE_TX_MAX_FRAMES >= 8, "the bridge ring configuration is outside what the ring supports");
const _: () = assert!(
    BRIDGE_TX_MAX_FRAMES * SLAB_BYTES / USB_BYTES_PER_MS <= RING_MAX_DRAIN_MS,
    "a full bridge ring would hold more than RING_MAX_DRAIN_MS of USB time: that is queueing delay on every packet"
);
const _: () = assert!(
    HOST_QUEUE_LIMIT as usize * SLOT_BYTES / USB_BYTES_PER_MS <= 6,
    "the host -> Wi-Fi standing queue must drain, at the USB OUT limit, in a few milliseconds: it is behind the host's own backpressure"
);
/// Boot-heap neutrality against the original bridge (ADR 0023): its permanent buffering was 32 pool frames of 1,524 B, its worker's 3,072 B stack
/// and a TCB. The new permanent buffering is the ring base, the ring worker, the host queue and the forwarder.
const _: () = assert!(
    BRIDGE_BASE_SLABS * SLAB_BYTES + USB_TX_WORKER_STACK + HOST_SLOTS * SLOT_BYTES + BRIDGE_TASK_STACK + 2 * 340 <= 32 * 1524 + 3072 + 340,
    "the bridge's permanent buffering (ring base, ring worker, host queue, forwarder) grew past what the original bridge held"
);
