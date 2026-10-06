//! A concrete instantiation of the runtime for measuring: the real `EmbassyNet`, stub platform / storage / USB, the engine over a RAM directory.
//!
//! Build with `--features size-probe`. On the device target:
//!
//! ```text
//! RUSTFLAGS="-Zprint-type-sizes" cargo +esp rustc -p tdongle-tailnet-runtime --lib --target xtensa-esp32s3-none-elf \
//!     -Zbuild-std=core,alloc --features size-probe | grep -E "async fn body of (control_slot|derp_slot|udp_slot|usb_pump|supervisor|engine_timer|link_watch|dns_upstream|run)"
//! ```
//!
//! and on the host the same function runs: [`future_sizes`] returns `size_of_val` of every top-level future. Nothing here is polled.

use crate::net::Net;
use crate::net_embassy::{EmbassyNet, GatewayBuffers};
use crate::shared::{Config, MAX_RUN, Shared};
use crate::sizes::*;
use crate::wifi::NoWifi;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use tdongle_tailnet_engine::RamDirectory;
use tdongle_tailnet_fw::{HeapProbe, Platform, Storage, StorageError, UsbFrames};
use tdongle_tailnet_types::Millis;

/// A platform with fixed answers.
#[derive(Debug, Default)]
pub struct StubPlatform;

struct StubHeap;
impl HeapProbe for StubHeap {
    fn free(&self) -> usize {
        100_000
    }
    fn largest_block(&self) -> usize {
        24_576
    }
    fn minimum_free(&self) -> usize {
        100_000
    }
}

impl Platform for StubPlatform {
    fn now_ms(&self) -> Millis {
        0
    }
    fn unix_seconds(&self) -> Option<u64> {
        None
    }
    fn fill_random(&self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn sta_mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 1]
    }
    fn heap(&self) -> &dyn HeapProbe {
        &StubHeap
    }
    fn console_line(&self, _: &str) {}
}

/// Storage that holds nothing.
#[derive(Debug, Default)]
pub struct StubStorage;

impl Storage for StubStorage {
    fn get(&mut self, _: &str, _: &str, _: &mut [u8]) -> Result<usize, StorageError> {
        Err(StorageError::NotFound)
    }
    fn set(&mut self, _: &str, _: &str, _: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }
    fn erase_namespace(&mut self, _: &str) -> Result<(), StorageError> {
        Ok(())
    }
}

/// A USB side that never receives.
#[derive(Debug, Default)]
pub struct StubUsb;

impl UsbFrames for StubUsb {
    async fn recv(&mut self, _: &mut [u8]) -> usize {
        core::future::pending().await
    }
    fn send(&mut self, _: &[u8]) -> bool {
        true
    }
    fn host_ready(&self) -> bool {
        true
    }
    fn link_generation(&self) -> u32 {
        0
    }
    fn set_carrier(&mut self, _: bool) {}
}

/// The directory of the probe's engine.
pub type ProbeDir = RamDirectory<3, 16, 32>;
/// The shared state of the probe.
pub type ProbeShared = Shared<CriticalSectionRawMutex, StubPlatform, StubStorage, ProbeDir>;

/// `size_of::<ProbeShared>()` (the statics: engine, slots with their workspaces and queues, host queue, lease, registry).
pub const SHARED_BYTES: usize = core::mem::size_of::<ProbeShared>();

/// Build the probe's shared state.
pub fn shared() -> ProbeShared {
    Shared::new(Config::tailscale(), StubPlatform, StubStorage, ProbeDir::new())
}

/// `size_of_val` of every top-level future of the runtime over `net`, in `crate::sizes::FUT_*` order. Nothing is polled.
pub fn future_sizes<N: Net>(sh: &ProbeShared, net: &N) -> [usize; FUTURES] {
    let mut usb = StubUsb;
    let wifi = NoWifi;
    let ctl: [_; MAX_RUN] = core::array::from_fn(|i| crate::control::control_slot(sh, i, net));
    let derp: [_; MAX_RUN] = core::array::from_fn(|i| crate::derp::derp_slot(sh, i, net));
    let udp: [_; MAX_RUN] = core::array::from_fn(|i| crate::udp::udp_slot(sh, i, net));
    let usb_f = crate::usb::usb_pump(sh, &mut usb, &wifi);
    let sup = crate::members::supervisor(sh);
    let timer = crate::tasks::engine_timer(sh);
    let link = crate::tasks::link_watch(sh, net, &wifi);
    let dns = crate::tasks::dns_upstream(sh, net);
    let mut out = [0; FUTURES];
    out[FUT_CONTROL] = core::mem::size_of_val(&ctl[0]);
    out[FUT_DERP] = core::mem::size_of_val(&derp[0]);
    out[FUT_UDP] = core::mem::size_of_val(&udp[0]);
    out[FUT_USB] = core::mem::size_of_val(&usb_f);
    out[FUT_SUPERVISOR] = core::mem::size_of_val(&sup);
    out[FUT_TIMER] = core::mem::size_of_val(&timer);
    out[FUT_LINK] = core::mem::size_of_val(&link);
    out[FUT_DNS] = core::mem::size_of_val(&dns);
    out
}

/// The whole joined `run` future of the probe: `size_of_val`.
pub fn run_future_bytes(sh: &ProbeShared, net: EmbassyNet) -> usize {
    let f = crate::runner::run(sh, net, StubUsb, NoWifi);
    core::mem::size_of_val(&f)
}

/// The socket buffer set of the probe (what the firmware starts with).
pub type ProbeBuffers = GatewayBuffers;

/// Called by nothing: its only job is to make the compiler instantiate the generic tasks for `-Zprint-type-sizes`.
#[doc(hidden)]
pub fn instantiate(sh: &'static ProbeShared, net: EmbassyNet) -> usize {
    let n = future_sizes(sh, &net);
    n.iter().sum::<usize>() + run_future_bytes(sh, net)
}
