//! [`run`]: the single entry point. It joins every task of the runtime into **one future** (the firmware spawns it once on the thread executor) and
//! records `size_of_val` of every top-level future in [`Shared::fut_bytes`] before the first poll.
//!
//! ```text
//! run = join( control x MAX_RUN, derp x MAX_RUN, udp x MAX_RUN,          one future each per membership slot, idle (and small) when the slot is free
//!             usb, supervisor, engine timer, link watch, dns upstream )  one each for the whole gateway
//! ```
//!
//! A `join` polls its parts when the task is woken; the parts register their own wakers (queues, signals, timers, sockets), so an idle gateway costs no
//! CPU. The firmware may also spawn the parts separately on an executor of its own through the `pub` task functions of this crate, at the price of a
//! static per task.

use crate::control::control_slot;
use crate::derp::derp_slot;
use crate::net::Net;
use crate::shared::{MAX_RUN, Shared};
use crate::sizes::*;
use crate::tasks::{dns_upstream, engine_timer, link_watch};
use crate::udp::udp_slot;
use crate::usb::usb_pump;
use crate::wifi::WifiRaw;
use core::sync::atomic::Ordering;
use embassy_futures::join::{join_array, join5};
use embassy_sync::blocking_mutex::raw::RawMutex;
use tdongle_tailnet_engine::PeerDirectory;
use tdongle_tailnet_fw::{Platform, Storage, UsbFrames};

/// Build the joined future and record the sizes of its parts. A plain function, not an `async fn`: the arrays of per-slot futures are moved into the join
/// at once, so they exist once (a local of an `async fn` that is moved out before an `.await` still reserves its space in the generator).
fn build<'a, R, P, S, D, N, U, W>(sh: &'a Shared<R, P, S, D>, net: &'a N, usb: &'a mut U, wifi: &'a W) -> impl core::future::Future + 'a
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
    U: UsbFrames,
    W: WifiRaw,
{
    let ctl: [_; MAX_RUN] = core::array::from_fn(|i| control_slot(sh, i, net));
    let derp: [_; MAX_RUN] = core::array::from_fn(|i| derp_slot(sh, i, net));
    let derpx: [_; MAX_RUN] = core::array::from_fn(|i| crate::derp::derp_extra(sh, i, net));
    let udp: [_; MAX_RUN] = core::array::from_fn(|i| udp_slot(sh, i, net));
    let usb_f = usb_pump(sh, usb, wifi);
    let sup = crate::members::supervisor(sh);
    let timer = engine_timer(sh);
    let link = link_watch(sh, net, wifi);
    let dns = dns_upstream(sh, net);
    let set = |i: usize, b: usize| sh.fut_bytes[i].store(b as u32, Ordering::Relaxed);
    set(FUT_CONTROL, core::mem::size_of_val(&ctl[0]));
    set(FUT_DERP, core::mem::size_of_val(&derp[0]));
    set(FUT_UDP, core::mem::size_of_val(&udp[0]));
    set(FUT_USB, core::mem::size_of_val(&usb_f));
    set(FUT_SUPERVISOR, core::mem::size_of_val(&sup));
    set(FUT_TIMER, core::mem::size_of_val(&timer));
    set(FUT_LINK, core::mem::size_of_val(&link));
    set(FUT_DNS, core::mem::size_of_val(&dns));
    sh.net_member_bytes.store(net.member_buffer_bytes() as u32, Ordering::Relaxed);
    let all = join5(join_array(ctl), join_array(derp), join_array(udp), embassy_futures::join::join5(usb_f, sup, timer, link, dns), join_array(derpx));
    set(FUT_RUN, core::mem::size_of_val(&all));
    all
}

/// Run the tailnet gateway forever. `net` is the network (embassy-net on the device), `usb` the NCM data interface, `wifi` the Wi-Fi data path for the
/// host's Internet passthrough ([`crate::wifi::NoWifi`] for none). The platform and storage are in `sh` (constructed with [`Shared::new`]) so that
/// `TailnetApi` can reach them without a task.
pub async fn run<R, P, S, D, N, U, W>(sh: &Shared<R, P, S, D>, net: N, mut usb: U, wifi: W)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
    U: UsbFrames,
    W: WifiRaw,
{
    let _ = build(sh, &net, &mut usb, &wifi).await;
}
