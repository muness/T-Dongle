//! The Wi-Fi side of the USB host's Internet passthrough, as the runtime needs it.
//!
//! The runtime owns the USB side (Ethernet, ARP, DHCP, the alias router, DNS). The host's ordinary Internet traffic is NATed over the **station's own
//! address** by `tdongle_tailnet_usbnet::Napt`, and that needs the Wi-Fi driver while `embassy-net` owns it for the dongle's own sockets (control, DERP,
//! DISCO). Another crate, `tdongle-tailnet-wifimux`, splits the driver between the stack and the NAT; **it** implements [`WifiRaw`]:
//!
//! | `WifiRaw` | `tdongle-tailnet-wifimux` |
//! |---|---|
//! | [`WifiRaw::nat_outbound`] | `SharedNapt::outbound` (the same table its receive tap runs `inbound` on) |
//! | [`WifiRaw::try_send`] | `RawPort::try_send` (framed with the next hop's MAC by the mux) |
//! | [`WifiRaw::next_to_host`], [`WifiRaw::try_next_to_host`] | `RawPort::next_to_host`, `try_next_to_host` (the receive tap's translated replies) |
//! | [`WifiRaw::stack_config_changed`], [`WifiRaw::new_association`] | `InfoHandle::refresh`, `InfoHandle::new_association` |
//! | [`WifiRaw::nat_tick`], [`WifiRaw::pop_rst`] | `SharedNapt::with(|n| n.expire(now))`, `n.pop_rst()` |
//!
//! The runtime never touches the radio itself; a gateway without passthrough uses [`NoWifi`].

use core::future::pending;
use tdongle_tailnet_types::Millis;
use tdongle_tailnet_usbnet::napt::{DropReason, Verdict};
use tdongle_tailnet_usbnet::reply::RstNotice;

/// What the runtime needs from the Wi-Fi data path. All methods take `&self` (the implementation is shared with the stack's task).
#[allow(async_fn_in_trait)]
pub trait WifiRaw {
    /// Translate one IPv4 packet from the USB host for the Internet, in place (the NAT's outbound path). The verdict is the NAT's.
    fn nat_outbound(&self, now: Millis, packet: &mut [u8]) -> Verdict;
    /// Queue a translated packet (source = the station's address) for the radio. `false`: refused (queue full, no link); the implementation counts it.
    fn try_send(&self, l3: &[u8]) -> bool;
    /// Wait for the next packet the NAT translated back for the host (IP header first) and copy it into `buf`; returns its length. Cancel-safe.
    async fn next_to_host(&self, buf: &mut [u8]) -> usize;
    /// [`WifiRaw::next_to_host`] without waiting.
    fn try_next_to_host(&self, buf: &mut [u8]) -> Option<usize>;
    /// Run the NAT's timers (the runtime calls it every second; the NAT does nothing if called sooner than its own interval). Returns flows removed.
    fn nat_tick(&self, now: Millis) -> usize;
    /// The stack's IPv4 configuration changed (DHCP bound, renewed, lost): re-read it.
    fn stack_config_changed(&self);
    /// The station associated again: flows and next-hop entries of the old association are stale.
    fn new_association(&self);
    /// The next TCP reset the NAT owes an evicted flow (build with `RstNotice::to_host` / `to_remote`).
    fn pop_rst(&self) -> Option<RstNotice> {
        None
    }
}

/// No passthrough: every packet the host sends towards the Internet is dropped and counted by the NAT verdict `Drop(NoWifiAddress)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoWifi;

impl WifiRaw for NoWifi {
    fn nat_outbound(&self, _: Millis, _: &mut [u8]) -> Verdict {
        Verdict::Drop(DropReason::NoWifiAddress)
    }
    fn try_send(&self, _: &[u8]) -> bool {
        false
    }
    async fn next_to_host(&self, _: &mut [u8]) -> usize {
        pending().await
    }
    fn try_next_to_host(&self, _: &mut [u8]) -> Option<usize> {
        None
    }
    fn nat_tick(&self, _: Millis) -> usize {
        0
    }
    fn stack_config_changed(&self) {}
    fn new_association(&self) {}
}
