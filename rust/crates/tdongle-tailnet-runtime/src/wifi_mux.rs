//! [`WifiRaw`] over `tdongle-tailnet-wifimux` (feature `wifimux`): the NAT table the mux's receive tap shares, the raw port, and the stack-configuration
//! handle, as one value the firmware passes to [`crate::run`].
//!
//! ```ignore
//! let (driver, port) = mux.split();                       // WifiMux<L2Driver, NaptTap<'static, 512>, 8, 16>
//! let (stack, runner) = embassy_net::new(driver, cfg, resources, seed);
//! let wifi = MuxWifi::new(port, napt /* &'static SharedNapt<512> */, stack /* StackInfo */);
//! spawner.spawn(runner_task(runner));
//! spawner.spawn(tailnet(run(SHARED, net, usb, wifi)));
//! ```

use crate::wifi::WifiRaw;
use tdongle_tailnet_types::Millis;
use tdongle_tailnet_usbnet::napt::Verdict;
use tdongle_tailnet_usbnet::reply::RstNotice;
use tdongle_tailnet_wifimux::{InfoHandle, RawPort, SharedNapt, StackInfo};

/// The mux as the runtime's Wi-Fi data path. `N` NAT flows, `TXQ` / `RXQ` mux queue slots, `S` the stack (anything that reports its IPv4 configuration:
/// `embassy_net::Stack` with `tdongle-tailnet-wifimux/embassy-net`).
pub struct MuxWifi<'a, S: StackInfo, const N: usize, const TXQ: usize, const RXQ: usize> {
    port: RawPort<'a, TXQ, RXQ>,
    info: InfoHandle<'a, TXQ, RXQ>,
    napt: &'a SharedNapt<N>,
    stack: S,
}

impl<S: StackInfo, const N: usize, const TXQ: usize, const RXQ: usize> core::fmt::Debug for MuxWifi<'_, S, N, TXQ, RXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MuxWifi")
    }
}

impl<'a, S: StackInfo, const N: usize, const TXQ: usize, const RXQ: usize> MuxWifi<'a, S, N, TXQ, RXQ> {
    /// Build it from the pieces `WifiMux::split` and the NAT give.
    pub fn new(port: RawPort<'a, TXQ, RXQ>, napt: &'a SharedNapt<N>, stack: S) -> Self {
        let info = port.info();
        info.refresh(&stack);
        MuxWifi { port, info, napt, stack }
    }
}

impl<S: StackInfo, const N: usize, const TXQ: usize, const RXQ: usize> WifiRaw for MuxWifi<'_, S, N, TXQ, RXQ> {
    fn nat_outbound(&self, now: Millis, packet: &mut [u8]) -> Verdict {
        self.napt.outbound(now, packet)
    }
    fn try_send(&self, l3: &[u8]) -> bool {
        self.port.try_send(l3).is_ok()
    }
    async fn next_to_host(&self, buf: &mut [u8]) -> usize {
        self.port.next_to_host(buf).await
    }
    fn try_next_to_host(&self, buf: &mut [u8]) -> Option<usize> {
        self.port.try_next_to_host(buf)
    }
    fn nat_tick(&self, now: Millis) -> usize {
        self.napt.with(|n| n.expire(now))
    }
    fn stack_config_changed(&self) {
        self.info.refresh(&self.stack);
    }
    fn new_association(&self) {
        self.info.new_association();
    }
    fn pop_rst(&self) -> Option<RstNotice> {
        self.napt.with(|n| n.pop_rst())
    }
}
