//! The Wi-Fi data-path multiplexer of the tailnet gateway.
//!
//! # The problem
//!
//! In tailnet mode `embassy-net` (smoltcp) owns the Wi-Fi station's [`embassy_net_driver::Driver`] for the device's own sockets (control TCP, DERP,
//! DISCO/STUN/WireGuard UDP, DNS, DHCP). The USB host's ordinary Internet traffic is NATed over the **same** interface by
//! `tdongle_tailnet_usbnet::Napt`, which is L3-only: somebody must frame its output for the radio and hand it the radio's frames first. The C did both
//! inside lwIP. Here:
//!
//! ```text
//!   USB side (runtime)                          this crate                         radio D
//!   host frame -> Napt::outbound -> RawPort::send --TX queue--+                     
//!                                                              +--> StackDriver::transmit/link_state --> D::transmit
//!   stack (embassy-net Runner) <---- StackDriver::receive <----+--- RxTap (NaptTap: Napt::inbound) <----- D::receive
//!   host <- frame <- RawPort::next_to_host <--host queue-------+      (a match is rewritten and queued for the host,
//!                                                                      everything else is the stack's, unchanged)
//! ```
//!
//! # No pump task
//!
//! [`WifiMux::split`] gives a [`StackDriver`] (what `embassy_net::new` takes) and a [`RawPort`]. **The radio is driven only by the stack's own polling**:
//! the `embassy_net::Runner` calls `receive`, `transmit` and `link_state` whenever it is woken, and the mux makes sure it is woken for everything that
//! concerns it:
//!
//! * RX: every call to `Driver::receive` pulls up to [`RX_BURST`] frames from the radio. NAT replies are queued for the host (and wake the host task);
//!   the first frame for the stack is copied into a one-frame staging slot and returned; the radio's own waker (registered with the stack's `cx`)
//!   wakes the Runner when more arrive. Stopping with frames left re-wakes the Runner (a NAT flood gets [`RX_BURST`] frames per turn, the stack's timers
//!   and egress run between turns).
//! * TX: [`RawPort::send`] queues the packet and wakes the Runner (the mux stores the Runner's waker on every call). `link_state` is called once at the
//!   end of every poll: it frames and sends queued NAT traffic ([`TX_BURST`] frames), asks for the next hop's MAC when unknown, and registers a timer
//!   waker (the way embassy-net itself does) while an ARP request is outstanding.
//! * Fairness: the stack's `transmit` hands out the radio's token directly. After the stack took a token the next token goes to the NAT first
//!   (alternation), so a stack that always has something to send cannot starve it. NAT traffic goes out in `link_state` only when the stack did not
//!   ask for a token it did not get (`owed`), so a NAT flood cannot starve the stack. Both queues are bounded; a full NAT queue refuses with
//!   [`TxDrop::QueueFull`] (or `send` waits), a full host queue drops and counts ([`RxDrop::HostQueueFull`]): the radio is never backpressured by the USB side.
//!
//! The only requirement on the runtime is that the `embassy_net::Runner` runs (it must anyway) and that something drains [`RawPort::next_to_host`].
//!
//! # Next hop
//!
//! The NAT's packets leave to the lease's gateway (or to the destination itself when it is on the station's subnet; subnet and limited broadcasts and
//! IPv4 multicast get their group MACs). The gateway's MAC is learned by **snooping** (an ARP packet addressed to us; any IPv4 frame whose source is the
//! gateway's IP) and by the mux's **own ARP requests** (`tdongle_tailnet_usbnet::arp::Neighbors`: five requests one second apart, 300 s ageing, refresh
//! at 285 s). The TX queue is the hold queue: the packet at its head waits for the answer, at most five seconds, then it is dropped and counted
//! ([`TxDrop::ArpFailed`]); packets behind it wait too (one next hop in practice). The mux never answers ARP for the station's address: the stack does.
//!
//! # What the runtime fills
//!
//! [`InfoHandle`] (from [`RawPort::info`]): [`InfoHandle::set_config`] or [`InfoHandle::refresh`] with the stack's IPv4 configuration whenever it changes
//! (with the `embassy-net` feature `embassy_net::Stack` implements [`StackInfo`]), and [`InfoHandle::new_association`] on every Wi-Fi association. A
//! different address or a new association clears the neighbour table and the queued NAT packets (counted [`TxDrop::Flushed`]) and tells the tap to
//! forget its flows ([`RxTap::reset`]); the radio's link going down does the same by itself.
//!
//! # Ports: the one rule for the runtime
//!
//! NAPT maps host flows to ports of the station's address; a mapped port must not collide with a local socket's. The runtime calls
//! [`SharedNapt::reserve_local_port`] for every UDP/TCP port the stack binds (WireGuard's listen port, DISCO/STUN sockets, a TCP listener) and
//! `release_local_port` when it closes. embassy-net hands out ephemeral client ports sequentially from a seeded start in 1025..=65535, which overlaps the
//! NAT's mapped range (49152..=61439): the runtime should bind the stack's client sockets itself (`TcpSocket::connect` with a local endpoint it
//! picked below 49152, or `UdpSocket::bind`) and reserve the ones above, or move `NaptConfig::port_start/port_end` away from what the stack uses. A
//! collision is cheap by construction: the NAT only takes an inbound packet whose remote address and port match the flow, everything else goes to the
//! stack (`LocalReason::RemoteMismatch`/`NoMapping`), so only a reply from the very same remote endpoint to the very same port is lost.
//!
//! # What the firmware author supplies
//!
//! An `embassy_net_driver::Driver` (0.2) for the station. esp-radio 1.0.0-beta.1 **already implements it** for `esp_radio::wifi::Interface`
//! (`Interface::station()`, `src/wifi/mod.rs` `embassy_02` module, enabled by the `wifi` feature, which pulls `embassy-net-driver` 0.2 and `xarxa-driver`;
//! it is a driver for "up to three latest versions" of the trait). That implementation is **not** what this mux should run on, for the S1 reasons
//! (`rust/spikes/s1-wifi-l2/FINDINGS.md`): `receive()` only yields when a TX credit is also free (RX is coupled to TX credit; the credit leaks when the
//! driver drops frames on a link change and nothing resets it), `consume` zero-fills an `MTU`-sized stack buffer per frame and **panics** for a frame
//! longer than `ESP_RADIO_CONFIG_WIFI_MTU` (default 1492; set 1514), and there is no hook for the tx-done callback. The mux works on it (tokens are
//! gated only by `receive`/`transmit` returning `None`, wakers are registered on the `cx` it is given) but inherits the wedge. The adapter to write
//! is the C's (`firmware/src/l2.rs`) as a `Driver`:
//!
//! ```ignore
//! struct L2Driver { mac: [u8; 6] }                       // the rest is statics fed by the driver's callbacks
//! impl embassy_net_driver::Driver for L2Driver {
//!     type RxToken<'a> = L2Rx; type TxToken<'a> = L2Tx;
//!     fn receive(&mut self, cx: &mut Context<'_>) -> Option<(L2Rx, L2Tx)> {
//!         RX_WAKER.register(cx.waker());                 // woken by rx_cb after it pushes
//!         let frame = RX_RING.pop()?;                    // rx_cb copies the frame out of the driver buffer and frees it at once (no TX credit needed)
//!         Some((L2Rx(frame), self.tx_token(cx)?))        // or a TX token that does not borrow credit: see below
//!     }
//!     fn transmit(&mut self, cx: &mut Context<'_>) -> Option<L2Tx> {
//!         TX_WAKER.register(cx.waker());                 // woken by tx_done (and by link_changed)
//!         PINS.room(now_ms()).then_some(L2Tx)            // the budget of tdongle-wifi-budget (limit 6 in flight, heap floor)
//!     }
//!     fn link_state(&mut self, cx: &mut Context<'_>) -> LinkState { LINK_WAKER.register(cx.waker()); /* Connected? */ }
//!     fn capabilities(&self) -> Capabilities { /* MTU 1514, no checksum offload (esp-wifi-sys has none): Checksum::Both */ }
//!     fn hardware_address(&self) -> HardwareAddress { HardwareAddress::Ethernet(self.mac) }
//! }
//! // L2Tx::consume(len, f): fill a [u8; 1514] on the stack, f(&mut buf[..len]), then l2::tx(&buf[..len]) (PINS.tx + esp_wifi_internal_tx).
//! ```
//!
//! The three wakers are `embassy_sync::waitqueue::AtomicWaker`s woken from the callbacks (`rx_cb` after a successful push, `tx_done`,
//! `link_changed`); `PINS.flush()` and a wake of all three on every link change. The `rx_cb` ring must be deeper than [`RX_BURST`] (8 frames) so one
//! pull does not empty it into a hole; when it overflows the callback drops and counts (the radio keeps no frame for us). With that adapter RX never waits for TX.
//!
//! Wiring (sketch):
//!
//! ```ignore
//! static MUX: StaticCell<WifiMux<L2Driver, NaptTap<'static, 512>, 8, 16>> = StaticCell::new();
//! static NAPT: StaticCell<SharedNapt<512>> = StaticCell::new();
//! let napt: &'static SharedNapt<512> = NAPT.init(SharedNapt::new(NaptConfig::C, &mut entropy));
//! let mux = MUX.init(WifiMux::new(L2Driver::new(), NaptTap::new(napt))?);
//! let (driver, port) = mux.split();
//! let (stack, runner) = embassy_net::new(driver, cfg, resources, seed);      // runner.run() is the only pump
//! // task A (config): loop { stack.wait_config_up().await; port.info().refresh(&stack); ... wait for the config to change ... }
//! // task B (USB -> Wi-Fi): host frame -> UsbNet::host_frame -> Verdict::Forward -> port.send(&frame[off..off + len]).await
//! // task C (Wi-Fi -> USB): let n = port.next_to_host(&mut buf).await; put the Ethernet header (host MAC) on buf[..n]; send on the NCM IN endpoint
//! // task D (timers): napt.with(|n| n.expire(now)) every 2 s; napt.with(|n| n.pop_rst()) for the RSTs of evicted flows (send to both ends via port / USB)
//! ```
//!
//! # Memory
//!
//! Queues are inline arrays of 1500-byte slots (1504 B with the length): [`WifiMux::QUEUE_BYTES`] = (`TXQ` + `RXQ`) x 1500. Measured on xtensa
//! (32-bit): the shared state `Core<TXQ, RXQ>` is 3,600 B for 1+1 slots, 5,096 B for 2+1 and **36,640 B for 8+16** (about 600 B fixed: the 4-entry
//! ARP table, counters, wakers, configuration); plus the 1,514-byte staging frame in the stack side. `WifiMux<_, _, 8, 16>` is about 38.2 KB
//! (38,224 B on a 64-bit host with `NoTap` and a zero-size driver). `NaptTap` is 4 bytes; the `SharedNapt<512>` it points to is 19,136 B.
//! The firmware's `CriticalSectionRawMutex` needs a `critical-section` implementation (esp-hal provides one).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

/// Largest Ethernet frame (without FCS) the mux handles.
pub const FRAME_MAX: usize = 1514;
/// Ethernet header length.
pub const ETH_HDR: usize = 14;
/// Largest IPv4 packet that fits a frame (1500).
pub const L3_MAX: usize = FRAME_MAX - ETH_HDR;

pub mod info;
mod mux;
mod ring;
pub mod rx;
mod state;
pub mod tap;

pub use crate::state::{MuxStats, TxDrop};
pub use info::{Ipv4Cfg, StackInfo};
pub use mux::{InfoHandle, MuxError, MuxRxToken, MuxTxToken, RX_BURST, RawPort, StackDriver, TX_BURST, WifiMux};
pub use rx::{RxClass, RxDrop, classify_rx};
pub use tap::{NaptTap, NoTap, RxTap, SharedNapt, TapDrop, TapVerdict};

/// Fuzz entry: the pure classifier plus the mux's receive bookkeeping on arbitrary bytes. Hidden: used by `fuzz/` and the tests.
#[doc(hidden)]
pub mod fuzzing {
    use crate::info::Ipv4Cfg;
    use crate::rx::RxClass;
    use crate::state::Core;

    /// A bare core with a fixed MAC and configuration, no driver.
    pub struct Bench(Core<4, 4>);

    impl core::fmt::Debug for Bench {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Bench").finish_non_exhaustive()
        }
    }

    impl Default for Bench {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Bench {
        /// A bench with station 192.168.1.50/24, gateway 192.168.1.1, MAC 02:00:00:00:00:01, link up.
        pub fn new() -> Self {
            let mut c = Core::new([2, 0, 0, 0, 0, 1]);
            c.set_want(Some(Ipv4Cfg { addr: 0xC0A8_0132, gateway: Some(0xC0A8_0101), prefix: 24 }));
            let _ = c.take_sync();
            let _ = c.set_link(true);
            Bench(c)
        }
        /// One received frame through classification and snooping.
        pub fn rx(&mut self, now: u64, frame: &[u8]) -> RxClass {
            let r = self.0.rx_pre(now, frame);
            match r {
                RxClass::Drop(_) => {}
                RxClass::Ipv4 { unicast: true, .. } => {
                    let _ = self.0.host_push(&frame[14..]);
                }
                RxClass::Ipv4 { .. } | RxClass::Arp | RxClass::Other => self.0.count_to_stack(),
            }
            r
        }
        /// One packet from the runtime.
        pub fn send(&mut self, pkt: &[u8]) -> Result<(), crate::TxDrop> {
            self.0.tx_push(pkt, None)
        }
        /// Advance the transmit side one step; returns what it decided as text-free numbers (0 idle, 1 wait, 2 arp, 3 frame).
        pub fn tx_step(&mut self, now: u64) -> u8 {
            match self.0.tx_plan(now) {
                crate::state::TxPlan::Idle => 0,
                crate::state::TxPlan::Wait(_) => 1,
                crate::state::TxPlan::Arp(_) => 2,
                crate::state::TxPlan::Frame(mac) => {
                    let Some(n) = self.0.head_frame_len() else { return 3 };
                    let mut buf = [0u8; crate::FRAME_MAX];
                    self.0.pop_frame(&mut buf[..n], mac);
                    3
                }
            }
        }
        /// Every received frame ended as exactly one of: dropped, to the stack, to the host (the invariant the fuzzers check).
        pub fn accounted(&self) -> bool {
            let s = self.0.snapshot();
            let dropped: u32 = s.rx_dropped.iter().map(|c| c.get()).sum();
            s.rx_frames.get() == dropped + s.rx_to_stack.get() + s.rx_to_host.get()
        }
    }
}
