//! The receive hook: every frame from the radio is offered to an [`RxTap`] before the stack sees it, and [`NaptTap`] is the one that runs the NAPT
//! inbound path.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use tdongle_tailnet_types::{Entropy, Millis};
use tdongle_tailnet_usbnet::napt::{Napt, NaptConfig, Verdict, WifiAddr};

use crate::info::Ipv4Cfg;

/// Why a tap consumed a frame without delivering it anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapDrop {
    /// The tap refused the frame with a reply the mux cannot originate (NAPT inbound reject).
    Rejected,
    /// The tap dropped the frame (a spoof, a malformed packet).
    Dropped,
}

/// The tap's decision for one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum TapVerdict {
    /// Not the tap's: the stack gets the frame unchanged (the tap must not have modified it).
    Stack,
    /// The IPv4 packet `frame[offset..offset + len]` (rewritten in place by the tap) belongs to the USB host: queue it for [`crate::RawPort::next_to_host`].
    ToHost {
        /// Offset of the IP header in the frame.
        offset: usize,
        /// IP packet length.
        len: usize,
    },
    /// Consumed and counted by the mux; neither the stack nor the host sees it.
    Dropped(TapDrop),
}

/// The inbound decision. The mux calls it for every **IPv4 frame addressed to the station's own MAC whose IP header the mux found consistent**
/// (broadcast, multicast, ARP and everything else never reach it). `frame` is the whole Ethernet frame; the tap may rewrite it in place.
pub trait RxTap {
    /// Decide what happens to `frame`.
    fn classify(&mut self, now: Millis, frame: &mut [u8]) -> TapVerdict;
    /// The association ended or changed: forget every flow.
    fn reset(&mut self) {}
    /// The stack's IPv4 configuration changed (`None`: unconfigured).
    fn config_changed(&mut self, _cfg: Option<Ipv4Cfg>) {}
}

/// A tap that passes everything to the stack (a gateway without NAPT).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTap;

impl RxTap for NoTap {
    fn classify(&mut self, _now: Millis, _frame: &mut [u8]) -> TapVerdict {
        TapVerdict::Stack
    }
}

/// The NAT table shared between the receive path (the mux's [`NaptTap`], in the stack's task) and the transmit path (the runtime, which calls
/// [`Napt::outbound`] on the host's packets). A critical-section mutex: every operation is a few microseconds (checksums are patched
/// incrementally, nothing is copied).
#[derive(Debug)]
pub struct SharedNapt<const N: usize>(Mutex<CriticalSectionRawMutex, RefCell<Napt<N>>>);

impl<const N: usize> SharedNapt<N> {
    /// A NAT with the given constants, its port allocator seeded from `entropy`.
    pub fn new(cfg: NaptConfig, entropy: &mut dyn Entropy) -> Self {
        SharedNapt(Mutex::new(RefCell::new(Napt::new(cfg, entropy))))
    }
    /// Run `f` on the table. Do not call it from inside another `with` of the same table.
    pub fn with<R>(&self, f: impl FnOnce(&mut Napt<N>) -> R) -> R {
        self.0.lock(|n| f(&mut n.borrow_mut()))
    }
    /// [`Napt::outbound`]: translate a packet from the host (then give it to [`crate::RawPort::send`] on `Verdict::Forward`).
    pub fn outbound(&self, now: Millis, pkt: &mut [u8]) -> Verdict {
        self.with(|n| n.outbound(now, pkt))
    }
    /// Keep a local socket's port out of the mapped range (see [`Napt::reserve_local_port`]).
    pub fn reserve_local_port(&self, proto: tdongle_tailnet_usbnet::napt::Proto, port: u16) -> bool {
        self.with(|n| n.reserve_local_port(proto, port))
    }
    /// Undo [`SharedNapt::reserve_local_port`].
    pub fn release_local_port(&self, proto: tdongle_tailnet_usbnet::napt::Proto, port: u16) {
        self.with(|n| n.release_local_port(proto, port));
    }
}

/// The ready [`RxTap`]: runs [`Napt::inbound`] on the shared table. The mux sets the NAT's Wi-Fi address from the stack's configuration and flushes it
/// on re-association.
#[derive(Debug)]
pub struct NaptTap<'a, const N: usize> {
    napt: &'a SharedNapt<N>,
}

impl<'a, const N: usize> NaptTap<'a, N> {
    /// A tap over `napt`.
    pub const fn new(napt: &'a SharedNapt<N>) -> Self {
        NaptTap { napt }
    }
}

impl<const N: usize> RxTap for NaptTap<'_, N> {
    fn classify(&mut self, now: Millis, frame: &mut [u8]) -> TapVerdict {
        if frame.len() <= crate::ETH_HDR {
            return TapVerdict::Stack;
        }
        match self.napt.with(|n| n.inbound(now, &mut frame[crate::ETH_HDR..])) {
            Verdict::Forward { len, .. } => TapVerdict::ToHost { offset: crate::ETH_HDR, len: usize::from(len) },
            Verdict::Local(_) => TapVerdict::Stack,
            Verdict::Reject(_) => TapVerdict::Dropped(TapDrop::Rejected),
            Verdict::Drop(_) => TapVerdict::Dropped(TapDrop::Dropped),
        }
    }
    fn reset(&mut self) {
        self.napt.with(|n| n.set_wifi(None));
    }
    fn config_changed(&mut self, cfg: Option<Ipv4Cfg>) {
        let w = cfg.map(|c| WifiAddr { ip: c.addr, mask: c.mask() });
        self.napt.with(|n| n.set_wifi(w));
    }
}
