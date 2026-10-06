//! The mux's own first look at a received frame: Ethernet and IPv4 sanity, nothing stateful. A pure function (the fuzz target and the property tests
//! call it directly).

use tdongle_tailnet_usbnet::wire::{ETHERTYPE_ARP, ETHERTYPE_IPV4, Mac, mac_is_group, rd16, rd32};

use crate::ETH_HDR;

/// Why the mux dropped a received frame (every variant has a counter, ADR 0001 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxDrop {
    /// Shorter than an Ethernet header.
    Runt,
    /// Longer than [`crate::FRAME_MAX`].
    Oversize,
    /// A unicast frame for another station.
    NotForUs,
    /// The source address is a group address.
    BadSource,
    /// An IPv4 frame whose header or total length does not fit the frame.
    BadIpv4,
    /// The tap refused the frame (see [`crate::TapDrop::Rejected`]).
    TapRejected,
    /// The tap dropped the frame (see [`crate::TapDrop::Dropped`]).
    TapDropped,
    /// The tap named a range outside the frame (a tap bug; the frame is dropped, never delivered).
    TapBadRange,
    /// The tap delivered to the host but the queue towards it is full (the radio is never backpressured by a slow host).
    HostQueueFull,
}

impl RxDrop {
    /// Number of variants.
    pub const COUNT: usize = 9;
    /// Dense index (exhaustive).
    pub const fn index(self) -> usize {
        match self {
            RxDrop::Runt => 0,
            RxDrop::Oversize => 1,
            RxDrop::NotForUs => 2,
            RxDrop::BadSource => 3,
            RxDrop::BadIpv4 => 4,
            RxDrop::TapRejected => 5,
            RxDrop::TapDropped => 6,
            RxDrop::TapBadRange => 7,
            RxDrop::HostQueueFull => 8,
        }
    }
}

/// What a received frame is, to the mux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum RxClass {
    /// ARP: snooped, then given to the stack.
    Arp,
    /// IPv4 with a consistent header. `unicast` is true when addressed to the station's own MAC (only those are offered to the tap).
    Ipv4 {
        /// Addressed to our MAC (not broadcast or multicast).
        unicast: bool,
        /// Source MAC.
        src_mac: Mac,
        /// Source IP address.
        src_ip: u32,
        /// A fragment (MF set or a nonzero offset): counted, and passed to the tap like any other packet.
        fragment: bool,
    },
    /// Any other EtherType (IPv6, EAPOL): the stack gets it.
    Other,
    /// Dropped.
    Drop(RxDrop),
}

/// Classify `frame` for a station with Ethernet address `local`. Never panics, whatever the bytes.
pub fn classify_rx(frame: &[u8], local: &Mac) -> RxClass {
    if frame.len() < ETH_HDR {
        return RxClass::Drop(RxDrop::Runt);
    }
    if frame.len() > crate::FRAME_MAX {
        return RxClass::Drop(RxDrop::Oversize);
    }
    let dst: Mac = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
    let src: Mac = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
    if mac_is_group(&src) {
        return RxClass::Drop(RxDrop::BadSource);
    }
    let unicast = dst == *local;
    if !unicast && !mac_is_group(&dst) {
        return RxClass::Drop(RxDrop::NotForUs);
    }
    match rd16(frame, 12) {
        ETHERTYPE_ARP => RxClass::Arp,
        ETHERTYPE_IPV4 => {
            let p = &frame[ETH_HDR..];
            if p.len() < 20 || p[0] >> 4 != 4 {
                return RxClass::Drop(RxDrop::BadIpv4);
            }
            let ihl = usize::from(p[0] & 15) * 4;
            let total = usize::from(rd16(p, 2));
            if ihl < 20 || total < ihl || total > p.len() {
                return RxClass::Drop(RxDrop::BadIpv4);
            }
            let ff = rd16(p, 6);
            RxClass::Ipv4 { unicast, src_mac: src, src_ip: rd32(p, 12), fragment: ff & 0x3fff != 0 }
        }
        _ => RxClass::Other,
    }
}
