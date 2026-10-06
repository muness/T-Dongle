//! Ingress policy in front of the router: which packets from which interface are routed, consumed or left to the IP stack, and the bounded
//! queue (depth and byte budget) that feeds the single routing consumer. Behaviour of the C's `gateway_host_input` / `gateway_process_host_input`
//! hook and `rt_queue_budget`.

use crate::packet::is_alias;
use crate::router::Router;
use crate::stats::{Extra, Stat};
use crate::{QUEUE_BYTES, QUEUE_BYTES_MIN, QUEUE_DEPTH, ROUTE_MTU};

/// Largest queue byte budget that the free heap allows: free internal heap above `reserve` (the one elastic floor, ADR 0022), never below two
/// full packets ([`QUEUE_BYTES_MIN`]), never above [`QUEUE_BYTES`].
pub const fn queue_budget(free_heap: usize, reserve: usize) -> u32 {
    let room = free_heap.saturating_sub(reserve);
    let room = if room < QUEUE_BYTES_MIN as usize { QUEUE_BYTES_MIN as usize } else { room };
    if room > QUEUE_BYTES as usize { QUEUE_BYTES } else { room as u32 }
}

/// Counting gate of the bounded ingress queue: at most [`QUEUE_DEPTH`] packets and at most `budget` bytes (queued plus held-for-fill) in
/// flight. It owns no packets; the runtime holds them (in pool slabs) and calls [`Self::admit`] before queueing and [`Self::release`] when the
/// consumer takes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressGate {
    packets: u32,
    bytes: u32,
    budget: u32,
}

impl Default for IngressGate {
    fn default() -> Self {
        Self::new()
    }
}

impl IngressGate {
    /// An empty gate with the full byte budget.
    pub const fn new() -> Self {
        Self { packets: 0, bytes: 0, budget: QUEUE_BYTES }
    }
    /// Set the byte budget (see [`queue_budget`]); packets already queued stay, nothing more is admitted above it.
    pub fn set_budget(&mut self, budget: u32) {
        self.budget = budget;
    }
    /// Try to account one packet of `len` bytes, with `held` bytes parked in the router's hold (they share the budget). `false` = refused, the
    /// caller drops the packet; nothing is left counted.
    pub fn admit(&mut self, len: usize, held: usize) -> bool {
        let len = len as u32;
        let ok = self.packets < QUEUE_DEPTH && self.bytes.saturating_add(len).saturating_add(held as u32) <= self.budget;
        if ok {
            self.packets += 1;
            self.bytes += len;
        }
        ok
    }
    /// The consumer took (or discarded) a queued packet of `len` bytes.
    pub fn release(&mut self, len: usize) {
        self.packets = self.packets.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(len as u32);
    }
    /// Packets queued.
    pub fn packets(&self) -> u32 {
        self.packets
    }
    /// Bytes queued.
    pub fn bytes(&self) -> u32 {
        self.bytes
    }
}

/// What the ingress hook knows about a packet before it is queued.
#[derive(Clone, Copy, Debug)]
pub struct IngressFacts<'a> {
    /// The first 20 bytes (a shorter packet is passed through).
    pub first: &'a [u8],
    /// Total length of the packet.
    pub len: usize,
    /// It arrived on the USB netif.
    pub from_usb: bool,
    /// From another interface: the destination is that interface's own address.
    pub to_input_addr: bool,
    /// From another interface: the TCP/UDP destination port, when the packet is TCP or UDP and has one.
    pub dport: Option<u16>,
}

/// The hook's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    /// Leave to the IP stack.
    PassThrough,
    /// Queue it for [`Router::host_packet`] (the gate accepted it; release the gate when the consumer takes it).
    Queue,
    /// Consumed and dropped (counted).
    Drop(IngressDrop),
}

/// Why the hook dropped a packet itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressDrop {
    /// A packet for the gateway's management address (192.168.77.1), or its HTTP/DNS port, that did not come from USB: only USB may reach them.
    Management,
    /// A packet to an alias address from an interface other than USB.
    ForeignAlias,
    /// Larger than the tunnel MTU without DF: dropped before queueing.
    OversizeNoDf,
    /// The gate refused it (depth or byte budget).
    QueueFull,
}

impl<const M: usize, const A: usize, const F: usize> Router<M, A, F> {
    /// The ingress hook as a pure function: classify one IPv4 packet, account it in `gate` and count the drops. The gateway management
    /// address is 192.168.77.1.
    pub fn ingress(&mut self, gate: &mut IngressGate, f: &IngressFacts<'_>) -> Ingress {
        if f.first.len() < 20 || f.len < 20 {
            return Ingress::PassThrough;
        }
        let dest = u32::from_be_bytes([f.first[16], f.first[17], f.first[18], f.first[19]]);
        if !f.from_usb {
            let management = dest == crate::USB_HOST_NET + 1 || (f.to_input_addr && matches!(f.dport, Some(80) | Some(53)));
            if management {
                self.note_extra(Extra::ManagementDrop);
                return Ingress::Drop(IngressDrop::Management);
            }
        }
        if !is_alias(dest) {
            return Ingress::PassThrough;
        }
        if !f.from_usb {
            self.note_extra(Extra::ForeignIngress);
            return Ingress::Drop(IngressDrop::ForeignAlias);
        }
        if f.len > ROUTE_MTU && f.first[6] & 0x40 == 0 {
            self.note(Stat::OversizeDrop);
            return Ingress::Drop(IngressDrop::OversizeNoDf);
        }
        if gate.admit(f.len, self.held_bytes()) {
            Ingress::Queue
        } else {
            self.note(Stat::QueueFull);
            Ingress::Drop(IngressDrop::QueueFull)
        }
    }
    /// Count an extra event.
    pub fn note_extra(&mut self, e: Extra) {
        self.stats_mut().bump_extra(e);
    }
}
