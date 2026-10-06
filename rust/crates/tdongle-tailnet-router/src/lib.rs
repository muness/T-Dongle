//! USB host <-> WireGuard tunnel forwarding engine of the T-Dongle tailnet gateway.
//!
//! # Model (what the C does, exactly)
//!
//! The router is **not** a general IPv4 gateway and **not** a source NAT of an arbitrary host to one address. The dongle presents the USB host
//! (192.168.77.2..254, the dongle is .1) with one *alias* address per tailnet peer, from 198.18.0.0/15 (RFC 2544 benchmarking space). DNS
//! answers with the alias (the `tdongle-tailnet-dns` crate); the host connects to it like to any host; this crate rewrites:
//!
//! * **USB -> tunnel** ([`Router::host_packet`]): destination alias -> the peer's tailnet address; source -> the tailnet address of the
//!   membership that owns the peer; source port -> a *mapped* port that encodes the flow slot and the USB link generation
//!   (`40000 + slot + 64 * ((generation - 1) % 300)`); TTL decremented; checksums updated incrementally (RFC 1624). A SYN's MSS is clamped
//!   to 1360. Several memberships coexist: the alias selects the membership, no route table is consulted.
//! * **tunnel -> USB** ([`Router::tunnel_packet`]): only an exact reply to a USB-originated flow of the same membership: source = the peer,
//!   destination = the membership's address, destination port = the flow's mapped port. Source -> the alias, destination -> the host,
//!   destination port -> the host's own port. TTL is left alone. Nothing else enters the USB side.
//! * Only **unfragmented IPv4 TCP and UDP**. ICMP, IPv6, fragments and IP options beyond header length are dropped. The only packet the router
//!   *originates* is ICMP "fragmentation needed" (type 3 code 4, next-hop MTU 1400, rate limited 1 per 50 ms) for an oversized DF packet.
//!   Ordinary Internet traffic of the host never reaches this crate ([`HostOutcome::PassThrough`]): the IP stack NATs it over Wi-Fi.
//!
//! # Time
//!
//! Every method that needs time takes `now: Millis` (monotonic ms). The C used microseconds; the only constants affected are 120 s flow
//! idle, 100 ms hold, 20 ms fill spacing, 50 ms ICMP spacing, 10 s negative cache, all unchanged in value.
//!
//! # Concurrency (replaces the C's RCU, portMUX and `members_lock`)
//!
//! A [`Router`] has one owner and every operation takes `&mut self`. The C needs a spin-protected table plus a two-bucket epoch RCU because the
//! USB consumer, the WireGuard decrypt task and the control task touch the tables concurrently and a membership may be destroyed under a packet
//! that has "pinned" it. Here the membership is data, not a pointer: a [`MemberSet`] snapshot (ids, addresses, readiness) that the control task
//! builds and the owner installs with [`Router::publish`] *between* two packets. A packet outcome names the membership by id
//! ([`HostOutcome::Forwarded::member`]); the runtime resolves the id to a WireGuard device when it sends, and a device that vanished in the
//! meantime is a counted `tunnel_reject`, not a use-after-free. There is no grace period to wait for: nothing can hold a reference across the
//! swap. Deployment: wrap the router in one `critical_section`/embassy `Mutex` (each call is bounded by a single in-place rewrite of at most
//! 1400 bytes and never blocks or allocates), or give it to one task and feed it by channels. No `unsafe`, no atomics, no locks inside.
//!
//! # Memory
//!
//! Everything is inline and sized by const generics ([`GatewayRouter`] = 16 memberships, 64 aliases, 64 flows). Packets are caller buffers
//! rewritten in place; the only copies are the hold (2 packets, 2048 bytes, arena inside the router) and the ICMP reply (built in the caller's
//! buffer). The ingress queue ([`IngressGate`]) and the packet [`pool`] are bounded and drop-and-count; nothing falls back to a heap.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod csum;
pub mod ingress;
pub mod outcome;
pub mod packet;
pub mod pool;
pub mod router;
pub mod stats;
pub mod tables;

pub use ingress::{Ingress, IngressDrop, IngressFacts, IngressGate, queue_budget};
pub use outcome::{Dir, HostDrop, HostOutcome, TunnelDrop, TunnelOutcome};
pub use router::{GatewayRouter, Member, MemberSet, Router};
pub use stats::{Extra, Stat, Stats};
pub use tables::{AliasCache, AliasRecord, Flow, FlowInReject, FlowTable};

/// Largest IPv4 packet the tunnel carries (`ROUTE_MTU`). Larger packets with DF get ICMP fragmentation-needed, without DF are dropped.
pub const ROUTE_MTU: usize = 1400;
/// MSS written into SYNs of both directions when larger (`ROUTE_MTU` - 40).
pub const MSS_CLAMP: u16 = 1360;
/// Ingress queue depth (`ROUTE_QUEUE_DEPTH`): one USB NTB carries about three full frames or tens of ACKs.
pub const QUEUE_DEPTH: u32 = 16;
/// Ingress queue byte budget ceiling (`ROUTE_QUEUE_BYTES`).
pub const QUEUE_BYTES: u32 = 16 * 1024;
/// Smallest budget the heap can shrink the queue to (`ROUTE_QUEUE_BYTES_MIN`): two full packets.
pub const QUEUE_BYTES_MIN: u32 = 2800;
/// Hold slots (`ROUTE_HOLD_SLOTS`).
pub const HOLD_SLOTS: usize = 2;
/// Hold bytes in all (`ROUTE_HOLD_BYTES`).
pub const HOLD_BYTES: usize = 2048;
/// Longest a packet waits for an alias fill (`ROUTE_HOLD_US` = 100 ms).
pub const HOLD_MS: u64 = 100;
/// Consumer fairness: after this many packets in a row from a never-empty queue it sleeps one tick (`ROUTE_BURST_PACKETS`).
pub const BURST_PACKETS: u32 = 32;
/// Packets one tunnel batch handles between two USB output lock acquisitions (`GATEWAY_TUNNEL_BATCH_MAX`).
pub const TUNNEL_BATCH_MAX: usize = 16;
/// Alias fill requests in flight (the C's four slots).
pub const FILL_SLOTS: usize = 4;
/// Minimum spacing of background fills (`ROUTE_FILL_SPACING_US`).
pub const FILL_SPACING_MS: u64 = 20;
/// How long a missing record is remembered as absent.
pub const FILL_NEGATIVE_MS: u64 = 10_000;
/// Minimum spacing of ICMP replies (`ROUTE_ICMP_SPACING_US`).
pub const ICMP_SPACING_MS: u64 = 50;
/// A flow idle this long is dead (`RT_FLOW_IDLE_US`).
pub const FLOW_IDLE_MS: u64 = 120_000;
/// First mapped source port (`RT_MAPPED_BASE`).
pub const MAPPED_BASE: u16 = 40_000;
/// Most USB link generations a mapped port distinguishes (`RT_MAPPED_GENERATIONS`).
pub const MAPPED_GENERATIONS_MAX: u32 = 300;
/// First alias address, 198.18.0.1 (`RT_ALIAS_BASE`).
pub const ALIAS_BASE: u32 = 0xc612_0001;
/// 198.18.0.0, the alias range's network.
pub const ALIAS_NET: u32 = 0xc612_0000;
/// Mask of the alias range 198.18.0.0/15.
pub const ALIAS_MASK: u32 = 0xfffe_0000;
/// 192.168.77.0, the USB network (the dongle is .1, the DHCP host .2).
pub const USB_HOST_NET: u32 = 0xc0a8_4d00;
