//! What the runtime costs in bytes, per membership and shared, measured with `size_of` / `size_of_val` (never asserted).
//!
//! Three kinds of figures, labelled the way the ADR labels them:
//!
//! * **M-host**: measured on the 64-bit host (`cargo test -p tdongle-tailnet-runtime -- sizes --nocapture`, and the host harness prints the full table).
//! * **M-elf**: measured on the device target (`RUSTFLAGS=-Zprint-type-sizes`, or the const asserts of `ELF_SIZES` below, checked by
//!   `cargo +esp check --target xtensa-esp32s3-none-elf -Zbuild-std=core,alloc`).
//! * **EST**: derived from fields (an estimate; the ADR says so).
//!
//! The task futures are generic over the `Net`, so their sizes are measured where the types are known: [`crate::run`] stores `size_of_val` of every
//! top-level future in [`crate::Shared::fut_bytes`] before polling anything, and [`member_sizes`] / [`shared_bytes`] read them.

use crate::shared::{MAX_RUN, Shared, Slot};
use core::sync::atomic::Ordering;
use embassy_sync::blocking_mutex::raw::RawMutex;
use tdongle_tailnet_admission::adm::MemberSizes;
use tdongle_tailnet_engine::PeerDirectory;
use tdongle_tailnet_fw::{Platform, Storage};

/// Index of the control task's future (one per slot) in [`Shared::fut_bytes`].
pub const FUT_CONTROL: usize = 0;
/// The DERP task's future (one per slot).
pub const FUT_DERP: usize = 1;
/// The UDP task's future (one per slot).
pub const FUT_UDP: usize = 2;
/// The USB task's future.
pub const FUT_USB: usize = 3;
/// The supervisor's future.
pub const FUT_SUPERVISOR: usize = 4;
/// The engine timer's future.
pub const FUT_TIMER: usize = 5;
/// The link watcher's future.
pub const FUT_LINK: usize = 6;
/// The DNS upstream task's future.
pub const FUT_DNS: usize = 7;
/// The whole joined `run` future.
pub const FUT_RUN: usize = 8;
/// Entries of [`Shared::fut_bytes`].
pub const FUTURES: usize = 9;

/// Names for the table, in index order.
pub const FUTURE_NAMES: [&str; FUTURES] =
    ["control (per slot)", "derp (per slot)", "udp (per slot)", "usb", "supervisor", "engine timer", "link watch", "dns upstream", "run (joined)"];

/// One future's size.
pub fn future_bytes<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, which: usize) -> usize {
    sh.fut_bytes[which].load(Ordering::Relaxed) as usize
}

/// Bytes of one slot's statics: queues, workspace, status, identity (`size_of::<Slot<R>>()`).
pub const fn slot_static_bytes<R: RawMutex>() -> usize {
    core::mem::size_of::<Slot<R>>()
}

/// What one membership costs the runtime, as `Params::rust` wants it (see the crate docs for what is and is not heap):
/// `control` = the control future and the session state its slot pins (the big buffers are leased from one gateway-wide set, [`StaticSizes::bulk`]); `peer_table` = the engine's per-membership record; `derp_link` = the DERP future
/// (which owns the link); `queues` = the slot's two egress queues plus the `Net`'s socket buffers; `misc` = the rest of the slot (status, identity).
pub fn member_sizes<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>) -> MemberSizes {
    let eng = tdongle_tailnet_engine::GatewayEngine::<D>::per_member_bytes();
    let slot = slot_static_bytes::<R>();
    let queues = crate::shared::UDP_Q + crate::shared::DERP_Q;
    let ws = core::mem::size_of::<tdongle_tailnet_ctl::SessionBuf>();
    MemberSizes {
        control: future_bytes(sh, FUT_CONTROL) + ws,
        peer_table: eng.in_engine,
        derp_link: future_bytes(sh, FUT_DERP),
        queues: queues + sh.net_member_bytes.load(Ordering::Relaxed) as usize + future_bytes(sh, FUT_UDP),
        wg_device: 0,
        misc: slot.saturating_sub(queues + ws),
    }
}

/// What the shared tasks cost (the first membership pays it in `Params::rust`).
pub fn shared_bytes<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>) -> usize {
    [FUT_USB, FUT_SUPERVISOR, FUT_TIMER, FUT_LINK, FUT_DNS].iter().map(|&i| future_bytes(sh, i)).sum::<usize>() + crate::shared::HOST_Q + crate::shared::DNS_Q
}

/// The sizes of the statics that do not depend on the generic parameters, for the memory table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticSizes {
    /// `ctl::Bulk`: the control sessions' big buffers; **pooled**, taken for a negotiation or a map message and given back (no static).
    pub bulk: usize,
    /// `ctl::SessionBuf`: what a control session keeps per membership.
    pub session_buf: usize,
    /// One slot's UDP egress queue.
    pub udp_q: usize,
    /// One slot's DERP egress queue.
    pub derp_q: usize,
    /// The host queue.
    pub host_q: usize,
    /// The DNS upstream queue.
    pub dns_q: usize,
    /// The largest TLS record lease (a maximal record body); **pooled**, normally a record is about 2 KB.
    pub lease: usize,
    /// The engine without its directory.
    pub engine: usize,
    /// One DERP link.
    pub derp_link: usize,
    /// The USB side (ARP, DHCP, Ethernet filter).
    pub usb_side: usize,
    /// The negotiation token.
    pub token: usize,
    /// The member registry.
    pub registry: usize,
    /// Slots in the static.
    pub slots: usize,
}

/// The static sizes on the compiling target.
pub const fn static_sizes<D: PeerDirectory>() -> StaticSizes {
    StaticSizes {
        bulk: core::mem::size_of::<tdongle_tailnet_ctl::Bulk>(),
        session_buf: core::mem::size_of::<tdongle_tailnet_ctl::SessionBuf>(),
        udp_q: crate::shared::UDP_Q,
        derp_q: crate::shared::DERP_Q,
        host_q: crate::shared::HOST_Q,
        dns_q: crate::shared::DNS_Q,
        lease: tdongle_tailnet_tls::READ_RECORD_BYTES,
        engine: tdongle_tailnet_engine::GatewayEngine::<D>::STATE_BYTES,
        derp_link: tdongle_tailnet_derp::Link::<{ crate::derp::DERP_TXQ }>::STATE_BYTES,
        usb_side: core::mem::size_of::<crate::usb::UsbSide>(),
        token: tdongle_tailnet_admission::negotiation::Negotiation::<tdongle_tailnet_admission::negotiation::NoObserver>::STATE_BYTES,
        registry: tdongle_tailnet_members::Registry::<{ tdongle_tailnet_members::MAX_MEMBERS }>::STATE_BYTES,
        slots: MAX_RUN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_sizes_print_and_are_sane() {
        type R = embassy_sync::blocking_mutex::raw::NoopRawMutex;
        let s = static_sizes::<crate::testutil::Dir>();
        std::println!("{s:#?}\nSlot<R> = {} B, Shared (test directory included) = {} B", slot_static_bytes::<R>(), core::mem::size_of::<crate::testutil::Sh>());
        assert_eq!(s.lease, 16_640);
        assert!(s.bulk > 15_000 && s.bulk < 25_000, "{}", s.bulk);
        assert!(s.session_buf < 2_000, "{}", s.session_buf);
        assert!(slot_static_bytes::<R>() >= s.session_buf + s.udp_q + s.derp_q);
        assert!(s.engine > 50_000);
    }
}

// Layout guard, checked by `cargo +esp check --target xtensa-esp32s3-none-elf -Zbuild-std=core,alloc`: the 32-bit sizes of the statics, as ceilings (a growth past
// them fails the build of the firmware, so the memory table of the ADR and this crate cannot drift apart unnoticed; the futures are measured by
// `size-table.sh`). The ceilings are the measured sizes of the RAM diet (ADR 0002, "RAM diet results").
#[cfg(target_arch = "xtensa")]
const _: () = {
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    assert!(core::mem::size_of::<tdongle_tailnet_ctl::Bulk>() <= 17_744);
    assert!(core::mem::size_of::<tdongle_tailnet_ctl::SessionBuf>() <= 1_160);
    assert!(core::mem::size_of::<Slot<NoopRawMutex>>() <= 8_400);
    assert!(core::mem::size_of::<crate::shared::SlotStatus>() <= 1_360);
    assert!(core::mem::size_of::<crate::shared::Ident>() == 352);
    assert!(core::mem::size_of::<tdongle_tailnet_derp::Link<{ crate::derp::DERP_TXQ }>>() == 4_376);
    assert!(core::mem::size_of::<crate::queue::ByteQueue<NoopRawMutex, { crate::shared::HOST_Q }>>() == 8_232);
    assert!(core::mem::size_of::<crate::shared::RegistryCell>() <= 2_232);
    assert!(core::mem::size_of::<crate::usb::UsbSide>() == 1_472);
};
