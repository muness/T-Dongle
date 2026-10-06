//! What it costs to admit one more membership (`ml_admission.h`, ADR 0013 N1.2).
//!
//! ```text
//! required free heap =  shared runtime      (first membership only)
//!                     + member start         (context, coordinator task, queues)
//!                     + member steady growth (WireGuard device + guaranteed peer slots, DERP TLS state, lwIP, other)
//!                     + one negotiation peak (the token guarantees at most one join in flight, whatever N is)
//!                     + the router queue floor (charged once: two full packets)
//!                     + the recovery reserve
//! and a largest free block of at least ML_ADM_LARGEST_BLOCK.
//! ```
//!
//! Not in the sum, on purpose (C header): the USB transmit ring and its worker (allocated before any
//! membership, so the free heap compared with `required` has already paid for them) and the USB
//! receive budget. The inputs are a [`Params`]: [`Params::c_reference`] is the C firmware's numbers
//! (the tests assert the C's `required` values for N = 1 and N = 2), [`Params::rust`] is the model for
//! the Rust task design (shared embassy tasks, no per-member FreeRTOS stack or TCB; per-member state
//! sizes come from [`MemberSizes`], built from the other crates' `size_of` constants).

/// DERP TLS state while connected (tagged `tls`, live). Board, 0.2.22, 2026-10-05.
pub const ML_ADM_TLS_LIVE_BYTES: usize = 1336;
/// Untagged: lwIP sockets and PCBs of DISCO, two STUN sockets, control and DERP.
pub const ML_ADM_LWIP_BYTES: usize = 9300;
/// 68,436 measured minus the itemised 62,804: peer directory, map and packet owners live at steady state.
pub const ML_ADM_OTHER_BYTES: usize = 5600;
/// One join's transient: the DERP TLS handshake. 15,964 B above steady before the trust-anchor match (ADR 0021), minus the 2,780 B the
/// board measured it saves, rounded up with headroom (13,184 -> 13,500).
pub const ML_ADM_NEG_PEAK_BYTES: usize = 13_500;
/// Kept free for HTTP/control recovery (the v120 panic was at 7,464 B free).
pub const ML_ADM_RECOVERY_BYTES: usize = 16_384;
/// Largest free block admission requires (steady measured 24,576 B; the TLS record buffer is ~16.7 KB).
pub const ML_ADM_LARGEST_BLOCK: usize = 24_000;
/// Resident WireGuard peers GUARANTEED per membership (the pool holds 12 in all); slots beyond these are elastic ([`slot_heap_ok`]).
pub const ML_ADM_PEER_SLOTS: u32 = 2;
/// One pending packet: `ML_JIT_PACKET_MAX` plus the update header, rounded. NOT charged (elastic).
pub const ML_ADM_JIT_PACKET_BYTES: usize = 1464;
/// The DERP TLS record buffer (~16.7 KB) must always find one free block this big; 17 KiB. A peer slot may not be the allocation that
/// takes the largest free block below it.
pub const ML_ADM_TLS_BLOCK_FLOOR: usize = 17_408;
/// The router queue's guaranteed floor (`ROUTE_QUEUE_BYTES_MIN`): two full packets.
pub const ROUTE_QUEUE_BYTES_MIN: usize = 2800;

/// Everything the admission arithmetic reads. All sizes in bytes.
///
/// Field names follow `ml_adm_sizes_t`; the measured constants of the header (`tls_live`, `lwip`, `other`, the peak, the reserve) are fields
/// too, so that a Rust preset can replace them with ledger measurements without touching the arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// `sizeof(microlink_t)`: the per-membership context.
    pub context: usize,
    /// The one task a membership keeps (stack).
    pub coord_stack: usize,
    /// `sizeof(StaticTask_t)`: one task control block.
    pub task_tcb: usize,
    /// Per-membership queue storage.
    pub queues: usize,
    /// `sizeof(struct wireguard_device)`.
    pub wg_device: usize,
    /// `sizeof(struct wireguard_peer)`: one resident peer slot.
    pub wg_slot: usize,
    /// Stacks of the shared tasks (net_io + derp + wg_mgr); paid by the first membership only.
    pub shared_stacks: usize,
    /// Number of shared tasks (each charged one TCB).
    pub shared_tasks: u32,
    /// The router queue's guaranteed floor.
    pub route_queue_min: usize,
    /// Guaranteed resident peer slots per membership.
    pub peer_slots: u32,
    /// DERP TLS state while connected.
    pub tls_live: usize,
    /// lwIP sockets and PCBs of one membership.
    pub lwip: usize,
    /// Other tagged state live at steady state.
    pub other: usize,
    /// One negotiation peak.
    pub negotiation_peak: usize,
    /// The recovery reserve.
    pub recovery: usize,
    /// The largest free block required.
    pub largest_block: usize,
}

/// Per-membership state of the Rust runtime, in bytes, from the `size_of` constants of the crates that own the state.
///
/// There is no per-member task stack or TCB in the Rust design: a membership's control loop is an embassy task whose future (its state
/// machine) is part of [`control`](Self::control), and the executor's arena is charged once as [`SharedSizes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemberSizes {
    /// The control task's state machine and its working state (Noise session, registration, map cursor).
    pub control: usize,
    /// The member's peer table (`tdongle_tailnet_peers::PeerTable::STATE_BYTES`).
    pub peer_table: usize,
    /// The member's DERP link state machine.
    pub derp_link: usize,
    /// The per-member queue storage (DISCO, STUN, DERP transmit, WireGuard receive slots, commands).
    pub queues: usize,
    /// The WireGuard device (keys, handshake state shared by the member's peers), without the peer slots.
    pub wg_device: usize,
    /// Anything else owned per member (settings copy, names).
    pub misc: usize,
}

/// What the shared (first-membership-only) part of the Rust runtime costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SharedSizes {
    /// Stack of the executor thread(s) and the arenas of the shared tasks (net_io, derp, wg_mgr).
    pub executor_bytes: usize,
}

/// Values the Rust preset cannot compute from `size_of`: they are board measurements of the C firmware's lwIP, TLS and tagged state, kept
/// as the defaults until the Rust ledger measures them (**provisional**; ADR 0001 rule 7 is what replaces them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provisional {
    /// DERP TLS state while connected.
    pub tls_live: usize,
    /// lwIP sockets and PCBs.
    pub lwip: usize,
    /// Other tagged state at steady state.
    pub other: usize,
}

impl Provisional {
    /// The C firmware's measurements.
    pub const C_MEASURED: Provisional = Provisional { tls_live: ML_ADM_TLS_LIVE_BYTES, lwip: ML_ADM_LWIP_BYTES, other: ML_ADM_OTHER_BYTES };
}

impl Params {
    /// The C firmware's sizes (`tests/test_admission.c`: the xtensa `sizeof` values of that tree). With these, [`Params::budget`] yields
    /// `required` = 96,400 B for the first membership and 72,340 B for each further one.
    #[must_use]
    pub const fn c_reference() -> Params {
        Params {
            context: 10_256,
            coord_stack: 8704,
            task_tcb: 340,
            queues: 1500 + 192,
            wg_device: 228 + 8,
            wg_slot: 1096,
            shared_stacks: 7168 + 7680 + 8192,
            shared_tasks: 3,
            route_queue_min: ROUTE_QUEUE_BYTES_MIN,
            peer_slots: ML_ADM_PEER_SLOTS,
            tls_live: ML_ADM_TLS_LIVE_BYTES,
            lwip: ML_ADM_LWIP_BYTES,
            other: ML_ADM_OTHER_BYTES,
            negotiation_peak: ML_ADM_NEG_PEAK_BYTES,
            recovery: ML_ADM_RECOVERY_BYTES,
            largest_block: ML_ADM_LARGEST_BLOCK,
        }
    }

    /// The Rust task model: shared embassy tasks, so no per-member stack and no TCB; the per-member state is the sum of [`MemberSizes`].
    ///
    /// `wg_slot` is `size_of` the WireGuard crate's slot (the hot state), `shared` the executor's cost, `p` the provisional measurements.
    #[must_use]
    pub const fn rust(member: &MemberSizes, wg_slot: usize, shared: &SharedSizes, p: &Provisional) -> Params {
        Params {
            context: member.control + member.peer_table + member.derp_link + member.misc,
            coord_stack: 0,
            task_tcb: 0,
            queues: member.queues,
            wg_device: member.wg_device,
            wg_slot,
            shared_stacks: shared.executor_bytes,
            shared_tasks: 0,
            route_queue_min: ROUTE_QUEUE_BYTES_MIN,
            peer_slots: ML_ADM_PEER_SLOTS,
            tls_live: p.tls_live,
            lwip: p.lwip,
            other: p.other,
            negotiation_peak: ML_ADM_NEG_PEAK_BYTES,
            recovery: ML_ADM_RECOVERY_BYTES,
            largest_block: ML_ADM_LARGEST_BLOCK,
        }
    }

    /// `ml_adm_budget`: the cost of admitting the next membership. `runtime_running` is true once the shared tasks already run (the first
    /// membership pays for them, later ones do not).
    #[must_use]
    pub const fn budget(&self, runtime_running: bool) -> Budget {
        let shared_runtime = if runtime_running { 0 } else { self.shared_stacks + self.shared_tasks as usize * self.task_tcb };
        let member_start = self.context + self.coord_stack + self.task_tcb + self.queues;
        let member_growth = self.wg_device + self.peer_slots as usize * self.wg_slot + self.tls_live + self.lwip + self.other;
        let member_steady = member_start + member_growth;
        Budget {
            shared_runtime,
            member_start,
            member_growth,
            member_steady,
            negotiation: self.negotiation_peak,
            recovery: self.recovery,
            required: shared_runtime + member_steady + self.negotiation_peak + self.recovery + self.route_queue_min,
            largest_block: self.largest_block,
            router: self.route_queue_min,
        }
    }
}

/// `ml_adm_budget_t`: the terms of the admission sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Charged only while the shared tasks are not running.
    pub shared_runtime: usize,
    /// Context, coordinator stack, TCB and queues.
    pub member_start: usize,
    /// WireGuard device, guaranteed slots, TLS, lwIP, other.
    pub member_growth: usize,
    /// `member_start + member_growth`: the marginal cost of one more membership.
    pub member_steady: usize,
    /// One negotiation peak.
    pub negotiation: usize,
    /// The recovery reserve.
    pub recovery: usize,
    /// Free heap needed to admit the next membership.
    pub required: usize,
    /// Largest free block needed.
    pub largest_block: usize,
    /// The router queue's floor, charged once.
    pub router: usize,
}

/// `ml_adm_verdict_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// Admitted.
    Ok,
    /// Not enough free heap.
    RefusedBudget,
    /// Enough free heap but no large enough free block.
    RefusedLargest,
}

impl Budget {
    /// `ml_adm_decide`: budget first, then the contiguous block.
    pub const fn decide(&self, free_now: usize, largest: usize) -> Verdict {
        if free_now < self.required {
            Verdict::RefusedBudget
        } else if largest < self.largest_block {
            Verdict::RefusedLargest
        } else {
            Verdict::Ok
        }
    }
}

/// `ml_adm_elastic_floor`: the floor for elastic heap (ADR 0020): the recovery reserve for everything, one negotiation peak more for what
/// persists or must not starve a join.
#[must_use]
pub const fn elastic_floor(leaves_negotiation_peak: bool) -> usize {
    ML_ADM_RECOVERY_BYTES + if leaves_negotiation_peak { ML_ADM_NEG_PEAK_BYTES } else { 0 }
}

/// `ml_adm_slot_heap_ok`: a peer slot of `bytes` when `live` slots are resident (all memberships) and `free_before` is the free internal
/// heap. The first [`ML_ADM_PEER_SLOTS`] are in `required` and keep only the recovery reserve; the others keep the reserve AND one
/// negotiation peak.
#[must_use]
pub const fn slot_heap_ok(live: u32, free_before: usize, bytes: usize) -> bool {
    free_before >= elastic_floor(live >= ML_ADM_PEER_SLOTS) + bytes
}

/// `ml_adm_slot_alloc_ok`: an allocation that is the one taking the largest free block from at least `floor` to below it is refused. A heap
/// already below the floor is not made an excuse for refusing everything: the check is about what THIS allocation did.
#[must_use]
pub const fn slot_alloc_ok(largest_before: usize, largest_after: usize, floor: usize) -> bool {
    !(largest_before >= floor && largest_after < floor)
}

const _: () = assert!(ML_ADM_NEG_PEAK_BYTES == 13_500 && 15_964 - 2_780 <= ML_ADM_NEG_PEAK_BYTES);
const _: () = assert!(ML_ADM_TLS_BLOCK_FLOOR < ML_ADM_LARGEST_BLOCK, "the slot guard floor sits below the admission largest-block floor");
const _: () = assert!(ML_ADM_PEER_SLOTS == 2);
