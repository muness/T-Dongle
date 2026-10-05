/**
 * @file ml_admission.h
 * @brief What it costs to admit one more membership, from measured constants (ADR 0013, N1.2).
 *
 * The old gate was one fixed sum per membership (108,200 B: four task stacks, the context, queues, 2,048 B of
 * slack, 16 KiB of recovery reserve and a 40,000 B "deferred WireGuard/TLS allowance") that did not know the
 * stacks are now shared, that the WireGuard device is a few hundred bytes plus the peers actually resident, or
 * that negotiations are serialised so only ONE join peak can ever be in flight. This module replaces it:
 *
 *   required free heap =  shared runtime (the first membership only: 3 stacks + 3 TCBs)
 *                       + member start allocations (context, coord stack + TCB, queues)
 *                       + member steady growth     (WireGuard device + the guaranteed resident peer slots, DERP TLS state,
 *                                                  lwIP sockets and PCBs, other tagged state)
 *                       + one negotiation peak     (a single join's transient above steady: the token guarantees
 *                                                  at most one at a time, whatever N is)

 *                       + the router queue floor   (charged once: two full packets; the queue's ceiling and the
 *                                                  pending-packet worst case (ML_JIT_PENDING per membership) are NOT
 *                                                  charged but are refused at allocation time whenever they would take free heap
 *                                                  below the recovery reserve: rt_queue_budget, ml_gateway_queue_packet)
 *                       + the recovery reserve     (free heap kept for HTTP/control recovery)
 *   and a largest free block of at least ML_ADM_LARGEST_BLOCK.
 *
 * Not in the sum, on purpose: the USB transmit ring (4,576 B), its usb_txq worker (1,536 B stack + TCB) and the USB receive
 * budget. The ring and worker are allocated once at USB start, before any membership, so the free heap that is compared
 * with `required` has already paid for them (6,476 B, offset by the 6,400 B the smaller IN NTBs gave back: ADR 0015). The
 * receive frames are transient and bounded by usb_rx_budget.h, not reserved.
 *
 * Sizes that the compiler knows (sizeof the context, the WireGuard peer slot, stack and TCB sizes, queue bytes) are
 * passed in; the rest are measurements, with their provenance below. Everything is exposed in /status so a
 * refusal can be checked against the numbers that caused it. Pure arithmetic, tested on the host.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Measurements: firmware 0.2.22 on the board, 2026-10-05 (docs/diagnostics/baseline-0.2.22-2026-10-05.md and
 * ADR 0013). One membership's steady cost was 68.4 KB. */
#define ML_ADM_TLS_LIVE_BYTES   1336    /* DERP TLS state while connected (tagged `tls`, live) */
#define ML_ADM_LWIP_BYTES       9300    /* untagged: lwIP sockets and PCBs of DISCO, two STUN sockets, control, DERP */
#define ML_ADM_OTHER_BYTES      5600    /* 68,436 measured - itemised (stacks 31,232 + context 9,728 + WireGuard 7,952 +
                                           TCBs/queues 3,256 + TLS 1,336 + lwIP 9,300 = 62,804): peer directory, map
                                           and packet owners that are live at steady state */
#define ML_ADM_NEG_PEAK_BYTES   11500   /* one join's transient: the DERP TLS handshake with certificate verification
                                           peaked at 17.3 KB against 1.3 KB live, 15,964 B above steady, when the presented
                                           cross-signed ISRG Root X2 was verified through ISRG Root X1 (RSA-4096). The trust
                                           anchor match (ml_derp_tls.c, docs/adr/0021) skips that verification: 5.8 KB less on
                                           the host, estimated 4.5 KB on the board (the RSA integers are the same size, the
                                           hardware MPI shortens the work, not the memory; 4.5 KB is the 58 % RSA share of
                                           the board's measured extra, the safe end of the 4.5 to 5.8 KB range):
                                           15,964 - 4,500 = 11,464, rounded up. ESTIMATE until the board's `members` derp
                                           phase peak is read (docs/adr/0021 "On-board verification"); raise it if that is
                                           higher. The 24,000 B largest block and the 17,408 B TLS floor below are record
                                           buffers, which the match does not change. */
#define ML_ADM_RECOVERY_BYTES   16384   /* kept free for HTTP/control recovery (the v120 panic was at 7,464 B free) */
#define ML_ADM_LARGEST_BLOCK    24000   /* steady largest block measured 24,576 B; the TLS record buffer is ~16.7 KB */
#define ML_ADM_PEER_SLOTS       2       /* resident WireGuard peers GUARANTEED per membership (the pool holds 12 in all); slots beyond
                                           these are elastic: ml_adm_slot_heap_ok. ADR 0013 expected three resident typically (2,712 B at
                                           904 B a slot); the guarantee is the two a gateway cannot be useful without (the peer it
                                           reaches and the exit node or the second destination), the rest come from free heap */
#define ML_ADM_JIT_PACKET_BYTES 1464    /* one pending packet: ML_JIT_PACKET_MAX + the update header, rounded. NOT charged: the packets
                                           pending while a peer's handshake runs are elastic (ml_gateway_queue_packet refuses one that
                                           would take the free heap below the recovery reserve), 2 x 1,464 = 2,928 B that used to be in
                                           `required` as a "typical" allowance on top of that guard */
#define ML_ADM_TLS_BLOCK_FLOOR  17408   /* the DERP TLS record buffer (~16.7 KB) must always find one free block this big;
                                           17 KiB. A peer slot may not be the allocation that takes the heap below it. */

typedef struct {
    size_t context;          /* sizeof(microlink_t) */
    size_t coord_stack;      /* the one task a membership keeps */
    size_t task_tcb;         /* sizeof(StaticTask_t) */
    size_t queues;           /* per-membership queue storage */
    size_t wg_device;        /* sizeof(struct wireguard_device) */
    size_t wg_slot;          /* sizeof(struct wireguard_peer) */
    size_t shared_stacks;    /* net_io + derp + wg_mgr stacks */
    unsigned shared_tasks;   /* 3 */
    size_t route_queue_min;  /* the router queue's guaranteed floor (ROUTE_QUEUE_BYTES_MIN): two full packets */
} ml_adm_sizes_t;

typedef struct {
    size_t shared_runtime;   /* charged only while the shared tasks are not running */
    size_t member_start;
    size_t member_growth;
    size_t member_steady;    /* start + growth: the marginal cost of one more membership */
    size_t negotiation;
    size_t recovery;
    size_t required;         /* free heap needed to admit the next membership */
    size_t largest_block;
    size_t router;           /* charged once: the router queue's floor; its ceiling is drawn from free heap above the recovery reserve */
} ml_adm_budget_t;

typedef enum { ML_ADM_OK, ML_ADM_REFUSED_BUDGET, ML_ADM_REFUSED_LARGEST } ml_adm_verdict_t;

static inline void ml_adm_budget(const ml_adm_sizes_t *s, bool runtime_running, ml_adm_budget_t *b) {
    b->shared_runtime = runtime_running ? 0 : s->shared_stacks + s->shared_tasks * s->task_tcb;
    b->member_start = s->context + s->coord_stack + s->task_tcb + s->queues;
    b->member_growth = s->wg_device + ML_ADM_PEER_SLOTS * s->wg_slot + ML_ADM_TLS_LIVE_BYTES + ML_ADM_LWIP_BYTES +
                       ML_ADM_OTHER_BYTES;
    b->member_steady = b->member_start + b->member_growth;
    b->negotiation = ML_ADM_NEG_PEAK_BYTES;
    b->recovery = ML_ADM_RECOVERY_BYTES;
    b->router = s->route_queue_min;
    b->required = b->shared_runtime + b->member_steady + b->negotiation + b->recovery + b->router;
    b->largest_block = ML_ADM_LARGEST_BLOCK;
}

static inline ml_adm_verdict_t ml_adm_decide(const ml_adm_budget_t *b, size_t free_now, size_t largest) {
    if (free_now < b->required) return ML_ADM_REFUSED_BUDGET;
    if (largest < b->largest_block) return ML_ADM_REFUSED_LARGEST;
    return ML_ADM_OK;
}

/* ELASTIC heap (ADR 0020): memory that exists only while something waits or is in use, that is bounded in bytes, and that is
 * therefore not part of `required`: the WireGuard receive queue (ml_wg_rx_budget.h), the pending outbound packets
 * (ml_gateway_queue_packet), the router queue above its floor (rt_queue_budget), the USB transmit ring's growth chunks, and the
 * peer slots beyond the guaranteed ML_ADM_PEER_SLOTS. Each is refused at allocation time, counted, when it would take the free heap
 * below the recovery reserve; those that persist for long (USB chunks, slots) also leave one negotiation peak, because a join
 * (or a rejoin after a Wi-Fi flap) can start at any time and needs it; the receive queue, which drains in milliseconds, leaves it
 * only while a join is actually running. The floors, in one place so the tests state them: */
static inline size_t ml_adm_elastic_floor(bool leaves_negotiation_peak) {
    return ML_ADM_RECOVERY_BYTES + (leaves_negotiation_peak ? ML_ADM_NEG_PEAK_BYTES : 0);
}
/* A peer slot of `bytes` when `live` slots are resident (all memberships) and `free_before` is the free internal heap: the first
 * ML_ADM_PEER_SLOTS are in `required` (admission already left the heap for them) and only keep the recovery reserve; the others
 * keep recovery reserve AND one negotiation peak. */
static inline bool ml_adm_slot_heap_ok(unsigned live, size_t free_before, size_t bytes) {
    return free_before >= ml_adm_elastic_floor(live >= ML_ADM_PEER_SLOTS) + bytes;
}

/* The WireGuard peer-slot pool allocates its 904 B slots on demand, and a slot lives as long as its peer (hours). Long-lived
 * small blocks scattered through a heap that is already fragmented are how the largest free block shrinks: steady state
 * measured 24,576 B against the 24,000 B admission floor (a 576 B margin, smaller than ONE slot), and the pool may hold 12.
 * A static pool would pin the full 12 x 904 = 10,848 B for ever ((at 1,096 B a slot now) more than the slots admission charges at
 * N = 1, against ~107 KB free after boot), so slots stay on demand and each allocation is checked instead: an allocation
 * that is the one taking the largest free block from at least `floor` to below it is refused (and counted), which the pool
 * reports as "no memory" and the policy as a rejected activation. A heap already below the floor is not made an excuse
 * for refusing everything: the check is about what THIS allocation did. */
static inline bool ml_adm_slot_alloc_ok(size_t largest_before, size_t largest_after, size_t floor) {
    return !(largest_before >= floor && largest_after < floor);
}
