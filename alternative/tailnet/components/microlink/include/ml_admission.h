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
 *                       + member steady growth     (WireGuard device + typical resident peer slots, DERP TLS state,
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
#define ML_ADM_NEG_PEAK_BYTES   16000   /* one join's transient: the DERP TLS handshake with certificate verification
                                           peaks at 17.3 KB against 1.3 KB live, 15,964 B above steady (rounded) */
#define ML_ADM_RECOVERY_BYTES   16384   /* kept free for HTTP/control recovery (the v120 panic was at 7,464 B free) */
#define ML_ADM_LARGEST_BLOCK    24000   /* steady largest block measured 24,576 B; the TLS record buffer is ~16.7 KB */
#define ML_ADM_PEER_SLOTS       4       /* resident WireGuard peers charged per membership (the pool holds 12 in all) */
#define ML_ADM_JIT_TYPICAL      2       /* outbound packets pending on a membership while its peer's handshake runs (typical) */
#define ML_ADM_JIT_PACKET_BYTES 1464    /* one pending packet: ML_JIT_PACKET_MAX + the update header, rounded */
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
                       ML_ADM_OTHER_BYTES + ML_ADM_JIT_TYPICAL * ML_ADM_JIT_PACKET_BYTES;
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

/* The WireGuard peer-slot pool allocates its 904 B slots on demand, and a slot lives as long as its peer (hours). Long-lived
 * small blocks scattered through a heap that is already fragmented are how the largest free block shrinks: steady state
 * measured 24,576 B against the 24,000 B admission floor (a 576 B margin, smaller than ONE slot), and the pool may hold 12.
 * A static pool would pin the full 12 x 904 = 10,848 B for ever (7,232 B more than the four slots admission charges at
 * N = 1, against ~107 KB free after boot), so slots stay on demand and each allocation is checked instead: an allocation
 * that is the one taking the largest free block from at least `floor` to below it is refused (and counted), which the pool
 * reports as "no memory" and the policy as a rejected activation. A heap already below the floor is not made an excuse
 * for refusing everything: the check is about what THIS allocation did. */
static inline bool ml_adm_slot_alloc_ok(size_t largest_before, size_t largest_after, size_t floor) {
    return !(largest_before >= floor && largest_after < floor);
}
