#pragma once
/* Per-stage accounting of the shared wg_mgr packet path (serial `wgperf`, diagnostics builds only).
 *
 * The question this answers: where do the ~2.4 ms of wg_mgr CPU per forwarded packet go (docs/adr/0018-wg-mgr-packet-path.md)?
 * Every stage keeps a count, a total and a maximum, in CPU cycles (the Xtensa CCOUNT register, so one stamp costs about
 * one instruction and is exact at any DFS frequency) or, for cross-task latencies where the two stamps are taken on
 * different cores, in microseconds of esp_timer time. The unit of a stage is part of its definition below and is
 * printed with the report.
 *
 * Portable C: the accumulators are C11 atomics and the clocks are macros, so the host tests run the real code
 * (tests/test_wgperf.c, under ASan/UBSan and TSan). Release builds compile every call site to nothing:
 * CONFIG_TDONGLE_MEMORY_DIAGNOSTICS selects the real macros, otherwise they expand to ((void)0) and the timestamp
 * variables disappear with them.
 *
 * Writers: any task (the producer stages run in usb_routes, the others in wg_mgr). Each accumulator update is a few
 * relaxed atomic operations (the 64-bit total is one atomic, never torn); a reader (the console task) sees a snapshot
 * that may be one sample behind. Reset is advisory: a sample racing with it lands in either epoch. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* name, unit. Keep the order: the report prints stages in this order. */
#define TDONGLE_WGPERF_STAGES(X) \
    X(q_latency, "us")   /* enqueue by usb_routes -> dequeue by wg_mgr: wake-up, scheduling and queue wait */ \
    X(prep, "cy")        /* producer, usb_routes: heap guard, pbuf allocation, copy, enqueue, wake */ \
    X(pass, "cy")        /* one wg_mgr membership pass, everything in it */ \
    X(pm, "cy")          /* PM burst lock begin + end around a pass (esp_pm_lock acquire/release) */ \
    X(updates, "cy")     /* process_peer_updates: the whole queue drain of a pass */ \
    X(lookup, "cy")      /* per egress packet: peer lookup and session test (and directory activation on a miss) */ \
    X(lock_wait, "cy")   /* waiting to take the lwIP core lock, every wg_mgr site */ \
    X(lock_hold, "cy")   /* the body run under the lwIP core lock, every wg_mgr site */ \
    X(send, "cy")        /* egress packet, from ready to handed to the UDP/DERP path, lock wait included */ \
    X(out_lookup, "cy")  /* wireguardif: longest-prefix allowed-ip match */ \
    X(out_seal, "cy")    /* wireguardif: keypair choice, header, ChaCha20-Poly1305 in place */ \
    X(out_udp, "cy")     /* wireguardif_peer_output: udp_sendto (IP, ARP/ethernet, Wi-Fi hand-off) or DERP queue */ \
    X(rx_pkt, "cy")      /* inbound, one RUN of up to ML_WG_RX_BATCH datagrams (ADR 0020): everything from the first prep to the last delivery. Per packet: total / in_pkts */ \
    X(rx_prep, "cy")     /* inbound, per run: admission, wrapping each datagram in a pbuf (no copy, no allocation) */ \
    X(rx_begin, "cy")    /* inbound, per run: core lock wait + wireguardif_rx_begin_ex for every datagram under ONE hold (keypair lookup, key copy) */ \
    X(rx_decrypt, "cy")  /* inbound, per run: every datagram decrypted in place, core lock released */ \
    X(rx_complete, "cy") /* inbound, per run: core lock wait + wireguardif_rx_complete_deferred for every datagram under ONE hold (replay, endpoint, AllowedIPs, trim) */ \
    X(rx_route, "cy")    /* inbound, per run: wireguardif_rx_deliver: the router (rt_check + rt_lock_wait + rt_emit), no lock held on entry */ \
    X(rx_deliver, "cy")  /* inbound, per run: rx_complete + rx_route, the stage of this name before ADR 0020, per packet: everything after the decrypt */ \
    X(rx_run, "pkt")     /* datagrams per run: n = runs, sum = datagrams, max = the largest run */ \
    X(rx_qdepth, "pkt")  /* wg_rx_queue depth when a drain starts: n = drains, sum / n = mean backlog, max = the worst burst seen (sizes the queue) */ \
    X(rt_check, "cy")    /* router, per batch: validation, flow lookup, NAT rewrite of every packet, core lock NOT held */ \
    X(rt_lock_wait, "cy") /* router, per batch that emits: waiting for the core lock */ \
    X(rt_emit, "cy")     /* router, per batch that emits: USB netif output of every frame (ARP lookup, ring copy) under the lock */ \
    X(drain_wg, "cy")    /* both WG receive drains of a pass */ \
    X(disco_rx, "cy")    /* DISCO drain of a pass */ \
    X(periodic, "cy")    /* wg_periodic_sliced (every 400 ms) */ \
    X(disco_tick, "cy")  /* disco_periodic_probes (every 1 s) */ \
    X(batch, "pkt")      /* egress packets sent in one pass that sent any: n = such passes, sum = packets */

/* name. Plain event counts. */
#define TDONGLE_WGPERF_COUNTERS(X) \
    X(wakes)            /* producer wake-ups (ml_rt_wake after an enqueue) */ \
    X(passes)           /* wg_mgr passes */ \
    X(passes_idle)      /* passes that did no work: a spurious wake-up or a timer that was not due for any membership */ \
    X(passes_skipped)   /* membership slices that took the idle early exit (ml_wg_idle.h) */ \
    X(out_direct)       /* egress packets sent in the pass that dequeued them (session already up) */ \
    X(out_parked)       /* egress packets parked for a handshake */ \
    X(out_flushed)      /* parked packets sent after the handshake */ \
    X(out_discard)      /* egress packets discarded (no peer, expired, send error) */ \
    X(in_pkts)          /* inbound WireGuard datagrams processed */ \
    X(rx_runs)          /* inbound runs (one begin / decrypt / complete / deliver cycle) */ \
    X(rx_runs_full)     /* ... that reached ML_WG_RX_BATCH datagrams (the drain had more waiting) */ \
    X(rx_runs_cut)      /* ... that ended early because the next datagram was not transport data (a handshake is processed in order, alone) */ \
    X(lookup_scans)     /* peer-table entries visited by find_peer_by_ip */

typedef enum {
#define X(name, unit) TDONGLE_WGPERF_##name,
    TDONGLE_WGPERF_STAGES(X)
#undef X
    TDONGLE_WGPERF_STAGE_COUNT
} tdongle_wgperf_stage;

typedef enum {
#define X(name) TDONGLE_WGPERF_C_##name,
    TDONGLE_WGPERF_COUNTERS(X)
#undef X
    TDONGLE_WGPERF_COUNTER_COUNT
} tdongle_wgperf_counter;

typedef struct {
    atomic_uint count, max;
    atomic_ullong total;                 /* 64-bit atomic: IDF's stdatomic.c implements it with a short critical section */
} tdongle_wgperf_acc_t;

typedef struct {
    tdongle_wgperf_acc_t stage[TDONGLE_WGPERF_STAGE_COUNT];
    atomic_uint counter[TDONGLE_WGPERF_COUNTER_COUNT];
    atomic_uint since_us;                /* esp_timer time of the last reset, truncated to 32 bits */
} tdongle_wgperf_t;

typedef struct {
    uint32_t count;
    uint64_t total;
    uint32_t max;
} tdongle_wgperf_sample;

static inline void tdongle_wgperf_add(tdongle_wgperf_t *p, unsigned stage, uint32_t value) {
    if (stage >= TDONGLE_WGPERF_STAGE_COUNT) return;
    tdongle_wgperf_acc_t *a = &p->stage[stage];
    atomic_fetch_add_explicit(&a->count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&a->total, value, memory_order_relaxed);
    uint32_t seen = atomic_load_explicit(&a->max, memory_order_relaxed);
    while (value > seen &&
           !atomic_compare_exchange_weak_explicit(&a->max, &seen, value, memory_order_relaxed, memory_order_relaxed)) {
    }
}

static inline void tdongle_wgperf_count(tdongle_wgperf_t *p, unsigned counter, uint32_t n) {
    if (counter < TDONGLE_WGPERF_COUNTER_COUNT) atomic_fetch_add_explicit(&p->counter[counter], n, memory_order_relaxed);
}

/* (count, total, max) of one stage. The three are separate atomics, so a sample being added concurrently may show in
 * one and not yet in another; the total itself is never torn. */
static inline tdongle_wgperf_sample tdongle_wgperf_get(const tdongle_wgperf_t *p, unsigned stage) {
    tdongle_wgperf_sample s = {0, 0, 0};
    if (stage >= TDONGLE_WGPERF_STAGE_COUNT) return s;
    tdongle_wgperf_acc_t *a = (tdongle_wgperf_acc_t *)&p->stage[stage];
    s.total = atomic_load_explicit(&a->total, memory_order_relaxed);
    s.count = atomic_load_explicit(&a->count, memory_order_relaxed);
    s.max = atomic_load_explicit(&a->max, memory_order_relaxed);
    return s;
}

static inline uint32_t tdongle_wgperf_counter_get(const tdongle_wgperf_t *p, unsigned counter) {
    return counter < TDONGLE_WGPERF_COUNTER_COUNT
               ? atomic_load_explicit(&((tdongle_wgperf_t *)p)->counter[counter], memory_order_relaxed) : 0;
}

static inline void tdongle_wgperf_reset(tdongle_wgperf_t *p, uint32_t now_us) {
    for (unsigned i = 0; i < TDONGLE_WGPERF_STAGE_COUNT; i++) {
        tdongle_wgperf_acc_t *a = &p->stage[i];
        atomic_store_explicit(&a->count, 0, memory_order_relaxed);
        atomic_store_explicit(&a->total, 0, memory_order_relaxed);
        atomic_store_explicit(&a->max, 0, memory_order_relaxed);
    }
    for (unsigned i = 0; i < TDONGLE_WGPERF_COUNTER_COUNT; i++) atomic_store_explicit(&p->counter[i], 0, memory_order_relaxed);
    atomic_store_explicit(&p->since_us, now_us, memory_order_relaxed);
}

/* ---- call-site macros ------------------------------------------------------------------------------------------
 *
 *   WGPERF_T(t);                          declare a cycle stamp
 *   WGPERF_LAP(t, stage);                 add (now - t) cycles to `stage`, then t = now (stages chain)
 *   WGPERF_CHARGE(t, stage);              like LAP but does not restart the stamp
 *   WGPERF_US_NOW()                       esp_timer microseconds, 32-bit
 *   WGPERF_ADD(stage, value) / WGPERF_COUNT(counter, n)
 *
 * Release builds: all of it is ((void)0) and `t` never exists. */
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
extern tdongle_wgperf_t tdongle_wgperf;
#ifndef TDONGLE_WGPERF_CYCLES
#include "esp_cpu.h"
#define TDONGLE_WGPERF_CYCLES() ((uint32_t)esp_cpu_get_cycle_count())
#endif
#ifndef TDONGLE_WGPERF_US
#include "esp_timer.h"
#define TDONGLE_WGPERF_US() ((uint32_t)esp_timer_get_time())
#endif
#define WGPERF_T(t) uint32_t t = TDONGLE_WGPERF_CYCLES()
#define WGPERF_LAP(t, stage) do { uint32_t now_ = TDONGLE_WGPERF_CYCLES(); \
    tdongle_wgperf_add(&tdongle_wgperf, TDONGLE_WGPERF_##stage, now_ - (t)); (t) = now_; } while (0)
#define WGPERF_CHARGE(t, stage) tdongle_wgperf_add(&tdongle_wgperf, TDONGLE_WGPERF_##stage, TDONGLE_WGPERF_CYCLES() - (t))
#define WGPERF_RESTART(t) ((t) = TDONGLE_WGPERF_CYCLES())
#define WGPERF_US_NOW() TDONGLE_WGPERF_US()
#define WGPERF_ADD(stage, value) tdongle_wgperf_add(&tdongle_wgperf, TDONGLE_WGPERF_##stage, (value))
#define WGPERF_COUNT(counter, n) tdongle_wgperf_count(&tdongle_wgperf, TDONGLE_WGPERF_C_##counter, (n))
void tdongle_wgperf_reset_now(void);
#else
#define WGPERF_T(t) ((void)0)
#define WGPERF_LAP(t, stage) ((void)0)
#define WGPERF_CHARGE(t, stage) ((void)0)
#define WGPERF_RESTART(t) ((void)0)
#define WGPERF_US_NOW() 0u
#define WGPERF_ADD(stage, value) ((void)0)
#define WGPERF_COUNT(counter, n) ((void)0)
#endif
