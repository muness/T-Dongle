#ifndef ML_WG_RX_BATCH_H
#define ML_WG_RX_BATCH_H
/* The inbound WireGuard run (ADR 0020): up to ML_WG_RX_BATCH transport datagrams taken off wg_rx_queue by one wake of wg_mgr are
 * authenticated, decrypted and delivered together instead of one by one. Kept in a header so the host tests run the real code
 * against the real wireguardif.c (tests/test_wg_rx_batch.c).
 *
 *   core lock   begin     wireguardif_rx_begin_ex for every datagram   (keypair lookup, key copy; no allocation: in place)
 *   no lock     decrypt   wireguard_rx_decrypt for every datagram       (ChaCha20-Poly1305 over the datagram itself)
 *   core lock   complete  wireguardif_rx_complete_deferred for each      (replay window, endpoint, timers, AllowedIPs, trim)
 *   no lock     deliver   wireguardif_rx_deliver                         (the router: validate, NAT, then ONE core lock for the output)
 *
 * What a run changes against the one-datagram path it replaces, and what it does not:
 *  - Per datagram it removes two core-lock round trips (begin and complete became shared by the run) and the work that used to
 *    run INSIDE the second hold (the router's validation, flow lookup and NAT rewrite, a pbuf allocation and two copies of the
 *    packet): the tcpip task, which must take the same lock for every Wi-Fi frame it receives, waits for a hold that is now
 *    microseconds instead of ~0.7 ms.
 *  - Order. Datagrams complete and are delivered in the order they were taken off the queue, so one peer's packets stay in order
 *    (the replay window sees counters in arrival order exactly as before). A message that is not transport data (a handshake or a
 *    cookie, which can change keypairs) ends the run: the data before it is completed first, then it is handled alone, in one
 *    piece, as before; the data after it starts a new run.
 *  - Keepalives, endpoint updates, keypair confirmation, the replay ring and every counter behave exactly as in the one-piece path
 *    (the tests run both on the same random traffic and require identical results).
 *  - Memory. The datagram buffer taken off the queue is the only buffer: the plaintext replaces the ciphertext in it and the same
 *    pbuf is what the router reads. A run therefore holds the same bytes the queue held (ML_WG_RX_BATCH datagrams at most) and
 *    allocates nothing but the router's one output pbuf per packet, which replaces the datagram right away.
 *  - Bounded hold. At most ML_WG_RX_BATCH begins or completes run under one hold; each is a few microseconds. */
#include <stdbool.h>
#include <stdint.h>
#include "wireguard.h"
#include "wireguardif.h"
#include "tdongle_wgperf.h"

#define ML_WG_RX_BATCH 8          /* datagrams per run: the largest burst one begin/complete hold covers, and the jobs array's size */

typedef struct {
    struct pbuf *p;               /* the datagram: one segment, writable, owned by the run from the call on */
    ip_addr_t addr;               /* the outer source (any address = it came through DERP) */
    u16_t port;
} ml_wg_rx_item_t;

/* Sites a run takes the core lock at, for the caller's lock accounting (lock_hold sites). */
enum { ML_WG_RX_SITE_BEGIN, ML_WG_RX_SITE_COMMIT, ML_WG_RX_SITE_OTHER };
typedef struct {
    void (*lock)(void *ctx, unsigned site);
    void (*unlock)(void *ctx, unsigned site);
    void *ctx;
} ml_wg_rx_lock_t;

/* Test seam: a build that wants to assert "no lock is held here" before the decrypt and the delivery defines this. */
#ifndef ML_WG_RX_ASSERT_UNLOCKED
#define ML_WG_RX_ASSERT_UNLOCKED(where) ((void)0)
#endif

static inline bool ml_wg_rx_is_data(const struct pbuf *p) {
    return p && p->payload && wireguard_get_message_type((const uint8_t *)p->payload, p->len) == MESSAGE_TRANSPORT_DATA;
}

/* One run of `n` (1..ML_WG_RX_BATCH) transport datagrams. Returns the number delivered to the router. */
static inline unsigned ml_wg_rx_run_data(struct netif *netif, ml_wg_rx_item_t *items, unsigned n, struct wireguard_rx_job *jobs,
                                         const ml_wg_rx_lock_t *lk) {
    bool pending[ML_WG_RX_BATCH];
    WGPERF_T(t);
    lk->lock(lk->ctx, ML_WG_RX_SITE_BEGIN);
    for (unsigned i = 0; i < n; i++) {
        pending[i] = wireguardif_rx_begin_ex(netif, items[i].p, &items[i].addr, items[i].port, &jobs[i], WIREGUARDIF_RX_INPLACE) != 0;
        if (!pending[i]) jobs[i].deliver = NULL;   /* handled and freed by begin */
        items[i].p = NULL;                          /* from here the job owns it (or begin freed it) */
    }
    lk->unlock(lk->ctx, ML_WG_RX_SITE_BEGIN);
    WGPERF_LAP(t, rx_begin);

    ML_WG_RX_ASSERT_UNLOCKED("decrypt");
    for (unsigned i = 0; i < n; i++)
        if (pending[i]) wireguard_rx_decrypt(&jobs[i]);
    WGPERF_LAP(t, rx_decrypt);

    WGPERF_T(t_after);   /* rx_deliver: everything after the decrypt */
    lk->lock(lk->ctx, ML_WG_RX_SITE_COMMIT);
    for (unsigned i = 0; i < n; i++)
        if (pending[i]) wireguardif_rx_complete_deferred(netif, &items[i].addr, items[i].port, &jobs[i]);
    lk->unlock(lk->ctx, ML_WG_RX_SITE_COMMIT);
    WGPERF_LAP(t, rx_complete);

    ML_WG_RX_ASSERT_UNLOCKED("deliver");
    unsigned delivered = wireguardif_rx_deliver(netif, jobs, n);
    WGPERF_LAP(t, rx_route);
    WGPERF_CHARGE(t_after, rx_deliver);
    return delivered;
}

/* Any sequence of datagrams, in order: runs of transport data of at most ML_WG_RX_BATCH, and every other message on its own. */
static inline unsigned ml_wg_rx_run(struct netif *netif, ml_wg_rx_item_t *items, unsigned n, struct wireguard_rx_job *jobs,
                                    const ml_wg_rx_lock_t *lk) {
    unsigned delivered = 0, at = 0;
    while (at < n) {
        if (!ml_wg_rx_is_data(items[at].p)) {
            /* handshake, cookie, or something wireguardif refuses: one piece, under one hold, exactly as before */
            struct wireguard_rx_job job;
            lk->lock(lk->ctx, ML_WG_RX_SITE_OTHER);
            (void)wireguardif_rx_begin_ex(netif, items[at].p, &items[at].addr, items[at].port, &job, 0);
            lk->unlock(lk->ctx, ML_WG_RX_SITE_OTHER);
            items[at].p = NULL;
            at++;
            continue;
        }
        unsigned end = at + 1;
        while (end < n && end - at < ML_WG_RX_BATCH && ml_wg_rx_is_data(items[end].p)) end++;
        WGPERF_ADD(rx_run, end - at);
        WGPERF_COUNT(rx_runs, 1);
        if (end - at == ML_WG_RX_BATCH) WGPERF_COUNT(rx_runs_full, 1);
        if (end < n && end - at < ML_WG_RX_BATCH) WGPERF_COUNT(rx_runs_cut, 1);
        delivered += ml_wg_rx_run_data(netif, &items[at], end - at, jobs, lk);
        at = end;
    }
    return delivered;
}

#endif
