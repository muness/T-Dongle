#ifndef ML_RX_STATS_H
#define ML_RX_STATS_H
/* Cumulative counters for the inbound path ahead of WireGuard's own (wireguard_stats.h): from the UDP socket (and the DERP
 * receive loop) to the wg_mgr task's call into wireguardif. Every place a datagram can be refused, lost or discarded here is
 * counted, and so is every datagram that makes it, so the layers can be reconciled against each other and against lwIP's
 * own `udp.recv` (docs/adr/0019-inbound-loss.md):
 *
 *   lwIP udp.recv (this socket's datagrams)  ==  udp_rx + datagrams lwIP dropped in the socket mailbox, which lwIP does not count;
 *   udp_rx_wg  ==  q_wg_full + wg_enqueued ;  wg_enqueued + derp_rx_wg == wg_in + (still queued)
 *   wg_in      ==  wg_sender_unknown + wg_no_netif + wg_pbuf_fail + wireguard rx_data-or-handshake/other
 *
 * Always compiled: one relaxed atomic add per event on 32-bit words, against ~2.4 ms of wg_mgr CPU per forwarded packet
 * (ADR 0018). Portable C so the host tests run the real drain code. */
#include <stdatomic.h>
#include <stdint.h>

#define ML_RX_COUNTERS(X) \
    X(udp_rx)            /* datagrams read from a membership's DISCO/WireGuard UDP socket */ \
    X(udp_rx_empty)      /* of those, zero length: discarded */ \
    X(udp_unclassified)  /* of those, too short to be WireGuard, DISCO or STUN: discarded */ \
    X(udp_alloc_fail)    /* no heap for the copy that crosses to the wg_mgr task: discarded */ \
    X(udp_recv_err)      /* recvfrom failed with something other than "nothing to read" */ \
    X(udp_wg)            /* classified WireGuard, offered to wg_rx_queue */ \
    X(udp_disco)         /* classified DISCO, offered to disco_rx_queue */ \
    X(udp_stun)          /* classified STUN, offered to stun_rx_queue */ \
    X(q_wg_full)         /* wg_rx_queue full when the socket reader (net_io) offered a packet: dropped */ \
    X(q_disco_full)      /* disco_rx_queue full (net_io or DERP): dropped */ \
    X(q_stun_full)       /* stun_rx_queue full: dropped */ \
    X(derp_rx_wg)        /* WireGuard datagrams offered to wg_rx_queue by the DERP loop */ \
    X(derp_q_wg_full)    /* ... of which wg_rx_queue was full: dropped */ \
    X(q_wg_bytes)        /* WireGuard datagram refused: it would take the queued bytes past ML_WG_RX_QUEUE_BYTES (ml_wg_rx_budget.h), either producer */ \
    X(q_wg_heap)         /* WireGuard datagram refused: it would leave less free internal heap than the recovery reserve, either producer */ \
    X(drain_calls)       /* times net_io drained a ready socket */ \
    X(drain_capped)      /* ... that stopped at the per-call cap with the socket possibly not empty */ \
    X(drain_deep)        /* ... that read at least ML_NET_IO_DEEP datagrams: the socket mailbox (10) was nearly full when net_io got to it, one burst from the silent loss */ \
    X(wg_in)             /* datagrams taken off wg_rx_queue by wg_mgr */ \
    X(wg_sender_unknown) /* DERP source key admitted to no peer slot: dropped before any decryption */ \
    X(wg_no_netif)       /* membership has no WireGuard interface (yet or any more): dropped */ \
    X(wg_pbuf_fail)      /* pbuf allocation failed copying the datagram for wireguardif: dropped */ \
    X(wg_to_wireguardif) /* handed to wireguardif_rx_begin */

typedef enum {
#define X(name) ML_RXS_##name,
    ML_RX_COUNTERS(X)
#undef X
    ML_RXS_COUNT
} ml_rx_stat_t;

typedef struct {
    atomic_uint c[ML_RXS_COUNT];
    atomic_uint drain_burst_max;   /* gauge: most datagrams drained from one socket in one call */
} ml_rx_stats_t;
extern ml_rx_stats_t ml_rx_stats;

static inline void ml_rx_stat_add(ml_rx_stat_t which, uint32_t n) {
    atomic_fetch_add_explicit(&ml_rx_stats.c[which], n, memory_order_relaxed);
}
static inline uint32_t ml_rx_stat_get(unsigned which) {
    return which < ML_RXS_COUNT ? atomic_load_explicit(&ml_rx_stats.c[which], memory_order_relaxed) : 0;
}
static inline const char *ml_rx_stat_name(unsigned which) {
    static const char *const names[ML_RXS_COUNT] = {
#define X(name) #name,
        ML_RX_COUNTERS(X)
#undef X
    };
    return which < ML_RXS_COUNT ? names[which] : "";
}
static inline void ml_rx_stat_burst(uint32_t n) {
    uint32_t seen = atomic_load_explicit(&ml_rx_stats.drain_burst_max, memory_order_relaxed);
    while (n > seen && !atomic_compare_exchange_weak_explicit(&ml_rx_stats.drain_burst_max, &seen, n, memory_order_relaxed, memory_order_relaxed)) {
    }
}
static inline void ml_rx_stats_reset(void) {
    for (unsigned i = 0; i < ML_RXS_COUNT; i++) atomic_store_explicit(&ml_rx_stats.c[i], 0, memory_order_relaxed);
    atomic_store_explicit(&ml_rx_stats.drain_burst_max, 0, memory_order_relaxed);
}
#define ML_RX_STAT(name) ml_rx_stat_add(ML_RXS_##name, 1)

/* The WireGuard receive counters (wireguard_stats.h) and the replay window, for the serial report: the wireguard_lwip component is
 * private to microlink, so its numbers are reached through these (ml_wg_mgr.c). */
unsigned ml_wg_rx_stat_count(void);
uint32_t ml_wg_rx_stat(unsigned which);
const char *ml_wg_rx_stat_name(unsigned which);
unsigned ml_wg_replay_window(void);
unsigned ml_wg_rx_batch_size(void);   /* ML_WG_RX_BATCH: datagrams per inbound run (ADR 0020) */

#endif
