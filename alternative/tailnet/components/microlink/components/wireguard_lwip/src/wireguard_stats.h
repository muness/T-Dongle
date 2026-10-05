#ifndef WIREGUARD_STATS_H
#define WIREGUARD_STATS_H
/* Cumulative counters for every point where an inbound WireGuard transport datagram can leave the receive path, plus the
 * one point where it succeeds. Invariant (tests/test_wg_rx_counters.c): every datagram counted by `rx_data` ends in exactly one
 * of the terminal counters, so
 *
 *   rx_data == rx_no_peer + rx_keypair_unusable + rx_expired +
 *              rx_alloc_fail + rx_session_gone + rx_decrypt_fail + rx_keepalive + rx_replay_dup + rx_replay_old +
 *              rx_replay_limit + rx_bad_ip + rx_allowed_ip + rx_allowed_ip6 + rx_bad_length + rx_ipv6_unsupported + rx_input_fail + rx_delivered
 *
 * (read together while the path is idle; a datagram in flight is in rx_data and in no terminal yet). Counting is one relaxed
 * atomic add on a cold path, or per delivered packet one add against ~2.4 ms of wg_mgr CPU per forwarded packet (ADR 0018),
 * so it is compiled into every build. Writers: the wg_mgr task and, with zero-copy WG, the tcpip task; readers: the console. */
#include <stdatomic.h>
#include <stdint.h>

/* name -- meaning. Order is the report order. */
#define WIREGUARD_RX_COUNTERS(X) \
    X(rx_data)              /* transport datagrams that entered the data path */ \
    X(rx_bad_type)          /* not a WireGuard message at all (bad type, wrong length for its type): not part of rx_data */ \
    X(rx_no_peer)           /* receiver index belongs to no peer or keypair (stale session, scan, or another device's packet) */ \
    X(rx_keypair_unusable)  /* the keypair cannot receive (receiving_valid cleared) */ \
    X(rx_expired)           /* REJECT_AFTER_TIME or REJECT_AFTER_MESSAGES: session refused and destroyed */ \
    X(rx_alloc_fail)        /* no memory for the plaintext buffer */ \
    X(rx_session_gone)      /* the peer or keypair vanished while the datagram was being decrypted */ \
    X(rx_decrypt_fail)      /* ChaCha20-Poly1305 tag did not verify: corrupt, forged or wrong key */ \
    X(rx_keepalive)         /* authenticated keepalive: accepted, nothing to deliver */ \
    X(rx_replay_dup)        /* authenticated, counter already accepted (a duplicated or replayed datagram) */ \
    X(rx_replay_old)        /* authenticated, counter below the replay window (reordered by more than the window) */ \
    X(rx_replay_limit)      /* authenticated, counter at or above REJECT_AFTER_MESSAGES */ \
    X(rx_bad_ip)            /* plaintext is not a whole IPv4/IPv6 header */ \
    X(rx_allowed_ip)        /* inner IPv4 source address outside the peer's AllowedIPs (cryptokey routing) */ \
    X(rx_allowed_ip6)       /* inner IPv6 source address outside the peer's AllowedIPs (a gateway whose peers have no IPv6 entry counts every IPv6 packet here) */ \
    X(rx_bad_length)        /* inner IP length field inconsistent with the decrypted bytes (longer than them, or shorter than its own header) */ \
    X(rx_ipv6_unsupported)  /* authenticated inner IPv6 packet from an allowed source, well formed, that this gateway does not deliver (README) */ \
    X(rx_input_fail)        /* netif->input (the router) refused the packet */ \
    X(rx_delivered)         /* handed to netif->input and accepted */

typedef enum {
#define X(name) WG_RXS_##name,
    WIREGUARD_RX_COUNTERS(X)
#undef X
    WG_RXS_COUNT
} wireguard_rx_stat_t;

typedef struct { atomic_uint c[WG_RXS_COUNT]; } wireguard_rx_stats_t;
extern wireguard_rx_stats_t wireguard_rx_stats;

static inline void wireguard_rx_stat_add(wireguard_rx_stat_t which) {
    atomic_fetch_add_explicit(&wireguard_rx_stats.c[which], 1u, memory_order_relaxed);
}
static inline uint32_t wireguard_rx_stat_get(unsigned which) {
    return which < WG_RXS_COUNT ? atomic_load_explicit(&wireguard_rx_stats.c[which], memory_order_relaxed) : 0;
}
static inline const char *wireguard_rx_stat_name(unsigned which) {
    static const char *const names[WG_RXS_COUNT] = {
#define X(name) #name,
        WIREGUARD_RX_COUNTERS(X)
#undef X
    };
    return which < WG_RXS_COUNT ? names[which] : "";
}
static inline void wireguard_rx_stats_reset(void) {
    for (unsigned i = 0; i < WG_RXS_COUNT; i++) atomic_store_explicit(&wireguard_rx_stats.c[i], 0, memory_order_relaxed);
}
#define WG_RX_STAT(name) wireguard_rx_stat_add(WG_RXS_##name)

#endif
