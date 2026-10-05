#pragma once
/* RAM-resident, bounded, O(1) routing state for the USB <-> tunnel router.
 *
 * Pure C with no ESP-IDF or lwIP dependency, so the host tests run the exact
 * code the firmware links. router.c owns policy (who may talk to whom); this
 * file owns data structures:
 *
 *  - alias cache: 64 entries, chained hash on the alias address, CLOCK
 *    replacement. It is a cache of the append-only flash record, never the
 *    source of truth. A miss is answered by a background fill, not by flash I/O
 *    on the forwarding path.
 *  - flow table: 64 slots. Outbound lookups walk a short hash chain keyed by
 *    (alias, USB host, ports, protocol). The mapped source port encodes the slot
 *    (see rt_flow_in), so a tunnel reply is a direct index plus an exact tuple
 *    comparison: ownership is enforced, never inferred from the index.
 *  - a two-bucket epoch RCU used to pin membership state without members_lock.
 *  - RFC 1624 incremental checksum helpers.
 *
 * Tables are protected by one critical section (rt_lock) held for a few
 * microseconds and never across packet copies, allocation or any call out.
 * Callers pass the clock in; nothing here reads time. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Router policy shared with the ingress test. */
#define ROUTE_MTU 1400 /* largest IPv4 packet the tunnel queue accepts */
/* USB host to dongle bursts are one NCM NTB (about 3 full frames, or tens of
 * ACKs). 16 entries absorb that with margin; the byte budget bounds the pbuf
 * memory a stalled consumer can pin. */
#ifndef ROUTE_QUEUE_DEPTH
#define ROUTE_QUEUE_DEPTH 16
#endif
#ifndef ROUTE_QUEUE_BYTES
#define ROUTE_QUEUE_BYTES (16 * 1024)
#endif

#define RT_ALIASES 64
#define RT_FLOWS 64
#define RT_FLOW_IDLE_US 120000000LL
#define RT_MAPPED_BASE 40000u
#define RT_MAPPED_GENERATIONS 300u /* RT_MAPPED_BASE + 64*300 stays below 65536 */
#define RT_ALIAS_BASE 0xc6120001u

/* Counters for verification on the board and in tests; relaxed atomics. */
enum {
    RT_STAT_FORWARDED_OUT, RT_STAT_FORWARDED_IN, RT_STAT_BAD_PACKET, RT_STAT_ALIAS_MISS, RT_STAT_ALIAS_UNKNOWN,
    RT_STAT_ALIAS_FILL, RT_STAT_FLOW_FULL, RT_STAT_NO_MEMBER, RT_STAT_MEMBER_DOWN, RT_STAT_REPLY_NOMATCH,
    RT_STAT_QUEUE_FULL, RT_STAT_OVERSIZE_ICMP, RT_STAT_OVERSIZE_DROP, RT_STAT_ICMP_SUPPRESSED,
    RT_STAT_TUNNEL_REJECT, RT_STAT_TX_FAIL, RT_STAT_COUNT
};
static inline const char *rt_stat_name(unsigned which) {
    static const char *const names[RT_STAT_COUNT] = {
        "forwarded_out", "forwarded_in", "bad_packet", "alias_miss", "alias_unknown", "alias_fill", "flow_full", "no_member",
        "member_down", "reply_nomatch", "queue_full", "oversize_icmp", "oversize_drop", "icmp_suppressed", "tunnel_reject", "tx_fail"};
    return which < RT_STAT_COUNT ? names[which] : "";
}
extern atomic_uint rt_stats[RT_STAT_COUNT];
static inline void rt_stat(unsigned which) { atomic_fetch_add_explicit(&rt_stats[which], 1, memory_order_relaxed); }

typedef struct {
    uint32_t id, peer, alias;
} rt_alias_t;

typedef struct {
    uint32_t id, peer, alias, host;
    uint16_t local, remote, mapped;
    uint8_t proto;
} rt_flow_t; /* what a lookup returns: copied out under the lock */

typedef struct {
    rt_alias_t alias;
    uint8_t next, referenced, used;
} rt_alias_slot;
typedef struct {
    rt_flow_t flow;
    uint32_t generation;
    int64_t touched;
    uint8_t next, used;
} rt_flow_slot;

typedef struct {
    atomic_uint epoch;
    atomic_uint readers[2];
    atomic_flag writer;
} rt_rcu_t;

typedef struct {
    rt_alias_slot alias[RT_ALIASES];
    uint8_t alias_head[RT_ALIASES]; /* slot index + 1, 0 = empty */
    unsigned alias_hand;
    rt_flow_slot flow[RT_FLOWS];
    uint8_t flow_head[RT_FLOWS];
} rt_t;

void rt_init(rt_t *t);

/* The critical section. Firmware: portMUX (the tcpip thread must never spin
 * against a preempted lower-priority holder on the same core). Host: spinlock. */
void rt_lock(void);
void rt_unlock(void);

/* Aliases. Insert is idempotent and never changes an existing (id,peer)->alias
 * binding: a conflicting insert is rejected (returns false) because aliases are
 * never reassigned. */
bool rt_alias_find(rt_t *t, uint32_t alias, rt_alias_t *out);
bool rt_alias_find_key(rt_t *t, uint32_t id, uint32_t peer, uint32_t *alias);
bool rt_alias_insert(rt_t *t, const rt_alias_t *record);
unsigned rt_alias_forget(rt_t *t, uint32_t id);

/* Flows. Outbound lookup does not refresh the idle timer: only a packet that is
 * actually forwarded keeps a flow alive (rt_flow_touch). Create reclaims the first
 * free, stale-generation or idle slot (same policy as the previous linear
 * implementation, so mapped ports are identical) and fails when none exists. */
bool rt_flow_out(rt_t *t, uint32_t alias, uint32_t host, uint16_t local, uint16_t remote, uint8_t proto, uint32_t generation, rt_flow_t *out);
void rt_flow_touch(rt_t *t, const rt_flow_t *flow, uint32_t generation, int64_t now);
bool rt_flow_create(rt_t *t, const rt_flow_t *key, uint32_t generation, int64_t now, rt_flow_t *out);
/* Tunnel reply from `peer` for membership `id`: exact tuple or nothing. */
bool rt_flow_in(rt_t *t, uint32_t id, uint32_t peer, uint16_t remote, uint16_t mapped, uint8_t proto, uint32_t generation, int64_t now, rt_flow_t *out);
unsigned rt_flows_forget(rt_t *t, uint32_t id);

/* Quiescent-state RCU. Readers are wait-free. rt_rcu_synchronize returns once
 * every reader that could still hold a pointer unpublished before the call has
 * left its critical section; call it after unpublishing, before freeing. */
void rt_rcu_init(rt_rcu_t *r);
unsigned rt_rcu_enter(rt_rcu_t *r);
void rt_rcu_exit(rt_rcu_t *r, unsigned bucket);
void rt_rcu_synchronize(rt_rcu_t *r);

/* RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m'). `csum` points at the 16-bit field
 * in network order. Replacing a value with itself is a no-op. */
static inline uint16_t rt_csum_adjust(uint16_t csum, uint16_t old_value, uint16_t new_value) {
    uint32_t s = (uint16_t)~csum;
    s += (uint16_t)~old_value;
    s += new_value;
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
static inline void rt_csum_replace16(uint8_t *csum, uint16_t old_value, uint16_t new_value) {
    uint16_t c = rt_csum_adjust((uint16_t)(csum[0] << 8 | csum[1]), old_value, new_value);
    csum[0] = c >> 8;
    csum[1] = c;
}
static inline void rt_csum_replace32(uint8_t *csum, uint32_t old_value, uint32_t new_value) {
    rt_csum_replace16(csum, old_value >> 16, new_value >> 16);
    rt_csum_replace16(csum, (uint16_t)old_value, (uint16_t)new_value);
}
