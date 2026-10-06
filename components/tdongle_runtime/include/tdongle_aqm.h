#pragma once
/* Active queue management for the transparent bridge's host -> Wi-Fi ingress (ADR 0023 amendment 4): CoDel (RFC 8289) deciding, and ECN marking
 * (RFC 3168) or dropping acting. Portable C with no ESP-IDF dependency: the host tests run the real code against an independent reference.
 *
 * Why it is here at all. With lossless USB backpressure the dongle's own queue is a few milliseconds, but the host's transmit queue sits behind
 * our NAKs and is FIFO: the host's TCP grows its window until that queue is full and every other packet waits behind it (board: ping under upload
 * 55-83 ms in 13 configurations of every dongle setting, 22 ms on the original, which got its low latency from loss). The only lever the dongle has
 * is a congestion signal at the point where it applies backpressure: mark (ECN) or drop the packets that cross it once the pipe has been
 * saturated for longer than a target, which is what CoDel is for.
 *
 * What CoDel is given: a "sojourn" in microseconds. The caller chooses the signal (l2.c: the larger of the packet's own time in the dongle and
 * the time the pipe has been continuously full); this file does not care. */
#include <stdbool.h>
#include <stdint.h>

#define TDONGLE_CODEL_TARGET_US_DEFAULT 5000u
#define TDONGLE_CODEL_INTERVAL_MS_DEFAULT 100u

typedef struct {
    uint32_t target_us, interval_us;
    bool dropping;
    uint32_t first_above_us;     /* time at which the sojourn will have been above target for a full interval; 0: not above */
    uint32_t drop_next_us;
    uint32_t count, lastcount;
} tdongle_codel_t;

static inline void tdongle_codel_init(tdongle_codel_t *c, uint32_t target_us, uint32_t interval_us) {
    c->target_us = target_us;
    c->interval_us = interval_us;
    c->dropping = false;
    c->first_above_us = 0;
    c->drop_next_us = 0;
    c->count = c->lastcount = 0;
}
/* A change of parameters restarts the controller (a state built under other numbers means nothing). */
static inline void tdongle_codel_retune(tdongle_codel_t *c, uint32_t target_us, uint32_t interval_us) { tdongle_codel_init(c, target_us, interval_us); }

/* floor(sqrt(x)) for 32-bit x, by the bitwise method: no libm, no FPU (the S3 has none for double). */
static inline uint32_t tdongle_isqrt(uint32_t x) {
    uint32_t r = 0, bit = 1u << 30;
    while (bit > x) bit >>= 2;
    while (bit) {
        if (x >= r + bit) { x -= r + bit; r = (r >> 1) + bit; } else r >>= 1;
        bit >>= 2;
    }
    return r;
}
/* floor(sqrt(x)) for 64-bit x (same method). Signals are rare (at most a few hundred a second), so 32 iterations are nothing. */
static inline uint64_t tdongle_isqrt64(uint64_t x) {
    uint64_t r = 0, bit = 1ull << 62;
    while (bit > x) bit >>= 2;
    while (bit) {
        if (x >= r + bit) { x -= r + bit; r = (r >> 1) + bit; } else r >>= 1;
        bit >>= 2;
    }
    return r;
}
/* t + interval / sqrt(count): the control law. sqrt(count) in 16.16 fixed point (isqrt64(count << 32) = 65536 sqrt(count)): exact at count 1 and within 1e-5 relative
 * at 65535, where a coarser root made the schedule drift by 50 us per step in the first few signals. */
static inline uint32_t tdongle_codel_control_law(const tdongle_codel_t *c, uint32_t t_us, uint32_t count) {
    const uint64_t root = tdongle_isqrt64((uint64_t)(count ? count : 1u) << 32);
    return t_us + (uint32_t)(((uint64_t)c->interval_us << 16) / root);
}
/* a - b in wrapping microseconds as a signed quantity */
static inline int32_t tdongle_codel_diff(uint32_t a, uint32_t b) { return (int32_t)(a - b); }

/* One packet leaves the queue with this sojourn at time `now_us`: should it be signalled (marked or dropped)? RFC 8289 section 5.5, one packet at a time. The
 * standard loop that drops several packets from one dequeue call is not needed: each packet is decided once, and a packet that finds `now` already past
 * the next scheduled signal is signalled and the schedule advances, so the following packet is signalled too (the same sequence, packet by packet). */
static inline bool tdongle_codel_should_signal(tdongle_codel_t *c, uint32_t sojourn_us, uint32_t now_us) {
    bool ok_to_drop = false;
    if (sojourn_us < c->target_us) {
        c->first_above_us = 0;                                   /* good queue */
    } else if (c->first_above_us == 0) {
        c->first_above_us = now_us + c->interval_us;             /* bad: start the clock of a full interval */
        if (c->first_above_us == 0) c->first_above_us = 1;
    } else if (tdongle_codel_diff(now_us, c->first_above_us) >= 0) {
        ok_to_drop = true;                                       /* above target for a whole interval */
    }
    if (c->dropping) {
        if (!ok_to_drop) {
            c->dropping = false;                                 /* leave the dropping state */
            return false;
        }
        if (tdongle_codel_diff(now_us, c->drop_next_us) >= 0) {
            c->count++;
            c->drop_next_us = tdongle_codel_control_law(c, c->drop_next_us, c->count);
            return true;
        }
        return false;
    }
    if (ok_to_drop) {
        /* Entry: the sojourn has been above target for a whole interval. (RFC 8289's pseudocode guards the entry with one more clause about the time
         * since the last dropping state; what it protects is the choice of count below, kept here, not whether a standing queue is acted on.) */
        c->dropping = true;
        const uint32_t delta = c->count - c->lastcount;
        /* resume near the previous rate if the last dropping state ended recently (RFC 8289: within 16 intervals) */
        c->count = (delta > 1 && tdongle_codel_diff(now_us, c->drop_next_us) < (int32_t)(16u * c->interval_us)) ? delta : 1;
        c->drop_next_us = tdongle_codel_control_law(c, now_us, c->count);
        c->lastcount = c->count;
        return true;
    }
    return false;
}

/* ---- ECN ---------------------------------------------------------------------------------------------------------------------------------------- */
typedef enum {
    TDONGLE_ECN_NOT_IP,          /* not IPv4/IPv6 (ARP, ...), or malformed: never marked, never dropped */
    TDONGLE_ECN_EXEMPT,          /* IP, but never signalled: connection setup/teardown, DHCP, ICMPv6 neighbour discovery and the like */
    TDONGLE_ECN_NOT_ECT,         /* IP, may be dropped, cannot be marked */
    TDONGLE_ECN_CAPABLE,         /* ECT(0) or ECT(1): can be marked CE */
    TDONGLE_ECN_CE               /* already CE: a router cannot mark it again, and a signal for it is satisfied */
} tdongle_ecn_class_t;

/* Classify an Ethernet frame. Reads only what it needs, trusts no length. */
static inline tdongle_ecn_class_t tdongle_ecn_classify(const uint8_t *f, uint16_t len) {
    if (len < 14u) return TDONGLE_ECN_NOT_IP;
    const unsigned type = ((unsigned)f[12] << 8) | f[13];
    unsigned ecn;
    if (type == 0x0800 && len >= 14u + 20u && (f[14] >> 4) == 4) {
        const unsigned ihl = (unsigned)(f[14] & 0x0f) * 4u, proto = f[23];
        if (ihl < 20u || 14u + ihl > len) return TDONGLE_ECN_NOT_IP;
        const unsigned frag = (((unsigned)f[20] & 0x1f) << 8) | f[21];                 /* fragment offset (13 bits): only the first fragment carries a transport header */
        if (proto == 6 && !frag && len >= 14u + ihl + 14u) {
            if (f[14 + ihl + 13] & 0x07) return TDONGLE_ECN_EXEMPT;                    /* FIN, SYN, RST: connection setup and teardown */
        }
        if (proto == 17 && !frag && len >= 14u + ihl + 4u) {
            const unsigned dst = ((unsigned)f[14 + ihl + 2] << 8) | f[14 + ihl + 3], src = ((unsigned)f[14 + ihl] << 8) | f[14 + ihl + 1];
            if (dst == 67 || dst == 68 || src == 67 || src == 68) return TDONGLE_ECN_EXEMPT;     /* DHCP */
        }
        ecn = f[15] & 3u;
    } else if (type == 0x86dd && len >= 14u + 40u && (f[14] >> 4) == 6) {
        const unsigned next = f[20];
        if (next == 58) return TDONGLE_ECN_EXEMPT;                                     /* ICMPv6: neighbour discovery, router advertisements */
        if (next == 6 && len >= 14u + 40u + 14u && (f[14 + 40 + 13] & 0x07)) return TDONGLE_ECN_EXEMPT;
        if (next == 17 && len >= 14u + 40u + 4u) {
            const unsigned dst = ((unsigned)f[14 + 40 + 2] << 8) | f[14 + 40 + 3];
            if (dst == 546 || dst == 547) return TDONGLE_ECN_EXEMPT;                   /* DHCPv6 */
        }
        ecn = (f[15] >> 4) & 3u;
    } else {
        return TDONGLE_ECN_NOT_IP;
    }
    return ecn == 0 ? TDONGLE_ECN_NOT_ECT : ecn == 3 ? TDONGLE_ECN_CE : TDONGLE_ECN_CAPABLE;
}
/* Set CE on a TDONGLE_ECN_CAPABLE frame, in place. IPv4: the header checksum is corrected incrementally (RFC 1624 eqn 3: HC' = ~(~HC + ~m + m')), so
 * it is valid afterwards without a pass over the header. IPv6 has no header checksum, and neither TCP's nor UDP's pseudo header covers the ECN field. */
static inline void tdongle_ecn_mark_ce(uint8_t *f) {
    const unsigned type = ((unsigned)f[12] << 8) | f[13];
    if (type == 0x0800) {
        const uint16_t m = (uint16_t)((f[14] << 8) | f[15]);                           /* the 16-bit word holding version/IHL and TOS */
        const uint16_t m2 = (uint16_t)(m | 3u);
        uint32_t sum = (uint16_t)~((f[24] << 8) | f[25]);
        sum += (uint16_t)~m;
        sum += m2;
        sum = (sum & 0xffffu) + (sum >> 16);
        sum = (sum & 0xffffu) + (sum >> 16);
        const uint16_t hc = (uint16_t)~sum;
        f[15] = (uint8_t)(f[15] | 3u);
        f[24] = (uint8_t)(hc >> 8);
        f[25] = (uint8_t)hc;
    } else {
        f[15] = (uint8_t)(f[15] | 0x30u);                                              /* ECN bits are bits 5..4 of the second byte of the header */
    }
}

/* ECN negotiation, for diagnosis (the board's first CoDel sweep marked nothing: was ECN ever negotiated through this path?). RFC 3168: an initiator asks with
 * SYN+ECE+CWR, a server that accepts answers SYN+ACK+ECE (CWR clear). Anything else: 0. IPv4 and IPv6 without extension headers. */
typedef enum { TDONGLE_TCP_OTHER = 0, TDONGLE_TCP_SYN_ECN_SETUP, TDONGLE_TCP_SYNACK_ECN_ACCEPT } tdongle_tcp_ecn_syn_t;
static inline tdongle_tcp_ecn_syn_t tdongle_tcp_ecn_syn(const uint8_t *f, uint16_t len) {
    if (len < 14u) return TDONGLE_TCP_OTHER;
    const unsigned type = ((unsigned)f[12] << 8) | f[13];
    unsigned flags;
    if (type == 0x0800 && len >= 14u + 20u && (f[14] >> 4) == 4) {
        const unsigned ihl = (unsigned)(f[14] & 0x0f) * 4u;
        if (ihl < 20u || f[23] != 6 || 14u + ihl + 14u > len || (((f[20] & 0x1f) << 8) | f[21])) return TDONGLE_TCP_OTHER;
        flags = f[14 + ihl + 13];
    } else if (type == 0x86dd && len >= 14u + 40u + 14u && (f[14] >> 4) == 6 && f[20] == 6) {
        flags = f[14 + 40 + 13];
    } else {
        return TDONGLE_TCP_OTHER;
    }
    const bool syn = flags & 0x02, ack = flags & 0x10, ece = flags & 0x40, cwr = flags & 0x80;
    if (syn && !ack && ece && cwr) return TDONGLE_TCP_SYN_ECN_SETUP;
    if (syn && ack && ece && !cwr) return TDONGLE_TCP_SYNACK_ECN_ACCEPT;
    return TDONGLE_TCP_OTHER;
}
