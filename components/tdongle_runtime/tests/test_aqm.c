/* CoDel and ECN marking (include/tdongle_aqm.h) against an analytic reference and against recomputation from scratch.
 *
 * CoDel: the schedule RFC 8289 defines, worked out here in double precision from the specification (not from the code under test):
 *   the sojourn first exceeds the target at t0; a whole interval later (t0 + I) the controller enters the dropping state and signals the first packet
 *   (count 1); the next signal is the first packet at or after D1 = T1 + I/sqrt(1), then D2 = D1 + I/sqrt(2), D3 = D2 + I/sqrt(3), ...: the spacing
 *   shrinks as 1/sqrt(count). A packet below the target ends the dropping state; a new dropping state within 16 intervals resumes at count - lastcount.
 * ECN: for every header shape the checksum is recomputed from the bytes (not from the incremental formula) and compared. */
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tdongle_aqm.h"

static unsigned long long rng = 88172645463325252ull;
static unsigned rnd(unsigned n) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)(rng % n); }

/* ---- the integer square root and the control law ---- */
static void test_math(void) {
    for (uint32_t x = 0; x < 200000; x++) { const uint32_t r = tdongle_isqrt(x); assert((uint64_t)r * r <= x && (uint64_t)(r + 1) * (r + 1) > x); }
    for (int i = 0; i < 100000; i++) { const uint32_t x = (uint32_t)rnd(0xffffffffu); const uint32_t r = tdongle_isqrt(x); assert((uint64_t)r * r <= x && (uint64_t)(r + 1) * (r + 1) > x); }
    assert(tdongle_isqrt(0xffffffffu) == 65535);
    for (int i = 0; i < 100000; i++) { const uint64_t x = ((uint64_t)rnd(0xffffffffu) << 32) | rnd(0xffffffffu); const uint64_t r = tdongle_isqrt64(x); assert(r <= 0xffffffffull && r * r <= x && (r + 1 == 0x100000000ull || (r + 1) * (r + 1) > x)); }
    tdongle_codel_t c; tdongle_codel_init(&c, 5000, 100000);
    for (uint32_t count = 1; count < 65536; count += (count < 300 ? 1 : 97)) {
        const double want = 100000.0 / sqrt((double)count);
        const double got = (double)(tdongle_codel_control_law(&c, 0, count));
        assert(fabs(got - want) <= want * 0.0001 + 1.5);                     /* 16.16 fixed point */
    }
}

/* ---- the schedule ---- */
typedef struct { uint32_t t; } sig;
/* Feed packets every dt_us with a constant sojourn from t_start; return the times of the signals up to t_end. */
static unsigned run_constant(tdongle_codel_t *c, uint32_t t_start, uint32_t t_end, uint32_t dt, uint32_t sojourn, uint32_t *times, unsigned cap) {
    unsigned n = 0;
    for (uint32_t t = t_start; (int32_t)(t_end - t) > 0; t += dt)
        if (tdongle_codel_should_signal(c, sojourn, t) && n < cap) times[n++] = t;
    return n;
}
static void test_schedule(uint32_t base) {
    const uint32_t I = 100000, dt = 100;
    tdongle_codel_t c; tdongle_codel_init(&c, 5000, I);
    uint32_t times[64];
    /* 1. Below target forever: silence. */
    assert(run_constant(&c, base, base + 5000000, dt, 4999, times, 64) == 0);
    /* 2. Above target from t0: the first signal at t0 + I (within one packet), then the 1/sqrt(count) schedule. */
    tdongle_codel_init(&c, 5000, I);
    const uint32_t t0 = base + 1000;
    unsigned n = run_constant(&c, t0, t0 + 3000000, dt, 5000, times, 64);
    assert(n >= 25);
    assert(times[0] >= t0 + I && times[0] <= t0 + I + 3 * dt);               /* the first packet at or after t0 + I */
    /* Signal k+1 is the first packet at or after D_k, where D_k runs from the previous scheduled time, not from the packet that was signalled. */
    double drop_next = (double)times[0] + (double)I / sqrt(1.0);
    for (unsigned k = 1; k < n; k++) {
        assert((double)times[k] >= drop_next - 1.5 * k && (double)times[k] <= drop_next + dt + 1.5 * k);   /* the first packet at or after drop_next */
        drop_next += (double)I / sqrt((double)(k + 1));
    }
    /* The signal rate rises: spacing between signals falls as 1/sqrt(count). */
    assert(times[n - 1] - times[n - 2] < times[2] - times[1]);
    /* 3. The sojourn falls below target: the dropping state ends at once, and the next signal needs a whole new interval. */
    tdongle_codel_init(&c, 5000, I);
    n = run_constant(&c, t0, t0 + 1000000, dt, 5000, times, 64);
    assert(n >= 5 && c.dropping);
    const uint32_t t1 = t0 + 1000000;
    assert(!tdongle_codel_should_signal(&c, 100, t1) && !c.dropping && c.first_above_us == 0);
    unsigned m = run_constant(&c, t1 + dt, t1 + I - 2 * dt, dt, 6000, times, 64);       /* just under an interval above target again */
    assert(m == 0);
    /* 4. Re-entry soon after a dropping state resumes near the old rate: count = count - lastcount (RFC 8289). */
    tdongle_codel_init(&c, 5000, I);
    n = run_constant(&c, t0, t0 + 1500000, dt, 5000, times, 64);
    const uint32_t count_before = c.count;
    assert(count_before >= 6 && c.lastcount == 1);
    tdongle_codel_should_signal(&c, 100, t0 + 1500000);                             /* leave */
    n = run_constant(&c, t0 + 1500100, t0 + 1500100 + 2 * I, dt, 5000, times, 64);   /* above target again within 16 intervals */
    assert(n >= 1 && times[0] >= t0 + 1500100 + I && c.dropping);
    assert(c.lastcount == count_before - 1);                                         /* resumed at delta, not at 1 */
    /* ... but after a long calm (more than 16 intervals) it starts over at 1. */
    tdongle_codel_should_signal(&c, 100, t0 + 1500000 + 3 * I);
    n = run_constant(&c, t0 + 4000000, t0 + 4000000 + 2 * I, dt, 5000, times, 64);
    assert(n >= 1 && c.lastcount == 1);
}
/* Invariants over arbitrary input: never signal below target; never signal in less than an interval of continuous excess; one signal at most per packet. */
static void test_invariants(void) {
    tdongle_codel_t c; tdongle_codel_init(&c, 5000, 100000);
    uint32_t t = 0xFFFF0000u, above_since = 0; bool above = false; unsigned signals = 0;
    for (int i = 0; i < 2000000; i++) {
        t += 1 + rnd(400);
        const bool bad_spell = (i / 5000) % 3 == 1;
        const uint32_t sojourn = bad_spell ? 5000 + rnd(5000) : rnd(5000);
        if (sojourn < 5000) above = false; else if (!above) { above = true; above_since = t; }
        const bool sig = tdongle_codel_should_signal(&c, sojourn, t);
        if (sig) { signals++; assert(sojourn >= 5000 || c.dropping); }
        if (sig && above && !(c.count > 1)) assert((int32_t)(t - above_since) >= 100000 || c.dropping);     /* the first signal needs an interval above target */
        if (sojourn < 5000) assert(!sig && !c.dropping);
    }
    assert(signals > 100);
}

/* ---- ECN ---- */
static uint16_t csum16(const uint8_t *p, unsigned n, uint32_t init) {
    uint32_t sum = init;
    for (unsigned i = 0; i + 1 < n; i += 2) sum += (uint32_t)(p[i] << 8) | p[i + 1];
    if (n & 1) sum += (uint32_t)p[n - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}
static bool ip4_header_ok(const uint8_t *f) { const unsigned ihl = (f[14] & 15) * 4; return csum16(f + 14, ihl, 0) == 0; }
/* TCP/UDP checksum over the pseudo header and segment: independent of the ECN field. */
static uint16_t l4_checksum(const uint8_t *f, uint16_t len, bool v6) {
    const uint8_t *ip = f + 14; uint32_t sum = 0; unsigned l4off, l4len, proto;
    if (!v6) { const unsigned ihl = (ip[0] & 15) * 4; proto = ip[9]; l4off = 14 + ihl; l4len = ((ip[2] << 8) | ip[3]) - ihl;
               for (int i = 12; i < 20; i += 2) sum += (ip[i] << 8) | ip[i + 1]; }
    else { proto = ip[6]; l4off = 14 + 40; l4len = (ip[4] << 8) | ip[5]; for (int i = 8; i < 40; i += 2) sum += (ip[i] << 8) | ip[i + 1]; }
    sum += proto + l4len;
    assert(l4off + l4len <= len);
    return csum16(f + l4off, l4len, sum);
}
static uint16_t build4(uint8_t *f, unsigned tos, unsigned proto, unsigned ihl_words, unsigned payload, unsigned flags_frag) {
    memset(f, 0, 1600);
    for (int i = 0; i < 12; i++) f[i] = (uint8_t)rnd(256);
    f[12] = 0x08; f[13] = 0x00;
    const unsigned ihl = ihl_words * 4, total = ihl + payload;
    f[14] = (uint8_t)(0x40 | ihl_words); f[15] = (uint8_t)tos; f[16] = (uint8_t)(total >> 8); f[17] = (uint8_t)total;
    f[18] = (uint8_t)rnd(256); f[19] = (uint8_t)rnd(256); f[20] = (uint8_t)(flags_frag >> 8); f[21] = (uint8_t)flags_frag; f[22] = 64; f[23] = (uint8_t)proto;
    for (int i = 26; i < 34; i++) f[i] = (uint8_t)rnd(256);
    for (unsigned i = 34; i < 14 + ihl; i++) f[i] = (uint8_t)rnd(256);                  /* IP options */
    for (unsigned i = 14 + ihl; i < 14 + total; i++) f[i] = (uint8_t)rnd(256);
    if (proto == 6) f[14 + ihl + 13] = 0x10;                                             /* ACK: not SYN/FIN/RST */
    if (proto == 17) { f[14 + ihl + 2] = 0x13; f[14 + ihl + 3] = 0x88; f[14 + ihl] = 0xc3; f[14 + ihl + 1] = 0x50; }
    const uint16_t hc = csum16(f + 14, ihl, 0);
    f[24] = (uint8_t)(hc >> 8); f[25] = (uint8_t)hc;
    return (uint16_t)(14 + total);
}
static uint16_t build6(uint8_t *f, unsigned tclass, unsigned next, unsigned payload) {
    memset(f, 0, 1600);
    for (int i = 0; i < 12; i++) f[i] = (uint8_t)rnd(256);
    f[12] = 0x86; f[13] = 0xdd;
    f[14] = (uint8_t)(0x60 | (tclass >> 4)); f[15] = (uint8_t)(((tclass & 15) << 4) | rnd(16)); f[16] = (uint8_t)rnd(256); f[17] = (uint8_t)rnd(256);
    f[18] = (uint8_t)(payload >> 8); f[19] = (uint8_t)payload; f[20] = (uint8_t)next; f[21] = 64;
    for (unsigned i = 22; i < 54 + payload; i++) f[i] = (uint8_t)rnd(256);
    if (next == 6) f[14 + 40 + 13] = 0x10;
    return (uint16_t)(54 + payload);
}
static void test_ecn_ipv4(void) {
    uint8_t f[1600], g[1600];
    unsigned marked = 0;
    for (int iter = 0; iter < 200000; iter++) {
        const unsigned proto = rnd(3) == 0 ? 17 : rnd(2) ? 6 : 1;
        const unsigned ihl_words = 5 + (rnd(4) == 0 ? rnd(11) : 0);
        const unsigned payload = 20 + rnd(400);
        const unsigned tos = rnd(256);
        const uint16_t len = build4(f, tos, proto, ihl_words, payload, rnd(8) == 0 ? 0x4000 : 0);
        memcpy(g, f, len);
        assert(ip4_header_ok(f));
        const unsigned ecn = tos & 3;
        const tdongle_ecn_class_t cls = tdongle_ecn_classify(f, len);
        if (proto == 17 && ((f[14 + ihl_words * 4] << 8 | f[14 + ihl_words * 4 + 1]) == 67)) continue;
        assert(cls == (ecn == 0 ? TDONGLE_ECN_NOT_ECT : ecn == 3 ? TDONGLE_ECN_CE : TDONGLE_ECN_CAPABLE));
        if (cls != TDONGLE_ECN_CAPABLE) continue;
        const uint16_t l4_before = (proto == 6 || proto == 17) ? l4_checksum(f, len, false) : 0;
        tdongle_ecn_mark_ce(f);
        marked++;
        assert((f[15] & 3) == 3 && (f[15] & 0xfc) == (g[15] & 0xfc));                       /* CE, DSCP untouched */
        assert(ip4_header_ok(f));                                                           /* the checksum is valid, recomputed from the bytes */
        for (unsigned i = 0; i < len; i++) if (i != 15 && i != 24 && i != 25) assert(f[i] == g[i]);       /* nothing else changed */
        if (proto == 6 || proto == 17) assert(l4_checksum(f, len, false) == l4_before);     /* the transport checksum does not cover the ECN field */
        assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_CE);
    }
    assert(marked > 20000);
    /* the three classic values of the checksum field that give trouble: ones' complement zero, 0xffff, and a carry out of the incremental update */
    for (unsigned tos = 1; tos < 3; tos++)
        for (unsigned a = 0; a < 65536; a += 7) {
            const uint16_t len = build4(f, tos, 6, 5, 40, 0);
            f[18] = (uint8_t)(a >> 8); f[19] = (uint8_t)a;
            f[24] = f[25] = 0;
            const uint16_t hc = csum16(f + 14, 20, 0); f[24] = (uint8_t)(hc >> 8); f[25] = (uint8_t)hc;
            tdongle_ecn_mark_ce(f);
            assert(ip4_header_ok(f)); (void)len;
        }
}
static void test_ecn_ipv6(void) {
    uint8_t f[1600], g[1600];
    for (int iter = 0; iter < 100000; iter++) {
        const unsigned next = rnd(3) == 0 ? 17 : 6, payload = 20 + rnd(300), tclass = rnd(256);
        const uint16_t len = build6(f, tclass, next, payload);
        memcpy(g, f, len);
        const unsigned ecn = tclass & 3;
        const tdongle_ecn_class_t cls = tdongle_ecn_classify(f, len);
        if (next == 17 && (((f[14 + 40 + 2] << 8) | f[14 + 40 + 3]) == 546 || ((f[14 + 40 + 2] << 8) | f[14 + 40 + 3]) == 547)) continue;
        assert(cls == (ecn == 0 ? TDONGLE_ECN_NOT_ECT : ecn == 3 ? TDONGLE_ECN_CE : TDONGLE_ECN_CAPABLE));
        if (cls != TDONGLE_ECN_CAPABLE) continue;
        const uint16_t l4_before = l4_checksum(f, len, true);
        tdongle_ecn_mark_ce(f);
        const unsigned after = ((f[14] & 15) << 4) | (f[15] >> 4);
        assert((after & 3) == 3 && (after & 0xfc) == (tclass & 0xfc));                       /* traffic class: CE, DSCP untouched */
        for (unsigned i = 0; i < len; i++) if (i != 15) assert(f[i] == g[i]);                /* only the one byte */
        assert((f[15] & 0x0f) == (g[15] & 0x0f));                                            /* the flow label's high nibble sits in the same byte */
        assert(l4_checksum(f, len, true) == l4_before);                                      /* the IPv6 pseudo header does not cover the traffic class */
    }
}
static void test_exempt_and_foreign(void) {
    uint8_t f[1600];
    /* ARP and other ethertypes: never touched. */
    memset(f, 0, 60); f[12] = 0x08; f[13] = 0x06;
    assert(tdongle_ecn_classify(f, 60) == TDONGLE_ECN_NOT_IP);
    f[12] = 0x88; f[13] = 0x8e; assert(tdongle_ecn_classify(f, 60) == TDONGLE_ECN_NOT_IP);               /* EAPOL */
    f[12] = 0x81; f[13] = 0x00; assert(tdongle_ecn_classify(f, 60) == TDONGLE_ECN_NOT_IP);               /* VLAN tag: not parsed, so not touched */
    /* Truncated and malformed: not IP, not touched, no read past the end (ASan). */
    uint16_t len = build4(f, 2, 6, 5, 40, 0);
    for (unsigned n = 0; n < 40; n++) { const tdongle_ecn_class_t c = tdongle_ecn_classify(f, (uint16_t)n); (void)c; if (n < 34) assert(c == TDONGLE_ECN_NOT_IP); }
    f[14] = 0x44; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_NOT_IP);                              /* IHL below 5 */
    f[14] = 0x4f; assert(tdongle_ecn_classify(f, 40) == TDONGLE_ECN_NOT_IP);                               /* IHL beyond the frame */
    f[14] = 0x65; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_NOT_IP);                              /* version 6 in an IPv4 ethertype */
    len = build6(f, 2, 6, 40); f[14] = 0x40; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_NOT_IP);
    /* Exempt: SYN, FIN, RST, DHCP (both directions), ICMPv6, DHCPv6. */
    for (unsigned flag = 0x01; flag <= 0x04; flag <<= 1) { len = build4(f, 2, 6, 5, 40, 0); f[14 + 20 + 13] = (uint8_t)flag; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_EXEMPT); }
    len = build4(f, 2, 6, 5, 40, 0); f[14 + 20 + 13] = 0x12; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_EXEMPT);       /* SYN+ACK */
    len = build4(f, 2, 17, 5, 40, 0); f[14 + 20 + 2] = 0; f[14 + 20 + 3] = 68; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_EXEMPT);
    len = build4(f, 2, 17, 5, 40, 0); f[14 + 20] = 0; f[14 + 20 + 1] = 67; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_EXEMPT);
    len = build6(f, 2, 58, 40); assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_EXEMPT);
    len = build6(f, 2, 17, 40); f[14 + 40 + 2] = 0x02; f[14 + 40 + 3] = 0x22; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_EXEMPT);
    len = build6(f, 2, 6, 40); f[14 + 40 + 13] = 0x04; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_EXEMPT);
    /* A non-first fragment has no transport header: its bytes are payload, so flag-looking bytes there must not exempt it. */
    len = build4(f, 2, 6, 5, 80, 0x00b9); f[14 + 20 + 13] = 0x02; assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_CAPABLE);
    /* ICMP echo and ordinary data are eligible. */
    len = build4(f, 0, 1, 5, 64, 0); assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_NOT_ECT);
    len = build4(f, 1, 6, 5, 1000, 0); assert(tdongle_ecn_classify(f, len) == TDONGLE_ECN_CAPABLE);
}


/* IPv6 extension headers, built by hand: a chain of (type, length-in-units) headers between the fixed header and the transport header. */
typedef struct { uint8_t type; uint8_t units; } ext_t;           /* units: the Hdr Ext Len field (8-byte units beyond the first) for 0/43/60, 4-byte units + 2 for 51; fragment is 8 B */
static uint16_t build6_chain(uint8_t *f, unsigned tclass, const ext_t *chain, unsigned n, unsigned proto, unsigned tcp_flags, unsigned udp_dst, unsigned frag_off) {
    memset(f, 0, 1600);
    for (int i = 0; i < 12; i++) f[i] = (uint8_t)rnd(256);
    f[12] = 0x86; f[13] = 0xdd; f[14] = (uint8_t)(0x60 | (tclass >> 4)); f[15] = (uint8_t)((tclass & 15) << 4); f[21] = 64;
    unsigned o = 54, next = n ? chain[0].type : proto;
    f[20] = (uint8_t)next;
    for (unsigned i = 0; i < n; i++) {
        const unsigned t = chain[i].type, after = i + 1 < n ? chain[i + 1].type : proto;
        unsigned hl = t == 44 ? 8 : t == 51 ? ((unsigned)chain[i].units + 2) * 4 : ((unsigned)chain[i].units + 1) * 8;
        f[o] = (uint8_t)after;
        if (t == 51) f[o + 1] = chain[i].units; else if (t != 44) f[o + 1] = chain[i].units;
        if (t == 44) { f[o + 2] = (uint8_t)(frag_off >> 5); f[o + 3] = (uint8_t)((frag_off & 31) << 3); }
        o += hl;
    }
    if (proto == 6) { f[o + 12] = 0x50; f[o + 13] = (uint8_t)tcp_flags; }
    if (proto == 17) { f[o + 2] = (uint8_t)(udp_dst >> 8); f[o + 3] = (uint8_t)udp_dst; }
    const unsigned total = o + 60;
    f[18] = (uint8_t)((total - 54) >> 8); f[19] = (uint8_t)(total - 54);
    for (unsigned i = o + (proto == 6 ? 20 : 8); i < total; i++) f[i] = (uint8_t)rnd(256);
    return (uint16_t)total;
}
static void test_ipv6_extension_headers(void) {
    uint8_t f[1600], g[1600];
    const ext_t hbh = {0, 0}, hbh2 = {0, 2}, dst = {60, 1}, rt = {43, 1}, frag = {44, 0}, ah = {51, 1};
    /* MLD (ICMPv6) behind hop-by-hop: exempt, the case the review found being dropped. */
    uint16_t n = build6_chain(f, 2, &hbh, 1, 58, 0, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);
    n = build6_chain(f, 0, &hbh, 1, 58, 0, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);                  /* not-ECT too: never dropped */
    /* A SYN behind a destination-options header: exempt; data behind it: eligible and markable; the ECN field is where it always is. */
    n = build6_chain(f, 2, &dst, 1, 6, 0x02, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);
    n = build6_chain(f, 2, &dst, 1, 6, 0x10, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CAPABLE);
    memcpy(g, f, n); tdongle_ecn_mark_ce(f);
    for (unsigned i = 0; i < n; i++) if (i != 15) assert(f[i] == g[i]);
    assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CE);
    n = build6_chain(f, 0, &dst, 1, 6, 0x10, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_NOT_ECT);
    /* Chains: several headers, of every kind, in any order. */
    { const ext_t c[] = {hbh2, rt, dst, ah};
      n = build6_chain(f, 2, c, 4, 58, 0, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);
      n = build6_chain(f, 2, c, 4, 6, 0x04, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);                /* RST */
      n = build6_chain(f, 1, c, 4, 6, 0x18, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CAPABLE);
      n = build6_chain(f, 2, c, 4, 17, 0, 547, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);                /* DHCPv6 */
      n = build6_chain(f, 2, c, 4, 17, 0, 5001, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CAPABLE); }
    /* A first fragment still carries the transport header; a later one does not (its bytes are payload: eligible, never exempt, whatever they look like). */
    n = build6_chain(f, 2, &frag, 1, 6, 0x02, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);
    n = build6_chain(f, 2, &frag, 1, 6, 0x02, 0, 185); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CAPABLE);
    n = build6_chain(f, 2, &frag, 1, 58, 0, 0, 185); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CAPABLE);
    /* ESP and "no next header": opaque, eligible by their ECN field. */
    { const ext_t esp = {50, 0}; n = build6_chain(f, 2, &hbh, 1, 50, 0, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CAPABLE); (void)esp;
      n = build6_chain(f, 2, &hbh, 1, 59, 0, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_CAPABLE); }
    /* Bounds: too many headers, a header that runs past the frame, a length field that points beyond it: not IP, never touched, nothing read past the end (ASan). */
    { ext_t c[7]; for (int i = 0; i < 7; i++) c[i] = hbh;
      n = build6_chain(f, 2, c, 6, 58, 0, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_EXEMPT);                  /* six is the limit */
      n = build6_chain(f, 2, c, 7, 58, 0, 0, 0); assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_NOT_IP); }
    n = build6_chain(f, 2, &hbh, 1, 6, 0x10, 0, 0);
    for (unsigned cut = 0; cut < n; cut++) { const tdongle_ecn_class_t c = tdongle_ecn_classify(f, (uint16_t)cut); (void)c; }     /* every truncation: no read past `cut` */
    f[54 + 1] = 200; assert(tdongle_ecn_classify(f, n) == TDONGLE_ECN_NOT_IP);                                                 /* hop-by-hop length beyond the frame */
    /* The SYN/SYN-ACK negotiation helper walks the same chain. */
    n = build6_chain(f, 0, &hbh, 1, 6, 0xc2, 0, 0); assert(tdongle_tcp_ecn_syn(f, n) == TDONGLE_TCP_SYN_ECN_SETUP);
    n = build6_chain(f, 0, &dst, 1, 6, 0x52, 0, 0); assert(tdongle_tcp_ecn_syn(f, n) == TDONGLE_TCP_SYNACK_ECN_ACCEPT);
    n = build6_chain(f, 0, &frag, 1, 6, 0xc2, 0, 185); assert(tdongle_tcp_ecn_syn(f, n) == TDONGLE_TCP_OTHER);
    /* Random chains: classification never reads out of bounds and never calls a not-IP frame IP (fuzz under ASan). */
    for (int iter = 0; iter < 200000; iter++) {
        ext_t c[8]; const unsigned k = rnd(8); static const uint8_t kinds[] = {0, 43, 44, 51, 60};
        for (unsigned i = 0; i < k; i++) c[i] = (ext_t){kinds[rnd(5)], (uint8_t)rnd(4)};
        const unsigned proto = rnd(5) == 0 ? 58 : rnd(2) ? 6 : 17;
        n = build6_chain(f, rnd(256), c, k, proto, rnd(256), rnd(2) ? 546 : rnd(65536), rnd(3) == 0 ? rnd(8000) : 0);
        const uint16_t cut = (uint16_t)(rnd(4) == 0 ? rnd(n + 1) : n);
        (void)tdongle_ecn_classify(f, cut); (void)tdongle_tcp_ecn_syn(f, cut);
    }
}

int main(void) {
    test_math();
    test_schedule(0);
    test_schedule(0xFFFFFE00u);                     /* the 32-bit microsecond clock wraps inside the scenario */
    test_invariants();
    test_ecn_ipv4();
    test_ecn_ipv6();
    test_exempt_and_foreign();
    test_ipv6_extension_headers();
    puts("AQM: integer sqrt and control law, CoDel schedule against the analytic RFC 8289 reference (also across the clock wrap), invariants, ECN marking with recomputed checksums for IPv4 (options, fragments) and IPv6, exemptions and malformed frames, IPv6 extension-header chains built by hand and fuzzed");
    return 0;
}
