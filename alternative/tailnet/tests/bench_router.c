/* Host micro-benchmark: per-packet CPU of the old router (tests/reference/router_v1.c)
 * against the new one, driven through the same harness (same pbuf allocation,
 * same capture). The harness cost (a packet the router rejects at once) is
 * measured and printed so it can be read off. Host ns, not ESP32 cycles: use the
 * ratios, and the board's per-task CPU for absolute numbers.
 *
 * Scenarios are the worst case for linear scans: 64 aliases and 64 live flows,
 * traffic spread over all of them (the scan cost depends on position). */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define PK_SHORT_NAMES
#include "router_impl.h"
#include "router_packets.h"
IMPL_API(old_)
IMPL_API(new_)

typedef struct {
    uint8_t bytes[64][1500];
    size_t n[64];
} set_t;
static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}
#define RUN(name, impl_prefix, body, iterations) \
    static double name##_##impl_prefix(set_t *s, unsigned n) { \
        double start = now_ns(); \
        for (unsigned i = 0; i < n; i++) { \
            unsigned k = i & 63; \
            body \
            impl_prefix##clear(); \
        } \
        return (now_ns() - start) / n; \
    }
RUN(outbound, old_, { old_host_packet(s->bytes[k], s->n[k]); }, 0)
RUN(outbound, new_, { new_host_packet(s->bytes[k], s->n[k]); }, 0)
RUN(reply, old_, { old_tunnel_packet(1 + (k & 1), s->bytes[k], s->n[k]); }, 0)
RUN(reply, new_, { new_tunnel_packet(1 + (k & 1), s->bytes[k], s->n[k]); }, 0)
RUN(nothing, old_, { old_host_packet(s->bytes[k], s->n[k]); }, 0)
RUN(nothing, new_, { new_host_packet(s->bytes[k], s->n[k]); }, 0)

static double best(double (*f)(set_t *, unsigned), set_t *s) {
    double b = 1e30;
    for (unsigned r = 0; r < 7; r++) {
        double v = f(s, 100000);
        if (v < b)
            b = v;
    }
    return b;
}
int main(void) {
    old_setup();
    new_setup();
    old_add_member(1, 0x64400001);
    old_add_member(2, 0x64400002);
    new_add_member(1, 0x64400001);
    new_add_member(2, 0x64400002);
    old_set_clock(1000000);
    new_set_clock(1000000);
    uint32_t alias[64];
    for (unsigned i = 0; i < 64; i++) {
        uint32_t id = 1 + (i & 1), peer = 0x64500001 + i;
        alias[i] = old_alias(id, peer);
        assert(alias[i] == new_alias(id, peer));
    }
    for (unsigned size = 0; size < 2; size++) {
        static set_t out, reply_set, none;
        unsigned payload = size ? 1360 : 20; /* full-size data segment, or an ACK-sized one */
        for (unsigned k = 0; k < 64; k++) {
            /* flow k goes to alias k; the table fills in index order, so flow 63 is the last scan position */
            out.n[k] = build_packet(out.bytes[k], 0xc0a84d02, alias[63 - k], k % 3 ? 6 : 17, 3000 + k, 443, payload, false, false);
            none.n[k] = build_packet(none.bytes[k], 0xc0a84d02, 0x08080808, 6, 3000 + k, 443, payload, false, false); /* not ours: harness cost */
        }
        /* create the flows on both, learn the mapped ports, build the replies */
        for (unsigned k = 0; k < 64; k++) {
            old_host_packet(out.bytes[k], out.n[k]);
            new_host_packet(out.bytes[k], out.n[k]);
            const cap_t *c = new_capture(k);
            assert(old_captured() == new_captured());
            reply_set.n[k] = c->n;
            memcpy(reply_set.bytes[k], c->bytes, c->n);
            wr32(reply_set.bytes[k] + 12, c->next_hop);
            wr32(reply_set.bytes[k] + 16, rd32(c->bytes + 12));
            wr16(reply_set.bytes[k] + 20, rd16(c->bytes + 22));
            wr16(reply_set.bytes[k] + 22, rd16(c->bytes + 20));
            fill_checksums(reply_set.bytes[k], c->n, 20, false);
        }
        old_clear();
        new_clear();
        /* replies are addressed to the membership that owns the flow */
        double h_old = best(nothing_old_, &none), h_new = best(nothing_new_, &none);
        double o_old = best(outbound_old_, &out), o_new = best(outbound_new_, &out);
        double r_old = best(reply_old_, &reply_set), r_new = best(reply_new_, &reply_set);
        printf("%4u B payload: harness only %5.0f / %5.0f ns | USB->tunnel old %6.0f new %6.0f ns (net %5.0f -> %5.0f, x%.1f) | tunnel->USB old %6.0f new %6.0f ns (net %5.0f -> %5.0f, x%.1f)\n",
               payload, h_old, h_new, o_old, o_new, o_old - h_old, o_new - h_new, (o_old - h_old) / (o_new - h_new), r_old, r_new, r_old - h_old, r_new - h_new,
               (r_old - h_old) / (r_new - h_new));
    }
    return 0;
}
