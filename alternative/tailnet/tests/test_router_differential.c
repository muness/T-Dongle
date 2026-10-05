/* Differential test: the old linear/locked router (tests/reference/router_v1.c)
 * and the new hashed/RCU router receive the same random stream of packets and
 * control events. Everything either one emits must match: which packets are
 * forwarded, to whom, with which rewritten addresses, ports, TTL and payload,
 * and valid checksums. Only the two representations of a zero checksum may
 * differ. Run with a seed argument; test-gateway.sh runs several. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "router_impl.h"
IMPL_API(old_)
IMPL_API(new_)

#define PK_SHORT_NAMES
#include "router_packets.h"
static bool zero_pair(uint16_t a, uint16_t b) { return (a == 0 && b == 0xffff) || (a == 0xffff && b == 0); }

enum { LIVE_MAX = 4, PEERS = 6, SEEN = 64 };
typedef struct {
    uint32_t id, peer, vpn, host;
    uint16_t mapped, remote;
    uint8_t proto;
} seen_t;
static seen_t seen[SEEN];
static unsigned seen_n;

static void learn(void) {
    /* every packet sent to a tunnel is a flow whose reply we may later send */
    for (unsigned i = 0; i < old_captured(); i++) {
        const cap_t *c = old_capture(i);
        if (c->kind != 0)
            continue;
        seen_t s = {c->member, c->next_hop, rd32(c->bytes + 12), 0, rd16(c->bytes + 20), rd16(c->bytes + 22), c->bytes[9]};
        seen[seen_n < SEEN ? seen_n++ : rnd() % SEEN] = s;
    }
}

/* After every event the two flow tables must be identical slot for slot: same
 * owner, tuple, mapped port, generation and idle timer. */
static void compare_tables(const char *what) {
    flow_row a[64], b[64];
    old_flows(a);
    new_flows(b);
    for (unsigned i = 0; i < 64; i++)
        if (memcmp(&a[i], &b[i], sizeof(a[i])) && !(a[i].id == 0 && b[i].id == 0)) {
            fprintf(stderr, "%s: slot %u differs: old id=%u host=%x %u>%u mapped=%u gen=%u t=%lld | new id=%u host=%x %u>%u mapped=%u gen=%u t=%lld\n", what, i, a[i].id, a[i].host, a[i].local, a[i].remote, a[i].mapped, a[i].generation, (long long)a[i].touched, b[i].id, b[i].host, b[i].local, b[i].remote, b[i].mapped, b[i].generation, (long long)b[i].touched);
            abort();
        }
}
static unsigned forwarded_out, forwarded_in, dropped, mismatches_allowed_zero;
static uint8_t last_in[1500];
static size_t last_in_n;
static void compare(const char *what) {
    unsigned a = old_captured(), b = new_captured();
    if (a == b && a && getenv("DEBUGFLOWS") && memcmp(old_capture(0)->bytes + 20, new_capture(0)->bytes + 20, 2)) {
        old_debug(rd32(last_in + 16));
        new_debug(rd32(last_in + 16));
    }
    if (a != b) {
        for (size_t i = 0; i < last_in_n && i < 64; i++)
            fprintf(stderr, "%02x%s", last_in[i], i % 4 == 3 ? " " : "");
        fprintf(stderr, "\n");
        if (last_in_n >= 20) { old_debug(rd32(last_in + 16)); new_debug(rd32(last_in + 16)); }
        fprintf(stderr, "%s: old emitted %u packets, new %u\n", what, a, b);
        abort();
    }
    for (unsigned i = 0; i < a; i++) {
        const cap_t *x = old_capture(i), *y = new_capture(i);
        assert(x->kind == y->kind && x->member == y->member && x->next_hop == y->next_hop && x->n == y->n);
        unsigned h = (x->bytes[0] & 15) * 4;
        uint8_t u[1500], v[1500];
        memcpy(u, x->bytes, x->n);
        memcpy(v, y->bytes, y->n);
        /* checksums: both valid; compare the rest byte for byte */
        assert(finish(sum(u, h, 0)) == 0 && finish(sum(v, h, 0)) == 0);
        assert(l4_valid(u, x->n, h) && l4_valid(v, y->n, h));
        unsigned offset = h + (u[9] == 6 ? 16 : 6);
        uint16_t cu = rd16(u + offset), cv = rd16(v + offset);
        if (cu != cv) {
            /* the only legitimate difference: new keeps a UDP "no checksum" (0) the old one
             * replaced, or the two representations of zero */
            if (!(zero_pair(cu, cv) || (u[9] == 17 && cv == 0)))
                fprintf(stderr, "%s kind %d proto %u old %04x new %04x n=%zu h=%u\n", what, x->kind, u[9], cu, cv, x->n, h);
            mismatches_allowed_zero++;
        }
        wr16(u + offset, 0); wr16(v + offset, 0);
        wr16(u + 10, 0); wr16(v + 10, 0);
        if (memcmp(u, v, x->n)) {
            for (size_t i = 0; i < x->n; i++)
                if (u[i] != v[i]) fprintf(stderr, "%s byte %zu old %02x new %02x\n", what, i, u[i], v[i]);
        }
        assert(!memcmp(u, v, x->n));
        if (x->kind == 0) forwarded_out++; else forwarded_in++;
    }
    if (!a) dropped++;
    learn();
    old_clear();
    new_clear();
    compare_tables(what);
}
#define BOTH(call, ...) do { old_##call(__VA_ARGS__); new_##call(__VA_ARGS__); } while (0)

static uint32_t live[LIVE_MAX]; /* real membership ids; ids are never reused */
static unsigned live_n;
static uint32_t next_id = 1;
static unsigned alias_count;
typedef struct {
    uint32_t id, peer, alias;
} known_alias;
static known_alias known[64];
static uint32_t vpn_ip(uint32_t id) { return 0x64400000 + id; }
static uint32_t peer_ip(unsigned p) { return 0x64500001 + p; }

static size_t build(uint8_t *b, uint32_t src, uint32_t dst, uint8_t proto, uint16_t sport, uint16_t dport, size_t payload, bool syn, bool udp_none) {
    unsigned tcp_h = syn ? 24 : 20, h = 20;
    size_t n = h + (proto == 6 ? tcp_h : 8) + payload;
    memset(b, 0, n);
    b[0] = 0x45;
    b[8] = rnd() % 25 ? 2 + rnd() % 62 : 1 + rnd() % 2; /* mostly forwardable, sometimes TTL 1 */
    b[9] = proto;
    if (rnd() & 1)
        b[6] = 0x40;
    wr16(b + 2, n);
    wr16(b + 4, rnd());
    wr32(b + 12, src);
    wr32(b + 16, dst);
    wr16(b + h, sport);
    wr16(b + h + 2, dport);
    if (proto == 6) {
        wr32(b + h + 4, rnd());
        wr32(b + h + 8, rnd());
        b[h + 12] = (tcp_h / 4) << 4;
        b[h + 13] = syn ? 2 : 0x10;
        wr16(b + h + 14, rnd());
        if (syn) {
            b[h + 20] = 2;
            b[h + 21] = 4;
            wr16(b + h + 22, rnd() % 3 ? 1460 : 536 + rnd() % 900);
        }
    } else
        wr16(b + h + 4, n - h);
    for (size_t i = n - payload; i < n; i++)
        b[i] = rnd();
    fill_checksums(b, n, h, udp_none);
    return n;
}

#define BOTH(call, ...) do { old_##call(__VA_ARGS__); new_##call(__VA_ARGS__); } while (0)
void new_fill(void);

static void host_packet(void) {
    uint8_t b[1500];
    uint32_t dst;
    unsigned r = rnd() % 100;
    if (r < 75 && alias_count)
        dst = known[rnd() % alias_count].alias;
    else if (r < 85)
        dst = 0xc6120001 + rnd() % 80; /* allocated or not */
    else
        dst = 0xc6120000 + rnd() % 0x20000;
    uint32_t src = 0xc0a84d02 + rnd() % 3;
    if (!(rnd() % 40)) src = rnd() % 2 ? 0xc0a84d01 : 0xc0a80102;
    uint8_t proto = rnd() % 5 ? (rnd() % 3 ? 6 : 17) : (rnd() % 2 ? 6 : 17);
    uint16_t sport = 2000 + rnd() % 6, dport = 80 + rnd() % 3;
    size_t payload = rnd() % 8 ? rnd() % 64 : rnd() % 1300;
    bool syn = proto == 6 && !(rnd() % 4);
    size_t n = build(b, src, dst, proto, sport, dport, payload, syn, proto == 17 && !(rnd() % 8));
    switch (rnd() % 40) {
    case 0: b[10] ^= 0x55; break; /* bad IP checksum */
    case 1: b[6] |= 0x20; break;  /* fragment */
    case 2: n -= rnd() % 8; break; /* truncated: total length no longer matches */
    case 3: b[0] = 0x46; break;   /* options without room */
    case 4: if (proto == 6 && syn) b[20 + 21] = 255; break; /* malformed option */
    default: break;
    }
    memcpy(last_in, b, n);
    last_in_n = n;
    int ca = old_host_packet(b, n), cb = new_host_packet(b, n);
    assert(ca == cb);
    compare("host");
}
static void tunnel_packet(void) {
    if (!seen_n)
        return;
    seen_t s = seen[rnd() % seen_n];
    uint8_t b[1500];
    uint32_t src = s.peer, dst = s.vpn, id = s.id;
    uint16_t sport = s.remote, dport = s.mapped;
    uint8_t proto = s.proto;
    switch (rnd() % 14) {
    case 0: src ^= 1; break;
    case 1: sport ^= 1; break;
    case 2: dport += 1; break;
    case 3: proto ^= 6 ^ 17; break;
    case 4: if (live_n) id = live[rnd() % live_n]; break; /* some other membership's tunnel */
    case 5: dst ^= 1; break;
    default: break;
    }
    size_t payload = rnd() % 60 + (rnd() % 10 ? 0 : rnd() % 1200);
    size_t n = build(b, src, dst, proto, sport, dport, payload, proto == 6 && !(rnd() % 5), proto == 17 && !(rnd() % 8));
    b[8] = 1 + rnd() % 64; /* WireGuard peers can send any TTL; the router leaves it alone */
    fill_checksums(b, n, 20, proto == 17 && !rd16(b + 26));
    size_t padded = n;
    if (rnd() % 3 == 0) {
        padded = (n + 15) & ~(size_t)15;
        memset(b + n, 0, padded - n);
    }
    if (!(rnd() % 30)) b[10] ^= 0x33; /* bad checksum */
    memcpy(last_in, b, padded);
    last_in_n = padded;
    BOTH(tunnel_packet, id, b, padded);
    compare("tunnel");
}
int main(int argc, char **argv) {
    unsigned seed = argc > 1 ? atoi(argv[1]) : 1;
    rng_state = 88172645463325252ull ^ (seed * 0x9e3779b97f4a7c15ull);
    old_setup();
    new_setup();
    int64_t now = 1000000;
    BOTH(set_clock, now);
    for (unsigned op = 0; op < 6000; op++) {
        unsigned kind = rnd() % 1000; /* per mille */
        if (getenv("TRACE")) fprintf(stderr, "op %u kind %u live %u aliases %u now %lld\n", op, kind, live_n, alias_count, (long long)now);
        if (op < 40 && live_n < LIVE_MAX) kind = 0;           /* start with memberships ... */
        else if (op < 120 && alias_count < 24) kind = 30;       /* ... and aliases */
        if (kind < 6 && live_n < LIVE_MAX && next_id < 40) {
            uint32_t id = next_id++;
            BOTH(add_member, id, vpn_ip(id));
            live[live_n++] = id;
        } else if (kind < 40 && live_n && alias_count < 60) {
            uint32_t id = live[rnd() % live_n], peer = peer_ip(rnd() % PEERS);
            uint32_t a = old_alias(id, peer), b = new_alias(id, peer);
            assert(a && a == b);
            unsigned i;
            for (i = 0; i < alias_count; i++)
                if (known[i].id == id && known[i].peer == peer)
                    break;
            if (i == alias_count)
                known[alias_count++] = (known_alias){id, peer, a};
        } else if (kind < 44 && live_n) {
            uint32_t id = live[rnd() % live_n];
            BOTH(suspend, id);
            /* a restarted membership is republished by the next DNS answer */
            for (unsigned i = 0; i < alias_count; i++)
                if (known[i].id == id) {
                    assert(old_alias(id, known[i].peer) == new_alias(id, known[i].peer));
                    break;
                }
        } else if (kind < 45 && live_n) {
            unsigned i = rnd() % live_n;
            uint32_t id = live[i];
            BOTH(suspend, id);
            BOTH(remove_member, id);
            BOTH(forget, id);
            live[i] = live[--live_n];
        } else if (kind < 56 && live_n) {
            uint32_t id = live[rnd() % live_n];
            int state = rnd() % 4 ? 4 : 1; /* mostly back to connected */
            BOTH(set_state, id, state);
        } else if (kind < 60)
            BOTH(detach);
        else if (kind < 90) {
            now += rnd() % 8 ? rnd() % 5000000 : rnd() % 150000000;
            BOTH(set_clock, now);
        } else if (kind < 560) {
            host_packet();
        } else
            tunnel_packet();
        new_fill(); /* the background fill the usb_routes task performs when idle */
    }
    printf("seed %u: %u to tunnel, %u to USB, %u dropped, %u zero-checksum differences\n", seed, forwarded_out, forwarded_in, dropped, mismatches_allowed_zero);
    assert(forwarded_out > 50 && forwarded_in > 20);
    return 0;
}
