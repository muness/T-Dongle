/* Tunnel -> USB batch hand-off (gateway_tunnel_input_batch), the real router.c and route_table.c on host stubs.
 *
 * What it proves:
 *   1. a batch is exactly the same as its packets handed over one by one: the same frames to the USB netif in the same order, the same
 *      counters, the same results (random mixes of good replies for two memberships and every refusal reason, padded and exact, TCP
 *      and UDP, batches of 1 to 40);
 *   2. the USB netif is only ever called with the core lock held, and the lock is taken once per chunk of GATEWAY_TUNNEL_BATCH_MAX
 *      inputs that emits at least one frame, not once per packet, and not at all when nothing is emitted;
 *   3. ownership (lwIP's input contract): a consumed packet is the router's to free, a packet refused with ERR_MEM is still the
 *      caller's, an allocation failure in the middle of a batch refuses only that packet, and nothing is ever freed twice or leaked
 *      (live pbuf count; ASan);
 *   4. a USB output failure is tx_fail for that frame only, the rest of the batch still goes out in order.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -D_GNU_SOURCE -Wall -Wextra -pthread \
 *      -I tests -I main -I components/microlink/include -I ../../components/tdongle_runtime/include \
 *      -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter tests/test_router_batch.c -o build-host/test_router_batch */
#define GATEWAY_HOST_TEST
#include <stdio.h>
#include "router_stubs.h"
#include "router_packets.h"
#define rnd pk_rnd
static int ml_gateway_queue_packet(microlink_t *ml, uint32_t ip, const uint8_t *data, size_t len) {
    struct pbuf *p = pbuf_alloc(0, len, 0); memcpy(p->payload, data, len);
    ip4_addr_t dest = {.addr = ip}; struct netif *wg = ml->wg_netif;
    int result = wg->output(wg, p, &dest); pbuf_free(p); return result;
}
#include "../main/route_table.c"
#include "../main/router.c"

#define MAX_FRAMES 4096
static struct { uint8_t b[1500]; size_t n; uint32_t hop; } frames[MAX_FRAMES];
static unsigned frame_count;
static struct { uint8_t b[1500]; size_t n; } egress;
static unsigned egress_count;
static unsigned output_without_lock;
static int usb_fail_every;      /* every Nth USB output fails (0 = never) */
static unsigned usb_calls;
static err_t usb_output(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) {
    if (core_lock_depth <= 0) output_without_lock++;       /* etharp_output is not thread safe without the core lock */
    usb_calls++;
    if (usb_fail_every && usb_calls % usb_fail_every == 0) return ERR_MEM;
    assert(frame_count < MAX_FRAMES && p->tot_len <= 1500);
    memcpy(frames[frame_count].b, p->payload, p->tot_len); frames[frame_count].n = p->tot_len; frames[frame_count].hop = ip->addr; frame_count++;
    return ERR_OK;
}
static err_t wg_output(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) {
    assert(p->tot_len <= sizeof(egress.b)); memcpy(egress.b, p->payload, p->tot_len); egress.n = p->tot_len; egress_count++; return ERR_OK;
}

static struct netif wg1 = {.output = wg_output}, wg2 = {.output = wg_output};
static microlink_t c1 = {&wg1, 0x64400001, 4}, c2 = {&wg2, 0x64400002, 4};
static membership_t m2 = {NULL, 2, &c2}, m1 = {&m2, 1, &c1};

#define FLOWS 40
static struct { uint32_t peer; struct netif *wg; uint32_t vpn; uint8_t proto; uint16_t host_port, remote_port, mapped; uint32_t host; } flow[FLOWS];

/* a fresh router with FLOWS open flows (same sequence of events every time, so two runs are comparable) */
static void setup(void) {
    for (unsigned i = 0; i < ROUTE_MEMBERS; i++) atomic_store(&member_slot[i], NULL);
    rt_init(&rt);
    flash_count = 0; stub_next_alias = 64; atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    members = &m1; usb_interface = &usb; usb.output = usb_output;
    clock_us = 1000; usb_fail_every = 0;
    rng_state = 88172645463325252ull;
    uint32_t a1 = gateway_alias(1, 0x64500001), a2 = gateway_alias(2, 0x64500002);
    for (unsigned i = 0; i < FLOWS; i++) {
        bool one = i % 2 == 0;
        flow[i].peer = one ? 0x64500001 : 0x64500002; flow[i].wg = one ? &wg1 : &wg2; flow[i].vpn = one ? c1.vpn_ip : c2.vpn_ip;
        flow[i].proto = i % 3 ? 17 : 6; flow[i].host_port = 3000 + i; flow[i].remote_port = 443; flow[i].host = 0xc0a84d02 + i % 3;
        uint8_t pkt[200]; size_t n = build_packet(pkt, flow[i].host, one ? a1 : a2, flow[i].proto, flow[i].host_port, flow[i].remote_port, 20 + i, false, false);
        struct pbuf *p = pbuf_alloc(0, n, 0); pbuf_take(p, pkt, n);
        egress_count = 0;
        if (!gateway_host_input(p, &usb)) pbuf_free(p);
        assert(egress_count == 1);
        flow[i].mapped = rd16(egress.b + 20);
        clock_us += 10;
    }
}
static void teardown(void) { gateway_forget(1); gateway_forget(2); members = NULL; }

/* the reply to flow i: peer -> us, to the mapped port. `pad` extra bytes after the IP packet (WireGuard padding), as unauthenticated garbage the router must ignore. */
static size_t reply_for(uint8_t *b, unsigned i, size_t payload, size_t pad) {
    size_t n = build_packet(b, flow[i].peer, flow[i].vpn, flow[i].proto, flow[i].remote_port, flow[i].mapped, payload, false, false);
    for (size_t k = 0; k < pad; k++) b[n + k] = (uint8_t)(0xa5 + k);
    return n;
}
static struct pbuf *mk(const uint8_t *b, size_t n) { struct pbuf *p = pbuf_alloc(0, n, 0); pbuf_take(p, b, n); return p; }

static uint32_t snapshot[RT_STAT_COUNT];
static void snap(void) { for (unsigned i = 0; i < RT_STAT_COUNT; i++) snapshot[i] = gateway_route_stat(i); }

/* ---- 2 and the order: one batch of 24 good replies ---- */
static void t_order_and_lock(void) {
    setup(); snap();
    struct pbuf *in[24]; err_t res[24]; uint8_t b[300];
    long live = stub_pbuf_live;
    for (unsigned i = 0; i < 24; i++) { size_t n = reply_for(b, i, 10 + i, i % 5); in[i] = mk(b, n - 0 + (i % 5) * 0); }
    /* the packets carry their padding: rebuild with it so tot_len > IP length for some */
    for (unsigned i = 0; i < 24; i++) { pbuf_free(in[i]); size_t n = reply_for(b, i, 10 + i, i % 5); in[i] = mk(b, n + i % 5); }
    frame_count = 0; core_lock_acquires = 0; output_without_lock = 0; usb_calls = 0;
    gateway_tunnel_input_batch(in, 24, &wg1 /* wrong netif for odd flows: see below */, res);
    /* flows alternate between the two memberships; arriving on wg1 only the member-1 ones are valid */
    unsigned good = 0;
    for (unsigned i = 0; i < 24; i++) { assert(res[i] == ERR_OK); good += i % 2 == 0; }
    assert(frame_count == good && usb_calls == good);
    assert(core_lock_acquires == 2 && core_lock_depth == 0 && output_without_lock == 0);   /* 24 inputs = chunks of 16 and 8, each emitting: two acquisitions */
    for (unsigned k = 0; k < good; k++) {                  /* arrival order is delivery order */
        unsigned i = 2 * k;
        assert(rd16(frames[k].b + 22) == flow[i].host_port && frames[k].hop == htonl(flow[i].host));
        assert(rd16(frames[k].b + 2) == frames[k].n);      /* trimmed to the IP length, padding gone */
    }
    assert(gateway_route_stat(RT_STAT_FORWARDED_IN) - snapshot[RT_STAT_FORWARDED_IN] == good);
    assert(gateway_route_stat(RT_STAT_REPLY_NO_FLOW) + gateway_route_stat(RT_STAT_REPLY_OWNER) + gateway_route_stat(RT_STAT_REPLY_NO_MEMBER) + gateway_route_stat(RT_STAT_REPLY_NOT_US) - snapshot[RT_STAT_REPLY_NO_FLOW] - snapshot[RT_STAT_REPLY_OWNER] - snapshot[RT_STAT_REPLY_NO_MEMBER] - snapshot[RT_STAT_REPLY_NOT_US] == 24 - good);
    assert(stub_pbuf_live == live);

    /* 40 good packets for ONE membership: chunks of 16 -> three lock acquisitions, order kept across chunks */
    struct pbuf *big[40]; err_t bres[40]; frame_count = 0; core_lock_acquires = 0;
    for (unsigned i = 0; i < 40; i++) { unsigned f = (i % 20) * 2; size_t n = reply_for(b, f, 8, 0); big[i] = mk(b, n); }
    gateway_tunnel_input_batch(big, 40, &wg1, bres);
    assert(frame_count == 40 && core_lock_acquires == 3 && output_without_lock == 0);
    for (unsigned i = 0; i < 40; i++) assert(bres[i] == ERR_OK && rd16(frames[i].b + 22) == flow[(i % 20) * 2].host_port);
    assert(stub_pbuf_live == live);

    /* nothing to emit: the lock is never taken; an empty batch does nothing */
    core_lock_acquires = 0; frame_count = 0;
    uint8_t junk[40] = {0x45}; struct pbuf *bad[5]; err_t bad_res[5];
    for (unsigned i = 0; i < 5; i++) bad[i] = mk(junk, 10 + i * 5);
    gateway_tunnel_input_batch(bad, 5, &wg1, bad_res);
    gateway_tunnel_input_batch(bad, 0, &wg1, bad_res);
    assert(core_lock_acquires == 0 && frame_count == 0 && stub_pbuf_live == live);
    teardown();
}

/* ---- 1: batch == one by one ---- */
typedef struct { uint8_t b[400]; size_t n; unsigned wg; } item_t;
static size_t gen(item_t *it) {
    uint32_t r = rnd();
    unsigned i = rnd() % FLOWS;
    size_t pad = rnd() % 3 ? 0 : rnd() % 16;
    size_t n = reply_for(it->b, i, rnd() % 120, 0);
    it->wg = flow[i].wg == &wg1 ? 1 : 2;
    switch (r % 14) {
    case 0: it->wg = 3 - it->wg; break;                                           /* arrives on the other membership's interface */
    case 1: wr16(it->b + 22, (uint16_t)(flow[i].mapped + 1)); break;              /* no such flow (or another one: owner) */
    case 2: it->b[10] ^= 0x55; break;                                              /* bad IP header checksum */
    case 3: n = rnd() % 20; break;                                                 /* shorter than a header */
    case 4: wr16(it->b + 2, (uint16_t)(n + 30)); break;                            /* length longer than the data */
    case 5: wr16(it->b + 2, 12); break;                                            /* length below a header */
    case 6: it->b[0] = 0x65; break;                                                /* not IPv4 */
    case 7: wr32(it->b + 16, 0x64400009); break;                                   /* not addressed to us */
    case 8: wr16(it->b + 20, 444); break;                                          /* wrong remote port */
    case 9: it->b[n - 1] ^= 1; break;                                              /* bad L4 checksum: the router leaves it bad, still forwarded */
    default: break;
    }
    for (size_t k = 0; k < pad && n + k < sizeof(it->b); k++) it->b[n + k] = (uint8_t)rnd();
    it->n = n + (n >= 20 ? pad : 0);
    return it->n;
}
static void run_mix(unsigned seed, bool batched, item_t *items, unsigned count, err_t *results, unsigned *sizes) {
    setup(); rng_state = seed * 2654435761u + 1;
    frame_count = 0; snap();
    unsigned at = 0, s = 0;
    while (at < count) {
        unsigned size = batched ? 1 + rnd() % 40 : 1;
        if (at + size > count) size = count - at;
        struct pbuf *in[40]; struct netif *w[40]; err_t res[40];
        for (unsigned k = 0; k < size; k++) in[k] = mk(items[at + k].b, items[at + k].n);
        /* one call per run of packets for the same interface: the router takes the interface per call */
        unsigned k = 0;
        while (k < size) {
            unsigned m = k;
            while (m < size && items[at + m].wg == items[at + k].wg) m++;
            gateway_tunnel_input_batch(in + k, m - k, items[at + k].wg == 1 ? &wg1 : &wg2, res + k);
            k = m;
        }
        for (k = 0; k < size; k++) {
            results[at + k] = res[k];
            if (res[k] != ERR_OK) pbuf_free(in[k]);   /* refused: still ours */
        }
        at += size; s++;
    }
    *sizes = s;
}
static void t_batch_equals_sequential(void) {
    static item_t items[3000];
    static err_t r1[3000], r2[3000];
    static struct { uint8_t b[1500]; size_t n; uint32_t hop; } ref[MAX_FRAMES];
    for (unsigned seed = 1; seed <= 6; seed++) {
        setup(); rng_state = seed * 7919u + 3;
        unsigned count = 3000;
        for (unsigned i = 0; i < count; i++) gen(&items[i]);
        teardown();
        long live = stub_pbuf_live;
        unsigned s1, s2;
        run_mix(seed, false, items, count, r1, &s1);
        unsigned n_ref = frame_count; assert(n_ref < MAX_FRAMES);
        memcpy(ref, frames, sizeof(frames[0]) * n_ref);
        uint32_t d1[RT_STAT_COUNT]; for (unsigned i = 0; i < RT_STAT_COUNT; i++) d1[i] = gateway_route_stat(i) - snapshot[i];
        teardown();
        core_lock_acquires = 0;
        run_mix(seed, true, items, count, r2, &s2);
        assert(frame_count == n_ref);
        for (unsigned i = 0; i < n_ref; i++) assert(frames[i].n == ref[i].n && frames[i].hop == ref[i].hop && !memcmp(frames[i].b, ref[i].b, ref[i].n));
        for (unsigned i = 0; i < RT_STAT_COUNT; i++) if (gateway_route_stat(i) - snapshot[i] != d1[i]) { fprintf(stderr, "seed %u: counter %s: batch %u, one by one %u\n", seed, rt_stat_name(i), gateway_route_stat(i) - snapshot[i], d1[i]); abort(); }
        for (unsigned i = 0; i < count; i++) assert(r1[i] == r2[i]);
        assert(output_without_lock == 0 && stub_pbuf_live == live);
        assert(core_lock_acquires <= n_ref);                 /* never more than one per frame, and fewer with batching */
        printf("  seed %u: %u packets, %u frames identical, %u batches took %u lock acquisitions (one by one: %u)\n", seed, count, n_ref, s2, core_lock_acquires, n_ref);
        teardown();
    }
}

/* ---- 3: allocation failure in the middle of a batch ---- */
static void t_alloc_failure(void) {
    for (int fail_at = 0; fail_at < 8; fail_at++) {
        setup(); snap();
        uint8_t b[300]; struct pbuf *in[8]; err_t res[8]; long live = stub_pbuf_live;
        for (unsigned i = 0; i < 8; i++) { size_t n = reply_for(b, 2 * i, 40, 0); in[i] = mk(b, n); }
        uint8_t keep[8][300]; size_t keep_n[8];
        for (unsigned i = 0; i < 8; i++) { keep_n[i] = in[i]->tot_len; memcpy(keep[i], in[i]->payload, keep_n[i]); }
        frame_count = 0; stub_pbuf_fail_at = fail_at;     /* the router allocates one pbuf per packet: the fail_at-th one fails */
        gateway_tunnel_input_batch(in, 8, &wg1, res);
        stub_pbuf_fail_at = -1;
        for (unsigned i = 0; i < 8; i++) {
            if ((int)i == fail_at) {
                assert(res[i] == ERR_MEM);
                assert(in[i]->payload && !memcmp(in[i]->payload, keep[i], keep_n[i]));   /* untouched, still the caller's */
                pbuf_free(in[i]);
            } else assert(res[i] == ERR_OK);
        }
        assert(frame_count == 7 && gateway_route_stat(RT_STAT_TUNNEL_NOMEM) - snapshot[RT_STAT_TUNNEL_NOMEM] == 1 && stub_pbuf_live == live);
        unsigned k = 0;
        for (unsigned i = 0; i < 8; i++) if ((int)i != fail_at) assert(rd16(frames[k++].b + 22) == flow[2 * i].host_port);   /* the others, in order */
        teardown();
    }
}

/* ---- 4: USB refusals ---- */
static void t_usb_refusal(void) {
    setup(); snap();
    uint8_t b[300]; struct pbuf *in[12]; err_t res[12]; long live = stub_pbuf_live;
    for (unsigned i = 0; i < 12; i++) { size_t n = reply_for(b, 2 * i, 40, 0); in[i] = mk(b, n); }
    frame_count = 0; usb_calls = 0; usb_fail_every = 3; core_lock_acquires = 0;
    gateway_tunnel_input_batch(in, 12, &wg1, res);
    usb_fail_every = 0;
    for (unsigned i = 0; i < 12; i++) assert(res[i] == ERR_OK);       /* a refused frame is consumed and counted, not returned */
    assert(frame_count == 8 && gateway_route_stat(RT_STAT_TX_FAIL) - snapshot[RT_STAT_TX_FAIL] == 4 && gateway_route_stat(RT_STAT_FORWARDED_IN) - snapshot[RT_STAT_FORWARDED_IN] == 8);
    assert(core_lock_acquires == 1 && stub_pbuf_live == live);
    teardown();
}

/* the single-packet entry point is the batch of one */
static void t_single(void) {
    setup(); snap();
    uint8_t b[300]; size_t n = reply_for(b, 0, 30, 3);
    struct pbuf *p = mk(b, n + 3); long live = stub_pbuf_live - 1;
    frame_count = 0; core_lock_acquires = 0;
    assert(gateway_tunnel_input(p, &wg1) == ERR_OK);
    assert(frame_count == 1 && core_lock_acquires == 1 && stub_pbuf_live == live);
    p = mk(b, n); stub_pbuf_fail = 1;
    assert(gateway_tunnel_input(p, &wg1) == ERR_MEM); stub_pbuf_fail = 0;
    pbuf_free(p);
    teardown();
}

int main(void) {
    t_order_and_lock();
    t_batch_equals_sequential();
    t_alloc_failure();
    t_usb_refusal();
    t_single();
    printf("router batch ok\n");
    return 0;
}
