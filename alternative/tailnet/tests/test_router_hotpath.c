/* Forwarding-path tests: the real router.c against doubles for lwIP, the flash
 * directory and the tunnel queue. Build plain (ASan/UBSan) or with
 * -fsanitize=thread -DHOT_TSAN for the concurrent cases. */
#include <pthread.h>
#include <stdio.h>
#define GATEWAY_HOST_TEST
#include "router_stubs.h"
#include "router_packets.h"
#define CLIENT_ALIVE 0xa11fe
static int ml_gateway_queue_packet(microlink_t *ml, uint32_t ip, const uint8_t *data, size_t len) {
    assert(ml->magic == CLIENT_ALIVE); /* the client must never be used after gateway_suspend returned */
    struct pbuf *p = pbuf_alloc(0, len, 0);
    memcpy(p->payload, data, len);
    ip4_addr_t dest = {.addr = ip};
    struct netif *wg = ml->wg_netif;
    int result = wg->output(wg, p, &dest);
    pbuf_free(p);
    return result;
}
#include "../main/route_table.c"
#include "../main/router.c"

static uint8_t out_bytes[4][1500];
static size_t out_n[4];
static struct netif *out_on[4];
static uint32_t out_hop[4];
static unsigned out_count;
static atomic_uint concurrent_outputs;
static atomic_bool capturing = true;
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) {
    if (!atomic_load(&capturing)) { /* concurrent test: count only, nothing shared to race on */
        atomic_fetch_add(&concurrent_outputs, 1);
        return ERR_OK;
    }
    assert(p->tot_len <= sizeof(out_bytes[0]));
    unsigned i = out_count++ % 4;
    memcpy(out_bytes[i], p->payload, p->tot_len);
    out_n[i] = p->tot_len;
    out_on[i] = n;
    out_hop[i] = ip->addr;
    return ERR_OK;
}
static const uint8_t *last(size_t *n, struct netif **on) {
    unsigned i = (out_count - 1) % 4;
    *n = out_n[i];
    *on = out_on[i];
    return out_bytes[i];
}
static uint16_t l4_check(const uint8_t *b, size_t n) {
    unsigned h = (b[0] & 15) * 4;
    return pk_finish(pk_sum(b + h, n - h, pk_sum(b + 12, 8, 0) + b[9] + (n - h)));
}
static bool packet_ok(const uint8_t *b, size_t n) {
    unsigned h = (b[0] & 15) * 4;
    return pk_finish(pk_sum(b, h, 0)) == 0 && (l4_check(b, n) == 0 || (b[9] == 17 && !pk_rd16(b + h + 6)));
}
static void send_host(const uint8_t *b, size_t n) {
    struct pbuf *p = pbuf_alloc(0, n, 0);
    pbuf_take(p, b, n);
    if (!gateway_host_input(p, &usb))
        pbuf_free(p);
}
static void send_tunnel(struct netif *wg, const uint8_t *b, size_t n) {
    struct pbuf *p = pbuf_alloc(0, n, 0);
    pbuf_take(p, b, n);
    gateway_tunnel_input(p, wg);
}
static unsigned stat(unsigned which) { return gateway_route_stat(which); }

static struct netif wg1 = {.output = output}, wg2 = {.output = output};
static microlink_t c1 = {&wg1, 0x64400001, 4, CLIENT_ALIVE}, c2 = {&wg2, 0x64400002, 4, CLIENT_ALIVE};
static membership_t m2 = {NULL, 2, &c2}, m1 = {&m2, 1, &c1};

static void reset_tables(void) {
    hold_flush();
    rt_init(&rt);
    for (unsigned i = 0; i < ROUTE_MEMBERS; i++)
        atomic_store(&member_slot[i], NULL);
    memset(fill_request, 0, sizeof(fill_request));
    memset(fill_negative, 0, sizeof(fill_negative));
}

/* 1. Steady state: after the aliases are known, forwarding both ways performs
 *    no flash access of any kind, no matter how many packets. */
static void no_flash_on_forwarding_path(void) {
    members = &m1;
    uint32_t a = gateway_alias(1, 0x64500001), b = gateway_alias(2, 0x64500002);
    assert(a && b && a != b);
    unsigned finds = flash_finds, saves = flash_saves, scans = flash_scans;
    uint8_t pkt[1500];
    unsigned replies = 0;
    for (unsigned i = 0; i < 30000; i++) {
        unsigned flow = i % 48; /* 48 distinct flows: the table holds 64 */
        uint32_t alias = flow & 1 ? a : b;
        uint8_t proto = flow % 3 ? 6 : 17;
        size_t n = build_packet(pkt, 0xc0a84d02 + (flow / 2) % 3, alias, proto, 3000 + flow, 443, i % 7 ? 100 + i % 900 : 0, false, false);
        send_host(pkt, n);
        size_t sn;
        struct netif *on;
        const uint8_t *sent = last(&sn, &on);
        if (!(on == (alias == a ? &wg1 : &wg2) && packet_ok(sent, sn))) fprintf(stderr, "i=%u on=%p wg1=%p wg2=%p ok=%d proto=%u n=%zu stats out=%u down=%u miss=%u bad=%u\n", i, (void*)on, (void*)&wg1, (void*)&wg2, packet_ok(sent, sn), proto, sn, stat(0), stat(RT_STAT_MEMBER_DOWN), stat(RT_STAT_ALIAS_MISS), stat(RT_STAT_BAD_PACKET));
        assert(on == (alias == a ? &wg1 : &wg2) && packet_ok(sent, sn));
        /* the reply */
        uint8_t reply[1500];
        memcpy(reply, sent, sn);
        unsigned h = 20;
        pk_wr32(reply + 12, pk_rd32(sent + 16));
        pk_wr32(reply + 16, pk_rd32(sent + 12));
        pk_wr16(reply + h, pk_rd16(sent + h + 2));
        pk_wr16(reply + h + 2, pk_rd16(sent + h));
        fill_checksums(reply, sn, h, false);
        unsigned before = out_count;
        send_tunnel(on, reply, sn);
        replies += out_count == before + 1;
        assert(out_count == before + 1 && out_on[(out_count - 1) % 4] == &usb);
        clock_us += 50;
    }
    assert(replies == 30000);
    assert(flash_finds == finds && flash_saves == saves && flash_scans == scans);
    printf("  30000 round trips: flash finds/saves/scans during forwarding = %u/%u/%u\n", flash_finds - finds, flash_saves - saves, flash_scans - scans);
    gateway_forget(1);
    gateway_forget(2);
    members = NULL;
}

/* 2. Cache misses never touch flash on the forwarding path; the background fill
 *    does, once, and only for addresses that can exist. */
static void alias_cache_misses(void) {
    reset_tables();
    flash_count = 0;
    stub_next_alias = 64;
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    members = &m1;
    uint32_t first = gateway_alias(1, 0x64600000);
    for (unsigned i = 1; i < 200; i++)
        assert(gateway_alias(1 + i % 2, 0x64600000 + i)); /* 200 aliases: far beyond the 64-entry cache */
    uint32_t evicted = 0;
    rt_alias_t tmp;
    for (unsigned i = 0; i < 200 && !evicted; i++)
        if (!rt_alias_find(&rt, first + i, &tmp))
            evicted = first + i;
    assert(evicted);
    uint8_t pkt[1500];
    size_t n = build_packet(pkt, 0xc0a84d02, evicted, 6, 4000, 80, 10, false, false);
    unsigned finds = flash_finds, before = out_count, miss = stat(RT_STAT_ALIAS_MISS);
    for (unsigned i = 0; i < 100; i++)
        send_host(pkt, n);
    assert(flash_finds == finds && out_count == before);       /* dropped, no flash */
    assert(stat(RT_STAT_ALIAS_MISS) == miss + 100 && fill_pending()); /* one request, deduplicated */
    unsigned requests = 0;
    for (unsigned i = 0; i < 4; i++)
        requests += atomic_load(&fill_request[i]) != 0;
    assert(requests == 1);
    alias_fill_run(clock_us += 100000);
    assert(flash_finds == finds + 1 && !fill_pending());          /* one flash read, off the packet path */
    send_host(pkt, n);
    assert(out_count == before + 1 && flash_finds == finds + 1);   /* forwarded from RAM */
    /* an address that was never allocated: no request, no flash */
    n = build_packet(pkt, 0xc0a84d02, RT_ALIAS_BASE + 5000, 6, 4000, 80, 10, false, false);
    finds = flash_finds;
    send_host(pkt, n);
    assert(!fill_pending() && flash_finds == finds);
    alias_fill_run(clock_us += 100000);
    assert(flash_finds == finds);
    /* allocated but missing from flash (lost record): one read, then remembered as absent */
    atomic_store(&alias_limit, RT_ALIAS_BASE + 6000);
    n = build_packet(pkt, 0xc0a84d02, RT_ALIAS_BASE + 5000, 6, 4000, 80, 10, false, false);
    send_host(pkt, n);
    assert(fill_pending());
    finds = flash_finds;
    alias_fill_run(clock_us += 100000);
    assert(flash_finds == finds + 1);
    for (unsigned i = 0; i < 50; i++)
        send_host(pkt, n);
    assert(!fill_pending()); /* negative cache: the 50 retries did not ask flash again */
    clock_us += 11000000;
    send_host(pkt, n);
    assert(fill_pending()); /* ... until the entry expires */
    reset_tables();
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    flash_count = 0;
    gateway_forget(1);
    members = NULL;
}


/* 2b. A packet whose alias is not cached waits (bounded) for the background fill
 *     instead of being dropped: a dropped SYN costs a retransmission timeout. */
static unsigned held_bytes(void) { return atomic_load(&route_held_bytes); }
static uint32_t evict_one(uint32_t *first_out) {
    reset_tables();
    memset(fill_request, 0, sizeof(fill_request));
    memset(fill_negative, 0, sizeof(fill_negative));
    flash_count = 0;
    stub_next_alias = 64;
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    members = &m1;
    uint32_t first = gateway_alias(1, 0x64600000);
    for (unsigned i = 1; i < 200; i++)
        assert(gateway_alias(1 + i % 2, 0x64600000 + i));
    rt_alias_t tmp;
    for (unsigned i = 0; i < 200; i++)
        if (!rt_alias_find(&rt, first + i, &tmp))
            return first + i;
    assert(0);
    return 0;
}
static void miss_hold(void) {
    uint32_t first, a = evict_one(&first);
    uint8_t pkt[1500];
    size_t n = build_packet(pkt, 0xc0a84d02, a, 6, 4000, 80, 0, true, false);
    unsigned before = out_count, finds = flash_finds, held0 = stat(RT_STAT_HELD);
    /* First packets are held, not forwarded and not dropped; the third and later exceed the two slots. */
    send_host(pkt, n);
    assert(out_count == before && stat(RT_STAT_HELD) == held0 + 1 && held_bytes() == n);
    send_host(pkt, n);
    send_host(pkt, n);
    send_host(pkt, n);
    assert(out_count == before && hold_count == 2 && held_bytes() == 2 * n && flash_finds == finds);
    unsigned released = stat(RT_STAT_HELD_RELEASED);
    hold_service(clock_us); /* nothing to release before the fill */
    assert(out_count == before && hold_count == 2);
    alias_fill_run(clock_us += 20000);
    hold_service(clock_us);
    assert(hold_count == 0 && held_bytes() == 0 && stat(RT_STAT_HELD_RELEASED) == released + 2);
    assert(out_count == before + 2 && flash_finds == finds + 1);
    size_t sn;
    struct netif *on;
    const uint8_t *sent = last(&sn, &on);
    assert(on == &wg1 || on == &wg2);
    assert(packet_ok(sent, sn) && pk_rd32(sent + 12) == (on == &wg1 ? c1.vpn_ip : c2.vpn_ip));
    assert(pk_rd16(sent + 20) >= RT_MAPPED_BASE && pk_rd16(sent + 22) == 80);
    /* The held packet's flow is now established: the reply finds it. */
    uint8_t reply[1500];
    size_t rn = build_packet(reply, pk_rd32(sent + 16), pk_rd32(sent + 12), 6, 80, pk_rd16(sent + 20), 0, false, false);
    struct netif *wg = on;
    unsigned mark = out_count;
    send_tunnel(wg, reply, rn);
    sent = last(&sn, &on);
    assert(out_count == mark + 1 && on == &usb && pk_rd16(sent + 22) == 4000);

    /* Expiry: with no fill the held packet is dropped after ROUTE_HOLD_US, not kept. */
    a = evict_one(&first);
    n = build_packet(pkt, 0xc0a84d02, a, 6, 4001, 80, 0, true, false);
    before = out_count;
    send_host(pkt, n);
    assert(hold_count == 1);
    hold_service(clock_us += ROUTE_HOLD_US - 1);
    assert(hold_count == 1);
    unsigned dropped = stat(RT_STAT_HELD_DROPPED);
    hold_service(clock_us += 1);
    assert(hold_count == 0 && held_bytes() == 0 && stat(RT_STAT_HELD_DROPPED) == dropped + 1 && out_count == before);

    /* A fill that finds no record ends the hold at once. */
    memset(fill_request, 0, sizeof(fill_request));
    a = RT_ALIAS_BASE + 5000;
    atomic_store(&alias_limit, RT_ALIAS_BASE + 6000);
    n = build_packet(pkt, 0xc0a84d02, a, 6, 4002, 80, 0, true, false);
    send_host(pkt, n);
    assert(hold_count == 1);
    alias_fill_run(clock_us += 20000);
    hold_service(clock_us);
    assert(hold_count == 0 && held_bytes() == 0 && out_count == before);
    /* An address that cannot exist is never held. */
    n = build_packet(pkt, 0xc0a84d02, RT_ALIAS_BASE + 90000, 6, 4003, 80, 0, true, false);
    send_host(pkt, n);
    assert(hold_count == 0 && held_bytes() == 0);

    /* A USB detach (generation change) discards held packets unforwarded. */
    a = evict_one(&first);
    n = build_packet(pkt, 0xc0a84d02, a, 6, 4004, 80, 0, true, false);
    before = out_count;
    send_host(pkt, n);
    assert(hold_count == 1);
    alias_fill_run(clock_us += 20000);
    gateway_usb_detach();
    hold_service(clock_us);
    assert(hold_count == 0 && held_bytes() == 0 && out_count == before);

    /* The byte budget bounds what a hold can pin: a second full-size packet does not fit. */
    a = evict_one(&first);
    n = build_packet(pkt, 0xc0a84d02, a, 17, 4005, 53, ROUTE_MTU - 28, false, false);
    assert(n == ROUTE_MTU);
    send_host(pkt, n);
    send_host(pkt, n);
    assert(hold_count == 1 && held_bytes() == ROUTE_MTU && held_bytes() <= ROUTE_HOLD_BYTES);
    hold_flush();
    assert(held_bytes() == 0);

    /* A flood of distinct uncached aliases cannot hold more than the two slots. */
    reset_tables();
    flash_count = 0;
    stub_next_alias = 64;
    members = &m1;
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    for (unsigned i = 0; i < 100; i++)
        gateway_alias(1, 0x64800000 + i);
    for (unsigned i = 0; i < 64; i++) {
        n = build_packet(pkt, 0xc0a84d02, RT_ALIAS_BASE + 64 + (i * 7) % 100, 6, 5000 + i, 80, 0, true, false);
        send_host(pkt, n);
        assert(hold_count <= ROUTE_HOLD_SLOTS && held_bytes() <= ROUTE_HOLD_BYTES);
    }
    reset_tables();
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    flash_count = 0;
    members = NULL;

    /* Queue budget: a ceiling that shrinks with the free heap but always admits two full packets. */
    assert(rt_queue_budget(0) == ROUTE_QUEUE_BYTES_MIN && rt_queue_budget(6400) == ROUTE_QUEUE_BYTES_MIN);
    assert(rt_queue_budget(ROUTE_HEAP_RESERVE + 5000) == 5000 && rt_queue_budget(1u << 20) == ROUTE_QUEUE_BYTES);
    assert(ROUTE_QUEUE_BYTES_MIN >= 2 * ROUTE_MTU);
}

/* 3. Boot preload warms the cache from flash once; forwarding then needs nothing. */
static void preload(void) {
    reset_tables();
    flash_count = 0;
    stub_next_alias = 64;
    members = &m1;
    for (unsigned i = 0; i < 100; i++)
        assert(gateway_alias(1, 0x64700000 + i));
    reset_tables(); /* "reboot": RAM is empty, flash keeps the records */
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    unsigned scans = flash_scans, finds = flash_finds;
    route_load_cache();
    assert(flash_scans == scans + 1 && flash_finds == finds);
    assert(atomic_load(&alias_limit) >= RT_ALIAS_BASE + 64 + 100);
    members = &m1;
    gateway_alias(1, 0x64700000 + 99); /* a DNS answer republishes the membership */
    uint8_t pkt[1500];
    size_t n = build_packet(pkt, 0xc0a84d02, RT_ALIAS_BASE + 64 + 99, 17, 4000, 53, 10, false, false);
    unsigned before = out_count;
    send_host(pkt, n);
    assert(out_count == before + 1 && flash_finds == finds); /* newest records were preloaded */
    gateway_forget(1);
    members = NULL;
}

/* 4. Invalidation on membership/alias/USB generation change; ownership of replies. */
static void invalidation_and_ownership(void) {
    reset_tables();
    flash_count = 0;
    stub_next_alias = 64;
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    c1.state = c2.state = 4;
    members = &m1;
    uint32_t a = gateway_alias(1, 0x64500001), b = gateway_alias(2, 0x64500001); /* same peer address, two tailnets */
    assert(a != b);
    uint8_t pkt[1500], reply[1500];
    size_t n = build_packet(pkt, 0xc0a84d02, a, 6, 4000, 80, 20, false, false), sn;
    struct netif *on;
    send_host(pkt, n);
    const uint8_t *sent = last(&sn, &on);
    assert(on == &wg1);
    uint16_t mapped = pk_rd16(sent + 20);
    memcpy(reply, sent, sn);
    pk_wr32(reply + 12, 0x64500001); pk_wr32(reply + 16, c1.vpn_ip); pk_wr16(reply + 20, 80); pk_wr16(reply + 22, mapped);
    fill_checksums(reply, sn, 20, false);
    unsigned before = out_count;
    send_tunnel(&wg2, reply, sn); /* same bytes through the other membership's tunnel */
    assert(out_count == before);
    send_tunnel(&wg1, reply, sn);
    assert(out_count == before + 1 && out_on[(out_count - 1) % 4] == &usb);
    uint8_t bad[1500];
    memcpy(bad, reply, sn); pk_wr32(bad + 12, 0x64500002); fill_checksums(bad, sn, 20, false);
    send_tunnel(&wg1, bad, sn); /* other peer */
    memcpy(bad, reply, sn); pk_wr16(bad + 20, 81); fill_checksums(bad, sn, 20, false);
    send_tunnel(&wg1, bad, sn); /* other remote port */
    memcpy(bad, reply, sn); pk_wr16(bad + 22, mapped + 1); fill_checksums(bad, sn, 20, false);
    send_tunnel(&wg1, bad, sn); /* unmapped port */
    memcpy(bad, reply, sn); pk_wr32(bad + 16, c1.vpn_ip + 1); fill_checksums(bad, sn, 20, false);
    send_tunnel(&wg1, bad, sn); /* not addressed to this membership's tunnel address */
    assert(out_count == before + 1);
    /* membership down: outbound is refused, the flow survives, replies still match;
     * back up: the same flow (same mapped port) resumes */
    c1.state = 1;
    before = out_count;
    send_host(pkt, n);
    assert(out_count == before && stat(RT_STAT_MEMBER_DOWN) > 0);
    c1.state = 4;
    send_host(pkt, n);
    assert(out_count == before + 1 && pk_rd16(out_bytes[(out_count - 1) % 4] + 20) == mapped);
    /* USB re-enumeration: every flow is void, even though the entry is still in the table */
    gateway_usb_detach();
    before = out_count;
    send_tunnel(&wg1, reply, sn);
    assert(out_count == before);
    send_host(pkt, n);
    assert(pk_rd16(out_bytes[(out_count - 1) % 4] + 20) != mapped);
    /* suspend: flows go, aliases stay; the same address works again after restart */
    uint16_t again = pk_rd16(out_bytes[(out_count - 1) % 4] + 20);
    gateway_suspend(1);
    memcpy(reply + 22, out_bytes[(out_count - 1) % 4] + 20, 2);
    before = out_count;
    assert(member_by_id(1) == NULL); /* unpublished */
    clock_us += ROUTE_REFRESH_SPACING_US;
    send_host(pkt, n); /* the cold path republishes the membership from the list, under the lock */
    assert(out_count == before + 1 && member_by_id(1) == &m1 && gateway_alias(1, 0x64500001) == a);
    (void)again;
    /* forget: nothing can reach the old membership through its alias, even once
     * the background fill has put the (still allocated) record back in the cache */
    gateway_forget(1);
    m1.next = NULL;
    members = &m2;
    before = out_count;
    send_host(pkt, n);
    alias_fill_run(clock_us += 100000);
    clock_us += ROUTE_REFRESH_SPACING_US;
    send_host(pkt, n);
    assert(out_count == before);
    /* the removed membership's alias is never handed to anyone else */
    for (unsigned i = 0; i < 20; i++)
        assert(gateway_alias(2, 0x64800000 + i) != a);
    assert(gateway_alias(3, 0x64500001) != a && gateway_alias(3, 0x64500001) != b);
    gateway_forget(2);
    m1.next = &m2;
    members = NULL;
}

/* 5. The old router dropped every packet while another task held members_lock. */
static void no_members_lock_on_forwarding(void) {
    reset_tables();
    c1.state = 4;
    members = &m1;
    uint32_t a = gateway_alias(1, 0x64500001);
    uint8_t pkt[1500];
    size_t n = build_packet(pkt, 0xc0a84d02, a, 17, 4000, 80, 20, false, false);
    members_lock_free = false;
    unsigned before = out_count;
    for (unsigned i = 0; i < 1000; i++)
        send_host(pkt, n);
    assert(out_count == before + 1000);
    /* a membership that was never published needs the lock once (cold path),
     * and is dropped, not blocked on, when the lock is busy */
    reset_tables();
    before = out_count;
    clock_us += ROUTE_REFRESH_SPACING_US;
    unsigned none = stat(RT_STAT_NO_MEMBER);
    rt_alias_insert(&rt, &(rt_alias_t){1, 0x64500001, a});
    send_host(pkt, n);
    assert(out_count == before && stat(RT_STAT_NO_MEMBER) == none + 1);
    members_lock_free = true;
    clock_us += ROUTE_REFRESH_SPACING_US;
    send_host(pkt, n);
    assert(out_count == before + 1);
    gateway_forget(1);
    members = NULL;
}

/* 6. Checksums: integrity is preserved, never repaired or invented. */
static void checksum_integrity(void) {
    reset_tables();
    c1.state = 4;
    members = &m1;
    uint32_t a = gateway_alias(1, 0x64500001);
    uint8_t pkt[1500];
    size_t sn;
    struct netif *on;
    for (unsigned i = 0; i < 20000; i++) {
        uint8_t proto = i & 1 ? 6 : 17;
        bool syn = proto == 6 && i % 5 == 0;
        size_t n = build_packet(pkt, 0xc0a84d02 + i % 2, a, proto, 1024 + i % 10, 1 + i % 2, pk_rnd() % 1300, syn, proto == 17 && i % 11 == 0);
        bool none = proto == 17 && !pk_rd16(pkt + 26);
        uint16_t mss = syn ? pk_rd16(pkt + 42) : 0;
        send_host(pkt, n);
        const uint8_t *sent = last(&sn, &on);
        assert(packet_ok(sent, sn) && sn == n);
        if (none)
            assert(!pk_rd16(sent + 26)); /* "no checksum" stays that way */
        if (syn)
            assert(pk_rd16(sent + 42) == (mss > 1360 ? 1360 : mss));
        /* a corrupted TCP/UDP checksum stays corrupted: it is the receiver's to reject */
        if (!none && i % 7 == 0) {
            uint8_t broken[1500];
            memcpy(broken, pkt, n);
            broken[(proto == 6 ? 36 : 26) + (i & 1)] ^= 0x10;
            unsigned before = out_count;
            send_host(broken, n);
            assert(out_count == before + 1);
            sent = last(&sn, &on);
            assert(pk_finish(pk_sum(sent, 20, 0)) == 0 && l4_check(sent, sn) != 0);
        }
    }
    /* A NOP before the MSS option puts the value on an odd offset, so it straddles two
     * checksum words; the clamp must still leave a valid checksum. */
    for (unsigned nops = 0; nops < 4; nops++)
        for (unsigned old = 1361; old <= 1500; old += 139) {
            uint8_t b[64];
            size_t hdr = 20 + 4 * ((20 + nops + 4 + 3) / 4);
            memset(b, 0, sizeof(b));
            b[0] = 0x45; b[8] = 30; b[9] = 6;
            pk_wr16(b + 2, hdr);
            pk_wr32(b + 12, 0xc0a84d02); pk_wr32(b + 16, a);
            pk_wr16(b + 20, 4100 + nops); pk_wr16(b + 22, 80);
            pk_wr32(b + 24, pk_rnd()); pk_wr32(b + 28, pk_rnd());
            b[32] = ((hdr - 20) / 4) << 4; b[33] = 2; pk_wr16(b + 34, pk_rnd());
            for (unsigned i = 0; i < nops; i++) b[40 + i] = 1;
            b[40 + nops] = 2; b[41 + nops] = 4; pk_wr16(b + 42 + nops, old);
            fill_checksums(b, hdr, 20, false);
            assert(packet_ok(b, hdr));
            send_host(b, hdr);
            const uint8_t *sent = last(&sn, &on);
            assert(sn == hdr && packet_ok(sent, sn) && pk_rd16(sent + 42 + nops) == 1360);
        }
    gateway_forget(1);
    members = NULL;
}

/* 7. Oversized packets: ICMP fragmentation-needed for DF, drop otherwise. */
static void oversize(void) {
    reset_tables();
    c1.state = 4;
    members = &m1;
    uint32_t a = gateway_alias(1, 0x64500001);
    uint8_t pkt[1600];
    size_t n = build_packet(pkt, 0xc0a84d05, a, 17, 5000, 9, 1400, false, false); /* 1428 bytes */
    assert(n > ROUTE_MTU);
    pkt[6] = 0x40; /* DF */
    fill_checksums(pkt, n, 20, false);
    unsigned before = out_count, sent_before = stat(RT_STAT_OVERSIZE_ICMP);
    clock_us += 1000000;
    send_host(pkt, n);
    size_t sn;
    struct netif *on;
    const uint8_t *r = last(&sn, &on);
    assert(out_count == before + 1 && on == &usb && stat(RT_STAT_OVERSIZE_ICMP) == sent_before + 1);
    assert(r[9] == 1 && r[20] == 3 && r[21] == 4 && pk_rd16(r + 26) == ROUTE_MTU);          /* ICMP type 3 code 4, next-hop MTU */
    assert(pk_rd32(r + 12) == a && pk_rd32(r + 16) == 0xc0a84d05 && out_hop[(out_count - 1) % 4] == htonl(0xc0a84d05));
    assert(pk_finish(pk_sum(r, 20, 0)) == 0 && pk_finish(pk_sum(r + 20, sn - 20, 0)) == 0 && pk_rd16(r + 2) == sn);
    assert(sn == 20 + 8 + 20 + 8 && !memcmp(r + 28, pkt, 28)); /* quotes original header + 8 bytes */
    /* rate limited, so a flood of oversized packets cannot become a reflection storm */
    for (unsigned i = 0; i < 100; i++)
        send_host(pkt, n);
    assert(out_count == before + 1 && stat(RT_STAT_ICMP_SUPPRESSED) >= 100);
    clock_us += ROUTE_ICMP_SPACING_US;
    send_host(pkt, n);
    assert(out_count == before + 2);
    /* without DF the packet would only be fragmented by the host and fragments are rejected: drop */
    pkt[6] = 0;
    fill_checksums(pkt, n, 20, false);
    clock_us += 1000000;
    send_host(pkt, n);
    assert(out_count == before + 2 && stat(RT_STAT_OVERSIZE_DROP) == 1);
    /* a bad source or checksum gets no answer */
    pkt[6] = 0x40;
    pk_wr32(pkt + 12, 0xc0a80102);
    fill_checksums(pkt, n, 20, false);
    send_host(pkt, n);
    pkt[6] = 0x40; pk_wr32(pkt + 12, 0xc0a84d05); fill_checksums(pkt, n, 20, false); pkt[10] ^= 1;
    send_host(pkt, n);
    assert(out_count == before + 2);
    /* the largest accepted packet is still forwarded */
    n = build_packet(pkt, 0xc0a84d05, a, 17, 5000, 9, ROUTE_MTU - 28, false, false);
    assert(n == ROUTE_MTU);
    send_host(pkt, n);
    assert(out_count == before + 3 && out_on[(out_count - 1) % 4] == &wg1);
    gateway_forget(1);
    members = NULL;
}

#ifdef HOT_TSAN
/* 8. Forwarding on three threads against a control thread that stops, destroys
 *    and restarts the membership (what stop_member does): a client is never used
 *    after gateway_suspend returned. */
static atomic_bool done;
static microlink_t *live_client;
static membership_t live_member;
static struct netif live_wg = {.output = output};
static uint32_t live_alias;
static void *usb_routes_thread(void *arg) {
    (void)arg;
    uint8_t pkt[200];
    unsigned i = 0;
    while (!atomic_load(&done)) {
        size_t n = build_packet(pkt, 0xc0a84d02, live_alias, 6, 2000 + i++ % 30, 80, 20, false, false);
        struct pbuf *p = pbuf_alloc(0, n, 0);
        pbuf_take(p, pkt, n);
        if (!gateway_host_input(p, &usb))
            pbuf_free(p);
    }
    return NULL;
}
static void *tunnel_thread(void *arg) {
    (void)arg;
    uint8_t pkt[200];
    unsigned i = 0;
    while (!atomic_load(&done)) {
        size_t n = build_packet(pkt, 0x64500001, 0x64400009, 6, 80, 40064 + i++ % 64, 20, false, false);
        if (i & 1) {
            struct pbuf *p = pbuf_alloc(0, n, 0);
            pbuf_take(p, pkt, n);
            gateway_tunnel_input(p, &live_wg);
        } else {
            /* the batch form (what wg_mgr calls): the membership is pinned across the whole batch and unpinned before the core lock */
            struct pbuf *in[4];
            err_t res[4];
            for (unsigned k = 0; k < 4; k++) {
                in[k] = pbuf_alloc(0, n, 0);
                pbuf_take(in[k], pkt, n);
            }
            gateway_tunnel_input_batch(in, 4, &live_wg, res);
            for (unsigned k = 0; k < 4; k++)
                if (res[k] != ERR_OK)
                    pbuf_free(in[k]);
        }
    }
    return NULL;
}
static void membership_lifecycle(void) {
    reset_tables();
    flash_count = 0;
    stub_next_alias = 64;
    atomic_store(&alias_limit, RT_ALIAS_BASE + 64);
    live_member = (membership_t){NULL, 9, NULL};
    members = &live_member;
    live_client = calloc(1, sizeof(*live_client));
    *live_client = (microlink_t){&live_wg, 0x64400009, 4, CLIENT_ALIVE};
    live_member.client = live_client;
    assert(xSemaphoreTake(members_lock, 1000) == pdTRUE);
    live_alias = gateway_alias(9, 0x64500001);
    xSemaphoreGive(members_lock);
    atomic_store(&capturing, false);
    pthread_t t[2];
    pthread_create(&t[0], NULL, usb_routes_thread, NULL);
    pthread_create(&t[1], NULL, tunnel_thread, NULL);
    for (unsigned cycle = 0; cycle < 400; cycle++) {
        /* stop_member runs with members_lock held */
        assert(xSemaphoreTake(members_lock, 1000) == pdTRUE);
        gateway_suspend(9);
        /* destroy: nothing may still be forwarding with this client */
        microlink_t *old = live_client;
        live_member.client = NULL;
        old->magic = 0;
        old->state = 0;
        free(old);
        xSemaphoreGive(members_lock);
        sched_yield();
        /* start: a new client, republished by the next DNS answer (also under the lock) */
        assert(xSemaphoreTake(members_lock, 1000) == pdTRUE);
        live_client = calloc(1, sizeof(*live_client));
        *live_client = (microlink_t){&live_wg, 0x64400009, 4, CLIENT_ALIVE};
        live_member.client = live_client;
        assert(gateway_alias(9, 0x64500001) == live_alias);
        xSemaphoreGive(members_lock);
        for (volatile unsigned spin = 0; spin < 3000; spin++)
            ;
    }
    atomic_store(&done, true);
    for (unsigned i = 0; i < 2; i++)
        pthread_join(t[i], NULL);
    gateway_suspend(9);
    gateway_forget(9);
    members = NULL;
    free(live_client);
    printf("  400 stop/destroy/start cycles under concurrent forwarding: %u packets reached the tunnel, %u replies to USB\n", stat(RT_STAT_FORWARDED_OUT), stat(RT_STAT_FORWARDED_IN));
    assert(concurrent_outputs > 0);
}
#endif

int main(void) {
    usb_interface = &usb;
    usb.output = output;
    printf("router hot path\n");
    no_flash_on_forwarding_path();
    alias_cache_misses();
    miss_hold();
    preload();
    invalidation_and_ownership();
    no_members_lock_on_forwarding();
    checksum_integrity();
    oversize();
#ifdef HOT_TSAN
    membership_lifecycle();
#endif
    puts("router hot path: no flash on forwarding, cache miss/fill/preload, invalidation, ownership, no members_lock, checksums, ICMP frag-needed");
    return 0;
}
