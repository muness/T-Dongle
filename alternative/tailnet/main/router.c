#include <stdatomic.h>
#include "route_table.h"
#ifdef GATEWAY_HOST_TEST
#include "router_stubs.h"
#else
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "gateway.h"
#include "boot_health.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#include "ml_directory.h"
#endif
/* USB <-> tunnel router.
 *
 * Forwarding path (per packet, no flash, no members_lock, no allocation beyond
 * the pbufs lwIP already owns):
 *   lwIP hook -> route_queue -> usb_routes -> flow hash hit -> RCU-pinned
 *   membership -> incremental NAT rewrite -> ml_gateway_queue_packet
 *   tunnel -> gateway_tunnel_input -> direct-indexed flow -> rewrite -> USB
 * State is in route_table.c. The flash alias record stays the source of truth;
 * the 64-entry RAM cache is filled in the background after a miss.
 *
 * Membership state is pinned with RCU instead of members_lock. Writers
 * (gateway_suspend / gateway_forget) unpublish the membership, wait for readers
 * to drain, and only then does the caller destroy the client. */

#define ROUTE_MEMBERS 16
#define ROUTE_FILL_SPACING_US 20000
#define ROUTE_REFRESH_SPACING_US 100000
#define ROUTE_ICMP_SPACING_US 50000

static rt_t rt;
static rt_rcu_t rcu;
static membership_t *_Atomic member_slot[ROUTE_MEMBERS];
static atomic_uint alias_limit = RT_ALIAS_BASE + 64; /* first never-allocated alias */
static atomic_uint fill_request[4];
static atomic_uint fill_negative[4];
static int64_t fill_negative_until[4];
static int64_t last_fill_us = -ROUTE_FILL_SPACING_US, last_refresh_us = -ROUTE_REFRESH_SPACING_US, last_icmp_us = -ROUTE_ICMP_SPACING_US;
static uint8_t route_scratch[ROUTE_MTU]; /* usb_routes only */
static atomic_uint usb_generation = 1;
/* Packets waiting for an alias fill. usb_routes only (hold_* below); the byte
 * count is read by the ingress hook to charge them against the queue budget. */
static struct {
    struct pbuf *packet;
    uint32_t dest;
    unsigned length, generation;
    int64_t expires;
} hold[ROUTE_HOLD_SLOTS];
static unsigned hold_count;
static atomic_uint route_held_bytes;
#ifdef GATEWAY_HOST_TEST
static bool routes_ready = true;
#endif

uint32_t gateway_route_stat(unsigned which) { return which < RT_STAT_COUNT ? atomic_load_explicit(&rt_stats[which], memory_order_relaxed) : 0; }
void gateway_usb_detach(void) { atomic_fetch_add(&usb_generation, 1); }

static uint16_t rd16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)rd16(p) << 16) | rd16(p + 2); }
static void wr16(uint8_t *p, uint16_t v) {
    p[0] = v >> 8;
    p[1] = v;
}
static void wr32(uint8_t *p, uint32_t v) {
    wr16(p, v >> 16);
    wr16(p + 2, v);
}

/* ---- alias store: flash is the record, RAM is a cache ---------------------- */
static void alias_limit_raise(uint32_t alias) {
    unsigned seen = atomic_load(&alias_limit);
    while (alias >= seen && !atomic_compare_exchange_weak(&alias_limit, &seen, alias + 1))
        ;
}

/* Alias reservation advances a persistent counter before the address is
 * exposed, so an interrupted write never recycles an address. */
#ifndef GATEWAY_HOST_TEST
#include "nvs.h"
static nvs_handle_t route_store;
static bool routes_ready;
static QueueHandle_t route_queue;
static atomic_uint route_queued_bytes;
static atomic_uint route_budget = ROUTE_QUEUE_BYTES; /* refreshed by usb_routes from the free heap */
typedef struct {
    struct pbuf *packet;
    struct netif *input;
    unsigned generation, length;
} route_item;
static void route_task(void *context);
static bool alias_reserve(uint32_t *index) {
    uint32_t next = 64;
    esp_err_t err = nvs_get_u32(route_store, "next_alias", &next);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND)
        return false;
    if (next >= 0x1fffe)
        return false;
    if (nvs_set_u32(route_store, "next_alias", next + 1) != ESP_OK || nvs_commit(route_store) != ESP_OK)
        return false;
    *index = next;
    return true;
}
#endif

static void preload_visit(void *context, const ml_directory_alias_t *record) {
    (void)context;
    rt_alias_insert(&rt, &(rt_alias_t){record->id, record->peer, record->alias});
    alias_limit_raise(record->alias);
}
/* Boot only: warm the cache with the most recent records (file order). */
static void route_load_cache(void) { ml_directory_alias_scan(preload_visit, NULL); }

/* Callers hold members_lock (DNS, peer views); the lock also serialises
 * allocation so two callers cannot reserve different aliases for one peer. */
static void members_publish_locked(void);
uint32_t gateway_alias(uint32_t id, uint32_t peer) {
    uint32_t alias;
    if (rt_alias_find_key(&rt, id, peer, &alias)) {
        members_publish_locked();
        return alias;
    }
    ml_directory_alias_t record;
    if (!ml_directory_alias_find(id, peer, 0, &record)) {
        uint32_t index;
        if (!routes_ready || !alias_reserve(&index))
            return 0;
        record = (ml_directory_alias_t){id, peer, RT_ALIAS_BASE + index};
        if (!ml_directory_alias_save(&record))
            return 0;
        alias_limit_raise(record.alias);
    }
    rt_alias_insert(&rt, &(rt_alias_t){record.id, record.peer, record.alias});
    members_publish_locked();
    return record.alias;
}

/* A miss never reads flash on the forwarding path. Aliases are allocated
 * sequentially, so an address at or beyond the limit cannot exist: drop it
 * without a request. Otherwise ask for a background fill (deduplicated). */
static bool fill_pending(void) {
    for (unsigned i = 0; i < 4; i++)
        if (atomic_load(&fill_request[i]))
            return true;
    return false;
}
/* Returns true when a fill for this alias is pending (the packet may wait for it). */
static bool alias_miss(uint32_t alias, int64_t now) {
    rt_stat(RT_STAT_ALIAS_MISS);
    if (alias < RT_ALIAS_BASE || alias >= atomic_load(&alias_limit)) {
        rt_stat(RT_STAT_ALIAS_UNKNOWN);
        return false;
    }
    for (unsigned i = 0; i < 4; i++) {
        if (atomic_load(&fill_request[i]) == alias)
            return true;
        if (atomic_load(&fill_negative[i]) == alias && now < fill_negative_until[i])
            return false;
    }
    for (unsigned i = 0; i < 4; i++) {
        unsigned empty = 0;
        if (atomic_compare_exchange_strong(&fill_request[i], &empty, alias))
            return true;
    }
    return false;
}
static bool fill_requested(uint32_t alias) {
    for (unsigned i = 0; i < 4; i++)
        if (atomic_load(&fill_request[i]) == alias)
            return true;
    return false;
}
/* One background fill per call. Runs on usb_routes only when its queue is empty. */
static void alias_fill_run(int64_t now) {
    last_fill_us = now;
    for (unsigned i = 0; i < 4; i++) {
        uint32_t alias = atomic_load(&fill_request[i]);
        if (!alias)
            continue;
        ml_directory_alias_t record;
        if (ml_directory_alias_find(0, 0, alias, &record)) {
            rt_alias_insert(&rt, &(rt_alias_t){record.id, record.peer, record.alias});
            rt_stat(RT_STAT_ALIAS_FILL);
        } else {
            atomic_store(&fill_negative[i], alias);
            fill_negative_until[i] = now + 10000000;
        }
        atomic_store(&fill_request[i], 0);
        return;
    }
}

/* ---- membership pinning ---------------------------------------------------- */
static void members_publish_locked(void) {
    for (membership_t *m = members; m; m = m->next) {
        if (!m->client || !m->client->wg_netif)
            continue;
        unsigned empty = ROUTE_MEMBERS;
        bool present = false;
        for (unsigned i = 0; i < ROUTE_MEMBERS; i++) {
            membership_t *s = atomic_load_explicit(&member_slot[i], memory_order_relaxed);
            if (s == m)
                present = true;
            else if (!s && empty == ROUTE_MEMBERS)
                empty = i;
        }
        if (!present && empty < ROUTE_MEMBERS)
            atomic_store(&member_slot[empty], m);
    }
}
/* Cold path: a membership is not published yet. members_lock is taken with a
 * short timeout, outside any RCU section, and not more than once per 100 ms. */
static bool members_refresh(int64_t now) {
    if (now - last_refresh_us < ROUTE_REFRESH_SPACING_US)
        return false;
    last_refresh_us = now;
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(2)) != pdTRUE)
        return false;
    members_publish_locked();
    xSemaphoreGive(members_lock);
    return true;
}
/* Readers only, inside an RCU section. */
static membership_t *member_by_id(uint32_t id) {
    for (unsigned i = 0; i < ROUTE_MEMBERS; i++) {
        membership_t *m = atomic_load_explicit(&member_slot[i], memory_order_acquire);
        if (m && m->id == id)
            return m;
    }
    return NULL;
}
static membership_t *member_by_wg(struct netif *wg) {
    for (unsigned i = 0; i < ROUTE_MEMBERS; i++) {
        membership_t *m = atomic_load_explicit(&member_slot[i], memory_order_acquire);
        microlink_t *c = m ? m->client : NULL;
        if (c && c->wg_netif == wg)
            return m;
    }
    return NULL;
}
static bool member_ready(const membership_t *m) {
    const microlink_t *c = m->client;
    return c && c->wg_netif &&
#ifndef GATEWAY_HOST_TEST
           m->enabled && c->state == ML_STATE_CONNECTED && !c->key_expired && !c->last_error[0];
#else
           c->state == ML_STATE_CONNECTED;
#endif
}
static void member_unpublish(uint32_t id) {
    for (unsigned i = 0; i < ROUTE_MEMBERS; i++) {
        membership_t *m = atomic_load(&member_slot[i]);
        if (m && m->id == id)
            atomic_store(&member_slot[i], NULL);
    }
}

/* Stop forwarding for a membership. Returns only when no packet is still being
 * forwarded with its client, so the caller may then stop and destroy it. */
void gateway_suspend(uint32_t id) {
    member_unpublish(id);
    rt_flows_forget(&rt, id);
    rt_rcu_synchronize(&rcu);
}
/* The membership is gone for good. Its flash alias stays allocated and is never
 * reassigned; only the RAM state goes. */
void gateway_forget(uint32_t id) {
    member_unpublish(id);
    rt_alias_forget(&rt, id);
    rt_flows_forget(&rt, id);
    rt_rcu_synchronize(&rcu);
}

/* ---- packet helpers ---------------------------------------------------------- */
static uint32_t sum(const uint8_t *p, size_t n, uint32_t s) {
    while (n > 1) {
        s += rd16(p);
        p += 2;
        n -= 2;
    }
    if (n)
        s += p[0] << 8;
    return s;
}
static uint16_t finish(uint32_t s) {
    while (s >> 16)
        s = (s & 65535) + (s >> 16);
    return ~s;
}
/* Clamp both SYN directions so ordinary TCP data fits the queue/WG MTU. Never
 * enlarge an existing smaller offer; malformed options fail closed. The TCP
 * checksum is adjusted incrementally. */
static bool clamp_mss(uint8_t *b, size_t n, unsigned h) {
    if (b[9] != 6 || !(b[h + 13] & 2))
        return true;
    unsigned end = h + (b[h + 12] >> 4) * 4;
    if (end > n)
        return false;
    for (unsigned pos = h + 20; pos < end;) {
        unsigned kind = b[pos];
        if (!kind)
            break;
        if (kind == 1) {
            pos++;
            continue;
        }
        if (pos + 2 > end || b[pos + 1] < 2 || pos + b[pos + 1] > end)
            return false;
        if (kind == 2) {
            if (b[pos + 1] != 4)
                return false;
            uint16_t old = rd16(b + pos + 2);
            if (old > 1360) {
                wr16(b + pos + 2, 1360);
                if ((pos - h) & 1) {
                    /* After a NOP the value straddles two checksum words (x,hi) and
                     * (lo,y); a single 16-bit replacement would corrupt the sum. The
                     * byte after the value is inside the header (see below). */
                    uint16_t w0 = rd16(b + pos + 1), w1 = rd16(b + pos + 3);
                    rt_csum_replace16(b + h + 16, (uint16_t)((w0 & 0xff00) | (old >> 8)), w0);
                    rt_csum_replace16(b + h + 16, (uint16_t)((old & 0xff) << 8 | (w1 & 0xff)), w1);
                } else
                    rt_csum_replace16(b + h + 16, old, 1360);
            }
        }
        pos += b[pos + 1];
    }
    return true;
}
static bool valid(const uint8_t *b, size_t n, unsigned *h) {
    if (n < 20 || b[0] >> 4 != 4)
        return false;
    *h = (b[0] & 15) * 4;
    if (*h < 20 || *h > n || rd16(b + 2) != n || (rd16(b + 6) & 0x3fff))
        return false;
    if (b[9] != 6 && b[9] != 17)
        return false;
    if (n < *h + (b[9] == 6 ? 20 : 8))
        return false;
    if (b[9] == 6 && ((b[*h + 12] >> 4) * 4 < 20 || (b[*h + 12] >> 4) * 4 > n - *h))
        return false;
    if (b[9] == 17 && rd16(b + *h + 4) != n - *h)
        return false;
    return finish(sum(b, *h, 0)) == 0;
}
/* NAT rewrite with RFC 1624 incremental checksum updates: addresses touch the
 * IP header and the TCP/UDP pseudo-header, the port only the TCP/UDP checksum.
 * A UDP datagram that carries no checksum (0) keeps carrying none; an updated
 * UDP checksum is never emitted as 0. */
static void nat_rewrite(uint8_t *b, unsigned h, uint32_t src, uint32_t dst, unsigned port_offset, uint16_t port) {
    uint32_t old_src = rd32(b + 12), old_dst = rd32(b + 16);
    uint16_t old_port = rd16(b + h + port_offset);
    uint8_t *l4 = b + h + (b[9] == 6 ? 16 : 6);
    rt_csum_replace32(b + 10, old_src, src);
    rt_csum_replace32(b + 10, old_dst, dst);
    if (b[9] == 6 || (l4[0] | l4[1])) {
        rt_csum_replace32(l4, old_src, src);
        rt_csum_replace32(l4, old_dst, dst);
        rt_csum_replace16(l4, old_port, port);
        if (b[9] == 17 && !(l4[0] | l4[1]))
            l4[0] = l4[1] = 0xff;
    }
    wr32(b + 12, src);
    wr32(b + 16, dst);
    wr16(b + h + port_offset, port);
}
static void ttl_decrement(uint8_t *b) {
    uint16_t old = rd16(b + 8);
    b[8]--;
    rt_csum_replace16(b + 10, old, rd16(b + 8));
}

/* ---- seams for the shared packet pool (PR-B) ---------------------------------- */
static int route_emit_tunnel(membership_t *m, uint32_t peer, const uint8_t *b, size_t n) {
#ifndef GATEWAY_HOST_TEST
    gateway_route_mark(1, m->id);
#endif
    int result = ml_gateway_queue_packet(m->client, peer, b, n);
#ifndef GATEWAY_HOST_TEST
    gateway_route_mark(0, 0);
#endif
    return result;
}
static void route_emit_usb(struct pbuf *packet, uint32_t host) {
    ip4_addr_t ip = {.addr = htonl(host)};
    struct netif *usb = esp_netif_get_netif_impl(usb_interface);
    if (!usb || usb->output(usb, packet, &ip) != ERR_OK)
        rt_stat(RT_STAT_TX_FAIL);
}

/* ---- USB -> tunnel ------------------------------------------------------------- */
enum { ROUTE_DONE, ROUTE_NEED_MEMBERS, ROUTE_HOLD };

static int route_try(uint8_t *b, size_t n, unsigned h, uint32_t dest, uint32_t host, int64_t now, uint32_t generation) {
    uint16_t local = rd16(b + h), remote = rd16(b + h + 2);
    uint8_t proto = b[9];
    rt_flow_t f;
    rt_alias_t a;
    bool hit = rt_flow_out(&rt, dest, host, local, remote, proto, generation, &f);
    if (hit)
        a = (rt_alias_t){f.id, f.peer, f.alias};
    else if (!rt_alias_find(&rt, dest, &a)) {
        return alias_miss(dest, now) ? ROUTE_HOLD : ROUTE_DONE;
    }
    membership_t *m = member_by_id(a.id);
    if (!m)
        return ROUTE_NEED_MEMBERS;
    if (!member_ready(m)) {
        rt_stat(RT_STAT_MEMBER_DOWN);
        return ROUTE_DONE;
    }
    if (!hit) {
        rt_flow_t key = {.id = a.id, .peer = a.peer, .alias = dest, .host = host, .local = local, .remote = remote, .proto = proto};
        if (!rt_flow_create(&rt, &key, generation, now, &f)) {
            rt_stat(RT_STAT_FLOW_FULL);
            return ROUTE_DONE;
        }
    }
    if (hit)
        rt_flow_touch(&rt, &f, generation, now);
    nat_rewrite(b, h, m->client->vpn_ip, a.peer, 0, f.mapped);
    ttl_decrement(b);
    if (route_emit_tunnel(m, a.peer, b, n) != 0)
        rt_stat(RT_STAT_TUNNEL_REJECT);
    else
        rt_stat(RT_STAT_FORWARDED_OUT);
    return ROUTE_DONE;
}
/* Returns true when the alias is not cached but a fill is pending: the caller
 * may hold the packet and run it again after the fill (hold_service). */
static bool route_outbound(uint8_t *b, size_t n, uint32_t dest) {
    unsigned h;
    if (!valid(b, n, &h) || !clamp_mss(b, n, h) || b[8] < 2) {
        rt_stat(RT_STAT_BAD_PACKET);
        return false;
    }
    uint32_t host = rd32(b + 12);
    if ((host & 0xffffff00) != 0xc0a84d00 || host == 0xc0a84d01 || host == 0xc0a84dff) {
        rt_stat(RT_STAT_BAD_PACKET);
        return false;
    }
    uint32_t generation = atomic_load(&usb_generation);
    int64_t now = esp_timer_get_time();
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        unsigned token = rt_rcu_enter(&rcu);
        int result = route_try(b, n, h, dest, host, now, generation);
        rt_rcu_exit(&rcu, token);
        if (result == ROUTE_DONE)
            return false;
        if (result == ROUTE_HOLD)
            return true;
        if (!members_refresh(now))
            break;
    }
    rt_stat(RT_STAT_NO_MEMBER);
    return false;
}

/* ---- cache-miss hold ------------------------------------------------------------
 * A packet whose alias is not cached used to be dropped, so a new TCP flow to
 * an uncached peer paid a retransmission timeout (1 s, often longer) for its SYN.
 * Instead, up to ROUTE_HOLD_SLOTS packets (ROUTE_HOLD_BYTES in all) wait at most
 * ROUTE_HOLD_US for the background fill, then run through route_outbound again.
 * The pbuf is kept as it is (it was already charged to the queue), so nothing is
 * allocated and the memory is bounded by the same budget. A hold ends at once
 * when the fill found no record, and never outlives a USB detach. */
static void hold_drop(unsigned i) {
    atomic_fetch_sub(&route_held_bytes, hold[i].length);
    pbuf_free(hold[i].packet);
    rt_stat(RT_STAT_HELD_DROPPED);
    memmove(&hold[i], &hold[i + 1], (--hold_count - i) * sizeof(hold[0]));
}
static bool hold_add(struct pbuf *p, uint32_t dest, unsigned length, int64_t now) {
    if (hold_count == ROUTE_HOLD_SLOTS || atomic_load(&route_held_bytes) + length > ROUTE_HOLD_BYTES)
        return false;
    hold[hold_count++] = (__typeof__(hold[0])){p, dest, length, atomic_load(&usb_generation), now + ROUTE_HOLD_US};
    atomic_fetch_add(&route_held_bytes, length);
    rt_stat(RT_STAT_HELD);
    return true;
}
/* usb_routes only. Releases (in arrival order) every held packet whose alias has
 * arrived; drops those that expired, lost their fill or outlived the USB link. */
static void hold_service(int64_t now) {
    for (unsigned i = 0; i < hold_count;) {
        rt_alias_t a;
        if (hold[i].generation != atomic_load(&usb_generation) || now >= hold[i].expires) {
            hold_drop(i);
        } else if (rt_alias_find(&rt, hold[i].dest, &a)) {
            struct pbuf *p = hold[i].packet;
            uint32_t dest = hold[i].dest;
            unsigned length = hold[i].length;
            memmove(&hold[i], &hold[i + 1], (--hold_count - i) * sizeof(hold[0]));
            pbuf_copy_partial(p, route_scratch, length, 0);
            pbuf_free(p);
            atomic_fetch_sub(&route_held_bytes, length);
            rt_stat(RT_STAT_HELD_RELEASED);
            route_outbound(route_scratch, length, dest); /* a second miss drops: no second wait */
        } else if (!fill_requested(hold[i].dest)) {
            hold_drop(i); /* fill finished without a record */
        } else
            i++;
    }
}
static void hold_flush(void) {
    while (hold_count)
        hold_drop(0);
}
/* The tunnel cannot carry more than ROUTE_MTU and this router never fragments.
 * A DF packet gets the standard ICMP "fragmentation needed" (RFC 1191) with the
 * next-hop MTU so path-MTU discovery works; a packet without DF is dropped
 * (the host would only fragment it, and fragments are rejected). Replies are
 * rate limited and only go to a validated USB host. */
static void route_oversize(struct pbuf *p, uint32_t dest) {
    uint8_t q[68];
    size_t n = p->tot_len;
    unsigned h = 0;
    if (n < sizeof(q) || pbuf_copy_partial(p, q, sizeof(q), 0) != (int)sizeof(q))
        return;
    h = (q[0] & 15) * 4;
    uint32_t host = rd32(q + 12);
    if (q[0] >> 4 != 4 || h < 20 || h > 60 || rd16(q + 2) != n || (rd16(q + 6) & 0x3fff) || (q[9] != 6 && q[9] != 17) || finish(sum(q, h, 0)) != 0 ||
        (host & 0xffffff00) != 0xc0a84d00 || host == 0xc0a84d01 || host == 0xc0a84dff) {
        rt_stat(RT_STAT_BAD_PACKET);
        return;
    }
    if (!(rd16(q + 6) & 0x4000)) {
        rt_stat(RT_STAT_OVERSIZE_DROP);
        return;
    }
    int64_t now = esp_timer_get_time();
    if (now - last_icmp_us < ROUTE_ICMP_SPACING_US) {
        rt_stat(RT_STAT_ICMP_SUPPRESSED);
        return;
    }
    last_icmp_us = now;
    size_t quote = h + 8, total = 20 + 8 + quote;
    struct pbuf *reply = pbuf_alloc(PBUF_IP, total, PBUF_RAM);
    if (!reply)
        return;
    uint8_t r[20 + 8 + 60 + 8] = {0x45, 0};
    wr16(r + 2, total);
    wr16(r + 6, 0x4000);
    r[8] = 64;
    r[9] = 1;
    wr32(r + 12, dest);
    wr32(r + 16, host);
    wr16(r + 10, finish(sum(r, 20, 0)));
    r[20] = 3;
    r[21] = 4;
    wr16(r + 26, ROUTE_MTU);
    memcpy(r + 28, q, quote);
    wr16(r + 22, finish(sum(r + 20, 8 + quote, 0)));
    pbuf_take(reply, r, total);
#ifndef GATEWAY_HOST_TEST
    /* netif->output is etharp_output: not thread safe without the core lock, and
     * this runs on usb_routes, not on tcpip or under gateway_tunnel_input's lock. */
    LOCK_TCPIP_CORE();
#endif
    route_emit_usb(reply, host);
#ifndef GATEWAY_HOST_TEST
    UNLOCK_TCPIP_CORE();
#endif
    pbuf_free(reply);
    rt_stat(RT_STAT_OVERSIZE_ICMP);
}

/* Synthetic USB traffic runs on usb_routes; non-USB ingress is filtered in lwIP. */
static int gateway_process_host_input(struct pbuf *p, struct netif *input) {
    if (!usb_interface) {
        pbuf_free(p);
        return 1;
    }
    uint8_t first[20];
    if (p->tot_len < 20 || pbuf_copy_partial(p, first, 20, 0) != 20)
        return 0;
    uint32_t dest = rd32(first + 16);
    /* Enforce the ingress interface before HTTP/DNS reaches the socket
     * stack. Source-address checks alone cannot establish USB provenance. */
    if (input != esp_netif_get_netif_impl(usb_interface)) {
        bool management = dest == 0xc0a84d01;
#ifndef GATEWAY_HOST_TEST
        uint8_t ports[4];
        unsigned h = (first[0] & 15) * 4;
        if (dest == ntohl(ip4_addr_get_u32(netif_ip4_addr(input))) && h >= 20 && p->tot_len >= h + 4 && (first[9] == 6 || first[9] == 17) &&
            pbuf_copy_partial(p, ports, 4, h) == 4)
            management = management || rd16(ports + 2) == 80 || rd16(ports + 2) == 53;
#endif
        if (management) {
            pbuf_free(p);
            return 1;
        }
    }
    if ((dest & 0xfffe0000) != 0xc6120000)
        return 0;
    if (input != esp_netif_get_netif_impl(usb_interface)) {
        pbuf_free(p);
        return 1;
    }
    size_t n = p->tot_len;
    if (n > ROUTE_MTU) {
        route_oversize(p, dest);
        pbuf_free(p);
        return 1;
    }
    pbuf_copy_partial(p, route_scratch, n, 0);
    if (route_outbound(route_scratch, n, dest) && hold_add(p, dest, n, esp_timer_get_time()))
        return 1; /* the hold owns the pbuf now */
    pbuf_free(p);
    return 1;
}

/* ---- tunnel -> USB ------------------------------------------------------------- */
/* WireGuard already authenticated its sender and checked AllowedIPs. Accept
 * only exact replies to a USB-origin flow belonging to this same membership.
 * The reply is built once, directly into the pbuf that goes to USB. */
err_t gateway_tunnel_input(struct pbuf *p, struct netif *wg) {
    uint8_t first[20];
    /* The decryptor passes authenticated WireGuard padding with the IP packet.
     * Normally lwIP trims it; our custom input bypasses that path. Use the
     * inner IPv4 length without relaxing USB-side packet validation. */
    if (p->tot_len < 20 || pbuf_copy_partial(p, first, 20, 0) != 20 || first[0] >> 4 != 4 || rd16(first + 2) > p->tot_len || rd16(first + 2) < 20) {
        pbuf_free(p);
        return ERR_OK;
    }
    size_t n = rd16(first + 2);
    struct pbuf *out = pbuf_alloc(PBUF_IP, n, PBUF_RAM);
    if (!out) {
        pbuf_free(p);
        return ERR_MEM;
    }
    uint8_t *b = out->payload;
    pbuf_copy_partial(p, b, n, 0);
    pbuf_free(p);
    unsigned h;
    if (!valid(b, n, &h) || !clamp_mss(b, n, h))
        rt_stat(RT_STAT_BAD_PACKET);
    else {
        int64_t now = esp_timer_get_time();
        unsigned token = rt_rcu_enter(&rcu);
        membership_t *m = member_by_wg(wg);
        microlink_t *client = m ? m->client : NULL;
        rt_flow_t f;
        if (client && client->vpn_ip == rd32(b + 16) &&
            rt_flow_in(&rt, m->id, rd32(b + 12), rd16(b + h), rd16(b + h + 2), b[9], atomic_load(&usb_generation), now, &f)) {
            nat_rewrite(b, h, f.alias, f.host, 2, f.local);
            route_emit_usb(out, f.host);
            rt_stat(RT_STAT_FORWARDED_IN);
        } else
            rt_stat(RT_STAT_REPLY_NOMATCH);
        rt_rcu_exit(&rcu, token);
    }
    pbuf_free(out);
    return ERR_OK;
}

#ifndef GATEWAY_HOST_TEST
bool gateway_routes_init(void) {
    if (nvs_open("tn_routes", NVS_READWRITE, &route_store) != ESP_OK)
        return false;
    /* Legacy NVS table (pre-flash-directory): validate, then migrate. */
    struct {
        uint32_t id, peer, alias;
    } legacy[64];
    size_t size = sizeof(legacy);
    esp_err_t err = nvs_get_blob(route_store, "aliases", legacy, &size);
    routes_ready = err == ESP_ERR_NVS_NOT_FOUND || (err == ESP_OK && size == sizeof(legacy));
    for (unsigned i = 0; routes_ready && i < 64; i++)
        if (err == ESP_OK && legacy[i].alias && legacy[i].alias != RT_ALIAS_BASE + i)
            routes_ready = false;
    for (unsigned i = 0; routes_ready && err == ESP_OK && i < 64; i++)
        if (legacy[i].alias) {
            ml_directory_alias_t record = {legacy[i].id, legacy[i].peer, legacy[i].alias}, old;
            if (!ml_directory_alias_find(record.id, record.peer, record.alias, &old) && !ml_directory_alias_save(&record))
                routes_ready = false;
        }
    if (!routes_ready)
        return false;
    uint32_t next = 64;
    if (nvs_get_u32(route_store, "next_alias", &next) == ESP_OK)
        alias_limit_raise(RT_ALIAS_BASE + next - 1);
    route_load_cache();
    route_queue = xQueueCreate(ROUTE_QUEUE_DEPTH, sizeof(route_item));
    if (!route_queue)
        return false;
    /* Core 1 with the shared wg_mgr, one level above it (7): forwarding must
     * not wait behind a handshake, and it costs well under 5% of a core. Wi-Fi,
     * tcpip and net_io stay on core 0. */
    if (xTaskCreatePinnedToCore(route_task, "usb_routes", 4096, NULL, 8, NULL, 1) != pdPASS) {
        vQueueDelete(route_queue);
        route_queue = NULL;
        routes_ready = false;
    }
    return routes_ready;
}
static void route_task(void *context) {
    route_item item;
    unsigned burst = 0;
    int64_t last_budget_us = 0;
    for (;;) {
        int64_t now = esp_timer_get_time();
        if (now - last_budget_us >= 20000) {
            last_budget_us = now;
            atomic_store(&route_budget, rt_queue_budget(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)));
        }
        if (hold_count)
            hold_service(now);
        /* Sleep until a packet arrives. With a miss pending, sleep only until the
         * next fill is due, and fill when the queue is empty. Held packets bound
         * the sleep by their expiry so they are never stranded. */
        TickType_t wait = portMAX_DELAY;
        if (fill_pending() && !uxQueueMessagesWaiting(route_queue)) {
            int64_t due = last_fill_us + ROUTE_FILL_SPACING_US;
            if (now >= due) {
                alias_fill_run(now);
                hold_service(esp_timer_get_time());
                continue;
            }
            wait = pdMS_TO_TICKS((due - now + 999) / 1000);
            if (!wait)
                wait = 1; /* never degrade into a poll when the tick is coarser than the spacing */
        }
        if (hold_count) {
            TickType_t limit = pdMS_TO_TICKS((hold[0].expires - now + 999) / 1000);
            if (!limit)
                limit = 1;
            if (limit < wait)
                wait = limit;
        }
        if (xQueueReceive(route_queue, &item, wait) != pdTRUE)
            continue;
        atomic_fetch_sub(&route_queued_bytes, item.length);
        if (item.generation != atomic_load(&usb_generation))
            pbuf_free(item.packet);
        else if (!gateway_process_host_input(item.packet, item.input))
            pbuf_free(item.packet);
        /* Fairness: usb_routes outranks wg_mgr (7) and coord (5) on core 1. A
         * producer that keeps the queue non-empty would otherwise hold the core
         * until the idle-task watchdog fires. After ROUTE_BURST_PACKETS in a row
         * (about 3 ms of work) sleep one tick, a duty cycle near 25% worst case. */
        if (!uxQueueMessagesWaiting(route_queue))
            burst = 0;
        else if (++burst >= ROUTE_BURST_PACKETS) {
            burst = 0;
            vTaskDelay(1);
        }
    }
}
#endif
int gateway_host_input(struct pbuf *p,struct netif *input) {
#ifndef GATEWAY_HOST_TEST
    uint8_t first[20];
    if(usb_interface && input==esp_netif_get_netif_impl(usb_interface) &&
       pbuf_copy_partial(p,first,20,0)==20 && (rd32(first+16)&0xfffe0000)==0xc6120000) {
        route_item item={p,input,atomic_load(&usb_generation),p->tot_len};
        /* Without DF an oversized packet is dropped here; with DF it is queued so
         * usb_routes can answer with ICMP fragmentation-needed. */
        if(p->tot_len>ROUTE_MTU && !(first[6]&0x40)) {
            rt_stat(RT_STAT_OVERSIZE_DROP);tdongle_memory_drop(TDONGLE_DROP_ROUTER_INGRESS);pbuf_free(p);return 1;
        }
        bool accepted=false;
        if(routes_ready && route_queue) {
            accepted=atomic_fetch_add(&route_queued_bytes,item.length)+item.length+atomic_load(&route_held_bytes)<=atomic_load(&route_budget) &&
                     xQueueSend(route_queue,&item,0)==pdTRUE;
            if(!accepted)atomic_fetch_sub(&route_queued_bytes,item.length);
        }
        if(!accepted) {rt_stat(RT_STAT_QUEUE_FULL);tdongle_memory_drop(TDONGLE_DROP_ROUTER_INGRESS);pbuf_free(p);}
        return 1;
    }
#endif
    return gateway_process_host_input(p,input);
}
