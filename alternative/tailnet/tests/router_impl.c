/* One routing implementation behind a uniform host-test API. Compiled twice by
 * test_router_differential: -DIMPL_OLD against tests/reference/router_v1.c (the
 * pre-optimisation router) and -DIMPL_NEW against main/router.c. Each object gets
 * its own symbol prefix and its own copy of every static, so the two run side by
 * side in one process and can be fed identical packets. */
#define GATEWAY_HOST_TEST
#include <stdio.h>
#ifdef IMPL_OLD
#define H(x) old_##x
#define ROUTER_SOURCE "reference/router_v1.c"
#else
#define H(x) new_##x
#define ROUTER_SOURCE "../main/router.c"
#endif
#define gateway_host_input H(gateway_host_input)
#define gateway_tunnel_input H(gateway_tunnel_input)
#define gateway_alias H(gateway_alias)
#define gateway_forget H(gateway_forget)
#define gateway_suspend H(gateway_suspend)
#define gateway_usb_detach H(gateway_usb_detach)
#define STUB_FIRST_ALIAS 0 /* the old router allocated 0xc6120001 + n sequentially */
#include "router_stubs.h"
#include "router_impl.h"
static int ml_gateway_queue_packet(microlink_t *ml, uint32_t ip, const uint8_t *data, size_t len) {
    struct pbuf *p = pbuf_alloc(0, len, 0);
    memcpy(p->payload, data, len);
    ip4_addr_t dest = {.addr = ip};
    struct netif *wg = ml->wg_netif;
    int result = wg->output(wg, p, &dest);
    pbuf_free(p);
    return result;
}
#ifdef IMPL_NEW
#include "../main/route_table.c"
#endif
#include ROUTER_SOURCE

#define MAX_MEMBERS 8
static struct {
    membership_t m;
    microlink_t client;
    struct netif wg;
    bool used;
} slot[MAX_MEMBERS];
static cap_t captures[CAP_MAX];
static unsigned captured;
static err_t record(int kind, int member, struct pbuf *p, const ip4_addr_t *ip) {
    if (captured < CAP_MAX) {
        cap_t *c = &captures[captured++];
        c->kind = kind;
        c->member = member;
        c->next_hop = ip->addr;
        c->n = p->tot_len;
        assert(p->tot_len <= sizeof(c->bytes));
        memcpy(c->bytes, p->payload, p->tot_len);
    }
    return ERR_OK;
}
static err_t output_usb(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) { (void)n; return record(1, 0, p, ip); }
static err_t output_wg(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) {
    for (unsigned i = 0; i < MAX_MEMBERS; i++)
        if (&slot[i].wg == n)
            return record(0, slot[i].m.id, p, ip);
    abort();
}
void H(setup)(void) {
    usb_interface = &usb;
    usb.output = output_usb;
}
void H(add_member)(uint32_t id, uint32_t vpn_ip) {
    for (unsigned i = 0; i < MAX_MEMBERS; i++)
        if (!slot[i].used) {
            slot[i].used = true;
            slot[i].m = (membership_t){members, id, &slot[i].client};
            slot[i].client = (microlink_t){&slot[i].wg, vpn_ip, ML_STATE_CONNECTED, 0};
            slot[i].wg.output = output_wg;
            members = &slot[i].m;
            return;
        }
    abort();
}
void H(remove_member)(uint32_t id) {
    for (membership_t **link = &members; *link; link = &(*link)->next)
        if ((*link)->id == id) {
            *link = (*link)->next;
            break;
        }
    for (unsigned i = 0; i < MAX_MEMBERS; i++)
        if (slot[i].used && slot[i].m.id == id)
            memset(&slot[i], 0, sizeof(slot[i]));
}
void H(set_state)(uint32_t id, int state) {
    for (unsigned i = 0; i < MAX_MEMBERS; i++)
        if (slot[i].used && slot[i].m.id == id)
            slot[i].client.state = state;
}
uint32_t H(alias)(uint32_t id, uint32_t peer) { return gateway_alias(id, peer); }
void H(suspend)(uint32_t id) { gateway_suspend(id); }
void H(forget)(uint32_t id) { gateway_forget(id); }
void H(detach)(void) { gateway_usb_detach(); }
void H(set_clock)(int64_t us) { clock_us = us; }
int H(host_packet)(const uint8_t *b, size_t n) {
    struct pbuf *p = pbuf_alloc(0, n, 0);
    pbuf_take(p, b, n);
    int consumed = gateway_host_input(p, &usb);
    if (!consumed)
        pbuf_free(p);
    return consumed;
}
void H(tunnel_packet)(uint32_t id, const uint8_t *b, size_t n) {
    for (unsigned i = 0; i < MAX_MEMBERS; i++)
        if (slot[i].used && slot[i].m.id == id) {
            struct pbuf *p = pbuf_alloc(0, n, 0);
            pbuf_take(p, b, n);
            gateway_tunnel_input(p, &slot[i].wg);
            return;
        }
}
unsigned H(captured)(void) { return captured; }
const cap_t *H(capture)(unsigned i) { return &captures[i]; }
void H(clear)(void) { captured = 0; }
#ifdef IMPL_NEW
void new_fill(void) {
    alias_fill_run(clock_us);
    hold_service(clock_us);
}
void new_hold_flush(void) { hold_flush(); }
#endif
/* Debug aid for a failing differential run. */
void H(debug)(uint32_t dest) {
#ifdef IMPL_OLD
    for (unsigned i = 0; i < 64; i++)
        if (aliases[i].alias == dest)
            fprintf(stderr, "old alias[%u] id=%u peer=%x\n", i, aliases[i].id, aliases[i].peer);
    unsigned used = 0;
    for (unsigned i = 0; i < 64; i++)
        used += flows[i].id != 0;
    fprintf(stderr, "old flows used %u gen %u now %lld\n", used, atomic_load(&usb_generation), (long long)clock_us);
    for (unsigned i = 0; i < 64; i++)
        if (flows[i].id)
            fprintf(stderr, "  old[%u] id=%u host=%x %u>%u p%u mapped=%u gen=%u touched=%lld\n", i, flows[i].id, flows[i].host, flows[i].local, flows[i].remote, flows[i].proto, flows[i].mapped, flow_generations[i], (long long)flows[i].touched);
#else
    rt_alias_t a;
    fprintf(stderr, "new alias found=%d\n", rt_alias_find(&rt, dest, &a));
    for (unsigned i = 0; i < 64; i++)
        if (rt.flow[i].used)
            fprintf(stderr, "  new[%u] id=%u host=%x %u>%u p%u mapped=%u gen=%u touched=%lld\n", i, rt.flow[i].flow.id, rt.flow[i].flow.host, rt.flow[i].flow.local, rt.flow[i].flow.remote, rt.flow[i].flow.proto, rt.flow[i].flow.mapped, rt.flow[i].generation, (long long)rt.flow[i].touched);
    for (unsigned i = 0; i < RT_STAT_COUNT; i++)
        fprintf(stderr, "stat[%u]=%u ", i, gateway_route_stat(i));
    fprintf(stderr, "\n");
#endif
    for (membership_t *m = members; m; m = m->next)
        fprintf(stderr, "member %u state %d\n", m->id, m->client->state);
}
void H(flows)(flow_row rows[64]) {
    memset(rows, 0, 64 * sizeof(rows[0]));
    for (unsigned i = 0; i < 64; i++) {
#ifdef IMPL_OLD
        if (flows[i].id)
            rows[i] = (flow_row){flows[i].id, flows[i].peer, flows[i].host, flows[i].alias, flow_generations[i], flows[i].local, flows[i].remote, flows[i].mapped, flows[i].proto, flows[i].touched};
#else
        if (rt.flow[i].used)
            rows[i] = (flow_row){rt.flow[i].flow.id, rt.flow[i].flow.peer, rt.flow[i].flow.host, rt.flow[i].flow.alias, rt.flow[i].generation, rt.flow[i].flow.local, rt.flow[i].flow.remote, rt.flow[i].flow.mapped, rt.flow[i].flow.proto, rt.flow[i].touched};
#endif
    }
}
