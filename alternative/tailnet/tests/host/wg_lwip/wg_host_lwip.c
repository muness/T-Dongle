/* In-memory fakes for the lwIP calls made by wireguardif.c; see wg_host_lwip.h. */
#include "wg_host_lwip.h"
#include <assert.h>

const ip_addr_t ip_addr_any = { 0 };

const char *ipaddr_ntoa(const ip_addr_t *a) {
    static char buf[16];
#ifdef WG_HOST_IPV6
    if (a->type == IPADDR_TYPE_V6) return "v6";
    u32_t v = a->u_addr.ip4.addr;
#else
    u32_t v = a->addr;
#endif
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, v >> 24);
    return buf;
}

int wg_host_pbuf_fail;
int wg_host_pbuf_live;
unsigned long wg_host_pbuf_allocs, wg_host_copied_bytes;
struct pbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type) {
    (void)layer; (void)type;
    if (wg_host_pbuf_fail) return NULL;
    struct pbuf *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->base = p->payload = calloc(1, length ? length : 1);
    if (!p->payload) { free(p); return NULL; }
    p->tot_len = p->len = length;
    wg_host_pbuf_live++;
    wg_host_pbuf_allocs++;
    return p;
}
struct pbuf *pbuf_alloced_custom(pbuf_layer layer, u16_t length, pbuf_type type, struct pbuf_custom *pc, void *payload_mem, u16_t payload_mem_len) {
    (void)layer; (void)type; (void)payload_mem_len;
    memset(pc, 0, sizeof(*pc));
    pc->pbuf.payload = pc->pbuf.base = payload_mem;
    pc->pbuf.tot_len = pc->pbuf.len = length;
    pc->pbuf.flags = PBUF_FLAG_IS_CUSTOM;
    wg_host_pbuf_live++;
    return &pc->pbuf;
}
u8_t pbuf_free(struct pbuf *p) {
    if (!p) return 0;
    wg_host_pbuf_live--;
    if (p->flags & PBUF_FLAG_IS_CUSTOM) { ((struct pbuf_custom *)p)->custom_free_function(p); return 1; }
    free(p->base); free(p);
    return 1;
}
u8_t pbuf_remove_header(struct pbuf *p, size_t n) {
    if (n > p->len) return 1;
    p->payload = (u8_t *)p->payload + n; p->len = (u16_t)(p->len - n); p->tot_len = (u16_t)(p->tot_len - n);
    return 0;
}
void pbuf_realloc(struct pbuf *p, u16_t new_len) {
    if (new_len >= p->tot_len) return;
    assert(!p->next);   /* single-segment pbufs only: that is all the receive path makes */
    p->len = p->tot_len = new_len;
}
err_t pbuf_take(struct pbuf *p, const void *data, u16_t len) { if (len > p->tot_len) return ERR_MEM; memcpy(p->payload, data, len); wg_host_copied_bytes += len; return ERR_OK; }
u16_t pbuf_copy_partial(const struct pbuf *p, void *dst, u16_t len, u16_t off) {
    if (off >= p->tot_len) return 0;
    if (len > p->tot_len - off) len = (u16_t)(p->tot_len - off);
    memcpy(dst, (const u8_t *)p->payload + off, len);
    wg_host_copied_bytes += len;
    return len;
}
u8_t pbuf_get_at(const struct pbuf *p, u16_t off) { return off < p->tot_len ? ((const u8_t *)p->payload)[off] : 0; }

void netif_set_link_up(struct netif *n) { n->link_up = 1; }
void netif_set_link_down(struct netif *n) { n->link_up = 0; }
err_t tcpip_input(struct pbuf *p, struct netif *inp) { (void)inp; pbuf_free(p); return ERR_OK; }

struct udp_pcb *udp_new(void) { return calloc(1, sizeof(struct udp_pcb)); }
err_t udp_bind(struct udp_pcb *p, const ip_addr_t *a, u16_t port) { (void)p; (void)a; (void)port; return ERR_OK; }
void udp_bind_netif(struct udp_pcb *p, const struct netif *n) { (void)p; (void)n; }
void udp_recv(struct udp_pcb *p, udp_recv_fn r, void *arg) { (void)p; (void)r; (void)arg; }
void udp_remove(struct udp_pcb *p) { free(p); }
err_t udp_sendto(struct udp_pcb *p, struct pbuf *b, const ip_addr_t *d, u16_t port) { (void)p; (void)b; (void)d; (void)port; return ERR_OK; }

void *mem_malloc(size_t n) { return malloc(n); }
void *mem_calloc(size_t c, size_t s) { return calloc(c, s); }
void mem_free(void *p) { free(p); }

/* A single recorded timer: enough to assert that free/shutdown cancel it. */
int wg_host_timeouts_armed;
void sys_timeout(u32_t msecs, sys_timeout_handler h, void *arg) { (void)msecs; (void)h; (void)arg; wg_host_timeouts_armed++; }
void sys_untimeout(sys_timeout_handler h, void *arg) { (void)h; (void)arg; if (wg_host_timeouts_armed > 0) wg_host_timeouts_armed--; }

void *heap_caps_malloc(size_t n, uint32_t caps) { (void)caps; return malloc(n); }
void heap_caps_free(void *p) { free(p); }
