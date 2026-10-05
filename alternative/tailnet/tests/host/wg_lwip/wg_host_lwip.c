/* In-memory fakes for the lwIP calls made by wireguardif.c; see wg_host_lwip.h. */
#include "wg_host_lwip.h"

const ip_addr_t ip_addr_any = { 0 };

const char *ipaddr_ntoa(const ip_addr_t *a) {
    static char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a->addr & 0xff, (a->addr >> 8) & 0xff, (a->addr >> 16) & 0xff, a->addr >> 24);
    return buf;
}

int wg_host_pbuf_fail;
struct pbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type) {
    (void)layer; (void)type;
    if (wg_host_pbuf_fail) return NULL;
    struct pbuf *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->payload = calloc(1, length ? length : 1);
    if (!p->payload) { free(p); return NULL; }
    p->tot_len = p->len = length;
    return p;
}
u8_t pbuf_free(struct pbuf *p) { if (p) { free(p->payload); free(p); } return 1; }
err_t pbuf_take(struct pbuf *p, const void *data, u16_t len) { if (len > p->tot_len) return ERR_MEM; memcpy(p->payload, data, len); return ERR_OK; }
u16_t pbuf_copy_partial(const struct pbuf *p, void *dst, u16_t len, u16_t off) {
    if (off >= p->tot_len) return 0;
    if (len > p->tot_len - off) len = (u16_t)(p->tot_len - off);
    memcpy(dst, (const u8_t *)p->payload + off, len);
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
