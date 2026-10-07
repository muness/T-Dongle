/* Drives the REAL ESP-IDF dhcpserver.c (included below) through a script and prints what it sends and its lease list.
 *   CFG <server> <mask> <gw|-> <dns1> <dns2|-> <pool_start|-> <pool_end|-> <lease_units>
 *   P <delta_s> <hex>   run delta one-second timer ticks, print the lease list (L), then deliver the packet (R)
 *   T <delta_s>         run delta ticks, print the lease list (L)
 * Output: L <ip>=<mac> ...   and   R NONE | R <dest ip> <port> <len> <hex, trailing zero bytes stripped> <arp ip|-> <arp mac|->
 */
#include "stub.h"
#include "dhcpserver/dhcpserver.h"
#include "dhcpserver/dhcpserver_options.h"

const ip_addr_t ip_addr_any_instance = {0};
static struct sent { int n; u32_t ip; u16_t port; unsigned char data[2048]; u16_t len; } last;
static int arp_set; static ip4_addr_t arp_ip; static struct eth_addr arp_mac;
err_t etharp_add_static_entry(const ip4_addr_t *ip, struct eth_addr *mac) { arp_set = 1; arp_ip = *ip; arp_mac = *mac; return ERR_OK; }
err_t etharp_remove_static_entry(const ip4_addr_t *ip) { return ERR_OK; }
struct pbuf *pbuf_alloc(int l, u16_t len, int t) { struct pbuf *p = calloc(1, sizeof *p); p->payload = calloc(1, len); p->len = p->tot_len = len; p->ref = 1; return p; }
void pbuf_free(struct pbuf *p) { if (p && --p->ref == 0) { free(p->payload); free(p); } }
u16_t pbuf_copy_partial(const struct pbuf *p, void *dst, u16_t len, u16_t off) { memcpy(dst, (char *)p->payload + off, len); return len; }
static struct udp_pcb the_pcb; static udp_recv_fn recv_fn; static void *recv_arg;
struct udp_pcb *udp_new(void) { return &the_pcb; }
void udp_remove(struct udp_pcb *p) {}
err_t udp_disconnect(struct udp_pcb *p) { return ERR_OK; }
err_t udp_bind(struct udp_pcb *p, const ip_addr_t *ip, u16_t port) { return ERR_OK; }
void udp_bind_netif(struct udp_pcb *p, struct netif *n) {}
void udp_recv(struct udp_pcb *p, udp_recv_fn fn, void *arg) { recv_fn = fn; recv_arg = arg; }
err_t udp_sendto(struct udp_pcb *p, struct pbuf *b, const ip_addr_t *ip, u16_t port) {
    last.n++; last.ip = ip->addr; last.port = port; last.len = b->tot_len; memcpy(last.data, b->payload, b->tot_len); return ERR_OK;
}
static sys_timeout_handler tmr_fn; static void *tmr_arg;
void sys_timeout(u32_t ms, sys_timeout_handler h, void *arg) { tmr_fn = h; tmr_arg = arg; }
void sys_untimeout(sys_timeout_handler h, void *arg) {}

#include "dhcpserver.c"

static void lease_cb(void *arg, u8_t ip[4], u8_t mac[6]) {}
static int hexval(int c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
static ip4_addr_t ip4(const char *s) { ip4_addr_t a; a.addr = inet_addr(s); return a; }
static void ipstr(u32_t addr, char *o) { const u8_t *b = (const u8_t *)&addr; sprintf(o, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]); }

static void dump(dhcps_t *d) {
    printf("L");
    for (list_node *n = d->plist; n; n = n->pnext) {
        struct dhcps_pool *p = n->pnode; char s[20]; ipstr(p->ip.addr, s);
        printf(" %s=%02x%02x%02x%02x%02x%02x", s, p->mac[0], p->mac[1], p->mac[2], p->mac[3], p->mac[4], p->mac[5]);
    }
    printf("\n");
}

int main(void) {
    char line[8192];
    static struct netif nif; dhcps_t *d = NULL;
    while (fgets(line, sizeof line, stdin)) {
        char *tok = strtok(line, " \n");
        if (!tok) continue;
        if (!strcmp(tok, "CFG")) {
            char *srv = strtok(NULL, " \n"), *mask = strtok(NULL, " \n"), *gw = strtok(NULL, " \n"), *d1 = strtok(NULL, " \n"),
                 *d2 = strtok(NULL, " \n"), *ps = strtok(NULL, " \n"), *pe = strtok(NULL, " \n"), *lu = strtok(NULL, " \n");
            d = dhcps_new(); memset(&last, 0, sizeof last);
            nif.ip_addr = ip4(srv); nif.netmask = ip4(mask); nif.gw = strcmp(gw, "-") ? ip4(gw) : (ip4_addr_t){0}; nif.up = 1;
            dhcps_set_new_lease_cb(d, lease_cb, NULL);
            dhcps_set_option_info(d, SUBNET_MASK, &nif.netmask, sizeof(nif.netmask));
            ip_addr_t dns = ip4(d1); dhcps_dns_setserver_by_type(d, &dns, DNS_TYPE_MAIN);
            if (strcmp(d2, "-")) { ip_addr_t b = ip4(d2); dhcps_dns_setserver_by_type(d, &b, DNS_TYPE_BACKUP); }
            dhcps_offer_t dnsflag = OFFER_DNS; dhcps_set_option_info(d, DOMAIN_NAME_SERVER, &dnsflag, sizeof dnsflag);
            dhcps_time_t lt = (dhcps_time_t)atoi(lu); dhcps_set_option_info(d, IP_ADDRESS_LEASE_TIME, &lt, sizeof lt);
            if (strcmp(ps, "-")) {
                dhcps_lease_t pool = { .enable = true, .start_ip = ip4(ps), .end_ip = ip4(pe) };
                dhcps_set_option_info(d, REQUESTED_IP_ADDRESS, &pool, sizeof pool);
            }
            if (dhcps_start(d, &nif, nif.ip_addr) != ERR_OK) { printf("CFGERR\n"); return 1; }
            {   char a[20], b[20]; ipstr(d->dhcps_poll.start_ip.addr, a); ipstr(d->dhcps_poll.end_ip.addr, b); printf("POOL %s %s\n", a, b); }
        } else if (!strcmp(tok, "P") || !strcmp(tok, "T")) {
            int isp = tok[0] == 'P';
            int delta = atoi(strtok(NULL, " \n"));
            for (int i = 0; i < delta; i++) tmr_fn(tmr_arg);
            dump(d);
            if (!isp) continue;
            char *hex = strtok(NULL, " \n"); size_t n = strlen(hex) / 2;
            unsigned char *buf = malloc(n ? n : 1); for (size_t i = 0; i < n; i++) buf[i] = hexval(hex[2 * i]) << 4 | hexval(hex[2 * i + 1]);
            struct pbuf *p = pbuf_alloc(0, (u16_t)n, 0); memcpy(p->payload, buf, n); free(buf);
            last.n = 0; arp_set = 0;
            ip_addr_t from = {0};
            recv_fn(recv_arg, &the_pcb, p, &from, 68);   /* frees p, like lwIP's recv path hands it over */
            if (!last.n) { printf("R NONE\n"); continue; }
            char s[20]; ipstr(last.ip, s); int z = last.len; while (z > 0 && !last.data[z - 1]) z--;
            printf("R %s %u %u ", s, last.port, last.len);
            for (int i = 0; i < z; i++) printf("%02x", last.data[i]);
            if (arp_set) { char a[20]; ipstr(arp_ip.addr, a); printf(" %s %02x%02x%02x%02x%02x%02x\n", a, arp_mac.addr[0], arp_mac.addr[1], arp_mac.addr[2], arp_mac.addr[3], arp_mac.addr[4], arp_mac.addr[5]); }
            else printf(" - -\n");
        }
    }
    return 0;
}
