#define GATEWAY_HOST_TEST
#include "router_stubs.h"
static int ml_gateway_queue_packet(microlink_t *ml,uint32_t ip,const uint8_t *data,size_t len) {
    struct pbuf *p=pbuf_alloc(0,len,0);memcpy(p->payload,data,len);
    ip4_addr_t dest={.addr=ip};struct netif *wg=ml->wg_netif;
    int result=wg->output(wg,p,&dest);pbuf_free(p);return result;
}
#include "../main/router.c"
static uint8_t sent[1500];
static size_t sent_size;
static struct netif *sent_on;
static unsigned sends;
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) {
    assert(p->tot_len <= sizeof(sent));
    memcpy(sent, p->payload, p->tot_len);
    sent_size = p->tot_len;
    sent_on = n;
    sends++;
    return ERR_OK;
}
static struct pbuf *packet(uint32_t src, uint32_t dst, uint16_t sport,
                           uint16_t dport) {
    struct pbuf *p = pbuf_alloc(0, 32, 0);
    uint8_t *b = p->payload;
    b[0] = 0x45;
    b[8] = 64;
    b[9] = 17;
    wr16(b + 2, 32);
    wr32(b + 12, src);
    wr32(b + 16, dst);
    wr16(b + 20, sport);
    wr16(b + 22, dport);
    wr16(b + 24, 12);
    memcpy(b + 28, "ping", 4);
    checksums(b, 32, 20);
    return p;
}
int main(void) {
    usb.output = output;
    struct netif wg1 = {.output = output}, wg2 = {.output = output},
                 wg3 = {.output = output};
    microlink_t c1 = {&wg1, 0x64400001, 4}, c2 = {&wg2, 0x64400001, 4},
                c3 = {&wg3, 0x64400001, 4};
    membership_t m3 = {NULL, 3, &c3}, m2 = {&m3, 2, &c2}, m1 = {&m2, 1, &c1};
    /* 0 memberships: an unknown alias is consumed, never Internet-forwarded. */
    assert(gateway_host_input(packet(0xc0a84d02, 0xc6120001, 1234, 443),
                              &usb) == 1);
    assert(!sends);
    assert(gateway_host_input(packet(0xc0a84d02, 0xc0a84d01, 1234, 80), &wg1) ==
           1);
    members = &m1;
    uint32_t a = gateway_alias(1, 0x64400002), b = gateway_alias(2, 0x64400002),
             c = gateway_alias(3, 0x64400002);
    assert(a && b && c && a != b && b != c && a != c);
    assert(gateway_host_input(packet(0xc0a84d02, a, 1234, 443), &usb) == 1);
    assert(sends == 1 && sent_on == &wg1 && rd32(sent + 12) == c1.vpn_ip &&
           rd32(sent + 16) == 0x64400002);
    uint16_t port = rd16(sent + 20);
    assert(gateway_host_input(packet(0xc0a84d02, b, 1234, 443), &usb) == 1);
    assert(sends == 2 && sent_on == &wg2);
    assert(rd16(sent + 20) != port);
    assert(gateway_host_input(packet(0xc0a84d02, c, 1234, 443), &usb) == 1);
    assert(sent_on == &wg3);
    /* Identical IP/ports arriving from a different identity cannot claim a
     * flow. */
    unsigned before = sends;
    gateway_tunnel_input(packet(0x64400002, c1.vpn_ip, 443, port), &wg2);
    assert(sends == before);
    gateway_tunnel_input(packet(0x64400002, c1.vpn_ip, 443, port), &wg1);
    assert(sends == before + 1 && sent_on == &usb && rd32(sent + 12) == a &&
           rd32(sent + 16) == 0xc0a84d02 && rd16(sent + 22) == 1234);
    assert(finish(sum(sent, 20, 0)) == 0);
    assert(finish(sum(sent + 20, 12, sum(sent + 12, 8, 0) + 17 + 12)) == 0);
    before = sends;
    struct pbuf *bad = packet(0xc0a84d02, a, 1234, 443);
    ((uint8_t *)bad->payload)[6] = 0x20;
    gateway_host_input(bad, &usb);
    assert(sends == before);
    gateway_host_input(packet(0xc0a80102, a, 1234, 443), &usb);
    assert(sends == before);
    gateway_host_input(packet(0xc0a84d02, a, 1234, 443), &wg1);
    assert(sends == before);
    gateway_suspend(2);assert(gateway_alias(2,0x64400002)==b);
    gateway_forget(1);
    gateway_tunnel_input(packet(0x64400002, c1.vpn_ip, 443, port), &wg1);
    assert(sends == before);
    assert(gateway_alias(4, 0x64400002) != a);
    clock_us += 121000000;
    gateway_tunnel_input(packet(0x64400002, c2.vpn_ip, 443, 40001), &wg2);
    assert(sends == before);
    gateway_host_input(packet(0xc0a84d02, b, 1234, 443), &usb);
    uint16_t detach_port = rd16(sent + 20);
    before = sends;
    gateway_usb_detach();
    gateway_tunnel_input(packet(0x64400002, c2.vpn_ip, 443, detach_port), &wg2);
    assert(sends == before);
    gateway_host_input(packet(0xc0a84d02, b, 1234, 443), &usb);
    assert(rd16(sent + 20) != detach_port);
    /* Exercise malformed headers under sanitizers without creating routes. */
    for (unsigned n = 0; n < 10000; n++) {
        struct pbuf *p = pbuf_alloc(0, n % 80, 0);
        for (size_t i = 0; i < p->tot_len; i++)
            ((uint8_t *)p->payload)[i] = rand();
        int consumed = gateway_host_input(p, &usb);
        if (!consumed)
            pbuf_free(p);
    }
    return 0;
}
