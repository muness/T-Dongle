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
/* Real WireGuard plaintext retains up to 15 bytes of encryption padding.
 * SYN/ACK can happen to align while data and ACK-only packets do not. */
static void padded_replies(void) {
    struct netif wg = {.output = output}, other = {.output = output};
    microlink_t client = {&wg, 0x64400001, 4};
    membership_t member = {NULL, 42, &client};
    members = &member;
    uint32_t alias = gateway_alias(42, 0x64400002);
    for (unsigned proto = 6; proto <= 17; proto += 11) {
        for (unsigned payload = 0; payload < 64; payload++) {
            unsigned inner = 20 + (proto == 6 ? 20 : 8) + payload;
            struct pbuf *request = pbuf_alloc(0, inner, 0);
            uint8_t *b = request->payload;
            b[0] = 0x45; b[8] = 64; b[9] = proto;
            wr16(b+2, inner); wr32(b+12, 0xc0a84d02); wr32(b+16, alias);
            wr16(b+20, 1234); wr16(b+22, 8768);
            if (proto == 6) {b[32] = 0x50; b[33] = 0x10;}
            else wr16(b+24, inner-20);
            checksums(b, inner, 20);
            unsigned before = sends;
            gateway_host_input(request, &usb);
            assert(sends == before+1 && sent_on == &wg);
            uint16_t mapped = rd16(sent+20);
            unsigned padded = (inner+15)&~15;
            struct pbuf *reply = pbuf_alloc(0, padded, 0);
            b = reply->payload;
            memcpy(b, sent, inner);
            wr32(b+12, 0x64400002); wr32(b+16, client.vpn_ip);
            wr16(b+20, 8768); wr16(b+22, mapped);
            for (unsigned i=inner-payload; i<inner; i++) b[i]=(uint8_t)i;
            checksums(b, inner, 20);
            struct pbuf *wrong_member=pbuf_alloc(0,padded,0);
            pbuf_take(wrong_member,b,padded);
            gateway_tunnel_input(wrong_member,&other);
            assert(sends == before+1);
            struct pbuf *truncated=pbuf_alloc(0,inner-1,0);
            pbuf_take(truncated,b,inner-1);
            gateway_tunnel_input(truncated,&wg);
            assert(sends == before+1);
            gateway_tunnel_input(reply, &wg);
            assert(sends == before+2 && sent_on == &usb);
            assert(sent_size == inner && rd16(sent+2) == inner);
            assert(rd32(sent+12) == alias && rd32(sent+16) == 0xc0a84d02);
            assert(rd16(sent+20) == 8768 && rd16(sent+22) == 1234);
            assert(finish(sum(sent,20,0)) == 0);
            assert(finish(sum(sent+20,inner-20,sum(sent+12,8,0)+proto+inner-20)) == 0);
            for (unsigned i=inner-payload; i<inner; i++) assert(sent[i] == (uint8_t)i);
            /* Padding tolerance belongs only at authenticated WG ingress. */
            if (inner != padded) {
                struct pbuf *bad_host=pbuf_alloc(0,padded,0);
                b=bad_host->payload;memcpy(b,sent,inner);
                wr32(b+12,0xc0a84d02);wr32(b+16,alias);checksums(b,inner,20);
                gateway_host_input(bad_host,&usb);
                assert(sends == before+2);
            }
        }
    }
    gateway_forget(42);
    members=NULL;
}
int main(void) {
    usb_interface=&usb;
    usb.output = output;
    padded_replies();
    sends=0;
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
    // Both SYN directions must advertise a safe segment size. Lower values
    // survive, malformed option lengths are rejected without out-of-bounds reads.
    uint8_t syn[44]={0};syn[9]=6;syn[32]=0x60;syn[33]=2;syn[40]=2;syn[41]=4;
    wr16(syn+42,1460);assert(clamp_mss(syn,sizeof(syn),20) && rd16(syn+42)==1360);
    wr16(syn+42,1200);assert(clamp_mss(syn,sizeof(syn),20) && rd16(syn+42)==1200);
    syn[41]=255;assert(!clamp_mss(syn,sizeof(syn),20));
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
