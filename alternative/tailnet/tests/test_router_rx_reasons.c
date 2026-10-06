/* Tunnel -> USB: every way gateway_tunnel_input can refuse a packet increments exactly its own counter (plus the REPLY_NOMATCH
 * aggregate for the flow/membership reasons), a good reply increments only forwarded_in, and an allocation failure returns the
 * packet to its caller (lwIP's input contract: the caller frees on an error). The real router.c and route_table.c on host stubs.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -D_GNU_SOURCE -Wall -Wextra -pthread \
 *      -I tests -I main -I components/microlink/include -I ../../components/tdongle_runtime/include \
 *      -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter tests/test_router_rx_reasons.c -o build-host/test_router_rx_reasons */
#define GATEWAY_HOST_TEST
#include <stdio.h>
#include "router_stubs.h"
static int ml_gateway_queue_packet(microlink_t *ml, uint32_t ip, const uint8_t *data, size_t len) {
    struct pbuf *p = pbuf_alloc(0, len, 0); memcpy(p->payload, data, len);
    ip4_addr_t dest = {.addr = ip}; struct netif *wg = ml->wg_netif;
    int result = wg->output(wg, p, &dest); pbuf_free(p); return result;
}
#include "../main/route_table.c"
#include "../main/router.c"

static void checksums(uint8_t *b, size_t n, unsigned h) {
    wr16(b + 10, 0); wr16(b + 10, finish(sum(b, h, 0)));
    unsigned offset = b[9] == 6 ? 16 : 6; uint8_t *t = b + h; unsigned length = n - h;
    wr16(t + offset, 0);
    uint32_t s = sum(b + 12, 8, 0) + b[9] + length; s = sum(t, length, s);
    uint16_t c = finish(s); wr16(t + offset, c ? c : 65535);
}
static uint8_t sent[1500]; static size_t sent_size; static struct netif *sent_on; static unsigned sends;
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) {
    assert(p->tot_len <= sizeof(sent)); memcpy(sent, p->payload, p->tot_len); sent_size = p->tot_len; sent_on = n; sends++; return ERR_OK;
}
static err_t output_fail(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) { (void)n; (void)p; (void)ip; return ERR_MEM; }

static uint32_t snapshot[RT_STAT_COUNT];
static void snap(void) { for (unsigned i = 0; i < RT_STAT_COUNT; i++) snapshot[i] = gateway_route_stat(i); }
static uint32_t d(unsigned s) { return gateway_route_stat(s) - snapshot[s]; }
/* exactly these counters moved by one each; every other counter is unchanged */
static void expect(const char *what, unsigned a, unsigned b, unsigned c) {
    for (unsigned i = 0; i < RT_STAT_COUNT; i++) {
        unsigned want = (i == a || i == b || i == c) ? 1 : 0;
        if (d(i) != want) { fprintf(stderr, "%s: counter %s moved by %u, wanted %u\n", what, rt_stat_name(i), d(i), want); abort(); }
    }
}
#define NONE RT_STAT_COUNT

int main(void) {
    usb_interface = &usb; usb.output = output;
    struct netif wg = {.output = output}, other = {.output = output};
    microlink_t client = {&wg, 0x64400001, 4};
    membership_t member = {NULL, 42, &client};
    members = &member;
    uint32_t alias = gateway_alias(42, 0x64400002);

    /* open a flow USB -> tunnel and keep the reply we will mangle */
    struct pbuf *request = pbuf_alloc(0, 32, 0); uint8_t *b = request->payload;
    b[0] = 0x45; b[8] = 64; b[9] = 17; wr16(b + 2, 32); wr32(b + 12, 0xc0a84d02); wr32(b + 16, alias); wr16(b + 20, 1234); wr16(b + 22, 8768); wr16(b + 24, 12);
    checksums(b, 32, 20);
    gateway_host_input(request, &usb);
    assert(sends == 1 && sent_on == &wg);
    uint16_t mapped = rd16(sent + 20);
    uint8_t reply[32]; memcpy(reply, sent, 32);
    wr32(reply + 12, 0x64400002); wr32(reply + 16, client.vpn_ip); wr16(reply + 20, 8768); wr16(reply + 22, mapped);
    checksums(reply, 32, 20);

#define SEND(label, bytes, len, netif_) do { struct pbuf *p_ = pbuf_alloc(0, (len), 0); pbuf_take(p_, (bytes), (len)); snap(); \
        err_t r_ = gateway_tunnel_input(p_, (netif_)); assert(r_ == ERR_OK); (void)label; } while (0)

    /* a good reply */
    unsigned before = sends;
    SEND("good", reply, 32, &wg);
    expect("good", RT_STAT_FORWARDED_IN, NONE, NONE);
    assert(sends == before + 1 && sent_on == &usb);

    /* malformed: shorter than a header, not IPv4, total length longer than the data, total length below a header */
    uint8_t m[64];
    for (unsigned len = 0; len < 20; len++) { memcpy(m, reply, 32); SEND("short", m, len, &wg); expect("short", RT_STAT_TUNNEL_MALFORMED, NONE, NONE); }
    memcpy(m, reply, 32); m[0] = 0x65; SEND("v6", m, 32, &wg); expect("not ipv4", RT_STAT_TUNNEL_MALFORMED, NONE, NONE);
    memcpy(m, reply, 32); wr16(m + 2, 33); SEND("long", m, 32, &wg); expect("length > data", RT_STAT_TUNNEL_MALFORMED, NONE, NONE);
    memcpy(m, reply, 32); wr16(m + 2, 19); SEND("tiny", m, 32, &wg); expect("length < header", RT_STAT_TUNNEL_MALFORMED, NONE, NONE);

    /* a bad IP header checksum fails the router's own validation */
    memcpy(m, reply, 32); m[10] ^= 0xff; SEND("csum", m, 32, &wg); expect("bad packet", RT_STAT_BAD_PACKET, NONE, NONE);

    /* membership and address checks */
    SEND("no member", reply, 32, &other); expect("no member", RT_STAT_REPLY_NO_MEMBER, RT_STAT_REPLY_NOMATCH, NONE);
    memcpy(m, reply, 32); wr32(m + 16, 0x64400009); checksums(m, 32, 20); SEND("not us", m, 32, &wg); expect("not us", RT_STAT_REPLY_NOT_US, RT_STAT_REPLY_NOMATCH, NONE);

    /* flow lookup, in the order rt_flow_in_why checks */
    memcpy(m, reply, 32); wr16(m + 22, 39999); checksums(m, 32, 20); SEND("range", m, 32, &wg); expect("range low", RT_STAT_REPLY_FLOW_RANGE, RT_STAT_REPLY_NOMATCH, NONE);
    memcpy(m, reply, 32); wr16(m + 22, 65535); checksums(m, 32, 20); SEND("range", m, 32, &wg); expect("range high", RT_STAT_REPLY_FLOW_RANGE, RT_STAT_REPLY_NOMATCH, NONE);
    memcpy(m, reply, 32); wr16(m + 22, (uint16_t)(mapped + 1)); checksums(m, 32, 20); SEND("no flow", m, 32, &wg); expect("no flow", RT_STAT_REPLY_NO_FLOW, RT_STAT_REPLY_NOMATCH, NONE);
    memcpy(m, reply, 32); wr16(m + 20, 8769); checksums(m, 32, 20); SEND("remote port", m, 32, &wg); expect("owner: remote port", RT_STAT_REPLY_OWNER, RT_STAT_REPLY_NOMATCH, NONE);
    memcpy(m, reply, 32); wr32(m + 12, 0x64400003); checksums(m, 32, 20); SEND("other peer", m, 32, &wg); expect("owner: peer", RT_STAT_REPLY_OWNER, RT_STAT_REPLY_NOMATCH, NONE);
    memcpy(m, reply, 32); m[9] = 6; /* protocol: TCP header needed for the checksum validation */ {
        uint8_t t[40]; memset(t, 0, sizeof(t)); memcpy(t, reply, 20); t[9] = 6; wr16(t + 2, 40); t[32] = 0x50; t[33] = 0x10; wr16(t + 20, 8768); wr16(t + 22, mapped); checksums(t, 40, 20);
        SEND("proto", t, 40, &wg); expect("owner: protocol", RT_STAT_REPLY_OWNER, RT_STAT_REPLY_NOMATCH, NONE);
    }
    gateway_usb_detach();                                                                    /* the USB side re-enumerated since */
    SEND("generation", reply, 32, &wg); expect("generation", RT_STAT_REPLY_GENERATION, RT_STAT_REPLY_NOMATCH, NONE);

    /* idle: a fresh flow, then the clock passes the idle limit */
    request = pbuf_alloc(0, 32, 0); b = request->payload;
    b[0] = 0x45; b[8] = 64; b[9] = 17; wr16(b + 2, 32); wr32(b + 12, 0xc0a84d02); wr32(b + 16, alias); wr16(b + 20, 4321); wr16(b + 22, 8768); wr16(b + 24, 12);
    checksums(b, 32, 20);
    gateway_host_input(request, &usb);
    uint16_t mapped2 = rd16(sent + 20);
    memcpy(reply, sent, 32); wr32(reply + 12, 0x64400002); wr32(reply + 16, client.vpn_ip); wr16(reply + 20, 8768); wr16(reply + 22, mapped2); checksums(reply, 32, 20);
    clock_us += RT_FLOW_IDLE_US + 1;
    SEND("idle", reply, 32, &wg); expect("idle", RT_STAT_REPLY_IDLE, RT_STAT_REPLY_NOMATCH, NONE);

    /* allocation failure: refused with ERR_MEM, counted, and the packet is still the caller's (freed exactly once, by us) */
    {
        struct pbuf *p = pbuf_alloc(0, 32, 0); pbuf_take(p, reply, 32);
        snap(); stub_pbuf_fail = 1;
        err_t r = gateway_tunnel_input(p, &wg);
        stub_pbuf_fail = 0;
        assert(r == ERR_MEM);
        expect("nomem", RT_STAT_TUNNEL_NOMEM, NONE, NONE);
        assert(p->payload && !memcmp(p->payload, reply, 32));          /* untouched: not freed by the router */
        pbuf_free(p);                                                  /* ASan: a double free here is the bug this guards against */
    }

    /* the USB netif refusing the frame is tx_fail and the reply is not counted as forwarded */
    usb.output = output_fail;
    request = pbuf_alloc(0, 32, 0); b = request->payload;
    b[0] = 0x45; b[8] = 64; b[9] = 17; wr16(b + 2, 32); wr32(b + 12, 0xc0a84d02); wr32(b + 16, alias); wr16(b + 20, 1111); wr16(b + 22, 8768); wr16(b + 24, 12);
    checksums(b, 32, 20);
    gateway_host_input(request, &usb);
    uint16_t mapped3 = rd16(sent + 20);
    memcpy(reply, sent, 32); wr32(reply + 12, 0x64400002); wr32(reply + 16, client.vpn_ip); wr16(reply + 20, 8768); wr16(reply + 22, mapped3); checksums(reply, 32, 20);
    SEND("tx fail", reply, 32, &wg); expect("usb output failure", RT_STAT_TX_FAIL, NONE, NONE);
    usb.output = output;

    /* every reason has its own name in the report */
    for (unsigned i = 0; i < RT_STAT_COUNT; i++) { assert(rt_stat_name(i)[0]); for (unsigned j = 0; j < i; j++) assert(strcmp(rt_stat_name(i), rt_stat_name(j))); }
    gateway_forget(42);
    members = NULL;
    printf("router rx reasons ok (%u counters)\n", (unsigned)RT_STAT_COUNT);
    return 0;
}
