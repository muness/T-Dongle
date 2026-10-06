/* Cryptokey routing on the inbound path (WireGuard whitepaper 5.4.6), IPv4 and IPv6, on the REAL wireguardif.c compiled against the
 * dual-stack lwIP fake (-DWG_HOST_IPV6: ip_addr_t is lwIP's union + type, ip_addr_net_eq is 0 for two IPv6 addresses, as in the
 * firmware build with CONFIG_LWIP_IPV6=y).
 *
 * The defect: after a transport message authenticated, the IPv6 branch of the receive path read bytes 2-3 of the IPv6 header (the low
 * flow-label bits) as the packet length, and skipped the AllowedIPs check entirely. A peer that is allowed to use one tunnel address
 * could therefore inject packets with ANY IPv6 source, and its flow label chose how much of the buffer was "the packet".
 *
 * Properties, each with an adversarial case:
 *   1. the source address must be in the sending peer's AllowedIPs of the SAME family, for IPv4 and IPv6 alike (a 0.0.0.0/0 entry
 *      does not admit an IPv6 source, a ::/0 entry does not admit an IPv4 one, a v6 prefix is compared bit for bit at every length);
 *   2. the IPv6 length is the Payload Length (bytes 4-5), never the flow label; it must fit the decrypted bytes; the delivered packet
 *      is exactly 40 + Payload Length bytes (the 16 byte padding is trimmed);
 *   3. a well formed packet from an allowed IPv6 source is dropped and counted (rx_ipv6_unsupported) unless the interface was told to
 *      deliver IPv6: the gateway rejects IPv6 (README);
 *   4. an impersonation attempt is counted as one (rx_allowed_ip for IPv4, rx_allowed_ip6 for IPv6) whatever else is wrong with the packet
 *      (counter order), and nothing reaches netif->input; a gateway whose peers have no IPv6 entry counts every IPv6 packet as rx_allowed_ip6;
 *   5. every datagram still ends in exactly one terminal counter (wireguard_stats.h) through the begin / decrypt / complete path, the
 *      in-place deferred path and the one-piece path.
 *
 *   wg=components/microlink/components/wireguard_lwip/src
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -w -DWIREGUARD_CRYPTO_REFC=1 -DWG_HOST_IPV6 \
 *      -I tests/host/wg_lwip -I tests/host_esp -I $wg -I $wg/crypto -I $wg/crypto/refc tests/test_wg_ipv6_rx.c \
 *      tests/host/wg_lwip/wg_host_lwip.c $wg/wireguard.c $wg/wireguardif.c $wg/wireguard_pool.c $wg/crypto.c \
 *      $wg/crypto/refc/{blake2s,chacha20,chacha20poly1305,poly1305-donna,x25519}.c -o build-host/test_wg_ipv6_rx */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wireguard.h"
#include "wireguardif.h"
#include "wireguard_stats.h"
#include "chacha20poly1305.h"
#define wireguard_aead_encrypt(dst, src, srclen, ad, adlen, nonce, key) chacha20poly1305_encrypt(dst, src, srclen, ad, adlen, nonce, key)

static uint32_t g_now = 100000;
uint32_t wireguard_sys_now(void) { return g_now; }
void wireguard_tai64n_now(uint8_t *out) { memset(out, 0, 12); out[7] = 1; }
bool wireguard_is_under_load(void) { return false; }
void wireguard_set_tai64n_base_seconds(uint64_t s) { (void)s; }
void wireguard_random_bytes(void *bytes, size_t size) { memset(bytes, 0x42, size); }

#define LOCAL_INDEX 0xA1B2C3D4u
static const uint8_t PEER_V4[4] = {10, 1, 0, 1};
static const uint8_t OTHER_V4[4] = {10, 1, 0, 2};
static const uint8_t PEER_V6[16] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t OTHER_V6[16] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

struct dev { struct netif nif; struct wireguardif_init_data init; char key_b64[64]; };
static struct dev D;
static struct wireguard_peer *PEER;

static unsigned delivered, input_calls;
static uint8_t last_input[1600];
static size_t last_input_len;
static err_t capture_input(struct pbuf *p, struct netif *inp) {
    (void)inp;
    input_calls++;
    assert(p->tot_len <= sizeof(last_input));
    memcpy(last_input, p->payload, p->tot_len); last_input_len = p->tot_len;
    delivered++;
    pbuf_free(p);
    return ERR_OK;
}

static ip_addr_t v4_addr(const uint8_t b[4]) { ip_addr_t a; memset(&a, 0, sizeof(a)); a.type = IPADDR_TYPE_V4; memcpy(&a.u_addr.ip4.addr, b, 4); return a; }
static ip_addr_t v4_mask(unsigned plen) {
    ip_addr_t a; memset(&a, 0, sizeof(a)); a.type = IPADDR_TYPE_V4;
    uint32_t m = plen ? 0xffffffffu << (32 - plen) : 0; m = __builtin_bswap32(m); a.u_addr.ip4.addr = m; return a;
}
static ip_addr_t v6_addr(const uint8_t b[16]) { ip_addr_t a; memset(&a, 0, sizeof(a)); a.type = IPADDR_TYPE_V6; memcpy(a.u_addr.ip6.addr, b, 16); return a; }
static ip_addr_t v6_mask(unsigned plen) {
    uint8_t m[16] = {0};
    for (unsigned i = 0; i < plen; i++) m[i / 8] |= (uint8_t)(0x80 >> (i % 8));
    return v6_addr(m);
}

static void rig_up(bool with_v4_peer_entry) {
    uint8_t key[32]; size_t n = 64;
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1);
    assert(wireguard_base64_encode(key, 32, D.key_b64, &n));
    memset(&D.nif, 0, sizeof(D.nif));
    D.init.private_key = D.key_b64; D.init.listen_port = 51820; D.init.bind_netif = NULL;
    D.nif.state = &D.init;
    assert(wireguardif_init(&D.nif) == ERR_OK);
    D.nif.input = capture_input;
    uint8_t pk[32], idx; char s[64]; n = 64; struct wireguardif_peer p;
    for (int i = 0; i < 32; i++) pk[i] = (uint8_t)(i + 5);
    pk[31] &= 0x7f;
    assert(wireguard_base64_encode(pk, 32, s, &n));
    wireguardif_peer_init(&p);
    p.public_key = s;
    if (with_v4_peer_entry) { p.allowed_ip = v4_addr(PEER_V4); p.allowed_mask = v4_mask(32); }
    assert(wireguardif_add_peer(&D.nif, &p, &idx) == ERR_OK);
    PEER = wireguard_device_peer((struct wireguard_device *)D.nif.state, idx);
    if (!with_v4_peer_entry) memset(PEER->allowed_source_ips, 0, sizeof(PEER->allowed_source_ips));   /* wireguardif_peer_init's default is 0.0.0.0/0: start empty */
}
static void rig_down(void) { wireguardif_free(&D.nif); }
static void add_v6(const uint8_t net[16], unsigned plen) {
    ip_addr_t ip = v6_addr(net), mask = v6_mask(plen);
    assert(wireguardif_add_allowed_ip(&D.nif, 0, &ip, &mask) == ERR_OK);
}

static void key_for(uint8_t key[32], uint32_t index) { for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x30 + i + (index & 0xff)); }
static void set_receiving(struct wireguard_keypair *k, uint32_t index) {
    memset(k, 0, sizeof(*k));
    k->valid = true; k->initiator = false; k->keypair_millis = g_now; k->local_index = index; k->remote_index = 0x11223344;
    k->receiving_valid = true; k->sending_valid = true; k->sending_counter = 0;
    key_for(k->receiving_key, index);
    wireguard_replay_reset(&k->replay);
}
static void fresh(bool with_v4_peer_entry) {
    rig_up(with_v4_peer_entry); wireguard_rx_stats_reset();
    set_receiving(&PEER->curr_keypair, LOCAL_INDEX);
    delivered = input_calls = 0;
}

static size_t seal_raw(uint8_t *out, uint32_t receiver, uint64_t counter, const uint8_t *plain, size_t plain_len, size_t pad_to) {
    uint8_t buf[1700]; memset(buf, 0, sizeof(buf)); memcpy(buf, plain, plain_len);
    size_t padded = pad_to > plain_len ? pad_to : plain_len;
    memset(out, 0, 16);
    out[0] = 4;
    memcpy(out + 4, &receiver, 4);
    for (int i = 0; i < 8; i++) out[8 + i] = (uint8_t)(counter >> (8 * i));
    uint8_t key[32]; key_for(key, receiver);
    wireguard_aead_encrypt(out + 16, buf, padded, NULL, 0, counter, key);
    return 16 + padded + WIREGUARD_AUTHTAG_LEN;
}
/* an IPv6 header: version 6, a hostile flow label (bytes 1-3), Payload Length at bytes 4-5, next header, hop limit, src, dst */
static size_t ip6_packet(uint8_t *b, const uint8_t src[16], unsigned payload_len_field, size_t bytes, uint8_t flow_hi, uint8_t flow_lo, uint8_t next_header) {
    memset(b, 0, bytes);
    b[0] = 0x60; b[1] = flow_hi; b[2] = flow_hi; b[3] = flow_lo;
    b[4] = (uint8_t)(payload_len_field >> 8); b[5] = (uint8_t)payload_len_field; b[6] = next_header; b[7] = 64;
    memcpy(b + 8, src, 16); b[24] = 0xfd; b[39] = 0x77;
    for (size_t i = 40; i < bytes; i++) b[i] = (uint8_t)(i * 5);
    return bytes;
}
static size_t ip4_packet(uint8_t *b, const uint8_t src[4], size_t total_field, size_t bytes) {
    memset(b, 0, bytes);
    b[0] = 0x45; b[2] = (uint8_t)(total_field >> 8); b[3] = (uint8_t)total_field; b[8] = 64; b[9] = 17;
    memcpy(b + 12, src, 4); b[16] = 10; b[17] = 9; b[18] = 9; b[19] = 9;
    for (size_t i = 20; i < bytes; i++) b[i] = (uint8_t)(i * 7);
    return bytes;
}

/* ---- delivery through each path ---- */
enum { PATH_SPLIT, PATH_INPLACE_DEFERRED, PATH_ONE_PIECE, PATHS };
static uint64_t counter_seq;
static void deliver(const uint8_t *plain, size_t plain_len, size_t pad_to, int path) {
    uint8_t dg[1800]; size_t n = seal_raw(dg, LOCAL_INDEX, counter_seq++, plain, plain_len, pad_to);
    ip_addr_t addr = v4_addr((const uint8_t[4]){192, 168, 0, 4});
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM);
    assert(p); memcpy(p->payload, dg, n);
    if (path == PATH_ONE_PIECE) {
        extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
        wireguardif_network_rx(D.nif.state, NULL, p, &addr, 41641);
        return;
    }
    struct wireguard_rx_job job;
    unsigned flags = path == PATH_INPLACE_DEFERRED ? WIREGUARDIF_RX_INPLACE : 0;
    if (wireguardif_rx_begin_ex(&D.nif, p, &addr, 41641, &job, flags)) {
        wireguard_rx_decrypt(&job);
        if (path == PATH_INPLACE_DEFERRED) {
            wireguardif_rx_complete_deferred(&D.nif, &addr, 41641, &job);
            wireguardif_rx_deliver(&D.nif, &job, 1);
        } else {
            wireguardif_rx_complete(&D.nif, &addr, 41641, &job);
        }
    }
}

static uint32_t before[WG_RXS_COUNT];
static void snap(void) { for (unsigned i = 0; i < WG_RXS_COUNT; i++) before[i] = wireguard_rx_stat_get(i); }
static uint32_t delta(unsigned s) { return wireguard_rx_stat_get(s) - before[s]; }
static void terminal_sum_check(void) {
    uint32_t sum = 0;
    for (unsigned i = 0; i < WG_RXS_COUNT; i++)
        if (i != WG_RXS_rx_data && i != WG_RXS_rx_bad_type) sum += wireguard_rx_stat_get(i);
    assert(sum == wireguard_rx_stat_get(WG_RXS_rx_data));
}
#define EXPECT_ONLY(terminal) do { \
        for (unsigned i = 0; i < WG_RXS_COUNT; i++) { \
            uint32_t want = (i == WG_RXS_rx_data || i == WG_RXS_##terminal) ? 1 : 0; \
            if (delta(i) != want) { fprintf(stderr, "%s:%d path %d: expected only %s, but %s moved by %u\n", __FILE__, __LINE__, path, #terminal, wireguard_rx_stat_name(i), delta(i)); abort(); } \
        } terminal_sum_check(); } while (0)

/* ---- the decision on raw bytes ---- */
static wg_inner_verdict_t check(const uint8_t *b, size_t n, bool v6_ok, size_t *ip_len) { *ip_len = 0; return wireguardif_inner_check(PEER, v6_ok, b, n, ip_len); }

static void t_v6_source_in_allowed(void) {
    fresh(true); add_v6(PEER_V6, 128);
    uint8_t b[200]; size_t len;
    ip6_packet(b, PEER_V6, 60, 100, 0, 0, 17);
    assert(check(b, 100, true, &len) == WG_INNER_OK && len == 100);
    assert(check(b, 100, false, &len) == WG_INNER_IPV6_UNSUPPORTED);
    /* a source one bit off */
    for (unsigned bit = 0; bit < 128; bit++) {
        uint8_t s[16]; memcpy(s, PEER_V6, 16); s[bit / 8] ^= (uint8_t)(0x80 >> (bit % 8));
        ip6_packet(b, s, 60, 100, 0, 0, 17);
        assert(check(b, 100, true, &len) == WG_INNER_ALLOWED_IP6);
        assert(check(b, 100, false, &len) == WG_INNER_ALLOWED_IP6);
    }
    rig_down();
}
/* a prefix entry is compared bit for bit at every length, against an independent bit-by-bit model */
static bool model_match(const uint8_t net[16], unsigned plen, const uint8_t src[16]) {
    for (unsigned i = 0; i < plen; i++) if (((net[i / 8] ^ src[i / 8]) >> (7 - i % 8)) & 1) return false;
    return true;
}
static void t_v6_prefixes(void) {
    srand(7);
    for (unsigned plen = 0; plen <= 128; plen++) {
        fresh(false);
        uint8_t net[16]; for (int i = 0; i < 16; i++) net[i] = (uint8_t)rand();
        add_v6(net, plen);
        for (int trial = 0; trial < 60; trial++) {
            uint8_t src[16]; memcpy(src, net, 16);
            switch (trial % 4) {
            case 0: break;                                                   /* the network address itself */
            case 1: for (int i = 0; i < 16; i++) src[i] = (uint8_t)rand(); break;
            case 2: if (plen < 128) { unsigned bit = plen + (unsigned)rand() % (128 - plen); src[bit / 8] ^= (uint8_t)(0x80 >> (bit % 8)); } break;   /* differs inside the host part: still in */
            default: if (plen) { unsigned bit = (unsigned)rand() % plen; src[bit / 8] ^= (uint8_t)(0x80 >> (bit % 8)); } break;                      /* differs inside the prefix: out */
            }
            uint8_t b[80]; size_t len;
            ip6_packet(b, src, 40, 80, 0, 0, 17);
            wg_inner_verdict_t v = check(b, 80, true, &len);
            assert((v == WG_INNER_OK) == model_match(net, plen, src));
            assert(v == WG_INNER_OK || v == WG_INNER_ALLOWED_IP6);
        }
        rig_down();
    }
}
/* families do not leak into each other: a catch-all of one family admits nothing of the other */
static void t_families(void) {
    fresh(false);
    ip_addr_t any4 = v4_addr((const uint8_t[4]){0, 0, 0, 0}), mask4 = v4_mask(0);
    assert(wireguardif_add_allowed_ip(&D.nif, 0, &any4, &mask4) == ERR_OK);     /* 0.0.0.0/0: the exit-node entry */
    uint8_t b[100]; size_t len;
    ip6_packet(b, PEER_V6, 40, 80, 0, 0, 17);
    assert(check(b, 80, true, &len) == WG_INNER_ALLOWED_IP6);                    /* an IPv4 default route is not an IPv6 one */
    ip4_packet(b, OTHER_V4, 60, 60);
    assert(check(b, 60, true, &len) == WG_INNER_OK && len == 60);
    rig_down();
    fresh(false);
    ip_addr_t any6 = v6_addr((const uint8_t[16]){0}), mask6 = v6_mask(0);
    assert(wireguardif_add_allowed_ip(&D.nif, 0, &any6, &mask6) == ERR_OK);     /* ::/0 */
    ip4_packet(b, PEER_V4, 60, 60);
    assert(check(b, 60, true, &len) == WG_INNER_ALLOWED_IP);                     /* ... admits no IPv4 source, whatever the overlay bytes say */
    ip6_packet(b, OTHER_V6, 40, 80, 0, 0, 17);
    assert(check(b, 80, true, &len) == WG_INNER_OK);
    /* an entry of one family with a mask of the other is refused when it is added, never stored */
    ip_addr_t net = v6_addr(PEER_V6), bad_mask = v4_mask(8);
    assert(wireguardif_add_allowed_ip(&D.nif, 0, &net, &bad_mask) == ERR_VAL);
    ip_addr_t net4 = v4_addr(PEER_V4), bad_mask6 = v6_mask(8);
    assert(wireguardif_add_allowed_ip(&D.nif, 0, &net4, &bad_mask6) == ERR_VAL);
    rig_down();
}
static void t_v6_length(void) {
    fresh(true); add_v6(PEER_V6, 128);
    uint8_t b[1600]; size_t len;
    /* the flow label (bytes 1-3) is not a length: 0xfffff there, a Payload Length that fits the bytes -> accepted, exactly 40 + 20 */
    ip6_packet(b, PEER_V6, 20, 100, 0xff, 0xff, 17);
    assert(check(b, 100, true, &len) == WG_INNER_OK && len == 60);
    /* and a tiny flow label with a Payload Length that does NOT fit -> refused (the old code would have read 0x0000 and delivered) */
    ip6_packet(b, PEER_V6, 61, 100, 0, 0, 17);
    assert(check(b, 100, true, &len) == WG_INNER_BAD_LENGTH);
    ip6_packet(b, PEER_V6, 60, 100, 0, 0, 17);
    assert(check(b, 100, true, &len) == WG_INNER_OK && len == 100);
    ip6_packet(b, PEER_V6, 61, 100, 0, 0, 17);
    assert(check(b, 100, true, &len) == WG_INNER_BAD_LENGTH);
    ip6_packet(b, PEER_V6, 0xffff, 100, 0, 0, 17);
    assert(check(b, 100, true, &len) == WG_INNER_BAD_LENGTH);
    /* Payload Length 0: a jumbogram marker or an empty packet; only "no next header" is a valid empty packet */
    ip6_packet(b, PEER_V6, 0, 100, 0, 0, 0);          /* hop-by-hop: a jumbogram */
    assert(check(b, 100, true, &len) == WG_INNER_BAD_LENGTH);
    ip6_packet(b, PEER_V6, 0, 100, 0, 0, 17);
    assert(check(b, 100, true, &len) == WG_INNER_BAD_LENGTH);
    ip6_packet(b, PEER_V6, 0, 100, 0, 0, 59);
    assert(check(b, 100, true, &len) == WG_INNER_OK && len == 40);
    /* the boundary: a header exactly 40 bytes, and one byte short of it */
    ip6_packet(b, PEER_V6, 0, 40, 0, 0, 59);
    assert(check(b, 40, true, &len) == WG_INNER_OK && len == 40);
    for (size_t n = 1; n < 40; n++) { ip6_packet(b, PEER_V6, 0, 64, 0, 0, 59); assert(check(b, n, true, &len) == WG_INNER_BAD_IP); }
    /* exact-size buffer under ASan: the check never reads past `n` */
    for (size_t n = 1; n <= 64; n++) {
        uint8_t *exact = malloc(n); ip6_packet(b, PEER_V6, 24, 64, 0, 0, 17); memcpy(exact, b, n);
        wg_inner_verdict_t v = check(exact, n, true, &len);
        assert(n < 40 ? v == WG_INNER_BAD_IP : (n >= 64 ? v == WG_INNER_OK : v == WG_INNER_BAD_LENGTH));
        free(exact);
    }
    rig_down();
}
static void t_v4_length_and_allowed(void) {
    fresh(true);
    uint8_t b[100]; size_t len;
    ip4_packet(b, PEER_V4, 60, 60); assert(check(b, 60, false, &len) == WG_INNER_OK && len == 60);
    ip4_packet(b, PEER_V4, 40, 64); assert(check(b, 64, false, &len) == WG_INNER_OK && len == 40);       /* padded: trimmed to Total Length */
    ip4_packet(b, PEER_V4, 65, 64); assert(check(b, 64, false, &len) == WG_INNER_BAD_LENGTH);
    ip4_packet(b, PEER_V4, 19, 64); assert(check(b, 64, false, &len) == WG_INNER_BAD_LENGTH);             /* shorter than its own header */
    ip4_packet(b, PEER_V4, 0, 64); assert(check(b, 64, false, &len) == WG_INNER_BAD_LENGTH);
    /* IHL: fewer than 5 words, or a header longer than the packet, is a bad length (the router relies on both bounds) */
    for (unsigned ihl = 0; ihl < 16; ihl++) {
        ip4_packet(b, PEER_V4, 60, 60); b[0] = (uint8_t)(0x40 | ihl);
        assert(check(b, 60, false, &len) == (ihl >= 5 ? WG_INNER_OK : WG_INNER_BAD_LENGTH));
        ip4_packet(b, PEER_V4, 24, 60); b[0] = (uint8_t)(0x40 | ihl);   /* Total Length 24: a header of more than 6 words does not fit */
        assert(check(b, 60, false, &len) == (ihl >= 5 && ihl <= 6 ? WG_INNER_OK : WG_INNER_BAD_LENGTH));
    }
    ip4_packet(b, OTHER_V4, 60, 60); b[0] = 0x40; assert(check(b, 60, false, &len) == WG_INNER_ALLOWED_IP);   /* impersonation outranks IHL */
    ip4_packet(b, OTHER_V4, 60, 60); assert(check(b, 60, false, &len) == WG_INNER_ALLOWED_IP);
    ip4_packet(b, OTHER_V4, 9999, 60); assert(check(b, 60, false, &len) == WG_INNER_ALLOWED_IP);          /* impersonation outranks the length */
    for (size_t n = 0; n < 20; n++) { ip4_packet(b, PEER_V4, 60, 64); assert(check(b, n, false, &len) == (n ? WG_INNER_BAD_IP : WG_INNER_BAD_IP)); }
    rig_down();
}
/* a random fuzz of the whole decision against an independent model */
static void t_fuzz(void) {
    srand(11);
    fresh(true); add_v6(PEER_V6, 120);
    for (int i = 0; i < 200000; i++) {
        uint8_t b[96]; size_t n = (size_t)(rand() % 96);
        for (size_t k = 0; k < sizeof(b); k++) b[k] = (uint8_t)rand();
        switch (rand() % 6) {
        case 0: b[0] = 0x45; memcpy(b + 12, PEER_V4, 4); break;
        case 1: b[0] = 0x60; memcpy(b + 8, PEER_V6, 15); b[23] = (uint8_t)rand(); break;
        case 2: b[0] = 0x60; memcpy(b + 8, PEER_V6, 16); break;
        case 3: b[0] = (uint8_t)(0x40 | (rand() & 0x0f)); if (rand() & 1) memcpy(b + 12, PEER_V4, 4); break;
        default: break;
        }
        if (rand() & 1) { b[4] = 0; b[5] = (uint8_t)(rand() % 64); }
        if (rand() & 1) { b[2] = 0; b[3] = (uint8_t)(rand() % 100); }
        for (int ok6 = 0; ok6 < 2; ok6++) {
            uint8_t *exact = malloc(n ? n : 1); memcpy(exact, b, n);
            size_t len = 0;
            wg_inner_verdict_t v = wireguardif_inner_check(PEER, ok6, exact, n, &len);
            wg_inner_verdict_t want;
            if (n < 1) want = WG_INNER_BAD_IP;
            else if ((exact[0] >> 4) == 4) {
                if (n < 20) want = WG_INNER_BAD_IP;
                else if (memcmp(exact + 12, PEER_V4, 4)) want = WG_INNER_ALLOWED_IP;
                else { size_t total = ((size_t)exact[2] << 8) | exact[3], ihl = (size_t)(exact[0] & 15) * 4;
                       want = (total < 20 || total > n || ihl < 20 || ihl > total) ? WG_INNER_BAD_LENGTH : WG_INNER_OK; if (want == WG_INNER_OK) assert(len == total); }
            } else if ((exact[0] >> 4) == 6) {
                if (n < 40) want = WG_INNER_BAD_IP;
                else if (!model_match(PEER_V6, 120, exact + 8)) want = WG_INNER_ALLOWED_IP6;
                else {
                    size_t payload = ((size_t)exact[4] << 8) | exact[5];
                    if (40 + payload > n || (payload == 0 && exact[6] != 59)) want = WG_INNER_BAD_LENGTH;
                    else if (!ok6) want = WG_INNER_IPV6_UNSUPPORTED;
                    else { want = WG_INNER_OK; assert(len == 40 + payload); }
                }
            } else want = WG_INNER_BAD_IP;
            if (v != want) { fprintf(stderr, "fuzz %d: verdict %d, model %d (n=%zu b0=%02x)\n", i, v, want, n, exact[0]); abort(); }
            free(exact);
        }
    }
    rig_down();
}

/* ---- through the real receive path, every path, with the counters ---- */
static void t_pipeline(int path) {
    fresh(true); add_v6(PEER_V6, 128);
    uint8_t b[1700];
    /* impersonation: authenticated, source not allowed -> rx_allowed_ip, nothing delivered, whatever the length field says */
    ip6_packet(b, OTHER_V6, 40, 80, 0, 0, 17);
    snap(); deliver(b, 80, 96, path); EXPECT_ONLY(rx_allowed_ip6);
    ip6_packet(b, OTHER_V6, 9000, 80, 0xff, 0xff, 17);
    snap(); deliver(b, 80, 96, path); EXPECT_ONLY(rx_allowed_ip6);
    ip4_packet(b, OTHER_V4, 60, 60);
    snap(); deliver(b, 60, 64, path); EXPECT_ONLY(rx_allowed_ip);
    /* a spoofed IPv6 source that equals the peer's IPv4 allowed bytes in the overlay position (bytes 0-3 of the v6 address) */
    uint8_t spoof[16] = {10, 1, 0, 1};
    ip6_packet(b, spoof, 40, 80, 0, 0, 17);
    snap(); deliver(b, 80, 96, path); EXPECT_ONLY(rx_allowed_ip6);
    /* allowed source, malformed */
    ip6_packet(b, PEER_V6, 41, 80, 0, 0, 17);                     /* claims 81 bytes, 80 sent and no padding */
    snap(); deliver(b, 80, 0, path); EXPECT_ONLY(rx_bad_length);
    ip6_packet(b, PEER_V6, 57, 80, 0, 0, 17);                     /* claims 97 bytes: more than the 96 decrypted including the padding */
    snap(); deliver(b, 80, 96, path); EXPECT_ONLY(rx_bad_length);
    ip6_packet(b, PEER_V6, 0, 80, 0, 0, 17);
    snap(); deliver(b, 80, 96, path); EXPECT_ONLY(rx_bad_length);
    ip6_packet(b, PEER_V6, 0, 39, 0, 0, 59);
    snap(); deliver(b, 39, 0, path); EXPECT_ONLY(rx_bad_ip);        /* one byte short of an IPv6 header (an unpadded plaintext: the peer chooses) */
    assert(input_calls == 0);
}

/* an allowed, well formed IPv6 packet: dropped and counted while the interface does not deliver IPv6 (the gateway: README),
 * delivered, trimmed to 40 + Payload Length, once it is told to */
static void t_v6_delivery_policy(int path) {
    fresh(true); add_v6(PEER_V6, 128);
    uint8_t b[1700];
    ip6_packet(b, PEER_V6, 60, 100, 0, 0, 17);
    snap(); deliver(b, 100, 112, path); EXPECT_ONLY(rx_ipv6_unsupported);
    assert(input_calls == 0 && wg_host_pbuf_live == 0);
    wireguardif_set_rx_ipv6(&D.nif, true);
    snap(); deliver(b, 100, 112, path); EXPECT_ONLY(rx_delivered);
    assert(input_calls == 1 && last_input_len == 100 && !memcmp(last_input, b, 100));
    /* the Payload Length shorter than the buffer: only 40 + 20 bytes are the packet, the rest is padding and is not passed on */
    ip6_packet(b, PEER_V6, 20, 100, 0xab, 0xcd, 17);
    snap(); deliver(b, 100, 112, path); EXPECT_ONLY(rx_delivered);
    assert(last_input_len == 60 && !memcmp(last_input, b, 60));
    /* an IPv4 packet from the IPv4 entry is unaffected by the IPv6 policy, and trimmed too */
    ip4_packet(b, PEER_V4, 44, 64);
    snap(); deliver(b, 64, 64, path); EXPECT_ONLY(rx_delivered);
    assert(last_input_len == 44 && !memcmp(last_input, b, 44));
    wireguardif_set_rx_ipv6(&D.nif, false);
    ip6_packet(b, PEER_V6, 60, 100, 0, 0, 17);
    snap(); deliver(b, 100, 112, path); EXPECT_ONLY(rx_ipv6_unsupported);
    assert(wg_host_pbuf_live == 0);
    rig_down();
}
/* a peer with ONLY an IPv4 entry can never get an IPv6 packet through, even with IPv6 delivery on (the attack in the report) */
static void t_v4_only_peer_cannot_send_v6(int path) {
    fresh(true);
    wireguardif_set_rx_ipv6(&D.nif, true);
    uint8_t b[1700];
    for (int i = 0; i < 64; i++) {
        uint8_t src[16]; for (int k = 0; k < 16; k++) src[k] = (uint8_t)(i * 17 + k * 3);
        if (i & 1) { memcpy(src, PEER_V4, 4); }
        ip6_packet(b, src, 40, 80 + (size_t)i, (uint8_t)i, (uint8_t)(i * 5), 17);
        snap(); deliver(b, 80 + (size_t)i, 0, path); EXPECT_ONLY(rx_allowed_ip6);
    }
    assert(input_calls == 0 && wg_host_pbuf_live == 0);
    rig_down();
}

int main(void) {
    t_v6_source_in_allowed();
    t_v6_prefixes();
    t_families();
    t_v6_length();
    t_v4_length_and_allowed();
    t_fuzz();
    for (int path = 0; path < PATHS; path++) {
        t_pipeline(path);
        t_v6_delivery_policy(path);
        t_v4_only_peer_cannot_send_v6(path);
    }
    printf("ipv6 cryptokey routing ok\n");
    return 0;
}
