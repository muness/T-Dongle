/* Egress equivalence on the REAL wireguardif.c (host fakes for lwIP): wireguardif_output_prepared() seals a datagram the
 * caller laid out in place; it must produce exactly the datagram, counters, timestamps, rekey flags and result codes of the
 * copying wireguardif_output(), over every length around the 16-byte padding boundary and every keypair state, and it must
 * hand the SAME pbuf to the UDP/DERP callback (no copy). The zero-copy callbacks must see the bytes the copying
 * callbacks see.
 *
 *   wg=components/microlink/components/wireguard_lwip/src
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -w -DWIREGUARD_CRYPTO_REFC=1 \
 *      -I tests/host/wg_lwip -I tests/host_esp -I $wg -I $wg/crypto -I $wg/crypto/refc tests/test_wg_egress.c \
 *      tests/host/wg_lwip/wg_host_lwip.c $wg/wireguard.c $wg/wireguardif.c $wg/wireguard_pool.c $wg/crypto.c \
 *      $wg/crypto/refc/{blake2s,chacha20,chacha20poly1305,poly1305-donna,x25519}.c -o build-host/test_wg_egress */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wireguard.h"
#include "wireguardif.h"
#include "chacha20poly1305.h"

static uint32_t g_now = 100000;
uint32_t wireguard_sys_now(void) { return g_now; }
void wireguard_tai64n_now(uint8_t *out) { memset(out, 0, 12); out[7] = 1; }
bool wireguard_is_under_load(void) { return false; }
void wireguard_set_tai64n_base_seconds(uint64_t s) { (void)s; }
void wireguard_random_bytes(void *bytes, size_t size) { memset(bytes, 0x42, size); }

#define MAXD 2048
typedef struct { uint8_t data[MAXD]; size_t len; uint32_t ip; uint16_t port; const void *payload_ptr; unsigned calls; int kind; } sent_t;
static sent_t sent;            /* the last datagram a callback saw */
static err_t cb_result;
static err_t copy_cb(uint32_t ip, uint16_t port, const uint8_t *data, size_t len, void *ctx) {
    (void)ctx; assert(len <= MAXD); memcpy(sent.data, data, len); sent.len = len; sent.ip = ip; sent.port = port; sent.kind = 1; sent.calls++;
    return cb_result;
}
static struct pbuf *last_pbuf;
static err_t pbuf_cb(uint32_t ip, uint16_t port, struct pbuf *p, void *ctx) {
    (void)ctx; assert(p->next == NULL && p->tot_len <= MAXD);
    memcpy(sent.data, p->payload, p->tot_len); sent.len = p->tot_len; sent.ip = ip; sent.port = port; sent.kind = 2; sent.calls++;
    sent.payload_ptr = p->payload; last_pbuf = p;
    return cb_result;
}
static err_t derp_cb(const uint8_t *key, const uint8_t *data, size_t len, void *ctx) {
    (void)key; (void)ctx; assert(len <= MAXD); memcpy(sent.data, data, len); sent.len = len; sent.kind = 3; sent.calls++;
    sent.payload_ptr = data;
    return cb_result;
}

struct dev { struct netif nif; struct wireguardif_init_data init; char key_b64[64]; };
static void dev_up(struct dev *d) {
    uint8_t key[32]; size_t n = 64;
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1);
    assert(wireguard_base64_encode(key, 32, d->key_b64, &n));
    memset(&d->nif, 0, sizeof(d->nif));
    d->init.private_key = d->key_b64; d->init.listen_port = 51820; d->init.bind_netif = NULL;
    d->nif.state = &d->init;
    assert(wireguardif_init(&d->nif) == ERR_OK);
}
#define PEER_IP 0x0100010au      /* network-order bytes 10.1.0.1, as add_peer's allowed ip */
static struct wireguard_peer *dev_peer(struct dev *d) {
    uint8_t pk[32], idx; char s[64]; size_t n = 64; struct wireguardif_peer p;
    for (int i = 0; i < 32; i++) pk[i] = (uint8_t)(i + 5);
    pk[31] &= 0x7f;
    assert(wireguard_base64_encode(pk, 32, s, &n));
    wireguardif_peer_init(&p);
    p.public_key = s; p.allowed_ip.addr = PEER_IP; p.allowed_mask.addr = 0xffffffff;
    assert(wireguardif_add_peer(&d->nif, &p, &idx) == ERR_OK);
    return wireguard_device_peer((struct wireguard_device *)d->nif.state, idx);
}
static void set_keys(struct wireguard_keypair *k, bool initiator, uint32_t last_rx, uint64_t counter) {
    memset(k, 0, sizeof(*k));
    k->valid = true; k->initiator = initiator; k->keypair_millis = g_now; k->last_rx = last_rx;
    k->sending_valid = true; k->sending_counter = counter; k->remote_index = 0x11223344;
    for (int i = 0; i < 32; i++) k->sending_key[i] = (uint8_t)(0xA0 + i);
}
static void set_endpoint(struct wireguard_peer *p, bool direct) {
    memset(&p->ip, 0, sizeof(p->ip));
    if (direct) { p->ip.addr = 0x0400a8c0u; p->port = 41641; } else p->port = 0;
}

/* The caller's side of the contract: build [16 B header space][plaintext][zero padding][16 B tag space]. */
static struct pbuf *prepare(const uint8_t *plain, size_t n) {
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, WIREGUARDIF_DATA_ALLOC(n), PBUF_RAM);
    assert(p && p->tot_len == WIREGUARDIF_DATA_ALLOC(n));
    memset(p->payload, 0, p->tot_len);
    memcpy((uint8_t *)p->payload + WIREGUARDIF_DATA_HDR, plain, n);
    return p;
}
static void plaintext(uint8_t *b, size_t n, unsigned seed) { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(i * 31 + seed); }

typedef struct { struct dev d; struct wireguard_peer *peer; } rig_t;
static void rig_up(rig_t *r) { dev_up(&r->d); r->peer = dev_peer(&r->d); }
static void rig_down(rig_t *r) { wireguardif_free(&r->d.nif); }
static ip4_addr_t dest(void) { ip4_addr_t a = {.addr = PEER_IP}; return a; }

/* One datagram through the copying path and one through the prepared path, on two identical rigs. */
static void compare(size_t n, bool initiator, uint32_t last_rx, uint64_t counter, bool direct, int cb_kind) {
    rig_t a, b; rig_up(&a); rig_up(&b);
    set_keys(&a.peer->curr_keypair, initiator, last_rx, counter); set_keys(&b.peer->curr_keypair, initiator, last_rx, counter);
    set_endpoint(a.peer, direct); set_endpoint(b.peer, direct);
    wireguardif_set_udp_output(&a.d.nif, copy_cb, NULL); wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
    wireguardif_set_derp_output(&a.d.nif, derp_cb, NULL); wireguardif_set_derp_output(&b.d.nif, derp_cb, NULL);
    if (cb_kind == 2) wireguardif_set_udp_output_pbuf(&b.d.nif, pbuf_cb);
    uint8_t plain[1400]; plaintext(plain, n, (unsigned)n);
    ip4_addr_t ip = dest();
    struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM); pbuf_take(q, plain, (u16_t)n);
    sent.calls = 0; g_now += 5;
    err_t ra = a.d.nif.output(&a.d.nif, q, &ip);
    assert(sent.calls == 1 || ra != ERR_OK);
    sent_t old = sent; sent.calls = 0;
    struct pbuf *w = prepare(plain, n);
    err_t rb = wireguardif_output_prepared(&b.d.nif, w, (uint16_t)n, &ip);
    assert(ra == rb);
    if (ra == ERR_OK) {
        assert(sent.calls == 1 && sent.len == old.len && !memcmp(sent.data, old.data, old.len));
        if (cb_kind == 2 && direct) assert(sent.kind == 2 && sent.payload_ptr == w->payload && last_pbuf == w);   /* no copy */
        if (!direct) assert(sent.kind == 3 && sent.payload_ptr == w->payload);                                /* DERP: the payload itself */
        if (cb_kind == 1 && direct) assert(sent.kind == 1);
        assert(sent.len == WIREGUARDIF_DATA_ALLOC(n));
        /* the receiver can open it */
        uint8_t out[1424]; size_t padded = WIREGUARDIF_DATA_PAD(n);
        assert(chacha20poly1305_decrypt(out, sent.data + 16, padded + 16, NULL, 0, counter, b.peer->curr_keypair.sending_key));
        assert(!memcmp(out, plain, n));
        for (size_t i = n; i < padded; i++) assert(out[i] == 0);
        /* the datagram header */
        assert(sent.data[0] == 4 && !sent.data[1] && !sent.data[2] && !sent.data[3]);
    }
    /* identical side effects on the peers */
    struct wireguard_keypair *ka = &a.peer->curr_keypair, *kb = &b.peer->curr_keypair;
    assert(ka->sending_counter == kb->sending_counter && ka->last_tx == kb->last_tx && ka->valid == kb->valid);
    assert(a.peer->last_tx == b.peer->last_tx && a.peer->send_handshake == b.peer->send_handshake);
    assert(a.peer->active == b.peer->active && a.peer->handshake_attempts == b.peer->handshake_attempts);
    assert(a.peer->curr_keypair.valid == b.peer->curr_keypair.valid && a.peer->prev_keypair.valid == b.peer->prev_keypair.valid);
    pbuf_free(q); pbuf_free(w); rig_down(&a); rig_down(&b);
}

#include <time.h>
/* `test_wg_egress bench`: the same datagram sealed through the copying path (what wireguardif_output did, plus the callback's
 * linearising copy) and through the prepared path, N times. Host numbers (an Apple-silicon laptop, -O1 here, the heap of
 * a desktop): read the ratio, not the nanoseconds; the board's costs are in `wgperf`. */
static double now_s(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
static err_t sink_copy(uint32_t ip, uint16_t port, const uint8_t *d, size_t n, void *c) { (void)ip; (void)port; (void)c; sent.len = n; return d[0] == 4 ? ERR_OK : ERR_VAL; }
static err_t sink_pbuf(uint32_t ip, uint16_t port, struct pbuf *p, void *c) { (void)ip; (void)port; (void)c; sent.len = p->tot_len; return ERR_OK; }
static int bench(void) {
    enum { N = 200000 };
    rig_t a, b; rig_up(&a); rig_up(&b);
    set_keys(&a.peer->curr_keypair, true, 0, 1); set_keys(&b.peer->curr_keypair, true, 0, 1);
    set_endpoint(a.peer, true); set_endpoint(b.peer, true);
    wireguardif_set_udp_output(&a.d.nif, sink_copy, NULL);
    wireguardif_set_udp_output(&b.d.nif, sink_copy, NULL); wireguardif_set_udp_output_pbuf(&b.d.nif, sink_pbuf);
    static const size_t sizes[] = {64, 1400};
    ip4_addr_t ip = dest();
    for (unsigned k = 0; k < 2; k++) {
        size_t n = sizes[k]; uint8_t plain[1400]; plaintext(plain, n, 1);
        double t0 = now_s();
        for (int i = 0; i < N; i++) {
            /* before: pbuf from the queue copy, then output copies again (transport pbuf), then the linearising buffer in peer_output */
            struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM); pbuf_take(q, plain, (u16_t)n);
            uint8_t *stage = malloc(n + 600); memcpy(stage, plain, n);              /* the calloc'd queue block copy */
            a.d.nif.output(&a.d.nif, q, &ip);
            free(stage); pbuf_free(q);
        }
        double t1 = now_s();
        for (int i = 0; i < N; i++) {
            struct pbuf *w = prepare(plain, n);
            wireguardif_output_prepared(&b.d.nif, w, (uint16_t)n, &ip);
            pbuf_free(w);
        }
        double t2 = now_s();
        printf("%4zu B: copying path %6.0f ns/pkt   in-place path %6.0f ns/pkt   (%.2fx; both include the same ChaCha20-Poly1305)\n",
               n, (t1 - t0) / N * 1e9, (t2 - t1) / N * 1e9, (t1 - t0) / (t2 - t1));
    }
    rig_down(&a); rig_down(&b);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "bench")) return bench();
    static const size_t lens[] = {1, 2, 15, 16, 17, 31, 32, 33, 100, 1399, 1400};
    for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        compare(lens[i], true, 0, 7, true, 1);       /* initiator, direct UDP, copying callback */
        compare(lens[i], true, 0, 7, true, 2);       /* ... zero-copy callback */
        compare(lens[i], false, 3, 123456789, true, 2);   /* responder that has received data */
        compare(lens[i], true, 0, 7, false, 2);      /* no endpoint: DERP */
    }
    cb_result = ERR_MEM;                             /* the send fails: same result, last_tx untouched */
    compare(100, true, 0, 7, true, 2);
    cb_result = ERR_OK;

    /* keypair states: none, responder that never received (falls to prev, which is invalid), expired, exhausted */
    {
        rig_t a, b; rig_up(&a); rig_up(&b);
        ip4_addr_t ip = dest(); uint8_t plain[64]; plaintext(plain, 64, 1);
        struct pbuf *w = prepare(plain, 64);
        struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, 64, PBUF_RAM); pbuf_take(q, plain, 64);
        a.peer->active = b.peer->active = false; a.peer->handshake_attempts = b.peer->handshake_attempts = 99;
        assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_CONN);
        assert(wireguardif_output_prepared(&b.d.nif, w, 64, &ip) == ERR_CONN);
        assert(a.peer->active && b.peer->active && !a.peer->handshake_attempts && !b.peer->handshake_attempts && !a.peer->last_initiation_tx && !b.peer->last_initiation_tx);   /* lazy handshake armed alike */
        set_keys(&a.peer->curr_keypair, false, 0, 1); set_keys(&b.peer->curr_keypair, false, 0, 1);   /* responder, nothing received */
        assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_CONN && wireguardif_output_prepared(&b.d.nif, w, 64, &ip) == ERR_CONN);
        g_now += 181000;                                                                             /* REJECT_AFTER_TIME */
        set_keys(&a.peer->curr_keypair, true, 0, 1); set_keys(&b.peer->curr_keypair, true, 0, 1);
        g_now += 181000;
        assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_CONN && wireguardif_output_prepared(&b.d.nif, w, 64, &ip) == ERR_CONN);
        assert(!a.peer->curr_keypair.valid && !b.peer->curr_keypair.valid);                          /* destroyed alike */
        set_keys(&a.peer->curr_keypair, true, 0, REJECT_AFTER_MESSAGES); set_keys(&b.peer->curr_keypair, true, 0, REJECT_AFTER_MESSAGES);
        assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_CONN && wireguardif_output_prepared(&b.d.nif, w, 64, &ip) == ERR_CONN);
        assert(!a.peer->curr_keypair.valid && !b.peer->curr_keypair.valid);
        /* a destination no peer owns */
        ip4_addr_t other = {.addr = 0x0900000au};
        assert(a.d.nif.output(&a.d.nif, q, &other) == ERR_RTE && wireguardif_output_prepared(&b.d.nif, w, 64, &other) == ERR_RTE);
        /* rekey flag: counter at the threshold, and an initiator keypair older than REKEY_AFTER_TIME */
        set_keys(&a.peer->curr_keypair, true, 0, REKEY_AFTER_MESSAGES); set_keys(&b.peer->curr_keypair, true, 0, REKEY_AFTER_MESSAGES);
        set_endpoint(a.peer, true); set_endpoint(b.peer, true);
        wireguardif_set_udp_output(&a.d.nif, copy_cb, NULL); wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
        assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_OK && wireguardif_output_prepared(&b.d.nif, w, 64, &ip) == ERR_OK);
        assert(a.peer->send_handshake && b.peer->send_handshake);
        a.peer->send_handshake = b.peer->send_handshake = false;
        set_keys(&a.peer->curr_keypair, true, 0, 1); set_keys(&b.peer->curr_keypair, true, 0, 1);
        a.peer->curr_keypair.keypair_millis = b.peer->curr_keypair.keypair_millis = g_now - 125000;   /* past REKEY_AFTER_TIME (120 s) */
        assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_OK && wireguardif_output_prepared(&b.d.nif, w, 64, &ip) == ERR_OK);
        assert(a.peer->send_handshake && b.peer->send_handshake);
        pbuf_free(q); pbuf_free(w); rig_down(&a); rig_down(&b);
    }

    /* keep-alive (no plaintext) still goes through the copying path and is a valid empty datagram */
    {
        rig_t a; rig_up(&a);
        set_keys(&a.peer->curr_keypair, true, 0, 9); set_endpoint(a.peer, true);
        wireguardif_set_udp_output(&a.d.nif, copy_cb, NULL); wireguardif_set_udp_output_pbuf(&a.d.nif, pbuf_cb);
        sent.calls = 0;
        a.d.nif.output(&a.d.nif, NULL, &(ip4_addr_t){.addr = PEER_IP});    /* lwIP never calls this with q NULL; keepalives do via the peer */
        rig_down(&a);
    }
    puts("wg egress: prepared in-place output equals the copying output (bytes, counters, timestamps, rekey flags, results); zero-copy callbacks see the same pbuf");
    return 0;
}
