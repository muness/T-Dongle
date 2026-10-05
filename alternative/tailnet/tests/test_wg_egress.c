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
#include <unistd.h>
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


/* ---- split form: begin (lock) / seal (no lock) / commit (lock) ---- */
static err_t split_send(struct netif *nif, struct pbuf *w, size_t n, ip4_addr_t *ip, struct wireguard_tx_job *out_job, void (*between)(void *), void *arg) {
    struct wireguard_tx_job job; err_t r;
    if (!wireguardif_tx_begin(nif, w, (uint16_t)n, ip, &job, &r)) return r;
    if (between) between(arg);
    wireguard_tx_seal(&job);
    if (out_job) *out_job = job;
    return wireguardif_tx_commit(nif, &job);
}
static void roll_keys(void *arg) {   /* what the lwIP receive path does under the lock while a seal is running */
    struct wireguard_peer *p = arg;
    p->prev_keypair = p->curr_keypair;
    memset(&p->curr_keypair, 0, sizeof(p->curr_keypair));
    p->curr_keypair.valid = true; p->curr_keypair.initiator = false; p->curr_keypair.last_rx = g_now; p->curr_keypair.sending_counter = 5000;
    p->curr_keypair.remote_index = 0x55667788; memset(p->curr_keypair.sending_key, 0xEE, 32);
}
static void destroy_keys(void *arg) {
    struct wireguard_peer *p = arg;
    memset(&p->curr_keypair, 0, sizeof(p->curr_keypair)); memset(&p->prev_keypair, 0, sizeof(p->prev_keypair));
}
static void unplug_peer(void *arg) { struct dev *d = arg; wireguardif_remove_peer(&d->nif, 0); }

static void split_tests(void) {
    ip4_addr_t ip = dest();
    /* 1. a run of packets: the counter advances by one per packet, the datagrams equal the copying path's, each opens with its own nonce */
    for (int dir = 0; dir < 2; dir++) {
        rig_t a, b; rig_up(&a); rig_up(&b);
        set_keys(&a.peer->curr_keypair, true, 0, 41); set_keys(&b.peer->curr_keypair, true, 0, 41);
        set_endpoint(a.peer, dir == 0); set_endpoint(b.peer, dir == 0);
        wireguardif_set_udp_output(&a.d.nif, copy_cb, NULL); wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
        wireguardif_set_derp_output(&a.d.nif, derp_cb, NULL); wireguardif_set_derp_output(&b.d.nif, derp_cb, NULL);
        for (unsigned i = 0; i < 40; i++) {
            size_t n = 1 + (i * 37) % 1400; uint8_t plain[1400]; plaintext(plain, n, i);
            struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM); pbuf_take(q, plain, (u16_t)n);
            g_now += 3; sent.calls = 0;
            assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_OK); sent_t old = sent; sent.calls = 0;
            struct pbuf *w = prepare(plain, n);
            assert(split_send(&b.d.nif, w, n, &ip, NULL, NULL, NULL) == ERR_OK);
            assert(sent.calls == 1 && sent.len == old.len && !memcmp(sent.data, old.data, old.len));
            assert(b.peer->curr_keypair.sending_counter == 42 + i && a.peer->curr_keypair.sending_counter == 42 + i);
            assert(b.peer->curr_keypair.last_tx == a.peer->curr_keypair.last_tx && b.peer->last_tx == a.peer->last_tx);
            uint8_t out[1424]; size_t padded = WIREGUARDIF_DATA_PAD(n);
            assert(chacha20poly1305_decrypt(out, sent.data + 16, padded + 16, NULL, 0, 41 + i, b.peer->curr_keypair.sending_key));
            assert(!memcmp(out, plain, n));
            uint64_t c = 0; for (int k = 7; k >= 0; k--) c = (c << 8) | sent.data[8 + k];
            assert(c == 41 + i);                                   /* the counter field of the header */
            pbuf_free(q); pbuf_free(w);
        }
        rig_down(&a); rig_down(&b);
    }
    /* 2. responder whose current keypair has not received yet sends with prev; the split form chooses the same */
    {
        rig_t a, b; rig_up(&a); rig_up(&b);
        for (rig_t *r = &a; r; r = (r == &a) ? &b : NULL) {
            set_keys(&r->peer->curr_keypair, false, 0, 1);               /* responder, nothing received */
            set_keys(&r->peer->prev_keypair, true, 0, 900); r->peer->prev_keypair.remote_index = 0x99aabbcc;
            set_endpoint(r->peer, true); wireguardif_set_udp_output(&r->d.nif, copy_cb, NULL);
        }
        uint8_t plain[50]; plaintext(plain, 50, 3);
        struct pbuf *q = pbuf_alloc(PBUF_TRANSPORT, 50, PBUF_RAM); pbuf_take(q, plain, 50);
        sent.calls = 0; assert(a.d.nif.output(&a.d.nif, q, &ip) == ERR_OK); sent_t old = sent; sent.calls = 0;
        struct pbuf *w = prepare(plain, 50);
        assert(split_send(&b.d.nif, w, 50, &ip, NULL, NULL, NULL) == ERR_OK);
        assert(sent.len == old.len && !memcmp(sent.data, old.data, old.len));
        assert(b.peer->prev_keypair.sending_counter == 901 && b.peer->curr_keypair.sending_counter == 1);
        assert(b.peer->prev_keypair.last_tx == a.peer->prev_keypair.last_tx && b.peer->prev_keypair.last_tx == g_now);
        pbuf_free(q); pbuf_free(w); rig_down(&a); rig_down(&b);
    }
    /* 3. keep-alive shaped packet (no plaintext): 32 bytes, an empty AEAD that opens */
    {
        rig_t b; rig_up(&b); set_keys(&b.peer->curr_keypair, true, 0, 9); set_endpoint(b.peer, true);
        wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
        struct pbuf *w = prepare((const uint8_t *)"", 0); sent.calls = 0;
        assert(w->tot_len == 32 && split_send(&b.d.nif, w, 0, &ip, NULL, NULL, NULL) == ERR_OK);
        uint8_t out[16];
        assert(sent.len == 32 && sent.data[0] == 4 && chacha20poly1305_decrypt(out, sent.data + 16, 16, NULL, 0, 9, b.peer->curr_keypair.sending_key));
        pbuf_free(w); rig_down(&b);
    }
    /* 4. the keypair changes between begin and commit: the datagram is already sealed with the key it reserved; the nonce is
     *    used once; the timestamp goes to the keypair that now carries that remote index, and not to a stranger */
    {
        rig_t b; rig_up(&b); set_keys(&b.peer->curr_keypair, true, 0, 100); set_endpoint(b.peer, true);
        wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
        uint8_t plain[200]; plaintext(plain, 200, 9); uint8_t oldkey[32]; memcpy(oldkey, b.peer->curr_keypair.sending_key, 32);
        struct pbuf *w = prepare(plain, 200); sent.calls = 0; g_now += 9;
        assert(split_send(&b.d.nif, w, 200, &ip, NULL, roll_keys, b.peer) == ERR_OK);
        uint8_t out[224];
        assert(chacha20poly1305_decrypt(out, sent.data + 16, 208 + 16, NULL, 0, 100, oldkey) && !memcmp(out, plain, 200));
        assert(sent.data[4] == 0x44 && sent.data[5] == 0x33 && sent.data[6] == 0x22 && sent.data[7] == 0x11);   /* the old remote index */
        assert(b.peer->prev_keypair.sending_counter == 101);                           /* reserved once, now the previous keypair */
        assert(b.peer->prev_keypair.last_tx == g_now);                                 /* found by remote index after the roll */
        assert(b.peer->curr_keypair.last_tx == 0 && b.peer->curr_keypair.sending_counter == 5000);   /* the new keypair is untouched */
        pbuf_free(w);
        /* destroyed between: still sent (sealed), no timestamp on a keypair that is gone */
        set_keys(&b.peer->curr_keypair, true, 0, 7); w = prepare(plain, 200); sent.calls = 0;
        assert(split_send(&b.d.nif, w, 200, &ip, NULL, destroy_keys, b.peer) == ERR_OK && sent.calls == 1);
        assert(!chacha20poly1305_decrypt(out, sent.data + 16, 208 + 16, NULL, 0, 7, (const uint8_t[32]){0}));   /* not sealed with a zeroed key */
        pbuf_free(w); rig_down(&b);
    }
    /* 5. the peer is removed between begin and commit: dropped, ERR_RTE, nothing sent, the pbuf is still the caller's */
    {
        rig_t b; rig_up(&b); set_keys(&b.peer->curr_keypair, true, 0, 1); set_endpoint(b.peer, true);
        wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
        uint8_t plain[20]; plaintext(plain, 20, 1); struct pbuf *w = prepare(plain, 20); sent.calls = 0;
        assert(split_send(&b.d.nif, w, 20, &ip, NULL, unplug_peer, &b.d) == ERR_RTE && sent.calls == 0);
        pbuf_free(w); rig_down(&b);
    }
    /* 6. a pbuf shorter than the layout needs, or chained, is refused before anything is written or reserved */
    {
        rig_t b; rig_up(&b); set_keys(&b.peer->curr_keypair, true, 0, 1); set_endpoint(b.peer, true);
        wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
        struct pbuf *w = pbuf_alloc(PBUF_TRANSPORT, WIREGUARDIF_DATA_ALLOC(64) - 1, PBUF_RAM); memset(w->payload, 0xCC, w->tot_len);
        struct wireguard_tx_job job; err_t r;
        assert(!wireguardif_tx_begin(&b.d.nif, w, 64, &ip, &job, &r) && r == ERR_ARG);
        assert(b.peer->curr_keypair.sending_counter == 1 && ((uint8_t *)w->payload)[0] == 0xCC);
        assert(!wireguardif_tx_begin(&b.d.nif, NULL, 64, &ip, &job, &r) && r == ERR_ARG);
        pbuf_free(w); rig_down(&b);
    }
    /* 7. begin with no usable keypair has the copying path's side effects (lazy handshake armed) and reserves nothing */
    {
        rig_t b; rig_up(&b); b.peer->active = false;
        struct pbuf *w = prepare((const uint8_t *)"x", 1); struct wireguard_tx_job job; err_t r;
        assert(!wireguardif_tx_begin(&b.d.nif, w, 1, &ip, &job, &r) && r == ERR_CONN && b.peer->active);
        pbuf_free(w); rig_down(&b);
    }
}

/* `test_wg_egress race` (built with -fsanitize=thread): the egress task seals outside a mutex standing for the lwIP core lock
 * while a "tcpip" thread rolls, destroys and replaces keypairs and sends its own datagrams from the same keypair under that
 * mutex. TSan finds any read or write of shared peer state outside the lock; and every datagram that reached the wire must
 * open with the key of its receiver index, with no (receiver index, nonce) pair used twice. */
#include <pthread.h>
static pthread_mutex_t core = PTHREAD_MUTEX_INITIALIZER;
static int race_stop;
static struct { uint32_t idx; uint64_t ctr; } seen_pairs[200000]; static unsigned n_seen;
static uint8_t key_of(uint32_t idx, int i) { return (uint8_t)(idx * 7 + i); }
static err_t race_cb(uint32_t ip, uint16_t port, const uint8_t *data, size_t len, void *ctx) {   /* runs under `core` (from commit) */
    (void)ip; (void)port; (void)ctx;
    uint32_t idx = data[4] | data[5] << 8 | data[6] << 16 | (uint32_t)data[7] << 24;
    uint64_t c = 0; for (int k = 7; k >= 0; k--) c = (c << 8) | data[8 + k];
    uint8_t key[32], out[1424]; for (int i = 0; i < 32; i++) key[i] = key_of(idx, i);
    assert(chacha20poly1305_decrypt(out, data + 16, len - 16, NULL, 0, c, key));
    assert(n_seen < 200000); seen_pairs[n_seen].idx = idx; seen_pairs[n_seen].ctr = c; n_seen++;
    return ERR_OK;
}
static void race_keys(struct wireguard_keypair *k, uint32_t idx, uint64_t ctr) {
    memset(k, 0, sizeof(*k)); k->valid = true; k->initiator = true; k->keypair_millis = g_now; k->sending_valid = true;
    k->sending_counter = ctr; k->remote_index = idx; for (int i = 0; i < 32; i++) k->sending_key[i] = key_of(idx, i);
}
static void *tcpip_thread(void *arg) {
    struct wireguard_peer *peer = arg; uint32_t gen = 1000;
    while (!__atomic_load_n(&race_stop, __ATOMIC_ACQUIRE)) {
        pthread_mutex_lock(&core);
        switch (gen % 4) {
        case 0: peer->prev_keypair = peer->curr_keypair; race_keys(&peer->curr_keypair, ++gen * 3, 0); gen--; break;   /* roll */
        case 1: { uint8_t buf[48]; memset(buf, 0, 48); if (peer->curr_keypair.valid) {        /* its own keepalive-like seal */
                    uint8_t *hdr = buf; hdr[0] = 4; hdr[4] = peer->curr_keypair.remote_index; hdr[5] = peer->curr_keypair.remote_index >> 8;
                    hdr[6] = peer->curr_keypair.remote_index >> 16; hdr[7] = peer->curr_keypair.remote_index >> 24;
                    uint64_t c = peer->curr_keypair.sending_counter;
                    for (int k = 0; k < 8; k++) hdr[8 + k] = (uint8_t)(c >> (8 * k));
                    wireguard_encrypt_packet(buf + 16, buf + 16, 16, &peer->curr_keypair);
                    race_cb(0, 0, buf, 48, NULL); } } break;
        case 2: memset(&peer->prev_keypair, 0, sizeof(peer->prev_keypair)); break;
        default: peer->curr_keypair.last_rx = g_now; break;
        }
        gen++;
        pthread_mutex_unlock(&core);
        usleep(20);
    }
    return NULL;
}
static int race(void) {
    rig_t b; rig_up(&b); race_keys(&b.peer->curr_keypair, 3, 0); set_endpoint(b.peer, true);
    wireguardif_set_udp_output(&b.d.nif, copy_cb, NULL);
    b.d.init.listen_port = 0;
    struct wireguard_device *dev = (struct wireguard_device *)b.d.nif.state; dev->udp_output_fn = race_cb;
    pthread_t th; pthread_create(&th, NULL, tcpip_thread, b.peer);
    ip4_addr_t ip = dest(); unsigned sent_n = 0;
    for (unsigned i = 0; i < 20000; i++) {
        size_t n = 1 + (i * 53) % 1400; uint8_t plain[1400]; plaintext(plain, n, i);
        struct pbuf *w = prepare(plain, n); struct wireguard_tx_job job; err_t r;
        pthread_mutex_lock(&core); int go = wireguardif_tx_begin(&b.d.nif, w, (uint16_t)n, &ip, &job, &r); pthread_mutex_unlock(&core);
        if (go) {
            wireguard_tx_seal(&job);                                                   /* no lock */
            pthread_mutex_lock(&core); r = wireguardif_tx_commit(&b.d.nif, &job); pthread_mutex_unlock(&core);
            if (r == ERR_OK) sent_n++;
        }
        pbuf_free(w);
    }
    __atomic_store_n(&race_stop, 1, __ATOMIC_RELEASE); pthread_join(th, NULL);
    /* nonce uniqueness per receiver index */
    for (unsigned i = 0; i < n_seen; i++) for (unsigned j = i + 1; j < n_seen && j < i + 4000; j++) assert(!(seen_pairs[i].idx == seen_pairs[j].idx && seen_pairs[i].ctr == seen_pairs[j].ctr));
    printf("wg egress race: %u datagrams sealed outside the lock while keypairs rolled; every one opens, no nonce reused\n", sent_n);
    rig_down(&b);
    return sent_n ? 0 : 1;
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
    if (argc > 1 && !strcmp(argv[1], "race")) return race();
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
    split_tests();
    puts("wg egress: prepared in-place output equals the copying output (bytes, counters, timestamps, rekey flags, results); zero-copy callbacks see the same pbuf");
    return 0;
}
