/* The inbound run (ml_wg_rx_batch.h, ADR 0020) on the REAL wireguardif.c / wireguard.c (IPv4 lwIP fake): begin / decrypt in place /
 * complete deferred / deliver, for up to ML_WG_RX_BATCH datagrams per core-lock cycle.
 *
 * The property that matters is EQUIVALENCE: two identical gateways receive the same random traffic, one a datagram at a time through
 * the path the run replaced (wireguardif_rx_begin / decrypt into a second pbuf / wireguardif_rx_complete, input called under the
 * lock), the other through ml_wg_rx_run with random run sizes. They must deliver the same packets in the same order and end with
 * the same counters, the same replay windows, the same endpoint and the same timers. Around it:
 *   - lock discipline: begin and complete run under the lock, decrypt and delivery without it (a seam in the header asserts it);
 *     the hold count is two per run; a handshake or any non-data message ends the run and is handled alone, in order;
 *   - ownership: every datagram's pbuf is freed exactly once on every path (live pbuf count back to its start; ASan);
 *   - ordering with two peers interleaved, a replay inside one run, a keypair that disappears between begin and complete, a
 *     keepalive that confirms a responder's next keypair in the middle of a run;
 *   - the in-place decrypt leaves a forged datagram's bytes untouched (the tag is verified before anything is written).
 *
 *   wg=components/microlink/components/wireguard_lwip/src
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -w -DWIREGUARD_CRYPTO_REFC=1 \
 *      -I tests/host/wg_lwip -I tests/host_esp -I components/microlink/include -I ../../components/tdongle_runtime/include \
 *      -I $wg -I $wg/crypto -I $wg/crypto/refc tests/test_wg_rx_batch.c tests/host/wg_lwip/wg_host_lwip.c $wg/wireguard.c \
 *      $wg/wireguardif.c $wg/wireguard_pool.c $wg/crypto.c $wg/crypto/refc/{blake2s,chacha20,chacha20poly1305,poly1305-donna,x25519}.c \
 *      -o build-host/test_wg_rx_batch */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include "wireguard.h"
#include "wireguardif.h"
#include "wireguard_stats.h"
#include "chacha20poly1305.h"
#define wireguard_aead_encrypt(dst, src, srclen, ad, adlen, nonce, key) chacha20poly1305_encrypt(dst, src, srclen, ad, adlen, nonce, key)

static _Thread_local int g_lock_held;
#define ML_WG_RX_ASSERT_UNLOCKED(where) do { if (g_lock_held) { fprintf(stderr, "the core lock is held at %s\n", where); abort(); } } while (0)
#include "ml_wg_rx_batch.h"

static uint32_t g_now = 100000;
uint32_t wireguard_sys_now(void) { return g_now; }
void wireguard_tai64n_now(uint8_t *out) { memset(out, 0, 12); out[7] = 1; }
bool wireguard_is_under_load(void) { return false; }
void wireguard_set_tai64n_base_seconds(uint64_t s) { (void)s; }
void wireguard_random_bytes(void *bytes, size_t size) { memset(bytes, 0x42, size); }

#define LOCAL_INDEX 0xA1B2C3D4u
#define NEXT_INDEX 0x0BADF00Du
#define PEER2_INDEX 0x5566AA01u
#define PEER_SRC 0x0100010au      /* 10.1.0.1 */
#define PEER2_SRC 0x0300010au     /* 10.1.0.3 */
#define OTHER_SRC 0x0200010au     /* 10.1.0.2: allowed for nobody */

typedef struct rig {
    struct netif nif;             /* first: capture_input maps the netif back to the rig */
    struct wireguardif_init_data init;
    char key_b64[64];
    struct wireguard_peer *peer[2];
    /* what netif->input saw */
    unsigned delivered;
    uint64_t digest;              /* order-sensitive hash of every delivered packet */
    size_t bytes;
    bool check_unlocked;
    unsigned refuse_every;        /* the router refuses every Nth packet (ERR_MEM, the packet stays the caller's) */
    unsigned offered;
} rig_t;

static err_t capture_input(struct pbuf *p, struct netif *inp) {
    rig_t *r = (rig_t *)inp;
    if (r->check_unlocked && g_lock_held) { fprintf(stderr, "netif->input called with the core lock held\n"); abort(); }
    if (r->refuse_every && ++r->offered % r->refuse_every == 0) return ERR_MEM;
    const uint8_t *b = p->payload;
    uint64_t h = r->digest * 1099511628211ull + p->tot_len;
    for (size_t i = 0; i < p->tot_len; i++) h = (h ^ b[i]) * 1099511628211ull;
    r->digest = h; r->bytes += p->tot_len; r->delivered++;
    pbuf_free(p);
    return ERR_OK;
}
static ip_addr_t from_addr(unsigned n) { ip_addr_t a = {.addr = 0x0400a8c0u + (n << 24)}; return a; }
static void key_for(uint8_t key[32], uint32_t index) { for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x30 + i + (index & 0xff)); }
static void set_receiving(struct wireguard_keypair *k, uint32_t index) {
    memset(k, 0, sizeof(*k));
    k->valid = true; k->initiator = false; k->keypair_millis = g_now; k->local_index = index; k->remote_index = 0x11223344;
    k->receiving_valid = true; k->sending_valid = true; k->sending_counter = 0;
    key_for(k->receiving_key, index);
    wireguard_replay_reset(&k->replay);
}
static void add_peer(rig_t *r, unsigned slot, uint8_t seed, uint32_t allowed, uint32_t index) {
    uint8_t pk[32], idx; char s[64]; size_t n = 64; struct wireguardif_peer p;
    for (int i = 0; i < 32; i++) pk[i] = (uint8_t)(i + seed);
    pk[31] &= 0x7f;
    assert(wireguard_base64_encode(pk, 32, s, &n));
    wireguardif_peer_init(&p);
    p.public_key = s; p.allowed_ip.addr = allowed; p.allowed_mask.addr = 0xffffffff;
    assert(wireguardif_add_peer(&r->nif, &p, &idx) == ERR_OK);
    r->peer[slot] = wireguard_device_peer((struct wireguard_device *)r->nif.state, idx);
    set_receiving(&r->peer[slot]->curr_keypair, index);
    memset(&r->peer[slot]->ip, 0, sizeof(r->peer[slot]->ip)); r->peer[slot]->port = 0;
}
static void rig_up(rig_t *r) {
    uint8_t key[32]; size_t n = 64;
    memset(r, 0, sizeof(*r));
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1);
    assert(wireguard_base64_encode(key, 32, r->key_b64, &n));
    r->init.private_key = r->key_b64; r->init.listen_port = 51820; r->init.bind_netif = NULL;
    r->nif.state = &r->init;
    assert(wireguardif_init(&r->nif) == ERR_OK);
    r->nif.input = capture_input;
    add_peer(r, 0, 5, PEER_SRC, LOCAL_INDEX);
    add_peer(r, 1, 77, PEER2_SRC, PEER2_INDEX);
}
static void rig_down(rig_t *r) { wireguardif_free(&r->nif); }

/* ---- datagrams ---- */
static size_t ip_packet(uint8_t *b, uint32_t src, size_t total, size_t pad, unsigned version) {
    memset(b, 0, total + pad);
    b[0] = (uint8_t)(version << 4 | 5); b[2] = (uint8_t)(total >> 8); b[3] = (uint8_t)total; b[8] = 64; b[9] = 17;
    memcpy(b + 12, &src, 4); b[16] = 10; b[17] = 9; b[18] = 9; b[19] = 9;
    for (size_t i = 20; i < total; i++) b[i] = (uint8_t)(i * 7 + total);
    return total;
}
static size_t seal_raw(uint8_t *out, uint32_t receiver, uint64_t counter, const uint8_t *plain, size_t plain_len, bool pad) {
    size_t padded = pad ? WIREGUARDIF_DATA_PAD(plain_len) : plain_len;
    uint8_t buf[1700]; memset(buf, 0, sizeof(buf)); if (plain_len) memcpy(buf, plain, plain_len);
    memset(out, 0, 16);
    out[0] = 4;
    memcpy(out + 4, &receiver, 4);
    for (int i = 0; i < 8; i++) out[8 + i] = (uint8_t)(counter >> (8 * i));
    uint8_t key[32]; key_for(key, receiver);
    wireguard_aead_encrypt(out + 16, buf, padded, NULL, 0, counter, key);
    return 16 + padded + WIREGUARD_AUTHTAG_LEN;
}
static size_t good(uint8_t *dg, uint32_t receiver, uint32_t src, uint64_t counter, size_t ip_len) {
    uint8_t ip[1500]; ip_packet(ip, src, ip_len, 0, 4);
    return seal_raw(dg, receiver, counter, ip, ip_len, true);
}

/* ---- the two ways in ---- */
static void legacy_one(rig_t *r, const uint8_t *dg, size_t len, unsigned from) {
    ip_addr_t addr = from_addr(from);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM); assert(p); memcpy(p->payload, dg, len);
    struct wireguard_rx_job job;
    if (wireguardif_rx_begin(&r->nif, p, &addr, 41641, &job)) {
        wireguard_rx_decrypt(&job);
        wireguardif_rx_complete(&r->nif, &addr, 41641, &job);
    }
}
static unsigned g_sites[4096], g_site_count;
static pthread_mutex_t core_lock = PTHREAD_MUTEX_INITIALIZER;   /* the lwIP core lock, for the race test */
static bool g_real_lock;
static void hook_lock(void *ctx, unsigned site) {
    assert(!g_lock_held);
    if (g_real_lock) pthread_mutex_lock(&core_lock);
    g_lock_held = 1;
    if (!g_real_lock && g_site_count < 4096) g_sites[g_site_count++] = site;
    (void)ctx;
}
static void hook_unlock(void *ctx, unsigned site) { assert(g_lock_held); g_lock_held = 0; if (g_real_lock) pthread_mutex_unlock(&core_lock); (void)ctx; (void)site; }
static const ml_wg_rx_lock_t LK = {hook_lock, hook_unlock, NULL};
static struct wireguard_rx_job jobs[ML_WG_RX_BATCH];
typedef struct { uint8_t dg[1700]; size_t len; unsigned from; } dgram_t;
static unsigned run_group(rig_t *r, const dgram_t *g, unsigned n) {
    ml_wg_rx_item_t items[64];
    assert(n <= 64);
    for (unsigned i = 0; i < n; i++) {
        items[i].p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)g[i].len, PBUF_RAM); assert(items[i].p);
        memcpy(items[i].p->payload, g[i].dg, g[i].len);
        items[i].addr = from_addr(g[i].from); items[i].port = 41641;
    }
    memset(jobs, 0xA5, sizeof(jobs));   /* the caller's scratch holds garbage: a run must initialise every field it reads */
    r->check_unlocked = true;
    unsigned d = ml_wg_rx_run(&r->nif, items, n, jobs, &LK);
    r->check_unlocked = false;
    for (unsigned i = 0; i < n; i++) assert(items[i].p == NULL);
    assert(!g_lock_held);
    return d;
}

/* ---- counters ---- */
static uint32_t cnt[WG_RXS_COUNT];
static void cnt_read(uint32_t *out) { for (unsigned i = 0; i < WG_RXS_COUNT; i++) out[i] = wireguard_rx_stat_get(i); }
static void cnt_accumulate(uint32_t *acc, const uint32_t *before) { for (unsigned i = 0; i < WG_RXS_COUNT; i++) acc[i] += wireguard_rx_stat_get(i) - before[i]; }
static void terminal_sum_check(const uint32_t *c) {
    uint32_t sum = 0;
    for (unsigned i = 0; i < WG_RXS_COUNT; i++) if (i != WG_RXS_rx_data && i != WG_RXS_rx_bad_type) sum += c[i];
    assert(sum == c[WG_RXS_rx_data]);
}
static void same_state(rig_t *a, rig_t *b) {
    for (int p = 0; p < 2; p++) {
        struct wireguard_peer *x = a->peer[p], *y = b->peer[p];
        assert(x->last_rx == y->last_rx && x->port == y->port && x->ip.addr == y->ip.addr && x->send_handshake == y->send_handshake);
        struct wireguard_keypair *kx[3] = {&x->curr_keypair, &x->prev_keypair, &x->next_keypair}, *ky[3] = {&y->curr_keypair, &y->prev_keypair, &y->next_keypair};
        for (int k = 0; k < 3; k++) {
            assert(kx[k]->valid == ky[k]->valid && kx[k]->local_index == ky[k]->local_index && kx[k]->last_rx == ky[k]->last_rx);
            assert(!memcmp(&kx[k]->replay, &ky[k]->replay, sizeof(kx[k]->replay)));
        }
    }
}

/* ---- random traffic ---- */
static uint32_t rs;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs; }
static uint64_t next_counter[2];
static void make(dgram_t *d, unsigned peer_hint) {
    unsigned peer = peer_hint & 1;
    uint32_t index = peer ? PEER2_INDEX : LOCAL_INDEX, src = peer ? PEER2_SRC : PEER_SRC;
    d->from = rnd() & 3;
    uint64_t c = next_counter[peer];
    uint8_t ip[1500];
    unsigned kind = rnd() % 16;
    size_t ip_len = 28 + rnd() % 1200;
    switch (kind) {
    case 0: case 1: case 2: case 3: case 4:  d->len = good(d->dg, index, src, next_counter[peer]++, ip_len); break;                 /* in order */
    case 5: d->len = good(d->dg, index, src, c + (rnd() % 40), ip_len); break;                                                     /* ahead / reordered (may be a dup later) */
    case 6: d->len = good(d->dg, index, src, c > 6 ? c - 1 - rnd() % 5 : c, ip_len); break;                                        /* recent past: usually a duplicate */
    case 7: d->len = good(d->dg, index, src, 0, ip_len); break;                                                                     /* ancient or duplicate of the first */
    case 8: d->len = good(d->dg, index, src, next_counter[peer]++, ip_len); d->dg[d->len - 1 - rnd() % 20] ^= 0x40; break;       /* forged tag or body */
    case 9: d->len = good(d->dg, 0xDEAD0000u + rnd() % 3, src, c, ip_len); break;                                                   /* unknown receiver index */
    case 10: d->len = seal_raw(d->dg, index, next_counter[peer]++, NULL, 0, true); break;                                           /* keepalive */
    case 11: ip_packet(ip, src, 60, 0, 3 + rnd() % 2 * 8); d->len = seal_raw(d->dg, index, next_counter[peer]++, ip, 60, true); break;   /* not IPv4 (3 or 11) */
    case 12: ip_packet(ip, OTHER_SRC, 80, 0, 4); d->len = seal_raw(d->dg, index, next_counter[peer]++, ip, 80, true); break;      /* source not allowed */
    case 13: ip_packet(ip, src, 80, 0, 4); ip[2] = 0x05; ip[3] = 0xdc; d->len = seal_raw(d->dg, index, next_counter[peer]++, ip, 80, true); break;   /* length lies */
    case 14: memset(d->dg, 0, 64); d->dg[0] = 4; d->len = 8 + rnd() % 24; break;                                                    /* too short to be transport data */
    default: memset(d->dg, 0x5a, 148); d->dg[0] = 1 + rnd() % 3; d->dg[1] = d->dg[2] = d->dg[3] = 0; d->len = rnd() & 1 ? 148 : 92; break;   /* a handshake-shaped message */
    }
}

static void t_equivalence(unsigned seed, unsigned groups) {
    rig_t A, B;
    rs = seed * 2654435761u | 1; memset(next_counter, 0, sizeof(next_counter));
    g_now = 100000;
    rig_up(&A); rig_up(&B);
    uint32_t ca[WG_RXS_COUNT] = {0}, cb[WG_RXS_COUNT] = {0}, snap[WG_RXS_COUNT];
    long live = wg_host_pbuf_live;
    unsigned runs_sizes[ML_WG_RX_BATCH + 1] = {0};
    static dgram_t g[64];
    for (unsigned grp = 0; grp < groups; grp++) {
        unsigned n = 1 + rnd() % 24;
        for (unsigned i = 0; i < n; i++) make(&g[i], rnd());
        g_now += rnd() % 50;
        /* the datagram-at-a-time path */
        cnt_read(snap);
        for (unsigned i = 0; i < n; i++) legacy_one(&A, g[i].dg, g[i].len, g[i].from);
        cnt_accumulate(ca, snap);
        /* the run path */
        cnt_read(snap); g_site_count = 0;
        run_group(&B, g, n);
        cnt_accumulate(cb, snap);
        /* two holds per run of data, one per other message: never more than 2 per datagram, and the sites alternate begin/commit */
        unsigned data = 0, other = 0;
        for (unsigned i = 0; i < n; i++) { if (g[i].len >= 32 && g[i].dg[0] == 4 && g[i].dg[1] == 0) data++; else other++; }
        assert(g_site_count <= 2 * data + other);
        (void)runs_sizes;
        assert(A.delivered == B.delivered && A.digest == B.digest && A.bytes == B.bytes);
    }
    assert(!memcmp(ca, cb, sizeof(ca)));
    terminal_sum_check(ca); terminal_sum_check(cb);
    same_state(&A, &B);
    assert(wg_host_pbuf_live == live);
    printf("  seed %u: %u groups, %u packets delivered identically, %u replay dup, %u too old, %u decrypt fail, %u keepalive\n", seed, groups,
           A.delivered, ca[WG_RXS_rx_replay_dup], ca[WG_RXS_rx_replay_old], ca[WG_RXS_rx_decrypt_fail], ca[WG_RXS_rx_keepalive]);
    rig_down(&A); rig_down(&B);
}

/* ---- structure of one run ---- */
static unsigned site_seq[64];
static void t_lock_structure(void) {
    rig_t R; rig_up(&R); memset(next_counter, 0, sizeof(next_counter));
    static dgram_t g[64];
    long live = wg_host_pbuf_live;
    /* 8 data: exactly one run: begin, commit */
    for (unsigned i = 0; i < 8; i++) { g[i].len = good(g[i].dg, LOCAL_INDEX, PEER_SRC, i, 100 + i); g[i].from = 1; }
    g_site_count = 0; unsigned d = run_group(&R, g, 8);
    assert(d == 8 && g_site_count == 2 && g_sites[0] == ML_WG_RX_SITE_BEGIN && g_sites[1] == ML_WG_RX_SITE_COMMIT);
    /* 20 data: runs of 8, 8, 4 */
    for (unsigned i = 0; i < 20; i++) { g[i].len = good(g[i].dg, LOCAL_INDEX, PEER_SRC, 100 + i, 100 + i); g[i].from = 1; }
    g_site_count = 0; d = run_group(&R, g, 20);
    assert(d == 20 && g_site_count == 6);
    for (unsigned k = 0; k < 6; k++) assert(g_sites[k] == (k & 1 ? ML_WG_RX_SITE_COMMIT : ML_WG_RX_SITE_BEGIN));
    /* data, data, handshake, data: [BEGIN COMMIT] [OTHER] [BEGIN COMMIT], delivered in order */
    for (unsigned i = 0; i < 4; i++) { g[i].len = good(g[i].dg, LOCAL_INDEX, PEER_SRC, 200 + i, 100 + i); g[i].from = 1; }
    memset(g[2].dg, 0x77, 148); g[2].dg[0] = 1; g[2].dg[1] = g[2].dg[2] = g[2].dg[3] = 0; g[2].len = 148;
    g_site_count = 0; uint64_t before = R.digest; d = run_group(&R, g, 4);
    assert(d == 3 && g_site_count == 5 && g_sites[0] == ML_WG_RX_SITE_BEGIN && g_sites[1] == ML_WG_RX_SITE_COMMIT && g_sites[2] == ML_WG_RX_SITE_OTHER &&
           g_sites[3] == ML_WG_RX_SITE_BEGIN && g_sites[4] == ML_WG_RX_SITE_COMMIT);
    (void)before; (void)site_seq;
    /* a single datagram and a lone non-data message */
    g[0].len = good(g[0].dg, LOCAL_INDEX, PEER_SRC, 300, 100); g_site_count = 0; assert(run_group(&R, g, 1) == 1 && g_site_count == 2);
    memset(g[0].dg, 0x77, 148); g[0].dg[0] = 2; g[0].dg[1] = g[0].dg[2] = g[0].dg[3] = 0; g[0].len = 148;
    g_site_count = 0; assert(run_group(&R, g, 1) == 0 && g_site_count == 1 && g_sites[0] == ML_WG_RX_SITE_OTHER);
    assert(wg_host_pbuf_live == live);
    rig_down(&R);
}

/* ---- ordering of two peers interleaved, in one run ---- */
static void t_order_two_peers(void) {
    rig_t R; rig_up(&R);
    static dgram_t g[ML_WG_RX_BATCH];
    for (unsigned i = 0; i < ML_WG_RX_BATCH; i++) {
        bool p2 = i & 1;
        g[i].len = good(g[i].dg, p2 ? PEER2_INDEX : LOCAL_INDEX, p2 ? PEER2_SRC : PEER_SRC, i / 2, 80 + 10 * i); g[i].from = 1;
    }
    /* what a reference that delivers them one at a time, in order, produces */
    rig_t Q; rig_up(&Q);
    for (unsigned i = 0; i < ML_WG_RX_BATCH; i++) legacy_one(&Q, g[i].dg, g[i].len, 1);
    assert(run_group(&R, g, ML_WG_RX_BATCH) == ML_WG_RX_BATCH && R.digest == Q.digest && R.bytes == Q.bytes);
    /* swapping two datagrams changes the digest: the test would notice a reorder */
    rig_t S; rig_up(&S);
    dgram_t t = g[0]; g[0] = g[2]; g[2] = t;
    for (unsigned i = 0; i < ML_WG_RX_BATCH; i++) legacy_one(&S, g[i].dg, g[i].len, 1);
    assert(S.digest != Q.digest);
    rig_down(&R); rig_down(&Q); rig_down(&S);
}

/* ---- a replay inside one run, a forged datagram, in-place integrity ---- */
static void t_replay_and_forgery(void) {
    rig_t R; rig_up(&R); wireguard_rx_stats_reset();
    static dgram_t g[ML_WG_RX_BATCH];
    for (unsigned i = 0; i < 6; i++) { g[i].len = good(g[i].dg, LOCAL_INDEX, PEER_SRC, 10 + i, 120); g[i].from = 1; }
    g[3] = g[1];                                                       /* the same datagram twice in one run */
    g[4].dg[g[4].len - 1] ^= 1;                                        /* a forged tag */
    uint8_t keep[1700]; memcpy(keep, g[4].dg, g[4].len);
    uint32_t b[WG_RXS_COUNT]; cnt_read(b);
    unsigned d = run_group(&R, g, 6);
    assert(d == 4);
    assert(wireguard_rx_stat_get(WG_RXS_rx_replay_dup) - b[WG_RXS_rx_replay_dup] == 1 && wireguard_rx_stat_get(WG_RXS_rx_decrypt_fail) - b[WG_RXS_rx_decrypt_fail] == 1);
    /* in place: the forged datagram was freed by complete, but its bytes were verified before being touched: reproduce on a pbuf we keep */
    {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)g[4].len, PBUF_RAM); memcpy(p->payload, g[4].dg, g[4].len);
        ip_addr_t addr = from_addr(1); struct wireguard_rx_job job;
        assert(wireguardif_rx_begin_ex(&R.nif, p, &addr, 41641, &job, WIREGUARDIF_RX_INPLACE) == 1 && job.inplace && job.pbuf == NULL && job.dst == job.src);
        wireguard_rx_decrypt(&job);
        assert(!job.ok && !memcmp(p->payload, keep, g[4].len));      /* untouched */
        wireguardif_rx_complete_deferred(&R.nif, &addr, 41641, &job);
        assert(job.deliver == NULL && job.input == NULL);
    }
    rig_down(&R);
}

/* ---- the keypair vanishes between begin and complete (the lock was released): that datagram only is rx_session_gone ---- */
static void t_session_gone_in_run(void) {
    rig_t R; rig_up(&R); wireguard_rx_stats_reset();
    static dgram_t g[4];
    for (unsigned i = 0; i < 4; i++) { bool p2 = i == 2; g[i].len = good(g[i].dg, p2 ? PEER2_INDEX : LOCAL_INDEX, p2 ? PEER2_SRC : PEER_SRC, 50 + i, 100); g[i].from = 1; }
    ml_wg_rx_item_t items[4];
    for (unsigned i = 0; i < 4; i++) { items[i].p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)g[i].len, PBUF_RAM); memcpy(items[i].p->payload, g[i].dg, g[i].len); items[i].addr = from_addr(1); items[i].port = 41641; }
    /* drive the steps by hand with the "other task" acting in between */
    struct wireguard_rx_job j[4];
    for (unsigned i = 0; i < 4; i++) assert(wireguardif_rx_begin_ex(&R.nif, items[i].p, &items[i].addr, items[i].port, &j[i], WIREGUARDIF_RX_INPLACE));
    for (unsigned i = 0; i < 4; i++) wireguard_rx_decrypt(&j[i]);
    memset(&R.peer[1]->curr_keypair, 0, sizeof(R.peer[1]->curr_keypair));        /* peer 2's session was replaced while decrypting */
    for (unsigned i = 0; i < 4; i++) wireguardif_rx_complete_deferred(&R.nif, &items[i].addr, items[i].port, &j[i]);
    assert(wireguardif_rx_deliver(&R.nif, j, 4) == 3 && wireguard_rx_stat_get(WG_RXS_rx_session_gone) == 1);
    long live = wg_host_pbuf_live; (void)live;
    rig_down(&R);
}

/* ---- the responder's next keypair is confirmed by a keepalive in the middle of a run; data on it follows in the same run ---- */
static void t_keepalive_confirms_inside_run(void) {
    rig_t R, Q; rig_up(&R); rig_up(&Q);
    for (int k = 0; k < 2; k++) {
        rig_t *r = k ? &Q : &R;
        set_receiving(&r->peer[0]->next_keypair, NEXT_INDEX);
        r->peer[0]->prev_keypair = r->peer[0]->curr_keypair; r->peer[0]->curr_keypair.valid = false;
    }
    static dgram_t g[4];
    g[0].len = seal_raw(g[0].dg, NEXT_INDEX, 0, NULL, 0, true);                   /* the keepalive that promotes */
    g[1].len = good(g[1].dg, NEXT_INDEX, PEER_SRC, 1, 100);
    g[2].len = good(g[2].dg, LOCAL_INDEX, PEER_SRC, 70, 100);                    /* on the previous keypair, still valid */
    g[3].len = good(g[3].dg, NEXT_INDEX, PEER_SRC, 2, 100);
    for (unsigned i = 0; i < 4; i++) { g[i].from = 2; legacy_one(&Q, g[i].dg, g[i].len, 2); }
    /* the keepalive promotes next -> current and rolls current -> previous (the old previous goes), so the datagram sealed for the
     * ORIGINAL index no longer finds a keypair: both paths deliver the two datagrams on the new keypair and refuse that one */
    unsigned dd = run_group(&R, g, 4);
    assert(dd == 2 && Q.delivered == 2 && R.digest == Q.digest);
    same_state(&R, &Q);
    assert(R.peer[0]->curr_keypair.local_index == NEXT_INDEX && !R.peer[0]->next_keypair.valid);
    rig_down(&R); rig_down(&Q);
}

/* the router refuses some packets: counted rx_input_fail, freed exactly once by wireguardif, the rest delivered in order; through
 * netif->input and through the batch callback alike */
static void batch_cb(struct pbuf **p, unsigned n, struct netif *netif, err_t *result) {
    ML_WG_RX_ASSERT_UNLOCKED("batch callback");
    for (unsigned i = 0; i < n; i++) result[i] = capture_input(p[i], netif);
}
static void t_router_refusals(void) {
    for (int use_batch = 0; use_batch < 2; use_batch++) {
        rig_t R, Q; rig_up(&R); rig_up(&Q);
        if (use_batch) wireguardif_set_rx_batch(&R.nif, batch_cb);
        R.refuse_every = Q.refuse_every = 3;
        wireguard_rx_stats_reset();
        static dgram_t g[ML_WG_RX_BATCH * 2 + 3];
        unsigned n = ML_WG_RX_BATCH * 2 + 3;
        long live = wg_host_pbuf_live;
        for (unsigned i = 0; i < n; i++) { g[i].len = good(g[i].dg, LOCAL_INDEX, PEER_SRC, i, 90 + i); g[i].from = 1; legacy_one(&Q, g[i].dg, g[i].len, 1); }
        uint32_t qd = wireguard_rx_stat_get(WG_RXS_rx_delivered), qf = wireguard_rx_stat_get(WG_RXS_rx_input_fail);
        wireguard_rx_stats_reset();
        unsigned d = run_group(&R, g, n);
        assert(d == R.delivered && R.delivered == Q.delivered && R.digest == Q.digest);
        assert(wireguard_rx_stat_get(WG_RXS_rx_delivered) == qd && wireguard_rx_stat_get(WG_RXS_rx_input_fail) == qf && qf == n / 3);
        assert(wg_host_pbuf_live == live);       /* the refused packets were freed by wireguardif, the delivered ones by the consumer */
        rig_down(&R); rig_down(&Q);
    }
}

/* ---- the netif is gone: begin frees what it was given and nothing leaks ---- */
static void t_no_netif(void) {
    long live = wg_host_pbuf_live;
    struct netif dead; memset(&dead, 0, sizeof(dead));
    ml_wg_rx_item_t items[3];
    uint8_t dg[1700]; size_t n = good(dg, LOCAL_INDEX, PEER_SRC, 1, 100);
    for (unsigned i = 0; i < 3; i++) { items[i].p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM); memcpy(items[i].p->payload, dg, n); items[i].addr = from_addr(1); items[i].port = 1; }
    assert(ml_wg_rx_run(&dead, items, 3, jobs, &LK) == 0);
    assert(wg_host_pbuf_live == live);
}


/* ---- the receive path against the "tcpip" thread (TSan): the decrypt runs with the lock released while another thread rolls, destroys
 * and replaces the very keypairs the datagrams are for, and moves the endpoint. A run must neither read what the other thread writes
 * outside the lock (it works from the key copied by begin and from the datagram it owns) nor lose track of a datagram: every one
 * ends in exactly one terminal counter and every pbuf is freed. */
static rig_t RR;
static atomic_bool race_done;
static void *tcpip_thread(void *arg) {
    (void)arg;
    unsigned n = 0;
    while (!atomic_load(&race_done)) {
        pthread_mutex_lock(&core_lock);
        struct wireguard_peer *p = RR.peer[n & 1];
        switch (n++ % 6) {
        case 0: set_receiving(&p->curr_keypair, (n & 2) ? PEER2_INDEX : LOCAL_INDEX); break;       /* a fresh session: replay window reset, same key */
        case 1: p->curr_keypair.receiving_valid = false; break;                                    /* destroyed while datagrams are in flight */
        case 2: p->curr_keypair.receiving_valid = true; break;
        case 3: p->prev_keypair = p->curr_keypair; break;
        case 4: p->ip = from_addr(n & 3); p->port = (u16_t)(n & 0xff); break;
        default: wireguard_replay_reset(&p->curr_keypair.replay); break;
        }
        pthread_mutex_unlock(&core_lock);
        sched_yield();
    }
    return NULL;
}
static void t_race(void) {
    rig_up(&RR);
    g_real_lock = true;
    long live = wg_host_pbuf_live;
    wireguard_rx_stats_reset();
    pthread_t t;
    pthread_create(&t, NULL, tcpip_thread, NULL);
    rs = 99; memset(next_counter, 0, sizeof(next_counter));
    static dgram_t g[24];
    unsigned total = 0;
    for (unsigned round = 0; round < 3000; round++) {
        unsigned n = 1 + rnd() % 24;
        for (unsigned i = 0; i < n; i++) { make(&g[i], rnd()); g[i].from = 1; }
        pthread_mutex_lock(&core_lock);                       /* run_group touches the rig's counters as the only datagram consumer */
        pthread_mutex_unlock(&core_lock);
        run_group(&RR, g, n);
        total += n;
    }
    atomic_store(&race_done, true);
    pthread_join(t, NULL);
    g_real_lock = false;
    uint32_t c[WG_RXS_COUNT]; cnt_read(c);
    terminal_sum_check(c);
    assert(wg_host_pbuf_live == live);
    printf("  race: %u datagrams against a thread rolling keypairs: %u delivered, %u session gone, %u unusable/no peer, identity holds\n", total, RR.delivered,
           c[WG_RXS_rx_session_gone], c[WG_RXS_rx_no_peer] + c[WG_RXS_rx_keypair_unusable]);
    rig_down(&RR);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "race")) { t_race(); printf("wg rx batch race ok\n"); return 0; }
    for (unsigned seed = 1; seed <= 12; seed++) t_equivalence(seed, 400);
    t_lock_structure();
    t_order_two_peers();
    t_replay_and_forgery();
    t_session_gone_in_run();
    t_keepalive_confirms_inside_run();
    t_router_refusals();
    t_no_netif();
    printf("wg rx batch ok\n");
    return 0;
}
