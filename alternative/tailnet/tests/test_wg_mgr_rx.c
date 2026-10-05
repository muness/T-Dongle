/* wg_mgr's inbound drain (ADR 0020): the REAL staging, flush and drain code of ml_wg_mgr.c (extracted by tools/test-gateway.sh into
 * build-host/wg_mgr_rx.inc) on the real wireguardif.c, with doubles for FreeRTOS, the DERP admission, the peer table and the clock.
 *
 * What it pins down:
 *   - the drain delivers what the one-datagram path delivered, in the same order, and ends in the same counters, with data and
 *     handshakes interleaved (a handshake is never staged behind data: the data before it is finished first);
 *   - every datagram's heap block is freed exactly once on every path (delivered, dropped before staging, refused by wireguardif,
 *     replayed, forged): the block is owned by the wrapping pbuf and released by its free callback;
 *   - the queue's byte budget (ml_wg_rx_budget.h) is released for exactly the datagrams that were popped, so it returns to zero;
 *   - the drain's limits: the burst count, the window of the pass and the pass budget stop it, and whatever it already took is
 *     processed (nothing stays staged between calls);
 *   - the per-datagram steps that followed wireguardif in the old code: a DERP sender's residency is refreshed only by a datagram
 *     wireguardif accepted (not a keepalive, not a forgery), directory_trial_poll runs after every run;
 *   - the drops that precede wireguardif are counted: unknown DERP sender, no interface, a datagram too long for a pbuf.
 *
 *   tools/test-gateway.sh builds it; the extraction is in the script (two ranges of ml_wg_mgr.c). */
#define ESP_PLATFORM 1
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
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

/* ---- doubles for what ml_wg_mgr.c includes ---- */
#define TAG "wg_mgr_test"
#define ESP_LOGI(tag, ...) ((void)0)
#define ESP_LOGW(tag, ...) ((void)0)
typedef struct { uint32_t diagnostic_id; } ml_config_double_t;
#include "ml_rx_stats.h"
ml_rx_stats_t ml_rx_stats;
#include "ml_wg_rx_budget.h"
ml_wgrx_budget_t ml_wgrx_budget;
#include "ml_wg_rx_batch.h"
typedef int QueueHandle_t_double;
#define MAX_Q 256
typedef struct { struct { uint8_t *data; size_t len; uint32_t src_ip; uint16_t src_port; uint8_t src_pubkey[32]; bool via_derp; } items[MAX_Q]; unsigned head, tail; } fake_queue_t;
typedef struct { uint8_t *data; size_t len; uint32_t src_ip; uint16_t src_port; uint8_t src_pubkey[32]; bool via_derp; } ml_rx_packet_t;
typedef fake_queue_t *QueueHandle_t;
typedef struct { void *wg_netif; QueueHandle_t wg_rx_queue; ml_config_double_t config; struct { uint64_t jit_used_ms; } peers[4]; } microlink_t;
typedef struct { uint64_t pass_start_ms; uint32_t drain_ms; uint64_t next_due_ms; } ml_wg_pass_t;
#define pdTRUE 1
static int xQueueReceive(QueueHandle_t q, ml_rx_packet_t *out, int ticks) {
    (void)ticks;
    if (q->head == q->tail) return 0;
    *out = *(ml_rx_packet_t *)&q->items[q->head++ % MAX_Q];
    return pdTRUE;
}
static unsigned uxQueueMessagesWaiting(QueueHandle_t q) { return q->tail - q->head; }
static unsigned blocks_freed, blocks_made; static const void *freed_log[4096]; static unsigned freed_n;
/* what a producer does (net_io, the DERP loop): admit the bytes against the shared budget, then queue the heap block. false = refused. */
static bool queue_push(QueueHandle_t q, const uint8_t *data, size_t len, bool via_derp, uint8_t sender_tag) {
    if (ml_wgrx_admit(&ml_wgrx_budget, len, 1u << 20) != ML_WGRX_OK) return false;
    uint8_t *block = malloc(len ? len : 1); memcpy(block, data, len); blocks_made++;
    ml_rx_packet_t *p = (ml_rx_packet_t *)&q->items[q->tail++ % MAX_Q];
    memset(p, 0, sizeof(*p)); p->data = block; p->len = len; p->via_derp = via_derp; p->src_ip = 0xc0a80004u; p->src_port = 41641; p->src_pubkey[0] = sender_tag;
    return true;
}
/* heap accounting: every block malloc'd by queue_push must be freed once */
#define TDONGLE_OWNER_PACKET 1
static void tdongle_heap_free(int owner, void *p) {
    (void)owner;
    for (unsigned i = 0; i < freed_n; i++) if (freed_log[i] == p) { fprintf(stderr, "double free of a datagram block\n"); abort(); }
    if (freed_n < 4096) freed_log[freed_n++] = p;
    blocks_freed++;
    free(p);
}
typedef enum { TDONGLE_LOCK_WG_OTHER, TDONGLE_LOCK_WG_PERIODIC, TDONGLE_LOCK_WG_COMMIT, TDONGLE_LOCK_WG_OUTPUT, TDONGLE_LOCK_WG_PEER } tdongle_lock_site;
static unsigned lock_sites[4096], lock_n; static int core_depth;
static int64_t tdongle_lock_clock(void) { return 0; }
static void tdongle_lock_hold(tdongle_lock_site site, uint32_t us) { (void)us; if (lock_n < 4096) lock_sites[lock_n++] = (unsigned)site; }
#define LOCK_TCPIP_CORE() (core_depth++)
#define UNLOCK_TCPIP_CORE() (core_depth--)
static void gateway_route_mark(unsigned stage, uint32_t member) { (void)stage; (void)member; }
/* the clock the drain's window reads: advances by `clock_step_ms` on every read */
static uint64_t clock_ms, clock_step_ms;
static uint64_t ml_get_time_ms(void) { uint64_t t = clock_ms; clock_ms += clock_step_ms; return t; }
/* DERP admission and the peer activity the residency refresh compares */
static int admit_result = 3; static unsigned admit_calls;
static int derp_sender_admit(microlink_t *ml, const ml_rx_packet_t *pkt) { (void)ml; admit_calls++; return pkt->src_pubkey[0] == 0xff ? -1 : admit_result; }
static struct wireguard_peer *activity_peer;   /* the real peer the double reads: wg_mgr's wg_peer_activity is last_rx + last_initiation_rx */
static uint32_t wg_peer_activity(microlink_t *ml, int idx) { (void)ml; (void)idx; return activity_peer ? activity_peer->last_rx + activity_peer->last_initiation_rx : 0; }
static unsigned trial_polls;
static void directory_trial_poll(microlink_t *ml) { (void)ml; trial_polls++; }
#define WGPERF_T(t) ((void)0)
#define WG_MGR_PASS_BUDGET_MS 100

#include "wg_mgr_rx.inc"

/* ---- the rig: two gateways, one receiving through the drain, one through the legacy one-datagram path ---- */
#define LOCAL_INDEX 0xA1B2C3D4u
#define PEER_SRC 0x0100010au
#define OTHER_SRC 0x0200010au
typedef struct rig {
    struct netif nif; struct wireguardif_init_data init; char key_b64[64]; struct wireguard_peer *peer;
    unsigned delivered; uint64_t digest;
} rig_t;
static err_t capture_input(struct pbuf *p, struct netif *inp) {
    rig_t *r = (rig_t *)inp;
    assert(core_depth == 0 || core_depth == 1);
    const uint8_t *b = p->payload; uint64_t h = r->digest * 1099511628211ull + p->tot_len;
    for (size_t i = 0; i < p->tot_len; i++) h = (h ^ b[i]) * 1099511628211ull;
    r->digest = h; r->delivered++;
    pbuf_free(p);
    return ERR_OK;
}
static void key_for(uint8_t key[32], uint32_t index) { for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x30 + i + (index & 0xff)); }
static void rig_up(rig_t *r) {
    uint8_t key[32]; size_t n = 64;
    memset(r, 0, sizeof(*r));
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1);
    assert(wireguard_base64_encode(key, 32, r->key_b64, &n));
    r->init.private_key = r->key_b64; r->init.listen_port = 51820;
    r->nif.state = &r->init;
    assert(wireguardif_init(&r->nif) == ERR_OK);
    r->nif.input = capture_input;
    uint8_t pk[32], idx; char s[64]; n = 64; struct wireguardif_peer p;
    for (int i = 0; i < 32; i++) pk[i] = (uint8_t)(i + 5);
    pk[31] &= 0x7f;
    assert(wireguard_base64_encode(pk, 32, s, &n));
    wireguardif_peer_init(&p);
    p.public_key = s; p.allowed_ip.addr = PEER_SRC; p.allowed_mask.addr = 0xffffffff;
    assert(wireguardif_add_peer(&r->nif, &p, &idx) == ERR_OK);
    r->peer = wireguard_device_peer((struct wireguard_device *)r->nif.state, idx);
    memset(&r->peer->curr_keypair, 0, sizeof(r->peer->curr_keypair));
    r->peer->curr_keypair.valid = true; r->peer->curr_keypair.keypair_millis = 100000; r->peer->curr_keypair.local_index = LOCAL_INDEX;
    r->peer->curr_keypair.receiving_valid = true; r->peer->curr_keypair.sending_valid = true;
    key_for(r->peer->curr_keypair.receiving_key, LOCAL_INDEX);
    wireguard_replay_reset(&r->peer->curr_keypair.replay);
    memset(&r->peer->ip, 0, sizeof(r->peer->ip)); r->peer->port = 0;
}
static void rig_down(rig_t *r) { wireguardif_free(&r->nif); }

static size_t seal(uint8_t *out, uint64_t counter, uint32_t src, size_t ip_len, bool forge) {
    uint8_t ip[1500]; memset(ip, 0, sizeof(ip));
    if (ip_len) { ip[0] = 0x45; ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len; ip[8] = 64; ip[9] = 17; memcpy(ip + 12, &src, 4); ip[16] = 10; ip[17] = 9; ip[18] = 9; ip[19] = 9; for (size_t i = 20; i < ip_len; i++) ip[i] = (uint8_t)(i * 7 + counter); }
    size_t padded = ip_len ? WIREGUARDIF_DATA_PAD(ip_len) : 0;
    memset(out, 0, 16); out[0] = 4; uint32_t recv = LOCAL_INDEX; memcpy(out + 4, &recv, 4);
    for (int i = 0; i < 8; i++) out[8 + i] = (uint8_t)(counter >> (8 * i));
    uint8_t key[32]; key_for(key, LOCAL_INDEX);
    wireguard_aead_encrypt(out + 16, ip, padded, NULL, 0, counter, key);
    size_t n = 16 + padded + 16;
    if (forge) out[n - 1] ^= 1;
    return n;
}
static void legacy(rig_t *r, const uint8_t *dg, size_t len, bool via_derp) {
    ip_addr_t addr = {.addr = via_derp ? 0 : htonl(0xc0a80004u)};
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM); memcpy(p->payload, dg, len);
    struct wireguard_rx_job job;
    if (wireguardif_rx_begin(&r->nif, p, &addr, 41641, &job)) { wireguard_rx_decrypt(&job); wireguardif_rx_complete(&r->nif, &addr, 41641, &job); }
}
static uint32_t snap[WG_RXS_COUNT];
static void cnt_snap(void) { for (unsigned i = 0; i < WG_RXS_COUNT; i++) snap[i] = wireguard_rx_stat_get(i); }
static void cnt_acc(uint32_t *acc) { for (unsigned i = 0; i < WG_RXS_COUNT; i++) acc[i] += wireguard_rx_stat_get(i) - snap[i]; }

static uint32_t rs = 7;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs; }

typedef struct { uint8_t b[1700]; size_t n; bool derp; } dg_t;
static void make(dg_t *d, uint64_t *counter) {
    d->derp = false;
    switch (rnd() % 12) {
    case 0: case 1: case 2: case 3: case 4: d->n = seal(d->b, (*counter)++, PEER_SRC, 28 + rnd() % 1200, false); break;
    case 5: d->n = seal(d->b, *counter ? *counter - 1 : 0, PEER_SRC, 100, false); break;                          /* a replay of the latest */
    case 6: d->n = seal(d->b, (*counter)++, PEER_SRC, 100, true); break;                                           /* forged */
    case 7: d->n = seal(d->b, (*counter)++, 0, 0, false); break;                                                    /* keepalive */
    case 8: d->n = seal(d->b, (*counter)++, OTHER_SRC, 80, false); break;                                           /* source not allowed */
    case 9: memset(d->b, 0x44, 148); d->b[0] = 1; d->b[1] = d->b[2] = d->b[3] = 0; d->n = 148; break;              /* handshake-shaped */
    case 10: d->n = seal(d->b, (*counter)++, PEER_SRC, 60, false); d->derp = true; break;                           /* arrived through DERP */
    default: memset(d->b, 0, 40); d->b[0] = 4; d->n = 10 + rnd() % 20; break;                                       /* too short for transport data */
    }
}

static fake_queue_t Q;
static microlink_t ML;

static void t_equivalence(unsigned seed, unsigned rounds) {
    rig_t A, B;
    rs = seed * 2654435761u | 1;
    rig_up(&A); rig_up(&B);
    ML.wg_rx_queue = &Q; ML.wg_netif = &B.nif;
    uint32_t ca[WG_RXS_COUNT] = {0}, cb[WG_RXS_COUNT] = {0};
    uint64_t counter = 0;
    ml_rx_stats_reset();
    unsigned drains = 0;
    for (unsigned round = 0; round < rounds; round++) {
        unsigned n = 1 + rnd() % 40;
        static dg_t g[40];
        for (unsigned i = 0; i < n; i++) make(&g[i], &counter);
        cnt_snap();
        for (unsigned i = 0; i < n; i++) legacy(&A, g[i].b, g[i].n, g[i].derp);
        cnt_acc(ca);
        /* the same datagrams through the queue and the drain; when the shared byte budget is full the producer would drop, here the
         * consumer runs first (its limits are tested below) */
        unsigned queued = 0, taken = 0;
        cnt_snap();
        for (unsigned i = 0; i < n; i++) {
            if (!queue_push(&Q, g[i].b, g[i].n, g[i].derp, 1)) {
                ml_wg_pass_t pass = {0, 0, 0}; clock_ms = 1000; clock_step_ms = 0;
                taken += wg_rx_drain(&ML, &pass, 1000, 30, 64); drains++;
                assert(g_rx_n == 0 && uxQueueMessagesWaiting(&Q) == 0);
                assert(queue_push(&Q, g[i].b, g[i].n, g[i].derp, 1));
            }
            queued++;
        }
        ml_wg_pass_t pass = {0, 0, 0}; clock_ms = 1000; clock_step_ms = 0;
        taken += wg_rx_drain(&ML, &pass, 1000, 30, 64); drains++;
        cnt_acc(cb);
        assert(taken == queued && uxQueueMessagesWaiting(&Q) == 0 && g_rx_n == 0);
        assert(A.delivered == B.delivered && A.digest == B.digest);
        assert(atomic_load(&ml_wgrx_budget.bytes) == 0);                  /* released for exactly what was popped */
    }
    for (unsigned i = 0; i < WG_RXS_COUNT; i++) {
        if (ca[i] != cb[i]) { fprintf(stderr, "seed %u: counter %s: one by one %u, drain %u\n", seed, wireguard_rx_stat_name(i), ca[i], cb[i]); abort(); }
    }
    assert(blocks_made == blocks_freed);   /* every heap block a producer queued was freed exactly once (the log catches a double free), none leaked */
    printf("  seed %u: %u rounds in %u drains, %u packets delivered identically, ordering, counters and the byte budget equal\n", seed, rounds, drains, A.delivered);
    rig_down(&A); rig_down(&B);
}

static void drain_once(void) { ml_wg_pass_t pass = {0, 0, 0}; clock_ms = 1000; clock_step_ms = 0; (void)wg_rx_drain(&ML, &pass, 1000, 30, 64); }
/* ---- a handshake is finished in its own run, between the data before it and the data after it ---- */
static void t_handshake_cuts_runs(void) {
    rig_t B; rig_up(&B);
    ML.wg_rx_queue = &Q; ML.wg_netif = &B.nif; activity_peer = NULL;
    uint8_t dg[1700], hs[148]; size_t n; unsigned counter = 0;
    memset(hs, 0x44, sizeof(hs)); hs[0] = 1; hs[1] = hs[2] = hs[3] = 0;
    const char *pattern[] = {"DDHD", "DHDD", "HDD", "DDH", "DHHD", "HH", "D", "DDDDDDDDDD"};
    const unsigned polls_expected[] = {3, 3, 2, 2, 4, 2, 1, 2};      /* one per run: [DD][H][D], [D][H][DD], [H][DD], [DD][H], [D][H][H][D], [H][H], [D], [DDDDDDDD][DD] */
    for (unsigned t = 0; t < sizeof(pattern) / sizeof(pattern[0]); t++) {
        trial_polls = 0; lock_n = 0;
        unsigned expected_lock = 0;
        for (const char *c = pattern[t]; *c; c++) {
            if (*c == 'D') { n = seal(dg, counter++, PEER_SRC, 100, false); assert(queue_push(&Q, dg, n, false, 1)); }
            else assert(queue_push(&Q, hs, sizeof(hs), false, 1));
        }
        drain_once();
        assert(trial_polls == polls_expected[t]);
        (void)expected_lock;
    }
    /* the lock sites of [DD][H][D]: begin and commit of the first run, the handshake alone, begin and commit of the last */
    lock_n = 0;
    for (const char *c = "DDHD"; *c; c++) {
        if (*c == 'D') { n = seal(dg, counter++, PEER_SRC, 100, false); assert(queue_push(&Q, dg, n, false, 1)); }
        else assert(queue_push(&Q, hs, sizeof(hs), false, 1));
    }
    drain_once();
    assert(lock_n == 5 && lock_sites[0] == TDONGLE_LOCK_WG_OTHER && lock_sites[1] == TDONGLE_LOCK_WG_COMMIT && lock_sites[2] == TDONGLE_LOCK_WG_OTHER &&
           lock_sites[3] == TDONGLE_LOCK_WG_OTHER && lock_sites[4] == TDONGLE_LOCK_WG_COMMIT && core_depth == 0);
    rig_down(&B);
}

/* ---- the drain's limits ---- */
static void t_limits(void) {
    rig_t B; rig_up(&B);
    ML.wg_rx_queue = &Q; ML.wg_netif = &B.nif;
    uint8_t dg[200]; size_t n;
    unsigned counter = 0;
    /* burst: 100 queued keepalives, burst 64 -> 64 taken, the rest stay */
    for (unsigned i = 0; i < 100; i++) { n = seal(dg, counter++, 0, 0, false); assert(queue_push(&Q, dg, n, false, 1)); }
    ml_wg_pass_t pass = {0, 0, 0}; clock_ms = 1000; clock_step_ms = 0;
    assert(wg_rx_drain(&ML, &pass, 1000, 30, 64) == 64 && uxQueueMessagesWaiting(&Q) == 36 && g_rx_n == 0);
    assert(atomic_load(&ml_wgrx_budget.bytes) == 36 * (32 + ML_WG_RX_OVERHEAD));      /* the 36 still waiting are still charged */
    /* the window: the clock moves 10 ms per read, the window is 30 ms: the drain stops early and what it took is processed */
    clock_ms = 1000; clock_step_ms = 10;
    unsigned took = wg_rx_drain(&ML, &pass, 1000, 30, 64);
    assert(took > 0 && took < 36 && g_rx_n == 0 && uxQueueMessagesWaiting(&Q) == 36 - took);
    /* the pass budget already spent: nothing is taken at all */
    ml_wg_pass_t spent = {0, WG_MGR_PASS_BUDGET_MS, 0}; clock_ms = 1000; clock_step_ms = 0;
    assert(wg_rx_drain(&ML, &spent, 1000, 30, 64) == 0 && uxQueueMessagesWaiting(&Q) == 36 - took);
    clock_ms = 1000; clock_step_ms = 0; pass.drain_ms = 0;
    assert(wg_rx_drain(&ML, &pass, 1000, 30, 64) == 36 - took && uxQueueMessagesWaiting(&Q) == 0);
    assert(atomic_load(&ml_wgrx_budget.bytes) == 0 && wireguard_rx_stat_get(WG_RXS_rx_keepalive) >= 100);
    assert(blocks_made == blocks_freed);
    rig_down(&B);
}

/* ---- drops before wireguardif, ownership, and the residency refresh ---- */
static void t_drops_and_activity(void) {
    rig_t B; rig_up(&B);
    ML.wg_rx_queue = &Q; ML.wg_netif = &B.nif;
    uint8_t dg[1700]; size_t n; unsigned counter = 0;
    memset(ML.peers, 0, sizeof(ML.peers)); trial_polls = 0; activity_peer = B.peer;
    ml_rx_stats_reset(); blocks_freed = blocks_made = 0; freed_n = 0;
    /* unknown DERP sender: dropped before any decryption, freed, counted */
    n = seal(dg, counter++, PEER_SRC, 100, false);
    assert(queue_push(&Q, dg, n, true, 0xff));
    drain_once();
    assert(ml_rx_stat_get(ML_RXS_wg_sender_unknown) == 1 && blocks_freed == 1 && B.delivered == 0 && g_rx_n == 0);
    /* no interface: freed, counted */
    ML.wg_netif = NULL;
    n = seal(dg, counter++, PEER_SRC, 100, false); assert(queue_push(&Q, dg, n, false, 1));
    drain_once();
    assert(ml_rx_stat_get(ML_RXS_wg_no_netif) == 1 && blocks_freed == 2 && B.delivered == 0);
    ML.wg_netif = &B.nif;
    /* a datagram too long for a pbuf is refused by the byte budget long before it is queued (a 70 KB block cannot reach the drain) */
    assert(ml_wgrx_admit(&ml_wgrx_budget, 70000, 1u << 20) == ML_WGRX_BYTES);
    /* residency refresh: ONLY a datagram wireguardif accepted refreshes the DERP sender */
    admit_result = 2;
    ML.peers[2].jit_used_ms = 0;
    g_now += 1000;
    n = seal(dg, counter++, PEER_SRC, 100, false); assert(queue_push(&Q, dg, n, true, 1));
    unsigned polls = trial_polls; clock_ms = 7000; clock_step_ms = 0;
    { ml_wg_pass_t pass = {0, 0, 0}; assert(wg_rx_drain(&ML, &pass, 7000, 30, 64) == 1); }
    assert(B.delivered == 1 && ML.peers[2].jit_used_ms == 7000 && trial_polls == polls + 1);      /* accepted: refreshed; one trial poll per run */
    ML.peers[2].jit_used_ms = 0; g_now += 1000;
    n = seal(dg, counter++, PEER_SRC, 100, true); assert(queue_push(&Q, dg, n, true, 1));          /* forged */
    drain_once(); assert(B.delivered == 1 && ML.peers[2].jit_used_ms == 0);
    uint64_t again = counter - 2;                                                                  /* replay of the accepted one */
    n = seal(dg, again, PEER_SRC, 100, false); assert(queue_push(&Q, dg, n, true, 1));
    g_now += 1000; drain_once(); assert(B.delivered == 1 && ML.peers[2].jit_used_ms == 0);
    n = seal(dg, counter++, 0, 0, false); assert(queue_push(&Q, dg, n, true, 1));                  /* an authenticated keepalive: not use */
    g_now += 1000; uint32_t lr = B.peer->last_rx; drain_once();
    assert(B.peer->last_rx != lr && ML.peers[2].jit_used_ms == 0 && B.delivered == 1);              /* the peer's timers moved, residency did not */
    /* two datagrams for the sender in ONE run, the first accepted, the second forged: the sender was used */
    n = seal(dg, counter++, PEER_SRC, 100, false); assert(queue_push(&Q, dg, n, true, 1));
    n = seal(dg, counter++, PEER_SRC, 100, true); assert(queue_push(&Q, dg, n, true, 1));
    g_now += 1000; clock_ms = 9000; clock_step_ms = 0;
    { ml_wg_pass_t pass = {0, 0, 0}; assert(wg_rx_drain(&ML, &pass, 9000, 30, 64) == 2); }
    assert(B.delivered == 2 && ML.peers[2].jit_used_ms == 9000);
    assert(atomic_load(&ml_wgrx_budget.bytes) == 0);
    assert(blocks_made == blocks_freed);
    activity_peer = NULL;
    rig_down(&B);
}

int main(void) {
    for (unsigned seed = 1; seed <= 4; seed++) t_equivalence(seed, 300);
    t_handshake_cuts_runs();
    t_limits();
    t_drops_and_activity();
    printf("wg_mgr rx drain ok\n");
    return 0;
}
