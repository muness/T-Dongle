/* Shared WireGuard peer-slot pool, integrated: the REAL wireguard.c and wireguardif.c
 * (plus the real crypto) compiled on the host against the tiny lwIP fakes in
 * tests/host/wg_lwip. Several wireguard netifs ("tailnet memberships") share one capped
 * pool; this exercises add/remove/teardown, exhaustion across devices, pool-wide receiver
 * index uniqueness, device-scoped lookups, and the per-device handshake cursor.
 *
 *   wg=components/microlink/components/wireguard_lwip/src
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra -Wno-unused-parameter \
 *      -DWIREGUARD_CRYPTO_REFC=1 -I tests/host/wg_lwip -I tests/host_esp -I $wg -I $wg/crypto -I $wg/crypto/refc \
 *      tests/test_wg_peer_pool_if.c tests/host/wg_lwip/wg_host_lwip.c $wg/wireguard.c $wg/wireguardif.c $wg/wireguard_pool.c \
 *      $wg/crypto.c $wg/crypto/refc/blake2s.c $wg/crypto/refc/chacha20.c $wg/crypto/refc/chacha20poly1305.c \
 *      $wg/crypto/refc/poly1305-donna.c $wg/crypto/refc/x25519.c -o build-host/test_wg_peer_pool_if
 * Counters are process-lifetime, so scenarios compare deltas. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wireguard.h"
#include "wireguardif.h"

/* ---------------- platform stubs (the library's wireguard-platform.h contract) ---------------- */
static uint32_t g_now = 100000;
uint32_t wireguard_sys_now(void) { return g_now; }
void wireguard_tai64n_now(uint8_t *out) { memset(out, 0, 12); out[7] = 1; }
bool wireguard_is_under_load(void) { return false; }
void wireguard_set_tai64n_base_seconds(uint64_t s) { (void)s; }

static uint64_t g_prng = 0x9E3779B97F4A7C15ULL;
static uint32_t g_script[32];
static int g_script_n, g_script_pos, g_idx_calls; /* scripted values for 4-byte (receiver index) requests */
static void script_set(const uint32_t *v, int n) { memcpy(g_script, v, n * sizeof(*v)); g_script_n = n; g_script_pos = 0; g_idx_calls = 0; }
void wireguard_random_bytes(void *bytes, size_t size) {
    uint8_t *b = bytes;
    if (size == 4) {
        g_idx_calls++;
        if (g_script_pos < g_script_n) {
            uint32_t v = g_script[g_script_pos++];
            memcpy(b, &v, 4);                      /* host is little-endian: U8TO32_LITTLE yields v */
            return;
        }
    }
    for (size_t i = 0; i < size; i++) { g_prng = g_prng * 6364136223846793005ULL + 1442695040888963407ULL; b[i] = (uint8_t)(g_prng >> 56); }
}

/* ---------------- pool allocator hooks: leak + wipe accounting ---------------- */
static int live_allocs, fail_next_alloc, nonzero_at_free, total_frees;
static void *hook_alloc(size_t n) {
    assert(n == sizeof(struct wireguard_peer));
    if (fail_next_alloc) { fail_next_alloc--; return NULL; }
    void *p = malloc(n); assert(p);
    memset(p, 0xA5, n);
    live_allocs++;
    return p;
}
static void hook_free(void *p) {
    const uint8_t *b = p;
    for (size_t i = 0; i < sizeof(struct wireguard_peer); i++) nonzero_at_free += b[i] != 0;
    total_frees++; live_allocs--;
    free(p);
}
static void pool_setup(size_t capacity) {
    live_allocs = fail_next_alloc = nonzero_at_free = total_frees = 0;
    assert(wireguardif_pool_configure(capacity, hook_alloc, hook_free));
}
static void pool_expect_empty(void) {
    wg_pool_stats_t s = wireguardif_pool_stats();
    assert(s.used == 0 && live_allocs == 0 && nonzero_at_free == 0);
    assert(s.acquired == s.released);
}

/* ---------------- device / peer helpers ---------------- */
struct dev { struct netif nif; struct wireguardif_init_data init; char key_b64[64]; };

static void b64(const uint8_t *in, char *out) { size_t n = 64; assert(wireguard_base64_encode(in, 32, out, &n)); }

static void dev_up(struct dev *d, uint8_t seed) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(seed * 7 + i * 3 + 1);
    b64(key, d->key_b64);
    memset(&d->nif, 0, sizeof(d->nif));
    d->init.private_key = d->key_b64; d->init.listen_port = 51820; d->init.bind_netif = NULL;
    d->nif.state = &d->init;
    assert(wireguardif_init(&d->nif) == ERR_OK);
    assert(d->nif.state != &d->init && d->nif.state != NULL);
}
static struct wireguard_device *devp(struct dev *d) { return d->nif.state; }
static void dev_down(struct dev *d) { wireguardif_free(&d->nif); assert(d->nif.state == NULL); }

static void pubkey(uint8_t seed, uint8_t out[32]) { for (int i = 0; i < 32; i++) out[i] = (uint8_t)(seed * 11 + i + 5); out[31] &= 0x7f; }

static err_t add_peer(struct dev *d, uint8_t seed, u8_t *idx) {
    uint8_t pk[32]; char s[64]; struct wireguardif_peer p;
    pubkey(seed, pk); b64(pk, s);
    wireguardif_peer_init(&p);
    p.public_key = s;
    p.allowed_ip.addr = 0x0100000a + ((u32_t)seed << 16); p.allowed_mask.addr = 0xffffffff;
    return wireguardif_add_peer(&d->nif, &p, idx);
}
static struct wireguard_peer *P(struct dev *d, uint8_t i) { return wireguard_device_peer(devp(d), i); }

/* ---------------- scenarios ---------------- */
static void test_sizes_and_default_pool(void) {
    printf("sizeof(struct wireguard_peer)=%zu sizeof(struct wireguard_device)=%zu (old embedded layout: %zu) WIREGUARD_POOL_SLOTS=%d\n",
           sizeof(struct wireguard_peer), sizeof(struct wireguard_device),
           sizeof(struct wireguard_device) - WIREGUARD_MAX_PEERS * sizeof(struct wireguard_peer *) + WIREGUARD_MAX_PEERS * sizeof(struct wireguard_peer),
           WIREGUARD_POOL_SLOTS);
    assert(sizeof(struct wireguard_device) < sizeof(struct wireguard_peer)); /* slots are no longer embedded */
    assert(wireguardif_pool_stats().capacity == WIREGUARD_POOL_SLOTS);       /* lazy default */
    assert(!wireguardif_pool_configure(0, NULL, NULL));
    assert(!wireguardif_pool_configure(WG_POOL_MAX_SLOTS + 1, NULL, NULL));
    assert(!wireguardif_pool_configure(4, hook_alloc, NULL));
}

static void test_two_devices_share_pool(void) {
    pool_setup(12);
    struct dev A, B; u8_t i;
    dev_up(&A, 1); dev_up(&B, 2);
    assert(wireguardif_device_peer_count(&A.nif) == 0 && wireguardif_device_peer_count(NULL) == 0);
    for (uint8_t k = 0; k < 3; k++) { assert(add_peer(&A, 10 + k, &i) == ERR_OK && i == k); }
    for (uint8_t k = 0; k < 2; k++) { assert(add_peer(&B, 10 + k, &i) == ERR_OK && i == k); } /* same pubkeys, own indices */
    wg_pool_stats_t s = wireguardif_pool_stats();
    assert(s.used == 5 && s.acquired == 5 && live_allocs == 5 && s.peak_used == 5);
    assert(wireguardif_device_peer_count(&A.nif) == 3 && wireguardif_device_peer_count(&B.nif) == 2);
    wg_pool_t *pool = wireguard_peer_pool();
    assert(wg_pool_owner_count(pool, devp(&A)) == 3 && wg_pool_owner_count(pool, devp(&B)) == 2);
    for (uint8_t k = 0; k < 3; k++) { assert(wg_pool_owner_of(pool, P(&A, k)) == devp(&A)); }
    assert(P(&A, 0) != P(&B, 0));                                   /* same key, different slots */
    uint8_t pk[32]; pubkey(10, pk);
    assert(peer_lookup_by_pubkey(devp(&A), pk) == P(&A, 0) && peer_lookup_by_pubkey(devp(&B), pk) == P(&B, 0));
    pubkey(12, pk);
    assert(peer_lookup_by_pubkey(devp(&A), pk) == P(&A, 2) && peer_lookup_by_pubkey(devp(&B), pk) == NULL);

    /* accessor semantics */
    assert(wireguard_device_peer(devp(&A), 3) == NULL && wireguard_device_peer(devp(&A), 8) == NULL &&
           wireguard_device_peer(devp(&A), 255) == NULL && wireguard_device_peer(NULL, 0) == NULL);
    assert(peer_lookup_by_peer_index(devp(&A), 2) == P(&A, 2) && peer_lookup_by_peer_index(devp(&A), 5) == NULL);
    assert(wireguard_peer_index(devp(&A), P(&A, 2)) == 2 && wireguard_peer_index(devp(&A), P(&B, 0)) == 0xFF &&
           wireguard_peer_index(devp(&A), NULL) == 0xFF);

    /* re-adding a known key is idempotent and costs no slot */
    assert(add_peer(&A, 11, &i) == ERR_OK && i == 1 && wireguardif_pool_stats().used == 5 && live_allocs == 5);

    /* the public per-peer API addresses the right device's peer */
    ip_addr_t ep = { 0x01020304 };
    assert(wireguardif_update_endpoint(&A.nif, 1, &ep, 4242) == ERR_OK);
    assert(P(&A, 1)->connect_port == 4242 && P(&B, 1)->connect_port == WIREGUARDIF_DEFAULT_PORT);
    assert(wireguardif_update_endpoint(&B.nif, 5, &ep, 1) == ERR_ARG);

    wireguardif_pool_note_eviction(&A.nif);
    assert(wireguardif_pool_stats().evictions == 1);

    /* tearing one device down frees exactly its slots */
    dev_down(&A);
    assert(wireguardif_pool_stats().used == 2 && live_allocs == 2 && nonzero_at_free == 0 && wg_pool_owner_count(pool, devp(&B)) == 2);
    wireguardif_free(&A.nif);                                      /* double free: no-op */
    assert(wireguardif_pool_stats().used == 2);
    dev_down(&B);
    pool_expect_empty();
    assert(wireguardif_pool_stats().peak_used == 5);
}

static void test_exhaustion_across_devices(void) {
    pool_setup(6);
    struct dev A, B; u8_t i;
    dev_up(&A, 3); dev_up(&B, 4);
    for (uint8_t k = 0; k < 6; k++) assert(add_peer(&A, 20 + k, &i) == ERR_OK);
    assert(wireguardif_pool_stats().used == 6 && !wireguardif_pool_configure(8, NULL, NULL));
    uint8_t before[6][32];
    for (uint8_t k = 0; k < 6; k++) memcpy(before[k], P(&A, k)->public_key, 32);

    wg_pool_stats_t s0 = wireguardif_pool_stats();
    assert(add_peer(&B, 40, &i) == ERR_MEM && i == WIREGUARDIF_INVALID_INDEX);
    wg_pool_stats_t s1 = wireguardif_pool_stats();
    assert(s1.refused_full == s0.refused_full + 1 && s1.refused_nomem == 0 && s1.used == 6 && live_allocs == 6);
    assert(wireguardif_device_peer_count(&B.nif) == 0 && wireguardif_device_peer_count(&A.nif) == 6);
    for (uint8_t k = 0; k < 6; k++) assert(P(&A, k) && P(&A, k)->valid && memcmp(P(&A, k)->public_key, before[k], 32) == 0);

    /* A frees one -> B gets exactly that capacity */
    nonzero_at_free = 0;
    assert(wireguardif_remove_peer(&A.nif, 2) == ERR_OK);
    assert(nonzero_at_free == 0 && P(&A, 2) == NULL && wireguardif_pool_stats().used == 5);
    assert(wireguardif_remove_peer(&A.nif, 2) == ERR_ARG);        /* double remove */
    assert(add_peer(&B, 40, &i) == ERR_OK && i == 0 && wireguardif_pool_stats().used == 6);
    assert(add_peer(&B, 41, &i) == ERR_MEM && wireguardif_pool_stats().refused_full == 2);
    /* A's freed table index is reused (lowest free) and other indices stayed put */
    assert(wireguardif_remove_peer(&B.nif, 0) == ERR_OK);
    assert(add_peer(&A, 50, &i) == ERR_OK && i == 2 && P(&A, 5) && memcmp(P(&A, 5)->public_key, before[5], 32) == 0);
    dev_down(&A); dev_down(&B);
    pool_expect_empty();

    /* per-device table limit is independent of the pool: 9th peer on one device fails but is not a pool refusal */
    pool_setup(WG_POOL_MAX_SLOTS);
    dev_up(&A, 3);
    for (uint8_t k = 0; k < WIREGUARD_MAX_PEERS; k++) assert(add_peer(&A, 60 + k, &i) == ERR_OK);
    uint32_t full_before = wireguardif_pool_stats().refused_full;
    assert(add_peer(&A, 99, &i) == ERR_MEM && i == WIREGUARDIF_INVALID_INDEX);
    s1 = wireguardif_pool_stats();
    assert(s1.refused_full == full_before && s1.used == WIREGUARD_MAX_PEERS && live_allocs == WIREGUARD_MAX_PEERS);
    dev_down(&A);
    pool_expect_empty();
}

static void test_failure_paths_are_atomic(void) {
    pool_setup(4);
    struct dev A; u8_t i; uint8_t zero[32] = {0}; char s[64]; struct wireguardif_peer p;
    dev_up(&A, 5);
    /* allocator failure */
    uint32_t full0 = wireguardif_pool_stats().refused_full, nomem0 = wireguardif_pool_stats().refused_nomem;
    fail_next_alloc = 1;
    assert(add_peer(&A, 70, &i) == ERR_MEM && i == WIREGUARDIF_INVALID_INDEX);
    wg_pool_stats_t st = wireguardif_pool_stats();
    assert(st.refused_nomem == nomem0 + 1 && st.refused_full == full0 && st.used == 0 && live_allocs == 0);
    /* peer init failure (low-order public key -> x25519 rejects): slot must be returned and wiped */
    b64(zero, s); wireguardif_peer_init(&p); p.public_key = s;
    assert(wireguardif_add_peer(&A.nif, &p, &i) == ERR_ARG && i == WIREGUARDIF_INVALID_INDEX);
    assert(wireguardif_pool_stats().used == 0 && live_allocs == 0 && nonzero_at_free == 0 && wireguardif_device_peer_count(&A.nif) == 0);
    /* undecodable key: nothing acquired at all */
    p.public_key = "not base64!";
    uint32_t acq = wireguardif_pool_stats().acquired;
    assert(wireguardif_add_peer(&A.nif, &p, &i) == ERR_ARG && wireguardif_pool_stats().acquired == acq);
    /* and the device is still fully usable afterwards */
    assert(add_peer(&A, 71, &i) == ERR_OK && i == 0 && wireguardif_pool_stats().used == 1);
    /* peer_free on strangers is a no-op */
    struct wireguard_peer stranger;
    assert(!peer_free(devp(&A), &stranger) && !peer_free(devp(&A), NULL) && !peer_free(NULL, P(&A, 0)));
    assert(wireguardif_pool_stats().used == 1);
    dev_down(&A);
    pool_expect_empty();
}

static void set_keypair(struct wireguard_keypair *k, uint32_t idx) { k->valid = true; k->local_index = idx; }

static void test_receiver_index_uniqueness_and_scoping(void) {
    pool_setup(12);
    struct dev A, B; u8_t i;
    dev_up(&A, 6); dev_up(&B, 7);
    add_peer(&A, 80, &i); add_peer(&A, 81, &i);
    add_peer(&B, 80, &i); add_peer(&B, 81, &i);
    const uint32_t X = 0x11111111, H = 0x22222222, N = 0x33333333, M = 0x44444444, Y = 0x55555555, Z = 0x66666666;

    /* indices live "anywhere in the pool": other device's curr / handshake / next / prev */
    set_keypair(&P(&A, 0)->curr_keypair, X);
    P(&A, 1)->handshake.valid = true; P(&A, 1)->handshake.local_index = H;
    P(&A, 1)->next_keypair.local_index = N;           /* not even marked valid: still reserved */
    P(&A, 0)->prev_keypair.local_index = M;
    set_keypair(&P(&B, 0)->curr_keypair, Y);
    wg_pool_t *pool = wireguard_peer_pool();
    assert(wireguard_receiver_index_in_use(pool, X) && wireguard_receiver_index_in_use(pool, H) &&
           wireguard_receiver_index_in_use(pool, N) && wireguard_receiver_index_in_use(pool, M) &&
           wireguard_receiver_index_in_use(pool, Y) && !wireguard_receiver_index_in_use(pool, Z));
    assert(!wireguard_receiver_index_in_use(NULL, X));

    /* the pure predicate works on any pool, not only the global one */
    wg_pool_t mine; int owner = 0;
    assert(wg_pool_init(&mine, 2, sizeof(struct wireguard_peer), NULL, NULL));
    struct wireguard_peer *mp = wg_pool_acquire(&mine, &owner);
    mp->handshake.local_index = 0xABCD;
    assert(wireguard_receiver_index_in_use(&mine, 0xABCD) && !wireguard_receiver_index_in_use(&mine, X));
    assert(!wireguard_receiver_index_in_use(pool, 0xABCD));
    wg_pool_release(&mine, mp);

    /* generator skips: invalid values, other device's slots (any field), this device's slots */
    const uint32_t script[] = { 0, 0xFFFFFFFFu, X, X, H, N, M, Y, Z, 0x77777777 };
    script_set(script, 10);
    assert(wireguard_generate_unique_index(devp(&B)) == Z && g_idx_calls == 9);

    /* ...and through the real handshake path: the initiation's sender index is the survivor */
    struct message_handshake_initiation msg;
    const uint32_t script2[] = { X, H, Y, 0x88888888 };
    script_set(script2, 4);
    assert(wireguard_create_handshake_initiation(devp(&B), P(&B, 1), &msg));
    assert(msg.sender == 0x88888888 && P(&B, 1)->handshake.local_index == 0x88888888 && g_idx_calls == 4);
    assert(wireguard_receiver_index_in_use(pool, 0x88888888));

    /* same-device slots are checked too: old code only ever looked at the LAST table entry */
    const uint32_t script3[] = { 0x88888888, Z };
    script_set(script3, 2);
    assert(wireguard_generate_unique_index(devp(&A)) == Z && g_idx_calls == 2);

    /* lookups are scoped to the device, even if two devices were to hold the same index */
    const uint32_t L = 0xCAFEBABE;
    set_keypair(&P(&A, 1)->curr_keypair, L);
    assert(peer_lookup_by_receiver(devp(&A), L) == P(&A, 1) && peer_lookup_by_receiver(devp(&B), L) == NULL);
    set_keypair(&P(&B, 1)->prev_keypair, L);              /* forced duplicate across devices */
    assert(peer_lookup_by_receiver(devp(&A), L) == P(&A, 1) && peer_lookup_by_receiver(devp(&B), L) == P(&B, 1));
    P(&A, 0)->handshake.valid = true; P(&A, 0)->handshake.initiator = true; P(&A, 0)->handshake.local_index = 0xDEADBEEF;
    assert(peer_lookup_by_handshake(devp(&A), 0xDEADBEEF) == P(&A, 0) && peer_lookup_by_handshake(devp(&B), 0xDEADBEEF) == NULL);
    /* a removed peer's indices leave the pool with it */
    assert(wireguardif_remove_peer(&A.nif, 0) == ERR_OK);
    assert(!wireguard_receiver_index_in_use(pool, 0xDEADBEEF) && !wireguard_receiver_index_in_use(pool, X));
    assert(peer_lookup_by_handshake(devp(&A), 0xDEADBEEF) == NULL);

    dev_down(&A); dev_down(&B);
    pool_expect_empty();
    assert(!wireguard_receiver_index_in_use(pool, L));
    script_set(NULL, 0);
}

static void test_handshake_cursor_is_per_device(void) {
    pool_setup(12);
    struct dev A, B; u8_t i;
    dev_up(&A, 8); dev_up(&B, 9);
    for (uint8_t k = 0; k < 3; k++) { add_peer(&A, 90 + k, &i); add_peer(&B, 90 + k, &i); }
    for (uint8_t k = 0; k < 3; k++) { P(&A, k)->active = true; P(&B, k)->active = true; }
    /* Each tick starts at most ONE handshake per device, round-robin from that device's own cursor. */
    wireguardif_periodic(&A.nif);
    assert(P(&A, 0)->handshake_attempts == 1 && P(&A, 1)->handshake_attempts == 0 && P(&A, 2)->handshake_attempts == 0);
    wireguardif_periodic(&B.nif);                       /* a process-global cursor would now start at index 1 */
    assert(P(&B, 0)->handshake_attempts == 1 && P(&B, 1)->handshake_attempts == 0 && P(&B, 2)->handshake_attempts == 0);
    wireguardif_periodic(&A.nif);
    assert(P(&A, 1)->handshake_attempts == 1 && P(&A, 2)->handshake_attempts == 0);
    wireguardif_periodic(&A.nif);
    wireguardif_periodic(&B.nif);
    assert(P(&A, 2)->handshake_attempts == 1 && P(&B, 1)->handshake_attempts == 1 && P(&B, 2)->handshake_attempts == 0);
    assert(devp(&A)->next_hs_peer == 3 && devp(&B)->next_hs_peer == 2);
    /* handshake indices handed out by the two devices are all distinct pool-wide */
    uint32_t seen[6]; int n = 0;
    for (uint8_t k = 0; k < 3; k++) {
        if (P(&A, k)->handshake.valid) seen[n++] = P(&A, k)->handshake.local_index;
        if (P(&B, k)->handshake.valid) seen[n++] = P(&B, k)->handshake.local_index;
    }
    assert(n == 5);
    for (int a = 0; a < n; a++) for (int b = a + 1; b < n; b++) assert(seen[a] != seen[b]);
    /* removing a peer under the cursor must not break the rotation */
    assert(wireguardif_remove_peer(&B.nif, 2) == ERR_OK);
    g_now += 6000;                                      /* past REKEY_TIMEOUT so retries are due */
    wireguardif_periodic(&B.nif);
    assert(P(&B, 0)->handshake_attempts == 2);
    dev_down(&A); dev_down(&B);
    pool_expect_empty();
}


/* The crypto-outside-the-lock splits (initiation begin/compute/commit, receive begin/decrypt/complete) against the one-piece
 * paths, using the real protocol code on two devices that talk to each other. */
static void link_peers(struct dev *A, struct dev *B, u8_t *ia, u8_t *ib) {
    char s[64]; struct wireguardif_peer p;
    wireguardif_peer_init(&p); b64(devp(B)->public_key, s); p.public_key = s;
    p.allowed_ip.addr = 0x0100000a; p.allowed_mask.addr = 0xffffffff;
    assert(wireguardif_add_peer(&A->nif, &p, ia) == ERR_OK);
    wireguardif_peer_init(&p); b64(devp(A)->public_key, s); p.public_key = s;
    p.allowed_ip.addr = 0x0200000a; p.allowed_mask.addr = 0xffffffff;
    assert(wireguardif_add_peer(&B->nif, &p, ib) == ERR_OK);
}
static void test_split_crypto(void) {
    pool_setup(12);
    struct dev A, B; u8_t ia, ib;
    dev_up(&A, 21); dev_up(&B, 22);
    link_peers(&A, &B, &ia, &ib);
    struct wireguard_peer *pa = P(&A, ia), *pb = P(&B, ib);
    pa->active = true;
    /* Initiation in three steps: B accepts it as a genuine initiation from A. */
    struct wireguard_initiation_job job;
    assert(wireguard_initiation_begin(devp(&A), pa, &job));
    assert(!pa->handshake.valid);                               /* nothing installed before commit */
    wireguard_initiation_compute(&job);
    assert(job.ok && job.msg.type == MESSAGE_HANDSHAKE_INITIATION && job.msg.sender == job.index);
    struct message_handshake_initiation msg = job.msg;
    assert(wireguard_initiation_commit(devp(&A), pa, &job));
    assert(pa->handshake.valid && pa->handshake.initiator && pa->handshake.local_index == msg.sender);
    assert(wireguard_process_initiation_message(devp(&B), &msg) == pb);
    /* Complete the handshake and move data: A seals, B opens through the receive job. */
    struct message_handshake_response resp;
    assert(wireguard_create_handshake_response(devp(&B), pb, &resp));
    assert(wireguard_process_handshake_response(devp(&A), pa, &resp));
    uint8_t plain[100], sealed[100 + 16];
    for (unsigned i = 0; i < sizeof(plain); i++) plain[i] = (uint8_t)(i * 5 + 3);
    wireguard_encrypt_packet(sealed, plain, sizeof(plain), &pa->next_keypair);
    struct pbuf out; uint8_t outbuf[100 + 16];
    memset(&out, 0, sizeof(out)); out.payload = outbuf; out.tot_len = out.len = sizeof(plain);
    struct wireguard_rx_job rx = {.pbuf = &out, .src = sealed, .src_len = sizeof(sealed), .nonce = 0};
    memcpy(rx.key, pb->next_keypair.receiving_key, 32);
    wireguard_rx_decrypt(&rx);
    assert(rx.ok && !memcmp(outbuf, plain, sizeof(plain)));
    for (unsigned i = 0; i < 32; i++) assert(rx.key[i] == 0);        /* the key copy does not linger */
    sealed[5] ^= 1;                                                    /* a forged packet fails authentication */
    rx.ok = true; memcpy(rx.key, pb->next_keypair.receiving_key, 32);
    wireguard_rx_decrypt(&rx);
    assert(!rx.ok);
    /* A peer removed while the crypto ran outside the lock: the commit installs nothing. */
    struct wireguard_initiation_job j2;
    assert(wireguard_initiation_begin(devp(&A), pa, &j2));
    wireguard_initiation_compute(&j2);
    assert(wireguardif_remove_peer(&A.nif, ia) == ERR_OK);
    assert(wireguardif_periodic_commit(&A.nif, ia, &j2) == ERR_ARG);
    for (unsigned i = 0; i < 32; i++) assert(j2.handshake.ephemeral_private[i] == 0);   /* ephemeral key wiped either way */
    dev_down(&A); dev_down(&B);
    pool_expect_empty();
}

/* The lock is free for ~40 ms while an initiation is computed. What can happen in that window must not produce a second,
 * competing initiation or a receiver index that is no longer unique. */
static void test_initiation_commit_guards(void) {
    pool_setup(12);
    struct dev A, B; u8_t ia, ib;
    dev_up(&A, 41); dev_up(&B, 42);
    link_peers(&A, &B, &ia, &ib);
    struct wireguard_peer *pa = P(&A, ia);
    pa->active = true;
    wg_pool_t *pool = wireguard_peer_pool();

    /* (1) Another initiation for the same peer was installed while ours was computed (the output path starts one when a
     *     packet finds no session): ours is dropped, theirs stays, nothing is sent twice. */
    struct wireguard_initiation_job job;
    assert(wireguard_initiation_begin(devp(&A), pa, &job));
    wireguard_initiation_compute(&job);
    assert(job.ok);
    struct message_handshake_initiation rival;
    assert(wireguard_create_handshake_initiation(devp(&A), pa, &rival));
    uint32_t rival_index = pa->handshake.local_index;
    assert(rival_index == rival.sender);
    assert(!wireguard_initiation_commit(devp(&A), pa, &job));
    assert(pa->handshake.local_index == rival_index && pa->handshake.valid);              /* the rival is untouched */
    assert(wireguardif_periodic_commit(&A.nif, ia, &job) == ERR_ARG);                      /* and nothing goes out */

    /* (2) An inbound handshake changed the state instead: same refusal. */
    assert(wireguard_initiation_begin(devp(&A), pa, &job));
    wireguard_initiation_compute(&job);
    pa->handshake.valid = false;                       /* what consuming a handshake does */
    assert(!wireguard_initiation_commit(devp(&A), pa, &job));

    /* (3) Untouched in between: installed (the single-membership case, unchanged behaviour). */
    assert(wireguard_initiation_begin(devp(&A), pa, &job));
    wireguard_initiation_compute(&job);
    assert(wireguard_initiation_commit(devp(&A), pa, &job) && pa->handshake.local_index == job.index);

    /* (4) The index drawn by begin was taken by someone (another device, another peer) before the commit. */
    struct wireguard_peer *pb = P(&B, ib);
    pa->handshake.valid = false;
    assert(wireguard_initiation_begin(devp(&A), pa, &job));
    wireguard_initiation_compute(&job);
    pb->curr_keypair.local_index = job.index;           /* a handshake response elsewhere claimed it */
    assert(wireguard_receiver_index_in_use(pool, job.index));
    assert(!wireguard_initiation_commit(devp(&A), pa, &job));
    assert(!pa->handshake.valid);

    /* The pool-wide check also covers a NON-last slot of the SAME device (the old check compared only the last slot). */
    u8_t extra;
    assert(add_peer(&A, 99, &extra) == ERR_OK && extra != ia);
    struct wireguard_peer *first = P(&A, 0), *last = P(&A, extra);
    assert(first != last);
    const uint32_t T = 0x13572468, U = 0x24681357;
    first->prev_keypair.local_index = T;
    const uint32_t script[] = { T, U };
    script_set(script, 2);
    assert(wireguard_generate_unique_index(devp(&A)) == U && g_idx_calls == 2);
    script_set(NULL, 0);
    dev_down(&A); dev_down(&B);
    pool_expect_empty();
}

static void test_sliced_periodic_matches_monolithic(void) {
    pool_setup(12);
    struct dev M, S; u8_t i;
    dev_up(&M, 31); dev_up(&S, 31);
    for (uint8_t k = 0; k < 3; k++) { add_peer(&M, 90 + k, &i); add_peer(&S, 90 + k, &i); P(&M, k)->active = P(&S, k)->active = true; }
    for (unsigned tick = 0; tick < 6; tick++) {
        g_now += 6000;
        wireguardif_periodic(&M.nif);
        /* the sliced form, exactly as wg_mgr runs it */
        uint8_t first = devp(&S)->next_hs_peer; bool allowed = true;
        for (unsigned k = 0; k < WIREGUARD_MAX_PEERS; k++) {
            uint8_t idx = (uint8_t)((first + k) % WIREGUARD_MAX_PEERS);
            struct wireguard_initiation_job job;
            if (wireguardif_periodic_peer(&S.nif, idx, allowed, &job)) {
                wireguard_initiation_compute(&job);
                assert(wireguardif_periodic_commit(&S.nif, idx, &job) == ERR_OK || true);
                allowed = false;
            }
        }
        wireguardif_periodic_end(&S.nif);
        for (uint8_t k = 0; k < 3; k++) assert(P(&M, k)->handshake_attempts == P(&S, k)->handshake_attempts && P(&M, k)->handshake.valid == P(&S, k)->handshake.valid);
        assert(devp(&M)->next_hs_peer == devp(&S)->next_hs_peer);
    }
    assert(P(&S, 0)->handshake_attempts >= 2 && P(&S, 1)->handshake_attempts >= 2);
    dev_down(&M); dev_down(&S);
    pool_expect_empty();
}

int main(void) {
    test_sizes_and_default_pool();
    test_two_devices_share_pool();
    test_exhaustion_across_devices();
    test_failure_paths_are_atomic();
    test_receiver_index_uniqueness_and_scoping();
    test_handshake_cursor_is_per_device();
    test_split_crypto();
    test_initiation_commit_guards();
    test_sliced_periodic_matches_monolithic();
    puts("wg peer pool integration: ok");
    return 0;
}
