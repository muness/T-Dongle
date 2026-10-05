/* The inbound WireGuard data path on the REAL wireguardif.c / wireguard.c (host fakes for lwIP): every way a transport datagram
 * can leave it increments exactly its own counter (wireguard_stats.h) and nothing else, through both entry points (the
 * wg_mgr split begin / decrypt / complete path and the one-piece network_rx path), the terminal counters always add up to
 * `rx_data`, replay protection is applied before anything it could change, and reordered arrival is accepted up to the window.
 *
 *   wg=components/microlink/components/wireguard_lwip/src
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -w -DWIREGUARD_CRYPTO_REFC=1 \
 *      -I tests/host/wg_lwip -I tests/host_esp -I $wg -I $wg/crypto -I $wg/crypto/refc tests/test_wg_rx_counters.c \
 *      tests/host/wg_lwip/wg_host_lwip.c $wg/wireguard.c $wg/wireguardif.c $wg/wireguard_pool.c $wg/crypto.c \
 *      $wg/crypto/refc/{blake2s,chacha20,chacha20poly1305,poly1305-donna,x25519}.c -o build-host/test_wg_rx_counters */
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
extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

#define PEER_SRC 0x0100010au      /* network-order bytes 10.1.0.1: the peer's allowed address */
#define OTHER_SRC 0x0200010au     /* 10.1.0.2: not allowed */
#define LOCAL_INDEX 0xA1B2C3D4u
#define NEXT_INDEX 0x0BADF00Du

struct dev { struct netif nif; struct wireguardif_init_data init; char key_b64[64]; };
static struct dev D;
static struct wireguard_peer *PEER;

/* what netif->input saw */
static unsigned delivered, input_calls;
static err_t input_result = ERR_OK;
static uint8_t last_input[1600];
static size_t last_input_len;
static err_t capture_input(struct pbuf *p, struct netif *inp) {
    (void)inp;
    input_calls++;
    if (input_result != ERR_OK) return input_result;      /* lwIP contract: the caller frees on an error */
    assert(p->tot_len <= sizeof(last_input));
    memcpy(last_input, p->payload, p->tot_len); last_input_len = p->tot_len;
    delivered++;
    pbuf_free(p);                                          /* and the consumer frees on success */
    return ERR_OK;
}

static void rig_up(void) {
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
    p.public_key = s; p.allowed_ip.addr = PEER_SRC; p.allowed_mask.addr = 0xffffffff;
    assert(wireguardif_add_peer(&D.nif, &p, &idx) == ERR_OK);
    PEER = wireguard_device_peer((struct wireguard_device *)D.nif.state, idx);
}
static void rig_down(void) { wireguardif_free(&D.nif); }

static void key_for(uint8_t key[32], uint32_t index) { for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x30 + i + (index & 0xff)); }
static void set_receiving(struct wireguard_keypair *k, uint32_t index) {
    memset(k, 0, sizeof(*k));
    k->valid = true; k->initiator = false; k->keypair_millis = g_now; k->local_index = index; k->remote_index = 0x11223344;
    k->receiving_valid = true; k->sending_valid = true; k->sending_counter = 0;
    key_for(k->receiving_key, index);
    wireguard_replay_reset(&k->replay);
}

/* ---- datagram construction ---- */
static size_t ip_packet(uint8_t *b, uint32_t src, size_t total, unsigned version, size_t pad) {
    memset(b, 0, total + pad);
    b[0] = (uint8_t)(version << 4 | 5); b[2] = (uint8_t)(total >> 8); b[3] = (uint8_t)total; b[8] = 64; b[9] = 17;
    memcpy(b + 12, &src, 4); b[16] = 10; b[17] = 9; b[18] = 9; b[19] = 9;
    for (size_t i = 20; i < total; i++) b[i] = (uint8_t)(i * 7);
    return total;
}
/* [type 4][receiver][counter][ChaCha20-Poly1305(plaintext zero-padded to 16)]. `plain_len` may be 0 (a keepalive). */
static size_t seal_raw(uint8_t *out, uint32_t receiver, uint64_t counter, const uint8_t *plain, size_t plain_len, bool pad) {
    size_t padded = pad ? WIREGUARDIF_DATA_PAD(plain_len) : plain_len;    /* a hostile peer need not pad */
    uint8_t buf[1600]; memset(buf, 0, sizeof(buf)); if (plain_len) memcpy(buf, plain, plain_len);
    memset(out, 0, 16);
    out[0] = 4;
    memcpy(out + 4, &receiver, 4);
    for (int i = 0; i < 8; i++) out[8 + i] = (uint8_t)(counter >> (8 * i));
    uint8_t key[32]; key_for(key, receiver);
    wireguard_aead_encrypt(out + 16, buf, padded, NULL, 0, counter, key);
    return 16 + padded + WIREGUARD_AUTHTAG_LEN;
}
static size_t seal(uint8_t *out, uint32_t receiver, uint64_t counter, const uint8_t *plain, size_t plain_len) {
    return seal_raw(out, receiver, counter, plain, plain_len, true);
}
static size_t good(uint8_t *dg, uint32_t receiver, uint64_t counter, size_t ip_len) {
    uint8_t ip[1500]; ip_packet(ip, PEER_SRC, ip_len, 4, 0);
    return seal(dg, receiver, counter, ip, ip_len);
}

/* ---- delivery through either entry point ---- */
static ip_addr_t from_addr(unsigned n) { ip_addr_t a = {.addr = 0x0400a8c0u + (n << 24)}; return a; }
static int inject_alloc_fail;      /* lwIP runs out of memory right after the input pbuf was allocated */
static void (*between_hook)(void *);
static void *between_arg;
static void deliver(const uint8_t *dg, size_t len, bool split, unsigned from) {
    ip_addr_t addr = from_addr(from);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    assert(p); memcpy(p->payload, dg, len);
    wg_host_pbuf_fail = inject_alloc_fail;
    if (split) {
        struct wireguard_rx_job job;
        if (wireguardif_rx_begin(&D.nif, p, &addr, 41641, &job)) {
            wireguard_rx_decrypt(&job);
            if (between_hook) between_hook(between_arg);
            wireguardif_rx_complete(&D.nif, &addr, 41641, &job);
        }
    } else {
        wireguardif_network_rx(D.nif.state, NULL, p, &addr, 41641);   /* consumes p */
    }
    wg_host_pbuf_fail = 0;
}

/* ---- counters ---- */
static uint32_t before[WG_RXS_COUNT];
static void snap(void) { for (unsigned i = 0; i < WG_RXS_COUNT; i++) before[i] = wireguard_rx_stat_get(i); }
static uint32_t delta(wireguard_rx_stat_t s) { return wireguard_rx_stat_get(s) - before[s]; }
static void terminal_sum_check(void) {
    uint32_t sum = 0;
    for (unsigned i = 0; i < WG_RXS_COUNT; i++)
        if (i != WG_RXS_rx_data && i != WG_RXS_rx_bad_type) sum += wireguard_rx_stat_get(i);
    assert(sum == wireguard_rx_stat_get(WG_RXS_rx_data));
}
/* exactly `terminal` and rx_data moved by one; everything else stayed put */
#define EXPECT_ONLY(terminal) do { \
        for (unsigned i = 0; i < WG_RXS_COUNT; i++) { \
            uint32_t want = (i == WG_RXS_rx_data || i == WG_RXS_##terminal) ? 1 : 0; \
            if (delta((wireguard_rx_stat_t)i) != want) { fprintf(stderr, "%s:%d expected only %s, but %s moved by %u\n", __FILE__, __LINE__, #terminal, wireguard_rx_stat_name(i), delta((wireguard_rx_stat_t)i)); abort(); } \
        } terminal_sum_check(); } while (0)

static void fresh(void) {
    rig_up(); wireguard_rx_stats_reset();
    set_receiving(&PEER->curr_keypair, LOCAL_INDEX);
    delivered = input_calls = 0; input_result = ERR_OK; between_hook = NULL;
    memset(&PEER->ip, 0, sizeof(PEER->ip)); PEER->port = 0;   /* no endpoint learned yet */
}

static void each_path(void (*body)(bool split)) {
    for (int split = 0; split < 2; split++) { fresh(); body(split); rig_down(); }
}

static void t_delivered(bool split) {
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_delivered);
    assert(delivered == 1 && last_input_len >= 100 && last_input[0] == 0x45);
    assert(PEER->ip.addr == from_addr(1).addr && PEER->port == 41641);   /* authenticated: the endpoint follows */
}
static void t_keepalive(bool split) {
    uint8_t dg[64]; size_t n = seal(dg, LOCAL_INDEX, 5, NULL, 0);
    assert(n == 32);
    snap(); deliver(dg, n, split, 1);
    if (split) { EXPECT_ONLY(rx_keepalive_skipped); assert(PEER->port == 0); }   /* documented: this path has never decrypted one */
    else { EXPECT_ONLY(rx_keepalive); assert(PEER->port == 41641); }
    assert(delivered == 0 && input_calls == 0);
}
static void t_no_peer(bool split) {
    uint8_t dg[1600]; size_t n = good(dg, 0xDEAD0001u, 0, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_no_peer);
    assert(input_calls == 0);
}
static void t_keypair_invalid_index(bool split) {   /* the index matches only an INVALID keypair: no peer */
    PEER->prev_keypair = PEER->curr_keypair; PEER->prev_keypair.valid = false; PEER->prev_keypair.local_index = 0x77770001u;
    uint8_t dg[1600]; size_t n = good(dg, 0x77770001u, 0, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_no_peer);
}
static void t_unusable(bool split) {
    PEER->curr_keypair.receiving_valid = false;
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_keypair_unusable);
    assert(!PEER->curr_keypair.valid);                 /* as before: a keypair that cannot receive is not kept */
}
static void t_expired_time(bool split) {
    g_now += (REJECT_AFTER_TIME + 1) * 1000;
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_expired);
    assert(!PEER->curr_keypair.valid);
    g_now = 100000;
}
static void t_expired_messages(bool split) {
    PEER->curr_keypair.sending_counter = REJECT_AFTER_MESSAGES;
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_expired);
}
static void t_alloc_fail(bool split) {
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    ip_addr_t addr = from_addr(1);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM); memcpy(p->payload, dg, n);   /* the input pbuf itself is allocated */
    snap();
    wg_host_pbuf_fail = 1;                                                                          /* ... then lwIP runs out of memory */
    if (split) { struct wireguard_rx_job job; assert(!wireguardif_rx_begin(&D.nif, p, &addr, 41641, &job)); }
    else wireguardif_network_rx(D.nif.state, NULL, p, &addr, 41641);
    wg_host_pbuf_fail = 0;
    EXPECT_ONLY(rx_alloc_fail);
    assert(input_calls == 0 && PEER->curr_keypair.replay.counter == 0);   /* nothing consumed: the retransmission can still be accepted */
}
static void t_decrypt_fail(bool split) {
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    dg[n - 1] ^= 0x01;                       /* tag */
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_decrypt_fail);
    assert(PEER->port == 0 && PEER->curr_keypair.replay.counter == 0);   /* a forged datagram changes no state */
    n = good(dg, LOCAL_INDEX, 1, 100); dg[20] ^= 0x80;                   /* ciphertext */
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_decrypt_fail);
    n = good(dg, LOCAL_INDEX, 2, 100); dg[8] ^= 0x01;                    /* counter field (it is the nonce) */
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_decrypt_fail);
}
static void gone_destroy(void *arg) { (void)arg; keypair_destroy(&PEER->curr_keypair); }
static void gone_peer(void *arg) { (void)arg; wireguardif_remove_peer(&D.nif, 0); }
static void t_session_gone(bool split) {
    if (!split) return;                                                  /* only the split path has a window between begin and complete */
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    snap(); between_hook = gone_destroy; deliver(dg, n, true, 1); between_hook = NULL;
    EXPECT_ONLY(rx_session_gone);
    assert(input_calls == 0);
    fresh();                                                             /* the whole peer removed meanwhile */
    n = good(dg, LOCAL_INDEX, 0, 100);
    snap(); between_hook = gone_peer; deliver(dg, n, true, 1); between_hook = NULL;
    EXPECT_ONLY(rx_session_gone);
}
static void t_replay_dup(bool split) {
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 7, 100);
    deliver(dg, n, split, 1);
    assert(delivered == 1);
    PEER->ip = from_addr(9); PEER->port = 9999;                           /* the peer roamed since */
    uint32_t last_rx = PEER->last_rx = 5;
    snap(); deliver(dg, n, split, 2);                                     /* an attacker replays the captured datagram from elsewhere */
    EXPECT_ONLY(rx_replay_dup);
    assert(delivered == 1 && input_calls == 1);
    /* replay protection comes before anything the datagram could change: endpoint, timers */
    assert(PEER->ip.addr == from_addr(9).addr && PEER->port == 9999 && PEER->last_rx == last_rx);
}
static void t_replay_old(bool split) {
    uint8_t dg[1600], old[1600];
    size_t n_old = good(old, LOCAL_INDEX, 3, 100);
    size_t n = good(dg, LOCAL_INDEX, 3 + WIREGUARD_REPLAY_WINDOW_SIZE + 1, 100);
    deliver(dg, n, split, 1);
    snap(); deliver(old, n_old, split, 1);
    EXPECT_ONLY(rx_replay_old);
    /* the last counter inside the window is still accepted, once */
    n = good(old, LOCAL_INDEX, 4, 100);
    snap(); deliver(old, n, split, 1);
    EXPECT_ONLY(rx_delivered);
    snap(); deliver(old, n, split, 1);
    EXPECT_ONLY(rx_replay_dup);
}
static void t_replay_limit(bool split) {
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, REJECT_AFTER_MESSAGES, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_replay_limit);
    n = good(dg, LOCAL_INDEX, UINT64_MAX, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_replay_limit);
    n = good(dg, LOCAL_INDEX, REJECT_AFTER_MESSAGES - 1, 100);           /* the last usable counter */
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_delivered);
}
static void t_bad_ip(bool split) {
    uint8_t ip[64], dg[1600];
    /* shorter than an IPv4 header: the header must not be read past the plaintext (ASan watches the exact-size buffer) */
    for (size_t plen = 1; plen <= 19; plen++) {
        ip_packet(ip, PEER_SRC, plen < 4 ? 4 : plen, 4, 0);
        size_t n = seal_raw(dg, LOCAL_INDEX, 100 + plen, ip, plen, false);   /* exactly plen bytes: no padding to hide behind */
        snap(); deliver(dg, n, split, 1);
        EXPECT_ONLY(rx_bad_ip);
    }
    for (unsigned version = 0; version < 16; version++) {                 /* not IPv4 / IPv6 */
        if (version == 4 || version == 6) continue;
        ip_packet(ip, PEER_SRC, 40, version, 0);
        size_t n = seal(dg, LOCAL_INDEX, 200 + version, ip, 40);
        snap(); deliver(dg, n, split, 1);
        EXPECT_ONLY(rx_bad_ip);
    }
    assert(input_calls == 0);
}
static void t_allowed_ip(bool split) {
    uint8_t ip[64], dg[1600];
    ip_packet(ip, OTHER_SRC, 40, 4, 0);
    size_t n = seal(dg, LOCAL_INDEX, 0, ip, 40);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_allowed_ip);
    assert(input_calls == 0);
}
static void t_bad_length(bool split) {
    uint8_t ip[64], dg[1600];
    ip_packet(ip, PEER_SRC, 40, 4, 0); ip[2] = 0x05; ip[3] = 0xDC;      /* header says 1500, 40 were sent */
    size_t n = seal(dg, LOCAL_INDEX, 0, ip, 40);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_bad_length);
    ip_packet(ip, PEER_SRC, 40, 4, 0);                                    /* total length 40, padded to 48: delivered, padding retained */
    n = seal(dg, LOCAL_INDEX, 1, ip, 40);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_delivered);
    assert(last_input_len == 48);
}
static void t_input_fail(bool split) {
    input_result = ERR_MEM;                                               /* the router refuses; ASan proves the pbuf is freed exactly once */
    uint8_t dg[1600]; size_t n = good(dg, LOCAL_INDEX, 0, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_input_fail);
    assert(input_calls == 1 && delivered == 0);
}
static void t_bad_type(bool split) {
    uint8_t dg[64] = {0}; ip_addr_t addr = from_addr(1);
    for (size_t len = 1; len < 64; len += 7) {
        for (int type = 0; type < 8; type++) {
            if (type == 4 && len >= 32) continue;
            if (type >= 1 && type <= 3) continue;                         /* handshake messages have their own (exact) lengths and checks */
            dg[0] = (uint8_t)type;
            struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM); memcpy(p->payload, dg, len);
            snap();
            if (split) { struct wireguard_rx_job job; assert(!wireguardif_rx_begin(&D.nif, p, &addr, 1, &job)); }
            else wireguardif_network_rx(D.nif.state, NULL, p, &addr, 1);
            assert(delta(WG_RXS_rx_bad_type) == 1 && delta(WG_RXS_rx_data) == 0);
            for (unsigned i = 0; i < WG_RXS_COUNT; i++) if (i != WG_RXS_rx_bad_type) assert(delta((wireguard_rx_stat_t)i) == 0);
        }
    }
}

/* A responder's first data packet promotes its next keypair. The packet that does so must be recorded in the LIVE keypair's
 * window: the old code checked it against the wiped slot, so that one datagram could be replayed once more. */
static void t_promotion(bool split) {
    set_receiving(&PEER->next_keypair, NEXT_INDEX);
    PEER->prev_keypair = PEER->curr_keypair;                              /* an older session exists: it moves to prev */
    PEER->curr_keypair.valid = false;
    uint8_t dg[1600]; size_t n = good(dg, NEXT_INDEX, 12, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_delivered);
    assert(PEER->curr_keypair.valid && PEER->curr_keypair.local_index == NEXT_INDEX && !PEER->next_keypair.valid);
    assert(PEER->curr_keypair.replay.counter == 12);                       /* the promoting packet is in the live window */
    snap(); deliver(dg, n, split, 2);
    EXPECT_ONLY(rx_replay_dup);                                            /* ... so its replay is refused */
    assert(delivered == 1);
}
static void t_prev_keypair(bool split) {                                  /* stragglers of the previous session still decrypt, with their own window */
    PEER->prev_keypair = PEER->curr_keypair; PEER->prev_keypair.local_index = 0x55550001u; key_for(PEER->prev_keypair.receiving_key, 0x55550001u);
    uint8_t dg[1600]; size_t n = good(dg, 0x55550001u, 3, 100);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_delivered);
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_replay_dup);
    n = good(dg, LOCAL_INDEX, 3, 100);                                    /* the same counter on the current keypair is a different packet */
    snap(); deliver(dg, n, split, 1);
    EXPECT_ONLY(rx_delivered);
}

/* ---- random mixes: the identity rx_data == sum of terminals holds however datagrams are thrown at the path ---- */
static void t_identity(void) {
    for (int split = 0; split < 2; split++) {
        fresh();
        uint64_t rngs = 0x1234567 + (uint64_t)split;
        for (unsigned i = 0; i < 6000; i++) {
            rngs = rngs * 6364136223846793005ull + 1442695040888963407ull;
            unsigned r = (unsigned)(rngs >> 33);
            uint8_t dg[1600], ip[1500]; size_t n;
            uint64_t counter = (r >> 4) % 400;
            switch (r % 12) {
            case 0: n = good(dg, LOCAL_INDEX, counter, 20 + r % 1400); break;
            case 1: n = good(dg, LOCAL_INDEX, counter + 1000 * (r % 7), 60); break;      /* forward jumps and backward */
            case 2: n = seal(dg, LOCAL_INDEX, counter, NULL, 0); break;                  /* keepalive */
            case 3: n = good(dg, 0xBAD00000u + (r & 0xff), counter, 60); break;           /* unknown receiver */
            case 4: n = good(dg, LOCAL_INDEX, counter, 60); dg[n - 3] ^= 4; break;        /* forged */
            case 5: ip_packet(ip, OTHER_SRC, 60, 4, 0); n = seal(dg, LOCAL_INDEX, counter, ip, 60); break;
            case 6: ip_packet(ip, PEER_SRC, 60, 4, 0); ip[3] = 200; n = seal(dg, LOCAL_INDEX, counter, ip, 60); break;
            case 7: ip_packet(ip, PEER_SRC, 30, 5, 0); n = seal(dg, LOCAL_INDEX, counter, ip, 1 + r % 30); break;
            case 8: input_result = ((r >> 7) & 1) ? ERR_MEM : ERR_OK; n = good(dg, LOCAL_INDEX, counter, 100); break;
            case 10: n = good(dg, LOCAL_INDEX, REJECT_AFTER_MESSAGES + (r % 3) * 5000, 60); break;   /* at and beyond the limit */
            case 9: inject_alloc_fail = 1; n = good(dg, LOCAL_INDEX, counter, 100); break;
            default: n = good(dg, LOCAL_INDEX, counter, 100); break;                      /* duplicates arise by themselves */
            }
            deliver(dg, n, split, r & 3);
            inject_alloc_fail = 0;
            if (r % 12 != 8) input_result = ERR_OK;
            if (!PEER->curr_keypair.valid) set_receiving(&PEER->curr_keypair, LOCAL_INDEX);
        }
        terminal_sum_check();
        for (unsigned i = 0; i < WG_RXS_COUNT; i++) {
            bool unreachable_here = i == WG_RXS_rx_bad_type || i == WG_RXS_rx_expired || i == WG_RXS_rx_keypair_unusable || i == WG_RXS_rx_session_gone ||
                                    (split && i == WG_RXS_rx_keepalive) || (!split && i == WG_RXS_rx_keepalive_skipped);
            if (!unreachable_here && wireguard_rx_stat_get(i) == 0) { fprintf(stderr, "mixed run never reached %s (split=%d)\n", wireguard_rx_stat_name(i), split); abort(); }
        }
        rig_down();
    }
    printf("rx counters: identity rx_data == sum(terminals) over 12000 mixed datagrams\n");
}

/* ---- the inbound ORDER: what the firmware's single wg_mgr task does to a stream, and reordered arrival ---- */
static void t_ordering(void) {
    /* 1. In order, through the split path, every datagram delivered in the order sent, none lost. */
    fresh();
    const unsigned N = 5000;
    uint8_t dg[1600];
    uint64_t seen_in_order = 0;
    for (unsigned i = 0; i < N; i++) {
        size_t n = good(dg, LOCAL_INDEX, i, 64);
        dg[0] = 4;
        deliver(dg, n, true, 1);
        assert(delivered == i + 1);
        (void)seen_in_order;
    }
    assert(wireguard_rx_stat_get(WG_RXS_rx_delivered) == N && wireguard_rx_stat_get(WG_RXS_rx_data) == N);
    rig_down();

    /* 2. Pipelined: several begins before the decrypts and completes, as long as completes are in begin order (one wg_mgr task:
     *    always). Delivery order == arrival order, the nonce of each is what the packet carried. */
    fresh();
    enum { BATCH = 8 };
    for (unsigned base = 0; base < 4000; base += BATCH) {
        struct wireguard_rx_job jobs[BATCH]; ip_addr_t addr = from_addr(1);
        int active[BATCH];
        for (int k = 0; k < BATCH; k++) {
            uint8_t ip[100]; ip_packet(ip, PEER_SRC, 64, 4, 0); ip[20] = (uint8_t)k; ip[21] = (uint8_t)(base >> 8); ip[22] = (uint8_t)base;
            size_t n = seal(dg, LOCAL_INDEX, base + k, ip, 64);
            struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM); memcpy(p->payload, dg, n);
            active[k] = wireguardif_rx_begin(&D.nif, p, &addr, 41641, &jobs[k]);
            assert(active[k]);
        }
        for (int k = 0; k < BATCH; k++) wireguard_rx_decrypt(&jobs[k]);
        for (int k = 0; k < BATCH; k++) {
            wireguardif_rx_complete(&D.nif, &addr, 41641, &jobs[k]);
            assert(last_input[20] == (uint8_t)k && last_input[21] == (uint8_t)(base >> 8) && last_input[22] == (uint8_t)base);   /* in order */
        }
    }
    assert(wireguard_rx_stat_get(WG_RXS_rx_delivered) == 4000);
    rig_down();

    /* 3. Reordered ARRIVAL (the network, a path switch): accepted up to the window, refused beyond it, each exactly once. */
    static const unsigned depths[] = {2, 16, 33, 64, 300, WIREGUARD_REPLAY_WINDOW_SIZE, WIREGUARD_REPLAY_WINDOW_SIZE + 1, 600};
    for (size_t d = 0; d < sizeof(depths) / sizeof(depths[0]); d++) {
        unsigned depth = depths[d], total = 3000;
        fresh();
        uint64_t *order = malloc(total * sizeof(*order));
        for (unsigned i = 0; i < total; i++) order[i] = i;
        /* reverse each block of `depth`: the worst case, the first of a block arrives `depth - 1` late */
        for (unsigned base = 0; base + depth <= total; base += depth)
            for (unsigned i = 0; i < depth / 2; i++) { uint64_t t = order[base + i]; order[base + i] = order[base + depth - 1 - i]; order[base + depth - 1 - i] = t; }
        for (unsigned i = 0; i < total; i++) { size_t n = good(dg, LOCAL_INDEX, order[i], 64); deliver(dg, n, (i & 1) != 0, 1); }
        uint32_t ok = wireguard_rx_stat_get(WG_RXS_rx_delivered), old = wireguard_rx_stat_get(WG_RXS_rx_replay_old);
        /* a reversed block of `depth` delivers its last counter first; the following depth - 1 are `1..depth-1` below it */
        uint32_t lost_per_block = depth - 1 > WIREGUARD_REPLAY_WINDOW_SIZE ? depth - 1 - WIREGUARD_REPLAY_WINDOW_SIZE : 0;
        uint32_t blocks = total / depth;
        printf("  arrival reversed in blocks of %3u: %u delivered, %u refused as too old (window %d)\n", depth, ok, old, WIREGUARD_REPLAY_WINDOW_SIZE);
        if (depth <= WIREGUARD_REPLAY_WINDOW_SIZE) assert(ok == total && old == 0);
        assert(ok + old == total && old == lost_per_block * blocks);
        terminal_sum_check();
        free(order); rig_down();
    }
}

int main(void) {
    each_path(t_delivered);
    each_path(t_keepalive);
    each_path(t_no_peer);
    each_path(t_keypair_invalid_index);
    each_path(t_unusable);
    each_path(t_expired_time);
    each_path(t_expired_messages);
    each_path(t_alloc_fail);
    each_path(t_decrypt_fail);
    each_path(t_session_gone);
    each_path(t_replay_dup);
    each_path(t_replay_old);
    each_path(t_replay_limit);
    each_path(t_bad_ip);
    each_path(t_allowed_ip);
    each_path(t_bad_length);
    each_path(t_input_fail);
    each_path(t_bad_type);
    each_path(t_promotion);
    each_path(t_prev_keypair);
    printf("rx counters: every drop point increments exactly its counter, on both entry points\n");
    t_identity();
    t_ordering();
    printf("wg rx counters ok\n");
    return 0;
}
