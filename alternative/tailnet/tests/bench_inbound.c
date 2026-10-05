/* Inbound microbenchmark (ADR 0020): the real wireguardif.c and the real router.c in one program, the datagram-at-a-time path they
 * replaced against the run (ml_wg_rx_run + gateway_tunnel_input_batch), on the same sealed datagrams.
 *
 * What a host can and cannot say. ChaCha20-Poly1305 and the allocator are cheap here and the lwIP core lock is a no-op, so the
 * absolute nanoseconds mean nothing for the Xtensa board (where the router measured ~166k cycles per datagram). What carries over,
 * because it is structure and not speed: pbuf allocations per datagram, bytes copied per datagram, core-lock acquisitions per
 * datagram, and how much of the per-datagram time is spent INSIDE the lock (the part that stalls the tcpip task). The nanoseconds are
 * printed for scale, and the crypto time (decrypt alone) is separated so the non-crypto path can be compared on its own.
 *
 *   tools/bench-inbound.sh            (builds with -O2, no sanitizers, and runs)
 *
 * Old path, per datagram (wg_mgr before): pbuf_alloc + copy of the datagram, rx_begin (lock), plaintext pbuf, decrypt, rx_complete
 * (lock) whose netif->input is gateway_tunnel_input: validate, NAT, one output pbuf, USB output, all inside the lock.
 * New path: wrap (no allocation, no copy), begin and complete for up to 8 datagrams per hold, decrypt in place, then the router
 * with the lock released and one hold for the output of the batch. */
#define GATEWAY_HOST_TEST
#define ROUTER_STUBS_EXTERNAL_LWIP
#define ROUTER_STUBS_EXTERNAL_LOCK
#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include "wireguard.h"
#include "wireguardif.h"
#include "wireguard_stats.h"
#include "chacha20poly1305.h"
#define wireguard_aead_encrypt(dst, src, srclen, ad, adlen, nonce, key) chacha20poly1305_encrypt(dst, src, srclen, ad, adlen, nonce, key)
#include "ml_wg_rx_batch.h"

uint32_t wireguard_sys_now(void) { return 100000; }
void wireguard_tai64n_now(uint8_t *out) { memset(out, 0, 12); out[7] = 1; }
bool wireguard_is_under_load(void) { return false; }
void wireguard_set_tai64n_base_seconds(uint64_t s) { (void)s; }
void wireguard_random_bytes(void *bytes, size_t size) { memset(bytes, 0x42, size); }

#include "router_stubs.h"
#include "router_packets.h"
/* the lock: timed holds, recursive, acquisitions counted at depth 0 -> 1 only (a nested take costs nothing on the device) */
static int lock_depth;
static unsigned long lock_acquires;
static struct timespec hold_start;
static double hold_ns;
static bool time_holds;
static void bench_lock(void) {
    if (lock_depth++ == 0) { lock_acquires++; if (time_holds) clock_gettime(CLOCK_MONOTONIC_RAW, &hold_start); }
}
static void bench_unlock(void) {
    if (--lock_depth == 0 && time_holds) {
        struct timespec t; clock_gettime(CLOCK_MONOTONIC_RAW, &t);
        hold_ns += (t.tv_sec - hold_start.tv_sec) * 1e9 + (t.tv_nsec - hold_start.tv_nsec);
    }
}
static void router_stub_core_lock(void) { bench_lock(); }
static void router_stub_core_unlock(void) { bench_unlock(); }
static uint8_t egress[1500]; static size_t egress_len;
static int ml_gateway_queue_packet(microlink_t *ml, uint32_t ip, const uint8_t *data, size_t len) {
    (void)ml; (void)ip; assert(len <= sizeof(egress)); memcpy(egress, data, len); egress_len = len; return 0;
}
#include "../main/route_table.c"
#include "../main/router.c"

static double now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC_RAW, &t); return t.tv_sec * 1e9 + t.tv_nsec; }

#define LOCAL_INDEX 0xA1B2C3D4u
#define PEER_VPN 0x64400002u        /* 100.64.0.2: the peer, host order */
#define OUR_VPN 0x64400001u
#define FLOWS 8
static struct netif wg;
static struct wireguardif_init_data init_data;
static char key_b64[64];
static struct wireguard_peer *peer;
static microlink_t client = {&wg, OUR_VPN, 4, 0};
static membership_t member = {NULL, 1, &client};
static unsigned long usb_frames;
static err_t usb_output(struct netif *n, struct pbuf *p, const ip4_addr_t *ip) { (void)n; (void)ip; usb_frames++; return p->tot_len ? ERR_OK : ERR_MEM; }

static void key_for(uint8_t key[32], uint32_t index) { for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x30 + i + (index & 0xff)); }
static void set_receiving(struct wireguard_keypair *k, uint32_t index) {
    memset(k, 0, sizeof(*k));
    k->valid = true; k->keypair_millis = 100000; k->local_index = index; k->remote_index = 0x11223344;
    k->receiving_valid = true; k->sending_valid = true;
    key_for(k->receiving_key, index);
    wireguard_replay_reset(&k->replay);
}
static void rig_up(void) {
    uint8_t key[32]; size_t n = 64;
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1);
    assert(wireguard_base64_encode(key, 32, key_b64, &n));
    init_data.private_key = key_b64; init_data.listen_port = 51820;
    wg.state = &init_data;
    assert(wireguardif_init(&wg) == ERR_OK);
    uint8_t pk[32], idx; char s[64]; n = 64; struct wireguardif_peer p;
    for (int i = 0; i < 32; i++) pk[i] = (uint8_t)(i + 5);
    pk[31] &= 0x7f;
    assert(wireguard_base64_encode(pk, 32, s, &n));
    wireguardif_peer_init(&p);
    p.public_key = s; p.allowed_ip.addr = htonl(PEER_VPN); p.allowed_mask.addr = 0xffffffff;
    assert(wireguardif_add_peer(&wg, &p, &idx) == ERR_OK);
    peer = wireguard_device_peer((struct wireguard_device *)wg.state, idx);
    set_receiving(&peer->curr_keypair, LOCAL_INDEX);
    wg.input = gateway_tunnel_input;
    wireguardif_set_rx_batch(&wg, gateway_tunnel_input_batch);   /* what ml_wg_mgr does at interface creation */
}

/* open FLOWS flows USB -> tunnel and build the reply to each, sealed for the peer's keypair, with `payload` bytes of UDP data */
static uint8_t sealed[FLOWS][1700]; static size_t sealed_len[FLOWS];
static void build_datagrams(size_t payload) {
    for (unsigned i = 0; i < FLOWS; i++) {
        uint8_t pkt[1500];
        uint32_t alias = gateway_alias(1, PEER_VPN);
        size_t n = build_packet(pkt, 0xc0a84d02, alias, 17, 4000 + i, 53, 16, false, false);
        struct pbuf *p = pbuf_alloc(PBUF_IP, (u16_t)n, PBUF_RAM); pbuf_take(p, pkt, (u16_t)n);
        if (!gateway_host_input(p, &usb)) pbuf_free(p);
        uint16_t mapped = rd16(egress + 20);
        uint8_t reply[1500];
        size_t rn = build_packet(reply, PEER_VPN, OUR_VPN, 17, 53, mapped, payload, false, false);
        fill_checksums(reply, rn, 20, false);
        size_t padded = WIREGUARDIF_DATA_PAD(rn);
        uint8_t buf[1700]; memset(buf, 0, sizeof(buf)); memcpy(buf, reply, rn);
        uint8_t *out = sealed[i]; memset(out, 0, 16); out[0] = 4;
        uint32_t receiver = LOCAL_INDEX; memcpy(out + 4, &receiver, 4);
        uint64_t counter = i; for (int k = 0; k < 8; k++) out[8 + k] = (uint8_t)(counter >> (8 * k));
        uint8_t key[32]; key_for(key, receiver);
        wireguard_aead_encrypt(out + 16, buf, padded, NULL, 0, counter, key);
        sealed_len[i] = 16 + padded + 16;
    }
}

/* the producer's heap block for a datagram (net_io / the DERP loop): the same in both paths, so allocated outside the timing */
static uint8_t *heap_block[FLOWS];
static void fill_blocks(void) { for (unsigned i = 0; i < FLOWS; i++) { heap_block[i] = malloc(sealed_len[i]); memcpy(heap_block[i], sealed[i], sealed_len[i]); } }

typedef struct { struct pbuf_custom pc; uint8_t *data; } wrap_t;
static wrap_t wraps[FLOWS];
static void wrap_free(struct pbuf *p) { wrap_t *w = (wrap_t *)p; free(w->data); w->data = NULL; }

static void lk_lock(void *ctx, unsigned site) { (void)ctx; (void)site; bench_lock(); }
static void lk_unlock(void *ctx, unsigned site) { (void)ctx; (void)site; bench_unlock(); }
static const ml_wg_rx_lock_t LK = {lk_lock, lk_unlock, NULL};
static struct wireguard_rx_job jobs[ML_WG_RX_BATCH];

static void reset_window(void) { wireguard_replay_reset(&peer->curr_keypair.replay); }

/* one round of FLOWS datagrams through the old path */
static void round_old(unsigned groups_of) {
    (void)groups_of;
    ip_addr_t addr; memset(&addr, 0, sizeof(addr));
    for (unsigned i = 0; i < FLOWS; i++) {
        /* process_wg_packet before: allocate a pbuf, copy the datagram into it, free the block */
        struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)sealed_len[i], PBUF_RAM);
        pbuf_take(p, heap_block[i], (u16_t)sealed_len[i]);
        free(heap_block[i]);
        struct wireguard_rx_job job;
        bench_lock();
        int pending = wireguardif_rx_begin(&wg, p, &addr, 41641, &job);
        bench_unlock();
        if (pending) {
            wireguard_rx_decrypt(&job);
            bench_lock();
            wireguardif_rx_complete(&wg, &addr, 41641, &job);   /* netif->input = gateway_tunnel_input, under the lock */
            bench_unlock();
        }
    }
}
static void round_new(void) {
    ml_wg_rx_item_t items[FLOWS];
    for (unsigned i = 0; i < FLOWS; i++) {
        wrap_t *w = &wraps[i];
        struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, (u16_t)sealed_len[i], PBUF_REF, &w->pc, heap_block[i], (u16_t)sealed_len[i]);
        w->pc.custom_free_function = wrap_free; w->data = heap_block[i];
        items[i].p = p; memset(&items[i].addr, 0, sizeof(items[i].addr)); items[i].port = 41641;
    }
    ml_wg_rx_run(&wg, items, FLOWS, jobs, &LK);
}

static void bench_size(size_t payload, unsigned rounds) {
    build_datagrams(payload);
    double t_old = 0, t_new = 0, t_dec = 0, h_old = 0, h_new = 0;
    unsigned long a_old = 0, a_new = 0, c_old = 0, c_new = 0, l_old = 0, l_new = 0;
    for (int variant = 0; variant < 4; variant++) {
        /* 0: old, timed total; 1: new, timed total; 2: old, timed holds; 3: new, timed holds */
        bool is_new = variant & 1; time_holds = variant >= 2;
        hold_ns = 0; lock_acquires = 0; wg_host_pbuf_allocs = 0; wg_host_copied_bytes = 0; usb_frames = 0;
        double total = 0;
        for (unsigned r = 0; r < rounds; r++) {
            fill_blocks(); reset_window();
            double t0 = now_ns();
            if (is_new) round_new(); else round_old(FLOWS);
            total += now_ns() - t0;
        }
        assert(usb_frames == (unsigned long)rounds * FLOWS);
        double per = total / ((double)rounds * FLOWS);
        if (variant == 0) { t_old = per; a_old = wg_host_pbuf_allocs; c_old = wg_host_copied_bytes; l_old = lock_acquires; }
        if (variant == 1) { t_new = per; a_new = wg_host_pbuf_allocs; c_new = wg_host_copied_bytes; l_new = lock_acquires; }
        if (variant == 2) h_old = hold_ns / ((double)rounds * FLOWS);
        if (variant == 3) h_new = hold_ns / ((double)rounds * FLOWS);
    }
    time_holds = false;
    /* the crypto alone: decrypt the same bytes in place */
    {
        uint8_t key[32]; key_for(key, LOCAL_INDEX);
        uint8_t buf[1700];
        double t0 = now_ns();
        unsigned n = rounds * FLOWS;
        for (unsigned k = 0; k < n; k++) {
            memcpy(buf, sealed[k % FLOWS], sealed_len[k % FLOWS]);
            (void)chacha20poly1305_decrypt(buf + 16, buf + 16, sealed_len[k % FLOWS] - 16, NULL, 0, k % FLOWS, key);
        }
        t_dec = (now_ns() - t0) / n;
    }
    double n = (double)rounds * FLOWS;
    printf("%5zu B payload | ns/datagram total %6.0f -> %6.0f (crypto alone %5.0f) | in the lock %6.0f -> %5.0f | pbuf allocs %.2f -> %.2f | bytes copied %5.0f -> %5.0f | lock takes %.2f -> %.2f\n",
           payload, t_old, t_new, t_dec, h_old, h_new, a_old / n, a_new / n, c_old / n, c_new / n, l_old / n, l_new / n);
    fflush(stdout);
}

int main(int argc, char **argv) {
    unsigned rounds = argc > 1 ? (unsigned)atoi(argv[1]) : 20000;
    usb_interface = &usb; usb.output = usb_output;
    members = &member;
    rig_up();
    printf("inbound path, real wireguardif.c + router.c, host -O2, %u rounds of %d datagrams per size (arrows: before -> after)\n", rounds, FLOWS);
    bench_size(32, rounds);
    bench_size(180, rounds);
    bench_size(600, rounds);
    bench_size(1200, rounds);
    gateway_forget(1);
    return 0;
}
