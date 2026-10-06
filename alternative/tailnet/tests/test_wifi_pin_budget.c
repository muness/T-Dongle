/* The Wi-Fi pin budget (wifi_pin_budget.h, ADR 0022 amendment 2).
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra -pthread \
 *      -I components/microlink/include -I main tests/test_wifi_pin_budget.c -o build-host/test_wifi_pin_budget
 *   (and -fsanitize=thread for the thread test)
 *
 * 1. Rules: the band, the elastic floor, the pool, the lease (with a wrapping clock), done / abort / flush, unmatched events.
 * 2. Exactly once: every charge leaves by exactly one of done, abort, flush or lease (charged == released + outstanding, always),
 *    under random event orders, and the same for RX (admitted == released + inflight).
 * 3. Threads: submitters, the pp task's done, the event task's flush and RX admit/release against one budget (TSan).
 * 4. The floor under concurrent TX and RX pins: Wi-Fi buffers of both directions, the WireGuard queue, the USB ring, USB receive frames
 *    and pending packets in one adversarial schedule, with racing checkers, through the real admission code (gw_wtx_admit, gw_wrx_admit,
 *    ml_wgrx_admit, gateway_usb_rx_admit, ml_hb_ok). The minimum free heap must stay at or above the recovery reserve (16,384 B). The same
 *    schedule against what PR #42 left unbounded (a 16-buffer RX pool, a 6-buffer TX pool) must NOT: it reproduces the board's few KB, and
 *    each ingredient of the budget (the RX gate, the band size, the floor) is shown to matter by removing it. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_wg_rx_budget.h"
#include "route_table.h"
#include "usb_rx_budget.h"
#include "wifi_pin_budget.h"

atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];
ml_wgrx_budget_t ml_wgrx_budget;

static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(uint32_t n) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)((rs >> 11) % n); }

static void conserved_tx(gateway_wifi_pins *b) {   /* quiescent: charged = released by any road + still outstanding */
    unsigned out = gw_wtx_outstanding(b);
    assert(atomic_load(&b->tx_charged) == atomic_load(&b->tx_done) + atomic_load(&b->tx_aborted) + atomic_load(&b->tx_flushed) +
                                              atomic_load(&b->tx_stale) + out);
    assert(out <= (unsigned)GATEWAY_WIFI_TX_POOL);
}
static void conserved_rx(gateway_wifi_pins *b) {
    assert(atomic_load(&b->rx_band) + atomic_load(&b->rx_elastic) == atomic_load(&b->rx_released) + gw_wrx_inflight(b));
}

/* ---- 1. rules ---- */
static void test_tx_rules(void) {
    const size_t F = ML_HB_FLOOR;
    gateway_wifi_pins b = GATEWAY_WIFI_PINS_INIT;
    /* The band: with the RX side idle a direction gets GATEWAY_WIFI_TX_BAND_MAX of the 5 shared slots whatever the heap says, any size. */
    for (unsigned i = 0; i < GATEWAY_WIFI_TX_BAND_MAX; i++) assert(gw_wtx_admit(&b, 1514, 0, 100) == GW_WTX_BAND);
    /* Past the band a frame needs the floor plus its own cost: exactly there it is admitted, one byte less it is refused and takes nothing. */
    assert(gw_wtx_cost(1514) == ML_HB_PIN_BUF_BYTES && gw_wtx_cost(66) == 66 + GW_WTX_OVERHEAD && gw_wtx_cost(65535) == ML_HB_PIN_BUF_BYTES);
    unsigned held = gw_wtx_outstanding(&b);
    assert(gw_wtx_admit(&b, 1514, F + ML_HB_PIN_BUF_BYTES - 1, 100) == GW_WTX_HEAP && gw_wtx_outstanding(&b) == held);
    assert(gw_wtx_admit(&b, 1514, F, 100) == GW_WTX_HEAP);
    assert(gw_wtx_admit(&b, 66, F + 66 + GW_WTX_OVERHEAD - 1, 100) == GW_WTX_HEAP);
    assert(gw_wtx_admit(&b, 66, F + 66 + GW_WTX_OVERHEAD, 100) == GW_WTX_ELASTIC);
    assert(gw_wtx_admit(&b, 1514, F + ML_HB_PIN_BUF_BYTES, 100) == GW_WTX_ELASTIC);
    /* Up to the pool, then BUSY, whatever the heap. */
    while (gw_wtx_outstanding(&b) < (unsigned)GATEWAY_WIFI_TX_POOL) assert(gw_wtx_admit(&b, 1514, 1u << 30, 100) == GW_WTX_ELASTIC);
    assert(gw_wtx_admit(&b, 66, 1u << 30, 100) == GW_WTX_POOL && gw_wtx_admit(&b, 1514, 0, 100) == GW_WTX_POOL);
    assert(atomic_load(&b.tx_refused_pool) == 2 && atomic_load(&b.tx_high_water) == (unsigned)GATEWAY_WIFI_TX_POOL);
    /* tx-done frees the oldest slot, and exactly one more frame is admitted (past the band: it takes the heap check). */
    gw_wtx_done(&b);
    assert(gw_wtx_admit(&b, 1514, 1u << 30, 100) == GW_WTX_ELASTIC && gw_wtx_admit(&b, 1514, 1u << 30, 100) == GW_WTX_POOL);
    conserved_tx(&b);
    /* Everything done: the band is back, and a done with nothing outstanding is counted and changes nothing. */
    while (gw_wtx_outstanding(&b)) gw_wtx_done(&b);
    assert(gw_wtx_admit(&b, 1514, 0, 100) == GW_WTX_BAND);
    gw_wtx_done(&b);
    gw_wtx_done(&b);
    assert(atomic_load(&b.tx_unmatched) == 1 && gw_wtx_outstanding(&b) == 0);
    conserved_tx(&b);
}

/* The joint band: RX and TX together hold at most GATEWAY_WIFI_BAND_TOTAL without a heap check, each at most 4, so neither can take the
 * last slot from the other: an ACK (RX) or an ARP reply (TX) always has a buffer, and a one-way flow gets 4 of the 5. */
static void test_joint_band(void) {
    const size_t F = ML_HB_FLOOR;
    gateway_wifi_pins b = GATEWAY_WIFI_PINS_INIT;
    assert(GATEWAY_WIFI_BAND_TOTAL == 5 && GATEWAY_WIFI_RX_BAND_MAX == 4 && GATEWAY_WIFI_TX_BAND_MAX == 4);
    /* RX alone: 4 in the band, the 5th needs the heap (so does a TX frame once 4 RX are in: TX takes the 5th slot, then nothing). */
    for (unsigned i = 0; i < GATEWAY_WIFI_RX_BAND_MAX; i++) assert(gw_wrx_admit(&b, 0));
    assert(!gw_wrx_admit(&b, F - 1));                                                    /* RX at its maximum: the heap decides */
    assert(gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_BAND);                                  /* TX still has the last slot */
    assert(gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_HEAP);                                  /* and the band is now full */
    assert(gw_wrx_inflight(&b) == 4 && gw_wtx_outstanding(&b) == 1);
    gw_wtx_done(&b);
    for (unsigned i = 0; i < GATEWAY_WIFI_RX_BAND_MAX; i++) gw_wrx_release(&b);
    /* TX alone: 4 in the band; RX keeps the last slot. */
    for (unsigned i = 0; i < GATEWAY_WIFI_TX_BAND_MAX; i++) assert(gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_BAND);
    assert(gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_HEAP);
    assert(gw_wrx_admit(&b, 0) && !gw_wrx_admit(&b, F - 1));                              /* the one RX frame, then the heap decides */
    while (gw_wtx_outstanding(&b)) gw_wtx_done(&b);
    gw_wrx_release(&b);
    /* Mixed: 2 RX + 3 TX fill the band; the sum, not either count, is what is limited. */
    assert(gw_wrx_admit(&b, 0) && gw_wrx_admit(&b, 0));
    for (int i = 0; i < 3; i++) assert(gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_BAND);
    assert(gw_wtx_admit(&b, 1514, F + ML_HB_PIN_BUF_BYTES - 1, 1) == GW_WTX_HEAP && !gw_wrx_admit(&b, F - 1));
    assert(gw_wtx_admit(&b, 1514, F + ML_HB_PIN_BUF_BYTES, 1) == GW_WTX_ELASTIC && gw_wrx_admit(&b, F));   /* elastic: the floor after the buffer exists */
    assert(gw_wp_rx(atomic_load(&b.pins)) == 3 && gw_wp_tx(atomic_load(&b.pins)) == 4);
    /* Elastic pins count too, so the band does not reopen while they are held. */
    gw_wtx_done(&b);                                                                       /* 3 RX + 3 TX = 6 >= 5: still full */
    assert(gw_wtx_admit(&b, 1514, F - 1, 1) == GW_WTX_HEAP);
    gw_wtx_done(&b); gw_wtx_done(&b); gw_wtx_done(&b);                                     /* 3 RX + 0 TX: two slots free again */
    assert(gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_BAND && gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_BAND && gw_wtx_admit(&b, 1514, 0, 1) == GW_WTX_HEAP);
    /* The worst the band can pin below the floor, at any interleaving of the two directions: BAND_TOTAL buffers. */
    for (int seed = 1; seed <= 20; seed++) {
        gateway_wifi_pins r = GATEWAY_WIFI_PINS_INIT;
        uint64_t save = rs;
        rs = 0x2545F4914F6CDD1Dull * (unsigned)seed;
        unsigned peak = 0, rx = 0, tx = 0;
        for (int i = 0; i < 20000; i++) {
            switch (rnd(4)) {
            case 0: if (gw_wrx_admit(&r, 0 /* no heap: the band only */)) rx++; break;
            case 1: if (gw_wtx_admitted(gw_wtx_admit(&r, 1514, 0, (uint32_t)i))) tx++; break;
            case 2: if (rx) { gw_wrx_release(&r); rx--; } break;
            default: if (tx) { gw_wtx_done(&r); tx--; } break;
            }
            assert(gw_wrx_inflight(&r) == rx && gw_wtx_outstanding(&r) == tx);
            if (rx + tx > peak) peak = rx + tx;
        }
        assert(peak == GATEWAY_WIFI_BAND_TOTAL);                                           /* reached, and never exceeded, with no heap at all */
        rs = save;
    }
}

static void test_tx_abort_flush_lease(void) {
    gateway_wifi_pins b = GATEWAY_WIFI_PINS_INIT;
    /* abort: esp_wifi_internal_tx failed, so no driver buffer: the charge goes, no tx-done will come. */
    assert(gw_wtx_admit(&b, 1514, 0, 5) == GW_WTX_BAND);
    gw_wtx_abort(&b);
    assert(gw_wtx_outstanding(&b) == 0 && atomic_load(&b.tx_aborted) == 1);
    gw_wtx_abort(&b);                                                                       /* nothing to abort: counted, not an underflow */
    assert(gw_wtx_outstanding(&b) == 0 && atomic_load(&b.tx_unmatched) == 1);
    /* flush: the link changed, the driver cleared its queues. */
    for (int i = 0; i < 5; i++) assert(gw_wtx_admitted(gw_wtx_admit(&b, 1514, 1u << 30, 10 + (uint32_t)i)));
    assert(gw_wtx_flush(&b) == 5 && gw_wtx_outstanding(&b) == 0 && atomic_load(&b.tx_flushed) == 5 && gw_wtx_flush(&b) == 0);
    gw_wtx_done(&b);                                                                        /* a late done from before the flush: ignored */
    assert(gw_wtx_outstanding(&b) == 0);
    /* the lease: a charge older than GW_WTX_LEASE_MS is presumed dropped by the driver, only the head can expire, the clock may wrap. */
    const uint32_t t0 = 0xFFFFFF00u;
    assert(gw_wtx_admitted(gw_wtx_admit(&b, 1514, 1u << 30, t0)));                            /* A */
    assert(gw_wtx_admitted(gw_wtx_admit(&b, 1514, 1u << 30, t0 + 600)));                      /* B */
    assert(atomic_load(&b.tx_stale) == 0 && gw_wtx_outstanding(&b) == 2);
    assert(gw_wtx_admitted(gw_wtx_admit(&b, 1514, 1u << 30, t0 + GW_WTX_LEASE_MS)));          /* C: A is exactly at the lease, not yet stale */
    assert(atomic_load(&b.tx_stale) == 0 && gw_wtx_outstanding(&b) == 3);
    assert(gw_wtx_admitted(gw_wtx_admit(&b, 1514, 1u << 30, t0 + GW_WTX_LEASE_MS + 1)));      /* D: A is stale and expired; B (601 ms old) is not */
    assert(atomic_load(&b.tx_stale) == 1 && gw_wtx_outstanding(&b) == 3);
    assert(gw_wtx_admitted(gw_wtx_admit(&b, 1514, 1u << 30, t0 + 600 + GW_WTX_LEASE_MS + 1))); /* E: B is stale now too */
    assert(atomic_load(&b.tx_stale) == 2 && gw_wtx_outstanding(&b) == 3);
    conserved_tx(&b);
    /* a stalled driver cannot leak credits for ever: after one lease everything outstanding is gone and the band is back. */
    gateway_wifi_pins s = GATEWAY_WIFI_PINS_INIT;
    for (int i = 0; i < GATEWAY_WIFI_TX_POOL; i++) assert(gw_wtx_admitted(gw_wtx_admit(&s, 1514, 1u << 30, 1000)));
    assert(gw_wtx_admit(&s, 66, 0, 1000 + GW_WTX_LEASE_MS) == GW_WTX_POOL);
    assert(gw_wtx_admit(&s, 66, 0, 1000 + GW_WTX_LEASE_MS + 1) == GW_WTX_BAND);
    assert(atomic_load(&s.tx_stale) == (unsigned)GATEWAY_WIFI_TX_POOL && gw_wtx_outstanding(&s) == 1);
    conserved_tx(&s);
}

static void test_rx_rules(void) {
    const size_t F = ML_HB_FLOOR;
    gateway_wifi_pins b = GATEWAY_WIFI_PINS_INIT;
    for (unsigned i = 0; i < GATEWAY_WIFI_RX_BAND_MAX; i++) assert(gw_wrx_admit(&b, 0));    /* the band: whatever the heap */
    assert(!gw_wrx_admit(&b, F - 1) && atomic_load(&b.rx_dropped) == 1 && gw_wrx_inflight(&b) == GATEWAY_WIFI_RX_BAND_MAX);
    assert(gw_wrx_admit(&b, F) && gw_wrx_inflight(&b) == GATEWAY_WIFI_RX_BAND_MAX + 1);      /* past it: the floor after the buffer exists */
    gw_wrx_release(&b);                                                                     /* one freed: the count is back at the band, not under it */
    assert(!gw_wrx_admit(&b, 0));
    for (unsigned i = 0; i < GATEWAY_WIFI_RX_BAND_MAX; i++) gw_wrx_release(&b);
    assert(gw_wrx_inflight(&b) == 0 && atomic_load(&b.rx_unmatched) == 0);
    gw_wrx_release(&b);
    assert(gw_wrx_inflight(&b) == 0 && atomic_load(&b.rx_unmatched) == 1);                  /* no underflow */
    assert(atomic_load(&b.rx_high_water) == GATEWAY_WIFI_RX_BAND_MAX + 1);
    conserved_rx(&b);
}

static void test_constants(void) {
    /* The inequality the header asserts, restated with numbers: reserve + (the shared band + the RX frame under check) buffers + the racing
     * slack fit under the elastic floor, and the TX pool and the FIFO agree. */
    assert(GATEWAY_WIFI_BAND_TOTAL == 5 && GATEWAY_WIFI_TX_POOL == 16 && GW_WTX_RING == 16);
    assert(GATEWAY_WIFI_PIN_BAND_BYTES == 6u * 1664u);
    assert(ML_HB_RESERVE + GATEWAY_WIFI_PIN_BAND_BYTES + ML_HB_SLACK_BYTES == 29696 && 29696 <= ML_HB_FLOOR);
}

/* ---- 2. exactly once, random order, with a reference model ---- */
static void test_exactly_once_random(void) {
    for (int seed = 1; seed <= 40; seed++) {
        rs = 0x9e3779b97f4a7c15ull * (unsigned)seed;
        gateway_wifi_pins b = GATEWAY_WIFI_PINS_INIT;
        unsigned model = 0;          /* outstanding charges by the reference count */
        uint32_t now = (uint32_t)rnd(1000) + 0xFFFFF000u;   /* starts close to the wrap */
        for (int step = 0; step < 100000; step++) {
            now += rnd(7);
            switch (rnd(8)) {
            case 0: case 1: case 2: {                              /* submit */
                size_t heap = rnd(3) == 0 ? ML_HB_FLOOR + rnd(40000) : rnd(ML_HB_FLOOR);
                if (gw_wtx_admitted(gw_wtx_admit(&b, 1 + rnd(1514), heap, now))) model++;
                break;
            }
            case 3: if (rnd(3) == 0) { gw_wtx_abort(&b); if (model) model--; } break;   /* the submit failed */
            case 4: case 5: gw_wtx_done(&b); if (model) model--; break;
            case 6: if (rnd(200) == 0) { gw_wtx_flush(&b); model = 0; } break;
            default: now += rnd(GW_WTX_LEASE_MS / 4); break;          /* time passes: leases expire */
            }
            /* The reference count differs only by what the lease took, which the counter says. */
            unsigned out = gw_wtx_outstanding(&b);
            assert(out <= (unsigned)GATEWAY_WIFI_TX_POOL);
            if (out > model) assert(0);
            model = out;                                                       /* lease expiry is the one silent release */
            conserved_tx(&b);
        }
    }
    for (int seed = 1; seed <= 40; seed++) {                           /* RX */
        rs = 0xd1b54a32d192ed03ull * (unsigned)seed;
        gateway_wifi_pins b = GATEWAY_WIFI_PINS_INIT;
        unsigned model = 0;
        for (int step = 0; step < 100000; step++) {
            if (rnd(2)) { if (gw_wrx_admit(&b, rnd(2) ? ML_HB_FLOOR + rnd(5000) : rnd(ML_HB_FLOOR))) model++; }
            else if (model) { gw_wrx_release(&b); model--; }
            assert(gw_wrx_inflight(&b) == model);
            conserved_rx(&b);
        }
        assert(atomic_load(&b.rx_unmatched) == 0);
    }
}

/* ---- 3. threads ---- */
static gateway_wifi_pins shared = GATEWAY_WIFI_PINS_INIT;
static atomic_bool stop;
static void *submitter(void *arg) {
    uint32_t r = (uint32_t)(uintptr_t)arg * 2654435761u + 1;
    for (uint32_t now = 0; !atomic_load(&stop); now++) {
        r ^= r << 13; r ^= r >> 17; r ^= r << 5;
        if (gw_wtx_admitted(gw_wtx_admit(&shared, 1 + r % 1514, (r & 1) ? 1u << 30 : 0, now)) && r % 5 == 0) gw_wtx_abort(&shared);
        assert(gw_wtx_outstanding(&shared) <= (unsigned)GATEWAY_WIFI_TX_POOL);
    }
    return NULL;
}
static void *pp_task(void *arg) { (void)arg; while (!atomic_load(&stop)) gw_wtx_done(&shared); return NULL; }
static void *flusher(void *arg) { (void)arg; while (!atomic_load(&stop)) { gw_wtx_flush(&shared); for (volatile int i = 0; i < 2000; i++) {} } return NULL; }
static void *rx_user(void *arg) {
    uint32_t r = (uint32_t)(uintptr_t)arg * 2246822519u + 7;
    unsigned mine = 0;
    while (!atomic_load(&stop)) {
        r ^= r << 13; r ^= r >> 17; r ^= r << 5;
        if (r & 1) { if (gw_wrx_admit(&shared, (r & 2) ? 1u << 30 : 0)) mine++; }
        else if (mine) { gw_wrx_release(&shared); mine--; }
        assert(gw_wrx_inflight(&shared) <= 4096);
    }
    while (mine--) gw_wrx_release(&shared);
    return NULL;
}
static void test_threads(void) {
    pthread_t t[8];
    int n = 0;
    for (long i = 1; i <= 2; i++) pthread_create(&t[n++], NULL, submitter, (void *)i);
    pthread_create(&t[n++], NULL, pp_task, NULL);
    pthread_create(&t[n++], NULL, flusher, NULL);
    for (long i = 1; i <= 3; i++) pthread_create(&t[n++], NULL, rx_user, (void *)i);
    for (volatile long spin = 0; spin < 40000000; spin++) {}
    atomic_store(&stop, true);
    while (n--) pthread_join(t[n], NULL);
    conserved_tx(&shared);
    assert(gw_wrx_inflight(&shared) == 0 && atomic_load(&shared.rx_unmatched) == 0);
    conserved_rx(&shared);
}

/* ---- 4. the floor under concurrent TX and RX pins ---- */
#define CHUNK_BYTES 3048u
#define MAX_HELD 64
typedef struct {
    const char *name;
    int rx_mode, tx_mode;             /* 0: the driver's pool alone, 1: the budget (real code), 2 (RX): a mutant of it (rx_band, pin_floor) */
    unsigned rx_pool, tx_pool;        /* the driver's pools: what it can pin when nothing else stops it */
    unsigned rx_band;                 /* mutants only */
    size_t pin_floor;                 /* mutants only: the elastic pin floor; 0 = the real ML_HB_FLOOR */
    bool upload, download;
} model_t;
typedef struct { unsigned len; } held_t;
typedef struct {
    long free, min_free;
    gateway_wifi_pins pins;
    unsigned rx_cost[64], rx_n;                         /* driver RX buffers pinned (cost each) */
    unsigned tx_cost[32], tx_n;                         /* driver TX buffers in flight */
    held_t wgq[MAX_HELD]; unsigned wgq_n;
    unsigned ring_chunks;
    gateway_usb_rx_budget usb; unsigned usb_len[GATEWAY_USB_RX_INFLIGHT_MAX]; unsigned usb_n;
    unsigned jit_n, derp_n;
    unsigned long driver_fail, rx_refused, tx_refused, tx_stale_released;
    ml_wgrx_budget_t wb;
    uint32_t now;
    unsigned mut_rx;                                    /* mutants: pins admitted by their own count */
} sim_t;

static void take(sim_t *s, long n) { s->free -= n; if (s->free < s->min_free) s->min_free = s->free; }
static unsigned rx_cost_of(unsigned len) { unsigned c = len + 130u; return c > ML_HB_PIN_BUF_BYTES ? ML_HB_PIN_BUF_BYTES : c; }

typedef enum { K_WGQ, K_RING, K_USB, K_TX, K_JIT, K_KINDS } kind_t;
typedef struct { kind_t kind; bool ok; unsigned len; } check_t;
static check_t do_check(const model_t *m, sim_t *s, kind_t kind, size_t snapshot) {
    check_t c = {.kind = kind, .len = (kind == K_WGQ) ? (rnd(4) ? 1264u : 60u + rnd(300)) : 60u + rnd(1454)};
    switch (kind) {
    case K_WGQ: c.ok = s->wgq_n + 2 <= MAX_HELD && ml_wgrx_admit(&s->wb, c.len, snapshot) == ML_WGRX_OK; break;
    case K_RING: c.ok = s->ring_chunks < 10 && ml_hb_ok(snapshot, CHUNK_BYTES + 16); break;
    case K_USB: c.ok = m->upload && s->usb_n < GATEWAY_USB_RX_INFLIGHT_MAX && gateway_usb_rx_admit(&s->usb, c.len, snapshot); break;
    case K_TX:
        c.ok = false;
        if (!m->upload) break;
        if (m->tx_mode == 1) c.ok = gw_wtx_admitted(gw_wtx_admit(&s->pins, c.len, snapshot, s->now));
        else c.ok = s->tx_n < m->tx_pool;
        if (c.ok && s->tx_n >= 16) { gw_wtx_abort(&s->pins); c.ok = false; }   /* the driver refuses: abort */
        if (!c.ok) s->tx_refused++;
        break;
    case K_JIT: c.ok = s->jit_n + s->derp_n < 12 && ml_hb_ok(snapshot, 1480); break;
    default: break;
    }
    return c;
}
static void do_commit(sim_t *s, check_t c) {
    if (!c.ok) return;
    switch (c.kind) {
    case K_WGQ: s->wgq[s->wgq_n++].len = c.len; take(s, c.len + ML_WG_RX_OVERHEAD); break;
    case K_RING: s->ring_chunks++; take(s, CHUNK_BYTES + 16); break;
    case K_USB: s->usb_len[s->usb_n++] = c.len; take(s, c.len + 16); break;
    case K_TX: s->tx_cost[s->tx_n++] = (unsigned)gw_wtx_cost(c.len); take(s, gw_wtx_cost(c.len)); break;
    case K_JIT: if (s->jit_n < 4) s->jit_n++; else s->derp_n++; take(s, 1480); break;
    default: break;
    }
}

static void rx_arrive(const model_t *m, sim_t *s, unsigned len) {
    const unsigned cost = rx_cost_of(len);
    if (s->free < (long)cost) { s->driver_fail++; return; }
    take(s, cost);                                              /* the driver allocated it: nothing has checked anything yet */
    bool keep;
    if (m->rx_mode == 1) keep = s->rx_n < 64 && gw_wrx_admit(&s->pins, (size_t)s->free);
    else if (m->rx_mode == 2) keep = s->rx_n < m->rx_pool && (s->rx_n < m->rx_band || (size_t)s->free >= (m->pin_floor ? m->pin_floor : ML_HB_FLOOR));   /* a mutant gate */
    else keep = s->rx_n < m->rx_pool;                           /* the driver's pool is the only limit */
    if (!keep) { s->free += cost; s->rx_refused++; return; }
    s->rx_cost[s->rx_n++] = cost;
}
static void rx_consume(const model_t *m, sim_t *s) {            /* net_io (or lwIP) frees one pinned buffer, maybe into the WireGuard queue */
    if (!s->rx_n) return;
    unsigned i = rnd(s->rx_n), cost = s->rx_cost[i];
    s->rx_cost[i] = s->rx_cost[--s->rx_n];
    unsigned len = rnd(4) ? 1264 : 60 + rnd(300);
    bool queue = m->download && rnd(4) != 0 && s->wgq_n < MAX_HELD && ml_wgrx_admit(&s->wb, len, (size_t)s->free) == ML_WGRX_OK;   /* checked while the pin is still held */
    if (m->rx_mode == 1) gw_wrx_release(&s->pins);
    s->free += cost;
    if (queue) { s->wgq[s->wgq_n++].len = len; take(s, len + ML_WG_RX_OVERHEAD); }
}
static void tx_complete(const model_t *m, sim_t *s) {
    if (!s->tx_n) { if (m->tx_mode == 1 && rnd(8) == 0) gw_wtx_done(&s->pins); return; }   /* a done for a frame that was not ours */
    unsigned i = rnd(s->tx_n);
    s->free += s->tx_cost[i];
    s->tx_cost[i] = s->tx_cost[--s->tx_n];
    unsigned r = rnd(100);
    if (m->tx_mode == 1 && r >= 4) gw_wtx_done(&s->pins);              /* 4 %: the driver recycled the buffer without a callback (queue clear): the lease takes it */
}

static void step(const model_t *m, sim_t *s) {
    s->now += 1;
    unsigned a = rnd(100);
    if (a < 24) {                                               /* download: a burst of frames, as one A-MPDU or a window of segments */
        if (m->download) { unsigned k = 1 + rnd(8); while (k--) rx_arrive(m, s, rnd(4) ? 1264 + 66 : 60 + rnd(300)); }
    } else if (a < 44) {                                        /* consumers drain, partially (preempted by the Wi-Fi task) */
        unsigned k = 1 + rnd(5);
        while (k--) { rx_consume(m, s); if (rnd(3) == 0) break; }
    } else if (a < 52) {                                        /* wg_mgr pops a run */
        unsigned k = 1 + rnd(8);
        while (k-- && s->wgq_n) { held_t h = s->wgq[--s->wgq_n]; ml_wgrx_release_to(&s->wb, h.len); s->free += h.len + ML_WG_RX_OVERHEAD; }
    } else if (a < 76) {                                        /* elastic consumers and TX submit, one to three checking on the same free value */
        /* The checkers that can overlap are different sites (the USB ring worker, TinyUSB's receive, lwIP's transmit, the packet-pending
         * path; net_io and the DERP loop both feed the WireGuard queue, so that one may appear twice): a site is one task and cannot race itself. */
        kind_t kinds[3] = {(kind_t)rnd(K_KINDS), (kind_t)rnd(K_KINDS), (kind_t)rnd(K_KINDS)};
        if (m->upload && rnd(3) == 0) kinds[0] = K_TX;
        unsigned racers = rnd(16) == 0 ? 3 : rnd(4) == 0 ? 2 : 1;
        for (unsigned i = 1; i < racers; i++)
            for (unsigned tries = 0; tries < 16; tries++) {
                unsigned dup = 0;
                for (unsigned j = 0; j < i; j++) dup += kinds[j] == kinds[i];
                if (!dup || (kinds[i] == K_WGQ && dup == 1)) break;
                kinds[i] = (kind_t)rnd(K_KINDS);
            }
        size_t snapshot = (size_t)(s->free > 0 ? s->free : 0);
        check_t c[3];
        for (unsigned i = 0; i < racers; i++) c[i] = do_check(m, s, kinds[i], snapshot);
        for (unsigned i = 0; i < racers; i++) do_commit(s, c[i]);
        if (racers == 1 && kinds[0] == K_RING && !c[0].ok && s->ring_chunks && rnd(3) == 0) { s->ring_chunks--; s->free += CHUNK_BYTES + 16; }
    } else if (a < 86) {                                        /* TX frames complete; sometimes the driver clears a queue */
        unsigned k = 1 + rnd(3);
        while (k--) tx_complete(m, s);
        if (m->tx_mode == 1 && rnd(300) == 0) { for (unsigned i = 0; i < s->tx_n; i++) s->free += s->tx_cost[i]; s->tx_n = 0; gw_wtx_flush(&s->pins); }
    } else if (a < 94) {                                        /* USB frames leave */
        unsigned k = 1 + rnd(4);
        while (k-- && s->usb_n) { unsigned len = s->usb_len[--s->usb_n]; gateway_usb_rx_release(&s->usb); s->free += len + 16; }
    } else {
        while (s->jit_n && rnd(2)) { s->jit_n--; s->free += 1480; }
        while (s->derp_n && rnd(2)) { s->derp_n--; s->free += 1480; }
        if (s->ring_chunks && rnd(3) == 0) { s->ring_chunks--; s->free += CHUNK_BYTES + 16; }
    }
}

static long run(const model_t *m, long f0, unsigned long steps, bool print) {
    sim_t *s = calloc(1, sizeof(*s));
    s->pins = (gateway_wifi_pins)GATEWAY_WIFI_PINS_INIT;
    s->free = s->min_free = f0;
    for (unsigned long i = 0; i < steps; i++) {
        step(m, s);
        assert(s->free <= f0 + 1);
        if (m->rx_mode == 1) assert(gw_wrx_inflight(&s->pins) == s->rx_n);
    }
    long min = s->min_free;
    if (print)
        printf("  %-46s F0 %6ld B: min free %6ld B (%+ld vs the %d B reserve); pins held at the end RX %u TX %u (high water RX %u TX %u); refused RX %lu TX %lu; stale %u\n",
               m->name, f0, min, min - (long)ML_HB_RESERVE, ML_HB_RESERVE, s->rx_n, s->tx_n,
               atomic_load(&s->pins.rx_high_water), atomic_load(&s->pins.tx_high_water), s->rx_refused, s->tx_refused,
               atomic_load(&s->pins.tx_stale));
    if (m->tx_mode == 1) conserved_tx(&s->pins);
    free(s);
    return min;
}

static void test_floor(void) {
    model_t now = {.name = "amendment 2: bands + elastic floor (pools 16)", .rx_mode = 1, .tx_mode = 1, .rx_pool = 16, .tx_pool = 16, .upload = true, .download = true};
    model_t down = now, up = now;
    down.upload = false; down.name = "  download only";
    up.download = false; up.name = "  upload only";
    long worst[3] = {1l << 30, 1l << 30, 1l << 30};
    const model_t *ms[3] = {&now, &down, &up};
    for (long f0 = 34000; f0 <= 46000; f0 += 2000)
        for (int seed = 1; seed <= 6; seed++)
            for (int k = 0; k < 3; k++) {
                rs = 0x9e3779b97f4a7c15ull * (unsigned)seed;
                long v = run(ms[k], f0, 400000, f0 == 38000 && seed == 1);
                if (v < worst[k]) worst[k] = v;
                assert(v >= (long)ML_HB_RESERVE);                    /* THE BOUND: never below the recovery reserve */
            }
    printf("  worst of 7 start levels x 6 seeds: both directions %ld B, download %ld B, upload %ld B (reserve %d)\n", worst[0], worst[1], worst[2], ML_HB_RESERVE);

    /* What PR #42 left: the driver's 16 RX buffers pinned by sockets and lwIP with nothing counting them, TX held to 6 by the pool. */
    model_t merged = {.name = "PR #42 as merged (RX pool 16, TX pool 6)", .rx_pool = 16, .tx_pool = 6, .upload = true, .download = true};
    model_t merged_dl = merged; merged_dl.upload = false; merged_dl.name = "  download only";
    model_t pool16 = {.name = "TX pool 16, no budget (the experiment)", .rx_pool = 6, .tx_pool = 16, .upload = true, .download = false};
    long wm = 1l << 30, wd = 1l << 30, wp = 1l << 30;
    for (long f0 = 36000; f0 <= 42000; f0 += 2000)
        for (int seed = 1; seed <= 6; seed++) {
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long a = run(&merged, f0, 400000, f0 == 38000 && seed == 1); if (a < wm) wm = a;
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long b = run(&merged_dl, f0, 400000, f0 == 38000 && seed == 1); if (b < wd) wd = b;
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long c = run(&pool16, f0, 400000, f0 == 38000 && seed == 1); if (c < wp) wp = c;
        }
    printf("  without the budget: PR #42 as merged %ld B (download only %ld B; the board's minimum under a 6 Mbit/s UDP download was 5,000 B), TX pool 16 alone %ld B\n"
           "  (the board's 2,536 B had TCP upload and the whole upload chain filling the heap; this model's upload does not saturate the pool, so only the direction is shown)\n", wm, wd, wp);
    assert(wm < (long)ML_HB_RESERVE - 8000 && wd < (long)ML_HB_RESERVE - 5000 && wp < (long)ML_HB_RESERVE - 3000);

    /* Each ingredient matters: a mutant that keeps the gate but widens the RX band, or lowers the floor it checks, breaks the reserve. */
    model_t wide = {.name = "mutant: gate with an RX band of 10", .rx_mode = 2, .tx_mode = 1, .rx_pool = 16, .tx_pool = 16, .rx_band = 10, .upload = true, .download = true};
    model_t low = {.name = "mutant: gate with a floor of reserve + 3 KB", .rx_mode = 2, .tx_mode = 1, .rx_pool = 16, .tx_pool = 16, .rx_band = GATEWAY_WIFI_RX_BAND_MAX,
                   .pin_floor = ML_HB_RESERVE + 3000, .upload = true, .download = true};
    long ww = 1l << 30, wl = 1l << 30;
    for (long f0 = 36000; f0 <= 42000; f0 += 2000)
        for (int seed = 1; seed <= 6; seed++) {
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long a = run(&wide, f0, 400000, false); if (a < ww) ww = a;
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long b = run(&low, f0, 400000, false); if (b < wl) wl = b;
        }
    printf("  mutants: RX band 10 -> %ld B; elastic floor reserve + 3 KB -> %ld B\n", ww, wl);
    assert(ww < (long)ML_HB_RESERVE && wl < (long)ML_HB_RESERVE);
}

/* The arithmetic behind the schedule, with the real functions: the worst legal interleaving, written out. Three checkers (a ring chunk and
 * two USB frames, 3,064 + 1,534 + 1,534 B: the design point of ADR 0022, the TX submit being one of the concurrent ones) pass on the same free
 * value; then every pin the budget allows arrives; the minimum is the floor minus what the two smaller racers took and the pins. */
static void test_worst_interleaving(void) {
    const long c_ring = CHUNK_BYTES + 16, c_frame = 1518 + 16;
    long free_now = (long)ML_HB_FLOOR + c_ring;                                 /* every check below passes here */
    assert(ml_hb_ok((size_t)free_now, (size_t)c_ring) && ml_hb_ok((size_t)free_now, (size_t)c_frame));
    gateway_wifi_pins b = GATEWAY_WIFI_PINS_INIT;
    free_now -= c_ring + 2 * c_frame;                                           /* the three racers allocate */
    assert(free_now == (long)ML_HB_FLOOR - 2 * c_frame);
    long min = free_now;
    /* The pins: the band first (5 shared slots, here 4 RX and 1 TX: admitted at any heap). Nothing else is admitted below the floor. */
    for (unsigned i = 0; i < GATEWAY_WIFI_RX_BAND_MAX; i++) {
        free_now -= ML_HB_PIN_BUF_BYTES;
        assert(gw_wrx_admit(&b, (size_t)free_now));
    }
    assert(gw_wtx_admit(&b, 1514, (size_t)free_now, 0) == GW_WTX_BAND);
    free_now -= ML_HB_PIN_BUF_BYTES;
    for (int i = 0; i < 20; i++) {                                              /* everything past the band is refused, whatever arrives */
        assert(gw_wtx_admit(&b, 1514, (size_t)free_now, 0) == GW_WTX_HEAP);
        assert(!gw_wrx_admit(&b, (size_t)(free_now - ML_HB_PIN_BUF_BYTES)));
    }
    long last = free_now - (long)ML_HB_PIN_BUF_BYTES;                          /* the one RX buffer under check when it is refused */
    if (last < min) min = last;
    printf("  worst legal interleaving: floor %d - racers %ld - band pins %u x %u - the RX frame under check %u = %ld B (reserve %d)\n",
           ML_HB_FLOOR, 2 * c_frame, GATEWAY_WIFI_BAND_TOTAL, ML_HB_PIN_BUF_BYTES, ML_HB_PIN_BUF_BYTES, min, ML_HB_RESERVE);
    assert(min >= (long)ML_HB_RESERVE && min == 16832);
    /* A fourth racer is the one place the bound is quantified, not proved (ADR 0022): it costs one more frame. */
    assert(min - c_frame < (long)ML_HB_RESERVE && min - c_frame > 14000);
}

int main(void) {
    printf("wifi pin budget: floor %d B = reserve %d + negotiation peak %d; TX pool %d, shared band %u (each direction at most %u/%u) + 1 RX frame under check = %u of %u buffers\n",
           ML_HB_FLOOR, ML_HB_RESERVE, ML_ADM_NEG_PEAK_BYTES, GATEWAY_WIFI_TX_POOL, GATEWAY_WIFI_BAND_TOTAL, GATEWAY_WIFI_RX_BAND_MAX, GATEWAY_WIFI_TX_BAND_MAX,
           GATEWAY_WIFI_BAND_TOTAL + 1, ML_HB_PIN_BUFFERS);
    test_constants();
    test_tx_rules();
    test_tx_abort_flush_lease();
    test_rx_rules();
    test_joint_band();
    test_exactly_once_random();
    printf("  rules, lease (wrapping clock), abort/flush, exactly-once over 40 seeds x 100,000 events: ok\n");
    test_threads();
    printf("  threads (2 submitters, pp task, flusher, 3 RX users): ok\n");
    test_worst_interleaving();
    test_floor();
    printf("wifi pin budget ok\n");
    return 0;
}
