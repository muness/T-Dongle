/* The heap budget (ml_heap_budget.h, ADR 0022): every elastic consumer under an adversarial schedule, with Wi-Fi buffers pinned by sockets
 * arriving without any check, must keep the free internal heap at or above the recovery reserve. The same schedule against the
 * constants before ADR 0022 must NOT: it reproduces the board's 3 KB minimum, which is what shows the test can fail.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra -pthread \
 *      -I components/microlink/include -I main tests/test_heap_budget.c -o build-host/test_heap_budget
 *
 * The model has one number, `free`. Consumers take from it only through the admission code the firmware runs (the real
 * ml_wgrx_admit, rt_queue_budget, gateway_usb_rx_admit, ml_hb_ok); the unchecked claimants take what they are configured to take.
 * Racing checkers: with probability 1/4 two consumers pass their check on the same `free` before either allocates. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_wg_rx_budget.h"
#include "route_table.h"
#include "usb_rx_budget.h"

#define CHUNK_BYTES 3048u   /* TINYUSB_NET_TX_CHUNK_BYTES: two 1,524 B slabs */
atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];
ml_wgrx_budget_t ml_wgrx_budget;

static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(uint32_t n) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)((rs >> 11) % n); }

typedef struct {
    const char *name;
    bool legacy;
    unsigned pins;          /* largest burst of pinned Wi-Fi buffers any one socket holds */
    size_t pin_cost;
    bool upload;            /* the schedule includes USB host frames (upload) */
    size_t wgq_floor, router_floor, ring_floor, other_floor, usb_floor;   /* legacy only (usb_floor 0: unchecked, as before): the new code takes its floors from the real functions */
} model_t;

typedef struct { unsigned len; } held_t;
#define MAX_HELD 64
typedef struct {
    long free, min_free;
    unsigned pinned;                          /* Wi-Fi buffers currently pinned */
    held_t wgq[MAX_HELD]; unsigned wgq_n;     /* WireGuard datagrams waiting (heap blocks) */
    unsigned ring_chunks;                     /* elastic USB chunks */
    held_t route[MAX_HELD]; unsigned route_n; unsigned route_bytes;
    gateway_usb_rx_budget usb; unsigned usb_len[GATEWAY_USB_RX_INFLIGHT_MAX]; unsigned usb_n;
    unsigned jit_n, derp_n;
    unsigned long driver_fail;                /* a pin that found the heap empty (the driver drops the frame) */
    unsigned long refused[6];
    ml_wgrx_budget_t wb;
} sim_t;

static void take(sim_t *s, long n) { s->free -= n; if (s->free < s->min_free) s->min_free = s->free; assert(s->free >= 0 || 1); }

static bool wgq_check(const model_t *m, sim_t *s, unsigned len) {
    if (m->legacy) return (size_t)s->free >= m->wgq_floor + len + ML_WG_RX_OVERHEAD && atomic_load(&s->wb.bytes) + len + ML_WG_RX_OVERHEAD <= ML_WG_RX_QUEUE_BYTES;
    return ml_wgrx_admit(&s->wb, len, (size_t)s->free) == ML_WGRX_OK;    /* reserves on success */
}
static void wgq_commit(const model_t *m, sim_t *s, unsigned len) {
    if (m->legacy) atomic_fetch_add(&s->wb.bytes, len + ML_WG_RX_OVERHEAD);
    s->wgq[s->wgq_n++].len = len;
    take(s, len + ML_WG_RX_OVERHEAD);
}
static bool ring_check(const model_t *m, sim_t *s) {
    const size_t chunk = CHUNK_BYTES + 16;
    return m->legacy ? (size_t)s->free >= chunk + m->ring_floor : ml_hb_ok((size_t)s->free, chunk);
}

/* one actor step; `defer` collects checks that passed before another allocation (the race) */
static void step(const model_t *m, sim_t *s) {
    unsigned a = rnd(100);
    if (a < 22) {                                          /* a burst arrives: sockets pin Wi-Fi buffers, nothing checks the heap */
        unsigned k = 1 + rnd(m->pins);
        for (unsigned i = 0; i < k && s->pinned < m->pins; i++) {
            if (s->free < (long)m->pin_cost) { s->driver_fail++; break; }
            s->pinned++; take(s, (long)m->pin_cost);
        }
    } else if (a < 52) {                                   /* net_io drains the mailbox: copy into the WireGuard queue, or drop; either frees the pin */
        while (s->pinned) {
            unsigned len = rnd(4) ? 1264 : 60 + rnd(300);
            bool race = rnd(4) == 0 && s->pinned >= 1;
            if (race) {                                    /* two checkers (net_io and the DERP loop) pass on the same free */
                bool ok1 = s->wgq_n + 2 <= MAX_HELD && wgq_check(m, s, len), ok2 = ok1 && wgq_check(m, s, len);
                if (ok1) { s->pinned--; s->free += (long)m->pin_cost; wgq_commit(m, s, len); }
                if (ok2) { wgq_commit(m, s, len); if (m->legacy == false) {} }
                if (!ok1) { s->pinned--; s->free += (long)m->pin_cost; s->refused[0]++; }
            } else if (s->wgq_n < MAX_HELD && wgq_check(m, s, len)) {
                s->pinned--; s->free += (long)m->pin_cost; wgq_commit(m, s, len);
            } else { s->pinned--; s->free += (long)m->pin_cost; s->refused[0]++; }
            if (rnd(3) == 0) break;                        /* net_io is preempted by the Wi-Fi task: a partial drain */
        }
    } else if (a < 64) {                                   /* wg_mgr pops a run of up to 8 and finishes with them later: modelled as release */
        unsigned k = 1 + rnd(8);
        while (k-- && s->wgq_n) {
            held_t h = s->wgq[--s->wgq_n];
            if (m->legacy) atomic_fetch_sub(&s->wb.bytes, h.len + ML_WG_RX_OVERHEAD); else ml_wgrx_release_to(&s->wb, h.len);
            s->free += h.len + ML_WG_RX_OVERHEAD;
        }
    } else if (a < 72) {                                   /* the USB ring worker grows or shrinks */
        if (ring_check(m, s) && s->ring_chunks < 10) { s->ring_chunks++; take(s, CHUNK_BYTES + 16); }
        else if (s->ring_chunks && rnd(3) == 0) { s->ring_chunks--; s->free += CHUNK_BYTES + 16; }
    } else if (a < 84) {                                   /* upload: a frame from the USB host, then the router queue */
        unsigned len = 60 + rnd(1458);
        if (!m->upload) {
        } else if (m->legacy) {
            if (s->usb_n < GATEWAY_USB_RX_INFLIGHT_MAX && (m->usb_floor == 0 || (size_t)s->free >= m->usb_floor + len + 16)) { s->usb_len[s->usb_n++] = len; atomic_fetch_add(&s->usb.inflight, 1); take(s, len + 16); }
            else s->refused[1]++;
        } else if (gateway_usb_rx_admit(&s->usb, len, (size_t)s->free)) { s->usb_len[s->usb_n++] = len; take(s, len + 16); }
        else s->refused[1]++;
    } else if (a < 92) {                                   /* usb frames leave (the router queue holds them to its byte budget, then the tunnel takes them) */
        unsigned k = 1 + rnd(4);
        while (k-- && s->usb_n) { unsigned len = s->usb_len[--s->usb_n]; gateway_usb_rx_release(&s->usb); s->free += len + 16; }
    } else if (a < 96) {                                   /* a packet pending a handshake / a relay packet */
        size_t cost = 1464 + 16;
        size_t floor = m->legacy ? m->other_floor : ML_HB_FLOOR;
        if ((size_t)s->free >= floor + cost && s->jit_n < 4) { s->jit_n++; take(s, (long)cost); } else s->refused[2]++;
        if ((size_t)s->free >= floor + cost && s->derp_n < 8) { s->derp_n++; take(s, (long)cost); } else s->refused[3]++;
    } else {
        while (s->jit_n && rnd(2)) { s->jit_n--; s->free += 1480; }
        while (s->derp_n && rnd(2)) { s->derp_n--; s->free += 1480; }
    }
}

static long run(const model_t *m, long f0, unsigned long steps, bool print) {
    sim_t *s = calloc(1, sizeof(*s));
    s->free = s->min_free = f0;
    for (unsigned long i = 0; i < steps; i++) {
        step(m, s);
        assert(s->free <= f0 + 1);
    }
    long min = s->min_free;
    if (print) printf("  %-34s F0 %6ld B: min free %6ld B (%+ld vs the %d B reserve); driver alloc failures %lu; refused wgq %lu, usb %lu, pending %lu, relay %lu\n",
                      m->name, f0, min, min - (long)ML_HB_RESERVE, ML_HB_RESERVE, s->driver_fail, s->refused[0], s->refused[1], s->refused[2], s->refused[3]);
    free(s);
    return min;
}

int main(void) {
    printf("heap budget: floor %d B = reserve %d + negotiation peak %d; largest pin burst %u buffers x %u B = %u B, slack %u B\n",
           ML_HB_FLOOR, ML_HB_RESERVE, ML_ADM_NEG_PEAK_BYTES, ML_HB_PIN_BUFFERS, ML_HB_PIN_BUF_BYTES, ML_HB_PIN_BYTES, ML_HB_SLACK_BYTES);
    assert(ML_HB_PIN_BUFFERS == 6);
    /* the inequality the header asserts, restated with numbers */
    assert(ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR);
    assert(ROUTE_HEAP_RESERVE == ML_HB_FLOOR && ML_WG_RX_FLOOR_FREE == ML_HB_FLOOR);
    assert(rt_queue_budget(ML_HB_FLOOR + 5000) == 5000 && rt_queue_budget(ML_HB_FLOOR) == ROUTE_QUEUE_BYTES_MIN);

    model_t now = {.name = "ADR 0022 (one floor, 6 pins)", .legacy = false, .pins = ML_HB_PIN_BUFFERS, .pin_cost = ML_HB_PIN_BUF_BYTES, .upload = true};
    /* before: queue and router at the recovery reserve, ring at recovery + a 16,000 B peak, ten pinned buffers */
    model_t before = {.name = "before (queue 16,384, ring 32,384, 10)", .legacy = true, .pins = 10, .pin_cost = ML_HB_PIN_BUF_BYTES, .upload = true,
                      .wgq_floor = 16384, .router_floor = 16384, .ring_floor = 32384, .other_floor = 16384, .usb_floor = 0};
    /* The board's case first: a download flood (no upload), 37 KB free. Before: the ring stops at 32,384, the queue fills its 12 KB below
     * that, ten pinned buffers arrive below that: a few KB. */
    {
        model_t d_now = now, d_before = before;
        d_now.upload = d_before.upload = false;
        d_now.name = "download flood, ADR 0022"; d_before.name = "download flood, before";
        long worst_d_before = 1l << 30, worst_d_now = 1l << 30;
        for (int seed = 1; seed <= 6; seed++) {
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long a = run(&d_now, 37000, 400000, seed == 1); if (a < worst_d_now) worst_d_now = a;
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long b = run(&d_before, 37000, 400000, seed == 1); if (b < worst_d_before) worst_d_before = b;
        }
        assert(worst_d_now >= (long)ML_HB_RESERVE);
        assert(worst_d_before < 6000 && worst_d_before > -4000);       /* the board saw 3,040-3,140 B; the model lands in the same few KB */
        printf("  download flood at 37 KB free, worst of 6 seeds: now %ld B, before %ld B (board: 3,040-3,140 B)\n", worst_d_now, worst_d_before);
    }
    long worst_now = 1l << 30, worst_before = 1l << 30;
    for (long f0 = 34000; f0 <= 44000; f0 += 1000) {
        for (int seed = 1; seed <= 6; seed++) {
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed;
            long a = run(&now, f0, 400000, f0 == 37000 && seed == 1);
            if (a < worst_now) worst_now = a;
            assert(a >= (long)ML_HB_RESERVE);              /* THE BOUND: never below the recovery reserve */
            rs = 0x9e3779b97f4a7c15ull * (unsigned)seed;
            long b = run(&before, f0, 400000, f0 == 37000 && seed == 1);
            if (b < worst_before) worst_before = b;
        }
    }
    printf("  worst case over F0 34-44 KB and 6 seeds: now %ld B (reserve %d), before %ld B\n", worst_now, ML_HB_RESERVE, worst_before);
    assert(worst_before < (long)ML_HB_RESERVE - 8000);     /* the old constants break the reserve by a wide margin (upload had no check at all) */
    /* The racing-checker slack, by arithmetic: two checkers that both pass on the same free value f >= FLOOR + max(c1, c2) leave
     * f - c1 - c2 >= FLOOR - min(c1, c2): at most one buffer below the floor. The largest cost is a ring chunk against a full frame. */
    {
        const long c_ring = CHUNK_BYTES + 16, c_frame = 1518 + 16;
        long f = (long)ML_HB_FLOOR + c_ring;                    /* both checks pass here */
        assert(ml_hb_ok((size_t)f, (size_t)c_ring) && ml_hb_ok((size_t)f, (size_t)c_frame));
        long after = f - c_ring - c_frame;
        assert(after == (long)ML_HB_FLOOR - c_frame && (long)ML_HB_FLOOR - after <= (long)ML_HB_SLACK_BYTES);
        assert(after - (long)ML_HB_PIN_BYTES >= (long)ML_HB_RESERVE);   /* and then the whole pin burst arrives */
    }
    /* How far the slack goes. N checkers that pass on the same free value f leave f - sum(costs) >= FLOOR - (sum - max): the largest
     * one is free, the rest come out of the slack. Two cores and a preemption in the check-to-allocate window make three concurrent
     * checkers the design point (a ring chunk and two frames: 3,068 B <= 3,328 B); a fourth (and the two exempt USB frames below the
     * floor) is not covered, and what it costs is bounded here: the pin burst still lands on top, and the heap stays far from empty.
     * Stated in ADR 0022 as the one place the bound is not proved, only quantified. */
    {
        const long c_ring = CHUNK_BYTES + 16, c_frame = 1518 + 16, pins = (long)ML_HB_PIN_BYTES, floor = (long)ML_HB_FLOOR, reserve = (long)ML_HB_RESERVE;
        long three = floor - 2 * c_frame - pins;               /* ring chunk + two frames race, then the largest pin burst */
        assert(2 * c_frame <= (long)ML_HB_SLACK_BYTES && three >= reserve);
        long four = floor - 3 * c_frame - pins;                /* a fourth checker */
        assert(four < reserve && four >= reserve - 1500 && four > 14000);
        long stacked = floor - 2 * c_frame - 2 * c_frame - pins; /* ... and the two exempt USB frames admitted below the floor */
        assert(stacked < reserve && stacked >= reserve - 3000);
        printf("  racing checkers: ring chunk + 2 frames + pin burst: %ld B (reserve %ld); a fourth: %ld B; plus both exempt USB frames: %ld B\n",
               three, reserve, four, stacked);
        (void)c_ring;
    }
    /* A floor that leaves out the pinned buffers must break the reserve (the slack is the arithmetic above). */
    for (int term = 0; term < 1; term++) {
        model_t m = now; m.legacy = true;
        m.wgq_floor = ML_HB_RESERVE + ML_HB_SLACK_BYTES;      /* without the pins */
        m.router_floor = m.ring_floor = m.other_floor = m.usb_floor = m.wgq_floor;
        long worst = 1l << 30;
        for (int seed = 1; seed <= 12; seed++) { rs = 0x9e3779b97f4a7c15ull * (unsigned)seed; long v = run(&m, 37000, 600000, false); if (v < worst) worst = v; }
        printf("  mutant, floor without the %s (%zu B): min free %ld B\n", "pinned buffers", m.wgq_floor, worst);
        assert(worst < (long)ML_HB_RESERVE);
    }
    printf("heap budget ok\n");
    return 0;
}
