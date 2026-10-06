/* Wi-Fi driver buffers pinned by the data path, counted at run time and held to the one heap floor (ADR 0022, amendment 2).
 *
 * A Wi-Fi buffer is heap that nothing in this firmware allocates, so nothing used to check it:
 *   RX  The driver copies each received frame into a dynamic RX buffer and hands it to lwIP; the buffer stays pinned until the pbuf
 *       that wraps it is freed (CONFIG_LWIP_L2_TO_L3_COPY is off), possibly in a socket mailbox, the TCP window or the tcpip mailbox.
 *   TX  esp_wifi_internal_tx() copies the frame into a dynamic TX buffer, which stays until the frame is sent or dropped.
 * Both are bounded only by the driver's pool sizes (16 dynamic RX and TX buffers, 26.6 KB each), which is far more than the 6
 * buffers the budget has room for (ml_heap_budget.h). ADR 0022 held TX to 6 by shrinking the pool, which cost upload throughput
 * (board: pool 16, TCP up +25 %, but heap minimum 2,536 B). Here both directions are counted at the one place each starts, and
 * the pool can be as large as the driver supports because the count, not the pool, decides.
 *
 * The rule, the same for both directions. A frame is admitted when
 *   (a) it fits the BAND: the Wi-Fi buffers pinned in BOTH directions together are fewer than GATEWAY_WIFI_BAND_TOTAL (5), and this
 *       direction holds fewer than its maximum (4, so the other direction always keeps one). 5 + 1 (the RX frame being checked, below)
 *       are the 6 buffers ML_HB_PIN_BUFFERS that the elastic floor leaves room for, so the band is paid for by the floor and needs no heap
 *       read: a TCP ACK, an ARP or DHCP reply, a WireGuard keepalive always finds a buffer, and a one-way flow gets 4 of the 5 (upload:
 *       4 TX frames in flight with the RX side idle; download: 4 RX with TX idle). Both counts live in one atomic word, so the joint
 *       limit has no race between the two directions; or
 *   (b) it is ELASTIC: the free internal heap stays at or above ML_HB_FLOOR after the buffer exists, exactly like every other
 *       elastic consumer (USB ring, WireGuard queue, router queue, pending packets, USB receive frames).
 * Otherwise it is refused and counted: TX returns ESP_ERR_NO_MEM (lwIP: ERR_MEM, below), RX frees the frame at once (loss, as the
 * driver's own pool exhaustion would be).
 *
 * Why this bounds the minimum. The floor holds (ml_heap_budget.h): ML_HB_FLOOR >= ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES.
 * Elastic frames never take the heap below ML_HB_FLOOR (TX checks before the driver allocates, RX after: the check includes the
 * buffer itself). Band frames are at most GATEWAY_WIFI_BAND_TOTAL buffers in both directions together, and the RX frame under check is
 * one more (the driver allocated it before the check and a refusal frees it at once, so it dips the heap for that moment): together
 * ML_HB_PIN_BUFFERS, the pin burst the floor was sized for. (The driver's static RX buffers and its management state are allocated
 * at start.) So pins cannot take the heap below ML_HB_FLOOR - ML_HB_PIN_BYTES, and the racing checkers take at most
 * ML_HB_SLACK_BYTES more (one concurrent check-to-allocate window per core plus one preemption, as before).
 * tests/test_wifi_pin_budget.c runs RX and TX pins, the other elastic consumers and racing checkers in one adversarial schedule.
 *
 * TX release: the tx-done callback, and why that alone is not enough. esp_wifi_set_tx_done_cb() (esp_private/wifi.h) installs one
 * global callback; the closed-source driver (libpp, ppProcTxDone) calls it, from the pp task, for each completed TX descriptor with
 * the "done" bit set, and passes the interface, the frame as the driver holds it (not our buffer), its length and a success flag.
 * It does not identify our frame, so the count is a FIFO of charge times: a done pops the oldest. It is not called for every buffer:
 * the driver also recycles queued TX buffers without completing them when it clears a queue (pp_stop_sw_txq, ppClearTxq,
 * lmacStopTransmit, pp_deattach; read from libpp.a, see ADR 0022 amendment 2). So a charge is also released by
 *   - the submitter, when esp_wifi_internal_tx() reports failure (no buffer exists then: abort),
 *   - the STA link going down or coming up (flush: the driver cleared its queues), and
 *   - a lease: a charge older than GW_WTX_LEASE_MS (3 s) is presumed gone (stale, counted). At 1 Mbit/s a full frame is 12 ms of air
 *     time; 16 queued frames with 7 retries each can take 1.4 s, and an off-channel scan dwell adds to that, hence 3 s, not 1.
 * Missing a callback therefore costs a credit until the flow pauses for a lease (never a permanent leak: an idle or throttled link
 * heals; but under steady traffic a systematically missing callback is not repaired, see GW_WTX_LEASE_MS), and an extra
 * callback (a management frame completing) can release one credit early, which admits one more frame than counted for a moment:
 * both are bounded by the pool and visible in the counters (`tx_stale`, `tx_unmatched`) so the board decides whether the callback
 * can be trusted more. Release is exactly once per charge by construction: only the FIFO's head or tail is ever removed, under one lock.
 *
 * lwIP behaviour. A refused TX frame returns ESP_ERR_NO_MEM, which wlanif maps to ERR_MEM. For TCP that is the best answer there
 * is: tcp_output_segment() returns the error without consuming the segment, the segment stays on the unsent queue (no loss inferred,
 * no congestion window cut, no retransmission counted) and goes out when tcp_output next runs: on the next ACK or segment from the peer
 * (tcp_input ends in tcp_output) or the next write. A refusal happens with frames in flight (the band is full of them), so an ACK
 * normally comes first. If none does (the refusal was by heap with nothing in flight), the retransmission timer that
 * tcp_output_segment() armed BEFORE the failed send fires, and tcp_slowtmr treats "unsent but nothing unacked" as a failed send:
 * rto back-off, ssthresh halved, cwnd one MSS. tcp_txnow() would retry sooner but nothing calls it. So: no cut in the usual case, the
 * ordinary RTO reaction (not worse than loss) when the heap itself is the reason. Dropping instead (returning ERR_OK)
 * made lwIP believe the segment was sent: it waits for an ACK that cannot come, then retransmits and halves the window. UDP
 * (WireGuard, the forwarded traffic) gets ERR_MEM from udp_sendto up through wireguardif_tx_commit; gateway_send_packet discards
 * the result and frees the packet: a silent loss for the inner flow (its own TCP reacts), counted only here (tx_refused_pool,
 * tx_refused_heap), the same loss as before.
 *
 * Locking. The TX FIFO is touched from the lwIP/tcpip context (submit), the pp task (done) and the event task (flush): one critical
 * section (portMUX on the target, a mutex on the host), a few instructions. RX is lock free (one atomic counter).
 * Everything the tx-done callback calls is inline and in IRAM (IRAM_ATTR) because the pp task can run while the flash cache is off. */
#pragma once
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ml_heap_budget.h"

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
typedef portMUX_TYPE gw_wp_lock_t;
#define GW_WP_LOCK_INIT portMUX_INITIALIZER_UNLOCKED
#define GW_WP_ENTER(b) portENTER_CRITICAL_SAFE(&(b)->lock)
#define GW_WP_EXIT(b) portEXIT_CRITICAL_SAFE(&(b)->lock)
#else
#include <pthread.h>
typedef pthread_mutex_t gw_wp_lock_t;
#define GW_WP_LOCK_INIT PTHREAD_MUTEX_INITIALIZER
#define GW_WP_ENTER(b) pthread_mutex_lock(&(b)->lock)
#define GW_WP_EXIT(b) pthread_mutex_unlock(&(b)->lock)
#endif
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif

/* The driver's dynamic TX pool (CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM) and the FIFO that follows it. */
#ifdef CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM
#define GATEWAY_WIFI_TX_POOL CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM
#else
#define GATEWAY_WIFI_TX_POOL 16
#endif
#define GW_WTX_RING 16u
/* The band: pinned buffers the two directions may have together without a heap check. BAND_TOTAL + the one RX frame under check =
 * ML_HB_PIN_BUFFERS (6), the burst the floor was sized for. Each direction is capped one below the total, so the other always has one. */
#define GATEWAY_WIFI_BAND_TOTAL 5u
#define GATEWAY_WIFI_RX_BAND_MAX 4u
#define GATEWAY_WIFI_TX_BAND_MAX 4u
/* A charge older than this was dropped by the driver without a tx-done (see above). It is the LAST fallback (link events flush the queues
 * the driver clears), so it is long: expiring a charge whose buffer is still queued admits a replacement above the count, and a stall
 * (an off-channel scan dwell, a channel switch, a low-priority access category behind a busy one, 16 queued frames each retried at
 * 1 Mbit/s: ~85 ms a frame, 1.4 s for the lot) must not read as loss. The price of a longer lease is only how long a really missed
 * done keeps one credit: a missed done leaves the surplus charge at the TAIL of the FIFO while traffic flows (dones pop the head), so
 * it expires only when the flow slows below pool/lease frames a second; at 3 s that is ~5 frames/s (~64 kbit/s) before a leak of
 * the whole pool heals itself, which is the floor of what a systematically missing callback costs. `tx_stale` says if that happens. */
#define GW_WTX_LEASE_MS 3000u
/* What a TX buffer costs beyond the frame: the driver's descriptor, the 802.11 QoS and LLC headers, the allocator header. Capped at
 * the full-frame cost the budget is sized with (ML_HB_PIN_BUF_BYTES). */
#define GW_WTX_OVERHEAD 192u

_Static_assert(GATEWAY_WIFI_BAND_TOTAL + 1u <= ML_HB_PIN_BUFFERS,
               "the Wi-Fi band and the RX frame under check can pin more buffers than the heap budget allows (ml_heap_budget.h)");
_Static_assert(GATEWAY_WIFI_RX_BAND_MAX + 1u <= GATEWAY_WIFI_BAND_TOTAL && GATEWAY_WIFI_TX_BAND_MAX + 1u <= GATEWAY_WIFI_BAND_TOTAL,
               "each direction must leave the other one band slot, or ACKs and ARP can be starved");
_Static_assert(GATEWAY_WIFI_BAND_TOTAL <= 127u, "the two band counts share one word, 8 bits each");
_Static_assert(GATEWAY_WIFI_TX_POOL >= (int)GATEWAY_WIFI_TX_BAND_MAX && GATEWAY_WIFI_TX_POOL <= (int)GW_WTX_RING, "the TX pool must hold the TX band and fit the FIFO");
_Static_assert(GW_WTX_OVERHEAD <= ML_HB_PIN_BUF_BYTES, "a TX buffer's overhead cannot exceed a full buffer");

typedef struct {
    gw_wp_lock_t lock;
    uint32_t tx_stamp[GW_WTX_RING];   /* ms at which each outstanding TX charge was made, oldest first from tx_head */
    uint32_t tx_head, tx_count;       /* guarded by lock */
    atomic_uint pins;                 /* RX buffers delivered to lwIP and not yet freed (bits 0-7) and TX charges outstanding (bits 8-15), one word
                                       * so the band's joint limit is decided on both at once. tx field == tx_count, changed under the lock */
    /* Evidence. All monotonic except the high-water marks. */
    atomic_uint tx_charged, tx_done, tx_aborted, tx_flushed, tx_stale, tx_unmatched;
    atomic_uint tx_band, tx_elastic, tx_refused_pool, tx_refused_heap, tx_high_water;
    atomic_uint rx_band, rx_elastic, rx_dropped, rx_released, rx_unmatched, rx_high_water;
} gateway_wifi_pins;
#define GATEWAY_WIFI_PINS_INIT {.lock = GW_WP_LOCK_INIT}
#define GW_WP_RX_ONE 1u
#define GW_WP_TX_ONE 0x100u
static inline unsigned gw_wp_rx(unsigned word) { return word & 0xffu; }
static inline unsigned gw_wp_tx(unsigned word) { return (word >> 8) & 0xffu; }
/* The band's decision for one more frame of a direction, from a snapshot of both counts. */
static inline bool gw_wp_rx_in_band(unsigned word) { return gw_wp_rx(word) < GATEWAY_WIFI_RX_BAND_MAX && gw_wp_rx(word) + gw_wp_tx(word) < GATEWAY_WIFI_BAND_TOTAL; }
static inline bool gw_wp_tx_in_band(unsigned word) { return gw_wp_tx(word) < GATEWAY_WIFI_TX_BAND_MAX && gw_wp_rx(word) + gw_wp_tx(word) < GATEWAY_WIFI_BAND_TOTAL; }
/* Readers without the lock (status, diagnostics, the tests). */
static inline unsigned gw_wtx_outstanding(const gateway_wifi_pins *b) { return gw_wp_tx(atomic_load_explicit(&b->pins, memory_order_relaxed)); }
static inline unsigned gw_wrx_inflight(const gateway_wifi_pins *b) { return gw_wp_rx(atomic_load_explicit(&b->pins, memory_order_relaxed)); }

typedef enum { GW_WTX_BAND, GW_WTX_ELASTIC, GW_WTX_POOL, GW_WTX_HEAP } gw_wtx_verdict;
static inline bool gw_wtx_admitted(gw_wtx_verdict v) { return v == GW_WTX_BAND || v == GW_WTX_ELASTIC; }

/* The heap one TX frame of `len` bytes costs. */
static inline size_t gw_wtx_cost(unsigned len) {
    size_t c = (size_t)len + GW_WTX_OVERHEAD;
    return c > ML_HB_PIN_BUF_BYTES ? ML_HB_PIN_BUF_BYTES : c;
}

static inline void gw_wp_max(atomic_uint *mark, unsigned v) {
    unsigned seen = atomic_load_explicit(mark, memory_order_relaxed);
    while (v > seen && !atomic_compare_exchange_weak_explicit(mark, &seen, v, memory_order_relaxed, memory_order_relaxed)) {
    }
}

/* Remove the oldest charge. Caller holds the lock and has checked tx_count. */
static inline IRAM_ATTR void gw_wtx_pop_head(gateway_wifi_pins *b) {
    b->tx_head = (b->tx_head + 1u) % GW_WTX_RING;
    b->tx_count--;
}

/* TX, before esp_wifi_internal_tx. `free_internal` is the free internal heap measured by the caller (injected for the tests), `now_ms`
 * a millisecond clock (wraps are fine). On GW_WTX_BAND or GW_WTX_ELASTIC the frame is charged and the caller MUST release it exactly
 * once: gw_wtx_abort if esp_wifi_internal_tx fails, otherwise the driver's tx-done, a flush or the lease does. */
static inline gw_wtx_verdict gw_wtx_admit(gateway_wifi_pins *b, unsigned len, size_t free_internal, uint32_t now_ms) {
    gw_wtx_verdict v;
    unsigned stale = 0, count;
    GW_WP_ENTER(b);
    /* Charges are in order, so only the head can be the oldest: expire from there. */
    while (b->tx_count && (int32_t)(now_ms - b->tx_stamp[b->tx_head]) > (int32_t)GW_WTX_LEASE_MS) {
        gw_wtx_pop_head(b);
        stale++;
    }
    if (stale) atomic_fetch_sub_explicit(&b->pins, stale * GW_WP_TX_ONE, memory_order_acq_rel);
    unsigned word = atomic_load_explicit(&b->pins, memory_order_relaxed);
    for (;;) {                                             /* RX changes the word without our lock: decide on a snapshot, commit with a CAS */
        if (b->tx_count >= (unsigned)GATEWAY_WIFI_TX_POOL) v = GW_WTX_POOL;
        else if (gw_wp_tx_in_band(word)) v = GW_WTX_BAND;
        else if (ml_hb_ok(free_internal, gw_wtx_cost(len))) v = GW_WTX_ELASTIC;
        else v = GW_WTX_HEAP;
        if (!gw_wtx_admitted(v) || atomic_compare_exchange_weak_explicit(&b->pins, &word, word + GW_WP_TX_ONE, memory_order_acq_rel, memory_order_relaxed)) break;
    }
    if (gw_wtx_admitted(v)) b->tx_stamp[(b->tx_head + b->tx_count++) % GW_WTX_RING] = now_ms;
    count = b->tx_count;
    GW_WP_EXIT(b);
    if (stale) atomic_fetch_add_explicit(&b->tx_stale, stale, memory_order_relaxed);
    switch (v) {
    case GW_WTX_BAND: atomic_fetch_add_explicit(&b->tx_band, 1, memory_order_relaxed); break;
    case GW_WTX_ELASTIC: atomic_fetch_add_explicit(&b->tx_elastic, 1, memory_order_relaxed); break;
    case GW_WTX_POOL: atomic_fetch_add_explicit(&b->tx_refused_pool, 1, memory_order_relaxed); break;
    case GW_WTX_HEAP: atomic_fetch_add_explicit(&b->tx_refused_heap, 1, memory_order_relaxed); break;
    }
    if (gw_wtx_admitted(v)) {
        atomic_fetch_add_explicit(&b->tx_charged, 1, memory_order_relaxed);
        gw_wp_max(&b->tx_high_water, count);
    }
    return v;
}

/* esp_wifi_internal_tx failed: no driver buffer exists for the charge just made, so no tx-done will come. The newest charge goes (the
 * charges are indistinguishable but for their time, and the lease reads only the head). */
static inline void gw_wtx_abort(gateway_wifi_pins *b) {
    bool had;
    GW_WP_ENTER(b);
    had = b->tx_count > 0;
    if (had) {
        b->tx_count--;
        atomic_fetch_sub_explicit(&b->pins, GW_WP_TX_ONE, memory_order_acq_rel);
    }
    GW_WP_EXIT(b);
    atomic_fetch_add_explicit(had ? &b->tx_aborted : &b->tx_unmatched, 1, memory_order_relaxed);
}

/* The driver's tx-done callback, in the pp task, once per completed frame (sent or failed). With nothing outstanding it is a frame
 * that was not ours (a management frame) or one a flush or the lease already released: counted, and nothing changes. */
static inline IRAM_ATTR void gw_wtx_done(gateway_wifi_pins *b) {
    bool had;
    GW_WP_ENTER(b);
    had = b->tx_count > 0;
    if (had) {
        gw_wtx_pop_head(b);
        atomic_fetch_sub_explicit(&b->pins, GW_WP_TX_ONE, memory_order_acq_rel);
    }
    GW_WP_EXIT(b);
    atomic_fetch_add_explicit(had ? &b->tx_done : &b->tx_unmatched, 1, memory_order_relaxed);
}

/* The STA link went down or came up: the driver cleared its queues without completing the frames in them. Returns how many charges
 * were released. */
static inline unsigned gw_wtx_flush(gateway_wifi_pins *b) {
    unsigned n;
    GW_WP_ENTER(b);
    n = b->tx_count;
    b->tx_count = 0;
    b->tx_head = 0;
    if (n) atomic_fetch_sub_explicit(&b->pins, n * GW_WP_TX_ONE, memory_order_acq_rel);
    GW_WP_EXIT(b);
    if (n) atomic_fetch_add_explicit(&b->tx_flushed, n, memory_order_relaxed);
    return n;
}

/* RX, in the Wi-Fi task, as the frame is handed to lwIP. `free_after` is the free internal heap NOW, which already excludes this
 * frame's buffer (the driver allocated it). True: counted, and gw_wrx_release must follow exactly once, when the frame's pbuf is
 * freed. False: the caller frees the frame at once. */
static inline bool gw_wrx_admit(gateway_wifi_pins *b, size_t free_after) {
    unsigned word = atomic_load_explicit(&b->pins, memory_order_relaxed);
    for (;;) {
        const bool band = gw_wp_rx_in_band(word);
        if (!band && !ml_hb_ok(free_after, 0)) {
            atomic_fetch_add_explicit(&b->rx_dropped, 1, memory_order_relaxed);
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(&b->pins, &word, word + GW_WP_RX_ONE, memory_order_acq_rel, memory_order_relaxed)) {
            atomic_fetch_add_explicit(band ? &b->rx_band : &b->rx_elastic, 1, memory_order_relaxed);
            gw_wp_max(&b->rx_high_water, gw_wp_rx(word) + 1);
            return true;
        }
    }
}

/* Any task: the pbuf of an admitted RX frame was freed (so was the driver buffer under it). */
static inline void gw_wrx_release(gateway_wifi_pins *b) {
    unsigned word = atomic_load_explicit(&b->pins, memory_order_relaxed);
    do {
        if (!gw_wp_rx(word)) {
            atomic_fetch_add_explicit(&b->rx_unmatched, 1, memory_order_relaxed);
            return;
        }
    } while (!atomic_compare_exchange_weak_explicit(&b->pins, &word, word - GW_WP_RX_ONE, memory_order_acq_rel, memory_order_relaxed));
    atomic_fetch_add_explicit(&b->rx_released, 1, memory_order_relaxed);
}

/* The most heap the data path can have pinned in the Wi-Fi driver below the floor (the bound this file exists for): the bands and the
 * RX frame under check; elastic frames never leave the floor. For the tests and the assertions. */
#define GATEWAY_WIFI_PIN_BAND_BYTES ((GATEWAY_WIFI_BAND_TOTAL + 1u) * ML_HB_PIN_BUF_BYTES)
_Static_assert(ML_HB_RESERVE + GATEWAY_WIFI_PIN_BAND_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR,
               "the Wi-Fi bands, the racing-checker slack and the recovery reserve must fit under the elastic floor");
