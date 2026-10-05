/*
 * SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "tinyusb_net.h"
#include "descriptors_control.h"
#include "usb_descriptors.h"
#include "device/usbd_pvt.h"
#include "esp_check.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"

#define MAC_ADDR_LEN 6

typedef struct packet {
    void *buffer;
    void *buff_free_arg;
    uint16_t len;
    esp_err_t result;
    bool ring;                 // payload lives in a TX ring slab: nothing to release
} packet_t;

struct tinyusb_net_handle {
    bool initialized;
    SemaphoreHandle_t buffer_sema;
    EventGroupHandle_t  tx_flags;
    tusb_net_rx_cb_t    rx_cb;
    tusb_net_free_tx_cb_t tx_buff_free_cb;
    tusb_net_init_cb_t init_cb;
    char mac_str[2 * MAC_ADDR_LEN + 1];
    void *ctx;
    packet_t *packet_to_send;
};

const static int TX_FINISHED_BIT = BIT0;
static struct tinyusb_net_handle s_net_obj = { };
static const char *TAG = "tusb_net";

static void do_send_sync(void *ctx)
{
    (void) ctx;
    if (xSemaphoreTake(s_net_obj.buffer_sema, 0) != pdTRUE) {
        return;
    }

    // A timed-out send can leave a deferred callback in the TinyUSB queue.
    // Treat callbacks as wakeups: consume the current slot exactly once while
    // holding the semaphore, before the copy/free callback can release it.
    packet_t *packet = s_net_obj.packet_to_send;
    s_net_obj.packet_to_send = NULL;
    if (packet == NULL) {
        xSemaphoreGive(s_net_obj.buffer_sema);
        return;
    }
    if (tud_network_can_xmit(packet->len)) {
        tud_network_xmit(packet, packet->len);
        packet->result = ESP_OK;
    } else {
        packet->result = ESP_FAIL;
    }
    xEventGroupSetBits(s_net_obj.tx_flags, TX_FINISHED_BIT);
    xSemaphoreGive(s_net_obj.buffer_sema);
}

static void do_send_async(void *ctx)
{
    packet_t *packet = ctx;
    if (tud_network_can_xmit(packet->len)) {
        tud_network_xmit(packet, packet->len);
    } else if (s_net_obj.tx_buff_free_cb) {
        ESP_LOGW(TAG, "Packet cannot be accepted on USB interface, dropping");
        s_net_obj.tx_buff_free_cb(packet->buff_free_arg, s_net_obj.ctx);
    }
    free(packet);
}

esp_err_t tinyusb_net_send_async(void *buffer, uint16_t len, void *buff_free_arg)
{
    if (!tud_ready()) {
        return ESP_ERR_INVALID_STATE;
    }

    packet_t *packet = calloc(1, sizeof(packet_t));
    packet->len = len;
    packet->buffer = buffer;
    packet->buff_free_arg = buff_free_arg;
    ESP_RETURN_ON_FALSE(packet, ESP_ERR_NO_MEM, TAG, "Failed to allocate packet to send");
    usbd_defer_func(do_send_async, packet, false);
    return ESP_OK;
}

esp_err_t tinyusb_net_send_sync(void *buffer, uint16_t len, void *buff_free_arg, TickType_t  timeout)
{
    if (!tud_ready()) {
        return ESP_ERR_INVALID_STATE;
    }

    // Lazy init the flags and semaphores, as they might not be needed (if async approach is used)
    if (!s_net_obj.tx_flags) {
        s_net_obj.tx_flags = xEventGroupCreate();
        ESP_RETURN_ON_FALSE(s_net_obj.tx_flags, ESP_ERR_NO_MEM, TAG, "Failed to allocate event flags");
    }
    if (!s_net_obj.buffer_sema) {
        s_net_obj.buffer_sema = xSemaphoreCreateBinary();
        ESP_RETURN_ON_FALSE(s_net_obj.buffer_sema, ESP_ERR_NO_MEM, TAG, "Failed to allocate buffer semaphore");
    }

    xEventGroupClearBits(s_net_obj.tx_flags, TX_FINISHED_BIT);
    packet_t packet = {
        .result = ESP_ERR_TIMEOUT,
        .buffer = buffer,
        .len = len,
        .buff_free_arg = buff_free_arg
    };
    s_net_obj.packet_to_send = &packet;
    xSemaphoreGive(s_net_obj.buffer_sema);  // now the packet is ready, let's mark it available to tusb send

    // to execute the send function in tinyUSB task context
    usbd_defer_func(do_send_sync, NULL, false);  // arg=NULL -> sync send, we keep the packet inside the object

    // wait wor completion with defined timeout
    xEventGroupWaitBits(s_net_obj.tx_flags, TX_FINISHED_BIT, pdTRUE, pdTRUE, timeout);
    xSemaphoreTake(s_net_obj.buffer_sema, portMAX_DELAY);   // if tusb sending already started, we have wait before ditching the packet
    s_net_obj.packet_to_send = NULL;        // invalidate the argument
    // Holding buffer_sema proves that any in-flight copy completed. A deadline
    // racing that copy must return its result, otherwise the caller frees twice.
    return packet.result;
}

//--------------------------------------------------------------------+
// Non-blocking, elastic transmit ring
//--------------------------------------------------------------------+
/*
 * tinyusb_net_send_sync() waits for the TinyUSB task, which is wrong for a
 * caller that holds a lock the rest of the system needs (the gateway sends
 * from inside the lwIP core lock). The ring is the alternative contract:
 *
 *   producer (any single, serialized context)      consumer (TinyUSB task)
 *   reserve slab range, copy, commit, notify  -->  tx_drain(): tud_network_xmit()
 *                                                   each frame exactly once
 *
 * Storage is a FIFO of SLABS. A slab is TX_SLAB_BYTES (one maximum frame
 * record, 1524 B); records are packed into the open (newest) slab and never
 * straddle two slabs, so every record is contiguous. A slab is sealed when the
 * next record does not fit and a successor is taken; the consumer frees a
 * sealed slab as soon as it has handed its last record to an NTB. Capacity is
 * counted in slabs: `base` of them are permanent (one allocation, made at
 * start), the rest live in elastic CHUNKS of TX_CHUNK_SLABS slabs that the
 * worker task allocates under pressure and frees when idle or when admission
 * asks for the memory back (see "Elastic buffering" below).
 *
 * One lock, short sections, copies outside it. All bookkeeping (the FIFO, which
 * slabs are free, per-chunk use counts) is protected by one critical section
 * (portMUX on the target). Its sections hold a few dozen instructions, never
 * a memcpy, an allocation, a free, a log line or a task call, so the producer
 * waits at most for another core to finish a few instructions: it never waits
 * for a task. The lock is what makes it safe for a THIRD party (the worker
 * growing and shrinking, or admission reclaiming) to change which memory
 * exists while the producer and the consumer run, which the first lock-free
 * ring could not do. The payload copies are outside it, protected by
 * ownership: a slab range is written only by the producer between reserve and
 * commit, read only by the consumer between peek and advance, and a slab
 * that is in the FIFO is never freed.
 *
 * - Producer: reserve (lock) -> copy -> commit (lock) -> notify the worker.
 *   Callers must be serialized, exactly like tinyusb_net_send_sync().
 * - Consumer: peek (lock) -> tud_network_xmit() copies synchronously -> advance
 *   (lock). The advance is the single release of that record; replaying a
 *   drain callback finds nothing to do. A flush that happens between peek and
 *   advance is detected (the read offset moved) and the advance is skipped.
 * - Link loss: records carry the link generation current when they were queued.
 *   The producer, tinyusb_net_tx_ring_link_down() and the worker bump the
 *   generation the first time they find USB not ready, so frames queued before
 *   a cable pull are discarded by the next drain instead of being delivered to
 *   the next host.
 * - Full ring: no free slab and no room in the open one: the new frame is
 *   dropped and counted (tail drop); lwIP/TCP treat it as ordinary loss.
 * - Drain triggers, both in the TinyUSB task: a deferred do_drain requested by
 *   the worker after a producer committed (usbd_defer_func() from a task blocks
 *   forever when TinyUSB's event queue is full, so that wait is taken by the
 *   worker, which holds no lock), and every IN transfer completion
 *   (__wrap_netd_xfer_cb), which refills the NTB that just came back.
 *
 * Elastic buffering. Growth needs memory the system may need for something
 * else, so it is conditional and reversible:
 * - Only the worker allocates. The producer notes pressure (few free slabs)
 *   and wakes it. The worker grows only if the gate (negotiation or admission
 *   in progress) is open, free internal heap stays above floor_free AFTER the
 *   chunk, and the largest free block is at least floor_largest before AND
 *   after the allocation (a growth that is the one to take the largest block
 *   below the floor is undone).
 * - Slabs are taken lowest index first (permanent slabs, then chunk 0, 1, ...)
 *   so the high chunks go idle first when load falls, and a chunk is freed
 *   only when none of its slabs is in the FIFO: frames in flight are never
 *   freed, they stay valid until the consumer advanced past them.
 * - Retiring a chunk (idle, gate closed, admission reclaim) stops new frames
 *   going into it; it is freed when its last slab is released.
 * - tinyusb_net_tx_elastic_reclaim() bumps an epoch under the lock; a growth
 *   that allocated before the reclaim and publishes after it is discarded.
 *
 * CPU frequency: the caller's pm_begin/pm_end hold the CPU at its maximum while
 * frames are queued. The producer only commits and notifies; `pm_want` is
 * true exactly while frames_queued > 0 (kept under the lock), and ONLY the
 * worker begins or ends the hold, so the pair cannot interleave. Both the
 * empty-to-non-empty and the non-empty-to-empty edge notify the worker.
 */
#define TX_REC_HDR        4u
#define TX_FRAME_MIN      14u
#define TX_FRAME_MAX      1518u      // 1500 byte MTU + Ethernet header + VLAN tag
#define TX_ALIGN4(n)      (((uint32_t)(n) + 3u) & ~3u)
#define TX_REC_MAX        (TX_REC_HDR + TX_ALIGN4(TX_FRAME_MAX))     // 1524
#define TX_SLAB_BYTES     TINYUSB_NET_TX_SLAB_BYTES
#define TX_CHUNK_SLABS    TINYUSB_NET_TX_CHUNK_SLABS
#define TX_CHUNK_BYTES    TINYUSB_NET_TX_CHUNK_BYTES
#define TX_MAX_CHUNKS     TINYUSB_NET_TX_MAX_CHUNKS
#define TX_MAX_SLABS      (TINYUSB_NET_TX_MAX_BASE_SLABS + TX_MAX_CHUNKS * TX_CHUNK_SLABS)
#define TX_FIFO_MASK      (TX_MAX_SLABS - 1u)
#define TX_GROW_HEADROOM  1u         // grow when this many free slabs or fewer remain (light traffic never gets here)
#define TX_WORKER_STACK   1536u      // above the IDF IPC task (1280), which does the same queue calls
#define TX_LINK_POLL_MS   200u       // while frames are queued: notice a link that went away silently
#define TX_HOUSEKEEP_MS  500u        // while elastic chunks exist: idle check
#define TX_GROW_RETRY_MS  100u       // after a refused growth (doubles per consecutive refusal)
#define TX_GROW_RETRY_MAX_MS 1600u
#define TX_IDLE_DEFAULT_MS 2000u
#define TX_HEAP_BLOCK_SLACK 16u      // allocator header, charged against the floor
_Static_assert(TX_REC_MAX == TX_SLAB_BYTES, "a slab holds exactly one maximum record");
_Static_assert(TX_MAX_SLABS == 32u, "slab bookkeeping uses a 32-bit mask and a 32-entry FIFO");

enum { TX_WHY_RECLAIM = 1, TX_WHY_IDLE = 2 };

typedef struct { uint16_t fill, rd, resv; } tx_slab_t;      // committed end, consumed offset, reserved end
typedef struct { uint8_t *mem; uint8_t used; uint8_t why; bool retiring; uint32_t last_use; } tx_chunk_t;
typedef struct { uint8_t slab; uint16_t rd, len, gen; const uint8_t *payload; } tx_rec_t;

static struct {
    tinyusb_net_tx_config_t cfg;
    uint8_t *base;
    uint8_t base_slabs;
    // ---- under the lock ----
    tx_chunk_t chunk[TX_MAX_CHUNKS];
    tx_slab_t slab[TX_MAX_SLABS];
    uint8_t fifo[TX_MAX_SLABS];     // slab ids, oldest (consumer) first, newest (open, producer) last
    uint8_t fifo_head, fifo_n;
    uint32_t alloc_mask;            // free slabs that may be handed to the producer
    uint32_t frames_queued, used_bytes;
    unsigned chunks_present, chunks_live;   // allocated, and of those not retiring
    uint32_t epoch;                 // bumped by every reclaim
    int8_t reading;                 // slab the consumer peeked and has not advanced past, or -1
    uint16_t reading_rd;            // offset of that record: it is the consumer's, a flush must not count it
    bool resv_open;                 // producer between reserve and commit
    bool cold_pending;              // the queue went empty to non-empty and that first frame has not been handed over
    uint32_t cold_edge_us;          // when
    uint32_t cold_starts, cold_us_sum, cold_us_max;     // under the lock (written by the consumer inside it)
    uint32_t high_water_bytes, high_water_slabs;
    // ---- producer only ----
    // ---- TinyUSB task only ----
    bool blocked;                   // last drain stopped on can_xmit() == false
    uint32_t last_comp_us;          // previous IN completion while frames were queued, 0 when the queue was empty then
    // Evidence counters: written by the TinyUSB task only, read by anyone (atomic so a reader never races).
    _Atomic uint32_t gap_count, gap_us_sum, gap_us_max, gap_hist[5];
    _Atomic uint32_t drains_sent[5];
    _Atomic uint32_t ntb_xfers, ntb_zlp, ntb_bytes, ntb_max_bytes;
    // ---- worker only ----
    uint32_t grow_retry;            // tick before which a refused growth is not retried
    uint32_t grow_backoff;          // ms of the last refusal's back-off, 0 after a growth
    // ---- anywhere ----
    _Atomic uint16_t gen;           // link generation
    _Atomic bool down_seen;         // USB was not ready on the last look
    _Atomic bool enabled;
    _Atomic bool drain_pending;     // a do_drain callback is queued in TinyUSB
    _Atomic bool pm_want;           // frames are queued (set and cleared under the lock)
    _Atomic bool pm_held;           // worker only writes
    _Atomic bool grow_wanted;
    _Atomic bool reap_pending;
    _Atomic uint32_t present_mirror;    // chunks_present, for the worker's wait without the lock
    TaskHandle_t worker;
    _Atomic uint32_t enq_frames, enq_bytes, sent_frames, sent_bytes;
    _Atomic uint32_t drop_full, drop_down, drop_invalid, flushed, blocked_events, xfer_events;
    _Atomic uint32_t grow_events, shrink_events, reclaim_events, reclaimed_chunks;
    _Atomic uint32_t deny_gate, deny_heap, deny_largest, deny_nomem, grow_raced;
    _Atomic uint32_t pm_acquired, pm_released;
    _Atomic uint32_t demotions;
} s_tx;

static portMUX_TYPE s_tx_mux = portMUX_INITIALIZER_UNLOCKED;
#define TX_ENTER() portENTER_CRITICAL(&s_tx_mux)
#define TX_EXIT()  portEXIT_CRITICAL(&s_tx_mux)

static uint8_t *tx_slab_ptr(unsigned s)
{
    if (s < s_tx.base_slabs) {
        return s_tx.base + s * TX_SLAB_BYTES;
    }
    unsigned k = s - s_tx.base_slabs;
    return s_tx.chunk[k / TX_CHUNK_SLABS].mem + (k % TX_CHUNK_SLABS) * TX_SLAB_BYTES;
}

static uint32_t tx_chunk_mask(unsigned c)
{
    return ((1u << TX_CHUNK_SLABS) - 1u) << (s_tx.base_slabs + c * TX_CHUNK_SLABS);
}

static void tx_set_present_locked(void)
{
    atomic_store_explicit(&s_tx.present_mirror, s_tx.chunks_present, memory_order_relaxed);
}

/* ---- pool, under the lock ---- */

static int tx_pop_slab_locked(void)
{
    if (s_tx.alloc_mask == 0) {
        return -1;
    }
    unsigned s = (unsigned)__builtin_ctz(s_tx.alloc_mask);     // lowest first
    s_tx.alloc_mask &= ~(1u << s);
    if (s >= s_tx.base_slabs) {
        s_tx.chunk[(s - s_tx.base_slabs) / TX_CHUNK_SLABS].used++;
    }
    return (int)s;
}

static void tx_release_slab_locked(unsigned s)
{
    if (s >= s_tx.base_slabs) {
        tx_chunk_t *ch = &s_tx.chunk[(s - s_tx.base_slabs) / TX_CHUNK_SLABS];
        ch->used--;
        ch->last_use = xTaskGetTickCount();
        if (ch->retiring) {
            if (ch->used == 0) {
                atomic_store_explicit(&s_tx.reap_pending, true, memory_order_relaxed);
            }
            return;         // a retiring chunk's slabs are never handed out again
        }
    }
    s_tx.alloc_mask |= 1u << s;
}

static void tx_drop_front_locked(void)
{
    unsigned s = s_tx.fifo[s_tx.fifo_head];
    s_tx.fifo_head = (uint8_t)((s_tx.fifo_head + 1u) & TX_FIFO_MASK);
    s_tx.fifo_n--;
    tx_release_slab_locked(s);
}

/* Nothing queued and nobody writing: give the open slab back so the next frame starts in the lowest slab
 * and the chunk that held it can go idle. Never the slab the consumer is reading. */
static void tx_compact_locked(void)
{
    while (s_tx.fifo_n > 0 && s_tx.frames_queued == 0 && !s_tx.resv_open &&
           (int)s_tx.fifo[s_tx.fifo_head] != s_tx.reading) {
        tx_drop_front_locked();
    }
}

/* Producer, under the lock: find room for `need` bytes. */
static bool tx_reserve_locked(uint32_t need, unsigned *slab, uint32_t *off)
{
    tx_compact_locked();
    if (s_tx.fifo_n > 0) {
        unsigned b = s_tx.fifo[(s_tx.fifo_head + s_tx.fifo_n - 1u) & TX_FIFO_MASK];
        if (s_tx.slab[b].resv + need <= TX_SLAB_BYTES) {
            *slab = b;
            *off = s_tx.slab[b].resv;
            s_tx.slab[b].resv = (uint16_t)(*off + need);
            s_tx.resv_open = true;
            return true;
        }
    }
    int s = tx_pop_slab_locked();
    if (s < 0) {
        return false;
    }
    s_tx.slab[s] = (tx_slab_t){ .fill = 0, .rd = 0, .resv = (uint16_t)need };
    s_tx.fifo[(s_tx.fifo_head + s_tx.fifo_n) & TX_FIFO_MASK] = (uint8_t)s;
    s_tx.fifo_n++;
    s_tx.resv_open = true;
    *slab = (unsigned)s;
    *off = 0;
    return true;
}

static void tx_commit_locked(unsigned s, uint32_t need, uint32_t now_us)
{
    s_tx.slab[s].fill = s_tx.slab[s].resv;
    s_tx.resv_open = false;
    if (s_tx.frames_queued == 0) {
        s_tx.cold_pending = true;       // the consumer measures how long this frame waited for the first hand-over
        s_tx.cold_edge_us = now_us;
    }
    s_tx.frames_queued++;
    s_tx.used_bytes += need;
    if (s_tx.used_bytes > s_tx.high_water_bytes) {
        s_tx.high_water_bytes = s_tx.used_bytes;
    }
    if (s_tx.fifo_n > s_tx.high_water_slabs) {
        s_tx.high_water_slabs = s_tx.fifo_n;
    }
    atomic_store_explicit(&s_tx.pm_want, true, memory_order_release);
}

/* Few free slabs and room for another chunk: ask the worker to grow. */
static bool tx_pressure_locked(void)
{
    // popcount(mask) <= 1 without a libgcc call inside the critical section: clearing the lowest set bit leaves nothing
    _Static_assert(TX_GROW_HEADROOM == 1u, "the pressure test below is written for one free slab");
    return s_tx.chunks_present < s_tx.cfg.max_chunks && (s_tx.alloc_mask & (s_tx.alloc_mask - 1u)) == 0u;
}

/* Consumer, under the lock: the oldest committed record, or false when there is none. */
static bool tx_peek_locked(tx_rec_t *r)
{
    while (s_tx.fifo_n > 0) {
        unsigned s = s_tx.fifo[s_tx.fifo_head];
        const tx_slab_t *sl = &s_tx.slab[s];
        if (sl->rd < sl->fill) {
            const uint8_t *p = tx_slab_ptr(s) + sl->rd;
            uint16_t hdr[2];
            memcpy(hdr, p, sizeof(hdr));
            *r = (tx_rec_t){ .slab = (uint8_t)s, .rd = sl->rd, .len = hdr[0], .gen = hdr[1], .payload = p + TX_REC_HDR };
            s_tx.reading = (int8_t)s;
            s_tx.reading_rd = sl->rd;
            return true;
        }
        if (s_tx.fifo_n == 1) {
            return false;       // the open slab, nothing committed in it
        }
        tx_drop_front_locked();     // sealed and fully consumed
    }
    return false;
}

/* Consumer, under the lock: the record returned by peek has been handed over (or discarded). True when the
 * queue just became empty. A flush that ran in between moved rd: then there is nothing to advance. */
static bool tx_advance_locked(const tx_rec_t *r, bool sent, uint32_t now_us)
{
    s_tx.reading = -1;
    tx_slab_t *sl = &s_tx.slab[r->slab];
    if (sl->rd != r->rd) {
        tx_compact_locked();
        return false;
    }
    uint32_t need = TX_REC_HDR + TX_ALIGN4(r->len);
    sl->rd = (uint16_t)(sl->rd + need);
    s_tx.used_bytes -= need;
    s_tx.frames_queued--;
    if (s_tx.cold_pending) {
        s_tx.cold_pending = false;
        if (sent) {
            uint32_t waited = now_us - s_tx.cold_edge_us;
            s_tx.cold_starts++;
            s_tx.cold_us_sum += waited;
            if (waited > s_tx.cold_us_max) {
                s_tx.cold_us_max = waited;
            }
        }
    }
    bool emptied = s_tx.frames_queued == 0;
    if (emptied) {
        atomic_store_explicit(&s_tx.pm_want, false, memory_order_release);
    }
    if (s_tx.fifo_n > 1 && s_tx.fifo[s_tx.fifo_head] == r->slab && sl->rd == sl->fill) {
        tx_drop_front_locked();
    }
    return emptied;
}

/* Under the lock: forget every committed record (link loss at teardown). Returns how many. */
static uint32_t tx_discard_locked(void)
{
    uint32_t count = 0;
    for (unsigned i = 0; i < s_tx.fifo_n; i++) {
        unsigned id = s_tx.fifo[(s_tx.fifo_head + i) & TX_FIFO_MASK];
        tx_slab_t *sl = &s_tx.slab[id];
        const uint8_t *base = tx_slab_ptr(id);
        bool inflight = (int)id == s_tx.reading && sl->rd == s_tx.reading_rd;   // the consumer is copying this one out
        while (sl->rd < sl->fill) {
            uint16_t len;
            memcpy(&len, base + sl->rd, sizeof(len));
            if (inflight) {
                // Not ours to count: the consumer finishes it (and counts it as sent or flushed).
                inflight = false;
                sl->rd = (uint16_t)(sl->rd + TX_REC_HDR + TX_ALIGN4(len));
                continue;
            }
            count++;
            if (len < TX_FRAME_MIN || len > TX_FRAME_MAX) {
                sl->rd = sl->fill;      // damaged (cannot happen): never read past it
                break;
            }
            sl->rd = (uint16_t)(sl->rd + TX_REC_HDR + TX_ALIGN4(len));
        }
    }
    s_tx.frames_queued = 0;
    s_tx.used_bytes = 0;
    s_tx.cold_pending = false;
    atomic_store_explicit(&s_tx.pm_want, false, memory_order_release);
    while (s_tx.fifo_n > 1 && (int)s_tx.fifo[s_tx.fifo_head] != s_tx.reading) {
        tx_drop_front_locked();
    }
    tx_compact_locked();
    return count;
}

/* ---- elastic chunks ---- */

/* Under the lock: stop handing out a chunk's slabs; it is freed once none is in the FIFO. */
static void tx_retire_chunk_locked(unsigned c, uint8_t why)
{
    tx_chunk_t *ch = &s_tx.chunk[c];
    ch->retiring = true;
    ch->why = why;
    s_tx.alloc_mask &= ~tx_chunk_mask(c);
    s_tx.chunks_live--;
}

static unsigned tx_retire_all_locked(uint8_t why)
{
    tx_compact_locked();
    unsigned n = 0;
    for (unsigned c = 0; c < TX_MAX_CHUNKS; c++) {
        if (s_tx.chunk[c].mem && !s_tx.chunk[c].retiring) {
            tx_retire_chunk_locked(c, why);
            n++;
        }
    }
    return n;
}

/* Free retiring chunks that no slab of is in the FIFO. Detach under the lock, free outside it. */
static unsigned tx_reap(void)
{
    void *mem[TX_MAX_CHUNKS];
    uint8_t why[TX_MAX_CHUNKS];
    unsigned n = 0;
    atomic_store_explicit(&s_tx.reap_pending, false, memory_order_relaxed);
    TX_ENTER();
    for (unsigned c = 0; c < TX_MAX_CHUNKS; c++) {
        tx_chunk_t *ch = &s_tx.chunk[c];
        if (ch->mem && ch->retiring && ch->used == 0) {
            mem[n] = ch->mem;
            why[n] = ch->why;
            n++;
            *ch = (tx_chunk_t){ 0 };
            s_tx.chunks_present--;
        }
    }
    tx_set_present_locked();
    TX_EXIT();
    for (unsigned i = 0; i < n; i++) {
        heap_caps_free(mem[i]);
        atomic_fetch_add_explicit(why[i] == TX_WHY_IDLE ? &s_tx.shrink_events : &s_tx.reclaimed_chunks, 1,
                                  memory_order_relaxed);
    }
    return n;
}

static bool tx_gate(void)
{
    return s_tx.cfg.gate ? s_tx.cfg.gate(s_tx.cfg.gate_ctx) : false;
}

/* Worker. Retire when the gate is closed, free chunks that sat idle, then free whatever is retired and empty. */
static void tx_housekeeping(void)
{
    if (atomic_load_explicit(&s_tx.present_mirror, memory_order_relaxed) == 0) {
        return;                     // no elastic chunk exists: nothing to retire, nothing to shrink (the common case)
    }
    bool busy = tx_gate();
    uint32_t now = xTaskGetTickCount();
    uint32_t idle = pdMS_TO_TICKS(s_tx.cfg.idle_ms ? s_tx.cfg.idle_ms : TX_IDLE_DEFAULT_MS);
    unsigned retired = 0;
    TX_ENTER();
    if (busy) {
        retired = tx_retire_all_locked(TX_WHY_RECLAIM);
    } else {
        tx_compact_locked();
        // Staged: one idle chunk per pass, highest index first (the one the lowest-first allocator touched last), so a
        // chunk that was just given back is not followed by nine more frees in the same instant. With the long idle
        // period this keeps bursty traffic from cycling the heap.
        for (unsigned c = TX_MAX_CHUNKS; c-- > 0;) {
            tx_chunk_t *ch = &s_tx.chunk[c];
            if (ch->mem && !ch->retiring && ch->used == 0 && (int32_t)(now - ch->last_use) >= (int32_t)idle) {
                tx_retire_chunk_locked(c, TX_WHY_IDLE);
                break;
            }
        }
    }
    TX_EXIT();
    if (retired) {
        atomic_fetch_add_explicit(&s_tx.reclaim_events, 1, memory_order_relaxed);
    }
    tx_reap();
}

/* A refusal backs off exponentially (100 ms, 200, ... 1.6 s), reset by the next successful growth: while the heap is
 * the problem, a sustained burst must not make the worker walk the heap (heap_caps_get_largest_free_block holds the
 * heap lock for the length of the walk) ten times a second. */
static void tx_deny(_Atomic uint32_t *counter, uint32_t now)
{
    atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
    s_tx.grow_backoff = s_tx.grow_backoff ? (s_tx.grow_backoff < TX_GROW_RETRY_MAX_MS ? s_tx.grow_backoff * 2u : s_tx.grow_backoff)
                                          : TX_GROW_RETRY_MS;
    s_tx.grow_retry = now + pdMS_TO_TICKS(s_tx.grow_backoff);
}

/* Worker. Add chunks while the producer is close to running out of slabs and the heap can afford it. */
static void tx_try_grow(void)
{
    if (!atomic_exchange_explicit(&s_tx.grow_wanted, false, memory_order_acq_rel)) {
        return;
    }
    for (;;) {
        TX_ENTER();
        bool need = tx_pressure_locked();
        uint32_t epoch = s_tx.epoch;
        TX_EXIT();
        uint32_t now = xTaskGetTickCount();
        if (!need || (int32_t)(now - s_tx.grow_retry) < 0) {
            return;
        }
        if (tx_gate()) {
            tx_deny(&s_tx.deny_gate, now);
            return;
        }
        // The O(1) total first; the largest-block query walks the heap with its lock held, so it only runs when the
        // total already allows a growth.
        if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) < TX_CHUNK_BYTES + TX_HEAP_BLOCK_SLACK + s_tx.cfg.floor_free) {
            tx_deny(&s_tx.deny_heap, now);
            return;
        }
        if (heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) < s_tx.cfg.floor_largest) {
            tx_deny(&s_tx.deny_largest, now);
            return;
        }
        uint8_t *mem = heap_caps_malloc(TX_CHUNK_BYTES, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (mem == NULL) {
            tx_deny(&s_tx.deny_nomem, now);
            return;
        }
        // The same rule as ml_adm_slot_alloc_ok(): this allocation must not be the one that takes the
        // largest free block below what admission needs.
        if (heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) < s_tx.cfg.floor_largest) {
            heap_caps_free(mem);
            tx_deny(&s_tx.deny_largest, now);
            return;
        }
        if (tx_gate()) {
            heap_caps_free(mem);
            tx_deny(&s_tx.deny_gate, now);
            return;
        }
        bool published = false;
        TX_ENTER();
        if (epoch == s_tx.epoch && s_tx.chunks_present < s_tx.cfg.max_chunks) {
            for (unsigned c = 0; c < TX_MAX_CHUNKS; c++) {
                tx_chunk_t *ch = &s_tx.chunk[c];
                if (ch->mem == NULL) {
                    *ch = (tx_chunk_t){ .mem = mem, .last_use = now };
                    s_tx.alloc_mask |= tx_chunk_mask(c);
                    s_tx.chunks_present++;
                    s_tx.chunks_live++;
                    tx_set_present_locked();
                    published = true;
                    break;
                }
            }
        }
        TX_EXIT();
        if (!published) {
            heap_caps_free(mem);        // a reclaim started while we allocated
            atomic_fetch_add_explicit(&s_tx.grow_raced, 1, memory_order_relaxed);
            return;
        }
        s_tx.grow_backoff = 0;
        atomic_fetch_add_explicit(&s_tx.grow_events, 1, memory_order_relaxed);
    }
}

size_t tinyusb_net_tx_elastic_reclaim(uint32_t wait_ms)
{
    if (!atomic_load_explicit(&s_tx.enabled, memory_order_acquire) || s_tx.cfg.max_chunks == 0) {
        return 0;
    }
    TX_ENTER();
    s_tx.epoch++;
    unsigned retired = tx_retire_all_locked(TX_WHY_RECLAIM);
    TX_EXIT();
    if (retired) {
        atomic_fetch_add_explicit(&s_tx.reclaim_events, 1, memory_order_relaxed);
    }
    tx_reap();
    // Chunks still holding frames drain at USB speed (23 frames take about 40 ms at 7 Mbit/s).
    for (uint32_t waited = 0; waited < pdMS_TO_TICKS(wait_ms) && atomic_load(&s_tx.present_mirror) != 0; waited++) {
        vTaskDelay(1);
        TX_ENTER();
        tx_compact_locked();
        TX_EXIT();
        tx_reap();
    }
    return (size_t)atomic_load(&s_tx.present_mirror) * TX_CHUNK_BYTES;
}

void tinyusb_net_tx_elastic_kick(void)
{
    if (s_tx.worker) {
        xTaskNotifyGive(s_tx.worker);
    }
}

/* ---- link generation ---- */

static void tx_note_link_down(void)
{
    if (!atomic_exchange_explicit(&s_tx.down_seen, true, memory_order_acq_rel)) {
        // First look after the link was up: everything queued so far is stale.
        atomic_fetch_add_explicit(&s_tx.gen, 1, memory_order_release);
    }
}

void tinyusb_net_tx_ring_link_down(void)
{
    if (s_tx.worker && atomic_load_explicit(&s_tx.enabled, memory_order_acquire)) {
        tx_note_link_down();
        xTaskNotifyGive(s_tx.worker);       // the worker queues a drain, which discards the stale frames
    }
}

/* ---- producer ---- */

esp_err_t tinyusb_net_tx_ring_send(const void *buffer, uint16_t len)
{
    if (!atomic_load_explicit(&s_tx.enabled, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (buffer == NULL || len < TX_FRAME_MIN || len > TX_FRAME_MAX) {
        atomic_fetch_add_explicit(&s_tx.drop_invalid, 1, memory_order_relaxed);
        return ESP_ERR_INVALID_ARG;
    }
    if (!tud_ready()) {
        tx_note_link_down();
        atomic_fetch_add_explicit(&s_tx.drop_down, 1, memory_order_relaxed);
        if (atomic_load_explicit(&s_tx.pm_want, memory_order_relaxed)) {
            xTaskNotifyGive(s_tx.worker);   // stale frames are queued: let the worker flush them and drop the PM lock
        }
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store_explicit(&s_tx.down_seen, false, memory_order_relaxed);
    uint32_t need = TX_REC_HDR + TX_ALIGN4(len);
    unsigned slab = 0;
    uint32_t off = 0;
    TX_ENTER();
    bool ok = tx_reserve_locked(need, &slab, &off);
    if (tx_pressure_locked()) {
        atomic_store_explicit(&s_tx.grow_wanted, true, memory_order_relaxed);
    }
    uint8_t *dst = ok ? tx_slab_ptr(slab) + off : NULL;
    TX_EXIT();
    if (!ok) {
        atomic_fetch_add_explicit(&s_tx.drop_full, 1, memory_order_relaxed);
        xTaskNotifyGive(s_tx.worker);       // pressure: let the worker grow (nothing else will wake it)
        return ESP_ERR_NO_MEM;
    }
    uint16_t hdr[2] = { len, atomic_load_explicit(&s_tx.gen, memory_order_relaxed) };
    memcpy(dst, hdr, sizeof(hdr));
    memcpy(dst + TX_REC_HDR, buffer, len);
    uint32_t now_us = (uint32_t)esp_timer_get_time();     // outside the section: a register read, but not ours to hold it for
    TX_ENTER();
    tx_commit_locked(slab, need, now_us);
    TX_EXIT();
    atomic_fetch_add_explicit(&s_tx.enq_frames, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_tx.enq_bytes, len, memory_order_relaxed);
    xTaskNotifyGive(s_tx.worker);   // never blocks
    return ESP_OK;
}

/* ---- consumer ---- */

/* TinyUSB task only. Idempotent: a duplicate call finds the ring drained. */
static void tx_drain(void)
{
    bool ready = tud_ready();
    bool notify = false;
    unsigned handed = 0;
    for (;;) {
        tx_rec_t r;
        TX_ENTER();
        bool have = tx_peek_locked(&r);
        TX_EXIT();
        if (!have) {
            s_tx.blocked = false;
            break;
        }
        if (r.len < TX_FRAME_MIN || r.len > TX_FRAME_MAX) {
            // Cannot happen (the producer validates); never read past a damaged record.
            TX_ENTER();
            s_tx.reading = -1;
            uint32_t n = tx_discard_locked();
            TX_EXIT();
            atomic_fetch_add_explicit(&s_tx.flushed, n, memory_order_relaxed);
            notify = true;
            continue;
        }
        // The generation was stored before the record was committed (lock): never newer than the one seen here.
        bool stale = !ready || r.gen != atomic_load_explicit(&s_tx.gen, memory_order_acquire);
        if (!stale) {
            if (!tud_network_can_xmit(r.len)) {
                // every NTB is in flight; keep the frame, the next IN completion drains again
                TX_ENTER();
                s_tx.reading = -1;
                TX_EXIT();
                if (!s_tx.blocked) {
                    s_tx.blocked = true;
                    atomic_fetch_add_explicit(&s_tx.blocked_events, 1, memory_order_relaxed);
                }
                break;
            }
            packet_t packet = { .buffer = (void *) r.payload, .len = r.len, .ring = true };
            tud_network_xmit(&packet, r.len);     // copies synchronously, outside the lock: the slab is still ours
            atomic_fetch_add_explicit(&s_tx.sent_frames, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&s_tx.sent_bytes, r.len, memory_order_relaxed);
            handed++;
        } else {
            atomic_fetch_add_explicit(&s_tx.flushed, 1, memory_order_relaxed);
        }
        uint32_t now_us = (uint32_t)esp_timer_get_time();
        TX_ENTER();
        bool emptied = tx_advance_locked(&r, !stale, now_us);
        TX_EXIT();
        notify |= emptied;
    }
    if (handed) {
        s_tx.drains_sent[(handed > 5 ? 5 : handed) - 1]++;     // TinyUSB task only
    }
    if (notify || atomic_load_explicit(&s_tx.reap_pending, memory_order_relaxed)) {
        xTaskNotifyGive(s_tx.worker);       // queue became empty (drop the PM lock) or a retiring chunk emptied
    }
}

/* Deferred into the TinyUSB task by the worker. */
static void do_drain(void *ctx)
{
    (void) ctx;
    atomic_store(&s_tx.drain_pending, false);   // before reading the queue: a frame committed after
    tx_drain();                                 // this point makes the worker queue another call
}

/* Linker --wrap of the NCM class driver's transfer-complete handler (CMakeLists.txt).
 * Runs in the TinyUSB task after the driver returned the NTB to its free list. */
bool __real_netd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes);
bool __wrap_netd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes)
{
    uint32_t now_us = (uint32_t)esp_timer_get_time();
    bool ret = __real_netd_xfer_cb(rhport, ep_addr, result, xferred_bytes);
    if ((ep_addr & 0x80u) && atomic_load_explicit(&s_tx.enabled, memory_order_acquire)) {
        atomic_fetch_add_explicit(&s_tx.xfer_events, 1, memory_order_relaxed);
        if (xferred_bytes) {
            s_tx.ntb_xfers++;
            s_tx.ntb_bytes += xferred_bytes;
            if (xferred_bytes > s_tx.ntb_max_bytes) {
                s_tx.ntb_max_bytes = xferred_bytes;
            }
        } else {
            s_tx.ntb_zlp++;
        }
        if (atomic_load_explicit(&s_tx.pm_want, memory_order_relaxed)) {      // frames are queued: this gap is the bus, not idleness
            if (s_tx.last_comp_us) {
                uint32_t gap = now_us - s_tx.last_comp_us;
                s_tx.gap_count++;
                s_tx.gap_us_sum += gap;
                if (gap > s_tx.gap_us_max) {
                    s_tx.gap_us_max = gap;
                }
                s_tx.gap_hist[gap < 1000u ? 0 : gap < 2000u ? 1 : gap < 4000u ? 2 : gap < 8000u ? 3 : 4]++;
            }
            s_tx.last_comp_us = now_us ? now_us : 1u;
        } else {
            s_tx.last_comp_us = 0;
        }
        tx_drain();
    }
    return ret;
}

/* ---- worker ---- */

/* The worker is the only context that acquires or releases the CPU-frequency lock, so the pair cannot interleave.
 * Both edges of pm_want notify it. The mechanism is the caller's when it supplies pm_begin/pm_end (the gateway binds
 * them to a tdongle_pm_burst_t, ADR 0016: one PM mechanism, with its depth accounting and /status counters); only a
 * caller that supplies none gets this component's own ESP_PM_CPU_FREQ_MAX lock. */
static void tx_pm_reconcile(void)
{
    if (s_tx.cfg.pm_begin == NULL || s_tx.cfg.pm_end == NULL) {
        return;                     // no power management in this build or caller: nothing to hold
    }
    bool want = atomic_load_explicit(&s_tx.pm_want, memory_order_acquire);
    bool held = atomic_load_explicit(&s_tx.pm_held, memory_order_relaxed);
    if (want && !held) {
        s_tx.cfg.pm_begin(s_tx.cfg.pm_ctx);
        atomic_store_explicit(&s_tx.pm_held, true, memory_order_relaxed);
        atomic_fetch_add_explicit(&s_tx.pm_acquired, 1, memory_order_relaxed);
    } else if (!want && held) {
        s_tx.cfg.pm_end(s_tx.cfg.pm_ctx);
        atomic_store_explicit(&s_tx.pm_held, false, memory_order_relaxed);
        atomic_fetch_add_explicit(&s_tx.pm_released, 1, memory_order_relaxed);
    }
}

static TickType_t tx_worker_wait(void)
{
    if (atomic_load_explicit(&s_tx.pm_want, memory_order_relaxed)) {
        return pdMS_TO_TICKS(TX_LINK_POLL_MS);      // frames queued: also notice a link that went away silently
    }
    if (atomic_load_explicit(&s_tx.present_mirror, memory_order_relaxed) != 0) {
        return pdMS_TO_TICKS(TX_HOUSEKEEP_MS);      // elastic chunks exist: idle check
    }
    return portMAX_DELAY;                           // nothing to do until a producer publishes
}

static void tx_worker_step(void)
{
    ulTaskNotifyTake(pdTRUE, tx_worker_wait());
    tx_pm_reconcile();
    if (atomic_load_explicit(&s_tx.pm_want, memory_order_acquire)) {
        if (!tud_ready()) {
            tx_note_link_down();    // silent link loss: the drain below discards what was queued
        }
        if (!atomic_exchange(&s_tx.drain_pending, true)) {
            usbd_defer_func(do_drain, NULL, false);     // may wait for TinyUSB; we hold no lock
        }
    }
    // Heap work (idle shrink, growth with its heap walks) runs below the producers: the relay above must outrank them, this
    // must not delay the TinyUSB task or the forwarding task. Only when there is some, so the common pass makes no call.
    bool heap_work = s_tx.cfg.work_priority != 0 && s_tx.cfg.work_priority != s_tx.cfg.priority &&
                     (atomic_load_explicit(&s_tx.present_mirror, memory_order_relaxed) != 0 ||
                      atomic_load_explicit(&s_tx.grow_wanted, memory_order_relaxed));
    if (heap_work) {
        vTaskPrioritySet(NULL, s_tx.cfg.work_priority);
        atomic_fetch_add_explicit(&s_tx.demotions, 1, memory_order_relaxed);
    }
    tx_housekeeping();
    tx_try_grow();
    if (heap_work) {
        vTaskPrioritySet(NULL, s_tx.cfg.priority);
    }
    tx_pm_reconcile();              // a drain that ran meanwhile may have emptied the queue
}

static void tx_worker(void *arg)
{
    (void) arg;
    for (;;) {
        tx_worker_step();
    }
}

esp_err_t tinyusb_net_tx_ring_start(const tinyusb_net_tx_config_t *cfg)
{
    ESP_RETURN_ON_FALSE(cfg != NULL && cfg->base_frames >= 2 && cfg->base_frames <= TINYUSB_NET_TX_MAX_BASE_SLABS &&
                        cfg->max_chunks <= TX_MAX_CHUNKS, ESP_ERR_INVALID_ARG, TAG, "bad TX ring configuration");
    if (s_tx.base != NULL) {
        ESP_RETURN_ON_FALSE(s_tx.cfg.base_frames == cfg->base_frames && s_tx.cfg.max_chunks == cfg->max_chunks &&
                            s_tx.cfg.floor_free == cfg->floor_free && s_tx.cfg.floor_largest == cfg->floor_largest &&
                            s_tx.cfg.gate == cfg->gate && s_tx.cfg.idle_ms == cfg->idle_ms &&
                            s_tx.cfg.priority == cfg->priority && s_tx.cfg.work_priority == cfg->work_priority &&
                            s_tx.cfg.pm_begin == cfg->pm_begin && s_tx.cfg.pm_end == cfg->pm_end,
                            ESP_ERR_INVALID_STATE, TAG, "TX ring already configured differently");
        atomic_store(&s_tx.enabled, true);
        return ESP_OK;
    }
    uint8_t *base = heap_caps_malloc(cfg->base_frames * TX_SLAB_BYTES, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    ESP_RETURN_ON_FALSE(base, ESP_ERR_NO_MEM, TAG, "Failed to allocate TX ring");
    s_tx.cfg = *cfg;
    s_tx.base = base;
    s_tx.base_slabs = (uint8_t)cfg->base_frames;
    s_tx.alloc_mask = (1u << cfg->base_frames) - 1u;
    s_tx.reading = -1;
    TaskHandle_t worker = NULL;
    if (xTaskCreatePinnedToCore(tx_worker, "usb_txq", TX_WORKER_STACK, NULL, cfg->priority, &worker, cfg->core) != pdPASS) {
        heap_caps_free(base);
        s_tx.base = NULL;
        return ESP_ERR_NO_MEM;
    }
    s_tx.worker = worker;
    atomic_store(&s_tx.enabled, true);
    return ESP_OK;
}

void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *out)
{
    uint32_t chunks, present, hw_bytes, hw_slabs, cold_n, cold_sum, cold_max;
    TX_ENTER();
    cold_n = s_tx.cold_starts;
    cold_sum = s_tx.cold_us_sum;
    cold_max = s_tx.cold_us_max;
    chunks = s_tx.chunks_live;
    present = s_tx.chunks_present;
    hw_bytes = s_tx.high_water_bytes;
    hw_slabs = s_tx.high_water_slabs;
    TX_EXIT();
    *out = (tinyusb_net_tx_stats_t) {
        .ring_bytes = (s_tx.base_slabs + chunks * TX_CHUNK_SLABS) * TX_SLAB_BYTES,
        .base_bytes = s_tx.base_slabs * TX_SLAB_BYTES,
        .max_bytes = (s_tx.base_slabs + s_tx.cfg.max_chunks * TX_CHUNK_SLABS) * TX_SLAB_BYTES,
        .elastic_held_bytes = present * TX_CHUNK_BYTES,
        .chunks = chunks,
        .high_water_bytes = hw_bytes,
        .high_water_slabs = hw_slabs,
        .enqueued_frames = atomic_load(&s_tx.enq_frames),
        .enqueued_bytes = atomic_load(&s_tx.enq_bytes),
        .sent_frames = atomic_load(&s_tx.sent_frames),
        .sent_bytes = atomic_load(&s_tx.sent_bytes),
        .dropped_full = atomic_load(&s_tx.drop_full),
        .dropped_link_down = atomic_load(&s_tx.drop_down),
        .dropped_invalid = atomic_load(&s_tx.drop_invalid),
        .flushed_link_down = atomic_load(&s_tx.flushed),
        .ntb_blocked = atomic_load(&s_tx.blocked_events),
        .xfer_events = atomic_load(&s_tx.xfer_events),
        .worker_stack_free = s_tx.worker ? (uint32_t) uxTaskGetStackHighWaterMark(s_tx.worker) : 0,
        .grow_events = atomic_load(&s_tx.grow_events),
        .shrink_events = atomic_load(&s_tx.shrink_events),
        .reclaim_events = atomic_load(&s_tx.reclaim_events),
        .reclaimed_chunks = atomic_load(&s_tx.reclaimed_chunks),
        .grow_denied_gate = atomic_load(&s_tx.deny_gate),
        .grow_denied_heap = atomic_load(&s_tx.deny_heap),
        .grow_denied_largest = atomic_load(&s_tx.deny_largest),
        .grow_denied_nomem = atomic_load(&s_tx.deny_nomem),
        .grow_raced = atomic_load(&s_tx.grow_raced),
        .pm_acquired = atomic_load(&s_tx.pm_acquired),
        .pm_released = atomic_load(&s_tx.pm_released),
        .pm_held = atomic_load(&s_tx.pm_held),
        .ntb_xfers = atomic_load(&s_tx.ntb_xfers),
        .ntb_zlp = atomic_load(&s_tx.ntb_zlp),
        .ntb_bytes = atomic_load(&s_tx.ntb_bytes),
        .ntb_max_bytes = atomic_load(&s_tx.ntb_max_bytes),
        .gap_count = atomic_load(&s_tx.gap_count),
        .gap_us_sum = atomic_load(&s_tx.gap_us_sum),
        .gap_us_max = atomic_load(&s_tx.gap_us_max),
        .cold_starts = cold_n,
        .cold_us_sum = cold_sum,
        .cold_us_max = cold_max,
        .worker_demotions = atomic_load(&s_tx.demotions),
    };
    for (unsigned i = 0; i < 5; i++) {
        out->drains_sent[i] = atomic_load(&s_tx.drains_sent[i]);
        out->gap_hist[i] = atomic_load(&s_tx.gap_hist[i]);
    }
}

esp_err_t tinyusb_net_init(const tinyusb_net_config_t *cfg)
{
    ESP_RETURN_ON_FALSE(s_net_obj.initialized == false, ESP_ERR_INVALID_STATE, TAG, "TinyUSB Net class is already initialized");

    // the semaphore and event flags are initialized only if needed
    s_net_obj.rx_cb = cfg->on_recv_callback;
    s_net_obj.init_cb = cfg->on_init_callback;
    s_net_obj.tx_buff_free_cb = cfg->free_tx_buffer;
    s_net_obj.ctx = cfg->user_context;

    const uint8_t *mac = &cfg->mac_addr[0];
    snprintf(s_net_obj.mac_str, sizeof(s_net_obj.mac_str), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    uint8_t mac_id = tusb_get_mac_string_id();
    // Pass it to Descriptor control module
    tinyusb_descriptors_set_string(s_net_obj.mac_str, mac_id);

    s_net_obj.initialized = true;

    return ESP_OK;
}

void tinyusb_net_deinit(void)
{
    // The ring's permanent slabs and its worker live for the life of the firmware; stop accepting frames, drop what
    // is queued (nothing will drain it now), give the elastic chunks back, and let the worker release the PM lock.
    atomic_store(&s_tx.enabled, false);
    if (s_tx.base != NULL) {
        TX_ENTER();
        uint32_t n = tx_discard_locked();
        s_tx.epoch++;                   // a growth that allocated before this and publishes after it is discarded
        tx_retire_all_locked(TX_WHY_RECLAIM);
        TX_EXIT();
        atomic_fetch_add_explicit(&s_tx.flushed, n, memory_order_relaxed);
        tx_reap();
        xTaskNotifyGive(s_tx.worker);
    }
    if (s_net_obj.buffer_sema) {
        vSemaphoreDelete(s_net_obj.buffer_sema);
        s_net_obj.buffer_sema = NULL;
    }
    if (s_net_obj.tx_flags) {
        vEventGroupDelete(s_net_obj.tx_flags);
        s_net_obj.tx_flags = NULL;
    }
    s_net_obj.initialized = false;
    s_net_obj.rx_cb = NULL;
    s_net_obj.init_cb = NULL;
    s_net_obj.tx_buff_free_cb = NULL;
    s_net_obj.ctx = NULL;
    s_net_obj.packet_to_send = NULL;
    memset(s_net_obj.mac_str, 0, sizeof(s_net_obj.mac_str));
}

//--------------------------------------------------------------------+
// tinyusb callbacks
//--------------------------------------------------------------------+
bool tud_network_recv_cb(const uint8_t *src, uint16_t size)
{
    if (s_net_obj.rx_cb) {
        s_net_obj.rx_cb((void *)src, size, s_net_obj.ctx);
    }
    tud_network_recv_renew();
    return true;
}

uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg)
{
    packet_t *packet = ref;
    uint16_t len = arg;

    if (packet->ring) {
        memcpy(dst, packet->buffer, packet->len);     // records never straddle a slab
        return len;
    }
    memcpy(dst, packet->buffer, packet->len);
    if (s_net_obj.tx_buff_free_cb) {
        s_net_obj.tx_buff_free_cb(packet->buff_free_arg, s_net_obj.ctx);
    }
    return len;
}

void tud_network_init_cb(void)
{
    if (s_net_obj.init_cb) {
        s_net_obj.init_cb(s_net_obj.ctx);
    }
}
