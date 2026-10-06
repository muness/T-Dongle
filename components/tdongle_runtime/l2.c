/* Transparent bridge forwarding (tdongle_l2.h; ADR 0023). Derived from main/bridge.c; the buffering, the generation flush, the CPU-clock
 * treatment and the Wi-Fi transmit budget are the gateway's own mechanisms, not copies of them.
 *
 * Both callbacks run in tasks that must not wait (the Wi-Fi task and the TinyUSB task: the TinyUSB task serves both USB directions, and
 * usbd_defer_func() waits forever when its event queue is full), so each only copies and returns. The state they share with the worker is
 * a pair of free-running counters over a fixed slot array (single producer, single consumer, no lock) and atomics. */
#include "tdongle_l2.h"
#include "tdongle_pm.h"
#include "esp_private/wifi.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb_net.h"
#include "tusb.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint16_t len;
    uint16_t epoch;              /* the link epoch at the time the frame was queued */
    uint32_t enq_us;             /* esp_timer_get_time() when the callback queued it */
    uint8_t bytes[TDONGLE_L2_FRAME_MAX];
} host_slot_t;
_Static_assert(sizeof(host_slot_t) <= TDONGLE_L2_SLOT_BYTES, "TDONGLE_L2_SLOT_BYTES is the size the heap budget is written with");
_Static_assert((TDONGLE_L2_HOST_SLOTS & (TDONGLE_L2_HOST_SLOTS - 1u)) == 0, "the slot counters run free: the slot count must divide 2^32");
_Static_assert(TDONGLE_L2_HOST_QUEUE_LIMIT >= 2 && TDONGLE_L2_HOST_QUEUE_LIMIT <= TDONGLE_L2_HOST_SLOTS, "the standing-queue limit lives inside the slot array");
_Static_assert((uint64_t)TDONGLE_L2_SOJOURN_MS * 1000u < TDONGLE_PM_ACTIVITY_HOLD_US,
               "a frame waiting for Wi-Fi must be inside the forwarding activity hold, or the clock drops under it");
_Static_assert(TDONGLE_L2_RETRY_US >= 100u && (uint64_t)TDONGLE_L2_RETRY_US * 4u <= (uint64_t)TDONGLE_L2_SOJOURN_MS * 1000u, "a retry period is a fraction of the sojourn limit");

#define SLOT_MASK (TDONGLE_L2_HOST_SLOTS - 1u)
#define BUMP(field) atomic_fetch_add_explicit(&l2.field, 1u, memory_order_relaxed)
#define ADD(field, v) atomic_fetch_add_explicit(&l2.field, (unsigned)(v), memory_order_relaxed)

static struct {
    esp_err_t (*wifi_tx)(void *frame, uint16_t len);
    host_slot_t *slots;
    TaskHandle_t worker;
    esp_timer_handle_t retry_timer;
    uint8_t identity[6];
    atomic_uint head, tail;      /* free-running: the producer (TinyUSB task) advances head, the worker tail */
    atomic_uint epoch;           /* bumped by every link change; a queued frame from an older epoch is stale */
    atomic_bool linked;
    atomic_uint link_changes;
    atomic_uint w2h_frames, w2h_forwarded, w2h_invalid, w2h_own_mac, w2h_link_down, w2h_usb_not_ready, w2h_ring_full, w2h_raced;
    atomic_uint h2w_frames, h2w_queued, h2w_invalid, h2w_foreign_mac, h2w_link_down, h2w_queue_full;
    atomic_uint h2w_sent, h2w_stale, h2w_sojourn_drop, h2w_link_down_queued, h2w_tx_failed, h2w_tx_retries, h2w_queue_high_water;
    atomic_int h2w_last_tx_error;
    atomic_uint pm_notes, pm_note_us_sum, pm_note_us_max, h2w_wait_us_sum, h2w_wait_us_max, h2w_tx_us_sum, h2w_tx_us_max;
} l2;

static void note_max(atomic_uint *mark, unsigned v) {
    unsigned seen = atomic_load_explicit(mark, memory_order_relaxed);
    while (v > seen && !atomic_compare_exchange_weak_explicit(mark, &seen, v, memory_order_relaxed, memory_order_relaxed)) {
    }
}
static uint32_t now_us(void) { return (uint32_t)esp_timer_get_time(); }

/* A link-layer multicast or broadcast frame (the I/G bit) is the neighbours' chatter: it is forwarded like any other but must not pin the
 * clock at its maximum for a hold period (tdongle_pm.h; the same rule gateway_host_input applies). */
static bool unicast(const uint8_t *frame) { return (frame[0] & 1u) == 0; }
/* tdongle_pm_note_activity() with its cost recorded: the first note after an idle period raises the CPU clock inside the caller, and how long
 * that takes is what the idle-latency question of the first board run is about (ADR 0023, "idle ping"). */
static void note_activity(void) {
    const uint32_t t0 = now_us();
    tdongle_pm_note_activity();
    const uint32_t dt = now_us() - t0;
    BUMP(pm_notes);
    ADD(pm_note_us_sum, dt);
    note_max(&l2.pm_note_us_max, dt);
}

/* ---- Wi-Fi -> host: the Wi-Fi task ---- */
static esp_err_t receive(void *buffer, uint16_t len, void *driver_buffer) {
    const uint8_t *frame = buffer;
    /* The epoch is read BEFORE the link is looked at: a link change that lands while this frame is being copied is then visible afterwards. */
    const unsigned epoch = atomic_load_explicit(&l2.epoch, memory_order_acquire);
    BUMP(w2h_frames);
    if (len < 14 || len > TDONGLE_L2_FRAME_MAX)
        BUMP(w2h_invalid);
    else if (!memcmp(frame + 6, l2.identity, 6))
        BUMP(w2h_own_mac);
    else if (!atomic_load_explicit(&l2.linked, memory_order_acquire))
        BUMP(w2h_link_down);
    else {
        /* Raise the clock before the copy: the first frame after an idle period finds the CPU at its low frequency, and everything after
         * it (the ring worker, the TinyUSB drain) should not. One atomic load while the hold is active. */
        if (unicast(frame)) note_activity();
        switch (tinyusb_net_tx_ring_send(buffer, len)) {
        case ESP_OK:
            BUMP(w2h_forwarded);
            /* The window: this frame passed the link check under an association that ended before the ring stamped it, so it carries the NEW
             * generation and the flush of the change cannot discard it. The epoch moved: flush again. It costs the frames of the first
             * microseconds of the new association, which is the right side to err on. */
            if (atomic_load_explicit(&l2.epoch, memory_order_acquire) != epoch) {
                BUMP(w2h_raced);
                tinyusb_net_tx_ring_flush();
            }
            break;
        case ESP_ERR_NO_MEM: BUMP(w2h_ring_full); break;
        case ESP_ERR_INVALID_STATE: BUMP(w2h_usb_not_ready); break;
        default: BUMP(w2h_invalid); break;
        }
    }
    esp_wifi_internal_free_rx_buffer(driver_buffer);    /* always, exactly once, before returning: the driver's pool is not ours to hold */
    return ESP_OK;
}

/* ---- host -> Wi-Fi ---- */
esp_err_t tdongle_l2_host(void *buffer, uint16_t len) {
    const uint8_t *frame = buffer;
    if (!l2.slots) return ESP_ERR_INVALID_STATE;
    BUMP(h2w_frames);
    if (len < 14 || len > TDONGLE_L2_FRAME_MAX) {
        BUMP(h2w_invalid);
        return ESP_ERR_INVALID_ARG;
    }
    if (memcmp(frame + 6, l2.identity, 6)) {
        BUMP(h2w_foreign_mac);
        return ESP_OK;
    }
    if (!atomic_load_explicit(&l2.linked, memory_order_acquire)) {
        BUMP(h2w_link_down);
        return ESP_ERR_INVALID_STATE;
    }
    /* tail first, then head: head only grows, so head - tail can never be negative whatever the worker does between the two loads. */
    const unsigned tail = atomic_load_explicit(&l2.tail, memory_order_acquire);
    const unsigned head = atomic_load_explicit(&l2.head, memory_order_relaxed);
    if (head - tail >= TDONGLE_L2_HOST_QUEUE_LIMIT) {
        BUMP(h2w_queue_full);
        return ESP_ERR_NO_MEM;
    }
    if (unicast(frame)) note_activity();
    host_slot_t *slot = &l2.slots[head & SLOT_MASK];
    slot->len = len;
    slot->epoch = (uint16_t)atomic_load_explicit(&l2.epoch, memory_order_acquire);
    slot->enq_us = now_us();
    memcpy(slot->bytes, buffer, len);
    atomic_store_explicit(&l2.head, head + 1u, memory_order_release);
    BUMP(h2w_queued);
    note_max(&l2.h2w_queue_high_water, head + 1u - tail);
    xTaskNotifyGive(l2.worker);                          /* never blocks */
    return ESP_OK;
}

static void retry_fire(void *arg) { (void)arg; xTaskNotifyGive(l2.worker); }   /* esp_timer task */
/* Wait for the next chance: a retry period, or earlier if a notification arrives (a new frame: the loop re-attempts at once, harmlessly). */
static void retry_wait(void) {
    esp_timer_start_once(l2.retry_timer, TDONGLE_L2_RETRY_US);       /* already armed: ESP_ERR_INVALID_STATE, nothing to do */
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(TDONGLE_L2_SOJOURN_MS) + 1);
}

/* One queued frame, in the worker. The only place the Wi-Fi driver is called from the host side. */
static void deliver(const host_slot_t *slot) {
    if (!atomic_load_explicit(&l2.linked, memory_order_acquire)) {
        BUMP(h2w_link_down_queued);
        return;
    }
    if (slot->epoch != (uint16_t)atomic_load_explicit(&l2.epoch, memory_order_acquire)) {
        BUMP(h2w_stale);                                 /* queued under an association that has since ended */
        return;
    }
    const uint32_t first = now_us();
    const uint32_t waited = first - slot->enq_us;
    const uint32_t limit = (uint32_t)TDONGLE_L2_SOJOURN_MS * 1000u;
    if (waited >= limit) {
        BUMP(h2w_sojourn_drop);                          /* a stalled link must not turn the queue into a delay line */
        return;
    }
    ADD(h2w_wait_us_sum, waited);
    note_max(&l2.h2w_wait_us_max, waited);
    for (;;) {
        /* The slot is read in place: only this task frees it (by advancing tail), and the driver copies the frame inside the call. */
        const uint32_t t0 = now_us();
        const esp_err_t result = l2.wifi_tx((void *)slot->bytes, slot->len);
        const uint32_t t1 = now_us();
        if (result == ESP_OK) {
            BUMP(h2w_sent);
            ADD(h2w_tx_us_sum, t1 - t0);
            note_max(&l2.h2w_tx_us_max, t1 - t0);
            return;
        }
        atomic_store_explicit(&l2.h2w_last_tx_error, result, memory_order_relaxed);
        /* Only "no buffer" can clear by itself. A link change while we wait makes the frame stale, whatever the driver says. */
        if (result != ESP_ERR_NO_MEM || !atomic_load_explicit(&l2.linked, memory_order_acquire) ||
            slot->epoch != (uint16_t)atomic_load_explicit(&l2.epoch, memory_order_acquire) || t1 - slot->enq_us >= limit) {
            BUMP(h2w_tx_failed);
            return;
        }
        BUMP(h2w_tx_retries);
        retry_wait();
    }
}

/* Everything queued so far; returns how many frames were handled. */
static unsigned drain(void) {
    unsigned handled = 0;
    for (;;) {
        const unsigned tail = atomic_load_explicit(&l2.tail, memory_order_relaxed);
        if (tail == atomic_load_explicit(&l2.head, memory_order_acquire)) return handled;
        deliver(&l2.slots[tail & SLOT_MASK]);
        atomic_store_explicit(&l2.tail, tail + 1u, memory_order_release);    /* the slot is the producer's again */
        handled++;
    }
}

static void forward(void *unused) {
    (void)unused;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);         /* a notification that arrives during drain() is kept: no lost wakeup */
        drain();
    }
}

esp_err_t tdongle_l2_start(const uint8_t mac[6], const tdongle_l2_config_t *config) {
    if (!config || !config->wifi_tx || !config->task_stack) return ESP_ERR_INVALID_ARG;
    if (l2.slots) return ESP_ERR_INVALID_STATE;
    memset(&l2, 0, sizeof(l2));
    memcpy(l2.identity, mac, 6);
    l2.wifi_tx = config->wifi_tx;
    l2.slots = calloc(TDONGLE_L2_HOST_SLOTS, sizeof(host_slot_t));
    if (!l2.slots) return ESP_ERR_NO_MEM;
    const esp_timer_create_args_t timer = {.callback = retry_fire, .name = "l2_retry"};
    if (esp_timer_create(&timer, &l2.retry_timer) != ESP_OK) {
        free(l2.slots);
        l2.slots = NULL;
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreatePinnedToCore(forward, "l2_wifi", config->task_stack, NULL, config->task_priority, &l2.worker, config->task_core) != pdPASS) {
        esp_timer_delete(l2.retry_timer);
        free(l2.slots);
        l2.slots = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

void tdongle_l2_link(bool connected) {
    atomic_fetch_add_explicit(&l2.epoch, 1u, memory_order_acq_rel);
    BUMP(link_changes);
    if (connected) {
        /* Everything in the ring was received under the previous association, and nothing of the new one can arrive before the callback is
         * registered: flush first, then open the gate. */
        tinyusb_net_tx_ring_flush();
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, receive);
        atomic_store_explicit(&l2.linked, true, memory_order_release);
    } else {
        atomic_store_explicit(&l2.linked, false, memory_order_release);
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, NULL);
        tinyusb_net_tx_ring_flush();                     /* frames received before the link dropped must not reach the host after it */
    }
    tud_network_link_state(0, connected);
}

void tdongle_l2_stats(tdongle_l2_stats_t *out) {
#define LOAD(field) atomic_load_explicit(&l2.field, memory_order_relaxed)
    /* tail BEFORE head: head only grows, so the difference cannot go negative (and wrap to 4 billion) however the worker interleaves. */
    const unsigned tail = atomic_load_explicit(&l2.tail, memory_order_acquire), head = atomic_load_explicit(&l2.head, memory_order_acquire);
    *out = (tdongle_l2_stats_t){
        .linked = atomic_load_explicit(&l2.linked, memory_order_acquire), .link_changes = LOAD(link_changes),
        .w2h_frames = LOAD(w2h_frames), .w2h_forwarded = LOAD(w2h_forwarded), .w2h_invalid = LOAD(w2h_invalid),
        .w2h_own_mac = LOAD(w2h_own_mac), .w2h_link_down = LOAD(w2h_link_down), .w2h_usb_not_ready = LOAD(w2h_usb_not_ready),
        .w2h_ring_full = LOAD(w2h_ring_full), .w2h_raced = LOAD(w2h_raced),
        .h2w_frames = LOAD(h2w_frames), .h2w_queued = LOAD(h2w_queued), .h2w_invalid = LOAD(h2w_invalid),
        .h2w_foreign_mac = LOAD(h2w_foreign_mac), .h2w_link_down = LOAD(h2w_link_down), .h2w_queue_full = LOAD(h2w_queue_full),
        .h2w_sent = LOAD(h2w_sent), .h2w_stale = LOAD(h2w_stale), .h2w_sojourn_drop = LOAD(h2w_sojourn_drop),
        .h2w_link_down_queued = LOAD(h2w_link_down_queued),
        .h2w_tx_failed = LOAD(h2w_tx_failed), .h2w_tx_retries = LOAD(h2w_tx_retries), .h2w_last_tx_error = LOAD(h2w_last_tx_error),
        .h2w_queue_depth = head - tail, .h2w_queue_high_water = LOAD(h2w_queue_high_water),
        .worker_stack_free = l2.worker ? (uint32_t)uxTaskGetStackHighWaterMark(l2.worker) : 0,
        .pm_notes = LOAD(pm_notes), .pm_note_us_sum = LOAD(pm_note_us_sum), .pm_note_us_max = LOAD(pm_note_us_max),
        .h2w_wait_us_sum = LOAD(h2w_wait_us_sum), .h2w_wait_us_max = LOAD(h2w_wait_us_max),
        .h2w_tx_us_sum = LOAD(h2w_tx_us_sum), .h2w_tx_us_max = LOAD(h2w_tx_us_max),
    };
#undef LOAD
}
