/* Transparent bridge forwarding (tdongle_l2.h; ADR 0023). Derived from main/bridge.c; the buffering, the generation flush, the CPU-clock
 * treatment and the Wi-Fi transmit budget are the gateway's own mechanisms, not copies of them.
 *
 * Both callbacks run in tasks that must not wait (the Wi-Fi task and the TinyUSB task: the TinyUSB task serves both USB directions, and
 * usbd_defer_func() waits forever when its event queue is full), so each only copies and returns. The state they share with the worker is
 * a pair of free-running counters over a fixed slot array (single producer, single consumer, no lock) and atomics. */
#include "tdongle_l2.h"
#include "tdongle_pm.h"
#include "esp_private/wifi.h"
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
    uint8_t bytes[TDONGLE_L2_FRAME_MAX];
} host_slot_t;
_Static_assert(sizeof(host_slot_t) <= TDONGLE_L2_SLOT_BYTES, "TDONGLE_L2_SLOT_BYTES is the size the heap budget is written with");
_Static_assert((TDONGLE_L2_HOST_SLOTS & (TDONGLE_L2_HOST_SLOTS - 1u)) == 0, "the slot counters run free: the slot count must divide 2^32");
_Static_assert(TDONGLE_L2_HOST_SLOTS <= 64u, "the queue depth is reported in 32 bits and sized for a few milliseconds of USB");
_Static_assert((uint64_t)TDONGLE_L2_TX_RETRY_MS * 1000u < TDONGLE_PM_ACTIVITY_HOLD_US,
               "a frame waiting for Wi-Fi must be inside the forwarding activity hold, or the clock drops under it");

#define SLOT_MASK (TDONGLE_L2_HOST_SLOTS - 1u)
#define BUMP(field) atomic_fetch_add_explicit(&l2.field, 1u, memory_order_relaxed)

static struct {
    esp_err_t (*wifi_tx)(void *frame, uint16_t len);
    host_slot_t *slots;
    TaskHandle_t worker;
    uint8_t identity[6];
    atomic_uint head, tail;      /* free-running: the producer (TinyUSB task) advances head, the worker tail */
    atomic_uint epoch;           /* bumped by every link change; a queued frame from an older epoch is stale */
    atomic_bool linked;
    atomic_uint link_changes;
    atomic_uint w2h_frames, w2h_forwarded, w2h_invalid, w2h_own_mac, w2h_link_down, w2h_usb_not_ready, w2h_ring_full;
    atomic_uint h2w_frames, h2w_queued, h2w_invalid, h2w_foreign_mac, h2w_link_down, h2w_queue_full;
    atomic_uint h2w_sent, h2w_stale, h2w_link_down_queued, h2w_tx_failed, h2w_tx_retries, h2w_queue_high_water;
    atomic_int h2w_last_tx_error;
} l2;

/* A link-layer multicast or broadcast frame (the I/G bit) is the neighbours' chatter: it is forwarded like any other but must not pin the
 * clock at its maximum for a hold period (tdongle_pm.h; the same rule gateway_host_input applies). */
static bool unicast(const uint8_t *frame) { return (frame[0] & 1u) == 0; }

/* ---- Wi-Fi -> host: the Wi-Fi task ---- */
static esp_err_t receive(void *buffer, uint16_t len, void *driver_buffer) {
    const uint8_t *frame = buffer;
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
        if (unicast(frame)) tdongle_pm_note_activity();
        switch (tinyusb_net_tx_ring_send(buffer, len)) {
        case ESP_OK: BUMP(w2h_forwarded); break;
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
    const unsigned head = atomic_load_explicit(&l2.head, memory_order_relaxed);
    const unsigned tail = atomic_load_explicit(&l2.tail, memory_order_acquire);
    if (head - tail >= TDONGLE_L2_HOST_SLOTS) {
        BUMP(h2w_queue_full);
        return ESP_ERR_NO_MEM;
    }
    if (unicast(frame)) tdongle_pm_note_activity();
    host_slot_t *slot = &l2.slots[head & SLOT_MASK];
    slot->len = len;
    slot->epoch = (uint16_t)atomic_load_explicit(&l2.epoch, memory_order_acquire);
    memcpy(slot->bytes, buffer, len);
    atomic_store_explicit(&l2.head, head + 1u, memory_order_release);
    BUMP(h2w_queued);
    const unsigned depth = head + 1u - tail;
    unsigned seen = atomic_load_explicit(&l2.h2w_queue_high_water, memory_order_relaxed);
    while (depth > seen && !atomic_compare_exchange_weak_explicit(&l2.h2w_queue_high_water, &seen, depth, memory_order_relaxed, memory_order_relaxed)) {
    }
    xTaskNotifyGive(l2.worker);                          /* never blocks */
    return ESP_OK;
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
    TickType_t budget = pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS);
    if (budget == 0) budget = 1;
    const TickType_t start = xTaskGetTickCount();
    for (;;) {
        /* The slot is read in place: only this task frees it (by advancing tail), and the driver copies the frame inside the call. */
        const esp_err_t result = l2.wifi_tx((void *)slot->bytes, slot->len);
        if (result == ESP_OK) {
            BUMP(h2w_sent);
            return;
        }
        atomic_store_explicit(&l2.h2w_last_tx_error, result, memory_order_relaxed);
        /* Only "no buffer" can clear by itself. A link change while we wait makes the frame stale, whatever the driver says. */
        if (result != ESP_ERR_NO_MEM || !atomic_load_explicit(&l2.linked, memory_order_acquire) ||
            slot->epoch != (uint16_t)atomic_load_explicit(&l2.epoch, memory_order_acquire) ||
            (TickType_t)(xTaskGetTickCount() - start) >= budget) {
            BUMP(h2w_tx_failed);
            return;
        }
        BUMP(h2w_tx_retries);
        vTaskDelay(1);                                   /* one tick: the driver frees buffers as frames are sent */
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
    if (xTaskCreatePinnedToCore(forward, "l2_wifi", config->task_stack, NULL, config->task_priority, &l2.worker, config->task_core) != pdPASS) {
        free(l2.slots);
        l2.slots = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

void tdongle_l2_link(bool connected) {
    atomic_store_explicit(&l2.linked, connected, memory_order_release);
    atomic_fetch_add_explicit(&l2.epoch, 1u, memory_order_acq_rel);
    BUMP(link_changes);
    /* The driver keeps the RX callback across a link change but its buffers belong to the old association: register on connect only. */
    esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, connected ? receive : NULL);
    /* Frames queued toward the host were received under the previous association: discard them, as a USB detach does. */
    tinyusb_net_tx_ring_flush();
    tud_network_link_state(0, connected);
}

void tdongle_l2_stats(tdongle_l2_stats_t *out) {
#define LOAD(field) atomic_load_explicit(&l2.field, memory_order_relaxed)
    const unsigned head = atomic_load_explicit(&l2.head, memory_order_acquire), tail = atomic_load_explicit(&l2.tail, memory_order_acquire);
    *out = (tdongle_l2_stats_t){
        .linked = atomic_load_explicit(&l2.linked, memory_order_acquire), .link_changes = LOAD(link_changes),
        .w2h_frames = LOAD(w2h_frames), .w2h_forwarded = LOAD(w2h_forwarded), .w2h_invalid = LOAD(w2h_invalid),
        .w2h_own_mac = LOAD(w2h_own_mac), .w2h_link_down = LOAD(w2h_link_down), .w2h_usb_not_ready = LOAD(w2h_usb_not_ready),
        .w2h_ring_full = LOAD(w2h_ring_full),
        .h2w_frames = LOAD(h2w_frames), .h2w_queued = LOAD(h2w_queued), .h2w_invalid = LOAD(h2w_invalid),
        .h2w_foreign_mac = LOAD(h2w_foreign_mac), .h2w_link_down = LOAD(h2w_link_down), .h2w_queue_full = LOAD(h2w_queue_full),
        .h2w_sent = LOAD(h2w_sent), .h2w_stale = LOAD(h2w_stale), .h2w_link_down_queued = LOAD(h2w_link_down_queued),
        .h2w_tx_failed = LOAD(h2w_tx_failed), .h2w_tx_retries = LOAD(h2w_tx_retries), .h2w_last_tx_error = LOAD(h2w_last_tx_error),
        .h2w_queue_depth = head - tail, .h2w_queue_high_water = LOAD(h2w_queue_high_water),
        .worker_stack_free = l2.worker ? (uint32_t)uxTaskGetStackHighWaterMark(l2.worker) : 0,
    };
#undef LOAD
}
