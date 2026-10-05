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

#define MAC_ADDR_LEN 6

typedef struct packet {
    void *buffer;
    void *buff_free_arg;
    uint16_t len;
    esp_err_t result;
    bool ring;                 // payload lives in the TX ring: nothing to release
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
// Non-blocking transmit ring
//--------------------------------------------------------------------+
/*
 * tinyusb_net_send_sync() waits for the TinyUSB task, which is wrong for a
 * caller that holds a lock the rest of the system needs (the gateway sends
 * from inside the lwIP core lock). The ring is the alternative contract:
 *
 *   producer (any single, serialized context)      consumer (TinyUSB task)
 *   copy frame into ring, publish head, notify --> do_drain: tud_network_xmit()
 *                                                   each frame exactly once
 *
 * - One producer, one consumer: head is written only by the producer, tail
 *   only by the consumer, each published with release and read with acquire.
 *   No lock, no allocation and no wait on the producer side. Callers must be
 *   serialized, exactly like tinyusb_net_send_sync().
 * - Records are [len:2][reserved:2][payload, padded to 4]. A record never
 *   straddles the end of the buffer: the producer writes a pad record
 *   (len == TX_PAD) and wraps. One word is always left free so head == tail
 *   means empty.
 * - A frame leaves the ring only when TinyUSB copied it into an NTB (or it is
 *   discarded because USB went away). The copy is synchronous inside
 *   tud_network_xmit(), so advancing tail right after it is the single
 *   release of that slot; replaying a drain callback finds nothing to do.
 * - Full ring: the new frame is dropped and counted (tail drop); lwIP/TCP
 *   treat it as ordinary loss. There is no retry loop on the producer.
 * - tud_network_xmit() must run in the TinyUSB task, and usbd_defer_func()
 *   from a task blocks forever when TinyUSB's event queue is full. So the
 *   producer only does a task notification; a small worker task performs the
 *   (possibly blocking) defer. When every NTB is in flight the worker retries
 *   each tick until the host has taken one.
 */
#define TX_REC_HDR   4u
#define TX_PAD       0xFFFFu
#define TX_FRAME_MIN 14u
#define TX_FRAME_MAX 1518u      // 1500 byte MTU + Ethernet header + VLAN tag
#define TX_ALIGN4(n) (((uint32_t)(n) + 3u) & ~3u)

static struct {
    uint8_t *buf;
    uint32_t cap;
    _Atomic uint32_t head;      // next write offset, producer only
    _Atomic uint32_t tail;      // next read offset, consumer only
    _Atomic bool enabled;
    _Atomic bool drain_pending; // a do_drain callback is queued in TinyUSB
    _Atomic bool blocked;       // last drain stopped on can_xmit() == false
    TaskHandle_t worker;
    _Atomic uint32_t high_water;
    _Atomic uint32_t enq_frames, enq_bytes, sent_frames, sent_bytes;
    _Atomic uint32_t drop_full, drop_down, drop_invalid, flushed, blocked_events;
} s_tx;

static uint32_t tx_used(uint32_t head, uint32_t tail, uint32_t cap)
{
    return head >= tail ? head - tail : cap - tail + head;
}

/* Producer: find room for a record of `need` bytes. */
static bool tx_reserve(uint32_t need, uint32_t head, uint32_t tail, uint32_t cap,
                       uint32_t *pos, uint32_t *pad_at, uint32_t *new_head)
{
    *pad_at = UINT32_MAX;
    if (head >= tail) {
        uint32_t end = cap - head;
        if (need <= end && !(head + need == cap && tail == 0)) {
            *pos = head;
            *new_head = (head + need == cap) ? 0 : head + need;
            return true;
        }
        if (need < tail) {      // wrap: pad out the end, start again at 0
            *pad_at = end ? head : UINT32_MAX;
            *pos = 0;
            *new_head = need;
            return true;
        }
        return false;
    }
    if (need < tail - head) {
        *pos = head;
        *new_head = head + need;
        return true;
    }
    return false;
}

esp_err_t tinyusb_net_tx_ring_send(const void *buffer, uint16_t len)
{
    if (!atomic_load_explicit(&s_tx.enabled, memory_order_relaxed)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (buffer == NULL || len < TX_FRAME_MIN || len > TX_FRAME_MAX) {
        atomic_fetch_add_explicit(&s_tx.drop_invalid, 1, memory_order_relaxed);
        return ESP_ERR_INVALID_ARG;
    }
    if (!tud_ready()) {
        atomic_fetch_add_explicit(&s_tx.drop_down, 1, memory_order_relaxed);
        return ESP_ERR_INVALID_STATE;
    }
    uint32_t head = atomic_load_explicit(&s_tx.head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&s_tx.tail, memory_order_acquire);
    uint32_t pos, pad_at, new_head, need = TX_REC_HDR + TX_ALIGN4(len);
    if (!tx_reserve(need, head, tail, s_tx.cap, &pos, &pad_at, &new_head)) {
        atomic_fetch_add_explicit(&s_tx.drop_full, 1, memory_order_relaxed);
        return ESP_ERR_NO_MEM;
    }
    if (pad_at != UINT32_MAX) {
        uint16_t pad[2] = { TX_PAD, 0 };
        memcpy(s_tx.buf + pad_at, pad, sizeof(pad));
    }
    uint16_t hdr[2] = { len, 0 };
    memcpy(s_tx.buf + pos, hdr, sizeof(hdr));
    memcpy(s_tx.buf + pos + TX_REC_HDR, buffer, len);
    atomic_store_explicit(&s_tx.head, new_head, memory_order_release);

    uint32_t used = tx_used(new_head, tail, s_tx.cap);
    if (used > atomic_load_explicit(&s_tx.high_water, memory_order_relaxed)) {
        atomic_store_explicit(&s_tx.high_water, used, memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&s_tx.enq_frames, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_tx.enq_bytes, len, memory_order_relaxed);
    xTaskNotifyGive(s_tx.worker);   // never blocks
    return ESP_OK;
}

/* TinyUSB task. Idempotent: a duplicate callback finds the ring drained. */
static void do_drain(void *ctx)
{
    (void) ctx;
    atomic_store(&s_tx.drain_pending, false);
    bool ready = tud_ready();
    for (;;) {
        uint32_t tail = atomic_load_explicit(&s_tx.tail, memory_order_relaxed);
        uint32_t head = atomic_load_explicit(&s_tx.head, memory_order_acquire);
        if (tail == head) {
            atomic_store(&s_tx.blocked, false);
            return;
        }
        uint16_t hdr[2];
        memcpy(hdr, s_tx.buf + tail, sizeof(hdr));
        if (hdr[0] == TX_PAD) {
            atomic_store_explicit(&s_tx.tail, 0, memory_order_release);
            continue;
        }
        uint16_t len = hdr[0];
        if (ready && !tud_network_can_xmit(len)) {
            // every NTB is in flight; keep the frame, the worker retries
            if (!atomic_exchange(&s_tx.blocked, true)) {
                atomic_fetch_add_explicit(&s_tx.blocked_events, 1, memory_order_relaxed);
            }
            return;
        }
        if (ready) {
            packet_t packet = { .buffer = s_tx.buf + tail + TX_REC_HDR, .len = len, .ring = true };
            tud_network_xmit(&packet, len);     // copies synchronously
            atomic_fetch_add_explicit(&s_tx.sent_frames, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&s_tx.sent_bytes, len, memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&s_tx.flushed, 1, memory_order_relaxed);
        }
        uint32_t next = tail + TX_REC_HDR + TX_ALIGN4(len);
        atomic_store_explicit(&s_tx.tail, next == s_tx.cap ? 0 : next, memory_order_release);
    }
}

static void tx_worker_step(void)
{
    // Sleep until a producer publishes; while blocked on NTBs poll each tick.
    bool blocked = atomic_load(&s_tx.blocked);
    ulTaskNotifyTake(pdTRUE, blocked ? 1 : portMAX_DELAY);
    if (atomic_load_explicit(&s_tx.tail, memory_order_relaxed) ==
        atomic_load_explicit(&s_tx.head, memory_order_acquire)) {
        return;
    }
    if (!atomic_exchange(&s_tx.drain_pending, true)) {
        usbd_defer_func(do_drain, NULL, false);     // may wait for TinyUSB; we hold no lock
    }
}

static void tx_worker(void *arg)
{
    (void) arg;
    for (;;) {
        tx_worker_step();
    }
}

esp_err_t tinyusb_net_tx_ring_start(size_t ring_bytes, unsigned priority)
{
    ESP_RETURN_ON_FALSE(ring_bytes >= 2 * (TX_REC_HDR + TX_FRAME_MAX), ESP_ERR_INVALID_ARG, TAG,
                        "TX ring must hold two frames");
    ring_bytes &= ~(size_t)3;
    if (s_tx.buf != NULL) {
        ESP_RETURN_ON_FALSE(s_tx.cap == ring_bytes, ESP_ERR_INVALID_STATE, TAG, "TX ring already sized differently");
        atomic_store(&s_tx.enabled, true);
        return ESP_OK;
    }
    uint8_t *buf = malloc(ring_bytes);
    ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "Failed to allocate TX ring");
    TaskHandle_t worker = NULL;
    if (xTaskCreate(tx_worker, "usb_txq", 2560, NULL, priority, &worker) != pdPASS) {
        free(buf);
        return ESP_ERR_NO_MEM;
    }
    s_tx.buf = buf;
    s_tx.cap = (uint32_t)ring_bytes;
    s_tx.worker = worker;
    atomic_store(&s_tx.enabled, true);
    return ESP_OK;
}

void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *out)
{
    *out = (tinyusb_net_tx_stats_t) {
        .ring_bytes = s_tx.cap,
        .high_water_bytes = atomic_load(&s_tx.high_water),
        .enqueued_frames = atomic_load(&s_tx.enq_frames),
        .enqueued_bytes = atomic_load(&s_tx.enq_bytes),
        .sent_frames = atomic_load(&s_tx.sent_frames),
        .sent_bytes = atomic_load(&s_tx.sent_bytes),
        .dropped_full = atomic_load(&s_tx.drop_full),
        .dropped_link_down = atomic_load(&s_tx.drop_down),
        .dropped_invalid = atomic_load(&s_tx.drop_invalid),
        .flushed_link_down = atomic_load(&s_tx.flushed),
        .ntb_blocked = atomic_load(&s_tx.blocked_events),
    };
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
    // The ring and its worker live for the life of the firmware; stop accepting frames.
    atomic_store(&s_tx.enabled, false);
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

    memcpy(dst, packet->buffer, packet->len);
    if (!packet->ring && s_net_obj.tx_buff_free_cb) {
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
