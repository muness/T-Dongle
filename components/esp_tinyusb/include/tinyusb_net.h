/*
 * SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "sdkconfig.h"

#if (CONFIG_TINYUSB_NET_MODE_NONE != 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief On receive callback type
 */
typedef esp_err_t (*tusb_net_rx_cb_t)(void *buffer, uint16_t len, void *ctx);

/**
 * @brief Free Tx buffer callback type
 */
typedef void (*tusb_net_free_tx_cb_t)(void *buffer, void *ctx);

/**
 * @brief On init callback type
 */
typedef void (*tusb_net_init_cb_t)(void *ctx);

/**
 * @brief ESP TinyUSB NCM driver configuration structure
 */
typedef struct {
    uint8_t mac_addr[6];                      /*!< MAC address. Must be 6 bytes long. */
    tusb_net_rx_cb_t on_recv_callback;        /*!< TinyUSB receive data callbeck */
    tusb_net_free_tx_cb_t free_tx_buffer;     /*!< User function for freeing the Tx buffer.
                                               *    - could be NULL, if user app is responsible for freeing the buffer
                                               *    - must be used in asynchronous send mode
                                               *    - is only called if the used tinyusb_net_send...() function returns ESP_OK
                                               *        - in sync mode means that the packet was accepted by TinyUSB
                                               *        - in async mode means that the packet was queued to be processed in TinyUSB task
                                               */
    tusb_net_init_cb_t on_init_callback;      /*!< TinyUSB init network callback */
    void *user_context;                       /*!< User context to be passed to any of the callback */
} tinyusb_net_config_t;

/**
 * @brief Initialize TinyUSB NET driver
 *
 * @param[in] cfg     Configuration of the driver
 * @return esp_err_t
 */
esp_err_t tinyusb_net_init(const tinyusb_net_config_t *cfg);

/**
 * @brief Deinitialize TinyUSB NET driver
 */
void tinyusb_net_deinit(void);

/**
 * @brief TinyUSB NET driver send data synchronously
 *
 * @note It is possible to use sync and async send interchangeably.
 * This function needs some synchronization primitives, so using sync mode (even once) uses more heap
 * Calls must be serialized by the caller (the gateway uses the lwIP core lock).
 *
 * @param[in] buffer            USB send data
 * @param[in] len               Send data len
 * @param[in] buff_free_arg     Pointer to be passed to the free_tx_buffer() callback
 * @param[in] timeout           Send data len
 * @return  ESP_OK on success == packet has been consumed by tusb and would be eventually freed
 *                              by free_tx_buffer() callback (if non null)
 *          ESP_ERR_TIMEOUT on timeout
 *          ESP_ERR_INVALID_STATE if tusb not initialized, ESP_ERR_NO_MEM on alloc failure
 */
esp_err_t tinyusb_net_send_sync(void *buffer, uint16_t len, void *buff_free_arg, TickType_t  timeout);

/**
 * @brief TinyUSB NET driver send data asynchronously
 *
 * @note If using asynchronous sends, you must free the buffer using free_tx_buffer() callback.
 * @note It is possible to use sync and async send interchangeably.
 * @note Async flavor of the send is useful when the USB stack runs faster than the caller,
 * since we have no control over the transmitted packets, if they get accepted or discarded.
 *
 * @param[in] buffer            USB send data
 * @param[in] len               Send data len
 * @param[in] buff_free_arg     Pointer to be passed to the free_tx_buffer() callback
 * @return  ESP_OK on success == packet has been consumed by tusb and will be freed
 *                              by free_tx_buffer() callback (if non null)
 *          ESP_ERR_INVALID_STATE if tusb not initialized
 */
esp_err_t tinyusb_net_send_async(void *buffer, uint16_t len, void *buff_free_arg);

/** One ring slab holds one maximum frame record: [len:2][gen:2][payload padded to 4] = 4 + 1520. */
#define TINYUSB_NET_TX_SLAB_BYTES   1524u
/** Elastic memory is allocated in chunks of this many slabs (one heap block of TINYUSB_NET_TX_CHUNK_BYTES). */
#define TINYUSB_NET_TX_CHUNK_SLABS  2u
#define TINYUSB_NET_TX_CHUNK_BYTES  (TINYUSB_NET_TX_CHUNK_SLABS * TINYUSB_NET_TX_SLAB_BYTES)
#define TINYUSB_NET_TX_MAX_BASE_SLABS 8u
#define TINYUSB_NET_TX_MAX_CHUNKS   12u

/**
 * @brief Transmit-ring counters (monotonic except the sizes and `chunks`/`pm_held`)
 */
typedef struct {
    uint32_t ring_bytes;         /*!< capacity now: permanent slabs plus live elastic chunks */
    uint32_t base_bytes;         /*!< permanent capacity (always allocated) */
    uint32_t max_bytes;          /*!< capacity with every elastic chunk present: the cap */
    uint32_t elastic_held_bytes; /*!< heap held by elastic chunks, including chunks still draining before they are freed */
    uint32_t chunks;             /*!< live elastic chunks (not counting ones being retired) */
    uint32_t high_water_bytes;   /*!< most record bytes ever queued at once */
    uint32_t high_water_slabs;   /*!< most slabs ever in the queue at once */
    uint32_t enqueued_frames;    /*!< frames accepted into the ring */
    uint32_t enqueued_bytes;
    uint32_t sent_frames;        /*!< frames handed to an NTB (each exactly once) */
    uint32_t sent_bytes;
    uint32_t dropped_full;       /*!< no free slab and no room in the open one: backpressure, frame dropped */
    uint32_t dropped_link_down;  /*!< refused because USB was not ready */
    uint32_t dropped_invalid;    /*!< length outside 14..1518 */
    uint32_t flushed_link_down;  /*!< queued frames discarded when USB went away */
    uint32_t ntb_blocked;        /*!< times a drain stopped with every NTB in flight */
    uint32_t xfer_events;        /*!< IN transfer completions that drained the ring (no polling) */
    uint32_t worker_stack_free;  /*!< worker stack high-water mark, bytes never used */
    uint32_t grow_events;        /*!< elastic chunks added */
    uint32_t shrink_events;      /*!< elastic chunks freed after sitting idle */
    uint32_t reclaim_events;     /*!< times chunks were retired because admission/negotiation needed the heap */
    uint32_t reclaimed_chunks;   /*!< chunks freed by those reclaims */
    uint32_t grow_denied_gate;   /*!< growth refused: admission or a negotiation is in progress */
    uint32_t grow_denied_heap;   /*!< growth refused: free heap would fall below the floor */
    uint32_t grow_denied_largest;/*!< growth refused: largest free block below the floor, before or after the allocation */
    uint32_t grow_denied_nomem;  /*!< growth refused: the allocator returned NULL */
    uint32_t grow_raced;         /*!< a chunk was allocated and discarded because a reclaim started meanwhile */
    uint32_t pm_acquired;        /*!< CPU-frequency lock acquisitions (0 unless CONFIG_PM_ENABLE) */
    uint32_t pm_released;
    uint32_t pm_held;            /*!< 1 while the lock is held */
} tinyusb_net_tx_stats_t;

/**
 * @brief Transmit ring and elastic-buffer configuration
 *
 * Capacity is `base_frames` full frames that are always present plus up to `max_chunks` elastic chunks of
 * TINYUSB_NET_TX_CHUNK_SLABS frames each, allocated on demand by the worker task (never by the producer) and
 * released when idle or when admission needs the heap.
 */
typedef struct {
    unsigned base_frames;        /*!< permanent slabs, 2..TINYUSB_NET_TX_MAX_BASE_SLABS */
    unsigned max_chunks;         /*!< elastic chunks, 0..TINYUSB_NET_TX_MAX_CHUNKS (0: fixed ring) */
    unsigned priority;           /*!< worker task priority */
    int core;                    /*!< worker core (tskNO_AFFINITY for none) */
    size_t floor_free;           /*!< free internal heap that must remain after a growth */
    size_t floor_largest;        /*!< largest free internal block that must exist before AND after a growth */
    uint32_t idle_ms;            /*!< a chunk unused this long is freed, one chunk per 500 ms pass, highest first (0: 2000) */
    bool (*gate)(void *ctx);     /*!< true while growth is forbidden and idle chunks must go (negotiation); may be NULL */
    void *gate_ctx;
    /** CPU-frequency hold while frames are queued (the gateway binds them to a tdongle_pm_burst_t). Both NULL: no
     *  hold. Called from the worker task only, strictly alternating begin/end (begin on empty to non-empty, end on
     *  non-empty to empty, link loss or teardown), with no lock of the ring held. */
    void (*pm_begin)(void *ctx);
    void (*pm_end)(void *ctx);
    void *pm_ctx;
} tinyusb_net_tx_config_t;

/**
 * @brief Allocate the permanent ring and start its worker task (once, after tinyusb_net_init)
 *
 * The ring is an alternative to tinyusb_net_send_sync() for callers that hold a lock and must
 * never wait. It costs base_frames * 1524 bytes of heap plus the worker (1,536 B stack and a 340 B TCB);
 * send_sync users pay nothing. The transmit-complete event that keeps it draining is a
 * linker wrap of netd_xfer_cb (CMakeLists.txt).
 *
 * @return ESP_OK, ESP_ERR_NO_MEM, ESP_ERR_INVALID_ARG, ESP_ERR_INVALID_STATE (started with another config)
 */
esp_err_t tinyusb_net_tx_ring_start(const tinyusb_net_tx_config_t *cfg);

/**
 * @brief Queue a frame for transmission without blocking
 *
 * The frame is copied: the caller keeps ownership of `buffer` in every case and the
 * free_tx_buffer callback is NOT used. Calls must be serialized by the caller (single
 * producer). Never waits for a task, never allocates: it takes a critical section of a few
 * instructions twice (reserve and commit a slab range) and copies outside it.
 *
 * @return ESP_OK            queued; it will be handed to USB exactly once or flushed on link loss
 *         ESP_ERR_NO_MEM    ring full (dropped, counted)
 *         ESP_ERR_INVALID_STATE  ring not started or USB not ready (dropped, counted)
 *         ESP_ERR_INVALID_ARG    frame length outside 14..1518
 */
esp_err_t tinyusb_net_tx_ring_send(const void *buffer, uint16_t len);

/**
 * @brief Give back the elastic memory now (membership admission)
 *
 * Retires every elastic chunk: idle ones are freed at once, chunks that still hold queued frames stop receiving
 * new frames and are freed when the last frame in them has been handed to USB (frames in flight are never
 * dropped or freed under the consumer). Waits up to `wait_ms` for those chunks to drain. Call it AFTER the
 * negotiation token is held (the gate then keeps the worker from growing again) and BEFORE measuring free heap.
 * Not for use from the lwIP lock holder or the TinyUSB task: it may sleep.
 *
 * @return bytes of elastic memory still held when it returns (0 when the whole elastic part is back in the heap)
 */
size_t tinyusb_net_tx_elastic_reclaim(uint32_t wait_ms);

/** @brief Wake the worker so it re-evaluates the gate (retire idle chunks). Never blocks; any task context. */
void tinyusb_net_tx_elastic_kick(void);

/** @brief The USB link went away (detach): frames queued so far are stale and are flushed. Any task context. */
void tinyusb_net_tx_ring_link_down(void);

/** @brief Snapshot the transmit-ring counters */
void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *out);

#endif // (CONFIG_TINYUSB_NET_MODE_NONE != 1)

#ifdef __cplusplus
}
#endif
