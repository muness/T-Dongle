/*
 * SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

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

/**
 * @brief Transmit-ring counters (all monotonic except the sizes)
 */
typedef struct {
    uint32_t ring_bytes;         /*!< ring capacity */
    uint32_t high_water_bytes;   /*!< most bytes ever queued at once */
    uint32_t enqueued_frames;    /*!< frames accepted into the ring */
    uint32_t enqueued_bytes;
    uint32_t sent_frames;        /*!< frames handed to an NTB (each exactly once) */
    uint32_t sent_bytes;
    uint32_t dropped_full;       /*!< ring full: backpressure, frame dropped */
    uint32_t dropped_link_down;  /*!< refused because USB was not ready */
    uint32_t dropped_invalid;    /*!< length outside 14..1518 */
    uint32_t flushed_link_down;  /*!< queued frames discarded when USB went away */
    uint32_t ntb_blocked;        /*!< times a drain stopped with every NTB in flight */
} tinyusb_net_tx_stats_t;

/**
 * @brief Allocate the transmit ring and start its worker task (once, after tinyusb_net_init)
 *
 * The ring is an alternative to tinyusb_net_send_sync() for callers that hold a lock and must
 * never wait. It costs ring_bytes of heap plus the worker's stack; send_sync users pay nothing.
 *
 * @param[in] ring_bytes  capacity, at least two maximum frames
 * @param[in] priority    worker task priority
 * @return ESP_OK, ESP_ERR_NO_MEM, ESP_ERR_INVALID_ARG
 */
esp_err_t tinyusb_net_tx_ring_start(size_t ring_bytes, unsigned priority);

/**
 * @brief Queue a frame for transmission without blocking
 *
 * The frame is copied: the caller keeps ownership of `buffer` in every case and the
 * free_tx_buffer callback is NOT used. Calls must be serialized by the caller (single
 * producer). Never waits, never allocates.
 *
 * @return ESP_OK            queued; it will be handed to USB exactly once or flushed on link loss
 *         ESP_ERR_NO_MEM    ring full (dropped, counted)
 *         ESP_ERR_INVALID_STATE  ring not started or USB not ready (dropped, counted)
 *         ESP_ERR_INVALID_ARG    frame length outside 14..1518
 */
esp_err_t tinyusb_net_tx_ring_send(const void *buffer, uint16_t len);

/** @brief Snapshot the transmit-ring counters */
void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *out);

#endif // (CONFIG_TINYUSB_NET_MODE_NONE != 1)

#ifdef __cplusplus
}
#endif
