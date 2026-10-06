#pragma once
/* Transparent bridge forwarding (wifi_bridge mode of the unified image). Design, numbers and the board plan:
 * alternative/tailnet/docs/adr/0023-bridge-mode-data-plane.md.
 *
 *   Wi-Fi -> host   the Wi-Fi RX callback copies the frame into the USB transmit ring of tinyusb_net.c (the mechanism the tailnet gateway
 *                   uses: exactly-once hand-over, link-generation flush, IN-completion drain, elastic capacity bounded by the heap floor)
 *                   and frees the driver buffer at once. It never waits.
 *   host -> Wi-Fi   the TinyUSB receive callback copies the frame into a small fixed queue and returns; one worker task sends it with
 *                   the injected, budgeted Wi-Fi transmit (wifi_pins.inc). Neither callback waits, allocates or calls into the Wi-Fi driver
 *                   from the TinyUSB task. A full queue drops the frame (counted): TCP treats it as the loss it is.
 *
 * Every frame that enters either callback is counted exactly once as forwarded or as one named drop (tdongle_l2_stats_t), so a missing
 * frame is always attributable. */
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

/* The largest Ethernet frame the bridge carries (1,500 byte MTU + header; no VLAN tag): anything else is dropped and counted. */
#define TDONGLE_L2_FRAME_MAX 1514u
/* Host -> Wi-Fi hand-off queue: a power of two (free-running counters), each slot one maximum frame plus its header. 16 slots are 24 KB
 * and 22.5 full frames of USB OUT time, enough to cover TDONGLE_L2_TX_RETRY_MS of a stalled Wi-Fi transmit at the bus limit (875 B/ms:
 * 17.5 KB) with a margin. */
#define TDONGLE_L2_HOST_SLOTS 16u
#define TDONGLE_L2_SLOT_BYTES 1520u
/* How long the worker keeps retrying one frame that the Wi-Fi transmit refused for lack of buffers (ESP_ERR_NO_MEM, the budget's
 * refusal or the driver's own pool), in ticks of the RTOS tick (CONFIG_FREERTOS_HZ is 100: the retry period is one 10 ms tick). Past it
 * the frame is dropped and counted. It is below TDONGLE_PM_ACTIVITY_HOLD_US (asserted in l2.c), so the CPU never drops its clock under
 * a frame that is waiting. */
#define TDONGLE_L2_TX_RETRY_MS 20u

typedef struct {
    /* Required. Sends one frame on the STA interface through the Wi-Fi TX budget (wifi_pins.inc): ESP_OK when the driver took it,
     * ESP_ERR_NO_MEM when it was refused for buffers (retried for TDONGLE_L2_TX_RETRY_MS), anything else is final. Worker task only. */
    esp_err_t (*wifi_tx)(void *frame, uint16_t len);
    unsigned task_priority;      /* the host -> Wi-Fi worker: GATEWAY_TASK_BRIDGE_PRIO */
    int task_core;
    uint32_t task_stack;         /* bytes */
} tdongle_l2_config_t;

typedef struct {
    bool linked;
    uint32_t link_changes;
    /* Wi-Fi -> host. wifi_rx = forwarded + invalid + own_mac + link_down + usb_not_ready + ring_full, always. */
    uint32_t w2h_frames;         /* frames the driver handed to the RX callback */
    uint32_t w2h_forwarded;      /* accepted into the USB transmit ring (its own counters say what USB then did) */
    uint32_t w2h_invalid;        /* shorter than an Ethernet header or longer than TDONGLE_L2_FRAME_MAX */
    uint32_t w2h_own_mac;        /* source is the bridge's own (STA) MAC: a frame the host sent that came back; filtered by design */
    uint32_t w2h_link_down;      /* the Wi-Fi link was marked down: the callback was racing the disconnect */
    uint32_t w2h_usb_not_ready;  /* USB not configured (cable out, host asleep) or the ring not started */
    uint32_t w2h_ring_full;      /* no room in the USB transmit ring, at its elastic cap: backpressure drop */
    /* host -> Wi-Fi. h2w_frames = queued + invalid + foreign_mac + link_down + queue_full, always. */
    uint32_t h2w_frames;         /* frames the TinyUSB receive callback handed over */
    uint32_t h2w_queued;
    uint32_t h2w_invalid;
    uint32_t h2w_foreign_mac;    /* source is not the STA MAC: the bridge speaks for the STA address only; filtered by design */
    uint32_t h2w_link_down;      /* Wi-Fi not connected when the frame arrived */
    uint32_t h2w_queue_full;     /* the hand-off queue is full: backpressure drop */
    /* The worker. h2w_queued = sent + stale + link_down_queued + tx_failed + queue depth, always (at rest). */
    uint32_t h2w_sent;           /* the Wi-Fi driver took the frame */
    uint32_t h2w_stale;          /* queued before the link changed: dropped without sending */
    uint32_t h2w_link_down_queued;   /* the link went down while the frame was queued */
    uint32_t h2w_tx_failed;      /* refused past the retry window, or a final error */
    uint32_t h2w_tx_retries;
    int32_t h2w_last_tx_error;   /* esp_err_t of the last refusal, 0 if none */
    uint32_t h2w_queue_depth;    /* now, including the frame being sent */
    uint32_t h2w_queue_high_water;
    uint32_t worker_stack_free;  /* bytes never used */
} tdongle_l2_stats_t;

/* Once, after tinyusb_net_tx_ring_start() (the ring is the Wi-Fi -> host path) and before Wi-Fi starts. */
esp_err_t tdongle_l2_start(const uint8_t mac[6], const tdongle_l2_config_t *config);
/* The STA associated or lost its association. Event task. Frames queued toward the host and toward Wi-Fi from the previous
 * association are discarded (generation), the host sees the carrier change. */
void tdongle_l2_link(bool connected);
/* TinyUSB receive callback: never blocks. ESP_OK: queued, or filtered by design (counted). An error: dropped, counted. */
esp_err_t tdongle_l2_host(void *buffer, uint16_t len);
void tdongle_l2_stats(tdongle_l2_stats_t *out);
