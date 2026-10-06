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
/* Host -> Wi-Fi hand-off queue, and USB backpressure. The queue's job is to decouple the TinyUSB task from the Wi-Fi driver, not to buffer:
 * everything that stands in it is latency for every packet behind it. The first two board A/Bs of ADR 0023 measured it: 16 slots, then 6, still
 * gave ping under TCP upload of 52 and 59 ms against 18-24 ms on the original, which blocked in the USB OUT callback so that USB NAKed and the
 * queue stayed on the host (macOS schedules interface queues per flow, so a ping bypasses the bulk queue there). Dropping at a limit only turns
 * a queue into loss. So the limit is not a drop point but a flow-control point:
 *  - TDONGLE_L2_HOST_QUEUE_LIMIT frames (3) may stand here. At the limit the callback returns TUSB_NET_RX_HOLD: the NCM class driver keeps the
 *    datagram, stops re-arming the OUT endpoint when its CFG_TUD_NCM_OUT_NTB_N receive buffers fill, and the host is NAKed. The TinyUSB task
 *    never blocks and nothing is dropped;
 *  - when the worker has drained the queue to TDONGLE_L2_HOST_RESUME_DEPTH (1) it asks for the held datagram again (rx_resume ->
 *    tinyusb_net_rx_resume()), so the pipe keeps a frame of runway;
 *  - physical slots (a power of two: the counters run free), 1,524 B each; the limit is a tunable (below) so a board sweep can pick it;
 *  - TDONGLE_L2_SOJOURN_MS remains as a safety net for a stalled Wi-Fi link (CoDel's target reduced to its essence), not as the steady-state
 *    mechanism: with backpressure it should read 0. */
#define TDONGLE_L2_HOST_SLOTS 8u                /* physical slots of the bulk queue: the tunable limit below may use up to all of them */
#define TDONGLE_L2_HOST_QUEUE_LIMIT 3u          /* default standing limit (tdongle_l2_tuning_t.queue_limit) */
#define TDONGLE_L2_HOST_RESUME_DEPTH 1u         /* default */
#define TDONGLE_L2_SLOT_BYTES 1524u
#define TDONGLE_L2_SOJOURN_MS 100u              /* default sojourn limit */
#define TDONGLE_L2_SOJOURN_MS_MIN 5u
#define TDONGLE_L2_CODEL_TARGET_US_MIN 500u
#define TDONGLE_L2_CODEL_TARGET_US_MAX 50000u
#define TDONGLE_L2_CODEL_INTERVAL_MS_MIN 20u
#define TDONGLE_L2_CODEL_INTERVAL_MS_MAX 1000u
#define TDONGLE_L2_CODEL_DEFAULT true
#define TDONGLE_L2_SOJOURN_MS_MAX 190u          /* below TDONGLE_PM_ACTIVITY_HOLD_US (asserted in l2.c) */
/* A refusal for buffers (the budget's, or the driver's pool) clears as frames leave the antenna, about every 0.3 to 1 ms at the Wi-Fi rate, so the
 * worker retries on a 500 us timer (esp_timer), not on the RTOS tick: at CONFIG_FREERTOS_HZ=100 a tick sleep is 10 ms, long enough for the whole
 * 16-buffer pool to drain and the radio to idle (measured: 590 retries, 101 frames lost, upload below what the link carries). */
#define TDONGLE_L2_RETRY_US 500u


typedef struct {
    /* Required. Sends one frame on the STA interface through the Wi-Fi TX budget (wifi_pins.inc): ESP_OK when the driver took it,
     * ESP_ERR_NO_MEM when it was refused for buffers (retried every TDONGLE_L2_RETRY_US until the frame's sojourn limit), anything else is final. Worker task only. */
    esp_err_t (*wifi_tx)(void *frame, uint16_t len);
    /* Optional. True when the radio can take another frame now (wifi_pins_tx_room). While it is false the worker waits instead of calling wifi_tx and
     * being refused: the bridge keeps few frames in the driver (GATEWAY_BRIDGE_WIFI_TX_INFLIGHT), and a full allowance is the normal state of a link
     * that is the bottleneck, not an error. */
    bool (*wifi_room)(void);
    /* Required with a host that can be held: ask the USB layer to offer the held datagram again (tinyusb_net_rx_resume). Called by the worker. */
    void (*rx_resume)(void);
    unsigned task_priority;      /* the host -> Wi-Fi worker: GATEWAY_TASK_BRIDGE_PRIO */
    int task_core;
    uint32_t task_stack;         /* bytes */
} tdongle_l2_config_t;

/* Run-time tuning (diagnostics-build serial command `bridgetune`; not persisted): the compile-time constants above are the defaults. Bounds are checked
 * as a whole: a rejected set changes nothing. */
typedef struct {
    uint32_t queue_limit;        /* 1..TDONGLE_L2_HOST_SLOTS: frames that may stand in the bulk queue before the host is held */
    uint32_t resume_depth;       /* 0..queue_limit-1: drain to this depth before the held datagram is offered again */
    uint32_t sojourn_ms;         /* TDONGLE_L2_SOJOURN_MS_MIN..MAX: age at which a frame is dropped */
    /* CoDel/ECN on the ingress (tdongle_aqm.h, ADR 0023 amendments 4-6): ON by default at RFC 8289's 5 ms target and 100 ms interval (the board's third sweep:
 * load ping halved, download better, upload about 15% lower; looser targets bought nothing). The same defaults in the release and diagnostics images. */
    bool codel;
    uint32_t codel_target_us;    /* TDONGLE_L2_CODEL_TARGET_US_MIN..MAX */
    uint32_t codel_interval_ms;  /* TDONGLE_L2_CODEL_INTERVAL_MS_MIN..MAX */
} tdongle_l2_tuning_t;
esp_err_t tdongle_l2_set_tuning(const tdongle_l2_tuning_t *tuning);
void tdongle_l2_get_tuning(tdongle_l2_tuning_t *out);

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
    /* host -> Wi-Fi. h2w_frames = queued + invalid + foreign_mac + link_down, always. */
    uint32_t h2w_frames;         /* frames the TinyUSB receive callback took (a held offer is not a frame until it is taken) */
    uint32_t h2w_queued;
    uint32_t h2w_invalid;
    uint32_t h2w_foreign_mac;    /* source is not the STA MAC: the bridge speaks for the STA address only; filtered by design */
    uint32_t h2w_link_down;      /* Wi-Fi not connected when the frame arrived */
    uint32_t h2w_held;           /* offers refused with TUSB_NET_RX_HOLD at the queue limit: USB backpressure, nothing dropped */
    uint32_t h2w_resumes;        /* times the worker asked for held datagrams again */
    /* CoDel (only when enabled). h2w_queued = sent + stale + sojourn_drop + link_down_queued + tx_failed + codel_drop + depth; a marked frame is sent. */
    uint32_t h2w_codel_signals;  /* eligible frames CoDel signalled (marked, already CE, or dropped) */
    uint32_t h2w_ce_marked;      /* ECT frames that left with CE set */
    uint32_t h2w_codel_drop;     /* non-ECT frames dropped by CoDel */
    uint32_t h2w_signal_us_sum, h2w_signal_us_max;   /* the signal CoDel sees per eligible frame: max(its own time in the dongle, time the pipe has been continuously full) */
    uint32_t h2w_codel_count;    /* CoDel's signal count in the current dropping state (0 outside it) */
    /* ECN as it crosses the bridge, always counted (whether or not CoDel is on): is ECN negotiated, and what do the host's frames carry? */
    uint32_t h2w_ecn_not_ect, h2w_ecn_capable, h2w_ecn_ce, h2w_ecn_exempt, h2w_ecn_not_ip;   /* host -> Wi-Fi, per frame taken */
    uint32_t h2w_syn_ecn_setup;  /* SYN+ECE+CWR from the host: it asked for ECN */
    uint32_t w2h_synack_ecn;     /* SYN+ACK+ECE to the host: the server accepted */
    uint32_t h2w_room_waits, h2w_room_wait_us_sum, h2w_room_wait_us_max;   /* frames that had to wait for the radio's allowance, and for how long: the radio's dwell */
    /* The worker. h2w_queued = sent + stale + sojourn_drop + link_down_queued + tx_failed + codel_drop + queue depth, always (at rest). */
    uint32_t h2w_sent;           /* the Wi-Fi driver took the frame */
    uint32_t h2w_stale;          /* queued before the link changed: dropped without sending */
    uint32_t h2w_sojourn_drop;   /* older than TDONGLE_L2_SOJOURN_MS when the worker reached it: dropped without sending */
    uint32_t h2w_link_down_queued;   /* the link went down while the frame was queued */
    uint32_t h2w_tx_failed;      /* refused until the sojourn limit, or a final error */
    uint32_t h2w_tx_retries;
    int32_t h2w_last_tx_error;   /* esp_err_t of the last refusal, 0 if none */
    uint32_t h2w_queue_depth;    /* now, including the frame being sent */
    uint32_t h2w_queue_high_water;
    uint32_t w2h_raced;          /* a frame was in the RX callback while the link changed: the ring was flushed again so it cannot outlive the change */
    uint32_t worker_stack_free;  /* bytes never used */
    /* Where the time goes (microseconds; sums wrap at 71 minutes, take differences). Added to find the latency of the first board run. */
    uint32_t pm_notes, pm_note_us_sum, pm_note_us_max;   /* tdongle_pm_note_activity(): the first note after idle raises the clock; its cost is here */
    uint32_t h2w_wait_us_sum, h2w_wait_us_max;           /* callback to the worker's first attempt (queueing), per frame that was attempted */
    uint32_t h2w_tx_us_sum, h2w_tx_us_max;               /* the Wi-Fi transmit call itself, per call that succeeded */
} tdongle_l2_stats_t;

/* Once, after tinyusb_net_tx_ring_start() (the ring is the Wi-Fi -> host path) and before Wi-Fi starts. */
esp_err_t tdongle_l2_start(const uint8_t mac[6], const tdongle_l2_config_t *config);
/* The STA associated or lost its association. Event task. Frames queued toward the host and toward Wi-Fi from the previous
 * association are discarded (generation), the host sees the carrier change. */
void tdongle_l2_link(bool connected);
/* TinyUSB receive callback: never blocks. ESP_OK: queued, or filtered by design (counted). TUSB_NET_RX_HOLD: the queue is at its limit; the datagram
 * stays in the USB class driver and is offered again after rx_resume (counted as h2w_held, not as a frame). Any other error: dropped, counted. */
esp_err_t tdongle_l2_host(void *buffer, uint16_t len);
void tdongle_l2_stats(tdongle_l2_stats_t *out);
