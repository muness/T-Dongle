/* Transparent bridge forwarding (tdongle_l2.h; ADR 0023). Derived from main/bridge.c; the buffering, the generation flush, the CPU-clock
 * treatment and the Wi-Fi transmit budget are the gateway's own mechanisms, not copies of them.
 *
 * Both callbacks run in tasks that must not wait (the Wi-Fi task and the TinyUSB task: the TinyUSB task serves both USB directions, and
 * usbd_defer_func() waits forever when its event queue is full), so each only copies and returns. The state they share with the worker is
 * a pair of free-running counters over a fixed slot array (single producer, single consumer, no lock) and atomics. */
#include "tdongle_l2.h"
#include "tdongle_aqm.h"
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
_Static_assert(TDONGLE_L2_SOJOURN_MS >= TDONGLE_L2_SOJOURN_MS_MIN && TDONGLE_L2_SOJOURN_MS <= TDONGLE_L2_SOJOURN_MS_MAX, "the default sojourn limit is inside its bounds");
_Static_assert(TDONGLE_L2_HOST_RESUME_DEPTH < TDONGLE_L2_HOST_QUEUE_LIMIT, "resume below the limit, or the pipe is released at the moment it is refused again");
_Static_assert(TDONGLE_L2_HOST_QUEUE_LIMIT >= 2 && TDONGLE_L2_HOST_QUEUE_LIMIT <= TDONGLE_L2_HOST_SLOTS, "the standing-queue limit lives inside the slot array");
_Static_assert((uint64_t)TDONGLE_L2_SOJOURN_MS_MAX * 1000u < TDONGLE_PM_ACTIVITY_HOLD_US,
               "a frame waiting for Wi-Fi must be inside the forwarding activity hold, or the clock drops under it");
_Static_assert(TDONGLE_L2_RETRY_US >= 100u && (uint64_t)TDONGLE_L2_RETRY_US * 4u <= (uint64_t)TDONGLE_L2_SOJOURN_MS_MIN * 1000u, "a retry period is a fraction of the sojourn limit");

#define SLOT_MASK (TDONGLE_L2_HOST_SLOTS - 1u)
#define BUMP(field) atomic_fetch_add_explicit(&l2.field, 1u, memory_order_relaxed)
#define ADD(field, v) atomic_fetch_add_explicit(&l2.field, (unsigned)(v), memory_order_relaxed)

static struct {
    esp_err_t (*wifi_tx)(void *frame, uint16_t len);
    bool (*wifi_room)(void);
    void (*rx_resume)(void);
    atomic_bool held;            /* the callback refused a datagram at the queue limit and the worker owes the USB layer a resume */
    host_slot_t *slots;
    atomic_uint t_queue_limit, t_resume, t_sojourn_ms;     /* tuning */
    atomic_bool t_codel;
    atomic_uint t_codel_target_us, t_codel_interval_ms, t_codel_gen;     /* gen moves when the AQM parameters change: the worker restarts its controller */
    unsigned codel_gen_seen;                               /* worker only */
    tdongle_codel_t codel;                                 /* worker only (stats read count racily) */
    atomic_uint busy_start_us;                             /* start of the host's current busy period (see accept_busy) */
    atomic_uint last_accept_us;                            /* callback only */
    atomic_bool hold_pending;                              /* the datagram being offered was held before (callback only) */
    atomic_uint t_host_idle_us;
    atomic_uint h2w_ecn_not_ect, h2w_ecn_capable, h2w_ecn_ce, h2w_ecn_exempt, h2w_ecn_not_ip, h2w_syn_ecn_setup, w2h_synack_ecn;
    atomic_uint h2w_codel_signals, h2w_ce_marked, h2w_codel_drop, h2w_signal_us_sum, h2w_signal_us_max;
    TaskHandle_t worker;
    esp_timer_handle_t retry_timer;
    uint8_t identity[6];
    atomic_uint head, tail;      /* free-running: the producer (TinyUSB task) advances head, the worker tail */
    atomic_uint epoch;           /* bumped by every link change; a queued frame from an older epoch is stale */
    atomic_bool linked;
    atomic_uint link_changes;
    atomic_uint w2h_frames, w2h_forwarded, w2h_invalid, w2h_own_mac, w2h_link_down, w2h_usb_not_ready, w2h_ring_full, w2h_raced;
    atomic_uint h2w_frames, h2w_queued, h2w_invalid, h2w_foreign_mac, h2w_link_down, h2w_held, h2w_resumes;
    atomic_uint h2w_sent, h2w_stale, h2w_sojourn_drop, h2w_link_down_queued, h2w_tx_failed, h2w_tx_retries, h2w_queue_high_water;
    atomic_int h2w_last_tx_error;
    atomic_uint h2w_room_waits, h2w_room_wait_us_sum, h2w_room_wait_us_max;
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
        if (tdongle_tcp_ecn_syn(frame, len) == TDONGLE_TCP_SYNACK_ECN_ACCEPT) BUMP(w2h_synack_ecn);
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
static void accept_busy(uint32_t now, const uint8_t *frame, uint16_t len);
esp_err_t tdongle_l2_host(void *buffer, uint16_t len) {
    const uint8_t *frame = buffer;
    if (!l2.slots) return ESP_ERR_INVALID_STATE;
    /* h2w_frames counts frames TAKEN (queued or dropped by name); a held offer comes back and is counted when it is finally taken. */
    if (len < 14 || len > TDONGLE_L2_FRAME_MAX) {
        BUMP(h2w_frames);
        BUMP(h2w_invalid);
        return ESP_ERR_INVALID_ARG;
    }
    if (memcmp(frame + 6, l2.identity, 6)) {
        BUMP(h2w_frames);
        BUMP(h2w_foreign_mac);
        return ESP_OK;
    }
    if (!atomic_load_explicit(&l2.linked, memory_order_acquire)) {
        BUMP(h2w_frames);
        BUMP(h2w_link_down);
        return ESP_ERR_INVALID_STATE;
    }
    /* tail first, then head: head only grows, so head - tail can never be negative whatever the worker does between the two loads. */
    unsigned tail = atomic_load_explicit(&l2.tail, memory_order_acquire);
    const unsigned head = atomic_load_explicit(&l2.head, memory_order_relaxed);
    const unsigned limit = atomic_load_explicit(&l2.t_queue_limit, memory_order_relaxed);
    if (head - tail >= limit) {
        /* Backpressure: say "not now" (the USB class driver keeps the datagram and NAKs the host), and make sure the worker will say "now". The flag is
         * published BEFORE the queue is looked at again, so a worker that drains in between either sees it (and resumes) or this look sees its room. */
        atomic_store_explicit(&l2.held, true, memory_order_seq_cst);
        tail = atomic_load_explicit(&l2.tail, memory_order_seq_cst);
        if (head - tail >= limit || !atomic_exchange_explicit(&l2.held, false, memory_order_seq_cst)) {
            BUMP(h2w_held);      /* (the second case: the worker already took the flag and owes a resume that re-offers this datagram) */
            atomic_store_explicit(&l2.hold_pending, true, memory_order_relaxed);
            return TUSB_NET_RX_HOLD;
        }
    }
    if (unicast(frame)) note_activity();
    host_slot_t *slot = &l2.slots[head & SLOT_MASK];
    slot->len = len;
    slot->epoch = (uint16_t)atomic_load_explicit(&l2.epoch, memory_order_acquire);
    slot->enq_us = now_us();
    accept_busy(slot->enq_us, frame, len);
    memcpy(slot->bytes, buffer, len);
    atomic_store_explicit(&l2.head, head + 1u, memory_order_release);
    BUMP(h2w_frames);
    BUMP(h2w_queued);
    note_max(&l2.h2w_queue_high_water, head + 1u - tail);
    xTaskNotifyGive(l2.worker);                          /* never blocks */
    return ESP_OK;
}

/* The host's busy period, the standing-queue clock CoDel is given. What matters is whether the HOST has a backlog, which the dongle can only infer from how
 * the host's datagrams arrive: a host with nothing queued leaves gaps (a window-limited or ACK-clocked sender sends in bursts and waits), a host with a
 * backlog does not (it re-arms the pipe and the next NTB is already there), and a host that is being held has a backlog by definition (it is waiting for us).
 * So the period restarts when a datagram is accepted that was not held and followed the previous accepted datagram by more than the idle gap, and
 * otherwise continues: the age is how long the host has been continuously pushing. (The first version of this clock restarted whenever the l2 queue
 * emptied; the board showed that to happen constantly, 7% of frames held, because the wire and the radio are about as fast as the sender: the queue
 * was empty most of the time while the host's own queue stood.) */
static void accept_busy(uint32_t now, const uint8_t *frame, uint16_t len) {
    const bool was_held = atomic_exchange_explicit(&l2.hold_pending, false, memory_order_relaxed);
    const uint32_t gap = now - atomic_load_explicit(&l2.last_accept_us, memory_order_relaxed);
    if (!was_held && gap > atomic_load_explicit(&l2.t_host_idle_us, memory_order_relaxed))
        atomic_store_explicit(&l2.busy_start_us, now, memory_order_relaxed);
    atomic_store_explicit(&l2.last_accept_us, now, memory_order_relaxed);
    switch (tdongle_ecn_classify(frame, len)) {
    case TDONGLE_ECN_NOT_ECT: BUMP(h2w_ecn_not_ect); break;
    case TDONGLE_ECN_CAPABLE: BUMP(h2w_ecn_capable); break;
    case TDONGLE_ECN_CE: BUMP(h2w_ecn_ce); break;
    case TDONGLE_ECN_EXEMPT: BUMP(h2w_ecn_exempt); break;
    default: BUMP(h2w_ecn_not_ip); break;
    }
    if (tdongle_tcp_ecn_syn(frame, len) == TDONGLE_TCP_SYN_ECN_SETUP) BUMP(h2w_syn_ecn_setup);
}

static void retry_fire(void *arg) { (void)arg; xTaskNotifyGive(l2.worker); }   /* esp_timer task */
/* Wait for the next chance: a retry period, or earlier if a notification arrives (a new frame: the loop re-attempts at once, harmlessly). */
static void retry_wait(void) {
    esp_timer_start_once(l2.retry_timer, TDONGLE_L2_RETRY_US);       /* already armed: ESP_ERR_INVALID_STATE, nothing to do */
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(TDONGLE_L2_SOJOURN_MS_MAX) + 1);
}

/* One queued frame, in the worker. The only place the Wi-Fi driver is called from the host side. */
static void room_done(uint32_t since) { const uint32_t dt = now_us() - since; ADD(h2w_room_wait_us_sum, dt); note_max(&l2.h2w_room_wait_us_max, dt); }
/* CoDel at the hand-to-radio. The signal is what the dongle can see of a standing queue: the larger of this frame's own time in the dongle (the
 * standard sojourn) and how long the pipe has been continuously full (the age of the host's current busy period: how long it has been pushing without a gap, see accept_busy). The first alone cannot see the host's queue: with
 * backpressure it stays at a few milliseconds while the host's FIFO sits behind our NAKs (board: 2-3 ms in the dongle, 55-83 ms ping). The second
 * grows for exactly as long as the host has a backlog to push into a full pipe, and falls back to zero the moment the host finds room without
 * waiting, which is what CoDel's "minimum over an interval" needs. Returns true when the frame was dropped. */
static bool codel_signals(host_slot_t *slot, uint32_t now, uint32_t own_sojourn) {
    const tdongle_ecn_class_t cls = tdongle_ecn_classify(slot->bytes, slot->len);
    if (cls == TDONGLE_ECN_NOT_IP || cls == TDONGLE_ECN_EXEMPT) return false;      /* ARP, DHCP, ND, SYN/FIN/RST: never signalled, not measured */
    const unsigned gen = atomic_load_explicit(&l2.t_codel_gen, memory_order_acquire);
    if (gen != l2.codel_gen_seen) {
        tdongle_codel_retune(&l2.codel, atomic_load(&l2.t_codel_target_us), atomic_load(&l2.t_codel_interval_ms) * 1000u);
        l2.codel_gen_seen = gen;
    }
    const uint32_t full = now - atomic_load_explicit(&l2.busy_start_us, memory_order_relaxed);
    const uint32_t signal = full > own_sojourn ? full : own_sojourn;
    ADD(h2w_signal_us_sum, signal);
    note_max(&l2.h2w_signal_us_max, signal);
    if (!tdongle_codel_should_signal(&l2.codel, signal, now)) return false;
    BUMP(h2w_codel_signals);
    if (cls == TDONGLE_ECN_CAPABLE) {
        tdongle_ecn_mark_ce(slot->bytes);
        BUMP(h2w_ce_marked);
        return false;
    }
    if (cls == TDONGLE_ECN_CE) return false;                                       /* already marked upstream: the signal is satisfied */
    BUMP(h2w_codel_drop);
    return true;
}

static void deliver(host_slot_t *slot) {
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
    const uint32_t limit = atomic_load_explicit(&l2.t_sojourn_ms, memory_order_relaxed) * 1000u;
    if (waited >= limit) {
        BUMP(h2w_sojourn_drop);                          /* a stalled link must not turn the queue into a delay line */
        return;
    }
    ADD(h2w_wait_us_sum, waited);
    note_max(&l2.h2w_wait_us_max, waited);
    if (atomic_load_explicit(&l2.t_codel, memory_order_relaxed) && codel_signals(slot, first, waited)) return;      /* dropped by CoDel */
    uint32_t room_since = 0;
    for (;;) {
        if (l2.wifi_room && !l2.wifi_room()) {
            /* The radio has its allowance in flight: that is the bottleneck working, not a failure. Wait for a frame to leave the antenna. The sojourn
             * limit still bounds the wait (a link that never completes anything). */
            if (!room_since) { room_since = now_us(); BUMP(h2w_room_waits); }
            if (now_us() - slot->enq_us >= limit) {
                room_done(room_since);
                BUMP(h2w_tx_failed);
                return;
            }
            BUMP(h2w_tx_retries);
            retry_wait();
            continue;
        }
        if (room_since) { room_done(room_since); room_since = 0; }
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

static void resume(void) {
    BUMP(h2w_resumes);
    if (l2.rx_resume) l2.rx_resume();
}

/* Everything queued so far; returns how many frames were handled. */
static unsigned drain(void) {
    unsigned handled = 0;
    for (;;) {
        const unsigned tail = atomic_load_explicit(&l2.tail, memory_order_relaxed);
        if (tail == atomic_load_explicit(&l2.head, memory_order_acquire)) return handled;
        deliver(&l2.slots[tail & SLOT_MASK]);
        atomic_store_explicit(&l2.tail, tail + 1u, memory_order_seq_cst);    /* the slot is the producer's again */
        handled++;
        /* The queue has room again: if the callback refused a datagram, ask the USB layer to offer it. Below the resume depth, not the limit, so the pipe
         * is refilled while the worker still has frames to send. */
        const unsigned depth_after = atomic_load_explicit(&l2.head, memory_order_acquire) - (tail + 1u);
        if (depth_after <= atomic_load_explicit(&l2.t_resume, memory_order_relaxed) && atomic_exchange_explicit(&l2.held, false, memory_order_seq_cst)) {
            resume();
        }
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
    l2.wifi_room = config->wifi_room;
    l2.rx_resume = config->rx_resume;
    atomic_store(&l2.t_queue_limit, TDONGLE_L2_HOST_QUEUE_LIMIT);
    atomic_store(&l2.t_resume, TDONGLE_L2_HOST_RESUME_DEPTH);
    atomic_store(&l2.t_sojourn_ms, TDONGLE_L2_SOJOURN_MS);
    atomic_store(&l2.t_codel, TDONGLE_L2_CODEL_DEFAULT);
    atomic_store(&l2.t_codel_target_us, TDONGLE_CODEL_TARGET_US_DEFAULT);
    atomic_store(&l2.t_codel_interval_ms, TDONGLE_CODEL_INTERVAL_MS_DEFAULT);
    atomic_store(&l2.t_host_idle_us, TDONGLE_L2_HOST_IDLE_US);
    atomic_store(&l2.busy_start_us, now_us());
    tdongle_codel_init(&l2.codel, TDONGLE_CODEL_TARGET_US_DEFAULT, TDONGLE_CODEL_INTERVAL_MS_DEFAULT * 1000u);
    l2.slots = calloc(TDONGLE_L2_HOST_SLOTS, sizeof(host_slot_t));
    if (!l2.slots) {
        return ESP_ERR_NO_MEM;
    }
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
    /* A datagram held at the queue limit belongs to the old association's backlog: the queue is stale now, so let the USB layer re-offer it. */
    atomic_store_explicit(&l2.busy_start_us, now_us(), memory_order_relaxed);   /* a new association: the old backlog means nothing */
    if (atomic_exchange_explicit(&l2.held, false, memory_order_seq_cst)) resume();
    tud_network_link_state(0, connected);
}

esp_err_t tdongle_l2_set_tuning(const tdongle_l2_tuning_t *t) {
    if (!l2.slots) return ESP_ERR_INVALID_STATE;
    if (!t || t->queue_limit < 1 || t->queue_limit > TDONGLE_L2_HOST_SLOTS || t->resume_depth >= t->queue_limit ||
        t->sojourn_ms < TDONGLE_L2_SOJOURN_MS_MIN || t->sojourn_ms > TDONGLE_L2_SOJOURN_MS_MAX ||
        t->codel_target_us < TDONGLE_L2_CODEL_TARGET_US_MIN || t->codel_target_us > TDONGLE_L2_CODEL_TARGET_US_MAX ||
        t->codel_interval_ms < TDONGLE_L2_CODEL_INTERVAL_MS_MIN || t->codel_interval_ms > TDONGLE_L2_CODEL_INTERVAL_MS_MAX ||
        t->host_idle_us < TDONGLE_L2_HOST_IDLE_US_MIN || t->host_idle_us > TDONGLE_L2_HOST_IDLE_US_MAX)
        return ESP_ERR_INVALID_ARG;
    atomic_store(&l2.t_queue_limit, t->queue_limit);
    atomic_store(&l2.t_resume, t->resume_depth);
    atomic_store(&l2.t_sojourn_ms, t->sojourn_ms);
    const bool changed = atomic_load(&l2.t_codel_target_us) != t->codel_target_us || atomic_load(&l2.t_codel_interval_ms) != t->codel_interval_ms ||
                         atomic_load(&l2.t_codel) != t->codel;
    atomic_store(&l2.t_codel_target_us, t->codel_target_us);
    atomic_store(&l2.t_codel_interval_ms, t->codel_interval_ms);
    atomic_store(&l2.t_codel, t->codel);
    atomic_store(&l2.t_host_idle_us, t->host_idle_us);
    if (changed) atomic_fetch_add_explicit(&l2.t_codel_gen, 1u, memory_order_release);      /* a controller built under other numbers (or while off) means nothing */
    /* A lower limit may leave the queue above it: it simply drains; a held datagram is released by the next drain as before. */
    return ESP_OK;
}
void tdongle_l2_get_tuning(tdongle_l2_tuning_t *out) {
    *out = (tdongle_l2_tuning_t){.queue_limit = atomic_load(&l2.t_queue_limit), .resume_depth = atomic_load(&l2.t_resume),
                                 .sojourn_ms = atomic_load(&l2.t_sojourn_ms), .codel = atomic_load(&l2.t_codel),
                                 .codel_target_us = atomic_load(&l2.t_codel_target_us), .codel_interval_ms = atomic_load(&l2.t_codel_interval_ms), .host_idle_us = atomic_load(&l2.t_host_idle_us)};
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
        .h2w_foreign_mac = LOAD(h2w_foreign_mac), .h2w_link_down = LOAD(h2w_link_down), .h2w_held = LOAD(h2w_held), .h2w_resumes = LOAD(h2w_resumes), .h2w_codel_signals = LOAD(h2w_codel_signals), .h2w_ce_marked = LOAD(h2w_ce_marked),
        .h2w_codel_drop = LOAD(h2w_codel_drop), .h2w_signal_us_sum = LOAD(h2w_signal_us_sum), .h2w_signal_us_max = LOAD(h2w_signal_us_max),
        .h2w_codel_count = l2.codel.dropping ? l2.codel.count : 0,
        .h2w_ecn_not_ect = LOAD(h2w_ecn_not_ect), .h2w_ecn_capable = LOAD(h2w_ecn_capable), .h2w_ecn_ce = LOAD(h2w_ecn_ce), .h2w_ecn_exempt = LOAD(h2w_ecn_exempt),
        .h2w_ecn_not_ip = LOAD(h2w_ecn_not_ip), .h2w_syn_ecn_setup = LOAD(h2w_syn_ecn_setup), .w2h_synack_ecn = LOAD(w2h_synack_ecn), .h2w_room_waits = LOAD(h2w_room_waits),
        .h2w_room_wait_us_sum = LOAD(h2w_room_wait_us_sum), .h2w_room_wait_us_max = LOAD(h2w_room_wait_us_max),
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
