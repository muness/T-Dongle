/* Bound on USB-to-lwIP frames in flight. usb_rx copies each frame out of the NTB (the NTB is
 * reused as soon as usb_rx returns) and hands the copy to lwIP, which frees it through
 * usb_free_rx when the packet is done, possibly many milliseconds later while the core lock is
 * held elsewhere. Without a bound the copies queue behind the tcpip mailbox (32 entries, 1.5 KB
 * each) and the router queue. Past the cap the frame is dropped and counted: TCP sees ordinary
 * loss and slows down, and the heap keeps its headroom. */
#pragma once
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define GATEWAY_USB_RX_FRAME_MIN 14u
#define GATEWAY_USB_RX_FRAME_MAX 1518u   /* 1500 MTU + Ethernet header + VLAN tag */
/* Frames the router can hold at once (ROUTE_QUEUE_DEPTH 16 + ROUTE_HOLD_SLOTS 2: the router queues the lwIP pbuf that wraps the
 * usb_rx copy, so each queued packet keeps its slot until usb_routes frees it) plus 4 for everything else on the interface (DHCP,
 * DNS, ARP, setup HTTP): a flooded router can never take every slot and starve recovery traffic. gateway_main.c asserts it.
 * Heap: the router's own byte budget (rt_queue_budget: free heap above the 16,384 B recovery reserve, at most 16 KB, floor two
 * packets) already bounds the bytes it holds, so the slots add at most the 4 spare frames (6 KB) beyond it, and only in a flood. */
#define GATEWAY_USB_RX_INFLIGHT_MAX 22u

typedef struct {
    atomic_uint inflight;
    atomic_uint dropped_busy;     /* in-flight cap reached */
    atomic_uint dropped_nomem;    /* malloc failed */
    atomic_uint dropped_invalid;  /* length outside 14..1518 */
    atomic_uint high_water;
} gateway_usb_rx_budget;

/* TinyUSB task. True: the caller now owns one slot and must release it exactly once. */
static inline bool gateway_usb_rx_admit(gateway_usb_rx_budget *b, unsigned len) {
    if (len < GATEWAY_USB_RX_FRAME_MIN || len > GATEWAY_USB_RX_FRAME_MAX) {
        atomic_fetch_add_explicit(&b->dropped_invalid, 1, memory_order_relaxed);
        return false;
    }
    unsigned now = atomic_fetch_add_explicit(&b->inflight, 1, memory_order_acq_rel) + 1;
    if (now > GATEWAY_USB_RX_INFLIGHT_MAX) {
        atomic_fetch_sub_explicit(&b->inflight, 1, memory_order_acq_rel);
        atomic_fetch_add_explicit(&b->dropped_busy, 1, memory_order_relaxed);
        return false;
    }
    if (now > atomic_load_explicit(&b->high_water, memory_order_relaxed))
        atomic_store_explicit(&b->high_water, now, memory_order_relaxed);
    return true;
}
/* Any context: the copy was freed (or never handed to lwIP). */
static inline void gateway_usb_rx_release(gateway_usb_rx_budget *b) {
    atomic_fetch_sub_explicit(&b->inflight, 1, memory_order_acq_rel);
}
