/* USB RX in-flight budget: bounded, exactly-once release, drops counted. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "usb_rx_budget.h"

#define BIG (1u << 20)
static gateway_usb_rx_budget b;

static void test_cap_and_accounting(void) {
    unsigned admitted = 0;
    for (int i = 0; i < 100; i++) admitted += gateway_usb_rx_admit(&b, 1514, BIG);
    assert(admitted == GATEWAY_USB_RX_INFLIGHT_MAX);
    assert(atomic_load(&b.inflight) == GATEWAY_USB_RX_INFLIGHT_MAX);
    assert(atomic_load(&b.dropped_busy) == 100 - GATEWAY_USB_RX_INFLIGHT_MAX);
    assert(atomic_load(&b.high_water) == GATEWAY_USB_RX_INFLIGHT_MAX);
    /* lwIP frees one: exactly one more is admitted. */
    gateway_usb_rx_release(&b);
    assert(gateway_usb_rx_admit(&b, 60, BIG) && !gateway_usb_rx_admit(&b, 60, BIG));
    for (unsigned i = 0; i < GATEWAY_USB_RX_INFLIGHT_MAX; i++) gateway_usb_rx_release(&b);
    assert(atomic_load(&b.inflight) == 0);
}

/* ADR 0022: past the exempt frames a frame is refused, counted, when it would leave less than the elastic floor; the exempt ones
 * (control traffic) always pass, whatever the heap. */
static void test_heap_floor(void) {
    gateway_usb_rx_budget h = {0};
    const unsigned len = 1514, cost = len + 16;
    const size_t at = (size_t)ML_HB_FLOOR + cost;
    /* Exactly at the floor + cost: admitted; one byte less: refused. Fill the two exempt slots first. */
    for (unsigned i = 0; i < GATEWAY_USB_RX_HEAP_EXEMPT; i++) assert(gateway_usb_rx_admit(&h, len, 0));          /* heap 0: still admitted */
    assert(atomic_load(&h.dropped_heap) == 0);
    assert(!gateway_usb_rx_admit(&h, len, at - 1) && atomic_load(&h.dropped_heap) == 1);
    assert(atomic_load(&h.inflight) == GATEWAY_USB_RX_HEAP_EXEMPT);                                              /* the refused frame took no slot */
    assert(gateway_usb_rx_admit(&h, len, at) && atomic_load(&h.inflight) == GATEWAY_USB_RX_HEAP_EXEMPT + 1);
    /* A small frame needs less. */
    assert(gateway_usb_rx_admit(&h, 60, (size_t)ML_HB_FLOOR + 60 + 16));
    assert(!gateway_usb_rx_admit(&h, 60, (size_t)ML_HB_FLOOR + 60 + 15) && atomic_load(&h.dropped_heap) == 2);
    /* The exemption is about frames in flight, not a free pass: release them all and the exemption is back. */
    while (atomic_load(&h.inflight)) gateway_usb_rx_release(&h);
    assert(gateway_usb_rx_admit(&h, len, 0) && gateway_usb_rx_admit(&h, len, 0) && !gateway_usb_rx_admit(&h, len, 0));
    /* Worst case below the floor from exempt frames: two frames. */
    assert((size_t)GATEWAY_USB_RX_HEAP_EXEMPT * cost <= ML_HB_SLACK_BYTES);
    /* Priority of refusals: the in-flight cap is checked first and counted as busy, not heap. */
    gateway_usb_rx_budget c = {0};
    for (unsigned i = 0; i < GATEWAY_USB_RX_INFLIGHT_MAX; i++) assert(gateway_usb_rx_admit(&c, 100, BIG));
    assert(!gateway_usb_rx_admit(&c, 100, 0) && atomic_load(&c.dropped_busy) == 1 && atomic_load(&c.dropped_heap) == 0);
}
static void test_invalid_lengths_take_no_slot(void) {
    unsigned before = atomic_load(&b.dropped_invalid);
    assert(!gateway_usb_rx_admit(&b, 0, BIG) && !gateway_usb_rx_admit(&b, 13, BIG) && !gateway_usb_rx_admit(&b, 1519, BIG) && !gateway_usb_rx_admit(&b, 65535, BIG));
    assert(atomic_load(&b.dropped_invalid) == before + 4 && atomic_load(&b.inflight) == 0);
    assert(gateway_usb_rx_admit(&b, 14, BIG) && gateway_usb_rx_admit(&b, 1518, BIG));
    gateway_usb_rx_release(&b); gateway_usb_rx_release(&b);
}

/* Producer (TinyUSB task) admits and "hands to lwIP"; a consumer (tcpip) frees later, out of order.
 * The in-flight count must never exceed the cap and every admitted frame is freed exactly once. */
#define FRAMES 400000
static void *slots[GATEWAY_USB_RX_INFLIGHT_MAX + 1];
static atomic_uint head, tail, peak;
static atomic_bool done;
static unsigned long freed;
static void *consumer(void *arg) {
    (void)arg;
    for (;;) {
        unsigned t = atomic_load(&tail), h = atomic_load(&head);
        if (t == h) { if (atomic_load(&done) && atomic_load(&head) == t) return NULL; continue; }
        free(slots[t % (GATEWAY_USB_RX_INFLIGHT_MAX + 1)]);   /* ASan: double free or leak shows here */
        freed++;
        atomic_store(&tail, t + 1);
        gateway_usb_rx_release(&b);
    }
}
static void test_concurrent(void) {
    pthread_t c;
    pthread_create(&c, NULL, consumer, NULL);
    unsigned long admitted = 0, refused = 0;
    for (int i = 0; i < FRAMES; i++) {
        if (!gateway_usb_rx_admit(&b, 100 + i % 1400, BIG)) { refused++; continue; }
        unsigned live = atomic_load(&b.inflight);
        assert(live <= GATEWAY_USB_RX_INFLIGHT_MAX);
        void *copy = malloc(100);
        assert(copy);
        unsigned h = atomic_load(&head);
        slots[h % (GATEWAY_USB_RX_INFLIGHT_MAX + 1)] = copy;
        atomic_store(&head, h + 1);
        admitted++;
    }
    atomic_store(&done, true);
    pthread_join(c, NULL);
    assert(freed == admitted && atomic_load(&b.inflight) == 0);
    assert(atomic_load(&b.dropped_busy) >= refused && atomic_load(&b.high_water) <= GATEWAY_USB_RX_INFLIGHT_MAX);
    printf("concurrent: %lu admitted and freed once, %lu refused at the cap\n", admitted, refused);
}
int main(void) {
    test_cap_and_accounting();
    test_invalid_lengths_take_no_slot();
    test_heap_floor();
    test_concurrent();
    puts("USB RX budget: cap, exactly-once release, invalid length and concurrent producer/consumer pass");
    return 0;
}
