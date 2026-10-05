/* USB RX in-flight budget: bounded, exactly-once release, drops counted. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "usb_rx_budget.h"

static gateway_usb_rx_budget b;

static void test_cap_and_accounting(void) {
    unsigned admitted = 0;
    for (int i = 0; i < 100; i++) admitted += gateway_usb_rx_admit(&b, 1514);
    assert(admitted == GATEWAY_USB_RX_INFLIGHT_MAX);
    assert(atomic_load(&b.inflight) == GATEWAY_USB_RX_INFLIGHT_MAX);
    assert(atomic_load(&b.dropped_busy) == 100 - GATEWAY_USB_RX_INFLIGHT_MAX);
    assert(atomic_load(&b.high_water) == GATEWAY_USB_RX_INFLIGHT_MAX);
    /* lwIP frees one: exactly one more is admitted. */
    gateway_usb_rx_release(&b);
    assert(gateway_usb_rx_admit(&b, 60) && !gateway_usb_rx_admit(&b, 60));
    for (unsigned i = 0; i < GATEWAY_USB_RX_INFLIGHT_MAX; i++) gateway_usb_rx_release(&b);
    assert(atomic_load(&b.inflight) == 0);
}
static void test_invalid_lengths_take_no_slot(void) {
    unsigned before = atomic_load(&b.dropped_invalid);
    assert(!gateway_usb_rx_admit(&b, 0) && !gateway_usb_rx_admit(&b, 13) && !gateway_usb_rx_admit(&b, 1519) && !gateway_usb_rx_admit(&b, 65535));
    assert(atomic_load(&b.dropped_invalid) == before + 4 && atomic_load(&b.inflight) == 0);
    assert(gateway_usb_rx_admit(&b, 14) && gateway_usb_rx_admit(&b, 1518));
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
        if (!gateway_usb_rx_admit(&b, 100 + i % 1400)) { refused++; continue; }
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
    test_concurrent();
    puts("USB RX budget: cap, exactly-once release, invalid length and concurrent producer/consumer pass");
    return 0;
}
