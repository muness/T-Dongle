// SPDX-License-Identifier: MIT
/* The transmit ring with a real producer thread and a real consumer thread (the lwIP core lock
 * holder and the TinyUSB task are on different cores). Built with ThreadSanitizer when the compiler
 * has it, so the acquire/release pairs on head, tail and gen are checked for data races on the
 * ring bytes, not just for the right answer. The consumer drains from both triggers.
 * Every accepted frame must be delivered once, in order, bytes intact. */
#include <pthread.h>
#include <sched.h>
#define CAP (3u * 1524u + 4u)
static _Atomic int producer_done;
static uint32_t delivered_seq, delivered_frames;
static void observe(const uint8_t *p, uint16_t n) {
    uint32_t seq;
    memcpy(&seq, p, sizeof(seq));
    assert(seq == delivered_seq);
    for (uint16_t i = 4; i < n; i++) assert(p[i] == (uint8_t)(seq * 7 + n + i));
    delivered_seq++;
    delivered_frames++;
}
static unsigned long accepted;
static void *producer(void *arg) {
    (void)arg;
    unsigned long long r = 0x9e3779b97f4a7c15ull;
    uint32_t seq = 0;
    uint8_t f[1518];
    for (int i = 0; i < 400000; i++) {
        r ^= r << 13; r ^= r >> 7; r ^= r << 17;
        uint16_t n = (r & 3) == 0 ? 14 + (r >> 8) % 60 : 14 + (r >> 8) % 1505;
        memcpy(f, &seq, 4);
        for (uint16_t k = 4; k < n; k++) f[k] = (uint8_t)(seq * 7 + n + k);
        esp_err_t e = tinyusb_net_tx_ring_send(f, n);
        if (e == ESP_OK) { seq++; accepted++; }
        else if ((r >> 40) & 1) sched_yield();
    }
    atomic_store(&producer_done, 1);
    return NULL;
}
static void *consumer(void *arg) {
    (void)arg;
    unsigned long long r = 0xdeadbeefcafef00dull;
    while (!atomic_load(&producer_done) || s_tx.head != s_tx.tail) {
        r ^= r << 13; r ^= r >> 7; r ^= r << 17;
        ntb_credit = (r & 7) == 0 ? 0 : -1;      /* touched by this thread only */
        if ((r >> 20) & 1) do_drain(NULL); else __wrap_netd_xfer_cb(0, 0x81, 0, 64);
        if (!((r >> 30) & 3)) sched_yield();
    }
    return NULL;
}
int main(void) {
    tinyusb_net_config_t cfg = {0};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_OK);
    xmit_hook = observe;
    pthread_t p, c;
    pthread_create(&c, NULL, consumer, NULL);
    pthread_create(&p, NULL, producer, NULL);
    pthread_join(p, NULL);
    pthread_join(c, NULL);
    ntb_credit = -1;
    do_drain(NULL);
    assert(s_tx.head == s_tx.tail);
    assert(delivered_frames == accepted && s_tx.sent_frames == accepted && s_tx.flushed == 0);
    assert(accepted > 10000 && s_tx.drop_full > 0);
    printf("PASS: transmit ring across two threads: %lu frames, %u dropped (ring full), in order, none lost or repeated\n",
           accepted, (unsigned)s_tx.drop_full);
}
