/* The inbound counters are written by several tasks (net_io on core 0, the DERP loop, wg_mgr on core 1, the tcpip task with
 * zero-copy WG) and read by the console: relaxed atomics, no lost increments, no torn reads, a max gauge that only grows.
 * Run under ThreadSanitizer (and ASan/UBSan).
 *
 *   cc -std=gnu11 -O1 -g -fsanitize=thread -pthread -I components/microlink/include \
 *      -I components/microlink/components/wireguard_lwip/src tests/test_rx_stats_threads.c -o build-host/test_rx_stats_threads */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include "ml_rx_stats.h"
#include "wireguard_stats.h"

ml_rx_stats_t ml_rx_stats;
wireguard_rx_stats_t wireguard_rx_stats;

#define THREADS 4
#define ROUNDS 50000
static atomic_int go;
static void *writer(void *arg) {
    unsigned id = (unsigned)(uintptr_t)arg;
    while (!atomic_load(&go)) {}
    for (unsigned i = 0; i < ROUNDS; i++) {
        ML_RX_STAT(udp_rx);
        if ((i + id) % 3 == 0) ML_RX_STAT(q_wg_full);
        ml_rx_stat_burst((i * 7 + id) % 17);
        WG_RX_STAT(rx_data);
        if (i & 1) WG_RX_STAT(rx_delivered); else WG_RX_STAT(rx_replay_dup);
    }
    return NULL;
}
static void *reader(void *arg) {
    (void)arg;
    uint32_t last_max = 0, last_rx = 0;
    while (atomic_load(&go) < 2) {
        uint32_t m = atomic_load(&ml_rx_stats.drain_burst_max), rx = ml_rx_stat_get(ML_RXS_udp_rx);
        assert(m >= last_max && rx >= last_rx && m <= 16 && rx <= THREADS * ROUNDS);   /* monotone, bounded: never torn */
        last_max = m; last_rx = rx;
        /* Cross-counter identities are NOT asserted here: relaxed atomics give each counter its own order, so a reader may see a
         * terminal before the rx_data increment that preceded it. They hold at quiescence, which main() checks. */
    }
    return NULL;
}
int main(void) {
    pthread_t w[THREADS], r;
    pthread_create(&r, NULL, reader, NULL);
    for (uintptr_t i = 0; i < THREADS; i++) pthread_create(&w[i], NULL, writer, (void *)i);
    atomic_store(&go, 1);
    for (int i = 0; i < THREADS; i++) pthread_join(w[i], NULL);
    atomic_store(&go, 2);
    pthread_join(r, NULL);
    assert(ml_rx_stat_get(ML_RXS_udp_rx) == THREADS * ROUNDS);
    assert(wireguard_rx_stat_get(WG_RXS_rx_data) == THREADS * ROUNDS);
    assert(wireguard_rx_stat_get(WG_RXS_rx_delivered) == THREADS * ROUNDS / 2 && wireguard_rx_stat_get(WG_RXS_rx_replay_dup) == THREADS * ROUNDS / 2);
    assert(atomic_load(&ml_rx_stats.drain_burst_max) == 16);
    unsigned q = 0; for (unsigned id = 0; id < THREADS; id++) for (unsigned i = 0; i < ROUNDS; i++) q += (i + id) % 3 == 0;
    assert(ml_rx_stat_get(ML_RXS_q_wg_full) == q);
    ml_rx_stats_reset(); wireguard_rx_stats_reset();
    assert(ml_rx_stat_get(ML_RXS_udp_rx) == 0 && wireguard_rx_stat_get(WG_RXS_rx_data) == 0 && atomic_load(&ml_rx_stats.drain_burst_max) == 0);
    for (unsigned i = 0; i < ML_RXS_COUNT; i++) assert(ml_rx_stat_name(i)[0]);
    for (unsigned i = 0; i < WG_RXS_COUNT; i++) assert(wireguard_rx_stat_name(i)[0]);
    assert(!ml_rx_stat_name(ML_RXS_COUNT)[0] && !wireguard_rx_stat_name(WG_RXS_COUNT)[0] && !ml_rx_stat_get(ML_RXS_COUNT));
    printf("rx stats threads ok\n");
    return 0;
}
