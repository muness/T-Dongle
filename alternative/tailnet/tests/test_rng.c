/* The shared DRBG: real mbedTLS CTR-DRBG, acquire/release lifetime, and eight threads drawing at once. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_rng.h"
#include "mbedtls/error.h"

static atomic_int seeds, fail_seed;
static int seed_source(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    if (atomic_load(&fail_seed)) return -1;
    atomic_fetch_add(&seeds, 1);
    for (size_t i = 0; i < len; i++) out[i] = (unsigned char)(i * 37 + 11 + atomic_load(&seeds) * 101);
    return 0;
}

#define THREADS 8
#define DRAWS 400
static unsigned char got[THREADS][DRAWS][16];
static void *drawer(void *arg) {
    int t = (int)(intptr_t)arg;
    for (int i = 0; i < DRAWS; i++) assert(ml_rng(NULL, got[t][i], 16) == 0);
    return NULL;
}

int main(void) {
    ml_rng_stats_t st;
    unsigned char b[16];
    ml_rng_set_seed_source(seed_source, NULL);

    /* No state without an acquire: a TLS handshake started after teardown fails cleanly instead of crashing. */
    assert(ml_rng(NULL, b, sizeof(b)) != 0);

    /* A seeding failure holds nothing and is retryable. */
    atomic_store(&fail_seed, 1);
    assert(ml_rng_acquire() != 0);
    ml_rng_stats(&st); assert(st.users == 0 && st.bytes_resident == 0 && st.failures == 2);   /* the no-state draw, then the failed seeding */
    atomic_store(&fail_seed, 0);

    /* Two users share one state; the last release frees it. */
    assert(ml_rng_acquire() == 0 && ml_rng_acquire() == 0);
    ml_rng_stats(&st); assert(st.users == 2 && st.seedings == 1 && st.bytes_resident > 0);
    ml_rng_release();
    assert(ml_rng(NULL, b, sizeof(b)) == 0);          /* still usable by the other membership */
    ml_rng_release();
    ml_rng_stats(&st); assert(st.users == 0 && st.bytes_resident == 0);
    assert(ml_rng(NULL, b, sizeof(b)) != 0);
    ml_rng_release();                                  /* surplus release is harmless */

    /* Concurrent draws from one DRBG: no repeated 16-byte block, bit balance sane (TSan covers the races). */
    assert(ml_rng_acquire() == 0);
    pthread_t t[THREADS];
    for (intptr_t i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, drawer, (void *)i);
    for (int i = 0; i < THREADS; i++) pthread_join(t[i], NULL);
    unsigned long ones = 0;
    for (int a = 0; a < THREADS * DRAWS; a++) {
        const unsigned char *x = got[a / DRAWS][a % DRAWS];
        for (int k = 0; k < 16; k++) for (int bit = 0; bit < 8; bit++) ones += (x[k] >> bit) & 1;
        for (int c = a + 1; c < THREADS * DRAWS; c++) assert(memcmp(x, got[c / DRAWS][c % DRAWS], 16) != 0);
    }
    double frac = (double)ones / (THREADS * DRAWS * 128.0);
    assert(frac > 0.48 && frac < 0.52);
    ml_rng_stats(&st); assert(st.bytes == (unsigned long)THREADS * DRAWS * 16 + 16 && st.failures == 3);
    unsigned resident = st.bytes_resident;
    ml_rng_release();
    printf("shared RNG: %d draws from %d threads, no repeats, bit balance %.4f, %u B resident only while in use\n",
           THREADS * DRAWS, THREADS, frac, resident);
    return 0;
}
