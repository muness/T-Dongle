#include "ml_rng.h"
#include "ml_port.h"
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"

#ifdef ESP_PLATFORM
#include "tdongle_memory.h"
#define RNG_TAG(p) tdongle_heap_tag(TDONGLE_OWNER_TLS, (p))
#define RNG_FREE(p) tdongle_heap_free(TDONGLE_OWNER_TLS, (p))
#else
#define RNG_TAG(p) (p)
#define RNG_FREE(p) free(p)
#endif

typedef struct {
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
    bool own_entropy;
} rng_state_t;

static ml_mutex_t lock;
static volatile int lock_ready;      /* 0 = not built, 1 = building, 2 = ready */
static rng_state_t *state;
static unsigned users;
static ml_rng_seed_fn seed_fn;
static void *seed_ctx;
static ml_rng_stats_t stats;

/* The lock itself must exist before anyone can take it; build it once without a lock. */
static void ensure_lock(void) {
    int expected = 0;
    if (__atomic_compare_exchange_n(&lock_ready, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        ml_mutex_init(&lock);
        __atomic_store_n(&lock_ready, 2, __ATOMIC_RELEASE);
    } else {
        while (__atomic_load_n(&lock_ready, __ATOMIC_ACQUIRE) != 2) ml_sleep_ms(1);
    }
}

void ml_rng_set_seed_source(ml_rng_seed_fn fn, void *ctx) {
    ensure_lock();
    ml_mutex_lock(&lock);
    seed_fn = fn;
    seed_ctx = ctx;
    ml_mutex_unlock(&lock);
}

static int build(void) {
    rng_state_t *s = RNG_TAG(calloc(1, sizeof(*s)));
    if (!s) return -1;
    mbedtls_ctr_drbg_init(&s->drbg);
    mbedtls_entropy_init(&s->entropy);
    s->own_entropy = true;
    int ret;
    if (seed_fn) ret = mbedtls_ctr_drbg_seed(&s->drbg, seed_fn, seed_ctx, NULL, 0);
    else ret = mbedtls_ctr_drbg_seed(&s->drbg, mbedtls_entropy_func, &s->entropy, NULL, 0);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&s->drbg);
        mbedtls_entropy_free(&s->entropy);
        RNG_FREE(s);
        return ret;
    }
    state = s;
    stats.seedings++;
    stats.bytes_resident = (unsigned)sizeof(*s);
    return 0;
}

int ml_rng_acquire(void) {
    ensure_lock();
    ml_mutex_lock(&lock);
    int ret = 0;
    if (!state) ret = build();
    if (ret == 0) { users++; stats.users = users; }
    else stats.failures++;
    ml_mutex_unlock(&lock);
    return ret;
}

void ml_rng_release(void) {
    ensure_lock();
    ml_mutex_lock(&lock);
    if (users) {
        users--;
        stats.users = users;
        if (!users && state) {
            mbedtls_ctr_drbg_free(&state->drbg);
            mbedtls_entropy_free(&state->entropy);
            RNG_FREE(state);
            state = NULL;
            stats.bytes_resident = 0;
        }
    }
    ml_mutex_unlock(&lock);
}

int ml_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    ensure_lock();
    ml_mutex_lock(&lock);
    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    if (state) {
        /* mbedtls_ctr_drbg_random is itself mutex-protected only with MBEDTLS_THREADING_C; ours covers it either way. */
        ret = mbedtls_ctr_drbg_random(&state->drbg, out, len);
        if (ret == 0) stats.bytes += len;
    }
    if (ret != 0) stats.failures++;
    ml_mutex_unlock(&lock);
    return ret;
}

void ml_rng_stats(ml_rng_stats_t *out) {
    ensure_lock();
    ml_mutex_lock(&lock);
    *out = stats;
    ml_mutex_unlock(&lock);
}
