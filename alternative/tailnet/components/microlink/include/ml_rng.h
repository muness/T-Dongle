/**
 * @file ml_rng.h
 * @brief One entropy source and one CTR-DRBG for every membership (ADR 0013, N3).
 *
 * Each membership used to carry its own mbedtls_entropy_context (420 B) and mbedtls_ctr_drbg_context (76 B) inside
 * its DERP connection, seeded on every connect: about 496 B of context per membership, a seeding pass per
 * handshake, and a fresh DRBG instance per connection. They exist only to give mbedtls_ssl_conf_rng() a generator.
 * The generator can be shared: ml_rng() is a thread-safe mbedtls f_rng over ONE seeded DRBG, reseeded by mbedTLS
 * on its normal interval from the platform entropy source (ESP-IDF's hardware RNG through mbedtls_entropy_func).
 *
 * The state is allocated by the first ml_rng_acquire() and freed by the last ml_rng_release(), so a gateway with no
 * membership holds none. Every user (each DERP link) acquires for as long as it may call ml_rng().
 * The seeding source is injectable so the host tests can run the real DRBG under ASan and TSan.
 */
#pragma once

#include <stddef.h>

/* Entropy source for the DRBG: mbedtls_entropy_func-compatible. NULL = the platform default. Call before the
 * first acquire; the host tests install a deterministic one. */
typedef int (*ml_rng_seed_fn)(void *ctx, unsigned char *out, size_t len);
void ml_rng_set_seed_source(ml_rng_seed_fn fn, void *ctx);

/* 0 on success, nonzero when the state could not be allocated or seeded (nothing is held then). Counted. */
int ml_rng_acquire(void);
void ml_rng_release(void);

/* mbedTLS f_rng. Returns a negative mbedTLS error when no acquire is outstanding or the DRBG fails. */
int ml_rng(void *ctx, unsigned char *out, size_t len);

typedef struct {
    unsigned users;                 /* outstanding acquires */
    unsigned long bytes;            /* generated so far */
    unsigned seedings;              /* times the state was built */
    unsigned failures;              /* failed acquires and failed generations */
    unsigned bytes_resident;        /* heap held right now (0 when idle) */
} ml_rng_stats_t;
void ml_rng_stats(ml_rng_stats_t *out);
