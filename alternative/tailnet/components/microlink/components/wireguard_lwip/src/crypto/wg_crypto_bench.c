/*
 * ChaCha20-Poly1305 self-test and micro-benchmark. See wg_crypto_bench.h.
 *
 * Methodology: every case is measured two ways.
 *   min   - best of BENCH_REPS runs, each with interrupts masked, so Wi-Fi/USB
 *           interrupts and (on the other core) nothing else can add cycles. This is
 *           the intrinsic cost of the code, including its flash-cache behaviour
 *           after the first (warm-up) run.
 *   avg   - mean of BENCH_REPS runs with interrupts enabled. The gap between avg
 *           and min is what interrupts, preemption and cache eviction cost in the
 *           real system.
 * The masked window is one operation (<= ~0.2 ms for the optimised code, a few ms
 * for the legacy baseline), well below the interrupt watchdog.
 */
#include "wg_crypto_bench.h"

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chacha20.h"
#include "chacha20poly1305.h"
#include "poly1305-donna.h"

#if defined(CONFIG_WG_CRYPTO_BENCH_BASELINE) && CONFIG_WG_CRYPTO_BENCH_BASELINE
#define WG_BENCH_LEGACY 1
#include "legacy/wg_crypto_legacy.h"
#else
#define WG_BENCH_LEGACY 0
#endif

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#include "esp_cpu.h"
#include "esp_heap_caps.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#define BENCH_UNIT "cyc"
#define BENCH_INNER 1 /* one operation per timed window: cycle counter resolution is 1 */
static portMUX_TYPE bench_mux = portMUX_INITIALIZER_UNLOCKED;
static inline uint32_t bench_now(void) { return (uint32_t)esp_cpu_get_cycle_count(); }
static inline void bench_mask(void) { portENTER_CRITICAL(&bench_mux); }
static inline void bench_unmask(void) { portEXIT_CRITICAL(&bench_mux); }
static void *bench_alloc(size_t n) { return heap_caps_malloc(n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT); }
static unsigned bench_mhz(void) { return esp_rom_get_cpu_ticks_per_us(); }
static void bench_free(void *p) { heap_caps_free(p); }
#else
#include <time.h>
#define BENCH_UNIT "ns"
#define BENCH_INNER 256 /* host clock is coarse: time a batch and divide */
static inline uint32_t bench_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec);
}
static inline void bench_mask(void) {}
static inline void bench_unmask(void) {}
static void *bench_alloc(size_t n) { return malloc(n); }
static void bench_free(void *p) { free(p); }
static unsigned bench_mhz(void) { return 0; }
#endif

#define BENCH_REPS 8
#define BENCH_MAX 1400
#define BENCH_SLACK 8 /* tag + misalignment slack */

typedef void (*bench_fn)(void *state);

struct bench_ctx {
    wg_crypto_bench_write_fn write;
    uint8_t key[32];
    uint64_t nonce;
    uint8_t *in;      /* BENCH_MAX + BENCH_SLACK, 4-byte aligned base */
    uint8_t *out;
    uint8_t *sealed;  /* valid ciphertext||tag for the open cases */
    size_t len;       /* current case length */
    size_t in_off;    /* misalignment applied to in/out */
    uint8_t ad[12];
};

static void emit(struct bench_ctx *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void emit(struct bench_ctx *b, const char *fmt, ...) {
    char line[128];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    strcat(line, "\r\n");
    b->write(line);
}

/* ---- the operations being timed ---- */
static void op_chacha20(void *s) {
    struct bench_ctx *b = s;
    struct chacha20_ctx c;
    chacha20_init(&c, b->key, b->nonce++);
    chacha20(&c, b->out + b->in_off, b->in + b->in_off, (uint32_t)b->len);
}
static void op_poly1305(void *s) {
    struct bench_ctx *b = s;
    poly1305_context p;
    uint8_t tag[16];
    poly1305_init(&p, b->key);
    poly1305_update(&p, b->in + b->in_off, b->len);
    poly1305_finish(&p, tag);
    b->out[0] = tag[0]; /* keep the result live */
}
static void op_seal(void *s) {
    struct bench_ctx *b = s;
    chacha20poly1305_encrypt(b->out + b->in_off, b->in + b->in_off, b->len, b->ad, 0, b->nonce++, b->key);
}
static void op_open(void *s) {
    struct bench_ctx *b = s;
    /* sealed was produced for nonce 0 by prepare_open() */
    if (!chacha20poly1305_decrypt(b->out + b->in_off, b->sealed + b->in_off, b->len + 16, b->ad, 0, 0, b->key))
        b->out[0] = 0xEE;
}
#if WG_BENCH_LEGACY
static void op_legacy_chacha20(void *s) {
    struct bench_ctx *b = s;
    struct legacy_chacha20_ctx c;
    legacy_chacha20_init(&c, b->key, b->nonce++);
    legacy_chacha20(&c, b->out + b->in_off, b->in + b->in_off, (uint32_t)b->len);
}
static void op_legacy_poly1305(void *s) {
    struct bench_ctx *b = s;
    legacy_poly1305_context p;
    uint8_t tag[16];
    legacy_poly1305_init(&p, b->key);
    legacy_poly1305_update(&p, b->in + b->in_off, b->len);
    legacy_poly1305_finish(&p, tag);
    b->out[0] = tag[0];
}
static void op_legacy_seal(void *s) {
    struct bench_ctx *b = s;
    legacy_chacha20poly1305_encrypt(b->out + b->in_off, b->in + b->in_off, b->len, b->ad, 0, b->nonce++, b->key);
}
static void op_legacy_open(void *s) {
    struct bench_ctx *b = s;
    if (!legacy_chacha20poly1305_decrypt(b->out + b->in_off, b->sealed + b->in_off, b->len + 16, b->ad, 0, 0, b->key))
        b->out[0] = 0xEE;
}
#endif

static void prepare_open(struct bench_ctx *b) {
    chacha20poly1305_encrypt(b->sealed + b->in_off, b->in + b->in_off, b->len, b->ad, 0, 0, b->key);
}

static void measure(struct bench_ctx *b, const char *name, bench_fn fn) {
    uint32_t best = UINT32_MAX, t0, d;
    uint64_t sum = 0;
    int i, j;

    fn(b); /* warm the instruction cache and any lazy state */
    for (i = 0; i < BENCH_REPS; i++) {
        bench_mask();
        t0 = bench_now();
        for (j = 0; j < BENCH_INNER; j++)
            fn(b);
        d = (bench_now() - t0) / BENCH_INNER;
        bench_unmask();
        if (d < best)
            best = d;
    }
    for (i = 0; i < BENCH_REPS; i++) {
        t0 = bench_now();
        for (j = 0; j < BENCH_INNER; j++)
            fn(b);
        sum += (uint32_t)(bench_now() - t0) / BENCH_INNER;
    }
    /* units per byte with two decimals, in integers (no soft-float in the firmware) */
    unsigned long cpb100 = (unsigned long)(((uint64_t)best * 100 + b->len / 2) / b->len);
    emit(b, "%-16s %4u B  min=%7lu %s  %3lu.%02lu %s/B  avg=%7lu %s", name, (unsigned)b->len,
         (unsigned long)best, BENCH_UNIT, cpb100 / 100, cpb100 % 100, BENCH_UNIT,
         (unsigned long)(sum / BENCH_REPS), BENCH_UNIT);
}

/* ---- known-answer self-test ---- */
/* Everything is checked against RFC 8439 or against a property that cannot hold by accident:
 *  - Poly1305: 2.5.2 example (34 bytes: two full blocks and a partial one)
 *  - ChaCha20: A.1 test vector #1 keystream (64 bytes, zero key)
 *  - AEAD: seal/open round trip at lengths covering every tail size, tag corruption rejected.
 * The host tests (tests/test_wg_crypto.c) carry the full RFC vector set. */
#define SELFTEST_MAX 130
bool wg_crypto_selftest(void) {
    static const uint8_t pkey[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                                     0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
    static const uint8_t ptag[16] = {0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9};
    static const uint8_t ks0[16] = {0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28};
    static const size_t lens[] = {0, 1, 15, 16, 17, 63, 64, 65, 114, SELFTEST_MAX};
    uint8_t *mem, *base, *in, *sealed, *plain;
    uint8_t key[32] = {0}, tag[16], blk[64] = {0}, out[64];
    poly1305_context p;
    struct chacha20_ctx c;
    size_t i, k;
    bool ok = true;

    base = bench_alloc(3 * (SELFTEST_MAX + 16) + 4); /* keep the stack small: the console task has 4 KB */
    if (!base)
        return false;
    mem = (uint8_t *)(((uintptr_t)base + 3) & ~(uintptr_t)3);
    in = mem;
    sealed = mem + (SELFTEST_MAX + 16);
    plain = sealed + (SELFTEST_MAX + 16);

    poly1305_init(&p, pkey);
    poly1305_update(&p, (const uint8_t *)"Cryptographic Forum Research Group", 34);
    poly1305_finish(&p, tag);
    ok &= !memcmp(tag, ptag, 16);

    chacha20_init(&c, key, 0);
    chacha20(&c, out, blk, 64);
    ok &= !memcmp(out, ks0, 16);

    for (i = 0; i < SELFTEST_MAX; i++)
        in[i] = (uint8_t)(i * 7 + 3);
    key[1] = 0x5a;
    for (k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
        size_t n = lens[k];
        chacha20poly1305_encrypt(sealed, in, n, in, 5, 0x0102030405060708ULL, key);
        ok &= chacha20poly1305_decrypt(plain, sealed, n + 16, in, 5, 0x0102030405060708ULL, key);
        ok &= !memcmp(plain, in, n);
        sealed[n + 15] ^= 1; /* corrupt the tag */
        ok &= !chacha20poly1305_decrypt(plain, sealed, n + 16, in, 5, 0x0102030405060708ULL, key);
    }
    bench_free(base);
    return ok;
}

static void run_set(struct bench_ctx *b, int legacy) {
    static const size_t sizes[] = {64, 512, 1400};
    size_t i;
#if !WG_BENCH_LEGACY
    (void)legacy;
#endif
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]) + 1; i++) {
        b->len = i < 3 ? sizes[i] : 1400;
        b->in_off = i < 3 ? 0 : 1; /* last pass: misaligned buffers take the byte-wise path */
        prepare_open(b);
#if WG_BENCH_LEGACY
        if (legacy) {
            if (i < 3) {
                measure(b, "legacy chacha20", op_legacy_chacha20);
                measure(b, "legacy poly1305", op_legacy_poly1305);
            }
            measure(b, i < 3 ? "legacy seal" : "legacy seal(odd)", op_legacy_seal);
            measure(b, i < 3 ? "legacy open" : "legacy open(odd)", op_legacy_open);
            continue;
        }
#endif
        if (i < 3) {
            measure(b, "chacha20", op_chacha20);
            measure(b, "poly1305", op_poly1305);
        }
        measure(b, i < 3 ? "seal" : "seal(misaligned)", op_seal);
        measure(b, i < 3 ? "open" : "open(misaligned)", op_open);
    }
}

int wg_crypto_bench_run(wg_crypto_bench_write_fn write) {
    enum { STRIDE = BENCH_MAX + 16 + BENCH_SLACK }; /* multiple of 4 */
    struct bench_ctx b;
    uint8_t *base, *mem;
    size_t i;

    memset(&b, 0, sizeof(b));
    b.write = write;
    if (!wg_crypto_selftest()) {
        emit(&b, "crypto bench: SELF-TEST FAILED");
        return 1;
    }
    base = bench_alloc(3 * STRIDE + 4);
    if (!base) {
        emit(&b, "crypto bench: out of memory");
        return 2;
    }
    mem = (uint8_t *)(((uintptr_t)base + 3) & ~(uintptr_t)3);
    b.in = mem;
    b.out = mem + STRIDE;
    b.sealed = mem + 2 * STRIDE;
    for (i = 0; i < STRIDE; i++)
        b.in[i] = (uint8_t)(i * 131 + 17);
    for (i = 0; i < sizeof(b.key); i++)
        b.key[i] = (uint8_t)(0xA0 + i);

    emit(&b, "crypto bench v1 selftest=ok impl=%s cpu_mhz=%u unit=%s reps=%d", "refc", bench_mhz(), BENCH_UNIT, BENCH_REPS);
    run_set(&b, 0);
#if WG_BENCH_LEGACY
    run_set(&b, 1);
#endif
    emit(&b, "crypto bench: done");
    bench_free(base);
    return 0;
}
