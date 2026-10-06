/*
 * Freestanding harness for xtensa_emu.py: each phase_* function runs one operation on
 * static buffers and leaves a result in `result` (0 = correct). No libc is needed; the
 * emulator runs the phase functions from the linked ELF and counts executed instructions.
 *
 * Built with -DHARNESS_LEGACY to measure the original implementation instead (symbols
 * legacy_*), so before/after are measured by the same method on the same compiler.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef HARNESS_MBEDTLS
#include "mbedtls/chachapoly.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#elif defined(HARNESS_LEGACY)
#include "legacy/wg_crypto_legacy.h"
#define NS(x) legacy_##x
#define CTX struct legacy_chacha20_ctx
#define PCTX legacy_poly1305_context
#else
#include "chacha20.h"
#include "chacha20poly1305.h"
#include "poly1305-donna.h"
#define NS(x) x
#define CTX struct chacha20_ctx
#define PCTX poly1305_context
#endif

volatile int result = -1;
volatile size_t g_len = 1400;      /* set by the emulator before running a phase */
volatile int g_off = 0;            /* misalignment of in/out */
uint8_t g_key[32];
uint8_t g_in[1424] __attribute__((aligned(16)));
uint8_t g_out[1424] __attribute__((aligned(16)));
uint8_t g_ref[1424] __attribute__((aligned(16)));   /* expected output, filled by the host side */
uint8_t g_tag[16];                                  /* expected tag, filled by the host side */

#define NOLOOPPAT __attribute__((optimize("no-tree-loop-distribute-patterns")))
NOLOOPPAT void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}
NOLOOPPAT void *memset(void *d, int c, size_t n) {
    uint8_t *dd = d;
    while (n--) *dd++ = (uint8_t)c;
    return d;
}
NOLOOPPAT int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    while (n--) { if (*x != *y) return *x - *y; x++; y++; }
    return 0;
}

static int same(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    while (n--) d |= *a++ ^ *b++;
    return d != 0;
}

#ifdef HARNESS_MBEDTLS
void free(void *p) { (void)p; }
static const uint8_t nonce12[12] = {0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8};
void phase_chacha20(void) {
    mbedtls_chacha20_context c;
    mbedtls_chacha20_init(&c);
    mbedtls_chacha20_setkey(&c, g_key);
    mbedtls_chacha20_starts(&c, nonce12, 0);
    mbedtls_chacha20_update(&c, g_len, g_in + g_off, g_out + g_off);
    result = same(g_out + g_off, g_ref + g_off, g_len);
}
void phase_poly1305(void) {
    mbedtls_poly1305_context p;
    uint8_t tag[16];
    mbedtls_poly1305_init(&p);
    mbedtls_poly1305_starts(&p, g_key);
    mbedtls_poly1305_update(&p, g_in + g_off, g_len);
    mbedtls_poly1305_finish(&p, tag);
    memcpy(g_out, tag, 16);
    result = same(tag, g_tag, 16);
}
void phase_seal(void) {
    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    mbedtls_chachapoly_setkey(&c, g_key);
    mbedtls_chachapoly_encrypt_and_tag(&c, g_len, nonce12, 0, 0, g_in + g_off, g_out + g_off, g_out + g_off + g_len);
    result = same(g_out + g_off, g_ref + g_off, g_len + 16);
}
void phase_open(void) {
    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    mbedtls_chachapoly_setkey(&c, g_key);
    int rc = mbedtls_chachapoly_auth_decrypt(&c, g_len, nonce12, 0, 0, g_ref + g_off + g_len, g_ref + g_off, g_out + g_off);
    result = rc == 0 ? same(g_out + g_off, g_in + g_off, g_len) : 99;
}
#else
void phase_chacha20(void) {
    CTX c;
    NS(chacha20_init)(&c, g_key, 0x0807060504030201ULL);
    NS(chacha20)(&c, g_out + g_off, g_in + g_off, (uint32_t)g_len);
    result = same(g_out + g_off, g_ref + g_off, g_len);
}

void phase_poly1305(void) {
    PCTX p;
    uint8_t tag[16];
    NS(poly1305_init)(&p, g_key);
    NS(poly1305_update)(&p, g_in + g_off, g_len);
    NS(poly1305_finish)(&p, tag);
    memcpy(g_out, tag, 16);
    result = same(tag, g_tag, 16);
}

void phase_seal(void) {
    uint8_t ad[1] = {0};
    NS(chacha20poly1305_encrypt)(g_out + g_off, g_in + g_off, g_len, ad, 0, 0x0807060504030201ULL, g_key);
    result = same(g_out + g_off, g_ref + g_off, g_len + 16);
}

void phase_open(void) {
    uint8_t ad[1] = {0};
    /* g_ref holds ciphertext||tag; g_in holds the plaintext */
    int ok = NS(chacha20poly1305_decrypt)(g_out + g_off, g_ref + g_off, g_len + 16, ad, 0, 0x0807060504030201ULL, g_key);
    result = ok ? same(g_out + g_off, g_in + g_off, g_len) : 99;
}

#endif
