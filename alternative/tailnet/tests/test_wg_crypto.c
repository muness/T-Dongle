/*
 * Host tests for the WireGuard ChaCha20-Poly1305 (components/microlink/components/wireguard_lwip).
 *
 *  1. RFC 8439 known-answer vectors (generated from the RFC text, see
 *     gen_wg_crypto_rfc8439_vectors.py): ChaCha20 block + encryption, Poly1305,
 *     Poly1305 key generation, AEAD (2.8.2 via primitives, A.5 via the API).
 *  2. Differential tests of the optimised code against (a) the original
 *     implementation (legacy_*) and (b) mbedTLS chachapoly: thousands of random
 *     lengths 0..2048, random AAD, all four src/dst alignments, in-place and
 *     out-of-place, chunked Poly1305 updates, and tag/AAD/ciphertext corruption.
 *  3. Failure semantics: a rejected packet must not write the output buffer.
 *
 * Build (see tools/test-gateway.sh): the sanitizers are what check the aligned
 * fast paths really only run on aligned pointers (-fsanitize=alignment).
 * Usage: test_wg_crypto [iterations] [seed]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chacha20.h"
#include "chacha20poly1305.h"
#include "poly1305-donna.h"
#include "wg_crypto_legacy.h"
#include "mbedtls/chachapoly.h"
#include "wg_crypto_bench.h"
#include "wg_crypto_rfc8439_vectors.h"

static int failures;
static unsigned long checks;

#define CHECK(cond, ...) do { \
        checks++; \
        if (!(cond)) { \
            failures++; \
            printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); \
            if (failures > 20) { printf("too many failures\n"); exit(1); } \
        } \
    } while (0)

/* ---------- deterministic PRNG (xorshift64*) ---------- */
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd64(void) {
    rng_state ^= rng_state >> 12; rng_state ^= rng_state << 25; rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1DULL;
}
static uint32_t rnd(uint32_t n) { return (uint32_t)(rnd64() >> 33) % n; }
static void rnd_fill(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rnd64(); }

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }

/* Initialise ChaCha20 from the RFC's 96-bit nonce. The WireGuard API can only
 * express a zero first nonce word, so patch word 13 for the RFC vectors that use it. */
static void init12(struct chacha20_ctx *c, const uint8_t *key, const uint8_t *nonce12, uint32_t counter) {
    chacha20_init(c, key, le64(nonce12 + 4));
    c->state[13] = le32(nonce12);
    c->state[12] = counter;
}

/* ---------- RFC 8439 ---------- */
static void rfc_chacha(void) {
    for (size_t i = 0; i < sizeof(rfc_a1) / sizeof(rfc_a1[0]); i++) {
        const struct v_block *v = &rfc_a1[i];
        struct chacha20_ctx c;
        uint8_t zero[64] = {0}, out[64];
        init12(&c, v->key, v->nonce12, v->counter);
        chacha20(&c, out, zero, 64);
        CHECK(!memcmp(out, v->keystream, 64), "A.1 vector %zu keystream", i);
        CHECK(c.state[12] == v->counter + 1, "A.1 vector %zu counter advance", i);
    }
    for (size_t i = 0; i < sizeof(rfc_a2) / sizeof(rfc_a2[0]); i++) {
        const struct v_enc *v = &rfc_a2[i];
        for (int off = 0; off < 4; off++) {      /* every alignment of in and out */
            for (int inplace = 0; inplace < 2; inplace++) {
                struct chacha20_ctx c;
                uint8_t *in = malloc(v->len + 8), *out = inplace ? NULL : malloc(v->len + 8);
                uint8_t *src = in + off, *dst = inplace ? src : out + (off + 1) % 4;
                memcpy(src, v->pt, v->len);
                init12(&c, v->key, v->nonce12, v->counter);
                chacha20(&c, dst, src, (uint32_t)v->len);
                CHECK(!memcmp(dst, v->ct, v->len), "A.2 vector %zu off=%d inplace=%d", i, off, inplace);
                free(in); free(out);
            }
        }
    }
    /* RFC 7539 2.3.2 / HChaCha20 draft 2.2.1 */
    {
        uint8_t key[32], nonce[16] = {0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0, 0x31, 0x41, 0x59, 0x27}, out[32];
        static const uint8_t want[32] = {0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73,
                                         0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3, 0xec, 0xdc};
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        hchacha20(out, nonce, key);
        CHECK(!memcmp(out, want, 32), "HChaCha20 draft-irtf-cfrg-xchacha 2.2.1");
    }
}

static void poly_oneshot(uint8_t tag[16], const uint8_t *key, const uint8_t *msg, size_t n) {
    poly1305_context c;
    poly1305_init(&c, key);
    poly1305_update(&c, msg, n);
    poly1305_finish(&c, tag);
}

static void rfc_poly1305(void) {
    for (size_t i = 0; i < sizeof(rfc_poly) / sizeof(rfc_poly[0]); i++) {
        const struct v_poly *v = &rfc_poly[i];
        uint8_t tag[16];
        poly_oneshot(tag, v->key, v->msg, v->len);
        CHECK(!memcmp(tag, v->tag, 16), "Poly1305 vector %zu (len %zu)", i, v->len);
        /* Every split point and every alignment gives the same tag. */
        for (size_t split = 0; split <= v->len; split++) {
            for (int off = 0; off < 4; off++) {
                poly1305_context c;
                uint8_t *buf = malloc(v->len + 4);
                memcpy(buf + off, v->msg, v->len);
                poly1305_init(&c, v->key);
                poly1305_update(&c, buf + off, split);
                poly1305_update(&c, buf + off + split, v->len - split);
                poly1305_finish(&c, tag);
                CHECK(!memcmp(tag, v->tag, 16), "Poly1305 vector %zu split %zu off %d", i, split, off);
                free(buf);
            }
        }
    }
    for (size_t i = 0; i < sizeof(rfc_a4) / sizeof(rfc_a4[0]); i++) {
        const struct v_polykey *v = &rfc_a4[i];
        struct chacha20_ctx c;
        uint8_t block[64] = {0}, out[64];
        init12(&c, v->key, v->nonce12, 0);
        chacha20(&c, out, block, 64);
        CHECK(!memcmp(out, v->otk, 32), "A.4 Poly1305 key generation %zu", i);
    }
}

static void put_le64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

/* RFC 8439 2.8.2 uses nonce prefix 07 00 00 00, which the WireGuard 64-bit nonce
 * API cannot express, so rebuild the construction from the primitives. */
static void aead_from_primitives(uint8_t *ct_and_tag, const struct v_aead *v) {
    struct chacha20_ctx c;
    uint8_t zero64[64] = {0}, block[64], lens[16], pad[16] = {0};
    poly1305_context p;
    init12(&c, v->key, v->nonce12, 0);
    chacha20(&c, block, zero64, 64);                 /* counter 0: poly key; leaves counter = 1 */
    chacha20(&c, ct_and_tag, v->pt, (uint32_t)v->len);
    poly1305_init(&p, block);
    poly1305_update(&p, v->aad, v->aad_len);
    poly1305_update(&p, pad, (16 - v->aad_len % 16) % 16);
    poly1305_update(&p, ct_and_tag, v->len);
    poly1305_update(&p, pad, (16 - v->len % 16) % 16);
    put_le64(lens, v->aad_len); put_le64(lens + 8, v->len);
    poly1305_update(&p, lens, 16);
    poly1305_finish(&p, ct_and_tag + v->len);
}

static void rfc_aead_vectors(void) {
    for (size_t i = 0; i < sizeof(rfc_aead) / sizeof(rfc_aead[0]); i++) {
        const struct v_aead *v = &rfc_aead[i];
        uint8_t *out = malloc(v->len + 16);
        aead_from_primitives(out, v);
        CHECK(!memcmp(out, v->ct, v->len), "AEAD vector %zu ciphertext via primitives", i);
        CHECK(!memcmp(out + v->len, v->tag, 16), "AEAD vector %zu tag via primitives", i);
        free(out);

        if (le32(v->nonce12) == 0) {                  /* expressible through the WireGuard API */
            uint64_t nonce = le64(v->nonce12 + 4);
            uint8_t *enc = malloc(v->len + 16), *dec = malloc(v->len + 16), *ctt = malloc(v->len + 16);
            chacha20poly1305_encrypt(enc, v->pt, v->len, v->aad, v->aad_len, nonce, v->key);
            CHECK(!memcmp(enc, v->ct, v->len) && !memcmp(enc + v->len, v->tag, 16), "AEAD vector %zu API encrypt", i);
            memcpy(ctt, v->ct, v->len); memcpy(ctt + v->len, v->tag, 16);
            CHECK(chacha20poly1305_decrypt(dec, ctt, v->len + 16, v->aad, v->aad_len, nonce, v->key), "AEAD vector %zu API decrypt", i);
            CHECK(!memcmp(dec, v->pt, v->len), "AEAD vector %zu plaintext", i);
            free(enc); free(dec); free(ctt);
        }
    }
}

/* ---------- differential tests ---------- */
static void wg_nonce12(uint8_t n12[12], uint64_t nonce) { memset(n12, 0, 4); put_le64(n12 + 4, nonce); }

static void mbed_seal(uint8_t *out_ct_tag, const uint8_t *pt, size_t n, const uint8_t *ad, size_t adn, uint64_t nonce, const uint8_t *key) {
    mbedtls_chachapoly_context m;
    uint8_t n12[12];
    wg_nonce12(n12, nonce);
    mbedtls_chachapoly_init(&m);
    CHECK(mbedtls_chachapoly_setkey(&m, key) == 0, "mbedtls setkey");
    CHECK(mbedtls_chachapoly_encrypt_and_tag(&m, n, n12, ad, adn, pt, out_ct_tag, out_ct_tag + n) == 0, "mbedtls seal");
    mbedtls_chachapoly_free(&m);
}

static int mbed_open_ok(uint8_t *out, const uint8_t *ct_tag, size_t n, const uint8_t *ad, size_t adn, uint64_t nonce, const uint8_t *key) {
    mbedtls_chachapoly_context m;
    uint8_t n12[12];
    int rc;
    wg_nonce12(n12, nonce);
    mbedtls_chachapoly_init(&m);
    mbedtls_chachapoly_setkey(&m, key);
    rc = mbedtls_chachapoly_auth_decrypt(&m, n, n12, ad, adn, ct_tag + n, ct_tag, out);
    mbedtls_chachapoly_free(&m);
    return rc == 0;
}

#define MAXLEN 2048
#define PAD 16

static void differential_aead(unsigned iterations) {
    uint8_t *pt_base = malloc(MAXLEN + 2 * PAD), *ct_base = malloc(MAXLEN + 16 + 2 * PAD);
    uint8_t *ref_ct = malloc(MAXLEN + 16), *leg_ct = malloc(MAXLEN + 16), *dec = malloc(MAXLEN + 2 * PAD);
    uint8_t *ad = malloc(80);
    for (unsigned it = 0; it < iterations; it++) {
        uint8_t key[32];
        uint64_t nonce = rnd64();
        size_t n = it < MAXLEN + 1 ? it : rnd(MAXLEN + 1);     /* every length 0..2048 once, then random */
        size_t adn = rnd(4) == 0 ? 0 : rnd(65);
        int ioff = (int)rnd(4), ooff = (int)rnd(4);
        uint8_t *pt = pt_base + PAD + ioff, *ct = ct_base + PAD + ooff;
        rnd_fill(key, 32); rnd_fill(pt, n); rnd_fill(ad, 80);

        /* Seal: optimised vs legacy vs mbedTLS. */
        chacha20poly1305_encrypt(ct, pt, n, ad, adn, nonce, key);
        legacy_chacha20poly1305_encrypt(leg_ct, pt, n, ad, adn, nonce, key);
        mbed_seal(ref_ct, pt, n, ad, adn, nonce, key);
        CHECK(!memcmp(ct, leg_ct, n + 16), "seal != legacy n=%zu adn=%zu ioff=%d ooff=%d", n, adn, ioff, ooff);
        CHECK(!memcmp(ct, ref_ct, n + 16), "seal != mbedtls n=%zu adn=%zu ioff=%d ooff=%d", n, adn, ioff, ooff);

        /* Open (valid): all three accept and agree. */
        memset(dec, 0xA5, MAXLEN + 2 * PAD);
        CHECK(chacha20poly1305_decrypt(dec + PAD + ioff, ct, n + 16, ad, adn, nonce, key), "open rejected valid n=%zu", n);
        CHECK(!memcmp(dec + PAD + ioff, pt, n), "open plaintext n=%zu", n);
        CHECK(dec[PAD + ioff + n] == 0xA5 && dec[PAD + ioff - 1] == 0xA5, "open wrote outside dst n=%zu", n);
        CHECK(legacy_chacha20poly1305_decrypt(dec + PAD, ct, n + 16, ad, adn, nonce, key), "legacy rejects new seal n=%zu", n);
        CHECK(mbed_open_ok(dec + PAD, ct, n, ad, adn, nonce, key), "mbedtls rejects new seal n=%zu", n);

        /* In-place open (dst == src) must work when the ciphertext is aligned either way. */
        {
            uint8_t *buf = malloc(n + 16 + 8);
            memcpy(buf + ioff, ct, n + 16);
            CHECK(chacha20poly1305_decrypt(buf + ioff, buf + ioff, n + 16, ad, adn, nonce, key), "in-place open n=%zu", n);
            CHECK(!memcmp(buf + ioff, pt, n), "in-place plaintext n=%zu", n);
            free(buf);
        }

        /* Corruption: flip one bit anywhere in {ciphertext, tag, AAD}; wrong nonce; wrong key. */
        {
            size_t total = n + 16 + adn;
            size_t bit = rnd((uint32_t)(total * 8));
            uint8_t *bad = malloc(n + 16), *bad_ad = malloc(80);
            memcpy(bad, ct, n + 16); memcpy(bad_ad, ad, 80);
            if (bit < (n + 16) * 8) bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            else bad_ad[(bit / 8) - (n + 16)] ^= (uint8_t)(1u << (bit % 8));
            memset(dec, 0x5A, MAXLEN + 2 * PAD);
            CHECK(!chacha20poly1305_decrypt(dec + PAD, bad, n + 16, bad_ad, adn, nonce, key), "corrupt accepted n=%zu bit=%zu", n, bit);
            for (size_t k = 0; k < n && k < MAXLEN; k++) if (dec[PAD + k] != 0x5A) { CHECK(0, "rejected packet wrote dst n=%zu", n); break; }
            CHECK(!legacy_chacha20poly1305_decrypt(dec + PAD, bad, n + 16, bad_ad, adn, nonce, key), "legacy corrupt accepted");
            CHECK(!mbed_open_ok(dec + PAD, bad, n, bad_ad, adn, nonce, key), "mbedtls corrupt accepted");
            CHECK(!chacha20poly1305_decrypt(dec + PAD, ct, n + 16, ad, adn, nonce + 1, key), "wrong nonce accepted");
            key[0] ^= 1;
            CHECK(!chacha20poly1305_decrypt(dec + PAD, ct, n + 16, ad, adn, nonce, key), "wrong key accepted");
            free(bad); free(bad_ad);
        }
    }
    /* Too short to hold a tag. */
    {
        uint8_t key[32] = {0}, buf[16] = {0}, out[16];
        for (size_t n = 0; n < 16; n++)
            CHECK(!chacha20poly1305_decrypt(out, buf, n, NULL, 0, 0, key), "short packet len %zu accepted", n);
    }
    free(pt_base); free(ct_base); free(ref_ct); free(leg_ct); free(dec); free(ad);
}

static void differential_primitives(unsigned iterations) {
    uint8_t *in = malloc(MAXLEN + 16), *a = malloc(MAXLEN + 16), *b = malloc(MAXLEN + 16);
    for (unsigned it = 0; it < iterations; it++) {
        uint8_t key[32], tag_a[16], tag_b[16];
        size_t n = rnd(MAXLEN + 1);
        int ioff = (int)rnd(4), ooff = (int)rnd(4);
        uint64_t nonce = rnd64();
        struct chacha20_ctx ca;
        struct legacy_chacha20_ctx cb;
        poly1305_context pa;
        legacy_poly1305_context pb;
        rnd_fill(key, 32); rnd_fill(in, n + 8);
        /* ChaCha20 with random pre-advanced counter, including wrap-around. */
        chacha20_init(&ca, key, nonce); legacy_chacha20_init(&cb, key, nonce);
        ca.state[12] = cb.state[12] = rnd(4) == 0 ? 0xFFFFFFFFu - rnd(3) : (uint32_t)rnd64();
        chacha20(&ca, a + ooff, in + ioff, (uint32_t)n); legacy_chacha20(&cb, b + ooff, in + ioff, (uint32_t)n);
        CHECK(!memcmp(a + ooff, b + ooff, n) && ca.state[12] == cb.state[12], "chacha20 != legacy n=%zu", n);
        /* Poly1305 with random update chunking. */
        poly1305_init(&pa, key); legacy_poly1305_init(&pb, key);
        for (size_t pos = 0; pos < n;) {
            size_t take = rnd(3) == 0 ? rnd(40) : rnd(300);
            if (take > n - pos) take = n - pos;
            poly1305_update(&pa, in + ioff + pos, take); legacy_poly1305_update(&pb, in + ioff + pos, take);
            pos += take;
        }
        poly1305_finish(&pa, tag_a); legacy_poly1305_finish(&pb, tag_b);
        CHECK(!memcmp(tag_a, tag_b, 16), "poly1305 != legacy n=%zu", n);
        /* Adversarial limb values: all-ones / all-zero messages and keys stress carry propagation. */
        memset(in, (it & 1) ? 0xFF : 0x00, n);
        if (it & 2) memset(key, 0xFF, 32);
        poly_oneshot(tag_a, key, in + ioff, n);
        legacy_poly1305_init(&pb, key); legacy_poly1305_update(&pb, in + ioff, n); legacy_poly1305_finish(&pb, tag_b);
        CHECK(!memcmp(tag_a, tag_b, 16), "poly1305 edge != legacy n=%zu", n);
    }
    /* XChaCha20-Poly1305 (cookie replies). */
    for (unsigned it = 0; it < iterations / 8 + 1; it++) {
        uint8_t key[32], nonce[24], ad[32];
        size_t n = rnd(300), adn = rnd(33);
        rnd_fill(key, 32); rnd_fill(nonce, 24); rnd_fill(ad, 32); rnd_fill(in, n);
        xchacha20poly1305_encrypt(a, in, n, ad, adn, nonce, key);
        legacy_xchacha20poly1305_encrypt(b, in, n, ad, adn, nonce, key);
        CHECK(!memcmp(a, b, n + 16), "xchacha seal != legacy");
        CHECK(xchacha20poly1305_decrypt(b, a, n + 16, ad, adn, nonce, key) && !memcmp(b, in, n), "xchacha open");
        a[0] ^= 1;
        CHECK(!xchacha20poly1305_decrypt(b, a, n + 16, ad, adn, nonce, key) || n == 0, "xchacha corrupt accepted");
    }
    free(in); free(a); free(b);
}

/* Carry/overflow stress for Poly1305: keys and messages built from limb-boundary words, so the
 * accumulator keeps landing on 2^130-5, 2^128 and 2^32 edges that random bytes never reach. */
static uint32_t edge_word(void) {
    static const uint32_t edges[] = {0, 1, 2, 3, 4, 5, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFFEu,
                                     0xFFFFFFFBu, 0xFFFFFFFCu, 0x0FFFFFFFu, 0x0FFFFFFCu, 0x03FFFFFFu, 0x04000000u};
    return rnd(4) == 0 ? (uint32_t)rnd64() : edges[rnd(sizeof(edges) / sizeof(edges[0]))];
}

static void structured_poly(unsigned iterations) {
    for (unsigned it = 0; it < iterations; it++) {
        uint8_t key[32], msg[160], ta[16], tb[16];
        size_t n = rnd(161);
        legacy_poly1305_context pb;
        for (int i = 0; i < 8; i++) { uint32_t w = edge_word(); for (int j = 0; j < 4; j++) key[4 * i + j] = (uint8_t)(w >> (8 * j)); }
        for (size_t i = 0; i < 40; i++) { uint32_t w = edge_word(); for (int j = 0; j < 4; j++) if (4 * i + j < sizeof(msg)) msg[4 * i + j] = (uint8_t)(w >> (8 * j)); }
        poly_oneshot(ta, key, msg, n);
        legacy_poly1305_init(&pb, key); legacy_poly1305_update(&pb, msg, n); legacy_poly1305_finish(&pb, tb);
        CHECK(!memcmp(ta, tb, 16), "structured poly1305 n=%zu it=%u", n, it);
    }
}

int main(int argc, char **argv) {
    unsigned iterations = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 0) : 6000;
    if (argc > 2) rng_state = strtoull(argv[2], NULL, 0) | 1;
    printf("test_wg_crypto: iterations=%u seed=0x%llx\n", iterations, (unsigned long long)rng_state);
    rfc_chacha();
    rfc_poly1305();
    rfc_aead_vectors();
    differential_aead(iterations);
    differential_primitives(iterations);
    structured_poly(iterations * 4);
    CHECK(wg_crypto_selftest(), "firmware self-test (wg_crypto_selftest) fails on the host");
    printf("test_wg_crypto: %lu checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
