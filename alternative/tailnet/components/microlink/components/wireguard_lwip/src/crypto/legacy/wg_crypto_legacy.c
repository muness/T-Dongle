/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */

/*
 * LEGACY REFERENCE IMPLEMENTATION -- DO NOT USE IN FIRMWARE.
 *
 * This is the original, unoptimised WireGuard ChaCha20-Poly1305 (chacha20.c,
 * chacha20poly1305.c, poly1305-donna.c, poly1305-donna-32.h as of the base
 * commit), with every symbol prefixed legacy_. It exists as an independent
 * oracle for the host differential tests and, when
 * CONFIG_WG_CRYPTO_BENCH_BASELINE is set, as the "before" column of the
 * on-target `crypto bench`. Keep it byte-for-byte equivalent to the original
 * algorithms; optimise refc/ instead. (Only change: `unsigned long` poly1305 limbs
 * became uint32_t so the state fits its 136-byte opaque buffer on LP64 hosts;
 * identical on the 32-bit target.)
 */
#include "wg_crypto_legacy.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../../crypto.h"
#define CHACHA20_BLOCK_SIZE LEGACY_CHACHA20_BLOCK_SIZE
#define CHACHA20_KEY_SIZE LEGACY_CHACHA20_KEY_SIZE


#include <string.h>
#include <stdint.h>

// 2.3.  The ChaCha20 Block Function
// The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
static const uint32_t legacy_CHACHA20_CONSTANT_1 = 0x61707865;
static const uint32_t legacy_CHACHA20_CONSTANT_2 = 0x3320646e;
static const uint32_t legacy_CHACHA20_CONSTANT_3 = 0x79622d32;
static const uint32_t legacy_CHACHA20_CONSTANT_4 = 0x6b206574;

#define legacy_ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define legacy_PLUS(v,w) (U32V((v) + (w)))
#define legacy_PLUSONE(v) (legacy_PLUS((v),1))

// 2.1. The ChaCha Quarter Round
// 1.  a += b; d ^= a; d <<<= 16;
// 2.  c += d; b ^= c; b <<<= 12;
// 3.  a += b; d ^= a; d <<<= 8;
// 4.  c += d; b ^= c; b <<<= 7;

#define legacy_QUARTERROUND(a, b, c, d)       \
    a += b;  d ^= a;  d = legacy_ROTL32(d, 16);  \
    c += d;  b ^= c;  b = legacy_ROTL32(b, 12);  \
    a += b;  d ^= a;  d = legacy_ROTL32(d,  8);  \
    c += d;  b ^= c;  b = legacy_ROTL32(b,  7)

static inline void legacy_INNER_BLOCK(uint32_t *block) {
    legacy_QUARTERROUND(block[0], block[4], block[ 8], block[12]); // column 0
    legacy_QUARTERROUND(block[1], block[5], block[ 9], block[13]); // column 1
    legacy_QUARTERROUND(block[2], block[6], block[10], block[14]); // column 2
    legacy_QUARTERROUND(block[3], block[7], block[11], block[15]); // column 3
    legacy_QUARTERROUND(block[0], block[5], block[10], block[15]); // diagonal 1
    legacy_QUARTERROUND(block[1], block[6], block[11], block[12]); // diagonal 2
    legacy_QUARTERROUND(block[2], block[7], block[ 8], block[13]); // diagonal 3
    legacy_QUARTERROUND(block[3], block[4], block[ 9], block[14]); // diagonal 4
}

#define legacy_TWENTY_ROUNDS(x) ( \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x), \
    legacy_INNER_BLOCK(x) \
)

// 2.3.  The ChaCha20 Block Function
// legacy_chacha20_block(key, counter, nonce):
//  state = constants | key | counter | nonce
//  working_state = state
//	for i=1 upto 10
//   inner_block(working_state)
//  end
//	state += working_state
//	return serialize(state)
// end
static void legacy_chacha20_block(struct legacy_chacha20_ctx *ctx, uint8_t *stream) {
    uint32_t working_state[16];
    int i;

    for (i = 0; i < 16; ++i) {
        working_state[i] = ctx->state[i];
    }

    legacy_TWENTY_ROUNDS(working_state);

    for (i = 0; i < 16; ++i) {
        U32TO8_LITTLE(stream + (4 * i), legacy_PLUS(working_state[i], ctx->state[i]));
    }
}

void legacy_chacha20(struct legacy_chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len) {
    uint8_t output[CHACHA20_BLOCK_SIZE];
    int i;

    if (len) {
        for (;;) {
            legacy_chacha20_block(ctx, output);
            // Word 12 is a block counter
            ctx->state[12] = legacy_PLUSONE(ctx->state[12]);
            if (len <= 64) {
                for (i = 0;i < len;++i) {
                    out[i] = in[i] ^ output[i];
                }
                return;
            }
            for (i = 0;i < 64;++i) {
                out[i] = in[i] ^ output[i];
            }
            len -= 64;
            out += 64;
            in += 64;
        }
    }
}


// 2.3.  The ChaCha20 Block Function
// The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
// The next eight words (4-11) are taken from the 256-bit key by reading the bytes in little-endian order, in 4-byte chunks.
// Word 12 is a block counter.  Since each block is 64-byte, a 32-bit word is enough for 256 gigabytes of data.
// Words 13-15 are a nonce, which should not be repeated for the same key.
// For wireguard: "nonce being composed of 32 bits of zeros followed by the 64-bit little-endian value of counter." where counter comes from the Wireguard layer and is separate from the block counter in word 12
void legacy_chacha20_init(struct legacy_chacha20_ctx *ctx, const uint8_t *key, const uint64_t nonce) {
    ctx->state[0] = legacy_CHACHA20_CONSTANT_1;
    ctx->state[1] = legacy_CHACHA20_CONSTANT_2;
    ctx->state[2] = legacy_CHACHA20_CONSTANT_3;
    ctx->state[3] = legacy_CHACHA20_CONSTANT_4;
    ctx->state[4] = U8TO32_LITTLE(key + 0);
    ctx->state[5] = U8TO32_LITTLE(key + 4);
    ctx->state[6] = U8TO32_LITTLE(key + 8);
    ctx->state[7] = U8TO32_LITTLE(key + 12);
    ctx->state[8] = U8TO32_LITTLE(key + 16);
    ctx->state[9] = U8TO32_LITTLE(key + 20);
    ctx->state[10] = U8TO32_LITTLE(key + 24);
    ctx->state[11] = U8TO32_LITTLE(key + 28);
    ctx->state[12] = 0;
    ctx->state[13] = 0;
    ctx->state[14] = nonce & 0xFFFFFFFF;
    ctx->state[15] = nonce >> 32;
}

// 2.2. HChaCha20
// HChaCha20 is initialized the same way as the ChaCha cipher, except that HChaCha20 uses a 128-bit nonce and has no counter.
// After initialization, proceed through the ChaCha rounds as usual.
// Once the 20 ChaCha rounds have been completed, the first 128 bits and last 128 bits of the ChaCha state (both little-endian) are concatenated, and this 256-bit subkey is returned.
void legacy_hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key) {
    uint32_t state[16];
    state[0] = legacy_CHACHA20_CONSTANT_1;
    state[1] = legacy_CHACHA20_CONSTANT_2;
    state[2] = legacy_CHACHA20_CONSTANT_3;
    state[3] = legacy_CHACHA20_CONSTANT_4;
    state[4] = U8TO32_LITTLE(key + 0);
    state[5] = U8TO32_LITTLE(key + 4);
    state[6] = U8TO32_LITTLE(key + 8);
    state[7] = U8TO32_LITTLE(key + 12);
    state[8] = U8TO32_LITTLE(key + 16);
    state[9] = U8TO32_LITTLE(key + 20);
    state[10] = U8TO32_LITTLE(key + 24);
    state[11] = U8TO32_LITTLE(key + 28);
    state[12] = U8TO32_LITTLE(nonce +  0);
    state[13] = U8TO32_LITTLE(nonce +  4);
    state[14] = U8TO32_LITTLE(nonce +  8);
    state[15] = U8TO32_LITTLE(nonce + 12);

    legacy_TWENTY_ROUNDS(state);

    // Concatenate first/last 128 bits into 256bit output (as little endian)
    U32TO8_LITTLE(out + 0, state[0]);
    U32TO8_LITTLE(out + 4, state[1]);
    U32TO8_LITTLE(out + 8, state[2]);
    U32TO8_LITTLE(out + 12, state[3]);
    U32TO8_LITTLE(out + 16, state[12]);
    U32TO8_LITTLE(out + 20, state[13]);
    U32TO8_LITTLE(out + 24, state[14]);
    U32TO8_LITTLE(out + 28, state[15]);
}

/* ---- poly1305-donna (32-bit) ---- */
// Taken from https://github.com/floodyberry/poly1305-donna - public domain or MIT
/*
    poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64 bit addition
*/

#if defined(_MSC_VER)
    #define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
    #define POLY1305_NOINLINE __attribute__((noinline))
#else
    #define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

/* 17 + sizeof(size_t) + 14*sizeof(uint32_t) */
typedef struct legacy_poly1305_state_internal_t {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    unsigned char buffer[poly1305_block_size];
    unsigned char final;
} legacy_poly1305_state_internal_t;

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static uint32_t
legacy_U8TO32(const unsigned char *p) {
    return
        (((uint32_t)(p[0] & 0xff)      ) |
         ((uint32_t)(p[1] & 0xff) <<  8) |
         ((uint32_t)(p[2] & 0xff) << 16) |
         ((uint32_t)(p[3] & 0xff) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
legacy_U32TO8(unsigned char *p, uint32_t v) {
    p[0] = (v      ) & 0xff;
    p[1] = (v >>  8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

void
legacy_poly1305_init(legacy_poly1305_context *ctx, const unsigned char key[32]) {
    legacy_poly1305_state_internal_t *st = (legacy_poly1305_state_internal_t *)ctx;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = (legacy_U8TO32(&key[ 0])     ) & 0x3ffffff;
    st->r[1] = (legacy_U8TO32(&key[ 3]) >> 2) & 0x3ffff03;
    st->r[2] = (legacy_U8TO32(&key[ 6]) >> 4) & 0x3ffc0ff;
    st->r[3] = (legacy_U8TO32(&key[ 9]) >> 6) & 0x3f03fff;
    st->r[4] = (legacy_U8TO32(&key[12]) >> 8) & 0x00fffff;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* save pad for later */
    st->pad[0] = legacy_U8TO32(&key[16]);
    st->pad[1] = legacy_U8TO32(&key[20]);
    st->pad[2] = legacy_U8TO32(&key[24]);
    st->pad[3] = legacy_U8TO32(&key[28]);

    st->leftover = 0;
    st->final = 0;
}

static void
legacy_poly1305_blocks(legacy_poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
    const uint32_t hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
    uint32_t r0,r1,r2,r3,r4;
    uint32_t s1,s2,s3,s4;
    uint32_t h0,h1,h2,h3,h4;
    unsigned long long d0,d1,d2,d3,d4;
    uint32_t c;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];
    r4 = st->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    while (bytes >= poly1305_block_size) {
        /* h += m[i] */
        h0 += (legacy_U8TO32(m+ 0)     ) & 0x3ffffff;
        h1 += (legacy_U8TO32(m+ 3) >> 2) & 0x3ffffff;
        h2 += (legacy_U8TO32(m+ 6) >> 4) & 0x3ffffff;
        h3 += (legacy_U8TO32(m+ 9) >> 6) & 0x3ffffff;
        h4 += (legacy_U8TO32(m+12) >> 8) | hibit;

        /* h *= r */
        d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
        d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
        d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
        d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
        d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

        /* (partial) h %= p */
                      c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;      c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;      c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;      c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;      c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;  c =                (h0 >> 26); h0 =                h0 & 0x3ffffff;
        h1 += c;

        m += poly1305_block_size;
        bytes -= poly1305_block_size;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

POLY1305_NOINLINE void
legacy_poly1305_finish(legacy_poly1305_context *ctx, unsigned char mac[16]) {
    legacy_poly1305_state_internal_t *st = (legacy_poly1305_state_internal_t *)ctx;
    uint32_t h0,h1,h2,h3,h4,c;
    uint32_t g0,g1,g2,g3,g4;
    unsigned long long f;
    uint32_t mask;

    /* process the remaining block */
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < poly1305_block_size; i++)
            st->buffer[i] = 0;
        st->final = 1;
        legacy_poly1305_blocks(st, st->buffer, poly1305_block_size);
    }

    /* fully carry h */
    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

                 c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 +=     c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (unsigned long long)h0 + st->pad[0]            ; h0 = (uint32_t)f;
    f = (unsigned long long)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (unsigned long long)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (unsigned long long)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    legacy_U32TO8(mac +  0, h0);
    legacy_U32TO8(mac +  4, h1);
    legacy_U32TO8(mac +  8, h2);
    legacy_U32TO8(mac + 12, h3);

    /* zero out the state */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;
    st->r[0] = 0;
    st->r[1] = 0;
    st->r[2] = 0;
    st->r[3] = 0;
    st->r[4] = 0;
    st->pad[0] = 0;
    st->pad[1] = 0;
    st->pad[2] = 0;
    st->pad[3] = 0;
}

void
legacy_poly1305_update(legacy_poly1305_context *ctx, const unsigned char *m, size_t bytes) {
    legacy_poly1305_state_internal_t *st = (legacy_poly1305_state_internal_t *)ctx;
    size_t i;

    /* handle leftover */
    if (st->leftover) {
        size_t want = (poly1305_block_size - st->leftover);
        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            st->buffer[st->leftover + i] = m[i];
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size)
            return;
        legacy_poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        size_t want = (bytes & ~(poly1305_block_size - 1));
        legacy_poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++)
            st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}

/* ---- AEAD ---- */
// AEAD_CHACHA20_POLY1305 as described in https://tools.ietf.org/html/rfc7539
// AEAD_XChaCha20_Poly1305 as described in https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html

#include <stdlib.h>
#include <stdint.h>

#define POLY1305_KEY_SIZE		32
#define POLY1305_MAC_SIZE		16

static const uint8_t legacy_zero[CHACHA20_BLOCK_SIZE] = { 0 };

// 2.6.  Generating the Poly1305 Key Using ChaCha20
static void legacy_generate_poly1305_key(struct legacy_poly1305_context *poly1305_state, struct legacy_chacha20_ctx *chacha20_state, const uint8_t *key, uint64_t nonce) {
    uint8_t block[POLY1305_KEY_SIZE] = {0};

    // The method is to call the block function with the following parameters:
    // - The 256-bit session integrity key is used as the ChaCha20 key.
    // - The block counter is set to zero.
    // - The protocol will specify a 96-bit or 64-bit nonce
    legacy_chacha20_init(chacha20_state, key, nonce);

    // We take the first 256 bits or the serialized state, and use those as the one-time Poly1305 key
    legacy_chacha20(chacha20_state, block, block, sizeof(block));

    legacy_poly1305_init(poly1305_state, block);

    crypto_zero(&block, sizeof(block));
}

// 2.8.  AEAD Construction (Encryption)
void legacy_chacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key) {
    struct legacy_poly1305_context poly1305_state;
    struct legacy_chacha20_ctx chacha20_state;
    uint8_t block[8];
    size_t padded_len;

    // First, a Poly1305 one-time key is generated from the 256-bit key and nonce using the procedure described in Section 2.6.
    legacy_generate_poly1305_key(&poly1305_state, &chacha20_state, key, nonce);

    // Next, the ChaCha20 encryption function is called to encrypt the plaintext, using the same key and nonce, and with the initial counter set to 1.
    legacy_chacha20(&chacha20_state, dst, src, src_len);

    // Finally, the Poly1305 function is called with the Poly1305 key calculated above, and a message constructed as a concatenation of the following:
    // - The AAD
    legacy_poly1305_update(&poly1305_state, ad, ad_len);
    // - padding1 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16
    padded_len = (ad_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
    legacy_poly1305_update(&poly1305_state, legacy_zero, padded_len - ad_len);
    // - The ciphertext
    legacy_poly1305_update(&poly1305_state, dst, src_len);
    // - padding2 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16.
    padded_len = (src_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
    legacy_poly1305_update(&poly1305_state, legacy_zero, padded_len - src_len);
    // - The length of the additional data in octets (as a 64-bit little-endian integer)
    U64TO8_LITTLE(block, (uint64_t)ad_len);
    legacy_poly1305_update(&poly1305_state, block, sizeof(block));
    // - The length of the ciphertext in octets (as a 64-bit little-endian integer).
    U64TO8_LITTLE(block, (uint64_t)src_len);
    legacy_poly1305_update(&poly1305_state, block, sizeof(block));

    // The output from the AEAD is twofold:
    // - A ciphertext of the same length as the plaintext. (above, output of legacy_chacha20 into dst)
    // - A 128-bit tag, which is the output of the Poly1305 function. (append to dst)
    legacy_poly1305_finish(&poly1305_state, dst + src_len);

    // Make sure we leave nothing sensitive on the stack
    crypto_zero(&chacha20_state, sizeof(chacha20_state));
    crypto_zero(&block, sizeof(block));
}

// 2.8.  AEAD Construction (Decryption)
bool legacy_chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key) {
    struct legacy_poly1305_context poly1305_state;
    struct legacy_chacha20_ctx chacha20_state;
    uint8_t block[8];
    uint8_t mac[POLY1305_MAC_SIZE];
    size_t padded_len;
    int dst_len;
    bool result = false;

    // Decryption is similar [to encryption] with the following differences:
    // - The roles of ciphertext and plaintext are reversed, so the ChaCha20 encryption function is applied to the ciphertext, producing the plaintext.
    // - The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext.
    // - The calculated tag is bitwise compared to the received tag.  The message is authenticated if and only if the tags match.

    if (src_len >= POLY1305_MAC_SIZE) {
        dst_len = src_len - POLY1305_MAC_SIZE;

        // First, a Poly1305 one-time key is generated from the 256-bit key and nonce using the procedure described in Section 2.6.
        legacy_generate_poly1305_key(&poly1305_state, &chacha20_state, key, nonce);

        // Calculate the MAC before attempting decryption

        // the Poly1305 function is called with the Poly1305 key calculated above, and a message constructed as a concatenation of the following:
        // - The AAD
        legacy_poly1305_update(&poly1305_state, ad, ad_len);
        // - padding1 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16
        padded_len = (ad_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
        legacy_poly1305_update(&poly1305_state, legacy_zero, padded_len - ad_len);
        // - The ciphertext (note the Poly1305 function is still run on the AAD and the ciphertext, not the plaintext)
        legacy_poly1305_update(&poly1305_state, src, dst_len);
        // - padding2 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16.
        padded_len = (dst_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
        legacy_poly1305_update(&poly1305_state, legacy_zero, padded_len - dst_len);
        // - The length of the additional data in octets (as a 64-bit little-endian integer)
        U64TO8_LITTLE(block, (uint64_t)ad_len);
        legacy_poly1305_update(&poly1305_state, block, sizeof(block));
        // - The length of the ciphertext in octets (as a 64-bit little-endian integer).
        U64TO8_LITTLE(block, (uint64_t)dst_len);
        legacy_poly1305_update(&poly1305_state, block, sizeof(block));

        // The output from the AEAD is twofold:
        // - A plaintext of the same length as the ciphertext. (below, output of legacy_chacha20 into dst)
        // - A 128-bit tag, which is the output of the Poly1305 function. (into mac for checking against passed mac)
        legacy_poly1305_finish(&poly1305_state, mac);


        if (crypto_equal(mac, src + dst_len, POLY1305_MAC_SIZE)) {
            // mac is correct - do the decryption
            // Next, the ChaCha20 encryption function is called to decrypt the ciphertext, using the same key and nonce, and with the initial counter set to 1.
            legacy_chacha20(&chacha20_state, dst, src, dst_len);
            result = true;
        }
    }
    return result;
}

// AEAD_XChaCha20_Poly1305
// XChaCha20-Poly1305 is a variant of the ChaCha20-Poly1305 AEAD construction as defined in [RFC7539] that uses a 192-bit nonce instead of a 96-bit nonce.
// The algorithm for XChaCha20-Poly1305 is as follows:
// 1. Calculate a subkey from the first 16 bytes of the nonce and the key, using HChaCha20 (Section 2.2).
// 2. Use the subkey and remaining 8 bytes of the nonce (prefixed with 4 NUL bytes) with AEAD_CHACHA20_POLY1305 from [RFC7539] as normal. The definition for XChaCha20 is given in Section 2.3.
void legacy_xchacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key) {
    uint8_t subkey[CHACHA20_KEY_SIZE];
    uint64_t new_nonce;

    new_nonce = U8TO64_LITTLE(nonce + 16);

    legacy_hchacha20(subkey, nonce, key);
    legacy_chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, new_nonce, subkey);

    crypto_zero(subkey, sizeof(subkey));
}

bool legacy_xchacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key) {
    uint8_t subkey[CHACHA20_KEY_SIZE];
    uint64_t new_nonce;
    bool result;

    new_nonce = U8TO64_LITTLE(nonce + 16);

    legacy_hchacha20(subkey, nonce, key);
    result = legacy_chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, new_nonce, subkey);

    crypto_zero(subkey, sizeof(subkey));
    return result;
}
