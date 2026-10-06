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

// RFC7539 implementation of ChaCha20 with modified nonce size for WireGuard
// https://tools.ietf.org/html/rfc7539
// Adapted from https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c by D. J. Bernstein (Public Domain)
// HChaCha20 is described here: https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html

#include "chacha20.h"

#include <string.h>
#include <stdint.h>
#include "wg_crypto_internal.h"
#include "../../crypto.h"

/*
 * Performance notes (ESP32-S3 / Xtensa LX7, no ChaCha hardware):
 *
 *  - The block function keeps the 16 state words in locals. GCC scalarises the
 *    array because every index is a compile-time constant after the helpers are
 *    force-inlined, so no QUARTERROUND touches memory except for register spills.
 *    The previous version took the state through a pointer and, at -Os, left
 *    INNER_BLOCK as an out-of-line call executed 20 times per 64-byte block.
 *  - A 32-bit rotate is `ssai; src` (2 instructions) on Xtensa; GCC emits it for
 *    the shift/or idiom.
 *  - The keystream is XORed in 32-bit words when both buffers are 4-byte aligned
 *    (an unaligned l32i traps on this core, so the unaligned path is bytewise).
 *
 * Everything is data-independent: no secret-dependent branch, index or length.
 * `in` and `out` may be identical (in-place) but must not partially overlap.
 */

// 2.3.  The ChaCha20 Block Function
// The first four words (0-3) are constants: "expand 32-byte k"
#define CHACHA20_CONSTANT_1 0x61707865U
#define CHACHA20_CONSTANT_2 0x3320646eU
#define CHACHA20_CONSTANT_3 0x79622d32U
#define CHACHA20_CONSTANT_4 0x6b206574U

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

// 2.1. The ChaCha Quarter Round
// 1.  a += b; d ^= a; d <<<= 16;
// 2.  c += d; b ^= c; b <<<= 12;
// 3.  a += b; d ^= a; d <<<= 8;
// 4.  c += d; b ^= c; b <<<= 7;
#define QUARTERROUND(a, b, c, d)             \
    do {                                      \
        a += b;  d ^= a;  d = ROTL32(d, 16);  \
        c += d;  b ^= c;  b = ROTL32(b, 12);  \
        a += b;  d ^= a;  d = ROTL32(d,  8);  \
        c += d;  b ^= c;  b = ROTL32(b,  7);  \
    } while (0)

// 2.3.  The ChaCha20 Block Function
//  working_state = state; 10 x inner_block (a column round, then a diagonal round);
//  return state + working_state as 16 little-endian words.
// The working state is sixteen scalar locals, not an array: GCC turns an array copy
// loop into a memcpy() call and then keeps the array in memory.
#define CHACHA20_DOUBLE_ROUND                  \
    do {                                       \
        QUARTERROUND(x0, x4, x8,  x12);        \
        QUARTERROUND(x1, x5, x9,  x13);        \
        QUARTERROUND(x2, x6, x10, x14);        \
        QUARTERROUND(x3, x7, x11, x15);        \
        QUARTERROUND(x0, x5, x10, x15);        \
        QUARTERROUND(x1, x6, x11, x12);        \
        QUARTERROUND(x2, x7, x8,  x13);        \
        QUARTERROUND(x3, x4, x9,  x14);        \
    } while (0)

#define CHACHA20_LOAD_STATE(s)                                                           \
    uint32_t x0 = (s)[0], x1 = (s)[1], x2 = (s)[2], x3 = (s)[3], x4 = (s)[4], x5 = (s)[5], \
             x6 = (s)[6], x7 = (s)[7], x8 = (s)[8], x9 = (s)[9], x10 = (s)[10],           \
             x11 = (s)[11], x12 = (s)[12], x13 = (s)[13], x14 = (s)[14], x15 = (s)[15]

WG_CRYPTO_HOT static void chacha20_block_words(const uint32_t state[16], uint32_t out[16]) {
    CHACHA20_LOAD_STATE(state);
    int i;

    for (i = 0; i < 10; ++i)
        CHACHA20_DOUBLE_ROUND;

    out[0] = x0 + state[0];   out[1] = x1 + state[1];   out[2] = x2 + state[2];   out[3] = x3 + state[3];
    out[4] = x4 + state[4];   out[5] = x5 + state[5];   out[6] = x6 + state[6];   out[7] = x7 + state[7];
    out[8] = x8 + state[8];   out[9] = x9 + state[9];   out[10] = x10 + state[10]; out[11] = x11 + state[11];
    out[12] = x12 + state[12]; out[13] = x13 + state[13]; out[14] = x14 + state[14]; out[15] = x15 + state[15];
}

/*
 * Encrypt/decrypt `len` bytes (RFC 8439 2.4: XOR with the keystream).
 *
 * The aligned/unaligned decision is made once, outside the block loops. Choosing per block
 * with an if/else does not work: GCC for Xtensa merges the word-wise and byte-wise arms into
 * the byte-wise one, and the fast path silently vanishes (see tools/xtensa-insn-count).
 */
WG_CRYPTO_HOT void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len) {
    uint32_t ks[16];
    int i;

#if WG_CRYPTO_LITTLE_ENDIAN
    if ((((uintptr_t)in | (uintptr_t)out) & 3) == 0) {
        while (len >= CHACHA20_BLOCK_SIZE) {
            chacha20_block_words(ctx->state, ks);
            ctx->state[12] += 1; // Word 12 is a block counter
            for (i = 0; i < 16; ++i)
                wg_store32_aligned(out + 4 * i, wg_load32_aligned(in + 4 * i) ^ ks[i]);
            len -= CHACHA20_BLOCK_SIZE;
            out += CHACHA20_BLOCK_SIZE;
            in += CHACHA20_BLOCK_SIZE;
        }
    } else
#endif
    {
        while (len >= CHACHA20_BLOCK_SIZE) {
            chacha20_block_words(ctx->state, ks);
            ctx->state[12] += 1;
            for (i = 0; i < 16; ++i) {
                uint32_t w = ks[i];
                out[4 * i + 0] = in[4 * i + 0] ^ (uint8_t)(w);
                out[4 * i + 1] = in[4 * i + 1] ^ (uint8_t)(w >> 8);
                out[4 * i + 2] = in[4 * i + 2] ^ (uint8_t)(w >> 16);
                out[4 * i + 3] = in[4 * i + 3] ^ (uint8_t)(w >> 24);
            }
            len -= CHACHA20_BLOCK_SIZE;
            out += CHACHA20_BLOCK_SIZE;
            in += CHACHA20_BLOCK_SIZE;
        }
    }

    if (len) {
        // Final partial block: XOR byte by byte straight from the keystream words
        // (little-endian serialisation), so no secret-bearing scratch buffer is needed.
        chacha20_block_words(ctx->state, ks);
        ctx->state[12] += 1;
        for (i = 0; i < (int)len; ++i)
            out[i] = in[i] ^ (uint8_t)(ks[i >> 2] >> (8 * (i & 3)));
    }

    // Do not leave keystream on the stack.
    wg_zero_words(ks, 16);
}

// 2.3.  The ChaCha20 Block Function
// The next eight words (4-11) are taken from the 256-bit key by reading the bytes in little-endian order, in 4-byte chunks.
// Word 12 is a block counter.  Since each block is 64-byte, a 32-bit word is enough for 256 gigabytes of data.
// Words 13-15 are a nonce, which should not be repeated for the same key.
// For wireguard: "nonce being composed of 32 bits of zeros followed by the 64-bit little-endian value of counter." where counter comes from the Wireguard layer and is separate from the block counter in word 12
WG_CRYPTO_HOT void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, const uint64_t nonce) {
    ctx->state[0] = CHACHA20_CONSTANT_1;
    ctx->state[1] = CHACHA20_CONSTANT_2;
    ctx->state[2] = CHACHA20_CONSTANT_3;
    ctx->state[3] = CHACHA20_CONSTANT_4;
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
void hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key) {
    uint32_t state[16], x[16];
    state[0] = CHACHA20_CONSTANT_1;
    state[1] = CHACHA20_CONSTANT_2;
    state[2] = CHACHA20_CONSTANT_3;
    state[3] = CHACHA20_CONSTANT_4;
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

    // The block function returns working_state + state; HChaCha20 wants the working state
    // itself, so take the feed-forward addition back out (a rare path: cookie replies only).
    chacha20_block_words(state, x);

    // Concatenate first/last 128 bits into 256bit output (as little endian)
    U32TO8_LITTLE(out + 0, x[0] - state[0]);
    U32TO8_LITTLE(out + 4, x[1] - state[1]);
    U32TO8_LITTLE(out + 8, x[2] - state[2]);
    U32TO8_LITTLE(out + 12, x[3] - state[3]);
    U32TO8_LITTLE(out + 16, x[12] - state[12]);
    U32TO8_LITTLE(out + 20, x[13] - state[13]);
    U32TO8_LITTLE(out + 24, x[14] - state[14]);
    U32TO8_LITTLE(out + 28, x[15] - state[15]);
    wg_zero_words(state, 16);
    wg_zero_words(x, 16);
}
