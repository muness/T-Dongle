// Poly1305 (RFC 8439 section 2.5) for 32-bit cores with a 32x32->64 multiplier.
//
// Public-domain/MIT lineage: the state layout, partial-block handling (poly1305-donna.c) and
// the idea of 5/4*r come from floodyberry/poly1305-donna. The arithmetic core was rewritten
// for the ESP32-S3 (Xtensa LX7); the original radix-2^26 core is kept as the test oracle
// (crypto/legacy/wg_crypto_legacy.c).
//
// Representation: the accumulator is five 32-bit limbs (acc[4] holds the few bits above
// 2^128), r is the clamped key in four limbs. Because clamping clears the low two bits of
// r[1..3] and the top four bits of every r limb, 2^130 = 5 (mod p) lets the wrapped-around
// partial products use rs[i] = r[i] + r[i]/4 = (5/4) r[i], which still fits in 32 bits.
//
// Constant time: straight-line arithmetic, no secret-dependent branch or index. Carries are
// computed with unsigned compares (`saltu` on Xtensa). Summing uint64_t products instead
// lets GCC -Os turn every carry into a data-dependent `bgeu` branch (the original code did:
// 25 of them per block); tools/xtensa-insn-count checks the compiled code for this.
//
// Cost on LX7 (-Os): ~255 instructions per 16-byte block (about 16 per byte): 16 MULL+MULUH
// pairs for the 4x4 limb products, 3 MULL for the acc[4] terms, one MULL for acc[4]*r[0].

#if defined(__GNUC__)
#define POLY1305_NOINLINE __attribute__((noinline))
#else
#define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

typedef struct poly1305_state_internal_t {
    uint32_t r[4];
    uint32_t rs[3];   /* r[1..3] * 5/4 */
    uint32_t acc[5];
    uint32_t s[4];    /* the "pad": second half of the one-time key */
    size_t leftover;
    unsigned char buffer[poly1305_block_size];
    unsigned char final;
} poly1305_state_internal_t;

typedef char poly1305_context_fits[(sizeof(poly1305_state_internal_t) <= sizeof(((poly1305_context *)0)->opaque)) ? 1 : -1];

static WG_CRYPTO_ALWAYS_INLINE uint32_t
U8TO32(const unsigned char *p) {
    return
        (((uint32_t)(p[0] & 0xff)      ) |
         ((uint32_t)(p[1] & 0xff) <<  8) |
         ((uint32_t)(p[2] & 0xff) << 16) |
         ((uint32_t)(p[3] & 0xff) << 24));
}

static void
U32TO8(unsigned char *p, uint32_t v) {
    p[0] = (v      ) & 0xff;
    p[1] = (v >>  8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

/* Branch-free helpers on (lo, hi) 64-bit accumulators and carries. */
#define POLY1305_MUL(lo, hi, a, b)                                          \
    do { uint64_t p_ = (uint64_t)(a) * (b); (lo) = (uint32_t)p_; (hi) = (uint32_t)(p_ >> 32); } while (0)
#define POLY1305_MAC(lo, hi, a, b)                                          \
    do { uint64_t p_ = (uint64_t)(a) * (b); uint32_t pl_ = (uint32_t)p_;    \
         (lo) += pl_; (hi) += (uint32_t)(p_ >> 32) + ((lo) < pl_); } while (0)
#define POLY1305_ADD32(lo, hi, v)                                           \
    do { uint32_t v_ = (v); (lo) += v_; (hi) += ((lo) < v_); } while (0)
/* x += v; c = carry out (0 or 1) */
#define POLY1305_ADDC(x, v, c)                                              \
    do { uint32_t v_ = (v); (x) += v_; (c) = ((x) < v_); } while (0)

WG_CRYPTO_HOT void
poly1305_init(poly1305_context *ctx, const unsigned char key[32]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

    /* r &= 0x0ffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = U8TO32(&key[ 0]) & 0x0fffffff;
    st->r[1] = U8TO32(&key[ 4]) & 0x0ffffffc;
    st->r[2] = U8TO32(&key[ 8]) & 0x0ffffffc;
    st->r[3] = U8TO32(&key[12]) & 0x0ffffffc;
    st->rs[0] = st->r[1] + (st->r[1] >> 2);
    st->rs[1] = st->r[2] + (st->r[2] >> 2);
    st->rs[2] = st->r[3] + (st->r[3] >> 2);

    /* h = 0 */
    st->acc[0] = st->acc[1] = st->acc[2] = st->acc[3] = st->acc[4] = 0;

    /* save pad for later */
    st->s[0] = U8TO32(&key[16]);
    st->s[1] = U8TO32(&key[20]);
    st->s[2] = U8TO32(&key[24]);
    st->s[3] = U8TO32(&key[28]);

    st->leftover = 0;
    st->final = 0;
}

/*
 * acc = (acc + block) * r mod 2^130-5 (partially reduced), for each 16-byte block.
 * `m` must be 4-byte aligned on little-endian targets: the four message words are single
 * l32i loads. (Branching between a word load and a byte-assembled load inside the loop does
 * not work: GCC for Xtensa merges the arms into the byte-wise one and the fast path silently
 * disappears.) poly1305_blocks() below handles any alignment.
 */
WG_CRYPTO_HOT static __attribute__((noinline)) void
poly1305_blocks_aligned(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : 1; /* the 2^128 padding bit of a full block */
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3];
    uint32_t rs1 = st->rs[0], rs2 = st->rs[1], rs3 = st->rs[2];
    uint32_t a0 = st->acc[0], a1 = st->acc[1], a2 = st->acc[2], a3 = st->acc[3], a4 = st->acc[4];
    uint32_t m0, m1, m2, m3, c0, c1, f;
    uint32_t d0l, d0h, d1l, d1h, d2l, d2h, d3l, d3h, t4;

    for (; bytes >= poly1305_block_size; bytes -= poly1305_block_size, m += poly1305_block_size) {
#if WG_CRYPTO_LITTLE_ENDIAN
        m0 = wg_load32_aligned(m + 0); m1 = wg_load32_aligned(m + 4);
        m2 = wg_load32_aligned(m + 8); m3 = wg_load32_aligned(m + 12);
#else
        m0 = U8TO32(m + 0); m1 = U8TO32(m + 4); m2 = U8TO32(m + 8); m3 = U8TO32(m + 12);
#endif
        /* acc += block (130-bit add with carry chain) */
        POLY1305_ADDC(a0, m0, c0);
        POLY1305_ADDC(a1, m1, c1);  a1 += c0; c1 += (a1 < c0);
        POLY1305_ADDC(a2, m2, c0);  a2 += c1; c0 += (a2 < c1);
        POLY1305_ADDC(a3, m3, c1);  a3 += c0; c1 += (a3 < c0);
        a4 += c1 + hibit;

        /* acc *= r. a4 is at most a few bits, so its products fit in 32 bits (plain MULL). */
        POLY1305_MUL(d0l, d0h, a0, r0);  POLY1305_MAC(d0l, d0h, a1, rs3); POLY1305_MAC(d0l, d0h, a2, rs2); POLY1305_MAC(d0l, d0h, a3, rs1);
        POLY1305_MUL(d1l, d1h, a0, r1);  POLY1305_MAC(d1l, d1h, a1, r0);  POLY1305_MAC(d1l, d1h, a2, rs3); POLY1305_MAC(d1l, d1h, a3, rs2);
        POLY1305_ADD32(d1l, d1h, a4 * rs1);
        POLY1305_MUL(d2l, d2h, a0, r2);  POLY1305_MAC(d2l, d2h, a1, r1);  POLY1305_MAC(d2l, d2h, a2, r0);  POLY1305_MAC(d2l, d2h, a3, rs3);
        POLY1305_ADD32(d2l, d2h, a4 * rs2);
        POLY1305_MUL(d3l, d3h, a0, r3);  POLY1305_MAC(d3l, d3h, a1, r2);  POLY1305_MAC(d3l, d3h, a2, r1);  POLY1305_MAC(d3l, d3h, a3, r0);
        POLY1305_ADD32(d3l, d3h, a4 * rs3);
        t4 = a4 * r0;

        /* carry between the 32-bit columns, then fold bits >= 2^130 back in as *5 */
        POLY1305_ADD32(d1l, d1h, d0h);
        POLY1305_ADD32(d2l, d2h, d1h);
        POLY1305_ADD32(d3l, d3h, d2h);
        a0 = d0l; a1 = d1l; a2 = d2l; a3 = d3l;
        a4 = d3h + t4;

        f = (a4 >> 2) + (a4 & 0xFFFFFFFCU); /* 5 * (a4 >> 2) */
        a4 &= 3;
        POLY1305_ADDC(a0, f, c0);
        a1 += c0; c0 = (a1 < c0);
        a2 += c0; c0 = (a2 < c0);
        a3 += c0; c0 = (a3 < c0);
        a4 += c0;
    }

    st->acc[0] = a0;
    st->acc[1] = a1;
    st->acc[2] = a2;
    st->acc[3] = a3;
    st->acc[4] = a4;
}

/*
 * Entry point for any alignment. Misaligned input (e.g. an IP packet at the +14 offset
 * behind an Ethernet header) is staged through a small aligned buffer so the core above
 * has exactly one load path.
 */
WG_CRYPTO_HOT static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
    if (!WG_CRYPTO_LITTLE_ENDIAN || (((uintptr_t)m & 3) == 0)) {
        poly1305_blocks_aligned(st, m, bytes);
    } else {
        uint32_t stage[16]; /* 4 blocks */
        while (bytes) {
            size_t n = bytes < sizeof(stage) ? bytes : sizeof(stage);
            size_t i;
            for (i = 0; i < n; i++)
                ((unsigned char *)stage)[i] = m[i];
            poly1305_blocks_aligned(st, (const unsigned char *)stage, n);
            m += n;
            bytes -= n;
        }
    }
}

WG_CRYPTO_HOT POLY1305_NOINLINE void
poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
    uint32_t a0, a1, a2, a3, a4, g0, g1, g2, g3, g4, mask, c;

    /* process the remaining block */
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < poly1305_block_size; i++)
            st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, poly1305_block_size);
    }

    a0 = st->acc[0]; a1 = st->acc[1]; a2 = st->acc[2]; a3 = st->acc[3]; a4 = st->acc[4];

    /* g = acc + 5 (= acc - (2^130 - 5) mod 2^130 with the 131st bit as the "acc >= p" flag) */
    g0 = a0 + 5;  c = g0 < 5;
    g1 = a1 + c;  c = g1 < c;
    g2 = a2 + c;  c = g2 < c;
    g3 = a3 + c;  c = g3 < c;
    g4 = a4 + c;

    /* select acc, or g if acc >= p, without branching */
    mask = (uint32_t)0 - (g4 >> 2);
    a0 = (a0 & ~mask) | (g0 & mask);
    a1 = (a1 & ~mask) | (g1 & mask);
    a2 = (a2 & ~mask) | (g2 & mask);
    a3 = (a3 & ~mask) | (g3 & mask);

    /* mac = (acc + s) mod 2^128 */
    POLY1305_ADDC(a0, st->s[0], c);
    POLY1305_ADDC(a1, st->s[1], g0);  a1 += c;  g0 += (a1 < c);
    POLY1305_ADDC(a2, st->s[2], c);   a2 += g0; c += (a2 < g0);
    a3 += st->s[3] + c;

    U32TO8(mac +  0, a0);
    U32TO8(mac +  4, a1);
    U32TO8(mac +  8, a2);
    U32TO8(mac + 12, a3);

    /* zero out the state */
    st->acc[0] = st->acc[1] = st->acc[2] = st->acc[3] = st->acc[4] = 0;
    st->r[0] = st->r[1] = st->r[2] = st->r[3] = 0;
    st->rs[0] = st->rs[1] = st->rs[2] = 0;
    st->s[0] = st->s[1] = st->s[2] = st->s[3] = 0;
}
