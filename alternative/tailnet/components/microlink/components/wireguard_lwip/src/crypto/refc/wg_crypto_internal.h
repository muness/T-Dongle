#ifndef WG_CRYPTO_INTERNAL_H
#define WG_CRYPTO_INTERNAL_H
/*
 * Build helpers shared by the refc/ ChaCha20 and Poly1305 sources.
 *
 * WG_CRYPTO_HOT places a hot function in IRAM when CONFIG_WG_CRYPTO_IRAM is set
 * (off by default: IRAM is scarce, and the cache keeps the hot loops resident unless
 * Wi-Fi traffic evicts them; compare "min" and "avg" in `crypto bench`).
 */
#include <stdint.h>

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#if defined(__GNUC__)
#define WG_CRYPTO_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define WG_CRYPTO_ALWAYS_INLINE inline
#endif

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define WG_CRYPTO_LITTLE_ENDIAN 1
#else
#define WG_CRYPTO_LITTLE_ENDIAN 0
#endif

#if defined(CONFIG_WG_CRYPTO_IRAM) && CONFIG_WG_CRYPTO_IRAM
#include "esp_attr.h"
#define WG_CRYPTO_HOT IRAM_ATTR
#else
#define WG_CRYPTO_HOT
#endif

/*
 * Native-endian 32-bit access to a pointer the caller has already proven is
 * 4-byte aligned (WG_CRYPTO_LITTLE_ENDIAN only: it is the wire byte order).
 *
 * A may_alias type gives a single l32i / s32i on Xtensa without strict-aliasing
 * UB. memcpy() is deliberately avoided: GCC's expansion of a 4-byte memcpy
 * through __builtin_assume_aligned is not inlined on Xtensa (measured: one libc
 * call per word, ~10x slower), because Xtensa has no unaligned access.
 */
typedef uint32_t __attribute__((may_alias)) wg_u32_alias;

static WG_CRYPTO_ALWAYS_INLINE uint32_t wg_load32_aligned(const void *p) {
    return *(const wg_u32_alias *)p;
}

static WG_CRYPTO_ALWAYS_INLINE void wg_store32_aligned(void *p, uint32_t v) {
    *(wg_u32_alias *)p = v;
}

/*
 * Wipe `nwords` 32-bit words that may have held key material (aligned). Word-wise volatile
 * stores: crypto_zero() is a byte loop, ~5 instructions per byte, which is a visible
 * fraction of a short packet.
 */
static WG_CRYPTO_ALWAYS_INLINE void wg_zero_words(void *p, unsigned nwords) {
    volatile uint32_t *w = (volatile uint32_t *)p;
    while (nwords--)
        *w++ = 0;
}

#endif /* WG_CRYPTO_INTERNAL_H */
