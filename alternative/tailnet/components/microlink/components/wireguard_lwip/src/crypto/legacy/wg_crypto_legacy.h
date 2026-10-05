#ifndef WG_CRYPTO_LEGACY_H
#define WG_CRYPTO_LEGACY_H
/* Original (pre-optimisation) WireGuard AEAD, symbols prefixed legacy_. Oracle + A/B baseline only. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define LEGACY_CHACHA20_BLOCK_SIZE 64
#define LEGACY_CHACHA20_KEY_SIZE 32
struct legacy_chacha20_ctx { uint32_t state[16]; };
typedef struct legacy_poly1305_context { size_t aligner; unsigned char opaque[136]; } legacy_poly1305_context;
void legacy_chacha20_init(struct legacy_chacha20_ctx *ctx, const uint8_t *key, const uint64_t nonce);
void legacy_chacha20(struct legacy_chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len);
void legacy_hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key);
void legacy_poly1305_init(legacy_poly1305_context *ctx, const unsigned char key[32]);
void legacy_poly1305_update(legacy_poly1305_context *ctx, const unsigned char *m, size_t bytes);
void legacy_poly1305_finish(legacy_poly1305_context *ctx, unsigned char mac[16]);
void legacy_chacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key);
bool legacy_chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key);
void legacy_xchacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key);
bool legacy_xchacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key);
#endif
