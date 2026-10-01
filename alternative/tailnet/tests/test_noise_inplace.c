#include "mbedtls/chachapoly.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "noise_aead.inc"

int main(void) {
    uint8_t key[32] = {1}, plain[20480], wire[20496], decoded[20480];
    for (size_t i = 0; i < sizeof(plain); i++)
        plain[i] = (uint8_t)(i * 7);
    size_t lengths[] = {0, 1, 15, 16, 17, 1024, 16384, 20480};
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        size_t len = lengths[i];
        assert(!chacha20poly1305_encrypt(key, 7, NULL, 0, plain, len, wire));
        assert(!chacha20poly1305_decrypt(key, 7, NULL, 0, wire, len + 16,
                                         decoded));
        assert(!memcmp(decoded, plain, len));
        assert(
            !chacha20poly1305_decrypt(key, 7, NULL, 0, wire, len + 16, wire));
        assert(!memcmp(wire, plain, len));
        assert(!chacha20poly1305_encrypt(key, 7, NULL, 0, plain, len, wire));
        wire[len] ^= 1;
        assert(chacha20poly1305_decrypt(key, 7, NULL, 0, wire, len + 16,
                                        wire) != 0);
        for (size_t j = 0; j < len; j++)
            assert(wire[j] == 0);
    }
    return 0;
}
