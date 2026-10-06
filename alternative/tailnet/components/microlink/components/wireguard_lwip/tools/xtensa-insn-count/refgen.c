/* Host helper for xtensa_emu.py: prints the inputs and expected outputs (from the legacy
 * implementation, used as an independent oracle) as hex lines. Usage: refgen LEN OFF */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "legacy/wg_crypto_legacy.h"

static void hex(const char *name, const uint8_t *p, size_t n) {
    printf("%s=", name);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    size_t len = argc > 1 ? strtoul(argv[1], 0, 0) : 1400;
    size_t off = argc > 2 ? strtoul(argv[2], 0, 0) : 0;
    static uint8_t key[32], in[1424], chacha[1424], sealed[1424];
    uint8_t zero[1] = {0}, tag[16];
    struct legacy_chacha20_ctx c;
    legacy_poly1305_context p;
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA0 + i * 3);
    for (int i = 0; i < 1424; i++) in[i] = (uint8_t)(i * 131 + 17);
    legacy_chacha20_init(&c, key, 0x0807060504030201ULL);
    legacy_chacha20(&c, chacha + off, in + off, (uint32_t)len);
    legacy_chacha20poly1305_encrypt(sealed + off, in + off, len, zero, 0, 0x0807060504030201ULL, key);
    legacy_poly1305_init(&p, key);
    legacy_poly1305_update(&p, in + off, len);
    legacy_poly1305_finish(&p, tag);
    hex("key", key, 32); hex("in", in, 1424); hex("chacha", chacha, 1424); hex("sealed", sealed, 1424); hex("tag", tag, 16);
    return 0;
}
