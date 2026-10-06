#include "tdongle_memory.h"
#include "mbedtls/chachapoly.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>
#define ESP_OK 0
#define ESP_LOGE(...) ((void)0)
#include "noise_aead.inc"
typedef struct {
    uint8_t tx_key[32];
    uint64_t tx_nonce;
} ml_noise_state_t;
typedef struct {
    uint8_t wire[1024];
    size_t used, chunk, fail_after;
    bool fail_encrypt;
} microlink_t;
static int ml_conn_sockfd(microlink_t *m) { return 1; }
static int ml_setsockopt(int s, int level, int option, const void *p,
                         size_t n) {
    return 0;
}
static int ml_conn_write(microlink_t *m, const uint8_t *bytes, size_t n) {
    if (m->fail_after && m->used >= m->fail_after)
        return -1;
    if (n > m->chunk)
        n = m->chunk;
    assert(m->used + n <= sizeof(m->wire));
    memcpy(m->wire + m->used, bytes, n);
    m->used += n;
    return n;
}
static bool fail_encrypt;
static int ml_noise_encrypt(const uint8_t *key, uint64_t nonce,
                            const uint8_t *ad, size_t adlen,
                            const uint8_t *plain, size_t n, uint8_t *out) {
    if (fail_encrypt)
        return -1;
    return chacha20poly1305_encrypt(key, nonce, ad, adlen, plain, n, out);
}
#include "control_send.inc"
static void check(unsigned seed, unsigned chunk) {
    microlink_t m = {.chunk = chunk};
    ml_noise_state_t noise = {.tx_key = {seed}, .tx_nonce = 7};
    uint8_t plain[257], owned[273], decoded[257];
    for (size_t i = 0; i < sizeof(plain); i++)
        plain[i] = i * seed;
    memcpy(owned, plain, sizeof(plain));
    assert(noise_send_owned(&m, &noise, owned, sizeof(plain), sizeof(owned)) ==
           0);
    assert(noise.tx_nonce == 8 && m.used == 276 && m.wire[0] == 4 &&
           m.wire[1] == 1 && m.wire[2] == 17);
    assert(!chacha20poly1305_decrypt(noise.tx_key, 7, NULL, 0, m.wire + 3, 273,
                                     decoded));
    assert(!memcmp(decoded, plain, 257));
}
static void *thread(void *arg) {
    for (unsigned i = 0; i < 100; i++)
        check((uintptr_t)arg, 1 + i % 19);
    return NULL;
}
int main(void) {
    for (unsigned chunk = 1; chunk < 32; chunk++)
        check(1, chunk);
    microlink_t m = {.chunk = 1};
    ml_noise_state_t noise = {.tx_nonce = 8};
    uint8_t owned[64] = {0};
    assert(noise_send_owned(&m, &noise, owned, 64, 64) < 0 &&
           noise.tx_nonce == 8 && !m.used);
    fail_encrypt = true;
    assert(noise_send_owned(&m, &noise, owned, 16, 64) < 0 &&
           noise.tx_nonce == 8 && !m.used);
    fail_encrypt = false;
    m.fail_after = 2;
    assert(noise_send_owned(&m, &noise, owned, 16, 64) < 0 &&
           noise.tx_nonce == 9 && m.used == 2);
    pthread_t a, b;
    assert(!pthread_create(&a, NULL, thread, (void *)1) &&
           !pthread_create(&b, NULL, thread, (void *)2));
    pthread_join(a, NULL);
    pthread_join(b, NULL);
}
