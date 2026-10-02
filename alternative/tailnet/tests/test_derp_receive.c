#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define MBEDTLS_ERR_SSL_WANT_READ -1
#define MBEDTLS_ERR_SSL_WANT_WRITE -2
#define MBEDTLS_ERR_SSL_TIMEOUT -3
#define DERP_FRAME_RECV_PACKET 5
#define pdMS_TO_TICKS(x) (x)
typedef struct {
    struct {
        bool connected;
        int sockfd, ssl;
    } derp;
} microlink_t;
static unsigned char input[70000];
static size_t used, pos, chunk, allocations, live;
static bool fail_alloc, queue_reject;
static uint64_t ticks;
static uint64_t ml_get_time_ms(void) { return ticks++; }
static void vTaskDelay(int ms) { ticks += ms; }
static int mbedtls_ssl_read(int *ssl, uint8_t *out, size_t length) {
    if (pos == used)
        return MBEDTLS_ERR_SSL_TIMEOUT;
    size_t n = used - pos;
    if (n > length)
        n = length;
    if (n > chunk)
        n = chunk;
    memcpy(out, input + pos, n);
    pos += n;
    return n;
}
static void *ml_psram_malloc(size_t n) {
    allocations++;
    if (fail_alloc)
        return NULL;
    void *p = malloc(n);
    if (p)
        live++;
    return p;
}
static void release(void *p) {
    if (p) {
        assert(live);
        live--;
        free(p);
    }
}
#define free release
static uint8_t *delivered;
static size_t delivered_len;
static uint8_t delivered_key[32];
static void dispatch_derp_frame(microlink_t *ml, uint8_t type, uint8_t *key,
                                uint8_t *payload, size_t length) {
    memcpy(delivered_key, key, 32);
    delivered_len = length;
    if (queue_reject || type != 5)
        free(payload);
    else
        delivered = payload;
}
#include "derp_receive.inc"
static void reset(size_t n) {
    assert(!live);
    pos = ticks = allocations = 0;
    fail_alloc = queue_reject = false;
    delivered = NULL;
    used = n + 5;
    input[0] = 5;
    input[1] = n >> 24;
    input[2] = n >> 16;
    input[3] = n >> 8;
    input[4] = n;
    for (size_t i = 5; i < used; i++)
        input[i] = (uint8_t)i;
}
int main(void) {
    microlink_t m = {.derp = {true, 1, 0}};
    for (chunk = 1; chunk < 64; chunk++) {
        reset(200);
        assert(poll_derp_read(&m) == 1);
        assert(allocations == 1 && live == 1 && delivered_len == 168);
        assert(!memcmp(delivered, input + 37, 168));
        assert(!memcmp(delivered_key, input + 5, 32));
        free(delivered);
    }
    chunk = 13;
    reset(200);
    queue_reject = true;
    assert(poll_derp_read(&m) == 1 && !live && allocations == 1);
    reset(200);
    fail_alloc = true;
    assert(poll_derp_read(&m) < 0 && !live);
    reset(200);
    used = 50;
    assert(poll_derp_read(&m) < 0 && !live);
    reset(70000 - 5);
    assert(poll_derp_read(&m) < 0 && !allocations);
    reset(32);
    assert(poll_derp_read(&m) < 0 && !allocations);
    reset(200);
    used = 2;
    assert(poll_derp_read(&m) < 0 && !allocations);
    reset(200);
    used = 0;
    assert(poll_derp_read(&m) == 0 && !allocations);
    reset(8);
    input[0] = 6;
    assert(poll_derp_read(&m) == 1 && !live);
}
