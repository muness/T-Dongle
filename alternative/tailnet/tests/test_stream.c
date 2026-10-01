#include "cJSON.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#define ML_MAX_DERP_REGIONS 4
#define MALLOC_CAP_INTERNAL 1
static size_t heap_caps_get_free_size(int caps) { return 60000; }
static size_t heap_caps_get_largest_free_block(int caps) { return 30000; }
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef int StaticSemaphore_t;
typedef int SemaphoreHandle_t;
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))
#define pdMS_TO_TICKS(x) (x)
#define pdTRUE 1
static int xSemaphoreCreateMutexStatic(int *s) { return 1; }
static int xSemaphoreTake(int s, int n) { return 1; }
static void xSemaphoreGive(int s) {}
typedef struct {
    uint8_t stream_header[9], stream_special[8];
    size_t stream_header_used, stream_special_used;
    uint32_t stream_remaining, stream_id;
    uint8_t stream_type, stream_flags, stream_padding;
    bool stream_padding_pending;
    uint64_t ctrl_last_rx_ms, ctrl_stream_rx_ms;
    unsigned maps;
    char transport_error[64];
    unsigned noise_error, noise_frame_bytes;
    uint32_t map_attempts, map_failures, map_bytes, map_declared_bytes,
        map_projected_bytes, map_heap_before, map_heap_after,
        map_largest_before;
    unsigned map_error, map_stream_id, map_frame_type, derp_region_default;
    struct {
        void *map_callback;
    } config;
} microlink_t;
typedef int ml_noise_state_t;
static uint8_t input[100000];
static size_t input_len, input_pos, chunk;
static unsigned replies;
static uint64_t now;
static uint64_t ml_get_time_ms(void) { return ++now; }
static int noise_recv_inplace(microlink_t *ml, int *noise, uint8_t *b,
                              size_t max) {
    if (input_pos == input_len) {
        errno = EAGAIN;
        now += 20000;
        return -1;
    }
    size_t n = input_len - input_pos;
    if (n > chunk)
        n = chunk;
    assert(n <= max);
    memcpy(b, input + input_pos, n);
    input_pos += n;
    return n;
}
static int noise_send(microlink_t *ml, int *noise, uint8_t *b, size_t n) {
    replies++;
    return n;
}
static int ml_h2_build_window_update(uint8_t *b, size_t n, uint32_t stream,
                                     uint32_t count) {
    assert(n >= 13);
    memset(b, 0, 13);
    return 13;
}
static void apply_long_poll_map(microlink_t *ml, cJSON *map) {
    assert(cJSON_IsObject(map));
    ml->maps++;
}
#include "../components/microlink/src/gateway_project.inc"
#include "../components/microlink/src/gateway_stream.inc"
static void frame(uint8_t type, uint8_t flags, uint32_t stream,
                  const uint8_t *data, size_t len) {
    uint8_t header[9] = {len >> 16,    len >> 8,     len,         type,  flags,
                         stream >> 24, stream >> 16, stream >> 8, stream};
    memcpy(input + input_len, header, 9);
    input_len += 9;
    if (len) {
        memcpy(input + input_len, data, len);
        input_len += len;
    }
}
static void reset(void) {
    input_len = input_pos = now = replies = 0;
    chunk = 1024;
}
int main(void) {
    int noise = 0;
    uint8_t map[] = {2, 0, 0, 0, '{', '}'};
    for (chunk = 1; chunk <= 40; chunk++) {
        size_t saved = chunk;
        reset();
        chunk = saved;
        microlink_t m = {0};
        frame(0, 1, 3, map, sizeof(map));
        assert(gateway_read_map(&m, &noise, 3, true) == 0);
        assert(m.maps == 1 && input_pos == input_len);
    }
    reset();
    microlink_t m = {0};
    uint8_t two[12];
    memcpy(two, map, 6);
    memcpy(two + 6, map, 6);
    frame(0, 0, 5, two, sizeof(two));
    assert(poll_map_update(&m, &noise) == 0 && m.maps == 2);
    reset();
    memset(&m, 0, sizeof(m));
    frame(0, 0, 5, map, 2);
    frame(0, 0, 5, map + 2, 4);
    chunk = 1;
    assert(poll_map_update(&m, &noise) == 0 && m.maps == 1);
    reset();
    memset(&m, 0, sizeof(m));
    frame(1, 1, 3, NULL, 0);
    assert(gateway_read_map(&m, &noise, 3, true) == 1 && !m.maps);
    reset();
    memset(&m, 0, sizeof(m));
    frame(4, 0, 0, NULL, 0);
    frame(0, 1, 3, map, sizeof(map));
    assert(gateway_read_map(&m, &noise, 3, true) == 0 && replies >= 2);
    reset();
    memset(&m, 0, sizeof(m));
    uint8_t huge[] = {0xff, 0xff, 0xff, 0x7f};
    frame(0, 1, 3, huge, 4);
    assert(gateway_read_map(&m, &noise, 3, true) < 0 && !m.maps);
    reset();
    memset(&m, 0, sizeof(m));
    frame(0, 8, 5, map, 6);
    assert(poll_map_update(&m, &noise) < 0);
    reset();
    memset(&m, 0, sizeof(m));
    frame(0, 0, 5, map, 3);
    assert(poll_map_update(&m, &noise) < 0 && !m.maps);
    reset();
    memset(&m, 0, sizeof(m));
    uint8_t wrap[] = {0xff, 0xff, 0xff, 0xff};
    frame(0, 1, 3, wrap, 4);
    assert(gateway_read_map(&m, &noise, 3, true) < 0 && m.map_error == 7 &&
           m.map_failures == 1);
    reset();
    memset(&m, 0, sizeof(m));
    uint8_t bad[] = {3, 0, 0, 0, '{', 'x', '}'};
    frame(0, 1, 3, bad, 7);
    assert(gateway_read_map(&m, &noise, 3, true) < 0 && m.map_error == 8);
    reset();
    memset(&m, 0, sizeof(m));
    frame(0, 1, 3, map, 3);
    assert(gateway_read_map(&m, &noise, 3, true) < 0 && m.map_error == 12);
    reset();
    memset(&m, 0, sizeof(m));
    frame(0, 0, 3, map, 3);
    frame(0, 1, 3, NULL, 0);
    assert(gateway_read_map(&m, &noise, 3, true) < 0 && m.map_error == 12);
    reset();
    memset(&m, 0, sizeof(m));
    uint8_t padded[9] = {2};
    memcpy(padded + 1, map, 6);
    frame(0, 9, 3, padded, 9);
    chunk = 1;
    assert(gateway_read_map(&m, &noise, 3, true) == 0 && m.maps == 1);
    reset();
    memset(&m, 0, sizeof(m));
    uint8_t invalid_pad[] = {1};
    frame(0, 9, 3, invalid_pad, 1);
    assert(gateway_read_map(&m, &noise, 3, true) < 0 && m.map_error == 4);
    return 0;
}
