#include "cJSON.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
static size_t test_strlcpy(char *out,const char *src,size_t size) {
    size_t length=strlen(src);
    if(size){size_t n=length<size-1?length:size-1;memcpy(out,src,n);out[n]=0;}
    return length;
}
#define strlcpy test_strlcpy
#define ML_MAX_PEERS 8
#define ML_MAX_ENDPOINTS 8
#define MICROLINK_MAX_PEER_ROUTES 8
#define ML_MAX_DERP_REGIONS 4
#define ML_MAX_DERP_NODES 2
#define ML_EVT_DERP_CONNECT_REQ 1
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
typedef struct {
    uint32_t network;
    uint8_t prefix_len;
} microlink_route_t;
#include "semantic_types.inc"
typedef struct {
    volatile uint32_t peer_generation;
    volatile bool map_batch_pending;
    unsigned vpn_ip, map_generation;
    char self_dns_name[128], last_error[64];
    bool key_expired;
    unsigned derp_region_default;
    uint8_t derp_region_count;
    ml_derp_region_t derp_regions[4];
    struct {
        bool connected;
    } derp;
    uint8_t stream_header[9], stream_special[8];
    size_t stream_header_used, stream_special_used;
    uint32_t stream_remaining, stream_id;
    uint8_t stream_type, stream_flags, stream_padding;
    bool stream_padding_pending;
    uint64_t ctrl_last_rx_ms, ctrl_stream_rx_ms;
    char transport_error[64];
    unsigned noise_error, noise_frame_bytes, map_attempts, map_failures,
        map_error, map_bytes, map_declared_bytes, map_projected_bytes,
        map_heap_before, map_heap_after, map_largest_before, map_stream_id,
        map_frame_type;
    struct {
        void *map_callback;
    } config;
    int events, peer_update_queue;
    struct {
        bool active;
        char hostname[64];
        uint8_t public_key[32];
    } peers[8];
} microlink_t;
static size_t allocations, live;
static bool fail_alloc, reject_queue, legacy;
static unsigned queued_count;
static ml_peer_update_t queued[64];
static ml_peer_batch_t *batch;
static void *ml_psram_calloc(size_t n, size_t size) {
    allocations++;
    if (fail_alloc)
        return NULL;
    void *p = calloc(n, size);
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
static int xQueueSend(int q, void *item, int ticks) {
    assert(ticks <= 100);
    if (reject_queue)
        return 0;
    ml_peer_update_t *u = *(ml_peer_update_t **)item;
    if (u->action == ML_PEER_BATCH) {
        assert(!batch);
        batch = (ml_peer_batch_t *)u;
    } else {
        assert(queued_count < 64);
        queued[queued_count++] = *u;
        free(u);
    }
    return 1;
}
static void microlink_ip_to_str(unsigned ip, char *out) {
    snprintf(out, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}
static void hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        assert(sscanf(hex + i * 2, "%2x", &v) == 1);
        out[i] = v;
    }
}
static uint64_t ticks;
static uint64_t ml_get_time_ms(void) { return ticks++; }
static void vTaskDelay(unsigned ms) { ticks += ms; }
static void xEventGroupSetBits(int events, int bit) {}
static bool activate_derp_regions(microlink_t *ml) {
    return ml->derp_region_count > 0;
}
static union {
    uint64_t align;
    uint8_t bytes[32768];
} storage;
#define gateway_json storage.bytes
#include "../components/microlink/src/gateway_stage_types.inc"
#include "semantic_consumers.inc"
#include "../components/microlink/src/gateway_project.inc"
#include "../components/microlink/src/gateway_project_stream.inc"
#include "../components/microlink/src/gateway_stage.inc"
static bool feed(microlink_t *ml, const char *json) {
    gs_parser p;
    gateway_stage_init(&p, ml);
    for (size_t i = 0; i < strlen(json); i++)
        if (!gs_byte(&p, json[i]))
            return false;
    assert(!allocations);
    if (!gs_finish(&p))
        return false;
    return gateway_stage_commit(ml, &p);
}
typedef int ml_noise_state_t, StaticSemaphore_t, SemaphoreHandle_t,
    portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))
#define MALLOC_CAP_INTERNAL 1
static uint8_t gateway_plain[20496];
static int gateway_lock = 1, gateway_lock_storage, gateway_init_lock;
static int xSemaphoreCreateMutexStatic(int *p) { return 1; }
static int xSemaphoreTake(int a, int b) { return 1; }
static void xSemaphoreGive(int a) {}
static unsigned heap_caps_get_free_size(int x) { return 60000; }
static unsigned heap_caps_get_largest_free_block(int x) { return 30000; }
static uint8_t input[400000];
static size_t input_used, input_pos;
static int noise_recv_inplace(microlink_t *m, int *n, uint8_t *out,
                              size_t capacity) {
    if (input_pos == input_used) {
        errno = EAGAIN;
        ticks += 20000;
        return -1;
    }
    size_t count = input_used - input_pos;
    if (count > 257)
        count = 257;
    assert(count <= capacity);
    memcpy(out, input + input_pos, count);
    input_pos += count;
    return count;
}
static int noise_send(microlink_t *m, int *n, const uint8_t *out,
                      size_t length) {
    return length;
}
static int ml_h2_build_window_update(uint8_t *out, size_t capacity,
                                     unsigned stream, unsigned count) {
    memset(out, 0, 13);
    return 13;
}
static void apply_long_poll_map(microlink_t *m, cJSON *map) {
    assert(!"semantic branch must not construct a full map DOM");
}
#define GATEWAY_SEMANTIC_MAP 1
#include "../components/microlink/src/gateway_stream.inc"
static int xQueueReceive(int q, void *out, int ticks) {
    if (!batch)
        return 0;
    *(ml_peer_batch_t **)out = batch;
    batch = NULL;
    return 1;
}
static void remove_peer(microlink_t *m, const ml_peer_update_t *u) {
    for (unsigned i = 0; i < 8; i++)
        if (!memcmp(m->peers[i].public_key, u->public_key, 32))
            m->peers[i].active = false;
}
static void apply_peer_update(microlink_t *m, const ml_peer_update_t *u) {
    if (u->action == ML_PEER_REMOVE) {
        remove_peer(m, u);
        return;
    }
    if (u->action != ML_PEER_ADD)
        return;
    for (unsigned i = 0; i < 8; i++)
        if (m->peers[i].active &&
            !memcmp(m->peers[i].public_key, u->public_key, 32))
            return;
    for (unsigned i = 0; i < 8; i++)
        if (!m->peers[i].active) {
            m->peers[i].active = true;
            memcpy(m->peers[i].public_key, u->public_key, 32);
            return;
        }
    assert(!"authoritative replacement must free omitted slots before adding");
}
#include "batch_consumer.inc"
static void reset(void) {
    assert(!live);
    allocations = queued_count = 0;
    reject_queue = fail_alloc = false;
    batch = NULL;
    gateway_capture = NULL;
}
static void compare(const char *json) {
    reset();
    microlink_t old = {.derp_region_default = 4}, current = old;
    cJSON *root = cJSON_Parse(json);
    assert(root);
    parse_peers_from_map_response(&old, root);
    cJSON_Delete(root);
    assert(!live);
    allocations = 0;
    assert(feed(&current, json));
    assert(batch && batch->count == queued_count);
    for (unsigned i = 0; i < queued_count; i++)
        assert(!memcmp(&queued[i], &batch->updates[i], sizeof(queued[i])));
    free(batch);
    assert(current.map_generation == 1);
}
#define KEY "0101010101010101010101010101010101010101010101010101010101010101"
int main(void) {
    compare(
        "{\"Peers\":[{\"ID\":42,\"Name\":\"server.ts.net.\",\"Key\":"
        "\"nodekey:" KEY "\",\"DiscoKey\":\"discokey:" KEY
        "\",\"Addresses\":[\"100.1.2.3/"
        "32\"],\"Endpoints\":[\"1.2.3.4:123\"],\"HomeDERP\":4,\"Online\":true,"
        "\"AllowedIPs\":[\"0.0.0.0/0\",\"192.168.5.0/"
        "24\"]}],\"PeersRemoved\":[12],\"PeersChangedPatch\":[{\"NodeID\":42,"
        "\"DERPRegion\":3,\"Online\":false,\"Endpoints\":[\"5.6.7.8:456\"]}]}");
    compare(
        "{\"PeersChanged\":[{\"ID\":43,\"Key\":\"nodekey:" KEY
        "\",\"Addresses\":[\"100.2.3.4/32\"]}],\"PeersRemoved\":[\"nodekey:" KEY
        "\"]}");
    compare("{\"PeersChanged\":[{\"ID\":2}],\"Peers\":[{\"ID\":1}]}");
    reset();
    microlink_t m = {.derp_region_default = 4};
    assert(feed(&m, "{\"Node\":{\"Name\":\"d\\u00f6ngle\\ud83d\\ude00.ts.net\","
                    "\"Addresses\":[\"100.3.4.5/"
                    "32\"]},\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1},"
                    "\"2\":{\"RegionID\":2},\"3\":{\"RegionID\":3},\"5\":{"
                    "\"RegionID\":5},\"4\":{\"RegionID\":4,\"Nodes\":[{"
                    "\"HostName\":\"derp\",\"IPv4\":\"1.2.3.4\"}]}}}}"));
    assert(m.vpn_ip == 0x64030405 && strstr(m.self_dns_name, ".ts.net") &&
           m.derp_region_count == 4 && m.derp_regions[3].region_id == 4 &&
           !allocations);
    reset();
    m = (microlink_t){.vpn_ip = 123};
    assert(!feed(&m, "{\"PeersChanged\":[{\"ID\":1}],\"Node\":{\"Addresses\":["
                     "\"100.1.2.3/32\"]},\"Ignored\":\"bad\\q\"}"));
    assert(m.vpn_ip == 123 && !m.map_generation && !batch && !allocations);
    reset();
    m = (microlink_t){0};
    fail_alloc = true;
    assert(!feed(&m,
                 "{\"Node\":{\"Addresses\":[\"100.1.2.3/32\"]},\"Peers\":[]}"));
    assert(!m.vpn_ip && !m.map_generation && !live);
    reset();
    m = (microlink_t){0};
    reject_queue = true;
    assert(!feed(&m, "{\"Node\":{\"Name\":\"unchanged\"},\"Peers\":[]}"));
    assert(!m.self_dns_name[0] && !m.map_generation && !live);
    reset();
    m = (microlink_t){0};
    char *large = malloc(400000);
    strcpy(large, "{\"Unused\":\"");
    size_t n = strlen(large);
    memset(large + n, 'x', 300000);
    strcpy(large + n + 300000, "\",\"Node\":{\"Name\":\"kept\"}}");
    assert(feed(&m, large) && !strcmp(m.self_dns_name, "kept") &&
           !allocations); /* standard malloc is not staged allocator */
    reset();
    m = (microlink_t){0};
    assert(!feed(&m, "{\"Node\":{},\"Node\":{\"Name\":\"duplicate\"}}") &&
           !m.map_generation && !allocations);
    reset();
    m = (microlink_t){0};
    char many[512] = "{\"PeersChanged\":[";
    for (unsigned i = 0; i < 9; i++)
        strcat(many, i ? ",{}" : "{}");
    strcat(many, "]}");
    assert(!feed(&m, many) && !m.map_generation && !allocations);
    reset();
    m = (microlink_t){0};
    assert(feed(&m, "{\"Peers\":[{\"Key\":\"nodekey:" KEY "\"}]}"));
    for (unsigned i = 0; i < 8; i++) {
        m.peers[i].active = true;
        memset(m.peers[i].public_key, i + 2, 32);
    }
    process_peer_updates(&m);
    assert(!live && !batch && m.peers[0].active &&
           m.peers[0].public_key[0] == 1);
    for (unsigned i = 1; i < 8; i++)
        assert(!m.peers[i].active);
    reset();
    m = (microlink_t){.map_batch_pending = true};
    assert(!feed(&m, "{\"Peers\":[]}") && !m.map_generation && !allocations &&
           m.map_batch_pending);
    reset();
    m = (microlink_t){0};
    char *too_big = malloc(7000);
    strcpy(too_big, "{\"Node\":{\"Name\":\"");
    size_t prefix = strlen(too_big);
    memset(too_big + prefix, 'x', 6000);
    strcpy(too_big + prefix + 6000, "\"}}");
    assert(!feed(&m, too_big) && !m.map_generation &&
           !allocations); /* standard allocator below */
#undef free
    free(too_big);
#define free release
    reset();
    m = (microlink_t){0};
    ticks = input_used = input_pos = 0;
    size_t raw_length = strlen(large);
    for (size_t off = 0; off < raw_length + 4;) {
        uint8_t data[16000];
        size_t n = raw_length + 4 - off;
        if (n > sizeof(data))
            n = sizeof(data);
        for (size_t j = 0; j < n; j++) {
            size_t at = off + j;
            data[j] =
                at < 4 ? (raw_length >> (8 * at)) : (uint8_t)large[at - 4];
        }
        uint8_t header[9] = {
            n >> 16, n >> 8, n, 0, off + n == raw_length + 4 ? 1 : 0,
            0,       0,      0, 3};
        memcpy(input + input_used, header, 9);
        input_used += 9;
        memcpy(input + input_used, data, n);
        input_used += n;
        off += n;
    }
    int noise = 0;
    assert(gateway_read_map(&m, &noise, 3, true) == 0 &&
           m.map_generation == 1 && !strcmp(m.self_dns_name, "kept") &&
           !allocations);
#undef free
    free(large);
}
