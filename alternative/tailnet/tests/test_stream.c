#include "cJSON.h"
#include "tdongle_memory.h"
#include "ml_gateway_limits.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
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
static pthread_mutex_t test_workspace_lock=PTHREAD_MUTEX_INITIALIZER;
static int xSemaphoreTake(int s, int n) {return pthread_mutex_lock(&test_workspace_lock)==0;}
static void xSemaphoreGive(int s) {assert(!pthread_mutex_unlock(&test_workspace_lock));}
typedef struct {
    uint8_t *h2_acc;
    size_t h2_acc_len;
    uint8_t stream_header[9], stream_special[56];
    size_t stream_header_used, stream_special_used;
    uint32_t stream_remaining, stream_id;
    uint8_t stream_type, stream_flags, stream_padding;
    bool stream_padding_pending;
    uint64_t ctrl_last_rx_ms, ctrl_stream_rx_ms;
    unsigned maps, identity;
    const uint8_t *session_input; size_t session_len, session_pos, session_chunk;
    char transport_error[64];
    unsigned noise_error, noise_frame_bytes;
    uint32_t map_attempts, map_failures, map_bytes, map_declared_bytes,
        map_projected_bytes, map_heap_before, map_heap_after,
        map_largest_before;
    unsigned map_error, map_stream_id, map_frame_type, derp_region_default;
    char h2_debug[49];
    uint32_t map_h2_error, map_h2_last_stream;
    struct {
        void *map_callback;
    } config;
} microlink_t;
typedef int ml_noise_state_t;
static uint8_t input[100000];
static size_t input_len, input_pos, chunk;
static unsigned replies, settings_acks;
static void gateway_diag_record(const microlink_t *ml, uint32_t event, uint32_t detail) {}
static uint64_t now, receive_delay;
static uint64_t ml_get_time_ms(void) { return ++now; }
static int noise_recv_inplace(microlink_t *ml, int *noise, uint8_t *b,
                              size_t max) {
    now+=receive_delay;
    if(ml->session_input){
        if(ml->session_pos==ml->session_len){errno=EAGAIN;now+=20000;return -1;}
        size_t n=ml->session_len-ml->session_pos;if(n>ml->session_chunk)n=ml->session_chunk;
        assert(n<=max);memcpy(b,ml->session_input+ml->session_pos,n);ml->session_pos+=n;return n;
    }
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
    if (n == 9 && b[3] == 4 && b[4] == 1) settings_acks++;
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
    if(ml->identity){char expected[16];snprintf(expected,sizeof(expected),"identity-%u",ml->identity);
        assert(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(map,"Node"),"Name")->valuestring,expected));
        cJSON *peer=cJSON_GetArrayItem(cJSON_GetObjectItem(map,"Peers"),0);
        assert(!strcmp(cJSON_GetObjectItem(peer,"Name")->valuestring,expected));
    }
    ml->maps++;
}
#include "../components/microlink/src/gateway_project.inc"
#include "../components/microlink/src/gateway_workspace.inc"
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#include "../components/microlink/src/gateway_h2_close.inc"
#include "../components/microlink/src/gateway_register_response.inc"
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
    input_len = input_pos = now = replies = settings_acks = 0;
    chunk = 1024;receive_delay=0;
}
static void *fragmented_membership(void *arg) {
    unsigned identity=(uintptr_t)arg;
    for(unsigned chunk=1;chunk<25;chunk++){
        char json[128];int length=snprintf(json,sizeof(json),"{\"Node\":{\"Name\":\"identity-%u\"},\"Peers\":[{\"Name\":\"identity-%u\"}]}",identity,identity);
        uint8_t wire[256]={0,0,0,0,1,0,0,0,5};wire[2]=length+4;
        for(unsigned i=0;i<4;i++)wire[9+i]=length>>(8*i);memcpy(wire+13,json,length);
        microlink_t member={.identity=identity,.session_input=wire,.session_len=13+length,.session_chunk=chunk};int noise=0;
        assert(!gateway_read_map(&member,&noise,5,true)&&member.maps==1&&member.session_pos==member.session_len);
    }
    return NULL;
}
int main(void) {
    microlink_t debug={0};uint8_t close_frame[64]={0,0,0,7,0,0,0,1};
    const char *reason="too many settings acknowledgements";memcpy(close_frame+8,reason,strlen(reason));
    gateway_h2_close(&debug,7,0,close_frame,8+strlen(reason));
    assert(debug.map_h2_error==1&&debug.map_h2_last_stream==7&&!strcmp(debug.h2_debug,reason));
    memcpy(close_frame+8,"auth token secret",17);gateway_h2_close(&debug,7,0,close_frame,25);assert(!debug.h2_debug[0]);

    reset();microlink_t coalesced={0};int test_noise=0;
    frame(0,1,1,(const uint8_t*)"{}",2);
    frame(4,0,0,NULL,0);
    assert(gateway_read_registration(&coalesced,&test_noise)==2 && settings_acks==0 && coalesced.h2_acc_len==9);
    uint8_t later[]={2,0,0,0,'{','}'};frame(0,1,3,later,sizeof(later));
    assert(!gateway_read_map(&coalesced,&test_noise,3,true)&&settings_acks==1&&!coalesced.h2_acc);

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
    reset();
    memset(&m, 0, sizeof(m));
    size_t raw_len = 80000;
    uint8_t *large = malloc(raw_len + 4);
    large[0] = raw_len;
    large[1] = raw_len >> 8;
    large[2] = raw_len >> 16;
    large[3] = raw_len >> 24;
    const char *begin = "{\"Unused\":\"";
    size_t start = strlen(begin);
    memcpy(large + 4, begin, start);
    memset(large + 4 + start, 'x', raw_len - start - 2);
    memcpy(large + 4 + raw_len - 2, "\"}", 2);
    for (size_t off = 0; off < raw_len + 4;) {
        size_t count = raw_len + 4 - off;
        if (count > 16000)
            count = 16000;
        frame(0, off + count == raw_len + 4 ? 1 : 0, 3, large + off, count);
        off += count;
    }
    chunk = 257;
    assert(gateway_read_map(&m, &noise, 3, true) == 0 && m.maps == 1 &&
           m.map_declared_bytes == 80000 && m.map_projected_bytes == 2);
    free(large);
    // Reproduce the device's ~50 KB streaming map: advancing flash work must
    // not be discarded merely because the four-second poll slice expired.
    reset();memset(&m,0,sizeof(m));
    const char *slow="{\"Unused\":\"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\"}";
    size_t slow_len=strlen(slow);uint8_t slow_map[256];
    for(unsigned i=0;i<4;i++)slow_map[i]=slow_len>>(8*i);
    memcpy(slow_map+4,slow,slow_len);frame(0,0,5,slow_map,slow_len+4);
    chunk=15;receive_delay=5000;
    assert(!poll_map_update(&m,&noise) && m.maps==1 && now>15000);
    // Drip-fed input cannot hold the shared workspace indefinitely.
    reset();memset(&m,0,sizeof(m));frame(0,0,5,slow_map,slow_len+4);
    chunk=10;receive_delay=14000;
    assert(poll_map_update(&m,&noise)<0 && m.map_error==12 && !m.maps && now>=90000);
    // A stopped partial message still times out and cannot become a saved map.
    reset();memset(&m,0,sizeof(m));frame(0,0,5,slow_map,5);
    assert(poll_map_update(&m,&noise)<0 && !m.maps);
    reset();
    memset(&m, 0, sizeof(m));
    uint8_t settings[6] = {0}, ping[8] = {1};
    frame(4, 0, 0, settings, sizeof(settings));
    frame(6, 0, 0, ping, sizeof(ping));
    const char *registration = "{\"Node\":{\"Addresses\":[\"100.1.2.3/32\"]}}";
    frame(0, 1, 1, (const uint8_t *)registration, strlen(registration));
    chunk = 7;
    assert(gateway_read_registration(&m, &noise) == strlen(registration));
    assert(!strcmp((char *)gateway_json, registration));
    assert(replies == 3 && settings_acks == 1);
    reset();
    memset(&m, 0, sizeof(m));
    frame(4, 0, 0, settings, sizeof(settings));
    m.h2_acc_len = input_len;
    m.h2_acc = malloc(input_len);
    memcpy(m.h2_acc, input, input_len);
    input_len = 0;
    frame(4, 0, 0, settings, sizeof(settings));
    frame(4, 1, 0, NULL, 0);
    frame(0, 1, 1, (const uint8_t *)registration, strlen(registration));
    chunk = 1;
    assert(gateway_read_registration(&m, &noise) == strlen(registration));
    assert(settings_acks == 2 && !m.h2_acc && !m.h2_acc_len);
    reset();
    memset(&m, 0, sizeof(m));
    frame(0, 0, 1, (const uint8_t *)registration, strlen(registration));
    assert(gateway_read_registration(&m, &noise) < 0);
    reset();
    memset(&m, 0, sizeof(m));
    uint8_t goaway[8] = {0,0,0,1,0,0,0,1};
    frame(7, 0, 0, goaway, sizeof(goaway));
    chunk = 1;
    assert(gateway_read_registration(&m, &noise) < 0);
    assert(strstr(m.transport_error, "GOAWAY error=1"));
    reset();
    memset(&m, 0, sizeof(m));
    frame(7, 0, 0, goaway, sizeof(goaway));
    chunk = 1;
    assert(gateway_read_map(&m, &noise, 3, true) < 0);
    assert(strstr(m.transport_error, "GOAWAY error=1"));
    reset();
    memset(&m, 0, sizeof(m));
    char big_registration[12000];
    memset(big_registration, 'x', sizeof(big_registration));
    memcpy(big_registration, "{\"Unused\":\"", 11);
    memcpy(big_registration + sizeof(big_registration) - 2, "\"}", 2);
    frame(0, 0, 1, (uint8_t *)big_registration, 6000);
    frame(0, 1, 1, (uint8_t *)big_registration + 6000, 6000);
    chunk = 512;
    assert(gateway_read_registration(&m, &noise) == sizeof(big_registration));
    assert(!memcmp(gateway_json, big_registration, sizeof(big_registration)));
    reset();
    frame(0, 9, 1, padded, sizeof(padded));
    assert(gateway_read_registration(&m, &noise) == 6);
    assert(!memcmp(gateway_json, map, 6));
    reset();
    frame(0, 9, 1, invalid_pad, sizeof(invalid_pad));
    assert(gateway_read_registration(&m, &noise) < 0);
    reset();
    frame(3, 0, 1, NULL, 0);
    assert(gateway_read_registration(&m, &noise) < 0);
    reset();
    frame(7, 0, 0, NULL, 0);
    assert(gateway_read_registration(&m, &noise) < 0);
    reset();
    frame(0, 0, 1, (uint8_t *)big_registration, 12000);
    frame(0, 0, 1, (uint8_t *)big_registration, 12000);
    frame(0, 1, 1, (uint8_t *)big_registration, 12000);
    assert(gateway_read_registration(&m, &noise) < 0);
    reset();
    memset(&m, 0, sizeof(m));
    m.config.map_callback = (void *)1;
    frame(0, 1, 3, map, sizeof(map));
    assert(gateway_read_map(&m, &noise, 3, true) == 0 && m.maps == 1);
    pthread_t a,b;assert(!pthread_create(&a,NULL,fragmented_membership,(void*)1));assert(!pthread_create(&b,NULL,fragmented_membership,(void*)2));pthread_join(a,NULL);pthread_join(b,NULL);
    puts("Concurrent fragmented maps preserve each membership's node and peer identity");
    return 0;
}
