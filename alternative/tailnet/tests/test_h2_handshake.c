#include "cJSON.h"
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define ML_NOISE_MAC_LEN 16
#define ML_H2_BUFFER_SIZE 65536
#define ESP_OK 0
#define ml_psram_malloc malloc
typedef int esp_err_t;
typedef struct { uint8_t rx_key[32]; uint64_t rx_nonce; } ml_noise_state_t;
typedef struct {
    uint8_t *server_extra_data, *h2_acc;
    int server_extra_data_len;
    size_t h2_acc_len;
    bool has_node_key_challenge;
    uint8_t node_key_challenge[32];
} microlink_t;
static int64_t esp_timer_get_time(void) { return 0; }
static void hex_to_bytes(const char *s, uint8_t *out, int n) { memset(out, 0, n); }
static int ml_noise_decrypt(uint8_t *key, uint64_t nonce, void *ad, size_t adlen,
    uint8_t *in, size_t n, uint8_t *out) { memcpy(out, in, n-16); return 0; }
static int ml_h2_build_preface(uint8_t *b, size_t n) {
    memset(b, 0, 39); memcpy(b, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
    b[26]=6; b[27]=4; return 39;
}
static int ml_h2_build_settings_ack(uint8_t *b, size_t n) {
    memset(b,0,9); b[3]=4; b[4]=1; return 9;
}
static int ml_h2_build_window_update(uint8_t *b, size_t n, int stream, uint32_t d) {
    memset(b,0,13); b[2]=4; b[3]=8; return 13;
}
static int noise_send(microlink_t *m, ml_noise_state_t *noise, uint8_t *b, size_t n) {
    assert(n >= 39);
    for (size_t p=24; p+9<=n;) {
        assert(!(b[p+3]==4 && b[p+4]==1)); // Never ACK an unseen SETTINGS.
        p += 9 + ((size_t)b[p]<<16) + ((size_t)b[p+1]<<8) + b[p+2];
    }
    return n;
}
#include "h2_handshake.inc"
static void add(microlink_t *m, const uint8_t *data, size_t n) {
    size_t p=m->server_extra_data_len;
    m->server_extra_data=realloc(m->server_extra_data,p+n+19);
    uint8_t *b=m->server_extra_data+p;
    b[0]=4; b[1]=(n+16)>>8; b[2]=n+16;
    memcpy(b+3,data,n); memset(b+3+n,0,16);
    m->server_extra_data_len=p+n+19;
}
int main(void) {
    const char *json="{\"nodeKeyChallenge\":\"chalpub:0000000000000000000000000000000000000000000000000000000000000000\"}";
    uint8_t header[9]={255,255,255,'T','S',0,0,0,0}; header[8]=strlen(json);
    uint8_t settings[15]={0,0,6,4,0,0,0,0,0,0,4,0,1,0,0};
    for (int proactive=0; proactive<2; proactive++) {
        microlink_t m={0}; ml_noise_state_t noise={0};
        add(&m,header,5); add(&m,header+5,4); add(&m,(const uint8_t *)json,strlen(json));
        if(proactive) add(&m,settings,sizeof(settings));
        process_proactive_frames(&m,&noise);
        assert(m.has_node_key_challenge && noise.rx_nonce == 3+proactive);
        assert(m.h2_acc_len == (proactive ? sizeof(settings) : 0));
        if(proactive) assert(!memcmp(m.h2_acc,settings,sizeof(settings)));
        assert(do_h2_preface(&m,&noise)==0);
        free(m.h2_acc);
    }
}
