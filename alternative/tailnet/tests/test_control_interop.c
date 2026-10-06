#define coord_alloc ml_psram_malloc
#include "cJSON.h"
#include "tdongle_memory.h"
#include "ml_gateway_limits.h"
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
    uint8_t wg_public_key[32],disco_public_key[32];
    uint8_t *h2_acc;
    size_t h2_acc_len;
    uint8_t stream_header[9], stream_special[56];
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
    char h2_debug[49];
    uint32_t map_h2_error, map_h2_last_stream;
    struct {
        void *map_callback;
    } config;
} microlink_t;
typedef int ml_noise_state_t;
#include <unistd.h>
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define ML_H2_BUFFER_SIZE 65536
#define ML_CTRL_PROTOCOL_VER 131
#define CTRL_HOST_HDR(ml) "localhost"
#define ml_psram_malloc malloc
static uint64_t now;
static uint64_t ml_get_time_ms(void) {return ++now;}
static int64_t esp_timer_get_time(void) {return 0;}
static void gateway_diag_record(const microlink_t *m,uint32_t event,uint32_t detail) {}
static unsigned settings_acks;
static int noise_recv_inplace(microlink_t *m,int *n,uint8_t *out,size_t capacity) {return read(STDIN_FILENO,out,capacity);}
static int noise_send(microlink_t *m,int *n,const uint8_t *data,size_t length) {
    if(length==9&&data[3]==4&&data[4]==1)settings_acks++;
    size_t used=0;while(used<length){ssize_t count=write(STDOUT_FILENO,data+used,length-used);if(count<=0)return -1;used+=count;}return 0;
}
static int noise_send_owned(microlink_t *m,int *n,uint8_t *data,size_t length,size_t capacity) {return noise_send(m,n,data,length);}
static void bytes_to_hex(const uint8_t *bytes,size_t n,char *out){for(size_t i=0;i<n;i++)sprintf(out+i*2,"%02x",bytes[i]);}
static cJSON *build_hostinfo(microlink_t *m){return cJSON_CreateObject();}
static void apply_long_poll_map(microlink_t *m,cJSON *map){assert(cJSON_IsObject(map));m->maps++;}
#include "h2_core.inc"
#include "h2_preface.inc"
#include "map_request.inc"
#include "../components/microlink/src/gateway_project.inc"
#include "../components/microlink/src/gateway_workspace.inc"
#include "../components/microlink/src/gateway_h2_close.inc"
#include "../components/microlink/src/gateway_register_response.inc"
#include "../components/microlink/src/gateway_stream.inc"
int main(int argc,char **argv) {
    microlink_t m={0};int noise=0;bool duplicate=argc>1;
    assert(!do_h2_preface(&m,&noise));
    if(duplicate){uint8_t ack[9];assert(ml_h2_build_settings_ack(ack,9)==9);assert(!noise_send(&m,&noise,ack,9));}
    uint8_t request[1024];int h=ml_h2_build_headers_frame(request,sizeof(request),"POST","/machine/register","localhost","application/json",1,false);
    int d=ml_h2_build_data_frame(request+h,sizeof(request)-h,(const uint8_t*)"{}",2,1,true);assert(h>0&&d>0&&!noise_send(&m,&noise,request,h+d));
    int registered=gateway_read_registration(&m,&noise);
    if(duplicate){assert(registered<0&&m.map_h2_error==1);fprintf(stderr,"Duplicate ACK rejected: GOAWAY code=%u\n",m.map_h2_error);return 0;}
    assert(registered==2&&!memcmp(gateway_json,"{}",2)&&settings_acks==1);
    assert(!do_start_long_poll(&m,&noise,false));
    assert(!gateway_read_map(&m,&noise,5,true)&&m.maps==1&&settings_acks==1);
    fprintf(stderr,"Production H2 preface, HPACK/request builders, SETTINGS handling, registration reader and map reader interoperated\n");
    return 0;
}
