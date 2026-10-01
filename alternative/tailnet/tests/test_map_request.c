#include "cJSON.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define ML_CTRL_PROTOCOL_VER 131
#define CTRL_HOST_HDR(ml) "controlplane.tailscale.com"
#define ESP_LOGI(...) ((void)0)
typedef struct {uint8_t wg_public_key[32],disco_public_key[32];} microlink_t;
typedef int ml_noise_state_t;
static void bytes_to_hex(const uint8_t *bytes,size_t n,char *out){for(size_t i=0;i<n;i++)sprintf(out+i*2,"%02x",bytes[i]);}
static cJSON *build_hostinfo(microlink_t *m){return cJSON_CreateObject();}
static void *ml_psram_malloc(size_t n){return malloc(n);}
static cJSON *request;
static int ml_h2_build_headers_frame(uint8_t *b,size_t cap,const char *method,const char *path,const char *host,const char *type,uint32_t stream,bool end){assert(!strcmp(path,"/machine/map")&&stream==5);memset(b,0,9);return 9;}
static int ml_h2_build_data_frame(uint8_t *b,size_t cap,uint8_t *json,size_t len,uint32_t stream,bool end){assert(stream==5&&end);request=cJSON_ParseWithLength((char*)json,len+1);assert(request);return 9;}
static int noise_send_owned(microlink_t *m,int *noise,uint8_t *b,size_t n,size_t capacity){assert(capacity>=n+16);return 0;}
#include "map_request.inc"
int main(void){microlink_t m={0};int noise=0;
    assert(do_start_long_poll(&m,&noise,false)==0);assert(cJSON_IsTrue(cJSON_GetObjectItem(request,"Stream")));assert(cJSON_IsFalse(cJSON_GetObjectItem(request,"OmitPeers")));assert(cJSON_GetObjectItem(request,"Hostinfo"));cJSON_Delete(request);
    assert(do_start_long_poll(&m,&noise,true)==0);assert(cJSON_IsTrue(cJSON_GetObjectItem(request,"OmitPeers")));cJSON_Delete(request);
    return 0;
}
