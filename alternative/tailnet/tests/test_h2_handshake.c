#include "tdongle_memory.h"
#define coord_alloc ml_psram_malloc
#include "cJSON.h"
#include "mbedtls/chachapoly.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define ESP_OK 0
#define ML_H2_BUFFER_SIZE 65536
#define ml_psram_malloc malloc
#define pdMS_TO_TICKS(n) (n)
#include "noise_aead.inc"
typedef struct { uint8_t rx_key[32]; uint64_t rx_nonce; } ml_noise_state_t;
typedef struct {
    uint8_t wire[2048], *h2_acc;
    size_t length, position, split, chunk, h2_acc_len;
    bool paused, has_node_key_challenge, truncate;
    uint8_t node_key_challenge[32];
    unsigned noise_error, noise_frame_bytes, delays;
    uint32_t read_expected,read_received,read_elapsed_ms,read_errno;int32_t read_tls_result,conn_tls_result;
} microlink_t;
static atomic_uint_fast64_t ticks;
static int64_t esp_timer_get_time(void) { return atomic_fetch_add(&ticks,1000); }
static void vTaskDelay(unsigned n) { atomic_fetch_add(&ticks,n*1000); }
static int ml_conn_read(microlink_t *m,uint8_t *b,size_t n) {
    if(m->position==m->split && !m->paused) {m->paused=true;errno=EAGAIN;return -1;}
    if(m->delays) {m->delays--;errno=EAGAIN;return -1;}
    if(m->position==m->length) {errno=EAGAIN;return m->truncate?0:-1;}
    size_t left=m->length-m->position;if(n>left)n=left;
    if(n>m->chunk)n=m->chunk;
    if(m->position<m->split && n>m->split-m->position)n=m->split-m->position;
    memcpy(b,m->wire+m->position,n);m->position+=n;return n;
}
static int ml_noise_decrypt(const uint8_t *k,uint64_t nonce,const uint8_t *ad,size_t an,const uint8_t *in,size_t n,uint8_t *out) {
    return chacha20poly1305_decrypt(k,nonce,ad,an,in,n,out);
}
static void hex_to_bytes(const char *s,uint8_t *b,int n) {
    for(int i=0;i<n;i++){unsigned v;assert(sscanf(s+i*2,"%2x",&v)==1);b[i]=v;}
}
static int ml_noise_read_msg2(ml_noise_state_t *n,const uint8_t *payload,size_t length) {
    assert(length==48&&payload[0]==0x55&&payload[47]==0x55);return 0;
}
#include "receive_core.inc"
#include "../components/microlink/src/gateway_handshake.inc"
#include "h2_core.inc"
static int noise_send(microlink_t *m,ml_noise_state_t *noise,const uint8_t *b,size_t n) {
    assert(n>=39);
    for(size_t p=24;p+9<=n;){assert(!(b[p+3]==4 && b[p+4]==1));p+=9+((size_t)b[p]<<16)+((size_t)b[p+1]<<8)+b[p+2];}
    return 0;
}
#include "h2_preface.inc"
static void record(microlink_t *m,ml_noise_state_t *n,const uint8_t *b,size_t length,uint64_t nonce) {
    size_t p=m->length;assert(p+length+19<=sizeof(m->wire));
    m->wire[p]=4;m->wire[p+1]=(length+16)>>8;m->wire[p+2]=length+16;
    assert(!chacha20poly1305_encrypt(n->rx_key,nonce,NULL,0,b,length,m->wire+p+3));
    m->length+=length+19;
}
static const char *json="{\"nodeKeyChallenge\":\"chalpub:0101010101010101010101010101010101010101010101010101010101010101\"}";
static const uint8_t settings[15]={0,0,6,4,0,0,0,0,0,0,4,0,1,0,0};
static unsigned prepare(microlink_t *m,ml_noise_state_t *noise,size_t plaintext_split) {
    *m=(microlink_t){.chunk=4096,.split=SIZE_MAX};
    const char *upgrade="HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n";
    memcpy(m->wire,upgrade,strlen(upgrade));m->length=strlen(upgrade);
    uint8_t msg2[51]={2,0,48};memset(msg2+3,0x55,48);memcpy(m->wire+m->length,msg2,51);m->length+=51;
    uint8_t plain[200]={255,255,255,'T','S',0,0,0,0};plain[8]=strlen(json);
    memcpy(plain+9,json,strlen(json));size_t end=9+strlen(json);
    memcpy(plain+end,settings,sizeof(settings));
    if(plaintext_split){record(m,noise,plain,plaintext_split,0);record(m,noise,plain+plaintext_split,end+15-plaintext_split,1);return 2;}
    record(m,noise,plain,end+15,0);return 1;
}
static void check(microlink_t *m,ml_noise_state_t *noise,unsigned frames) {
    assert(!gateway_read_upgrade(m));
    assert(!gateway_read_msg2(m,noise));
    m->delays=3;assert(!do_h2_preface(m,noise));assert(!gateway_read_early(m,noise));
    assert(m->has_node_key_challenge&&m->node_key_challenge[0]==1);
    uint8_t retained[4096];size_t used=m->h2_acc_len;assert(used<=15);
    if(used)memcpy(retained,m->h2_acc,used);
    if(used<15){int length=noise_recv_inplace(m,noise,retained+used,sizeof(retained)-used);assert(length==15-used);used+=length;}
    assert(used==15&&!memcmp(retained,settings,15));
    assert(noise->rx_nonce==frames&&m->position==m->length);free(m->h2_acc);
}
static void *identity(void *arg) {
    for(unsigned i=0;i<60;i++){ml_noise_state_t n={.rx_key={(uintptr_t)arg}};microlink_t m;
        unsigned frames=prepare(&m,&n,1+i%100);m.chunk=1+i%19;check(&m,&n,frames);}
    return NULL;
}
int main(void) {
    for(size_t split=0;split<500;split++){ml_noise_state_t n={.rx_key={1}};microlink_t m;unsigned frames=prepare(&m,&n,5);
        if(split>m.length)break;m.split=split;check(&m,&n,frames);}
    for(size_t split=1;split<9+strlen(json)+15;split++){ml_noise_state_t n={.rx_key={2}};microlink_t m;unsigned frames=prepare(&m,&n,split);m.chunk=1;check(&m,&n,frames);}
    // Failed authentication and truncated ciphertext never advance the nonce.
    ml_noise_state_t n={.rx_key={3}};microlink_t m={.chunk=1,.split=SIZE_MAX};record(&m,&n,settings,15,0);m.wire[m.length-1]^=1;
    assert(gateway_read_early(&m,&n)<0&&m.noise_error==6&&n.rx_nonce==0&&errno==EBADMSG);
    m=(microlink_t){.chunk=1,.split=SIZE_MAX,.truncate=true};record(&m,&n,settings,15,0);m.length-=1;
    assert(gateway_read_early(&m,&n)<0&&m.noise_error==5&&n.rx_nonce==0&&errno==ECONNRESET);
    // A wrong msg2 declaration is rejected without consuming an unknown payload.
    m=(microlink_t){.chunk=1,.split=SIZE_MAX,.length=3};m.wire[0]=2;m.wire[2]=49;
    assert(gateway_read_msg2(&m,&n)<0&&errno==EPROTO&&m.position==3);
    // Missing EarlyNoise (custom coordinator) retains an ordinary H2 SETTINGS.
    m=(microlink_t){.chunk=1,.split=SIZE_MAX};record(&m,&n,settings,15,0);
    assert(!gateway_read_early(&m,&n)&&!m.has_node_key_challenge&&m.h2_acc_len==15);free(m.h2_acc);
    // Declared early length is enforced, rather than searching for a '{'.
    n.rx_nonce=0;m=(microlink_t){.chunk=1,.split=SIZE_MAX};uint8_t huge[9]={255,255,255,'T','S',0,0,4,1};record(&m,&n,huge,9,0);
    assert(gateway_read_early(&m,&n)<0&&errno==EMSGSIZE);
    pthread_t a,b;assert(!pthread_create(&a,NULL,identity,(void*)1));assert(!pthread_create(&b,NULL,identity,(void*)2));pthread_join(a,NULL);pthread_join(b,NULL);
    puts("Handshake: every TCP split, early plaintext split, delays, authentication, truncation and independent sessions passed");
}
