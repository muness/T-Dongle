#include "tdongle_memory.h"
#define ROUTE_MARK(stage) ((void)0)
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#define ML_MAX_ENDPOINTS 8
#define MICROLINK_MAX_PEER_ROUTES 8
#define ML_MAX_DERP_NODES 2
#define ML_MAX_DERP_REGIONS 4
#define ML_STATE_CONNECTED 4
#define ESP_ERR_INVALID_STATE -1
#define ESP_ERR_NO_MEM -2
#define ESP_OK 0
#define pdTRUE 1
#define PBUF_IP 0
#define PBUF_RAM 0
#define GATEWAY_WG_CALL(x) (x)
#define GATEWAY_WG_SITE(site,x) (x)
#define TDONGLE_LOCK_WG_OUTPUT 3
typedef int esp_err_t;
#define ML_JIT_PENDING 8
#define ML_RT_TASK_WG_MGR 2
static unsigned wakes;static void ml_rt_wake(int t){assert(t==ML_RT_TASK_WG_MGR);wakes++;}
typedef struct {uint32_t network;uint8_t prefix_len;} microlink_route_t;
#include "semantic_types.inc"
typedef struct {uint32_t addr;} ip4_addr_t;
struct pbuf {size_t len;uint8_t data[1400];};
struct netif {int (*output)(struct netif *,struct pbuf *,const ip4_addr_t *);};
typedef struct {
    unsigned state,jit_packet_count,jit_dropped;int peer_update_queue;
    struct {ml_peer_update_t *packet;uint64_t expires;} jit_pending[ML_JIT_PENDING];
    struct {uint64_t jit_used_ms;} peers[8];
    struct netif *wg_netif;
} microlink_t;
static bool reject,up,known=true;static unsigned queued,sends;static uint64_t now;
static ml_peer_update_t *queue[ML_JIT_PENDING];
static int xQueueSend(int q,void *packet,int wait) {
    if(reject)return 0;assert(queued<ML_JIT_PENDING);queue[queued++]=*(ml_peer_update_t **)packet;return 1;
}
static uint64_t ml_get_time_ms(void){return now;}
static int find_peer_by_ip(microlink_t *m,uint32_t ip){return known?0:-1;}
static bool ml_wg_mgr_peer_is_up(microlink_t *m,uint32_t ip){return up;}
static struct pbuf *pbuf_alloc(int layer,size_t n,int kind){struct pbuf *p=calloc(1,sizeof(*p));if(p)p->len=n;return p;}
static void pbuf_take(struct pbuf *p,const void *b,size_t n){memcpy(p->data,b,n);}
static void pbuf_free(struct pbuf *p){free(p);}
static int output(struct netif *n,struct pbuf *p,const ip4_addr_t *ip){assert(p->len==4 && !memcmp(p->data,"data",4));assert(ntohl(ip->addr)==0x64400001);sends++;return 0;}
#include "jit_queue.inc"
int main(void) {
    struct netif net={output};microlink_t m={.state=4,.wg_netif=&net};
    for(unsigned i=0;i<ML_JIT_PENDING;i++)assert(ml_gateway_queue_packet(&m,0x64400001,(const uint8_t *)"data",4)==0);
    assert(m.jit_packet_count==ML_JIT_PENDING && wakes==ML_JIT_PENDING);   /* every enqueue wakes the manager */assert(ml_gateway_queue_packet(&m,0x64400001,(const uint8_t *)"data",4)==ESP_ERR_NO_MEM);
    for(unsigned i=0;i<ML_JIT_PENDING;i++)m.jit_pending[i].packet=queue[i],m.jit_pending[i].expires=5000;
    directory_flush_packets(&m);assert(!sends && m.jit_packet_count==ML_JIT_PENDING);
    up=true;now=100;directory_flush_packets(&m);assert(sends==ML_JIT_PENDING && !m.jit_packet_count);
    queued=0;reject=true;assert(ml_gateway_queue_packet(&m,1,(const uint8_t *)"data",4)==ESP_ERR_NO_MEM);assert(!m.jit_packet_count);
    reject=false;assert(!ml_gateway_queue_packet(&m,0x64400001,(const uint8_t *)"data",4));m.jit_pending[0].packet=queue[0];m.jit_pending[0].expires=101;
    now=102;directory_flush_packets(&m);assert(!m.jit_packet_count && m.jit_dropped==1 && sends==ML_JIT_PENDING);
    puts("JIT packet queue: per-membership cap, retained until handshake, rejection cleanup and timeout passed");
}
