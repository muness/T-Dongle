#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#define pdTRUE 1
struct netif {int id;};
struct pbuf {size_t tot_len;uint8_t data[20];bool freed;};
static struct netif usb,other;
static void *usb_interface=&usb;
static atomic_uint usb_generation=1;
static bool routes_ready=true,queue_accept=true;
static int route_queue=1;
static unsigned queued,processed;
typedef struct {struct pbuf *packet;struct netif *input;unsigned generation;} route_item;
static void *esp_netif_get_netif_impl(void *handle){return handle;}
static int pbuf_copy_partial(struct pbuf *p,void *out,size_t n,size_t offset){assert(n==20 && !offset);if(p->tot_len<20)return 0;memcpy(out,p->data,n);return n;}
static uint32_t rd32(const uint8_t *p){return (uint32_t)p[0]<<24|p[1]<<16|p[2]<<8|p[3];}
static void pbuf_free(struct pbuf *p){assert(!p->freed);p->freed=true;}
static int xQueueSend(int q,route_item *item,int wait){assert(!wait && item->generation==atomic_load(&usb_generation));if(!queue_accept)return 0;queued++;return 1;}
static int gateway_process_host_input(struct pbuf *p,struct netif *input){processed++;return 0;}
#include "route_ingress.inc"
int main(void) {
    const size_t lengths[]={20,1400,1401,1500,65535};
    for(unsigned i=0;i<5;i++)for(unsigned accept=0;accept<2;accept++) {
        queue_accept=accept;queued=processed=0;
        struct pbuf p={.tot_len=lengths[i]};p.data[16]=198;p.data[17]=18;p.data[19]=65;
        assert(gateway_host_input(&p,&usb)==1 && !processed);
        assert(queued==(accept && lengths[i]<=1400));assert(p.freed==!queued);
    }
    routes_ready=false;struct pbuf p={.tot_len=40};p.data[16]=198;p.data[17]=18;
    assert(gateway_host_input(&p,&usb)==1 && p.freed);
    p.freed=false;p.data[16]=192;p.data[17]=168;
    assert(!gateway_host_input(&p,&usb) && !p.freed); // ordinary Internet stays on lwIP
    puts("Ingress: oversized synthetic packets never run flash/routing work on lwIP; bounded queue owns or frees exactly once");
}
