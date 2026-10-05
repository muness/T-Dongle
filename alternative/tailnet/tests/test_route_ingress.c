#define tdongle_memory_drop tdongle_memory_drop_stock /* the stock no-op is replaced by a counting one below */
#include "tdongle_memory.h"
#undef tdongle_memory_drop
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../main/route_table.c"
#define pdTRUE 1
struct netif {int id;};
#define PBUF_FLAG_LLBCAST 0x02
#define PBUF_FLAG_LLMCAST 0x04
struct pbuf {size_t tot_len;uint8_t data[20];bool freed;uint8_t flags;};
static unsigned activity_notes;
static void tdongle_pm_note_activity(void){activity_notes++;}
static struct netif usb,other;
static void *usb_interface=&usb;
static atomic_uint usb_generation=1;
static bool routes_ready=true,queue_accept=true;
static int route_queue=1;
static unsigned queued,processed,drops;
static atomic_uint route_queued_bytes,route_held_bytes,route_budget=ROUTE_QUEUE_BYTES;
typedef struct {struct pbuf *packet;struct netif *input;unsigned generation,length;} route_item;
static void *esp_netif_get_netif_impl(void *handle){return handle;}
static int pbuf_copy_partial(struct pbuf *p,void *out,size_t n,size_t offset){assert(n==20 && !offset);if(p->tot_len<20)return 0;memcpy(out,p->data,n);return n;}
static uint32_t rd32(const uint8_t *p){return (uint32_t)p[0]<<24|p[1]<<16|p[2]<<8|p[3];}
static void pbuf_free(struct pbuf *p){assert(!p->freed);p->freed=true;}
static int xQueueSend(int q,route_item *item,int wait){assert(!wait && item->generation==atomic_load(&usb_generation));if(!queue_accept)return 0;queued++;return 1;}
static int gateway_process_host_input(struct pbuf *p,struct netif *input){processed++;return 0;}
static void tdongle_memory_drop(tdongle_drop where){assert(where==TDONGLE_DROP_ROUTER_INGRESS);drops++;}
#include "route_ingress.inc"
static struct pbuf packet(size_t length,bool df) {
    struct pbuf p={.tot_len=length};p.data[0]=0x45;p.data[6]=df?0x40:0;p.data[16]=198;p.data[17]=18;p.data[19]=65;return p;
}
int main(void) {
    /* The forwarding-activity hold (ADR 0016): every unicast packet through the hook raises the clock request,
     * link-layer broadcast and multicast (neighbours' chatter) does not. */
    {
        struct pbuf u=packet(100,true),b=packet(100,true),m=packet(100,true);b.flags=PBUF_FLAG_LLBCAST;m.flags=PBUF_FLAG_LLMCAST;
        activity_notes=0;gateway_host_input(&u,&other);assert(activity_notes==1 && processed==1);
        gateway_host_input(&b,&other);gateway_host_input(&m,&usb);assert(activity_notes==1);   /* not counted, still handled */
        struct pbuf q=packet(100,true);gateway_host_input(&q,&usb);assert(activity_notes==2);   /* the USB route path notes too */
        processed=queued=0;atomic_store(&route_queued_bytes,0);
    }
    /* Oversized packets: without DF they are dropped on lwIP (they could only be
     * fragmented, and fragments are rejected); with DF they are queued so that
     * usb_routes can answer with ICMP fragmentation-needed. Nothing routes on lwIP. */
    const size_t lengths[]={20,1400,1401,1500,65535};
    for(unsigned i=0;i<5;i++)for(unsigned accept=0;accept<2;accept++)for(unsigned df=0;df<2;df++) {
        queue_accept=accept;queued=processed=drops=0;atomic_store(&route_queued_bytes,0);
        struct pbuf p=packet(lengths[i],df);
        bool oversize=lengths[i]>ROUTE_MTU;
        bool fits=lengths[i]<=ROUTE_QUEUE_BYTES;
        assert(gateway_host_input(&p,&usb)==1 && !processed);
        bool expect=accept && (!oversize || df) && fits;
        assert(queued==expect);assert(p.freed==!expect);assert(drops==!expect);
        assert(atomic_load(&route_queued_bytes)==(expect?lengths[i]:0)); /* a refused packet is never left counted */
    }
    /* Overflow accounting: every refused packet is counted exactly once, bytes
     * stay within the budget, and a consumer draining the queue frees room. */
    queue_accept=true;queued=drops=0;atomic_store(&route_queued_bytes,0);
    unsigned accepted=0,refused=0;
    for(unsigned i=0;i<64;i++) {
        struct pbuf p=packet(1400,true);
        gateway_host_input(&p,&usb);
        if(p.freed)refused++;else accepted++;
        assert(atomic_load(&route_queued_bytes)<=ROUTE_QUEUE_BYTES);
    }
    assert(accepted==ROUTE_QUEUE_BYTES/1400 && refused==64-accepted && drops==refused && queued==accepted);
    assert(atomic_load(&rt_stats[RT_STAT_QUEUE_FULL])>=refused);
    atomic_fetch_sub(&route_queued_bytes,1400*2); /* the consumer takes two */
    for(unsigned i=0;i<3;i++) {
        struct pbuf p=packet(1400,true);
        gateway_host_input(&p,&usb);
        assert(p.freed==(i>=2));
    }
    /* Packets parked for a cache fill are charged to the same budget. */
    atomic_store(&route_queued_bytes,0);atomic_store(&route_held_bytes,2000);
    {struct pbuf p=packet(ROUTE_QUEUE_BYTES-2000,true);gateway_host_input(&p,&usb);assert(!p.freed);atomic_fetch_sub(&route_queued_bytes,p.tot_len);}
    {struct pbuf p=packet(ROUTE_QUEUE_BYTES-2000+1,true);gateway_host_input(&p,&usb);assert(p.freed);}
    atomic_store(&route_held_bytes,0);
    /* The budget can shrink with the heap: nothing above it is admitted. */
    atomic_store(&route_queued_bytes,0);atomic_store(&route_budget,3000);
    {struct pbuf p=packet(1400,true),q=packet(1400,true),r=packet(1400,true);gateway_host_input(&p,&usb);gateway_host_input(&q,&usb);gateway_host_input(&r,&usb);assert(!p.freed&&!q.freed&&r.freed);}
    atomic_store(&route_budget,ROUTE_QUEUE_BYTES);atomic_store(&route_queued_bytes,0);
    /* A full queue refuses small packets too, and counts each one. */
    queue_accept=false;drops=0;atomic_store(&route_queued_bytes,0);
    for(unsigned i=0;i<10;i++) {struct pbuf p=packet(60,false);gateway_host_input(&p,&usb);assert(p.freed);}
    assert(drops==10 && atomic_load(&route_queued_bytes)==0);
    queue_accept=true;
    routes_ready=false;struct pbuf p=packet(40,false);
    assert(gateway_host_input(&p,&usb)==1 && p.freed);
    p.freed=false;p.data[16]=192;p.data[17]=168;
    assert(!gateway_host_input(&p,&usb) && !p.freed); // ordinary Internet stays on lwIP
    puts("Ingress: oversized synthetic packets never run flash/routing work on lwIP; bounded queue owns or frees exactly once and counts every refusal");
}
