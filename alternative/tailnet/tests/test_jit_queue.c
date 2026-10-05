/* The egress queue of ml_wg_mgr.c (ml_gateway_queue_packet, gateway_egress_packet, directory_flush_packets), extracted from the real
 * source and run against fakes. What it pins:
 *   - the producer builds the datagram in the transport layout (header space, plaintext, zero padding, tag space) in ONE
 *     pbuf, behind a small record in its headroom, and queues the pbuf (bit 0 set) itself: no other allocation, no copy later;
 *   - the per-membership budget (ML_JIT_PENDING, counting queued and parked packets), the heap reserve, every failure
 *     path gives back its pbuf and its budget;
 *   - a resident peer with a session is sent to in the same pass (no slot, no handshake call, no extra lookups); a peer
 *     whose session is down is parked and the handshake started; parked packets go out when the session comes up, are
 *     dropped when the peer disappears or after 5 s; ordering: a new packet never overtakes one parked for the same peer;
 *   - activation of a peer that is not resident goes through directory_activate with the generation bumped around it;
 *   - nothing leaks: every pbuf is freed exactly once. */
#include "tdongle_memory.h"
#define ROUTE_MARK(stage) ((void)0)
#define WGPERF_T(t) ((void)0)
#define WGPERF_LAP(t, s) ((void)0)
#define WGPERF_CHARGE(t, s) ((void)0)
#define WGPERF_ADD(s, v) ((void)0)
#define WGPERF_US_NOW() 7u
static unsigned counted_out_direct, counted_out_parked, counted_out_flushed, counted_out_discard, counted_wakes;
#define WGPERF_COUNT(c, n) do { counted_##c += (n); } while (0)
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
#define PBUF_TRANSPORT 0
#define PBUF_RAM 0
#define TDONGLE_LOCK_WG_OUTPUT 3
#define TDONGLE_LOCK_WG_COMMIT 2
#define ERR_OK 0
#define ERR_CONN -11
#define WIREGUARD_AUTHTAG_LEN 16
#define WIREGUARDIF_DATA_HDR 16
#define WIREGUARDIF_DATA_PAD(n) ((((size_t)(n)) + 15) & ~(size_t)15)
#define WIREGUARDIF_DATA_ALLOC(n) (WIREGUARDIF_DATA_HDR + WIREGUARDIF_DATA_PAD(n) + WIREGUARD_AUTHTAG_LEN)
typedef int esp_err_t;
typedef int err_t;
typedef uint16_t u16_t;
typedef uint8_t u8_t;
#define ML_JIT_PENDING 8
static unsigned wakes, lock_calls;
#define ML_RT_TASK_WG_MGR 2
static void ml_rt_wake(int t){assert(t==ML_RT_TASK_WG_MGR);wakes++;}
typedef struct {uint32_t network;uint8_t prefix_len;} microlink_route_t;
#include "semantic_types.inc"
typedef struct {uint32_t addr;} ip4_addr_t;
/* A pbuf that behaves like lwIP's RAM pbuf for the calls used: payload moves with add/remove header inside a block that
 * starts with 74 bytes of headroom, and every block is tracked. */
struct pbuf {uint8_t *payload;size_t tot_len,len;uint8_t *block;size_t headroom;};
static unsigned live_pbufs, alloc_calls, fail_pbuf_alloc;
static struct pbuf *pbuf_alloc(int layer,size_t n,int kind) {
    (void)layer;(void)kind;
    if(fail_pbuf_alloc)return NULL;
    struct pbuf *p=calloc(1,sizeof(*p));p->headroom=76;p->block=calloc(1,76+n);   /* LWIP_MEM_ALIGN_SIZE keeps the payload 4-aligned */
    p->payload=p->block+76;p->tot_len=p->len=n;live_pbufs++;alloc_calls++;return p;
}
static int pbuf_add_header(struct pbuf *p,size_t n){if((size_t)(p->payload-p->block)<n)return 1;p->payload-=n;p->tot_len+=n;p->len+=n;return 0;}
static int pbuf_remove_header(struct pbuf *p,size_t n){assert(p->len>=n);p->payload+=n;p->tot_len-=n;p->len-=n;return 0;}
static void pbuf_free(struct pbuf *p){assert(p && live_pbufs);live_pbufs--;free(p->block);free(p);}
struct netif {int unused;};
typedef struct {uint64_t jit_used_ms;uint32_t vpn_ip;bool active;int wg_peer_index;} ml_peer_t;
typedef struct {
    unsigned state,jit_packet_count,jit_dropped,jit_hits;uint32_t peer_generation;int peer_update_queue;
    struct {struct pbuf *packet;uint64_t expires;uint32_t vpn_ip;uint32_t seq;uint16_t len;} jit_pending[ML_JIT_PENDING];
    ml_peer_t peers[8];
    int peer_count;
    struct netif *wg_netif;
} microlink_t;
static bool reject,session_up[8],directory_has;static unsigned handshakes;static uint64_t now;
#define MALLOC_CAP_INTERNAL 1
#include "ml_heap_budget.h"
atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];
static size_t free_heap=1u<<20;
static size_t heap_caps_get_free_size(int caps){(void)caps;return free_heap;}
static void *queue[64];static unsigned queued;
static int xQueueSend(int q,void *entry,int wait) {
    (void)q;(void)wait;if(reject)return 0;assert(queued<64);queue[queued++]=*(void **)entry;return 1;
}
static uint64_t ml_get_time_ms(void){return now;}
static int find_peer_by_ip(microlink_t *m,uint32_t ip){for(int i=0;i<m->peer_count;i++)if(m->peers[i].active&&m->peers[i].vpn_ip==ip)return i;return -1;}
static bool ml_directory_find(microlink_t *m,uint32_t ip,const uint8_t *k,const uint8_t *d,uint64_t id,ml_peer_update_t *out){(void)m;(void)k;(void)d;(void)id;if(!directory_has)return false;out->vpn_ip=ip;return true;}
static unsigned activations;static uint32_t generation_during;
static int directory_activate(microlink_t *m,const ml_peer_update_t *r) {
    activations++;generation_during=m->peer_generation;
    int i=m->peer_count++;m->peers[i].active=true;m->peers[i].vpn_ip=r->vpn_ip;m->peers[i].wg_peer_index=i;return i;
}
static err_t wireguardif_peer_is_up(struct netif *n,u8_t idx,void *ip,void *port){(void)n;(void)ip;(void)port;return session_up[idx]?0:-1;}
static void ml_wg_mgr_trigger_handshake(microlink_t *m,uint32_t ip){(void)m;(void)ip;handshakes++;}
static struct {uint32_t ip;uint16_t len;uint8_t first[48];unsigned n;bool layout_ok;size_t tot_len;} out;
/* begin / seal / commit: the packet is "sent" at commit; begin and commit are the two lock holds, seal is outside them. */
struct wireguard_tx_job {struct pbuf *pbuf;uint16_t len;uint32_t ip;};
static unsigned seals,in_lock;static bool order_log_on;static unsigned order_n;static char order_log[16];static bool begin_refuses;
#define WG_LOCKED(site,body) do { lock_calls++; in_lock++; body; in_lock--; } while(0)
static int wireguardif_tx_begin(struct netif *n,struct pbuf *p,uint16_t len,const ip4_addr_t *ip,struct wireguard_tx_job *job,err_t *result) {
    (void)n;assert(in_lock==1);if(begin_refuses){*result=-1;return 0;}
    job->pbuf=p;job->len=len;job->ip=ntohl(ip->addr);*result=0;return 1;
}
static void wireguard_tx_seal(struct wireguard_tx_job *job){assert(in_lock==0 && job->pbuf);seals++;}   /* the seal is never under the lock */
static err_t wireguardif_tx_commit(struct netif *n,struct wireguard_tx_job *job) {
    (void)n;assert(in_lock==1);struct pbuf *p=job->pbuf;
    if(order_log_on)order_log[order_n++]=(char)((uint8_t *)p->payload)[16];
    out.ip=job->ip;out.len=job->len;out.n++;out.tot_len=p->tot_len;
    memcpy(out.first,p->payload,48<p->tot_len?48:p->tot_len);return 0;
}
typedef enum {WIREGUARD_DUMMY} dummy_t;
#include "jit_queue.inc"

static const uint8_t PLAIN[40]="0123456789abcdefghijklmnopqrstuvwxyzABC";
static void reset_out(void){memset(&out,0,sizeof(out));}
static void pump(microlink_t *m){ /* what process_peer_updates does for packet entries, in arrival order */
    for(unsigned i=0;i<queued;i++){assert(ml_pu_is_packet(queue[i]));gateway_egress_packet(m,ml_pu_packet(queue[i]));}
    queued=0;
}
#define IP1 0x64400001u
#define IP2 0x64400002u
int main(void) {
    microlink_t m={.state=4,.wg_netif=(struct netif *)1};
    struct netif net;m.wg_netif=&net;
    m.peer_count=2;m.peers[0]=(ml_peer_t){0,IP1,true,0};m.peers[1]=(ml_peer_t){0,IP2,true,1};
    /* --- producer: layout, budget, wake --- */
    for(unsigned len=1;len<=40;len+=13){
        assert(!ml_gateway_queue_packet(&m,IP1,PLAIN,len));
        struct pbuf *p=ml_pu_packet(queue[queued-1]);
        assert(ml_pu_is_packet(queue[queued-1]) && ((uintptr_t)p&1)==0);
        ml_egress_meta_t meta;memcpy(&meta,p->payload,sizeof(meta));
        assert(meta.vpn_ip==IP1 && meta.len==len && meta.enq_us==7);
        const uint8_t *wire=p->payload+sizeof(meta);
        assert(p->tot_len==sizeof(meta)+WIREGUARDIF_DATA_ALLOC(len));
        for(int i=0;i<16;i++)assert(wire[i]==0);                               /* header space: sealed later */
        assert(!memcmp(wire+16,PLAIN,len));
        for(size_t i=len;i<WIREGUARDIF_DATA_PAD(len)+16;i++)assert(wire[16+i]==0);   /* padding and tag space are zero */
        while(queued){pbuf_free(p);queued=0;m.jit_packet_count=0;}
    }
    assert(alloc_calls==4 && live_pbufs==0 && wakes==4);                           /* ONE allocation per packet */
    queued=0;m.jit_packet_count=0;wakes=0;alloc_calls=0;
    for(unsigned i=0;i<ML_JIT_PENDING;i++)assert(ml_gateway_queue_packet(&m,IP1,PLAIN,4)==0);
    assert(m.jit_packet_count==ML_JIT_PENDING && wakes==ML_JIT_PENDING && alloc_calls==ML_JIT_PENDING);
    assert(ml_gateway_queue_packet(&m,IP1,PLAIN,4)==ESP_ERR_NO_MEM && alloc_calls==ML_JIT_PENDING);   /* over budget: nothing allocated */
    /* --- consumer: session down parks and starts the handshake; nothing is sent --- */
    reset_out();handshakes=0;lock_calls=0;now=100;
    pump(&m);
    assert(!out.n && handshakes==ML_JIT_PENDING && m.jit_packet_count==ML_JIT_PENDING && live_pbufs==ML_JIT_PENDING);
    for(unsigned i=0;i<ML_JIT_PENDING;i++)assert(m.jit_pending[i].packet && m.jit_pending[i].vpn_ip==IP1 && m.jit_pending[i].len==4 && m.jit_pending[i].expires==5100);
    directory_flush_packets(&m);assert(!out.n && live_pbufs==ML_JIT_PENDING);   /* still down: kept */
    /* --- the session comes up: parked packets go out, slots and budget come back --- */
    session_up[0]=true;now=200;
    directory_flush_packets(&m);
    assert(out.n==ML_JIT_PENDING && out.ip==IP1 && out.len==4 && !m.jit_packet_count && !live_pbufs && lock_calls==2*ML_JIT_PENDING && seals==ML_JIT_PENDING);
    assert(m.peers[0].jit_used_ms==200);
    /* --- resident peer with a session: sent in the same pass, no slot, no handshake call, no flush needed --- */
    reset_out();handshakes=0;lock_calls=0;counted_out_direct=0;
    assert(!ml_gateway_queue_packet(&m,IP1,PLAIN,33));
    pump(&m);
    assert(out.n==1 && out.len==33 && out.tot_len==WIREGUARDIF_DATA_ALLOC(33) && !handshakes && !m.jit_packet_count && !live_pbufs && counted_out_direct==1);
    assert(!memcmp(out.first+16,PLAIN,33-0>32?32:33));
    for(unsigned i=0;i<ML_JIT_PENDING;i++)assert(!m.jit_pending[i].packet);
    assert(!(m.peer_generation&1) && m.peer_generation==0);                          /* a packet takes no part in the odd/even protocol */
    assert(m.jit_hits==1+ML_JIT_PENDING);
    /* --- ordering: a packet parked for a peer, then its session comes up: a NEW packet queues behind it, not ahead --- */
    session_up[1]=false;reset_out();
    assert(!ml_gateway_queue_packet(&m,IP2,(const uint8_t *)"A",1));pump(&m);assert(!out.n && m.jit_pending[0].packet);
    session_up[1]=true;
    assert(!ml_gateway_queue_packet(&m,IP2,(const uint8_t *)"B",1));pump(&m);
    assert(!out.n);                                                                  /* B waits behind A */
    directory_flush_packets(&m);
    assert(out.n==2 && !live_pbufs && !m.jit_packet_count);
    /* --- ordering across slot reuse: a freed low slot is taken by a newer packet; the flush still sends by arrival --- */
    {
        session_up[0]=false;session_up[1]=false;reset_out();
        const char *seq1[4]={"1","2","3","4"};
        uint32_t order_ip[4]={IP2,IP1,IP2,IP2};                /* slot 0: IP2 "1", slot 1: IP1 "2", slot 2: IP2 "3" */
        for(int i=0;i<3;i++){assert(!ml_gateway_queue_packet(&m,order_ip[i],(const uint8_t *)seq1[i],1));}
        pump(&m);
        session_up[0]=true;directory_flush_packets(&m);          /* IP1's packet in slot 1 goes; slots 0 and 2 stay */
        assert(out.n==1 && !m.jit_pending[1].packet && m.jit_pending[0].packet && m.jit_pending[2].packet);
        assert(!ml_gateway_queue_packet(&m,IP2,(const uint8_t *)"4",1));pump(&m);   /* the new one takes the free slot 1 */
        assert(m.jit_pending[1].packet && m.jit_pending[1].seq>m.jit_pending[2].seq);
        session_up[1]=true;reset_out();
        order_log_on=true;order_n=0;
        directory_flush_packets(&m);
        order_log_on=false;
        assert(order_n==3 && order_log[0]=='1' && order_log[1]=='3' && order_log[2]=='4');   /* 1,3,4 not 1,4,3 */
        assert(!live_pbufs && !m.jit_packet_count);
    }
    /* --- peers: unknown and not in the directory is dropped; in the directory is activated under the odd generation --- */
    reset_out();m.jit_dropped=0;counted_out_discard=0;
    assert(!ml_gateway_queue_packet(&m,0x64400009,PLAIN,4));pump(&m);
    assert(!out.n && m.jit_dropped==1 && !live_pbufs && !m.jit_packet_count && counted_out_discard==1);
    directory_has=true;activations=0;
    assert(!ml_gateway_queue_packet(&m,0x6440000a,PLAIN,4));pump(&m);
    assert(activations==1 && (generation_during&1) && !(m.peer_generation&1));       /* odd while activating, even after */
    assert(m.jit_pending[0].packet && m.jit_pending[0].vpn_ip==0x6440000a);          /* new session: parked until the handshake */
    directory_has=false;
    /* --- expiry: a packet whose peer never comes up goes after 5 s, and its pbuf with it --- */
    now+=4000;directory_flush_packets(&m);assert(m.jit_pending[0].packet);
    now+=2000;m.jit_dropped=0;directory_flush_packets(&m);
    assert(!m.jit_pending[0].packet && m.jit_dropped==1 && !live_pbufs && !m.jit_packet_count);
    /* --- the peer disappears while its packet is parked --- */
    session_up[1]=false;
    assert(!ml_gateway_queue_packet(&m,IP2,PLAIN,4));pump(&m);assert(m.jit_pending[0].packet);
    m.peers[1].active=false;m.jit_dropped=0;
    directory_flush_packets(&m);assert(!m.jit_pending[0].packet && m.jit_dropped==1 && !live_pbufs);
    m.peers[1].active=true;
    /* --- all slots busy and the peer not up: the 9th is dropped, not parked --- */
    session_up[0]=false;queued=0;m.jit_packet_count=0;
    for(unsigned i=0;i<ML_JIT_PENDING;i++){assert(!ml_gateway_queue_packet(&m,IP1,PLAIN,4));}
    pump(&m);assert(live_pbufs==ML_JIT_PENDING);
    for(unsigned i=0;i<ML_JIT_PENDING;i++)m.jit_pending[i].expires=0;   /* expire everything */
    directory_flush_packets(&m);assert(!live_pbufs && !m.jit_packet_count);
    /* --- failure paths give everything back --- */
    reject=true;assert(ml_gateway_queue_packet(&m,IP1,PLAIN,4)==ESP_ERR_NO_MEM);assert(!m.jit_packet_count && !live_pbufs);
    reject=false;fail_pbuf_alloc=1;assert(ml_gateway_queue_packet(&m,IP1,PLAIN,4)==ESP_ERR_NO_MEM);assert(!m.jit_packet_count && !live_pbufs);
    fail_pbuf_alloc=0;
    free_heap=ML_ADM_RECOVERY_BYTES+100;assert(ml_gateway_queue_packet(&m,1,PLAIN,4)==ESP_ERR_NO_MEM && !m.jit_packet_count);   /* never below the recovery reserve */
    /* the one elastic floor (ADR 0022): a refusal at the floor plus the packet's cost, an admission one byte above, each counted */
    {
        unsigned before=atomic_load(&ml_hb_refused[ML_HB_JIT]);
        size_t need=WIREGUARDIF_DATA_ALLOC(4)+sizeof(ml_egress_meta_t)+sizeof(struct pbuf)+64;
        free_heap=ML_HB_FLOOR+need-1;assert(ml_gateway_queue_packet(&m,IP1,PLAIN,4)==ESP_ERR_NO_MEM && !m.jit_packet_count && !live_pbufs);
        assert(atomic_load(&ml_hb_refused[ML_HB_JIT])==before+1);
        free_heap=ML_HB_FLOOR+need;
        session_up[0]=false;queued=0;assert(!ml_gateway_queue_packet(&m,IP1,PLAIN,4));assert(atomic_load(&ml_hb_refused[ML_HB_JIT])==before+1);
        pump(&m);for(unsigned i=0;i<ML_JIT_PENDING;i++)m.jit_pending[i].expires=0;directory_flush_packets(&m);assert(!live_pbufs && !m.jit_packet_count);
    }
    free_heap=1u<<20;
    assert(ml_gateway_queue_packet(&m,IP1,PLAIN,0)==ESP_ERR_INVALID_STATE && ml_gateway_queue_packet(&m,IP1,PLAIN,1401)==ESP_ERR_INVALID_STATE);
    m.state=0;assert(ml_gateway_queue_packet(&m,IP1,PLAIN,4)==ESP_ERR_INVALID_STATE);m.state=4;
    assert(!live_pbufs);
    puts("egress queue: one pbuf per packet in the transport layout, budget, direct send for an up session, parking, ordering, activation, expiry and cleanup passed");
}
