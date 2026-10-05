#include "tdongle_memory.h"
/* Activation on an unauthenticated claim: a forged DERP source key or DISCO
 * sender key must not buy a peer slot, evict a warm peer, or cost more than a
 * bounded amount of work, while a genuine peer is still activated.
 *
 * The decision code under test is the real code from ml_wg_mgr.c (sliced by
 * tools/test-gateway.sh); WireGuard itself is replaced by a stub that reports
 * which peers "authenticated". */
#define ROUTE_MARK(stage) ((void)0)
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define ML_MAX_PEERS 8
#define ML_MAX_ENDPOINTS 8
#define MICROLINK_MAX_PEER_ROUTES 8
#define ML_MAX_DERP_NODES 2
#define ML_MAX_DERP_REGIONS 4
#define NACL_BOX_MACBYTES 16
typedef struct {uint32_t network;uint8_t prefix_len;} microlink_route_t;
#include "semantic_types.inc"
typedef struct microlink_s microlink_t;
#include "ml_directory.h"
typedef struct {uint8_t *data;size_t len;bool via_derp;uint8_t src_pubkey[32];} ml_rx_packet_t;
typedef struct {
    bool active,unconfirmed,disco_shared_valid;uint64_t jit_used_ms,node_id;uint32_t vpn_ip;
    bool is_exit_node;uint8_t subnet_route_count;microlink_route_t subnet_routes[8];
    uint8_t public_key[32],disco_key[32];
} peer_state;
typedef peer_state ml_peer_t;
struct microlink_s {
    struct {uint8_t pending,tokens;uint64_t refill_ms,deadline_ms,cooldown_until_ms;uint32_t started,confirmed,expired,refused;} inbound_trial;
    uint32_t jit_hits,jit_misses,jit_evictions,jit_rejected,jit_dropped;
    uint8_t wg_public_key[32];ml_directory_t directory;uint32_t directory_applied;
    struct {uint32_t priority_peer_ip;} config;
    peer_state peers[8];
};
#define ML_DIRECTORY_HOST_TEST 1
#define ROOT "/tmp/tdongle-inbound-trial"
#include "../components/microlink/src/ml_directory.c"
static uint64_t now;
static uint64_t ml_get_time_ms(void){return now;}
static int find_peer_by_key(microlink_t *m,const uint8_t *key) {
    for(unsigned i=0;i<8;i++)if(m->peers[i].active && !memcmp(m->peers[i].public_key,key,32))return i;
    return -1;
}
static int find_peer_by_disco_key(microlink_t *m,const uint8_t *key) {
    for(unsigned i=0;i<8;i++)if(m->peers[i].active && !memcmp(m->peers[i].disco_key,key,32))return i;
    return -1;
}
static unsigned removals;
static void remove_peer(microlink_t *m,const ml_peer_update_t *u) {
    int i=find_peer_by_key(m,u->public_key);if(i>=0){memset(&m->peers[i],0,sizeof(m->peers[i]));removals++;}
}
static int add_peer(microlink_t *m,const ml_peer_update_t *u) {
    for(unsigned i=0;i<8;i++)if(!m->peers[i].active) {
        peer_state *p=&m->peers[i];p->active=true;p->unconfirmed=false;p->vpn_ip=u->vpn_ip;p->node_id=u->node_id;
        memcpy(p->public_key,u->public_key,32);memcpy(p->disco_key,u->disco_key,32);return i;
    }
    return -1;
}
static bool pool_ok=true; /* the global WireGuard slot pool (peer_pool_reserve) */
static bool peer_pool_reserve(microlink_t *m,uint64_t idle_ms){(void)m;(void)idle_ms;return pool_ok;}
static void apply_peer_update(microlink_t *m,const ml_peer_update_t *u) {}

/* WireGuard stand-ins. */
static bool initiation_looks_valid;           /* result of the size/type/mac1 screen */
static bool authenticated[8];                 /* peers WireGuard has authenticated */
static unsigned disco_boxes_opened;
static uint8_t disco_signers[8][32];          /* disco keys whose private key the "sender" holds */
static unsigned disco_signer_count;
static bool wg_peer_authenticated(microlink_t *m,int idx){return authenticated[idx];}
static bool wg_initiation_plausible(microlink_t *m,const ml_rx_packet_t *p){return initiation_looks_valid;}
static bool disco_authenticates(microlink_t *m,const uint8_t *k,const uint8_t *n,const uint8_t *c,size_t l) {
    disco_boxes_opened++;
    for(unsigned i=0;i<disco_signer_count;i++)if(!memcmp(disco_signers[i],k,32))return true;
    return false;
}
#include "jit_activation.inc"

static ml_peer_update_t record(unsigned id) {
    ml_peer_update_t u={.action=ML_PEER_ADD,.vpn_ip=0x64400000+id,.node_id=id,.has_node_id=true};
    memcpy(u.public_key,&id,4);memcpy(u.disco_key,&id,4);u.disco_key[31]=1;return u;
}
static ml_rx_packet_t packet(unsigned id) {
    ml_rx_packet_t p={.len=148,.via_derp=true};memcpy(p.src_pubkey,&id,4);return p;
}
static unsigned resident(microlink_t *m) {unsigned n=0;for(unsigned i=0;i<8;i++)n+=m->peers[i].active;return n;}
static void fill(microlink_t *m,unsigned first,unsigned count,uint64_t used) {
    for(unsigned i=0;i<count;i++){ml_peer_update_t u=record(first+i);int idx=add_peer(m,&u);assert(idx>=0);m->peers[idx].jit_used_ms=used;}
}
static void reset(microlink_t *m) {
    ml_directory_t d=m->directory;memset(m,0,sizeof(*m));m->directory=d;
    memset(authenticated,0,sizeof(authenticated));disco_signer_count=0;disco_boxes_opened=0;
    initiation_looks_valid=true;removals=0;
}

int main(void) {
    mkdir(ROOT,0700);microlink_t m={.wg_public_key={4}};
    assert(ml_directory_begin(&m));
    for(unsigned i=1;i<=40;i++){ml_peer_update_t u=record(i);assert(ml_directory_stage(&m,2,&u));}
    assert(ml_directory_commit(&m,true));
    ml_directory_t dir=m.directory;

    /* 1. A forged DERP key that is not an initiation never reaches the directory or a slot. */
    reset(&m);now=100000;initiation_looks_valid=false;
    for(unsigned i=1;i<=40;i++){ml_rx_packet_t p=packet(i);assert(derp_sender_admit(&m,&p)<0);}
    assert(resident(&m)==0 && !m.inbound_trial.started && !m.inbound_trial.pending);

    /* 2. A plausible initiation naming a key that is in no directory: refused, nothing activated. */
    reset(&m);now=100000;
    {ml_rx_packet_t p=packet(9999);assert(derp_sender_admit(&m,&p)<0);}
    assert(resident(&m)==0 && !m.inbound_trial.pending);

    /* 3. A forged initiation for a real directory peer gets a trial slot, not standing. */
    reset(&m);now=100000;
    {ml_rx_packet_t p=packet(5);int idx=derp_sender_admit(&m,&p);assert(idx>=0);
     assert(m.peers[idx].unconfirmed && m.inbound_trial.pending==idx+1 && m.inbound_trial.started==1);
     /* While it is pending no other unknown key gets in, however plausible. */
     ml_rx_packet_t q=packet(6);assert(derp_sender_admit(&m,&q)<0);
     assert(resident(&m)==1 && m.inbound_trial.refused>=1);
     /* WireGuard never authenticates it: it is removed at the deadline, the slot is free, and a cool-down follows. */
     now+=4999;directory_trial_poll(&m);assert(resident(&m)==1);
     now+=1;directory_trial_poll(&m);assert(resident(&m)==0 && removals==1 && m.inbound_trial.expired==1 && !m.inbound_trial.pending);
     now+=1000;assert(derp_sender_admit(&m,&q)<0 && resident(&m)==0);           /* cool-down */
     now+=29000;idx=derp_sender_admit(&m,&q);assert(idx>=0 && m.peers[idx].unconfirmed);} /* over */

    /* 4. The genuine peer: WireGuard authenticates the initiation, the trial becomes an ordinary peer. */
    reset(&m);now=100000;
    {ml_rx_packet_t p=packet(7);int idx=derp_sender_admit(&m,&p);assert(idx>=0 && m.peers[idx].unconfirmed);
     authenticated[idx]=true;directory_trial_poll(&m);
     assert(!m.peers[idx].unconfirmed && !m.inbound_trial.pending && m.inbound_trial.confirmed==1);
     now+=60000;directory_trial_poll(&m);assert(m.peers[idx].active);             /* never expires */
     ml_rx_packet_t q=packet(8);assert(derp_sender_admit(&m,&q)>=0);              /* slot free for the next */
     assert(derp_sender_admit(&m,&p)==idx);}                                     /* resident: no trial */

    /* 5. A forged key never evicts a warm peer. */
    reset(&m);now=100000;fill(&m,1,8,now-1000);                                  /* all hot */
    {ml_rx_packet_t p=packet(20);assert(derp_sender_admit(&m,&p)<0 && resident(&m)==8 && removals==0);}
    reset(&m);now=100000;fill(&m,1,8,now-20000);                                 /* idle 20 s: evictable for the host, not for a claim */
    {ml_rx_packet_t p=packet(20);assert(derp_sender_admit(&m,&p)<0 && resident(&m)==8 && removals==0);}
    reset(&m);now=100000;fill(&m,1,8,now-61000);m.peers[3].jit_used_ms=now-90000; /* idle a minute: one cold peer may go */
    {ml_rx_packet_t p=packet(20);int idx=derp_sender_admit(&m,&p);assert(idx==3 && removals==1 && resident(&m)==8);
     assert(m.peers[idx].unconfirmed);}
    reset(&m);now=100000;fill(&m,1,8,now-1000);                                  /* the authenticated path is unchanged */
    {ml_peer_update_t u=record(20);assert(directory_activate(&m,&u)<0);
     for(unsigned i=0;i<8;i++)m.peers[i].jit_used_ms=now-20000;
     assert(directory_activate(&m,&u)>=0 && removals==1);}

    /* 6. The priority peer is never the victim of a trial. */
    reset(&m);now=100000;fill(&m,1,8,now-90000);m.config.priority_peer_ip=record(1).vpn_ip;
    {ml_rx_packet_t p=packet(30);int idx=derp_sender_admit(&m,&p);assert(idx>=0 && idx!=0 && m.peers[0].active);}

    /* 7. Lookups an unauthenticated packet can cause are budgeted: a burst of 3, then one a second. */
    reset(&m);now=100000;
    {for(unsigned i=0;i<3;i++){ml_rx_packet_t p=packet(9000+i);assert(derp_sender_admit(&m,&p)<0);}
     assert(m.inbound_trial.refused==0 && m.inbound_trial.tokens==0);            /* three lookups reached the directory */
     ml_rx_packet_t p=packet(5);assert(derp_sender_admit(&m,&p)<0 && m.inbound_trial.refused==1); /* even a real key waits */
     now+=1000;assert(derp_sender_admit(&m,&p)>=0);}                             /* one token back */

    /* 8. DISCO: a forged sender key is dropped before it can activate anything; a box that opens activates. */
    reset(&m);now=100000;
    {ml_peer_update_t u=record(12);uint8_t nonce[24]={0},ct[32]={0};
     assert(directory_disco_admit(&m,u.disco_key,nonce,ct,sizeof(ct))<0);        /* nobody signed it */
     assert(resident(&m)==0 && disco_boxes_opened==1);
     memcpy(disco_signers[disco_signer_count++],u.disco_key,32);
     int idx=directory_disco_admit(&m,u.disco_key,nonce,ct,sizeof(ct));assert(idx>=0 && m.peers[idx].active && !m.peers[idx].unconfirmed);
     disco_boxes_opened=0;
     assert(directory_disco_admit(&m,u.disco_key,nonce,ct,sizeof(ct))==idx && !disco_boxes_opened); /* resident: no new crypto */
     uint8_t stranger[32]={255};assert(directory_disco_admit(&m,stranger,nonce,ct,sizeof(ct))<0 && !disco_boxes_opened);
     assert(directory_disco_admit(&m,u.disco_key,nonce,ct,8)==idx);}              /* short input is only refused for strangers */
    reset(&m);now=100000;fill(&m,1,8,now-1000);
    {ml_peer_update_t u=record(12);memcpy(disco_signers[disco_signer_count++],u.disco_key,32);uint8_t nonce[24]={0},ct[32]={0};
     assert(directory_disco_admit(&m,u.disco_key,nonce,ct,sizeof(ct))<0 && resident(&m)==8 && removals==0);} /* authentic, but no slot for it */
    reset(&m);now=100000;
    {for(unsigned i=0;i<10;i++){ml_peer_update_t u=record(11+i);uint8_t nonce[24]={0},ct[32]={0};
        assert(directory_disco_admit(&m,u.disco_key,nonce,ct,sizeof(ct))<0);}
     assert(disco_boxes_opened==3 && resident(&m)==0);}                          /* forged DISCO flood: only the burst reaches crypto */

    m.directory=dir;
    puts("Inbound trial: forged DERP/DISCO claims buy no slot, no eviction, bounded work; authenticated peers are confirmed and kept");
    return 0;
}
