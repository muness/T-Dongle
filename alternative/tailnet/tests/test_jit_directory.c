#include "tdongle_memory.h"
#define ROUTE_MARK(stage) ((void)0)
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ML_MAX_PEERS 8
#define ML_MAX_ENDPOINTS 8
#define MICROLINK_MAX_PEER_ROUTES 8
#define ML_MAX_DERP_NODES 2
#define ML_MAX_DERP_REGIONS 4
typedef struct {uint32_t network;uint8_t prefix_len;} microlink_route_t;
#include "semantic_types.inc"
typedef struct microlink_s microlink_t;
#include "ml_directory.h"
#define NACL_BOX_MACBYTES 16
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
#define ROOT "/tmp/tdongle-jit-directory"
#include "../components/microlink/src/ml_directory.c"
#include <sys/stat.h>
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
static void remove_peer(microlink_t *m,const ml_peer_update_t *u) {
    int i=find_peer_by_key(m,u->public_key);if(i>=0)memset(&m->peers[i],0,sizeof(m->peers[i]));
}
static int add_peer(microlink_t *m,const ml_peer_update_t *u) {
    for(unsigned i=0;i<8;i++)if(!m->peers[i].active) {
        peer_state *p=&m->peers[i];p->active=true;p->vpn_ip=u->vpn_ip;p->node_id=u->node_id;
        memcpy(p->public_key,u->public_key,32);memcpy(p->disco_key,u->disco_key,32);return i;
    }
    return -1;
}
static void apply_peer_update(microlink_t *m,const ml_peer_update_t *u) {}
static bool wg_peer_authenticated(microlink_t *m,int idx){return false;}
static bool wg_initiation_plausible(microlink_t *m,const ml_rx_packet_t *p){return false;}
static bool disco_authenticates(microlink_t *m,const uint8_t *k,const uint8_t *n,const uint8_t *c,size_t l){return false;}
#include "jit_activation.inc"
static ml_peer_update_t record(unsigned id) {
    ml_peer_update_t u={.action=ML_PEER_ADD,.vpn_ip=0x64400000+id,.node_id=id,.has_node_id=true};
    memcpy(u.public_key,&id,4);memcpy(u.disco_key,&id,4);return u;
}
int main(void) {
    mkdir(ROOT,0700);microlink_t m={.wg_public_key={4}};
    assert(ml_directory_begin(&m));
    for(unsigned i=1;i<=12;i++){ml_peer_update_t u=record(i);assert(ml_directory_stage(&m,2,&u));}
    assert(ml_directory_commit(&m,true));
    for(unsigned i=1;i<=8;i++){now=i;ml_peer_update_t u=record(i);assert(directory_activate(&m,&u)>=0);}
    ml_peer_update_t u=record(9);now=9000;assert(directory_activate(&m,&u)<0); // all recently used
    now=20000;ml_peer_update_t hot=record(1);assert(directory_activate(&m,&hot)==0);
    assert(directory_activate(&m,&u)==1); // evicts cold #2, preserves MRU #1
    assert(find_peer_by_key(&m,hot.public_key)==0);
    now=40000;u=record(10);m.config.priority_peer_ip=record(3).vpn_ip;
    assert(directory_activate(&m,&u)==3); // old #3 is pinned, evicts #4
    // Cold inbound discovery activates authorized peer, rejects unknown key.
    u=record(12);assert(directory_by_disco(&m,u.disco_key)>=0);
    uint8_t unknown[32]={255};assert(directory_by_disco(&m,unknown)<0);
    // Revocation evicts the warm peer; rotated key cannot reuse old connection.
    assert(ml_directory_begin(&m));u=record(1);u.action=ML_PEER_REMOVE;assert(ml_directory_stage(&m,3,&u));
    u=record(9);u.public_key[0]=99;assert(ml_directory_stage(&m,6,&u));assert(ml_directory_commit(&m,false));
    directory_reconcile(&m);assert(find_peer_by_key(&m,hot.public_key)<0);
    u=record(9);assert(find_peer_by_key(&m,u.public_key)<0);
    // Saved records after reboot are not admitted without current full-map approval.
    m.directory.session_valid=false;u=record(12);assert(directory_activate(&m,&u)<0);
    puts("JIT activation: LRU/MRU, busy protection, priority pin, inbound miss, revocation, rotation and fresh-map approval passed");
}
