#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* The recording paths must never touch the allocator: any use inside the code under test fails the run. */
static unsigned allocator_calls;
static void *forbidden(size_t n){allocator_calls++;return NULL;}
#define malloc(n) forbidden(n)
#define calloc(n,s) forbidden((n)*(s))
#define realloc(p,n) forbidden(n)
#define strdup(s) forbidden(0)
#define lock memory_lock
#include "../memory.c"
#undef lock
#include "../memory_diagnostics.c"
#undef malloc
#undef calloc
#undef realloc
#undef strdup
static uint32_t tick_ms=1000,free_heap=100000,min_heap=100000,largest=60000;
static struct {void *block;size_t size;} sizes[64];
int64_t esp_timer_get_time(void){return (int64_t)tick_ms*1000;}
size_t heap_caps_get_free_size(unsigned c){return free_heap;}
size_t heap_caps_get_minimum_free_size(unsigned c){return min_heap;}
size_t heap_caps_get_largest_free_block(unsigned c){return largest;}
size_t heap_caps_get_allocated_size(void *p){for(unsigned i=0;i<64;i++)if(sizes[i].block==p)return sizes[i].size;return 0;}
static void *block(size_t size){void *p=malloc(1);for(unsigned i=0;i<64;i++)if(!sizes[i].block){sizes[i].block=p;sizes[i].size=size;return p;}abort();}
static void forget(void *p){for(unsigned i=0;i<64;i++)if(sizes[i].block==p)sizes[i].block=NULL;}
static void release(void *p){forget(p);free(p);}
static void reset(void){memset(owners,0,sizeof(owners));memset(slots,0,sizeof(slots));memset(admissions,0,sizeof(admissions));admission_used=admission_next=0;underflow_count=eviction_count=0;guard_floor=CONFIG_TDONGLE_MEMORY_GUARD_FLOOR_BYTES;count=next=0;tick_ms=1000;free_heap=min_heap=100000;largest=60000;}
static void ledger(void){
 reset();
 void *a=tdongle_heap_tag(TDONGLE_OWNER_PACKET,block(1500)),*b=tdongle_heap_tag(TDONGLE_OWNER_PACKET,block(700));
 assert(a && b && tdongle_heap_owner(TDONGLE_OWNER_PACKET).live==2200 && tdongle_heap_owner(TDONGLE_OWNER_PACKET).peak==2200);
 tdongle_heap_note_free(TDONGLE_OWNER_PACKET,a);release(a);
 tdongle_owner_stats s=tdongle_heap_owner(TDONGLE_OWNER_PACKET);
 assert(s.live==700 && s.peak==2200 && s.allocs==2 && s.frees==1);
 void *c=tdongle_heap_tag(TDONGLE_OWNER_PACKET,block(2000));assert(tdongle_heap_owner(TDONGLE_OWNER_PACKET).peak==2700);
 tdongle_heap_note_free(TDONGLE_OWNER_PACKET,b);release(b);tdongle_heap_note_free(TDONGLE_OWNER_PACKET,c);release(c);
 s=tdongle_heap_owner(TDONGLE_OWNER_PACKET);assert(s.live==0 && s.peak==2700 && !underflow_count);
 /* A block the ledger never saw, or an owner out of range, cannot wrap live below zero. */
 void *stray=block(900);tdongle_heap_note_free(TDONGLE_OWNER_TLS,stray);release(stray);
 assert(tdongle_heap_owner(TDONGLE_OWNER_TLS).live==0 && tdongle_heap_underflows()==1);
 tdongle_heap_note_free(TDONGLE_OWNER_TLS,NULL);assert(tdongle_heap_underflows()==1);
 void *wild=tdongle_heap_tag((tdongle_owner)99,block(64));assert(tdongle_heap_owner(TDONGLE_OWNER_OTHER).live==64 && tdongle_heap_owner((tdongle_owner)99).allocs==0);
 tdongle_heap_note_free((tdongle_owner)99,wild);release(wild);
 /* Natural failure is counted; the guard floor refuses and frees the block. */
 assert(!tdongle_heap_tag(TDONGLE_OWNER_MAP,NULL) && tdongle_heap_owner(TDONGLE_OWNER_MAP).failed==1);
 free_heap=CONFIG_TDONGLE_MEMORY_GUARD_FLOOR_BYTES-1;void *d=block(5000);
 assert(!tdongle_heap_tag(TDONGLE_OWNER_MAP,d));forget(d); /* the guard already freed it; ASan flags a leak or double free otherwise */
 s=tdongle_heap_owner(TDONGLE_OWNER_MAP);assert(s.denied==1 && s.live==0 && s.allocs==0);
 tdongle_heap_set_guard_floor(0);d=tdongle_heap_tag(TDONGLE_OWNER_MAP,block(5000));assert(d && tdongle_heap_owner(TDONGLE_OWNER_MAP).live==5000);
 tdongle_heap_note_free(TDONGLE_OWNER_MAP,d);release(d);
 free_heap=50000;tdongle_heap_set_guard_floor(12288);
 assert(tdongle_memory_start_allowed(10240) && !tdongle_memory_start_allowed(40000));largest=8000;assert(!tdongle_memory_start_allowed(10240));largest=60000;
 tdongle_heap_set_guard_floor(0);assert(tdongle_memory_start_allowed(1000000));
}
static void phases(void){
 reset();
 tdongle_memory_phase(7,TDONGLE_PHASE_START);
 tdongle_member_phases m;assert(tdongle_memory_member_get(0,&m) && m.member_id==7 && m.attempt==1 && m.phase[0].valid && !m.phase[0].exact);
 assert(!tdongle_memory_member_get(1,&m) && !tdongle_memory_member_get(TDONGLE_MEMORY_MEMBERS,&m));
 /* Sampled low point inside a phase while the heap-wide minimum did not move. */
 void *a=tdongle_heap_tag(TDONGLE_OWNER_TLS,block(30000));free_heap=70000;
 void *b=tdongle_heap_tag(TDONGLE_OWNER_CONTROL,block(5000));free_heap=90000;
 tick_ms=2000;tdongle_memory_phase(7,TDONGLE_PHASE_CONTROL);
 assert(tdongle_memory_member_get(0,&m));
 tdongle_phase_record r=m.phase[TDONGLE_PHASE_CONTROL];
 assert(r.valid && !r.exact && r.minimum_bytes==70000 && r.free_bytes==90000 && r.largest_bytes==60000 && r.uptime_ms==2000);
 assert(r.owner_peak[TDONGLE_OWNER_TLS]==30000 && r.owner_peak[TDONGLE_OWNER_CONTROL]==5000);
 /* A new heap-wide minimum during the phase is exact, and owner peaks restart from live bytes. */
 tdongle_heap_note_free(TDONGLE_OWNER_TLS,a);release(a);
 free_heap=40000;min_heap=38000;tick_ms=3000;tdongle_memory_phase(7,TDONGLE_PHASE_NOISE);
 assert(tdongle_memory_member_get(0,&m));r=m.phase[TDONGLE_PHASE_NOISE];
 assert(r.exact && r.minimum_bytes==38000 && r.owner_peak[TDONGLE_OWNER_TLS]==30000 /* live when the phase began */ && r.owner_peak[TDONGLE_OWNER_CONTROL]==5000);
 assert(m.phase[TDONGLE_PHASE_CONTROL].minimum_bytes==70000);
 /* Phase boundaries leave low-water records tagged with the phase operation. */
 bool tagged=false;for(unsigned i=0;i<tdongle_memory_count();i++)if(tdongle_memory_get(i).operation==TDONGLE_MEMORY_OP_PHASE+TDONGLE_PHASE_NOISE)tagged=true;assert(tagged);
 tdongle_heap_note_free(TDONGLE_OWNER_CONTROL,b);release(b);
 tick_ms=3500;tdongle_memory_phase(7,TDONGLE_PHASE_REGISTER);
 assert(tdongle_memory_member_get(0,&m) && !m.phase[TDONGLE_PHASE_REGISTER].exact && m.phase[TDONGLE_PHASE_REGISTER].owner_peak[TDONGLE_OWNER_TLS]==0);
 /* A new attempt clears the phases of that membership only; a second membership gets its own slot. */
 tdongle_memory_phase(9,TDONGLE_PHASE_START);
 tdongle_memory_phase(7,TDONGLE_PHASE_START);
 assert(tdongle_memory_member_get(0,&m) && m.attempt==2 && !m.phase[TDONGLE_PHASE_NOISE].valid);
 assert(tdongle_memory_member_get(1,&m) && m.member_id==9 && m.attempt==1);
 tdongle_memory_phase(7,(tdongle_phase)99);assert(tdongle_memory_member_get(0,&m) && m.attempt==2);
}
static void slot_reuse(void){
 reset();
 /* Uptime wraps at 2^32 ms; the quietest slot is still found. */
 tick_ms=0xFFFFFF00u;tdongle_memory_phase(1,TDONGLE_PHASE_START);
 tick_ms=0xFFFFFF80u;tdongle_memory_phase(2,TDONGLE_PHASE_START);
 tick_ms=0xFFFFFFF0u;tdongle_memory_phase(3,TDONGLE_PHASE_START);
 tick_ms=0x00000040u;tdongle_memory_phase(2,TDONGLE_PHASE_CONTROL);
 assert(tdongle_memory_slot_evictions()==0);
 tdongle_memory_phase(4,TDONGLE_PHASE_START);
 tdongle_member_phases m;bool seen[5]={0};
 for(unsigned i=0;i<TDONGLE_MEMORY_MEMBERS;i++){assert(tdongle_memory_member_get(i,&m));seen[m.member_id]=true;}
 assert(tdongle_memory_slot_evictions()==1 && !seen[1] && seen[2] && seen[3] && seen[4]);
}
static void drops(void){
 reset();memset(drop_count,0,sizeof(drop_count));
 for(unsigned i=0;i<5;i++)tdongle_memory_drop(TDONGLE_DROP_DERP_TX_FULL);
 tdongle_memory_drop(TDONGLE_DROP_ROUTER_INGRESS);tdongle_memory_drop((tdongle_drop)99);
 assert(tdongle_memory_drops(TDONGLE_DROP_DERP_TX_FULL)==5 && tdongle_memory_drops(TDONGLE_DROP_ROUTER_INGRESS)==1 && !tdongle_memory_drops(TDONGLE_DROP_NET_WG_FULL) && !tdongle_memory_drops((tdongle_drop)99));
 drop_count[TDONGLE_DROP_NET_WG_FULL]=UINT32_MAX;tdongle_memory_drop(TDONGLE_DROP_NET_WG_FULL); /* counters wrap rather than saturate: consumers diff samples */
 assert(!tdongle_memory_drops(TDONGLE_DROP_NET_WG_FULL));
}
static void admissions_ring(void){
 reset();
 for(unsigned i=0;i<TDONGLE_MEMORY_ADMISSIONS+4;i++){tdongle_admission_record r={.member_id=i,.free_bytes=1000+i,.verdict=TDONGLE_ADMIT_OVERRIDE};tdongle_memory_admission_note(&r);}
 assert(tdongle_memory_admission_count()==TDONGLE_MEMORY_ADMISSIONS);
 assert(tdongle_memory_admission_get(0).member_id==4 && tdongle_memory_admission_get(TDONGLE_MEMORY_ADMISSIONS-1).member_id==TDONGLE_MEMORY_ADMISSIONS+3);
 assert(tdongle_memory_admission_get(TDONGLE_MEMORY_ADMISSIONS).uptime_ms==0);
 /* A refusal repeated every supervisor tick replaces itself instead of evicting real attempts. */
 reset();
 tdongle_admission_record ok={.member_id=1,.verdict=TDONGLE_ADMIT_OVERRIDE},no={.member_id=2,.verdict=TDONGLE_ADMIT_REFUSED_BUDGET};
 tdongle_memory_admission_note(&ok);
 for(unsigned i=0;i<50;i++){no.free_bytes=i;tdongle_memory_admission_note(&no);}
 assert(tdongle_memory_admission_count()==2 && tdongle_memory_admission_get(0).member_id==1 && tdongle_memory_admission_get(1).free_bytes==49);
 no.member_id=3;tdongle_memory_admission_note(&no);ok.member_id=2;tdongle_memory_admission_note(&ok);tdongle_memory_admission_note(&no);
 assert(tdongle_memory_admission_count()==5);
}
int main(void){
 /* Release-size guard: the diagnostic state is the whole static overhead of the profile. */
 assert(tdongle_memory_ledger_bytes()==sizeof(owners)+sizeof(slots)+sizeof(admissions)+sizeof(drop_count) && tdongle_memory_ledger_bytes()<=2048);
 ledger();phases();slot_reuse();drops();admissions_ring();
 assert(allocator_calls==0);
 return 0;
}
