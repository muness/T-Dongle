/* Memory diagnostics profile (CONFIG_TDONGLE_MEMORY_DIAGNOSTICS): owner ledger,
 * per-membership join-phase capture and admission record. Nothing here allocates;
 * all state is static and every critical section is a few stores. */
#include "tdongle_memory.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include <string.h>
typedef struct {
 tdongle_member_phases out;
 uint32_t running_min,life_min,last_ms,peak[TDONGLE_OWNER_COUNT];
 bool used,marked;
} member_slot;
static tdongle_owner_stats owners[TDONGLE_OWNER_COUNT];
static member_slot slots[TDONGLE_MEMORY_MEMBERS];
static tdongle_admission_record admissions[TDONGLE_MEMORY_ADMISSIONS];
static unsigned admission_used,admission_next;
static uint32_t drop_count[TDONGLE_DROP_COUNT];
static uint32_t underflow_count,eviction_count,guard_floor=CONFIG_TDONGLE_MEMORY_GUARD_FLOOR_BYTES;
static portMUX_TYPE diag_lock=portMUX_INITIALIZER_UNLOCKED;
/* Caller holds diag_lock. Every join in flight sees the heap low points and owner peaks. */
static void sample(uint32_t free_now){
 for(unsigned i=0;i<TDONGLE_MEMORY_MEMBERS;i++)if(slots[i].used && free_now<slots[i].running_min)slots[i].running_min=free_now;
}
static void *account(tdongle_owner owner,void *block,bool guarded){
 if(owner>=TDONGLE_OWNER_COUNT)owner=TDONGLE_OWNER_OTHER;
 size_t size=block?heap_caps_get_allocated_size(block):0,free_now=heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
 bool deny=false;
 portENTER_CRITICAL(&diag_lock);
 sample((uint32_t)free_now);
 tdongle_owner_stats *o=&owners[owner];
 if(!block)o->failed++;
 else if(guarded && guard_floor && free_now<guard_floor){o->denied++;deny=true;}
 else{
  o->allocs++;o->live+=(uint32_t)size;if(o->live>o->peak)o->peak=o->live;
  for(unsigned i=0;i<TDONGLE_MEMORY_MEMBERS;i++)if(slots[i].used && o->live>slots[i].peak[owner])slots[i].peak[owner]=o->live;
 }
 portEXIT_CRITICAL(&diag_lock);
 if(deny){free(block);return NULL;}
 return block;
}
void *tdongle_heap_note_alloc(tdongle_owner owner,void *block){return account(owner,block,true);}
void tdongle_heap_adopt(tdongle_owner owner,void *block){account(owner,block,false);}
void tdongle_heap_note_free(tdongle_owner owner,void *block){
 if(!block)return;
 if(owner>=TDONGLE_OWNER_COUNT)owner=TDONGLE_OWNER_OTHER;
 uint32_t size=(uint32_t)heap_caps_get_allocated_size(block);
 portENTER_CRITICAL(&diag_lock);
 tdongle_owner_stats *o=&owners[owner];
 if(o->live<size){underflow_count++;o->live=0;} else o->live-=size;
 o->frees++;
 portEXIT_CRITICAL(&diag_lock);
}
tdongle_owner_stats tdongle_heap_owner(tdongle_owner owner){
 tdongle_owner_stats r={0};
 if(owner>=TDONGLE_OWNER_COUNT)return r;
 portENTER_CRITICAL(&diag_lock);r=owners[owner];portEXIT_CRITICAL(&diag_lock);
 return r;
}
uint32_t tdongle_heap_underflows(void){portENTER_CRITICAL(&diag_lock);uint32_t n=underflow_count;portEXIT_CRITICAL(&diag_lock);return n;}
uint32_t tdongle_heap_guard_floor(void){portENTER_CRITICAL(&diag_lock);uint32_t n=guard_floor;portEXIT_CRITICAL(&diag_lock);return n;}
void tdongle_heap_set_guard_floor(uint32_t bytes){portENTER_CRITICAL(&diag_lock);guard_floor=bytes;portEXIT_CRITICAL(&diag_lock);}
bool tdongle_memory_start_allowed(size_t bytes){
 uint32_t floor=tdongle_heap_guard_floor();
 return !floor || (heap_caps_get_free_size(MALLOC_CAP_INTERNAL)>=bytes+floor && heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)>=bytes);
}
/* Reuse the slot of the membership that has been quiet longest; caller holds diag_lock. */
static member_slot *claim(uint32_t member_id,uint32_t now){
 member_slot *pick=&slots[0];
 for(unsigned i=0;i<TDONGLE_MEMORY_MEMBERS;i++){
  if(slots[i].used && slots[i].out.member_id==member_id)return &slots[i];
  if(!slots[i].used){pick=&slots[i];break;}
  if((uint32_t)(now-slots[i].last_ms)>(uint32_t)(now-pick->last_ms))pick=&slots[i];
 }
 if(pick->used)eviction_count++;
 memset(pick,0,sizeof(*pick));
 pick->used=true;pick->out.member_id=member_id;pick->running_min=UINT32_MAX;
 return pick;
}
void tdongle_memory_phase(uint32_t member_id,tdongle_phase phase){
 if(phase>=TDONGLE_PHASE_COUNT)return;
 size_t free_now=heap_caps_get_free_size(MALLOC_CAP_INTERNAL),life=heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),largest=heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
 uint32_t now=(uint32_t)(esp_timer_get_time()/1000);
 portENTER_CRITICAL(&diag_lock);
 member_slot *s=claim(member_id,now);
 if(phase==TDONGLE_PHASE_START){memset(s->out.phase,0,sizeof(s->out.phase));s->out.attempt++;s->marked=false;}
 sample((uint32_t)free_now);
 /* The heap-wide minimum only ever falls, so a drop since the last boundary happened in this phase. */
 bool exact=s->marked && life<s->life_min;
 tdongle_phase_record *r=&s->out.phase[phase];
 *r=(tdongle_phase_record){now,(uint32_t)free_now,exact?(uint32_t)life:s->running_min,(uint32_t)largest,1,exact,{0}};
 memcpy(r->owner_peak,s->peak,sizeof(r->owner_peak));
 s->running_min=(uint32_t)free_now;s->life_min=(uint32_t)life;s->marked=true;s->last_ms=now;
 for(unsigned i=0;i<TDONGLE_OWNER_COUNT;i++)s->peak[i]=owners[i].live;
 portEXIT_CRITICAL(&diag_lock);
 tdongle_memory_note(TDONGLE_MEMORY_OP_PHASE+phase,0,0);
}
bool tdongle_memory_member_get(unsigned slot,tdongle_member_phases *out){
 bool used=false;
 portENTER_CRITICAL(&diag_lock);
 if(slot<TDONGLE_MEMORY_MEMBERS && slots[slot].used){*out=slots[slot].out;used=true;}
 portEXIT_CRITICAL(&diag_lock);
 return used;
}
size_t tdongle_memory_ledger_bytes(void){return sizeof(owners)+sizeof(slots)+sizeof(admissions)+sizeof(drop_count);}
void tdongle_memory_drop(tdongle_drop where){if(where<TDONGLE_DROP_COUNT)__atomic_fetch_add(&drop_count[where],1,__ATOMIC_RELAXED);}
uint32_t tdongle_memory_drops(tdongle_drop where){return where<TDONGLE_DROP_COUNT?__atomic_load_n(&drop_count[where],__ATOMIC_RELAXED):0;}
uint32_t tdongle_memory_slot_evictions(void){portENTER_CRITICAL(&diag_lock);uint32_t n=eviction_count;portEXIT_CRITICAL(&diag_lock);return n;}
void tdongle_memory_admission_note(const tdongle_admission_record *record){
 portENTER_CRITICAL(&diag_lock);
 admissions[admission_next]=*record;admission_next=(admission_next+1)%TDONGLE_MEMORY_ADMISSIONS;
 if(admission_used<TDONGLE_MEMORY_ADMISSIONS)admission_used++;
 portEXIT_CRITICAL(&diag_lock);
}
unsigned tdongle_memory_admission_count(void){portENTER_CRITICAL(&diag_lock);unsigned n=admission_used;portEXIT_CRITICAL(&diag_lock);return n;}
tdongle_admission_record tdongle_memory_admission_get(unsigned offset){
 tdongle_admission_record r={0};
 portENTER_CRITICAL(&diag_lock);
 if(offset<admission_used)r=admissions[(admission_next+TDONGLE_MEMORY_ADMISSIONS-admission_used+offset)%TDONGLE_MEMORY_ADMISSIONS];
 portEXIT_CRITICAL(&diag_lock);
 return r;
}
