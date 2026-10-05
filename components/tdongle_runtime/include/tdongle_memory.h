#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "sdkconfig.h"
/* Low-water recorder: 16 records that keep heap transitions and failures. */
typedef struct {uint32_t uptime_ms,operation,requested,free_bytes,minimum_bytes,largest_bytes,failed;} tdongle_memory_record;
enum {
 TDONGLE_MEMORY_OP_TICK=0,TDONGLE_MEMORY_OP_CONTROL_BUFFER=1,TDONGLE_MEMORY_OP_DIAG_WRITE=2,
 TDONGLE_MEMORY_OP_JOURNAL=3,TDONGLE_MEMORY_OP_STATUS_SNAPSHOT=4,TDONGLE_MEMORY_OP_WIFI_PROFILES=5,
 TDONGLE_MEMORY_OP_PHASE=16 /* + tdongle_phase: a join-phase boundary */
};
void tdongle_memory_note(unsigned operation,size_t requested,int failed);
unsigned tdongle_memory_count(void);
tdongle_memory_record tdongle_memory_get(unsigned offset);

/* Who holds heap bytes. TLS is every mbedTLS allocation, CONTROL the Noise/HTTP2
 * control channel buffers, MAP every cJSON allocation, PEER peer directory and
 * update batches, WG the WireGuard netif and queued handshake packets, PACKET relay
 * and receive payloads, CONTEXT the microlink_t instance. */
typedef enum {TDONGLE_OWNER_OTHER,TDONGLE_OWNER_TLS,TDONGLE_OWNER_CONTROL,TDONGLE_OWNER_MAP,TDONGLE_OWNER_PEER,TDONGLE_OWNER_WG,TDONGLE_OWNER_PACKET,TDONGLE_OWNER_CONTEXT,TDONGLE_OWNER_COUNT} tdongle_owner;
/* Boundaries of a membership join. A record covers the work since the previous boundary. */
typedef enum {TDONGLE_PHASE_START,TDONGLE_PHASE_CONTROL,TDONGLE_PHASE_NOISE,TDONGLE_PHASE_REGISTER,TDONGLE_PHASE_MAP,TDONGLE_PHASE_DERP,TDONGLE_PHASE_STEADY,TDONGLE_PHASE_COUNT} tdongle_phase;

/* Where the data path discards a packet because a bounded queue is full. */
typedef enum {TDONGLE_DROP_DERP_TX_EVICT,TDONGLE_DROP_DERP_TX_FULL,TDONGLE_DROP_DERP_RX_FULL,TDONGLE_DROP_NET_DISCO_FULL,TDONGLE_DROP_NET_WG_FULL,TDONGLE_DROP_NET_STUN_FULL,TDONGLE_DROP_ROUTER_INGRESS,TDONGLE_DROP_COUNT} tdongle_drop;

/* How long the lwIP core lock (LOCK_TCPIP_CORE) is held, by call site. Diagnostics builds only: a histogram per site, so a
 * board run shows whether any single hold exceeds the ~1 ms budget the shared wg_mgr task works to. */
typedef enum {TDONGLE_LOCK_WG_OTHER,TDONGLE_LOCK_WG_PERIODIC,TDONGLE_LOCK_WG_COMMIT,TDONGLE_LOCK_WG_OUTPUT,TDONGLE_LOCK_WG_PEER,TDONGLE_LOCK_SITE_COUNT} tdongle_lock_site;
enum {TDONGLE_LOCK_BUCKETS=9}; /* hold < 100, 250, 500, 1000, 2000, 5000, 10000, 30000 us, then >= 30000 */
static const uint32_t tdongle_lock_bucket_limit_us[TDONGLE_LOCK_BUCKETS-1]={100,250,500,1000,2000,5000,10000,30000};
typedef struct {uint32_t count,max_us,over_1ms,bucket[TDONGLE_LOCK_BUCKETS];uint64_t total_us;} tdongle_lock_stats;

#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
enum {TDONGLE_MEMORY_MEMBERS=3,TDONGLE_MEMORY_ADMISSIONS=6};
typedef struct {uint32_t live,peak,allocs,frees,failed,denied;} tdongle_owner_stats;
typedef struct {
 uint32_t uptime_ms,free_bytes,minimum_bytes,largest_bytes;
 uint8_t valid,exact; /* exact: the heap-wide minimum fell during this phase, so minimum_bytes is the true low point */
 uint32_t owner_peak[TDONGLE_OWNER_COUNT];
} tdongle_phase_record;
typedef struct {uint32_t member_id,attempt;tdongle_phase_record phase[TDONGLE_PHASE_COUNT];} tdongle_member_phases;
typedef enum {TDONGLE_ADMIT_OK,TDONGLE_ADMIT_REFUSED_BUDGET,TDONGLE_ADMIT_REFUSED_LARGEST,TDONGLE_ADMIT_REFUSED_SOCKETS,TDONGLE_ADMIT_OVERRIDE,TDONGLE_ADMIT_REFUSED_FLOOR,TDONGLE_ADMIT_START_FAILED} tdongle_admit_verdict;
typedef struct {uint32_t uptime_ms,member_id,free_bytes,largest_bytes,budget_bytes,sockets_open,sockets_limit,active,verdict;} tdongle_admission_record;

/* Record that the core lock was held for `us` microseconds at `site`. Lock-free. */
void tdongle_lock_hold(tdongle_lock_site site,uint32_t us);
tdongle_lock_stats tdongle_lock_stats_get(tdongle_lock_site site);
int64_t tdongle_lock_clock(void);
/* Account a block that was just allocated; NULL when the guard floor refused it (the block is freed). */
void *tdongle_heap_note_alloc(tdongle_owner owner,void *block);
/* Account a block allocated by code we do not control (wireguardif_init); never refused. */
void tdongle_heap_adopt(tdongle_owner owner,void *block);
/* Account a block that is about to be freed. A block the ledger never saw only increments underflows. */
void tdongle_heap_note_free(tdongle_owner owner,void *block);
tdongle_owner_stats tdongle_heap_owner(tdongle_owner owner);
uint32_t tdongle_heap_underflows(void);
uint32_t tdongle_heap_guard_floor(void);
void tdongle_heap_set_guard_floor(uint32_t bytes);
/* False when allocating bytes would leave less than the guard floor free (task stacks bypass the tagged allocator). */
bool tdongle_memory_start_allowed(size_t bytes);
void tdongle_memory_phase(uint32_t member_id,tdongle_phase phase);
/* Copies a slot's capture; false when the slot is unused. */
bool tdongle_memory_member_get(unsigned slot,tdongle_member_phases *out);
uint32_t tdongle_memory_slot_evictions(void);
/* Static RAM held by the owner ledger, join-phase capture and admission ring. */
size_t tdongle_memory_ledger_bytes(void);
void tdongle_memory_drop(tdongle_drop where);
uint32_t tdongle_memory_drops(tdongle_drop where);
void tdongle_memory_admission_note(const tdongle_admission_record *record);
unsigned tdongle_memory_admission_count(void);
tdongle_admission_record tdongle_memory_admission_get(unsigned offset);
/* Route mbedTLS allocations through the TLS owner. Call before the first TLS use. */
void tdongle_memory_diagnostics_init(void);
static inline void *tdongle_heap_tag(tdongle_owner owner,void *block){return tdongle_heap_note_alloc(owner,block);}
static inline void tdongle_heap_free(tdongle_owner owner,void *block){tdongle_heap_note_free(owner,block);free(block);}
static inline void tdongle_heap_forget(tdongle_owner owner,void *block){tdongle_heap_note_free(owner,block);}
#else
static inline void tdongle_lock_hold(tdongle_lock_site site,uint32_t us){(void)site;(void)us;}
static inline int64_t tdongle_lock_clock(void){return 0;}
static inline void *tdongle_heap_tag(tdongle_owner owner,void *block){(void)owner;return block;}
static inline void tdongle_heap_free(tdongle_owner owner,void *block){(void)owner;free(block);}
static inline void tdongle_heap_adopt(tdongle_owner owner,void *block){(void)owner;(void)block;}
static inline void tdongle_heap_forget(tdongle_owner owner,void *block){(void)owner;(void)block;}
static inline bool tdongle_memory_start_allowed(size_t bytes){(void)bytes;return true;}
static inline void tdongle_memory_drop(tdongle_drop where){(void)where;}
static inline void tdongle_memory_phase(uint32_t member_id,tdongle_phase phase){(void)member_id;(void)phase;}
static inline void tdongle_memory_diagnostics_init(void){}
#endif
