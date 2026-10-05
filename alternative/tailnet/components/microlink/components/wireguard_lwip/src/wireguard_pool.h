/*
 * wireguard_pool.h - capped, on-demand slot pool (generic, lwIP-free, host-testable).
 *
 * Why this exists: every tailnet membership owns one `struct wireguard_device`.
 * Embedding WIREGUARD_MAX_PEERS peer structs (~1 KB each, session keys included)
 * in every device costs the same RAM for an idle membership as for a busy one and
 * multiplies by the number of memberships. Instead all devices draw peer slots
 * from ONE pool with a hard capacity: a membership with 3 peers costs 3 slots,
 * and the sum over all memberships can never exceed `capacity`.
 *
 * Behaviour
 *  - Slots are allocated on demand (zeroed) and freed on release; the pool itself
 *    is just a small table of pointers, so memory use tracks live residents.
 *  - acquire() fails (returns NULL) when the pool is at capacity OR the allocator
 *    fails; the two causes are counted separately. There is deliberately no
 *    fallback of any kind: the caller owns the eviction policy.
 *  - release() wipes the slot with a non-optimisable zeroing before freeing it,
 *    because slots hold session keys, preshared keys and DH precomputes.
 *  - Each live slot is tagged with an opaque `owner` pointer (the device).
 *
 * Concurrency: NOT thread-safe. In the firmware every caller already runs under
 * the lwIP core lock (LOCK_TCPIP_CORE) which serialises all access; this file
 * deliberately has no FreeRTOS dependency so it can be exercised on the host.
 * wg_pool_each() callbacks must not acquire or release slots of the same pool.
 */
#ifndef WIREGUARD_POOL_H
#define WIREGUARD_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bound for `capacity`; sizes the internal pointer table (16 * 2 pointers). */
#define WG_POOL_MAX_SLOTS 16

typedef void *(*wg_pool_alloc_fn)(size_t size);
typedef void (*wg_pool_free_fn)(void *ptr);

/* Visit callback: return true to continue, false to stop the walk. */
typedef bool (*wg_pool_each_fn)(void *slot, const void *owner, void *ctx);

typedef struct {
    uint32_t capacity;      /* configured hard cap */
    uint32_t used;          /* live slots right now */
    uint32_t peak_used;     /* high-water mark of `used` */
    uint32_t acquired;      /* successful acquire() calls */
    uint32_t released;      /* slots returned (release / release_owner) */
    uint32_t refused_full;  /* acquire() refused: pool at capacity */
    uint32_t refused_nomem; /* acquire() refused: allocator returned NULL */
    uint32_t evictions;     /* policy evictions reported via note_eviction() */
} wg_pool_stats_t;

typedef struct {
    void *slot;
    const void *owner;
} wg_pool_entry_t;

typedef struct {
    wg_pool_entry_t entries[WG_POOL_MAX_SLOTS]; /* slot == NULL: unused */
    size_t capacity;
    size_t slot_size;
    wg_pool_alloc_fn alloc_fn;
    wg_pool_free_fn free_fn;
    wg_pool_stats_t stats; /* capacity/used mirrored on read, see get_stats() */
} wg_pool_t;

/* Initialise a pool object from scratch (counters cleared). Returns false and
 * leaves the pool unusable (capacity 0) when capacity is 0 or > WG_POOL_MAX_SLOTS
 * or slot_size is 0. alloc/free NULL select malloc/free; they must be both set
 * or both NULL. */
bool wg_pool_init(wg_pool_t *pool, size_t capacity, size_t slot_size,
                  wg_pool_alloc_fn alloc, wg_pool_free_fn free_fn);

/* Re-configure an initialised pool. Refused (false) while any slot is live,
 * because a live slot must be freed by the hook that allocated it. Counters
 * are kept. Same validation as wg_pool_init. */
bool wg_pool_configure(wg_pool_t *pool, size_t capacity, size_t slot_size,
                       wg_pool_alloc_fn alloc, wg_pool_free_fn free_fn);

/* Take a zeroed slot of slot_size bytes tagged with `owner` (non-NULL).
 * NULL when full, out of memory, owner is NULL or the pool is unconfigured. */
void *wg_pool_acquire(wg_pool_t *pool, const void *owner);

/* Wipe and free one slot. False (no effect) if `slot` is not live in this pool,
 * so a double release is harmless. */
bool wg_pool_release(wg_pool_t *pool, void *slot);

/* Release every slot tagged with `owner`; returns how many were freed. */
size_t wg_pool_release_owner(wg_pool_t *pool, const void *owner);

size_t wg_pool_owner_count(const wg_pool_t *pool, const void *owner);
size_t wg_pool_used(const wg_pool_t *pool);
size_t wg_pool_capacity(const wg_pool_t *pool);

/* Owner of a live slot, or NULL when `slot` is not live in this pool. */
const void *wg_pool_owner_of(const wg_pool_t *pool, const void *slot);

/* True when `slot` is a live slot of this pool. */
bool wg_pool_contains(const wg_pool_t *pool, const void *slot);

/* Visit every live slot (stable order of the internal table). */
void wg_pool_each(const wg_pool_t *pool, wg_pool_each_fn cb, void *ctx);

/* The eviction POLICY lives in the caller (it must update its own state);
 * this only counts that one happened on behalf of `owner`. */
void wg_pool_note_eviction(wg_pool_t *pool, const void *owner);

wg_pool_stats_t wg_pool_get_stats(const wg_pool_t *pool);

/* Zero memory in a way the compiler may not elide (key material). */
void wg_pool_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_POOL_H */
