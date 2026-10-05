/* See wireguard_pool.h. Generic slot pool: no lwIP, no FreeRTOS, no globals. */
#include "wireguard_pool.h"

#include <stdlib.h>
#include <string.h>

/* Calling memset through a volatile function pointer stops the compiler from
 * proving the stores dead (which it does for memset right before free()). */
static void *(*const volatile s_memset)(void *, int, size_t) = memset;

void wg_pool_secure_zero(void *ptr, size_t len) {
    if (ptr && len) {
        s_memset(ptr, 0, len);
    }
}

static bool config_valid(size_t capacity, size_t slot_size,
                         wg_pool_alloc_fn alloc, wg_pool_free_fn free_fn) {
    return capacity > 0 && capacity <= WG_POOL_MAX_SLOTS && slot_size > 0 &&
           ((alloc == NULL) == (free_fn == NULL));
}

static bool apply_config(wg_pool_t *pool, size_t capacity, size_t slot_size,
                         wg_pool_alloc_fn alloc, wg_pool_free_fn free_fn) {
    if (!config_valid(capacity, slot_size, alloc, free_fn)) {
        return false;
    }
    pool->capacity = capacity;
    pool->slot_size = slot_size;
    pool->alloc_fn = alloc ? alloc : malloc;
    pool->free_fn = free_fn ? free_fn : free;
    return true;
}

bool wg_pool_init(wg_pool_t *pool, size_t capacity, size_t slot_size,
                  wg_pool_alloc_fn alloc, wg_pool_free_fn free_fn) {
    if (!pool) {
        return false;
    }
    memset(pool, 0, sizeof(*pool));
    return apply_config(pool, capacity, slot_size, alloc, free_fn);
}

bool wg_pool_configure(wg_pool_t *pool, size_t capacity, size_t slot_size,
                       wg_pool_alloc_fn alloc, wg_pool_free_fn free_fn) {
    if (!pool || wg_pool_used(pool) != 0) {
        return false;
    }
    return apply_config(pool, capacity, slot_size, alloc, free_fn);
}

size_t wg_pool_used(const wg_pool_t *pool) {
    size_t n = 0;
    for (size_t i = 0; pool && i < WG_POOL_MAX_SLOTS; i++) {
        n += pool->entries[i].slot != NULL;
    }
    return n;
}

size_t wg_pool_capacity(const wg_pool_t *pool) {
    return pool ? pool->capacity : 0;
}

void *wg_pool_acquire(wg_pool_t *pool, const void *owner) {
    if (!pool || !owner || pool->capacity == 0) {
        return NULL;
    }
    size_t used = wg_pool_used(pool);
    if (used >= pool->capacity) {
        pool->stats.refused_full++;
        return NULL;
    }
    void *slot = pool->alloc_fn(pool->slot_size);
    if (!slot) {
        pool->stats.refused_nomem++;
        return NULL;
    }
    memset(slot, 0, pool->slot_size);
    for (size_t i = 0; i < WG_POOL_MAX_SLOTS; i++) {
        if (!pool->entries[i].slot) {
            pool->entries[i].slot = slot;
            pool->entries[i].owner = owner;
            pool->stats.acquired++;
            if (used + 1 > pool->stats.peak_used) {
                pool->stats.peak_used = (uint32_t)(used + 1);
            }
            return slot;
        }
    }
    /* Unreachable: used < capacity <= WG_POOL_MAX_SLOTS guarantees a free entry. */
    wg_pool_secure_zero(slot, pool->slot_size);
    pool->free_fn(slot);
    return NULL;
}

static void release_entry(wg_pool_t *pool, wg_pool_entry_t *e) {
    void *slot = e->slot;
    e->slot = NULL;
    e->owner = NULL;
    wg_pool_secure_zero(slot, pool->slot_size);
    pool->free_fn(slot);
    pool->stats.released++;
}

bool wg_pool_release(wg_pool_t *pool, void *slot) {
    if (!pool || !slot) {
        return false;
    }
    for (size_t i = 0; i < WG_POOL_MAX_SLOTS; i++) {
        if (pool->entries[i].slot == slot) {
            release_entry(pool, &pool->entries[i]);
            return true;
        }
    }
    return false;
}

size_t wg_pool_release_owner(wg_pool_t *pool, const void *owner) {
    size_t n = 0;
    if (!pool || !owner) {
        return 0;
    }
    for (size_t i = 0; i < WG_POOL_MAX_SLOTS; i++) {
        if (pool->entries[i].slot && pool->entries[i].owner == owner) {
            release_entry(pool, &pool->entries[i]);
            n++;
        }
    }
    return n;
}

size_t wg_pool_owner_count(const wg_pool_t *pool, const void *owner) {
    size_t n = 0;
    for (size_t i = 0; pool && owner && i < WG_POOL_MAX_SLOTS; i++) {
        n += pool->entries[i].slot && pool->entries[i].owner == owner;
    }
    return n;
}

const void *wg_pool_owner_of(const wg_pool_t *pool, const void *slot) {
    for (size_t i = 0; pool && slot && i < WG_POOL_MAX_SLOTS; i++) {
        if (pool->entries[i].slot == slot) {
            return pool->entries[i].owner;
        }
    }
    return NULL;
}

bool wg_pool_contains(const wg_pool_t *pool, const void *slot) {
    return wg_pool_owner_of(pool, slot) != NULL;
}

void wg_pool_each(const wg_pool_t *pool, wg_pool_each_fn cb, void *ctx) {
    for (size_t i = 0; pool && cb && i < WG_POOL_MAX_SLOTS; i++) {
        if (pool->entries[i].slot &&
            !cb(pool->entries[i].slot, pool->entries[i].owner, ctx)) {
            return;
        }
    }
}

void wg_pool_note_eviction(wg_pool_t *pool, const void *owner) {
    (void)owner; /* kept in the signature so per-owner accounting can be added later */
    if (pool) {
        pool->stats.evictions++;
    }
}

wg_pool_stats_t wg_pool_get_stats(const wg_pool_t *pool) {
    wg_pool_stats_t s;
    memset(&s, 0, sizeof(s));
    if (pool) {
        s = pool->stats;
        s.capacity = (uint32_t)pool->capacity;
        s.used = (uint32_t)wg_pool_used(pool);
    }
    return s;
}
