#include "route_table.h"
#include <string.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
static portMUX_TYPE rt_mux = portMUX_INITIALIZER_UNLOCKED;
void rt_lock(void) { portENTER_CRITICAL(&rt_mux); }
void rt_unlock(void) { portEXIT_CRITICAL(&rt_mux); }
static void rt_pause(void) { vTaskDelay(1); }
#else
#include <sched.h>
static atomic_flag rt_spin = ATOMIC_FLAG_INIT;
void rt_lock(void) {
    while (atomic_flag_test_and_set_explicit(&rt_spin, memory_order_acquire))
        sched_yield();
}
void rt_unlock(void) { atomic_flag_clear_explicit(&rt_spin, memory_order_release); }
static void rt_pause(void) { sched_yield(); }
#endif

atomic_uint rt_stats[RT_STAT_COUNT];

void rt_init(rt_t *t) { memset(t, 0, sizeof(*t)); }

/* ---- aliases ---------------------------------------------------------- */
/* Aliases are allocated sequentially (RT_ALIAS_BASE + n), so the low bits are
 * already a perfect hash. */
static unsigned alias_bucket(uint32_t alias) { return alias & (RT_ALIASES - 1); }

static void alias_unlink(rt_t *t, unsigned index) {
    uint8_t *link = &t->alias_head[alias_bucket(t->alias[index].alias.alias)];
    while (*link && *link - 1 != (int)index)
        link = &t->alias[*link - 1].next;
    if (*link)
        *link = t->alias[index].next;
    memset(&t->alias[index], 0, sizeof(t->alias[index]));
}

bool rt_alias_find(rt_t *t, uint32_t alias, rt_alias_t *out) {
    bool found = false;
    rt_lock();
    for (unsigned i = t->alias_head[alias_bucket(alias)]; i; i = t->alias[i - 1].next)
        if (t->alias[i - 1].alias.alias == alias) {
            t->alias[i - 1].referenced = 1;
            *out = t->alias[i - 1].alias;
            found = true;
            break;
        }
    rt_unlock();
    return found;
}

/* Control path (DNS, peer views): a short linear scan is fine and keeps a
 * second index out of the cache. */
bool rt_alias_find_key(rt_t *t, uint32_t id, uint32_t peer, uint32_t *alias) {
    bool found = false;
    rt_lock();
    for (unsigned i = 0; i < RT_ALIASES; i++)
        if (t->alias[i].used && t->alias[i].alias.id == id && t->alias[i].alias.peer == peer) {
            t->alias[i].referenced = 1;
            *alias = t->alias[i].alias.alias;
            found = true;
            break;
        }
    rt_unlock();
    return found;
}

bool rt_alias_insert(rt_t *t, const rt_alias_t *record) {
    bool ok = true;
    if (!record->alias || !record->id)
        return false;
    rt_lock();
    for (unsigned i = t->alias_head[alias_bucket(record->alias)]; i; i = t->alias[i - 1].next)
        if (t->alias[i - 1].alias.alias == record->alias) {
            ok = t->alias[i - 1].alias.id == record->id && t->alias[i - 1].alias.peer == record->peer;
            t->alias[i - 1].referenced = 1;
            rt_unlock();
            return ok;
        }
    /* The same (id, peer) under a different alias would mean a bad store. */
    for (unsigned i = 0; i < RT_ALIASES; i++)
        if (t->alias[i].used && t->alias[i].alias.id == record->id && t->alias[i].alias.peer == record->peer) {
            rt_unlock();
            return false;
        }
    unsigned victim = RT_ALIASES;
    for (unsigned i = 0; i < RT_ALIASES; i++)
        if (!t->alias[i].used) {
            victim = i;
            break;
        }
    /* CLOCK: second chance for recently looked-up entries. Two sweeps always
     * find a victim. */
    for (unsigned n = 0; victim == RT_ALIASES && n < 2 * RT_ALIASES; n++) {
        unsigned i = t->alias_hand++ % RT_ALIASES;
        if (t->alias[i].referenced)
            t->alias[i].referenced = 0;
        else
            victim = i;
    }
    if (victim == RT_ALIASES)
        victim = t->alias_hand++ % RT_ALIASES;
    if (t->alias[victim].used)
        alias_unlink(t, victim);
    unsigned bucket = alias_bucket(record->alias);
    t->alias[victim] = (rt_alias_slot){.alias = *record, .next = t->alias_head[bucket], .used = 1};
    t->alias_head[bucket] = victim + 1;
    rt_unlock();
    return true;
}

unsigned rt_alias_forget(rt_t *t, uint32_t id) {
    unsigned n = 0;
    rt_lock();
    for (unsigned i = 0; i < RT_ALIASES; i++)
        if (t->alias[i].used && t->alias[i].alias.id == id) {
            alias_unlink(t, i);
            n++;
        }
    rt_unlock();
    return n;
}

/* ---- flows ------------------------------------------------------------ */
static unsigned flow_bucket(uint32_t alias, uint32_t host, uint16_t local, uint16_t remote, uint8_t proto) {
    uint32_t h = host * 0x9e3779b1u;
    h ^= alias * 0x85ebca6bu;
    h ^= ((uint32_t)local << 16 | remote) * 0xc2b2ae35u;
    h ^= proto;
    h ^= h >> 15;
    h *= 0x2c1b3c6du;
    return (h >> 20) & (RT_FLOWS - 1);
}

static void flow_unlink(rt_t *t, unsigned index) {
    rt_flow_slot *f = &t->flow[index];
    uint8_t *link = &t->flow_head[flow_bucket(f->flow.alias, f->flow.host, f->flow.local, f->flow.remote, f->flow.proto)];
    while (*link && *link - 1 != (int)index)
        link = &t->flow[*link - 1].next;
    if (*link)
        *link = f->next;
    memset(f, 0, sizeof(*f));
}

static rt_flow_slot *flow_match(rt_t *t, uint32_t alias, uint32_t host, uint16_t local, uint16_t remote, uint8_t proto, uint32_t generation) {
    for (unsigned i = t->flow_head[flow_bucket(alias, host, local, remote, proto)]; i; i = t->flow[i - 1].next) {
        rt_flow_slot *f = &t->flow[i - 1];
        if (f->generation == generation && f->flow.alias == alias && f->flow.host == host && f->flow.local == local && f->flow.remote == remote &&
            f->flow.proto == proto)
            return f;
    }
    return NULL;
}

bool rt_flow_out(rt_t *t, uint32_t alias, uint32_t host, uint16_t local, uint16_t remote, uint8_t proto, uint32_t generation, rt_flow_t *out) {
    rt_lock();
    rt_flow_slot *f = flow_match(t, alias, host, local, remote, proto, generation);
    if (f)
        *out = f->flow;
    rt_unlock();
    return f != NULL;
}

void rt_flow_touch(rt_t *t, const rt_flow_t *flow, uint32_t generation, int64_t now) {
    rt_lock();
    rt_flow_slot *f = flow_match(t, flow->alias, flow->host, flow->local, flow->remote, flow->proto, generation);
    if (f && f->flow.id == flow->id && f->flow.mapped == flow->mapped)
        f->touched = now;
    rt_unlock();
}

bool rt_flow_create(rt_t *t, const rt_flow_t *key, uint32_t generation, int64_t now, rt_flow_t *out) {
    bool ok = false;
    rt_lock();
    rt_flow_slot *f = flow_match(t, key->alias, key->host, key->local, key->remote, key->proto, generation);
    if (!f) {
        for (unsigned i = 0; i < RT_FLOWS; i++) {
            rt_flow_slot *s = &t->flow[i];
            if (s->used && s->generation == generation && now - s->touched <= RT_FLOW_IDLE_US)
                continue;
            if (s->used)
                flow_unlink(t, i);
            unsigned bucket = flow_bucket(key->alias, key->host, key->local, key->remote, key->proto);
            *s = (rt_flow_slot){.flow = *key, .generation = generation, .touched = now, .next = t->flow_head[bucket], .used = 1};
            s->flow.mapped = RT_MAPPED_BASE + i + RT_FLOWS * ((generation - 1) % RT_MAPPED_GENERATIONS);
            t->flow_head[bucket] = i + 1;
            f = s;
            break;
        }
    } else
        f->touched = now;
    if (f) {
        *out = f->flow;
        ok = true;
    }
    rt_unlock();
    return ok;
}

rt_flow_in_result rt_flow_in_why(rt_t *t, uint32_t id, uint32_t peer, uint16_t remote, uint16_t mapped, uint8_t proto, uint32_t generation, int64_t now, rt_flow_t *out) {
    rt_flow_in_result result = RT_FLOW_IN_OK;
    if (mapped < RT_MAPPED_BASE || mapped >= RT_MAPPED_BASE + RT_FLOWS * RT_MAPPED_GENERATIONS)
        return RT_FLOW_IN_RANGE;
    rt_lock();
    rt_flow_slot *f = &t->flow[(mapped - RT_MAPPED_BASE) & (RT_FLOWS - 1)];
    if (!f->used)
        result = RT_FLOW_IN_NO_FLOW;
    else if (f->generation != generation)
        result = RT_FLOW_IN_GENERATION;
    else if (!(f->flow.id == id && f->flow.peer == peer && f->flow.remote == remote && f->flow.mapped == mapped && f->flow.proto == proto))
        result = RT_FLOW_IN_OWNER;
    else if (!(now - f->touched < RT_FLOW_IDLE_US))
        result = RT_FLOW_IN_IDLE;
    else {
        f->touched = now;
        *out = f->flow;
    }
    rt_unlock();
    return result;
}

bool rt_flow_in(rt_t *t, uint32_t id, uint32_t peer, uint16_t remote, uint16_t mapped, uint8_t proto, uint32_t generation, int64_t now, rt_flow_t *out) {
    return rt_flow_in_why(t, id, peer, remote, mapped, proto, generation, now, out) == RT_FLOW_IN_OK;
}

unsigned rt_flows_forget(rt_t *t, uint32_t id) {
    unsigned n = 0;
    rt_lock();
    for (unsigned i = 0; i < RT_FLOWS; i++)
        if (t->flow[i].used && t->flow[i].flow.id == id) {
            flow_unlink(t, i);
            n++;
        }
    rt_unlock();
    return n;
}

/* ---- RCU -------------------------------------------------------------- */
void rt_rcu_init(rt_rcu_t *r) {
    atomic_init(&r->epoch, 0);
    atomic_init(&r->readers[0], 0);
    atomic_init(&r->readers[1], 0);
    atomic_flag_clear(&r->writer);
}

unsigned rt_rcu_enter(rt_rcu_t *r) {
    for (;;) {
        unsigned bucket = atomic_load(&r->epoch) & 1;
        atomic_fetch_add(&r->readers[bucket], 1);
        if ((atomic_load(&r->epoch) & 1) == bucket)
            return bucket;
        atomic_fetch_sub(&r->readers[bucket], 1);
    }
}

void rt_rcu_exit(rt_rcu_t *r, unsigned bucket) { atomic_fetch_sub(&r->readers[bucket], 1); }

/* Flip the epoch, then wait for the bucket that was current to drain. Readers
 * arriving after the flip register in the other bucket and, by program order
 * (unpublish, flip, reader's epoch check, reader's load), cannot see what was
 * unpublished. Writers are serialised; a second concurrent flip would make
 * "the old bucket" ambiguous. */
void rt_rcu_synchronize(rt_rcu_t *r) {
    while (atomic_flag_test_and_set(&r->writer))
        rt_pause();
    unsigned old = atomic_fetch_add(&r->epoch, 1) & 1;
    while (atomic_load(&r->readers[old]))
        rt_pause();
    atomic_flag_clear(&r->writer);
}
