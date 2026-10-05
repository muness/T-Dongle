/* Data-structure tests for route_table.c: incremental checksums, hash tables
 * against a straightforward model, ownership, eviction, and (under TSan) the
 * lock and the RCU. Build with -fsanitize=address,undefined, and separately with
 * -fsanitize=thread -DRT_TSAN to run the concurrent cases. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../main/route_table.c"

static uint64_t rng_state = 88172645463325252ull;
static uint32_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 11);
}
static uint16_t full_checksum(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    for (; n > 1; p += 2, n -= 2)
        s += p[0] << 8 | p[1];
    if (n)
        s += p[0] << 8;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return ~s;
}
static int equivalent(uint16_t a, uint16_t b) { return a == b || (a == 0 && b == 0xffff) || (a == 0xffff && b == 0); }

/* RFC 1624: updating a checksum after changing 16/32-bit fields must equal the
 * checksum of the changed data, for random data, lengths and alignments. */
static void checksums(void) {
    for (unsigned iter = 0; iter < 200000; iter++) {
        uint8_t buf[64];
        size_t n = 8 + (rnd() % 28) * 2;
        for (size_t i = 0; i < n; i++)
            buf[i] = rnd();
        if (iter % 97 == 0)
            memset(buf, iter & 1 ? 0xff : 0, n); /* all-zero / all-ones corner cases */
        buf[0] = buf[1] = 0; /* checksum field */
        uint16_t c = full_checksum(buf, n);
        buf[0] = c >> 8;
        buf[1] = c;
        assert(full_checksum(buf, n) == 0);
        unsigned at = 2 + 2 * (rnd() % ((n - 2) / 2 - 1));
        if (rnd() & 1) {
            uint16_t old = buf[at] << 8 | buf[at + 1], now = rnd();
            buf[at] = now >> 8;
            buf[at + 1] = now;
            rt_csum_replace16(buf, old, now);
        } else if (at + 4 <= n) {
            uint32_t old = (uint32_t)buf[at] << 24 | buf[at + 1] << 16 | buf[at + 2] << 8 | buf[at + 3], now = rnd() * 2654435761u;
            buf[at] = now >> 24;
            buf[at + 1] = now >> 16;
            buf[at + 2] = now >> 8;
            buf[at + 3] = now;
            rt_csum_replace32(buf, old, now);
        }
        /* Equal to a full recompute up to the two representations of zero. */
        uint16_t stored = buf[0] << 8 | buf[1];
        buf[0] = buf[1] = 0;
        assert(equivalent(stored, full_checksum(buf, n)));
        buf[0] = stored >> 8;
        buf[1] = stored;
        assert(full_checksum(buf, n) == 0);
    }
    /* Replacing a value by itself keeps a valid checksum valid. */
    uint8_t csum[2] = {0xff, 0xff};
    rt_csum_replace16(csum, 0x1234, 0x1234);
    assert(equivalent(csum[0] << 8 | csum[1], 0xffff));
}

/* Model of the flow table exactly as the pre-optimisation router implemented it. */
typedef struct {
    uint32_t id, peer, host, alias;
    uint16_t local, remote, mapped;
    uint8_t proto;
    int64_t touched;
} model_flow;
static model_flow model[64];
static uint32_t model_generation[64];
static bool model_out(uint32_t id, uint32_t peer, uint32_t alias, uint32_t host, uint16_t local, uint16_t remote, uint8_t proto, uint32_t generation, int64_t now, bool create, rt_flow_t *out) {
    model_flow *f = NULL;
    for (unsigned i = 0; i < 64; i++)
        if (model_generation[i] == generation && model[i].id == id && model[i].peer == peer && model[i].host == host && model[i].local == local &&
            model[i].remote == remote && model[i].proto == proto) {
            f = &model[i];
            break;
        }
    if (!f && create)
        for (unsigned i = 0; i < 64; i++)
            if (!model[i].id || model_generation[i] != generation || now - model[i].touched > 120000000) {
                f = &model[i];
                *f = (model_flow){id, peer, host, alias, local, remote, 40000 + i + 64 * ((generation - 1) % 300), proto, now};
                model_generation[i] = generation;
                break;
            }
    if (!f)
        return false;
    f->touched = now;
    *out = (rt_flow_t){f->id, f->peer, f->alias, f->host, f->local, f->remote, f->mapped, f->proto};
    return true;
}
static bool model_in(uint32_t id, uint32_t peer, uint16_t remote, uint16_t mapped, uint8_t proto, uint32_t generation, int64_t now, rt_flow_t *out) {
    for (unsigned i = 0; i < 64; i++) {
        model_flow *f = &model[i];
        if (model_generation[i] == generation && f->id == id && f->peer == peer && f->remote == remote && f->mapped == mapped && f->proto == proto &&
            now - f->touched < 120000000) {
            f->touched = now;
            *out = (rt_flow_t){f->id, f->peer, f->alias, f->host, f->local, f->remote, f->mapped, f->proto};
            return true;
        }
    }
    return false;
}
static unsigned cover_hit, cover_create, cover_full, cover_reply;
static bool same(const rt_flow_t *a, const rt_flow_t *b) { return !memcmp(a, b, sizeof(*a)); }

static void flows_differential(unsigned seed) {
    rng_state ^= seed * 0x9e3779b97f4a7c15ull;
    rt_t t;
    rt_init(&t);
    memset(model, 0, sizeof(model));
    memset(model_generation, 0, sizeof(model_generation));
    int64_t now = 1000;
    uint32_t generation = 1;
    /* A small key space makes hits, collisions, expiry reuse and table-full common. */
    for (unsigned op = 0; op < 20000; op++) {
        unsigned kind = rnd() % 100;
        if (kind < 55) {
            /* The key space is chosen per seed: from far below to a little above 64 flows. */
            unsigned space = seed % 3 == 0 ? 2 : seed % 3 == 1 ? 4 : 8;
            uint32_t alias = 0xc6120001 + rnd() % (space * 2); /* alias determines (id,peer) */
            uint32_t peer = 0x64400001 + (alias - 0xc6120001) % 6;
            uint32_t id = 1 + (alias - 0xc6120001) / 6;
            uint32_t host = 0xc0a84d02 + rnd() % 2;
            uint16_t local = 1000 + rnd() % space, remote = 80 + rnd() % 2;
            uint8_t proto = rnd() & 1 ? 6 : 17;
            rt_flow_t a, b;
            bool ha = rt_flow_out(&t, alias, host, local, remote, proto, generation, &a);
            bool hb = model_out(id, peer, alias, host, local, remote, proto, generation, now, false, &b);
            assert(ha == hb && (!ha || same(&a, &b)));
            cover_hit += ha;
            if (ha)
                rt_flow_touch(&t, &a, generation, now);
            if (!ha) {
                rt_flow_t key = {id, peer, alias, host, local, remote, 0, proto};
                ha = rt_flow_create(&t, &key, generation, now, &a);
                hb = model_out(id, peer, alias, host, local, remote, proto, generation, now, true, &b);
                assert(ha == hb && (!ha || same(&a, &b)));
                cover_create += ha;
                cover_full += !ha;
            }
        } else if (kind < 85) {
            /* a reply: mostly one that exists, sometimes wrong in one field */
            unsigned i = rnd() % 64;
            model_flow f = model[i];
            uint32_t id = f.id ? f.id : 1 + rnd() % 4, peer = f.peer ? f.peer : 0x64400001;
            uint16_t remote = f.remote ? f.remote : 80, mapped = f.mapped ? f.mapped : 40000 + rnd() % 64;
            uint8_t proto = f.proto ? f.proto : 6;
            switch (rnd() % 8) {
            case 0: id ^= 1; break;
            case 1: peer ^= 1; break;
            case 2: remote ^= 1; break;
            case 3: mapped += 1 + rnd() % 70; break;
            case 4: proto ^= 6 ^ 17; break;
            default: break;
            }
            rt_flow_t a, b;
            bool ha = rt_flow_in(&t, id, peer, remote, mapped, proto, generation, now, &a);
            bool hb = model_in(id, peer, remote, mapped, proto, generation, now, &b);
            assert(ha == hb && (!ha || same(&a, &b)));
            cover_reply += ha;
        } else if (kind < 90) {
            uint32_t id = 1 + rnd() % 4;
            rt_flows_forget(&t, id);
            for (unsigned i = 0; i < 64; i++)
                if (model[i].id == id)
                    memset(&model[i], 0, sizeof(model[i]));
        } else if (kind < 91)
            generation++;
        else
            now += rnd() % 16 ? rnd() % 1000000 : rnd() % 150000000;
    }
}

/* Aliases: while within capacity the cache is exact; beyond it, a hit is always
 * the recorded binding and an alias is never returned for the wrong identity. */
static void aliases(void) {
    rt_t t;
    rt_init(&t);
    rt_alias_t out;
    uint32_t alias;
    for (unsigned i = 0; i < 64; i++)
        assert(rt_alias_insert(&t, &(rt_alias_t){1 + i / 8, 0x64400000 + i, RT_ALIAS_BASE + i}));
    for (unsigned i = 0; i < 64; i++) {
        assert(rt_alias_find(&t, RT_ALIAS_BASE + i, &out) && out.id == 1 + i / 8 && out.peer == 0x64400000 + i);
        assert(rt_alias_find_key(&t, 1 + i / 8, 0x64400000 + i, &alias) && alias == RT_ALIAS_BASE + i);
    }
    /* idempotent; a conflicting binding for an existing alias or identity is refused */
    assert(rt_alias_insert(&t, &(rt_alias_t){1, 0x64400000, RT_ALIAS_BASE}));
    assert(!rt_alias_insert(&t, &(rt_alias_t){2, 0x64400000, RT_ALIAS_BASE}));
    assert(!rt_alias_insert(&t, &(rt_alias_t){1, 0x64400000, RT_ALIAS_BASE + 100}));
    assert(!rt_alias_insert(&t, &(rt_alias_t){0, 1, RT_ALIAS_BASE + 100}) && !rt_alias_insert(&t, &(rt_alias_t){1, 1, 0}));
    /* eviction: a recently used alias survives a flood of new ones; every hit is correct */
    unsigned kept = 0;
    for (unsigned n = 0; n < 5000; n++) {
        unsigned i = 64 + n;
        if (n % 3 == 0)
            kept += rt_alias_find(&t, RT_ALIAS_BASE + 5, &out);
        assert(rt_alias_insert(&t, &(rt_alias_t){100 + i, 0x64500000 + i, RT_ALIAS_BASE + i}));
        for (unsigned probe = 0; probe < 3; probe++) {
            uint32_t a = RT_ALIAS_BASE + rnd() % (i + 1);
            if (rt_alias_find(&t, a, &out)) {
                unsigned k = a - RT_ALIAS_BASE;
                assert(out.alias == a && out.id == (k < 64 ? 1 + k / 8 : 100 + k) && out.peer == (k < 64 ? 0x64400000 + k : 0x64500000 + k));
            }
        }
        unsigned live = 0;
        for (unsigned s = 0; s < RT_ALIASES; s++)
            live += t.alias[s].used;
        assert(live == RT_ALIASES);
    }
    assert(kept > 1000); /* the hot alias survived (CLOCK second chance) */
    /* forget removes exactly one identity's entries and keeps chains intact */
    unsigned before = 0, after = 0;
    for (unsigned s = 0; s < RT_ALIASES; s++)
        before += t.alias[s].used;
    unsigned id = t.alias[7].alias.id;
    unsigned removed = rt_alias_forget(&t, id);
    for (unsigned s = 0; s < RT_ALIASES; s++)
        after += t.alias[s].used;
    assert(removed == 1 && after == before - 1 && !rt_alias_find_key(&t, id, t.alias[7].alias.peer, &alias));
    for (unsigned s = 0; s < RT_ALIASES; s++)
        if (t.alias[s].used)
            assert(rt_alias_find(&t, t.alias[s].alias.alias, &out) && out.id == t.alias[s].alias.id);
}

/* Ownership: the mapped port is only a hint for the slot; every field must match. */
static void ownership(void) {
    rt_t t;
    rt_init(&t);
    rt_flow_t f, key = {7, 0x64400009, 0xc6120007, 0xc0a84d02, 5555, 443, 0, 6};
    assert(rt_flow_create(&t, &key, 1, 1000, &f));
    assert(f.mapped >= RT_MAPPED_BASE && f.mapped < RT_MAPPED_BASE + 64);
    rt_flow_t o;
    assert(rt_flow_in(&t, 7, 0x64400009, 443, f.mapped, 6, 1, 2000, &o) && o.host == 0xc0a84d02 && o.local == 5555 && o.alias == 0xc6120007);
    assert(!rt_flow_in(&t, 8, 0x64400009, 443, f.mapped, 6, 1, 2000, &o)); /* other membership */
    assert(!rt_flow_in(&t, 7, 0x6440000a, 443, f.mapped, 6, 1, 2000, &o)); /* other peer */
    assert(!rt_flow_in(&t, 7, 0x64400009, 444, f.mapped, 6, 1, 2000, &o)); /* other remote port */
    assert(!rt_flow_in(&t, 7, 0x64400009, 443, f.mapped, 17, 1, 2000, &o)); /* other protocol */
    assert(!rt_flow_in(&t, 7, 0x64400009, 443, f.mapped + 64, 6, 1, 2000, &o)); /* same slot, other generation port */
    assert(!rt_flow_in(&t, 7, 0x64400009, 443, f.mapped, 6, 2, 2000, &o)); /* USB detached since */
    assert(!rt_flow_in(&t, 7, 0x64400009, 443, 39999, 6, 1, 2000, &o) && !rt_flow_in(&t, 7, 0x64400009, 443, 65535, 6, 1, 2000, &o));
    assert(!rt_flow_in(&t, 7, 0x64400009, 443, f.mapped, 6, 1, 2000 + RT_FLOW_IDLE_US, &o)); /* idle */
    assert(rt_flow_in(&t, 7, 0x64400009, 443, f.mapped, 6, 1, 3000, &o));
    /* the same tuple via a different alias is a different flow */
    rt_flow_t other = key;
    other.alias++;
    other.id = 8;
    other.peer++;
    rt_flow_t g;
    assert(rt_flow_create(&t, &other, 1, 3000, &g) && g.mapped != f.mapped);
    assert(rt_flows_forget(&t, 7) == 1 && !rt_flow_in(&t, 7, 0x64400009, 443, f.mapped, 6, 1, 3000, &o));
    assert(!rt_flow_out(&t, 0xc6120007, 0xc0a84d02, 5555, 443, 6, 1, &o));
    assert(rt_flow_in(&t, 8, other.peer, 443, g.mapped, 6, 1, 3000, &o));
    /* table full: 64 live flows refuse the 65th, and an idle one is reclaimed */
    rt_init(&t);
    for (unsigned i = 0; i < 64; i++)
        assert(rt_flow_create(&t, &(rt_flow_t){1, 2, 3, 0xc0a84d02, 1000 + i, 80, 0, 6}, 1, 1000, &f));
    assert(!rt_flow_create(&t, &(rt_flow_t){1, 2, 3, 0xc0a84d02, 2000, 80, 0, 6}, 1, 1000, &f));
    assert(rt_flow_create(&t, &(rt_flow_t){1, 2, 3, 0xc0a84d02, 2000, 80, 0, 6}, 1, 1000 + RT_FLOW_IDLE_US + 1, &f));
    /* a mapped port stays inside 16 bits for every generation */
    for (uint32_t gen = 1; gen < 5000; gen++) {
        rt_init(&t);
        assert(rt_flow_create(&t, &(rt_flow_t){1, 2, 3, 4, 5, 6, 0, 6}, gen, 1, &f) && f.mapped >= RT_MAPPED_BASE && f.mapped < 60000);
    }
}

#ifdef RT_TSAN
/* ---- concurrency ---------------------------------------------------------- */
typedef struct {
    atomic_uint alive; /* 1 while the object may be used */
    uint32_t payload;
} guarded;
static rt_rcu_t rcu;
static _Atomic(guarded *) published;
static atomic_bool stop;
static atomic_uint violations, reads;
static void *rcu_reader(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        unsigned bucket = rt_rcu_enter(&rcu);
        guarded *g = atomic_load(&published);
        if (g) {
            /* Between enter and exit the writer must not have retired it. */
            for (unsigned i = 0; i < 50; i++)
                if (!atomic_load(&g->alive) || g->payload != 0xfeedface)
                    atomic_fetch_add(&violations, 1);
            atomic_fetch_add(&reads, 1);
        }
        rt_rcu_exit(&rcu, bucket);
    }
    return NULL;
}
static void rcu_concurrent(void) {
    rt_rcu_init(&rcu);
    pthread_t readers[3];
    for (unsigned i = 0; i < 3; i++)
        pthread_create(&readers[i], NULL, rcu_reader, NULL);
    for (unsigned round = 0; round < 3000; round++) {
        guarded *g = malloc(sizeof(*g));
        atomic_init(&g->alive, 1);
        g->payload = 0xfeedface;
        atomic_store(&published, g);
        for (volatile unsigned spin = 0; spin < 200; spin++)
            ;
        atomic_store(&published, NULL);
        rt_rcu_synchronize(&rcu);
        atomic_store(&g->alive, 0); /* "destroy" */
        g->payload = 0xdeaddead;
        free(g);
    }
    atomic_store(&stop, true);
    for (unsigned i = 0; i < 3; i++)
        pthread_join(readers[i], NULL);
    assert(atomic_load(&violations) == 0 && atomic_load(&reads) > 0);
}
static rt_t shared;
static void *table_worker(void *arg) {
    unsigned me = (unsigned)(uintptr_t)arg;
    uint64_t state = 12345 + me;
    for (unsigned i = 0; i < 40000; i++) {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        unsigned r = state >> 33;
        uint32_t id = 1 + r % 3, alias = RT_ALIAS_BASE + id;
        rt_flow_t f;
        switch (me) {
        case 0: /* usb_routes */
            if (!rt_flow_out(&shared, alias, 0xc0a84d02, 1000 + r % 20, 80, 6, 1, &f))
                rt_flow_create(&shared, &(rt_flow_t){id, 7, alias, 0xc0a84d02, 1000 + r % 20, 80, 0, 6}, 1, i, &f);
            else
                assert(f.id == id && f.alias == alias && f.proto == 6);
            rt_alias_find(&shared, alias, &(rt_alias_t){0});
            break;
        case 1: /* tunnel input */
            if (rt_flow_in(&shared, id, 7, 80, 40000 + r % 64, 6, 1, i, &f))
                assert(f.id == id && f.peer == 7 && f.alias == RT_ALIAS_BASE + id);
            break;
        case 2: /* control: gateway_alias, forget */
            rt_alias_insert(&shared, &(rt_alias_t){id, 7, alias});
            if (r % 50 == 0) {
                rt_alias_forget(&shared, id);
                rt_flows_forget(&shared, id);
            }
            break;
        }
    }
    return NULL;
}
static void table_concurrent(void) {
    rt_init(&shared);
    pthread_t th[3];
    for (uintptr_t i = 0; i < 3; i++)
        pthread_create(&th[i], NULL, table_worker, (void *)i);
    for (unsigned i = 0; i < 3; i++)
        pthread_join(th[i], NULL);
}
#endif

int main(void) {
    checksums();
    for (unsigned seed = 1; seed <= 24; seed++)
        flows_differential(seed);
    /* the random walk must actually exercise hits, creates, replies and a full table */
    printf("coverage hit=%u create=%u full=%u reply=%u\n", cover_hit, cover_create, cover_full, cover_reply);
    assert(cover_hit > 10000 && cover_create > 1000 && cover_full > 100 && cover_reply > 1000);
    aliases();
    ownership();
#ifdef RT_TSAN
    rcu_concurrent();
    table_concurrent();
#endif
    puts("route_table: incremental checksums = full recompute, hashed flows = linear model, alias cache correctness, ownership, RCU/lock concurrency");
    return 0;
}
