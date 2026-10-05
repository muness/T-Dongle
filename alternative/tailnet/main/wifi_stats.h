#pragma once
/* Diagnostics-image-only lwIP counter reports (memory_diagnostics.inc). Pure formatting so the lines are host tested;
 * lwIP itself is read in memory_diagnostics.inc. Every report is ONE bounded JSON line of raw cumulative counters:
 * the coordinator diffs two readings. lwIP's own counters are 16 bits (counter_bits) and wrap: diff modulo 2^bits. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct { uint32_t xmit, recv, fw, drop, chkerr, lenerr, memerr, rterr, proterr, opterr, err, cachehit; } ws_proto;
typedef struct { uint32_t avail, used, max, err, illegal; } ws_pool;
typedef void (*ws_emit_fn)(void *context, const char *line);

/* Widest line: 12 u32 counters (~22 chars each with key) plus the envelope. */
enum { WS_LINE_MAX = 512, WS_NAME_MAX = 24 };

/* Names come from lwIP's static tables, but a report must never let a stray byte break the JSON: keep [A-Za-z0-9_]. */
static inline void ws_clean_name(char *out, const char *name) {
    size_t n = 0;
    for (const char *p = name ? name : ""; *p && n < WS_NAME_MAX - 1; p++) {
        char c = *p;
        out[n++] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') ? c : '_';
    }
    out[n] = 0;
}
static inline bool ws_emit_proto(ws_emit_fn emit, void *context, const char *name, unsigned counter_bits, uint32_t uptime_ms, const ws_proto *p) {
    char clean[WS_NAME_MAX], line[WS_LINE_MAX];
    ws_clean_name(clean, name);
    int n = snprintf(line, sizeof(line),
        "{\"schema\":1,\"kind\":\"lwip_proto\",\"name\":\"%s\",\"uptime_ms\":%lu,\"counter_bits\":%u,\"xmit\":%lu,\"recv\":%lu,\"fw\":%lu,"
        "\"drop\":%lu,\"chkerr\":%lu,\"lenerr\":%lu,\"memerr\":%lu,\"rterr\":%lu,\"proterr\":%lu,\"opterr\":%lu,\"err\":%lu,\"cachehit\":%lu}\r\n",
        clean, (unsigned long)uptime_ms, counter_bits, (unsigned long)p->xmit, (unsigned long)p->recv, (unsigned long)p->fw,
        (unsigned long)p->drop, (unsigned long)p->chkerr, (unsigned long)p->lenerr, (unsigned long)p->memerr, (unsigned long)p->rterr,
        (unsigned long)p->proterr, (unsigned long)p->opterr, (unsigned long)p->err, (unsigned long)p->cachehit);
    if (n < 0 || (size_t)n >= sizeof(line)) return false;
    emit(context, line);
    return true;
}
/* A pool is the heap ("MEM") or one memp pool (PBUF, PBUF_POOL, TCP_PCB, TCP_SEG, ...). err counts failed allocations. */
static inline bool ws_emit_pool(ws_emit_fn emit, void *context, const char *name, uint32_t uptime_ms, const ws_pool *p) {
    char clean[WS_NAME_MAX], line[WS_LINE_MAX];
    ws_clean_name(clean, name);
    int n = snprintf(line, sizeof(line),
        "{\"schema\":1,\"kind\":\"lwip_pool\",\"name\":\"%s\",\"uptime_ms\":%lu,\"avail\":%lu,\"used\":%lu,\"max_used\":%lu,\"err\":%lu,\"illegal\":%lu}\r\n",
        clean, (unsigned long)uptime_ms, (unsigned long)p->avail, (unsigned long)p->used, (unsigned long)p->max,
        (unsigned long)p->err, (unsigned long)p->illegal);
    if (n < 0 || (size_t)n >= sizeof(line)) return false;
    emit(context, line);
    return true;
}

/* Copy lwIP's struct stats_proto / stats_mem (whatever width STAT_COUNTER has) into the fixed-width report types. */
#define WS_PROTO_FROM(dst, src) do { \
    (dst).xmit = (src).xmit; (dst).recv = (src).recv; (dst).fw = (src).fw; (dst).drop = (src).drop; (dst).chkerr = (src).chkerr; \
    (dst).lenerr = (src).lenerr; (dst).memerr = (src).memerr; (dst).rterr = (src).rterr; (dst).proterr = (src).proterr; \
    (dst).opterr = (src).opterr; (dst).err = (src).err; (dst).cachehit = (src).cachehit; } while (0)
#define WS_POOL_FROM(dst, src) do { \
    (dst).avail = (src).avail; (dst).used = (src).used; (dst).max = (src).max; (dst).err = (src).err; (dst).illegal = (src).illegal; } while (0)
