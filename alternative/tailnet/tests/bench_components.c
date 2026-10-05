/* Host cost of each per-packet step the old router performed, against what replaced it. Same
 * code shapes as router_v1.c / route_table.c, worst-case position (last of 64), -O2. Host
 * nanoseconds only; use ratios, and see forwarding-latency.md for the board numbers. */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../main/route_table.c"

typedef struct { uint32_t id, peer, alias; } old_alias_t;
typedef struct { uint32_t id, peer, host, alias; uint16_t local, remote, mapped; uint8_t proto; int64_t touched; } old_flow_t;
static old_alias_t old_aliases[64];
static old_flow_t old_flows[64];
static uint32_t old_generation_of[64];
static atomic_uint generation = 1;
static volatile uint32_t sink;
static double now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e9 + t.tv_nsec; }
#define TIME(name, body) do { double best = 1e30; for (int r = 0; r < 7; r++) { double s = now_ns(); for (unsigned i = 0; i < 200000; i++) { body } double v = (now_ns() - s) / 200000; if (v < best) best = v; } printf("  %-58s %8.1f ns\n", name, best); } while (0)
static uint16_t rd16(const uint8_t *p) { return p[0] << 8 | p[1]; }
static uint32_t sum(const uint8_t *p, size_t n, uint32_t s) { while (n > 1) { s += rd16(p); p += 2; n -= 2; } if (n) s += p[0] << 8; return s; }
int main(void) {
    for (unsigned i = 0; i < 64; i++) {
        old_aliases[i] = (old_alias_t){1 + i, 0x64400000 + i, 0xc6120001 + i};
        old_flows[i] = (old_flow_t){1 + i, 0x64400000 + i, 0xc0a84d02, 0xc6120001 + i, 1000 + i, 80, 40000 + i, 6, 1000};
        old_generation_of[i] = 1;
    }
    uint8_t packet[1400];
    for (unsigned i = 0; i < sizeof(packet); i++) packet[i] = rand();
    printf("old per-packet steps (1400 B packet, worst position):\n");
    TIME("alias scan, 64 entries, match last", { uint32_t dest = 0xc6120001 + 63 + (i & 0); old_alias_t *a = NULL; for (unsigned k = 0; k < 64; k++) if (old_aliases[k].alias == dest && old_aliases[k].id) { a = &old_aliases[k]; break; } sink = a->peer; });
    TIME("flow scan, 64 entries, atomic generation each, match last", { old_flow_t *f = NULL; for (unsigned k = 0; k < 64; k++) if (old_generation_of[k] == atomic_load(&generation) && old_flows[k].id == 64 + (i & 0) && old_flows[k].peer == 0x64400000 + 63 && old_flows[k].host == 0xc0a84d02 && old_flows[k].local == 1063 && old_flows[k].remote == 80 && old_flows[k].proto == 6) { f = &old_flows[k]; break; } sink = f->mapped; });
    TIME("full IPv4+TCP checksum recompute over 1400 B", { packet[10] = packet[11] = 0; uint32_t s = sum(packet, 20, 0); sink = s; s = sum(packet + 20, 1380, sum(packet + 12, 8, 0) + 6 + 1380); sink = s; });
    TIME("malloc + copy + free of 1400 B (the per-packet buffer)", { uint8_t *b = malloc(1400); memcpy(b, packet, 1400); sink = b[i & 1023]; free(b); });
    printf("new per-packet steps:\n");
    static rt_t t;
    rt_init(&t);
    for (unsigned i = 0; i < 64; i++) rt_alias_insert(&t, &(rt_alias_t){1 + i, 0x64400000 + i, 0xc6120001 + i});
    rt_flow_t f;
    for (unsigned i = 0; i < 64; i++) rt_flow_create(&t, &(rt_flow_t){1 + i, 0x64400000 + i, 0xc6120001 + i, 0xc0a84d02, 1000 + i, 80, 0, 6}, 1, 1000, &f);
    TIME("flow hash lookup + touch (critical section x2), 64 live", { rt_flow_out(&t, 0xc6120001 + 63, 0xc0a84d02, 1063, 80, 6, 1, &f); rt_flow_touch(&t, &f, 1, 2000 + i); sink = f.mapped; });
    TIME("alias hash lookup (first packet of a flow only)", { rt_alias_t a; rt_alias_find(&t, 0xc6120001 + 63, &a); sink = a.peer; });
    TIME("tunnel reply: direct-indexed flow lookup", { rt_flow_in(&t, 64, 0x64400000 + 63, 80, f.mapped, 6, 1, 2000 + i, &f); sink = f.alias; });
    TIME("incremental checksum: 3 address/port/TTL updates (IP + L4)", { rt_csum_replace32(packet + 10, 0xc0a84d02, 0x64400001); rt_csum_replace32(packet + 10, 0xc6120001, 0x64400002); rt_csum_replace16(packet + 36, 3000, 40001); rt_csum_replace32(packet + 36, 0xc0a84d02, 0x64400001); rt_csum_replace32(packet + 36, 0xc6120001, 0x64400002); rt_csum_replace16(packet + 18, 0x4006, 0x3f06); });
    TIME("copy 1400 B into the static scratch buffer", { static uint8_t scratch[1400]; memcpy(scratch, packet, 1400); sink = scratch[i & 1023]; });
    return 0;
}
