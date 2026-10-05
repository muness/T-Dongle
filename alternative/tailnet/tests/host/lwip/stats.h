/* Host stand-in for the parts of lwip/stats.h that main/memory_diagnostics.inc reads: same field names and the same
 * 16-bit STAT_COUNTER as ESP-IDF v5.5.5 (LWIP_STATS_LARGE is 0). */
#pragma once
#include <stdint.h>
typedef uint16_t STAT_COUNTER;
struct stats_proto { STAT_COUNTER xmit, recv, fw, drop, chkerr, lenerr, memerr, rterr, proterr, opterr, err, cachehit; };
struct stats_mem { const char *name; STAT_COUNTER err; uint16_t avail, used, max; STAT_COUNTER illegal; };
enum { MEMP_PBUF, MEMP_PBUF_POOL, MEMP_TCP_SEG, MEMP_MAX };
struct stats_ {
    struct stats_proto link, etharp, ip, icmp, udp, tcp;
    struct stats_mem mem;
    struct stats_mem *memp[MEMP_MAX];
};
static struct stats_ lwip_stats;
