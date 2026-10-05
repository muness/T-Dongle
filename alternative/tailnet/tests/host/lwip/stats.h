/* Host stand-in for the lwIP UDP statistics that main/memory_diagnostics.inc reports (lwip/stats.h). */
#pragma once
#include <stdint.h>
#define LWIP_STATS 1
#define UDP_STATS 1
struct stats_proto { uint32_t xmit, recv, fw, drop, chkerr, lenerr, memerr, rterr, proterr, opterr, err, cachehit; };
struct stats_ { struct stats_proto udp; };
extern struct stats_ lwip_stats;
