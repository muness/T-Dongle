/* Host stand-in for the lwIP settings that main/memory_diagnostics.inc reports. */
#pragma once
#define TCP_WND 5760
#define TCP_SND_BUF 5760
#define TCP_MSS 1440
#define TCP_SND_QUEUELEN 16
#define LWIP_WND_SCALE 0
#define PBUF_POOL_SIZE 16
#define PBUF_POOL_BUFSIZE 1496
#define MEMP_NUM_TCP_PCB 16
#define MEMP_NUM_TCP_SEG 16
/* lwIP statistics as the diagnostics image configures them (CONFIG_LWIP_STATS); -DHOST_LWIP_STATS=0 models the release image. */
#ifndef HOST_LWIP_STATS
#define HOST_LWIP_STATS 1
#endif
#define LWIP_STATS HOST_LWIP_STATS
#define LWIP_STATS_DISPLAY 1
#define LINK_STATS LWIP_STATS
#define ETHARP_STATS LWIP_STATS
#define IP_STATS LWIP_STATS
#define ICMP_STATS LWIP_STATS
#define UDP_STATS LWIP_STATS
#define TCP_STATS LWIP_STATS
#define MEM_STATS LWIP_STATS
#define MEMP_STATS LWIP_STATS
