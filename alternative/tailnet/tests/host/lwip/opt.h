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
