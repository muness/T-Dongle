/* Build-time checks for the lwIP TCP window settings (sdkconfig.defaults). Included by
 * gateway_main.c so a firmware build with inconsistent values does not compile, and compiled on
 * the host by tools/test-tcp-window.py against the values parsed from sdkconfig.defaults.
 * Rationale and heap accounting: docs/adr/0015-data-plane-io.md. */
#pragma once
#include "lwip/opt.h"

/* IDF lwIP has no per-socket TCP_WINDOW/TCP_SNDBUF (its Kconfig help is stale), TCP_WND is a
 * compile-time constant used as the per-pcb maximum, and LWIP_WND_SCALE needs SPIRAM. So the
 * window is global and must stay inside 16 bits. */
_Static_assert(!LWIP_WND_SCALE ? TCP_WND <= 65535 : 1, "TCP_WND over 64 KB needs window scaling, which this board cannot enable");
/* A segment is held until the application reads it. The mailbox bounds queued segments per socket;
 * a smaller mailbox than window/MSS + 2 makes lwIP drop segments the window said it would accept. */
_Static_assert(DEFAULT_TCP_RECVMBOX_SIZE >= TCP_WND / TCP_MSS + 2, "TCP receive mailbox smaller than window/MSS + 2");
/* With CONFIG_LWIP_L2_TO_L3_COPY off, queued TCP data pins Wi-Fi RX buffers. One stalled socket
 * must not be able to take more than half of the dynamic RX pool. */
_Static_assert(TCP_WND / TCP_MSS <= CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM / 2, "TCP window can pin more than half the Wi-Fi RX buffers");
/* lwIP's default segment pool is 16. IDF builds with MEMP_MEM_MALLOC (the pool is heap and not a limit), so
 * this only keeps the send buffer within that default; the real bound is per socket. */
_Static_assert(TCP_SND_BUF / TCP_MSS <= MEMP_NUM_TCP_SEG, "TCP send buffer needs more segments than the pool holds");
_Static_assert(TCP_SND_BUF >= 2 * TCP_MSS && TCP_WND >= 2 * TCP_MSS, "lwIP needs at least two segments of window and send buffer");
