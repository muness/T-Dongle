#ifndef ML_NET_IO_DRAIN_H
#define ML_NET_IO_DRAIN_H
/* Draining one ready UDP socket (the loop body of ml_net_io.c, kept here so the host tests run the real code).
 *
 * The bug this replaces: net_io read ONE datagram from a ready socket per select() pass. lwIP's per-socket receive mailbox
 * holds CONFIG_LWIP_UDP_RECVMBOX_SIZE datagrams (6 by default) and, when it is full, recv_udp() frees the datagram and
 * returns WITHOUT counting it anywhere (api_msg.c: sys_mbox_trypost failure; lwIP's udp.recv already counted it, udp.drop
 * did not). net_io (priority 7, core 0) is scheduled only after the Wi-Fi and tcpip tasks of the same core have finished a
 * burst, so a burst of more than 6 datagrams arrives faster than one-per-pass can empty it, and the excess vanished silently:
 * measured ~7 % of a 3 Mbit/s UDP stream. Now a ready socket is read until it is empty (EWOULDBLOCK), capped so one busy
 * socket cannot hold the shared net_io task (or the mux lock) for long; whatever is left stays in the mailbox, select()
 * reports the socket ready again at once, and `drain_capped` counts the times that happened.
 *
 * Order: datagrams of one socket are delivered to `sink` in the order recv returned them, which is lwIP's arrival order. */
#include <stddef.h>
#include <stdint.h>
#include "ml_rx_stats.h"

#define ML_NET_IO_DEEP 4            /* a drain this deep means the mailbox (CONFIG_LWIP_UDP_RECVMBOX_SIZE, 6) was within two datagrams of overflowing */
#define ML_NET_IO_DRAIN_CAP 16      /* datagrams per socket per pass: >= the mailbox, so a full mailbox is emptied in one go */
#define ML_DRAIN_EMPTY (-1)         /* recv: nothing (more) to read (EAGAIN / EWOULDBLOCK) */
#define ML_DRAIN_ERROR (-2)         /* recv: failed for another reason */

/* Returns the datagram length (0 allowed: an empty UDP datagram), ML_DRAIN_EMPTY or ML_DRAIN_ERROR. */
typedef int (*ml_drain_recv_fn)(void *ctx, uint8_t *buf, size_t cap, uint32_t *src_ip, uint16_t *src_port);
typedef void (*ml_drain_sink_fn)(void *ctx, const uint8_t *data, int len, uint32_t src_ip, uint16_t src_port);

static inline unsigned ml_net_io_drain(ml_drain_recv_fn recv, ml_drain_sink_fn sink, void *ctx, uint8_t *scratch, size_t cap, unsigned max) {
    unsigned got = 0;
    while (got < max) {
        uint32_t ip = 0;
        uint16_t port = 0;
        int n = recv(ctx, scratch, cap, &ip, &port);
        if (n == ML_DRAIN_EMPTY) break;
        if (n < 0) {
            ML_RX_STAT(udp_recv_err);
            break;
        }
        got++;
        ML_RX_STAT(udp_rx);
        if (n == 0) {
            ML_RX_STAT(udp_rx_empty);
            continue;
        }
        sink(ctx, scratch, n, ip, port);
    }
    ML_RX_STAT(drain_calls);
    if (got == max) ML_RX_STAT(drain_capped);
    if (got >= ML_NET_IO_DEEP) ML_RX_STAT(drain_deep);
    ml_rx_stat_burst(got);
    return got;
}

#endif
