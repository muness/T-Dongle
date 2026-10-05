/**
 * @file ml_net_io.c
 * @brief UDP Network I/O (the shared net_io task's loop body)
 *
 * select() over the UDP sockets (DISCO, STUN) of every membership.
 * DERP TLS is handled by the shared DERP task (ml_derp.c).
 *
 * Classifies received UDP packets and routes to appropriate queues:
 * - DISCO magic prefix -> disco_rx_queue -> wg_mgr task
 * - STUN response -> stun_rx_queue -> coord task
 * - WireGuard packet -> wg_rx_queue -> wg_mgr task
 *
 * Reference: tailscale/wgengine/magicsock/magicsock.go (receiveIPv4)
 */

#include "microlink_internal.h"
#include "ml_runtime.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <errno.h>

static const char *TAG = "ml_net_io";

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* Packet classification */
typedef enum {
    PKT_DISCO,
    PKT_STUN,
    PKT_WIREGUARD,
    PKT_UNKNOWN,
} pkt_type_t;

static pkt_type_t classify_packet(const uint8_t *data, size_t len) {
    /* STUN: starts with 0x00 0x01 (binding request) or 0x01 0x01 (binding response) */
    if (len >= 20 && (data[0] == 0x00 || data[0] == 0x01) && data[1] == 0x01) {
        return PKT_STUN;
    }
    /* DISCO: starts with 6-byte magic */
    if (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0) {
        return PKT_DISCO;
    }
    /* Everything else is WireGuard */
    if (len >= 4) {
        return PKT_WIREGUARD;
    }
    return PKT_UNKNOWN;
}

static void route_udp_packet(microlink_t *ml, uint8_t *data, size_t len,
                              uint32_t src_ip, uint16_t src_port) {
    pkt_type_t type = classify_packet(data, len);

    /* Log ALL direct UDP packets for debugging */
    ESP_LOGD(TAG, "UDP RX: %d bytes from %d.%d.%d.%d:%d type=%s hdr=%02x",
             (int)len,
             (int)((src_ip >> 24) & 0xFF), (int)((src_ip >> 16) & 0xFF),
             (int)((src_ip >> 8) & 0xFF), (int)(src_ip & 0xFF),
             (int)src_port,
             type == PKT_DISCO ? "DISCO" : type == PKT_STUN ? "STUN" :
             type == PKT_WIREGUARD ? "WG" : "UNK",
             len > 0 ? data[0] : 0xFF);

    ml_rx_packet_t pkt = {
        .data = data,
        .len = len,
        .src_ip = src_ip,
        .src_port = src_port,
        .via_derp = false,
    };

    bool wake_wg = false;
    switch (type) {
    case PKT_STUN:
        if (xQueueSend(ml->stun_rx_queue, &pkt, 0) != pdTRUE) {
            tdongle_memory_drop(TDONGLE_DROP_NET_STUN_FULL);
            tdongle_heap_free(TDONGLE_OWNER_PACKET, data);  /* Queue full, drop */
        }
        break;
    case PKT_DISCO:
        if (xQueueSend(ml->disco_rx_queue, &pkt, 0) != pdTRUE) {
            tdongle_memory_drop(TDONGLE_DROP_NET_DISCO_FULL);
            tdongle_heap_free(TDONGLE_OWNER_PACKET, data);
        } else wake_wg = true;
        break;
    case PKT_WIREGUARD:
        if (xQueueSend(ml->wg_rx_queue, &pkt, 0) != pdTRUE) {
            static uint32_t wg_rx_drops = 0;
            if ((++wg_rx_drops & 0x1F) == 1)
                ESP_LOGW(TAG, "WG-RX(direct) queue full: dropped %lu",
                         (unsigned long)wg_rx_drops);
            tdongle_memory_drop(TDONGLE_DROP_NET_WG_FULL);
            tdongle_heap_free(TDONGLE_OWNER_PACKET, data);  /* Queue full, drop */
        } else wake_wg = true;
        break;
    default:
        tdongle_heap_free(TDONGLE_OWNER_PACKET, data);
        break;
    }
    if (wake_wg) ml_rt_wake(ML_RT_TASK_WG_MGR);   /* event driven: a packet arrived, the manager runs now */
}

/* ---------------------------------------------------------------------------
 * The shared loop. ONE select() covers the DISCO and STUN sockets of every attached membership, so a UDP
 * packet wakes the task at once exactly as before and an idle gateway sleeps in a single call instead of
 * one per membership. The mux lock is held while the descriptor sets are built and while ready sockets are
 * drained (never across the select), so a membership that is detached has no packet in flight in this task
 * when detach returns, and its sockets can be closed right after.
 * ------------------------------------------------------------------------- */

typedef struct {
    fd_set *set;
    int max_fd;
} collect_t;

static void add_fd(collect_t *c, int fd) {
    if (fd < 0) return;
    FD_SET(fd, c->set);
    if (fd > c->max_fd) c->max_fd = fd;
}

static void collect_sockets(void *ctx, void *arg) {
    microlink_t *ml = ctx;
    collect_t *c = arg;
    add_fd(c, ml->disco_sock4);
    add_fd(c, ml->stun_sock);
    add_fd(c, ml->stun_sock6);
}

typedef struct {
    const fd_set *ready;
    uint8_t *scratch;
} drain_t;

static void queue_stun(microlink_t *ml, const uint8_t *scratch, int n, uint32_t src_ip, uint16_t src_port) {
    uint8_t *pkt_data = tdongle_heap_tag(TDONGLE_OWNER_PACKET, malloc(n));
    if (!pkt_data) return;
    memcpy(pkt_data, scratch, n);
    ml_rx_packet_t pkt = {
        .data = pkt_data,
        .len = n,
        .src_ip = src_ip,
        .src_port = src_port,
        .via_derp = false,
    };
    if (xQueueSend(ml->stun_rx_queue, &pkt, 0) != pdTRUE) {
        tdongle_memory_drop(TDONGLE_DROP_NET_STUN_FULL);
        tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt_data);
    }
}

static void drain_ready(void *ctx, void *arg) {
    microlink_t *ml = ctx;
    drain_t *d = arg;
    uint8_t *udp_buf = d->scratch;

    /* DISCO UDP socket */
    if (ml->disco_sock4 >= 0 && FD_ISSET(ml->disco_sock4, d->ready)) {
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        int n = ml_recvfrom(ml->disco_sock4, udp_buf, ML_NET_IO_SCRATCH_BYTES, 0,
                            (struct sockaddr *)&src_addr, &addr_len);
        if (n > 0) {
            uint8_t *pkt_data = tdongle_heap_tag(TDONGLE_OWNER_PACKET, malloc(n));
            if (pkt_data) {
                memcpy(pkt_data, udp_buf, n);
                uint32_t src_ip = ntohl(src_addr.sin_addr.s_addr);
                uint16_t src_port = ntohs(src_addr.sin_port);
                route_udp_packet(ml, pkt_data, n, src_ip, src_port);
            }
        }
    }

    /* STUN socket (IPv4) */
    if (ml->stun_sock >= 0 && FD_ISSET(ml->stun_sock, d->ready)) {
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        int n = ml_recvfrom(ml->stun_sock, udp_buf, ML_NET_IO_SCRATCH_BYTES, 0,
                            (struct sockaddr *)&src_addr, &addr_len);
        if (n > 0) queue_stun(ml, udp_buf, n, ntohl(src_addr.sin_addr.s_addr), ntohs(src_addr.sin_port));
    }

    /* STUN socket (IPv6) */
    if (ml->stun_sock6 >= 0 && FD_ISSET(ml->stun_sock6, d->ready)) {
        struct sockaddr_in6 src_addr6;
        socklen_t addr_len = sizeof(src_addr6);
        int n = ml_recvfrom(ml->stun_sock6, udp_buf, ML_NET_IO_SCRATCH_BYTES, 0,
                            (struct sockaddr *)&src_addr6, &addr_len);
        /* IPv6: src_ip 0, the parser reads the address from the payload (parse_response_ipv6) */
        if (n > 0) queue_stun(ml, udp_buf, n, 0, ntohs(src_addr6.sin6_port));
    }
}

static unsigned consecutive_badf;      /* only the net_io task reads or writes it */

void ml_net_io_pass(ml_mux_t *mux, uint8_t *scratch) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    collect_t c = { .set = &read_fds, .max_fd = -1 };
    ml_mux_foreach(mux, collect_sockets, &c);

    if (c.max_fd < 0) {
        /* No UDP sockets yet (nothing attached, or the memberships have not opened them): just yield. */
        vTaskDelay(pdMS_TO_TICKS(50));
        return;
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };  /* 50 ms select timeout, as before */
    int sel = ml_select_fds(c.max_fd + 1, &read_fds, NULL, NULL, &tv);
    if (sel < 0) {
        /* A membership's control task closes its STUN sockets while this select may be using them. The
         * descriptor sets are rebuilt from the memberships on the next pass, so one EBADF costs nothing
         * (and must not delay the other memberships); only a persistent failure backs off. */
        if (errno == EBADF && ++consecutive_badf < 5) return;
        if (errno != EINTR) {
            ESP_LOGW(TAG, "select error: %d", errno);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        return;
    }
    consecutive_badf = 0;
    if (sel == 0) return;  /* Timeout */

    drain_t d = { .ready = &read_fds, .scratch = scratch };
    ml_mux_foreach(mux, drain_ready, &d);
}
