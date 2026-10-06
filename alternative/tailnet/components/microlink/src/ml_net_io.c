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
#include "ml_net_io_drain.h"
#include "ml_wg_rx_budget.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <errno.h>

static const char *TAG = "ml_net_io";

ml_rx_stats_t ml_rx_stats;   /* zero-initialised; see ml_rx_stats.h */
atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];   /* refusals by the heap budget, by site (ml_heap_budget.h) */
ml_wgrx_budget_t ml_wgrx_budget;   /* bytes of WireGuard datagrams waiting in any membership's wg_rx_queue; see ml_wg_rx_budget.h */
bool ml_wgrx_join_busy(void) { return ml_neg_busy(ml_rt_negotiation()); }   /* a join holds the negotiation token: the queue yields heap to it */

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

/* The elastic check for a datagram, made BEFORE the copy that crosses to the receiving task, so a refused datagram never takes heap
 * (it used to be copied first and freed when the queue refused it: one block, but allocated below the floor and a malloc/free pair
 * per refusal in a flood). True: the caller makes the copy and owns what the check reserved (WireGuard: ml_wgrx_release when the copy
 * is not queued). DISCO and STUN: the floor, with the small-datagram exemption for an empty queue (ml_hb_rx_ok). */
static bool net_io_admit(microlink_t *ml, pkt_type_t type, size_t len) {
    const size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (type == PKT_WIREGUARD) {
        ml_wgrx_verdict_t admit = ml_wgrx_admit_gated(&ml_wgrx_budget, len, free_internal, ml_wgrx_join_busy);
        if (admit == ML_WGRX_OK) return true;
        if (admit == ML_WGRX_BYTES) ML_RX_STAT(q_wg_bytes); else ML_RX_STAT(q_wg_heap);
        static uint32_t wg_rx_refused = 0;
        if ((++wg_rx_refused & 0x1F) == 1)
            ESP_LOGW(TAG, "WG-RX(direct) queue budget: refused %lu (%s)", (unsigned long)wg_rx_refused, admit == ML_WGRX_BYTES ? "bytes" : "heap");
        tdongle_memory_drop(TDONGLE_DROP_NET_WG_FULL);
        return false;
    }
    QueueHandle_t queue = type == PKT_STUN ? ml->stun_rx_queue : ml->disco_rx_queue;
    if (ml_hb_rx_ok(free_internal, len, !queue || uxQueueMessagesWaiting(queue) == 0)) return true;
    ml_hb_refuse(ML_HB_RX_CTRL);
    tdongle_memory_drop(type == PKT_STUN ? TDONGLE_DROP_NET_STUN_FULL : TDONGLE_DROP_NET_DISCO_FULL);
    return false;
}

/* Takes ownership of `data`, which net_io_admit has admitted (a WireGuard datagram holds its ml_wgrx reservation).
 * Returns true when a queue the wg_mgr task reads gained a packet (the caller wakes it, once per drain). */
static bool route_udp_packet(microlink_t *ml, pkt_type_t type, uint8_t *data, size_t len,
                              uint32_t src_ip, uint16_t src_port) {
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
            ML_RX_STAT(q_stun_full);
            tdongle_memory_drop(TDONGLE_DROP_NET_STUN_FULL);
            tdongle_heap_free(TDONGLE_OWNER_PACKET, data);  /* Queue full, drop */
        }
        break;
    case PKT_DISCO:
        if (xQueueSend(ml->disco_rx_queue, &pkt, 0) != pdTRUE) {
            ML_RX_STAT(q_disco_full);
            tdongle_memory_drop(TDONGLE_DROP_NET_DISCO_FULL);
            tdongle_heap_free(TDONGLE_OWNER_PACKET, data);
        } else wake_wg = true;
        break;
    case PKT_WIREGUARD:
        if (xQueueSend(ml->wg_rx_queue, &pkt, 0) != pdTRUE) {
            ml_wgrx_release(len);
            ML_RX_STAT(q_wg_full);
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
    return wake_wg;
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

/* One socket being drained: its family decides the sockaddr, the sink says where a datagram goes. */
typedef struct {
    microlink_t *ml;
    int fd;
    bool v6;
    bool stun;      /* STUN socket: straight to the STUN queue; otherwise classify (DISCO socket, which also carries WireGuard) */
    bool wake;      /* a queue the wg_mgr task reads gained a packet */
} sock_drain_t;

static int sock_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t *src_ip, uint16_t *src_port) {
    sock_drain_t *s = ctx;
    int n;
    if (s->v6) {
        struct sockaddr_in6 a6;
        socklen_t len = sizeof(a6);
        n = ml_recvfrom(s->fd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&a6, &len);
        *src_ip = 0;   /* IPv6: the parser reads the address from the payload (parse_response_ipv6) */
        *src_port = ntohs(a6.sin6_port);
    } else {
        struct sockaddr_in a4;
        socklen_t len = sizeof(a4);
        n = ml_recvfrom(s->fd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&a4, &len);
        *src_ip = ntohl(a4.sin_addr.s_addr);
        *src_port = ntohs(a4.sin_port);
    }
    if (n >= 0) return n;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? ML_DRAIN_EMPTY : ML_DRAIN_ERROR;
}

static void sock_sink(void *ctx, const uint8_t *data, int n, uint32_t src_ip, uint16_t src_port) {
    sock_drain_t *s = ctx;
    const pkt_type_t type = s->stun ? PKT_STUN : classify_packet(data, (size_t)n);
    if (type == PKT_UNKNOWN) {
        ML_RX_STAT(udp_unclassified);   /* too short to be anything: discarded without a copy */
        return;
    }
    if (type == PKT_STUN) ML_RX_STAT(udp_stun);
    else if (type == PKT_DISCO) ML_RX_STAT(udp_disco);
    else ML_RX_STAT(udp_wg);
    if (!net_io_admit(s->ml, type, (size_t)n)) return;   /* refused before any heap was taken (a refusal is a counted drop) */
    uint8_t *pkt_data = tdongle_heap_tag(TDONGLE_OWNER_PACKET, malloc(n));
    if (!pkt_data) {
        ML_RX_STAT(udp_alloc_fail);
        if (type == PKT_WIREGUARD) ml_wgrx_release((size_t)n);
        return;
    }
    memcpy(pkt_data, data, n);
    if (route_udp_packet(s->ml, type, pkt_data, n, src_ip, src_port)) s->wake = true;
}

static void drain_one(microlink_t *ml, int fd, bool v6, bool stun, uint8_t *scratch) {
    sock_drain_t s = { .ml = ml, .fd = fd, .v6 = v6, .stun = stun, .wake = false };
    ml_net_io_drain(sock_recv, sock_sink, &s, scratch, ML_NET_IO_SCRATCH_BYTES, ML_NET_IO_DRAIN_CAP);
    if (s.wake) ml_rt_wake(ML_RT_TASK_WG_MGR);   /* event driven: packets arrived, the manager runs now (once per drain, not per packet) */
}

static void drain_ready(void *ctx, void *arg) {
    microlink_t *ml = ctx;
    drain_t *d = arg;

    /* DISCO/WireGuard UDP socket, then the STUN sockets (IPv4, IPv6) */
    if (ml->disco_sock4 >= 0 && FD_ISSET(ml->disco_sock4, d->ready)) drain_one(ml, ml->disco_sock4, false, false, d->scratch);
    if (ml->stun_sock >= 0 && FD_ISSET(ml->stun_sock, d->ready)) drain_one(ml, ml->stun_sock, false, true, d->scratch);
    if (ml->stun_sock6 >= 0 && FD_ISSET(ml->stun_sock6, d->ready)) drain_one(ml, ml->stun_sock6, true, true, d->scratch);
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

    /* Packets are waiting: run at full speed while they are read and classified, not while select sleeps. */
    ml_rt_burst_begin(ML_RT_TASK_NET_IO);
    drain_t d = { .ready = &read_fds, .scratch = scratch };
    ml_mux_foreach(mux, drain_ready, &d);
    ml_rt_burst_end(ML_RT_TASK_NET_IO);
}
