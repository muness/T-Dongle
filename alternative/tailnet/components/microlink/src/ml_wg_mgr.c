/**
 * @file ml_wg_mgr.c
 * @brief WireGuard Manager (shared task) - Peer Management + DISCO
 *
 * One task serves every membership (ml_runtime.h). It owns ALL peers' state of ALL memberships exclusively, which is
 * also what makes the global WireGuard peer-slot pool safe without a lock of its own: a membership that needs a slot
 * when none is free evicts a victim of ANY membership from inside this same task (peer_pool_reserve). Handles:
 * - Peer add/remove/update from coord task (via peer_update_queue)
 * - DISCO ping/pong with rate limiting (matching tailscaled timing)
 * - WireGuard peer provisioning via wireguard-lwip
 * - Direct path discovery and endpoint switching
 *
 * Reference: tailscale/wgengine/magicsock/magicsock.go
 *            tailscale/disco/disco.go
 */

#include "microlink_internal.h"
#include "ml_config_httpd.h"
#include "ml_peer_policy.h"
#include "ml_admission.h"
#include "esp_heap_caps.h"
#include "ml_runtime.h"
#include "tdongle_wgperf.h"
#include "ml_rx_stats.h"
#include "ml_wg_idle.h"
#include "ml_wg_rx_batch.h"
#include "ml_wg_rx_budget.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"
#include "lwip/tcpip.h"
#include "nacl_box.h"
#ifdef ESP_PLATFORM
extern void gateway_route_mark(unsigned stage,uint32_t member);
#define ROUTE_MARK(stage) gateway_route_mark(stage,ml->config.diagnostic_id)
#else
#define ROUTE_MARK(stage) ((void)0)
#endif

#include "wireguardif.h"
#include "wireguard.h"
#include "wireguard_stats.h"
#include "chacha20poly1305.h"
#include "mbedtls/base64.h"
#include <string.h>
#include <errno.h>

/* Forward declaration for zero-copy path */
extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb,
                                    struct pbuf *p, const ip_addr_t *addr, u16_t port);

static const char *TAG = "ml_wg_mgr";

/* Forward declarations */
static void disco_send_call_me_maybe(microlink_t *ml, int peer_idx);
static void disco_send_ping_to_peer(microlink_t *ml, int peer_idx, bool force);

/* lwIP requires netif state changes to happen in tcpip_thread context.
 * ESP-IDF v5.5+ asserts this strictly (LWIP_ASSERT_CORE_LOCKED). With
 * CONFIG_LWIP_TCPIP_CORE_LOCKING=n we cannot LOCK_TCPIP_CORE() the
 * wg_mgr task, so route the bring-up calls through tcpip_callback_with_block. */
static void wg_netif_bring_up_cb(void *ctx)
{
    struct netif *netif = (struct netif *)ctx;
    netif_set_up(netif);
    netif_set_link_up(netif);
}

/* Same TCPIP-context rule applies to udp_new() and any UDP-PCB field writes.
 * Allocate the WG output PCB (and stamp its local_port + tos) on the lwIP
 * thread so the asserts in udp.c don't fire on ESP-IDF v5.5+. */
static void wg_udp_pcb_create_cb(void *ctx)
{
    microlink_t *ml = ctx;
    struct udp_pcb *pcb = udp_new();
    if (pcb) {
        /* Source port matches the DISCO socket; tos=0xB8 = DSCP 46 (EF) */
        pcb->local_port = ml->disco_local_port;
        pcb->tos = 0xB8;
    }
    ml->wg_output_pcb = pcb;
}

/* DISCO message types */
#define DISCO_MSG_PING          0x01
#define DISCO_MSG_PONG          0x02
#define DISCO_MSG_CALL_ME_MAYBE 0x03

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

#define DISCO_TXID_LEN 12
#define DISCO_NONCE_LEN 24

/* Check if an IP (host byte order) is a LAN address */
static inline bool is_lan_ip(uint32_t ip) {
    return ((ip >> 24) == 10) ||                       /* 10.x.x.x */
           ((ip >> 16) == 0xC0A8) ||                   /* 192.168.x.x */
           (((ip >> 16) & 0xFFF0) == 0xAC10);          /* 172.16-31.x.x */
}

#define MAX_PENDING_PROBES 32
/* ============================================================================
 * Base64 Key Encoding (wireguard-lwip API requires base64 keys)
 * ========================================================================== */

static void key_to_base64(const uint8_t *key, char *b64, size_t b64_size) {
    size_t olen = 0;
    mbedtls_base64_encode((unsigned char *)b64, b64_size, &olen, key, 32);
    b64[olen] = '\0';
}

/* ============================================================================
 * UDP Send Helper — routes via BSD socket or zero-copy PCB
 *
 * All direct DISCO/WG UDP sends go through this function.
 * dest_ip is HOST byte order, dest_port is HOST byte order.
 * ========================================================================== */

static inline bool disco_has_udp_path(const microlink_t *ml) {
#ifdef CONFIG_ML_ZERO_COPY_WG
    if (ml->zc.pcb) return true;
#endif
    return (ml->disco_sock4 >= 0);
}

static int disco_udp_sendto(microlink_t *ml, const uint8_t *data, size_t len,
                             uint32_t dest_ip_hbo, uint16_t dest_port) {
#ifdef CONFIG_ML_ZERO_COPY_WG
    if (ml->zc.pcb) {
        return (ml_zerocopy_send(ml, data, len, dest_ip_hbo, dest_port) == ESP_OK) ? len : -1;
    }
#endif
    if (ml->disco_sock4 < 0) return -1;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    dest.sin_addr.s_addr = htonl(dest_ip_hbo);

    return ml_sendto(ml->disco_sock4, data, len, MSG_DONTWAIT,
                  (struct sockaddr *)&dest, sizeof(dest));
}

/* ============================================================================
 * WireGuard Output Callbacks (for magicsock mode)
 * ========================================================================== */

/* Called by wireguard-lwip when a peer has no direct endpoint (DERP relay) */
static err_t wg_derp_output_cb(const uint8_t *peer_public_key,
                                const uint8_t *data, size_t len, void *ctx) {
    microlink_t *ml = (microlink_t *)ctx;
    if (!ml || !ml->derp.connected) {
        ESP_LOGW(TAG, "DERP output cb: not connected, dropping %d bytes", (int)len);
        return ERR_CONN;
    }

    /* Log WG handshake initiations with key and one-time hex dump */
    if (len >= 4 && data[0] == 0x01) {
        static int init_dump_count = 0;
        const char *hostname = "?";
        for (int i = 0; i < ml->peer_count; i++) {
            if (memcmp(ml->peers[i].public_key, peer_public_key, 32) == 0) {
                hostname = ml->peers[i].hostname;
                break;
            }
        }
        /* Back to ESP_LOGI (compiled out by CONFIG_LOG_MAXIMUM_LEVEL=2) now that
         * the DERP send path is proven working — this fires per handshake init
         * (incl. offline DERP peers retrying ~every 5s) and was steady SD noise.
         * To re-trace the egress, set WG_HS_TRACE=1 in wireguardif.c: its
         * [WG_OUT_OK path=DERP derp_fn=1] line is the equivalent signal. */
        ESP_LOGI(TAG, "WG INIT -> %s len=%d key=%02x%02x%02x%02x%02x%02x%02x%02x",
                 hostname, (int)len,
                 peer_public_key[0], peer_public_key[1],
                 peer_public_key[2], peer_public_key[3],
                 peer_public_key[4], peer_public_key[5],
                 peer_public_key[6], peer_public_key[7]);

        /* Dump first handshake fully for byte-level verification */
        if (init_dump_count < 1 && len == 148) {
            init_dump_count++;
            /* WG handshake init: type(1) reserved(3) sender(4) ephemeral(32)
             * enc_static(48) enc_timestamp(28) mac1(16) mac2(16) = 148 */
            ESP_LOGI(TAG, "  type=%02x res=%02x%02x%02x sender=%02x%02x%02x%02x",
                     data[0], data[1], data[2], data[3],
                     data[4], data[5], data[6], data[7]);
            ESP_LOGI(TAG, "  ephemeral=%02x%02x%02x%02x...%02x%02x%02x%02x",
                     data[8], data[9], data[10], data[11],
                     data[36], data[37], data[38], data[39]);
            ESP_LOGI(TAG, "  mac1=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     data[116], data[117], data[118], data[119],
                     data[120], data[121], data[122], data[123],
                     data[124], data[125], data[126], data[127],
                     data[128], data[129], data[130], data[131]);
            ESP_LOGI(TAG, "  mac2=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     data[132], data[133], data[134], data[135],
                     data[136], data[137], data[138], data[139],
                     data[140], data[141], data[142], data[143],
                     data[144], data[145], data[146], data[147]);
        }
    }

    esp_err_t err = ml_derp_queue_send(ml, peer_public_key, data, len);
    return (err == ESP_OK) ? ERR_OK : ERR_MEM;
}

/* Called by wireguard-lwip when sending via external UDP socket (magicsock).
 * Uses raw lwIP udp_sendto() instead of BSD sendto() to avoid deadlock
 * when called from the TCPIP thread context (via tcpip_input → ip_input →
 * icmp/tcp reply → wireguardif_output → this callback). BSD sendto() posts
 * a message to the TCPIP thread and waits, which deadlocks if we're already
 * on that thread. */


/* Pin the magicsock WG output PCB to a specific upstream netif via
 * udp_bind_netif. Called from main code to support Phase 1.5e exit-node
 * mode where netif_default is flipped to the WG netif. */
static void pin_wg_output_cb(void *ctx)
{
    microlink_t *ml = ctx;
    udp_bind_netif(ml->wg_output_pcb, ml->upstream_netif);
}

esp_err_t microlink_pin_wg_output_netif(microlink_t *ml, struct netif *upstream)
{
    /* Remember the upstream (STA) netif so the coord + DERP tasks can pin
     * their own self-origin sockets to it on (re)connect — see
     * ml_bind_sock_to_upstream(). upstream == NULL (exit-node off) clears it. */
    if (ml) ml->upstream_netif = (void *)upstream;
    if (!ml->wg_output_pcb) return ESP_ERR_INVALID_STATE;
    tcpip_callback_with_block(pin_wg_output_cb, ml, 1);
    return ESP_OK;
}

/* SPIRAM-backed custom pbuf used by wg_udp_output_cb. The wrapper struct
 * itself stays on INTERNAL heap (tiny — ~32 B) because lwIP and the WiFi
 * driver may touch pbuf metadata from contexts where SPIRAM access is
 * unsafe (cache-disable windows during SPI flash writes). Only the bulk
 * data payload lives in SPIRAM — that buffer is only read by the WiFi
 * driver's TX path, which already handles SPIRAM→internal-DMA copy
 * transparently. */
typedef struct {
    struct pbuf_custom pc;
    void *data_spiram;
} ml_spiram_pbuf_t;

static void ml_spiram_pbuf_free_fn(struct pbuf *p) {
    /* pbuf_custom.pbuf == p; ml_spiram_pbuf_t starts at pc which is the
     * same address. Free the SPIRAM payload first, then the wrapper. */
    ml_spiram_pbuf_t *wrap = (ml_spiram_pbuf_t *)p;
    tdongle_heap_forget(TDONGLE_OWNER_PACKET, wrap->data_spiram);
    heap_caps_free(wrap->data_spiram);
    tdongle_heap_forget(TDONGLE_OWNER_PACKET, wrap);
    heap_caps_free(wrap);
}

/* The WireGuard device (peers, keypairs) is allocated inside wireguardif_init. */
static void wireguard_device_release(struct netif *netif) {
    tdongle_heap_forget(TDONGLE_OWNER_WG, netif->state);
    wireguardif_free(netif);
}

/* "WG UDP TX": one line per handshake/cookie packet, none per transport-data packet (type 4). */
static void wg_log_udp_tx(uint32_t dest_ip, uint16_t dest_port, const uint8_t *data, size_t len) {
    if (len >= 1 && data[0] == 0x04) return;
    uint32_t ip_host = ntohl(dest_ip);
    ESP_LOGI(TAG, "WG UDP TX: %d bytes -> %d.%d.%d.%d:%d type=%d",
             (int)len,
             (int)((ip_host >> 24) & 0xFF), (int)((ip_host >> 16) & 0xFF),
             (int)((ip_host >> 8) & 0xFF), (int)(ip_host & 0xFF),
             (int)dest_port,
             len >= 1 ? data[0] : -1);
}

/* tailscale "send both" (wgengine/magicsock/endpoint.go send), see the long note below: a handshake packet that went to
 * the direct endpoint is also relayed via DERP. Shared by the copying and the pbuf send. */
static void wg_send_both(microlink_t *ml, uint32_t dest_ip, const uint8_t *data, size_t len) {
    /* tailscale "send both" (wgengine/magicsock/endpoint.go send): a WireGuard
     * HANDSHAKE packet (type 0x01 init / 0x02 response / 0x03 cookie) is ALSO
     * relayed via DERP, not only sent to the direct endpoint. DERP is the
     * reliable bootstrap path that always works (both peers hold a home-DERP
     * connection); direct is an opportunistic upgrade. Without this, a peer
     * behind an aggressive symmetric NAT (per-packet source-port remap) never
     * completes the handshake: the direct copy goes to a port the peer no longer
     * uses and is silently dropped, and microlink's exclusive direct-OR-DERP
     * flip never reliably lands the init on DERP. Bulk data (type 0x04) is NOT
     * duplicated here -- the existing direct path + 30s DERP-fallback carry it
     * once the session is up. Peer found by dest address (host-order endpoints
     * vs network-order dest_ip). */
    if (len >= 1 && (data[0] == 0x01 || data[0] == 0x02 || data[0] == 0x03)) {
        for (int pi = 0; pi < ml->peer_count; pi++) {
            ml_peer_t *pr = &ml->peers[pi];
            bool match = (pr->best_ip && htonl(pr->best_ip) == dest_ip);
            if (!match) {
                for (int e = 0; e < pr->endpoint_count && e < ML_MAX_ENDPOINTS; e++) {
                    if (!pr->endpoints[e].is_ipv6 && pr->endpoints[e].ip &&
                        htonl(pr->endpoints[e].ip) == dest_ip) { match = true; break; }
                }
            }
            if (match) {
                ml_derp_queue_send(ml, pr->public_key, data, len);
                ESP_LOGI(TAG, "WG send-both: handshake type=%d also relayed via DERP to %s",
                         (int)data[0], pr->hostname);
                break;
            }
        }
    }
}

static err_t wg_udp_output_cb(uint32_t dest_ip, uint16_t dest_port,
                                const uint8_t *data, size_t len, void *ctx) {
    microlink_t *ml = (microlink_t *)ctx;
    if (!ml) return ERR_CONN;

    /* Only control packets (handshake, cookie) are logged: a transport-data line per packet was ~140 formatted
     * ESP_LOGI calls a second on the forwarding path (docs/adr/0018-wg-mgr-packet-path.md). */
    wg_log_udp_tx(dest_ip, dest_port, data, len);

    /* Use raw PCB to send — safe from any thread context */
    if (!ml->wg_output_pcb) return ERR_CONN;
    /* The copying send is for a pbuf chain, which this firmware never builds (wg_udp_output_pbuf_cb sends the one-piece pbuf as it is), but it
     * is a heap allocation on the data path: transport data is refused below the elastic floor like the rest (ADR 0022). */
    if (len >= 4 && data[0] == 0x04 &&
        !ml_hb_ok(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), len + (size_t)LWIP_MEM_ALIGN_SIZE((u16_t)PBUF_TRANSPORT) + sizeof(ml_spiram_pbuf_t) + 32u)) {
        ml_hb_refuse(ML_HB_WG_COPY);
        return ERR_MEM;
    }

    /* Throughput-stability fix (2026-05-24, re-applied after the WiFi
     * channel-mismatch fix uncovered this as the residual stutter
     * source): the original `pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM)`
     * goes to lwIP's internal-DRAM pool. Under sustained ~140 pps to a
     * single peer that pool fragments, and 1312-byte mem_malloc starts
     * failing (-1 ERR_MEM) at ~5/sec, producing visible speedtest
     * stuttering. Move the per-packet payload to SPIRAM via the
     * standard pbuf_alloced_custom() pattern — we have 8 MB of SPIRAM
     * idle and the ~10 us extra latency is invisible next to the WG
     * crypto cost. Wrapper struct stays on INTERNAL heap (tiny, ~16 B)
     * because lwIP/WiFi may touch pbuf metadata from contexts where
     * SPIRAM access is unsafe (cache-disable windows). */
    /* PBUF_TRANSPORT headroom so lwIP can prepend UDP+IP+Ether headers
     * in-place into the SPIRAM buffer instead of allocating a new
     * internal-DRAM pbuf for them per packet. lwIP positions the payload
     * at `payload_mem + LWIP_MEM_ALIGN_SIZE(layer_offset)`, so the
     * memcpy offset MUST match that exact computation (the earlier
     * attempt used the raw layer value and shipped corrupted data
     * because the aligned offset was 2 B off — fixed here by using the
     * same LWIP_MEM_ALIGN_SIZE macro for both sides). */
    const u16_t hdr_offset = (u16_t)LWIP_MEM_ALIGN_SIZE((u16_t)PBUF_TRANSPORT);
    const u16_t total_len = (u16_t)(hdr_offset + len);
    ml_spiram_pbuf_t *wrap = heap_caps_malloc(sizeof(*wrap),
                                                MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!tdongle_heap_tag(TDONGLE_OWNER_PACKET, wrap)) return ERR_MEM;
    wrap->data_spiram = tdongle_heap_tag(TDONGLE_OWNER_PACKET, malloc(total_len));
    if (!wrap->data_spiram) {
        tdongle_heap_forget(TDONGLE_OWNER_PACKET, wrap);
        heap_caps_free(wrap);
        return ERR_MEM;
    }
    memcpy((uint8_t *)wrap->data_spiram + hdr_offset, data, len);
    wrap->pc.custom_free_function = ml_spiram_pbuf_free_fn;
    struct pbuf *p = pbuf_alloced_custom(PBUF_TRANSPORT, (u16_t)len, PBUF_REF,
                                          &wrap->pc, wrap->data_spiram, total_len);
    if (!p) {
        tdongle_heap_forget(TDONGLE_OWNER_PACKET, wrap->data_spiram);
        heap_caps_free(wrap->data_spiram);
        tdongle_heap_forget(TDONGLE_OWNER_PACKET, wrap);
        heap_caps_free(wrap);
        return ERR_MEM;
    }

    ip_addr_t dst;
    IP_SET_TYPE_VAL(dst, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&dst), dest_ip);  /* already network byte order */

    err_t err = udp_sendto(ml->wg_output_pcb, p, &dst, dest_port);
    pbuf_free(p);
    wg_send_both(ml, dest_ip, data, len);
    return err;
}

/* The same send without the copies: the datagram is already a contiguous PBUF_TRANSPORT pbuf (wireguardif builds it in
 * place), so it goes to the UDP pcb as it is. lwIP adds its UDP, IP and link headers in the headroom (and leaves them
 * there: the pbuf's payload, len and tot_len are not the datagram any more once udp_sendto has run, so nothing here reads
 * them afterwards) and the caller's reference is untouched (udp_sendto does not consume the pbuf). */
static err_t wg_udp_output_pbuf_cb(uint32_t dest_ip, uint16_t dest_port, struct pbuf *p, void *ctx) {
    microlink_t *ml = (microlink_t *)ctx;
    if (!ml || !ml->wg_output_pcb) return ERR_CONN;
    const uint8_t *data = (const uint8_t *)p->payload;
    const size_t len = p->tot_len;   /* before the send: lwIP prepends its headers to this pbuf in place and does not take them off */
    wg_log_udp_tx(dest_ip, dest_port, data, len);
    ip_addr_t dst;
    IP_SET_TYPE_VAL(dst, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&dst), dest_ip);  /* already network byte order */
    err_t err = udp_sendto(ml->wg_output_pcb, p, &dst, dest_port);
    wg_send_both(ml, dest_ip, data, len);
    return err;
}

/* ============================================================================
 * WireGuard Interface Initialization
 * ========================================================================== */

#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
/* wireguardif's per-stage cycles (lookup, seal, udp) into the wgperf report. */
static void wg_stage_sink(unsigned stage, uint32_t cycles) {
    switch (stage) {
    case WGIF_STAGE_LOOKUP: WGPERF_ADD(out_lookup, cycles); break;
    case WGIF_STAGE_SEAL: WGPERF_ADD(out_seal, cycles); break;
    case WGIF_STAGE_UDP: WGPERF_ADD(out_udp, cycles); break;
    default: break;
    }
}
#define WG_PERF_INSTALL() (wireguardif_stage_sink = wg_stage_sink)
#else
#define WG_PERF_INSTALL() ((void)0)
#endif

/* Peer slots of the global pool: ledger-tagged to the `wg` owner (see peer_pool_reserve). */
static struct { uint32_t refused_largest; uint32_t refused_heap; uint32_t largest_low; unsigned live; } slot_guard = { .largest_low = UINT32_MAX };
static void *wg_pool_alloc(size_t bytes) {
    /* Slots beyond the guaranteed ML_ADM_PEER_SLOTS are elastic heap: they keep the recovery reserve and one negotiation peak free
     * (ml_adm_slot_heap_ok). A refusal is a rejected activation, like the largest-block one below. Under the core lock (add_peer). */
    if (!ml_adm_slot_heap_ok(slot_guard.live, heap_caps_get_free_size(MALLOC_CAP_INTERNAL), bytes)) {
        slot_guard.refused_heap++;
        ESP_LOGW(TAG, "WG peer slot refused: %u resident, free heap %u B would leave less than the reserve", slot_guard.live,
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        return NULL;
    }
    /* On demand, because a static pool would pin 12 slots for ever (ml_admission.h, ml_adm_slot_alloc_ok), but never the
     * allocation that takes the largest free block under what the DERP TLS record buffer needs. Called under the core
     * lock from add_peer, a handful of times per hour: two heap walks are affordable there. */
    size_t before = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    void *block = calloc(1, bytes);
    if (!block) return NULL;
    size_t after = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (after < slot_guard.largest_low) slot_guard.largest_low = (uint32_t)after;
    if (!ml_adm_slot_alloc_ok(before, after, ML_ADM_TLS_BLOCK_FLOOR)) {
        slot_guard.refused_largest++;
        ESP_LOGW(TAG, "WG peer slot refused: it would take the largest free block from %u to %u B (TLS needs %u)",
                 (unsigned)before, (unsigned)after, (unsigned)ML_ADM_TLS_BLOCK_FLOOR);
        free(block);
        return NULL;
    }
    slot_guard.live++;
    return tdongle_heap_tag(TDONGLE_OWNER_WG, block);
}
static void wg_pool_free(void *block) { if (slot_guard.live) slot_guard.live--; tdongle_heap_free(TDONGLE_OWNER_WG, block); }

/* Every hold of the lwIP core lock by this task is timed into the diagnostics ledger by call site (tdongle_lock_hold,
 * diagnostics builds only; `memory locks`). The budget the shared task works to is ~1 ms per hold: the cryptography runs
 * outside the lock (initiation: wireguard_initiation_*, receive: wireguard_rx_*) and periodic work is taken one peer at
 * a time. */
#define WG_LOCKED(site, body) do { WGPERF_T(wgperf_lk_); LOCK_TCPIP_CORE(); WGPERF_LAP(wgperf_lk_, lock_wait); \
    int64_t hold_start_ = tdongle_lock_clock(); body; \
    tdongle_lock_hold((site), (uint32_t)(tdongle_lock_clock() - hold_start_)); WGPERF_LAP(wgperf_lk_, lock_hold); UNLOCK_TCPIP_CORE(); } while (0)
#define GATEWAY_WG_SITE(site, expr) ({ err_t result_; WG_LOCKED(site, result_ = (expr)); result_; })
#define GATEWAY_WG_CALL(expr) GATEWAY_WG_SITE(TDONGLE_LOCK_WG_OTHER, expr)
static esp_err_t wg_init_interface_impl(microlink_t *ml) {
    /* Peer slots come from the one global pool, through ledger-tagged allocation. Reconfiguring is refused (and
     * harmless) once any slot is live, so every device after the first leaves it as it is. */
    wireguardif_pool_configure(WIREGUARD_POOL_SLOTS, wg_pool_alloc, wg_pool_free);
    /* Convert our WG private key to base64 */
    char privkey_b64[64];
    key_to_base64(ml->wg_private_key, privkey_b64, sizeof(privkey_b64));

    /* Allocate lwIP netif */
    struct netif *netif = (struct netif *)tdongle_heap_tag(TDONGLE_OWNER_WG, calloc(1, sizeof(struct netif)));
    if (!netif) {
        ESP_LOGE(TAG, "Failed to allocate WG netif");
        return ESP_FAIL;
    }

    /* Prepare init data */
    struct wireguardif_init_data wg_init = {0};
    wg_init.private_key = privkey_b64;
    wg_init.listen_port = 51820;
    wg_init.bind_netif = NULL;

    /* Disable internal socket binding (we use magicsock mode) */
    wireguardif_disable_socket_bind();

    /* Initialize WireGuard netif */
    netif->state = &wg_init;
    err_t err = wireguardif_init(netif);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "wireguardif_init failed: %d", err);
        tdongle_heap_free(TDONGLE_OWNER_WG, netif);
        return ESP_FAIL;
    }
    tdongle_heap_adopt(TDONGLE_OWNER_WG, netif->state);

    /* Set IP addresses: our VPN IP (or temporary until we get one) */
    if (ml->vpn_ip != 0) {
        uint8_t a = (ml->vpn_ip >> 24) & 0xFF;
        uint8_t b = (ml->vpn_ip >> 16) & 0xFF;
        uint8_t c = (ml->vpn_ip >> 8) & 0xFF;
        uint8_t d = ml->vpn_ip & 0xFF;
        IP4_ADDR(&netif->ip_addr.u_addr.ip4, a, b, c, d);
    } else {
        IP4_ADDR(&netif->ip_addr.u_addr.ip4, 100, 64, 0, 1);  /* temp */
    }
    IP4_ADDR(&netif->netmask.u_addr.ip4, 255, 192, 0, 0);     /* /10 */
    IP4_ADDR(&netif->gw.u_addr.ip4, 0, 0, 0, 0);

    /* Use tcpip_input so decrypted packets are posted to the TCPIP thread.
     * Required for TCP (esp_http_server sockets) — ip_input from the wg_mgr
     * thread accesses TCP PCB state without synchronization.  The WG output
     * callback uses raw udp_sendto (not BSD sendto) to avoid deadlock. */
    extern err_t gateway_tunnel_input(struct pbuf *, struct netif *);
    extern void gateway_tunnel_input_batch(struct pbuf **, unsigned, struct netif *, err_t *);
    netif->input = gateway_tunnel_input;
    wireguardif_set_rx_batch(netif, gateway_tunnel_input_batch);   /* the run hands its packets over together, with the core lock released (ADR 0020) */

    /* Add to lwIP netif list (bypass netif_add which wants init callback) */
    netif->next = netif_list;
    netif_list = netif;

    /* Bring interface up via tcpip_thread (see wg_netif_bring_up_cb above) */
    wg_netif_bring_up_cb(netif);

    /* Create raw UDP PCB for WG output (avoids BSD sendto deadlock on TCPIP
     * thread).  Bind to port 51820 to match the DISCO socket source port.
     * The existing BSD disco_sock4 is only used from the wg_mgr task for
     * DISCO/STUN; this raw PCB is used from the TCPIP thread for WG output. */
    if (!ml->wg_output_pcb) {
        /* Allocate + configure on tcpip_thread (see wg_udp_pcb_create_cb above).
         * Avoiding udp_bind keeps WG responses on the DISCO BSD socket;
         * udp_sendto only needs local_port set on the PCB. */
        wg_udp_pcb_create_cb(ml);
        if(!ml->wg_output_pcb) {
            wireguardif_shutdown(netif);netif_set_link_down(netif);netif_set_down(netif);
            netif_remove(netif);wireguard_device_release(netif);tdongle_heap_free(TDONGLE_OWNER_WG, netif);return ESP_ERR_NO_MEM;
        }
    }

    /* Register output callbacks for magicsock mode */
    wireguardif_set_derp_output(netif, wg_derp_output_cb, ml);
    wireguardif_set_udp_output(netif, wg_udp_output_cb, ml);
    wireguardif_set_udp_output_pbuf(netif, wg_udp_output_pbuf_cb);
    WG_PERF_INSTALL();

    /* On cellular AT socket bridge, force all WG output through DERP relay.
     * AT sockets are TCP-only, so direct UDP is impossible.
     * PPP mode has real lwIP sockets with UDP, so allow direct connections. */
#if CONFIG_ML_ENABLE_CELLULAR
    {
        bool at_ready = ml_at_socket_is_ready();
        ESP_LOGI(TAG, "Cellular mode: at_socket_ready=%d, force_derp=%d", at_ready, at_ready);
        if (at_ready) {
            wireguardif_force_derp_output(netif, true);
            ESP_LOGI(TAG, "Cellular AT socket: forcing DERP output (direct UDP disabled)");
        } else {
            ESP_LOGI(TAG, "Cellular PPP mode: direct UDP ENABLED");
        }
    }
#endif

    ml->wg_netif = netif;

    /* Verify WG device public key matches our expected key */
    {
        struct wireguard_device *dev = (struct wireguard_device *)netif->state;
        if (dev) {
            bool match = (memcmp(dev->public_key, ml->wg_public_key, 32) == 0);
            ESP_LOGI(TAG, "WG device pubkey: %02x%02x%02x%02x... %s ml->wg_public_key",
                     dev->public_key[0], dev->public_key[1],
                     dev->public_key[2], dev->public_key[3],
                     match ? "MATCHES" : "MISMATCH!");
            if (!match) {
                ESP_LOGE(TAG, "  Expected: %02x%02x%02x%02x...",
                         ml->wg_public_key[0], ml->wg_public_key[1],
                         ml->wg_public_key[2], ml->wg_public_key[3]);
            }
        }
    }

    ESP_LOGI(TAG, "WireGuard interface initialized (magicsock mode)");
    return ESP_OK;
}

static void wg_update_vpn_ip(microlink_t *ml) {
    if (ml->wg_netif && ml->vpn_ip != 0) {
        struct netif *netif = (struct netif *)ml->wg_netif;
        uint8_t a = (ml->vpn_ip >> 24) & 0xFF;
        uint8_t b = (ml->vpn_ip >> 16) & 0xFF;
        uint8_t c = (ml->vpn_ip >> 8) & 0xFF;
        uint8_t d = ml->vpn_ip & 0xFF;
        IP4_ADDR(&netif->ip_addr.u_addr.ip4, a, b, c, d);
    }
}

/* ============================================================================
 * Peer Management (owned exclusively by this task)
 * ========================================================================== */

static int find_peer_by_key(microlink_t *ml, const uint8_t *pubkey) {
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && memcmp(ml->peers[i].public_key, pubkey, 32) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_peer_by_ip(microlink_t *ml, uint32_t vpn_ip) {
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && ml->peers[i].vpn_ip == vpn_ip) {
            WGPERF_COUNT(lookup_scans, (uint32_t)i + 1);
            return i;
        }
    }
    WGPERF_COUNT(lookup_scans, (uint32_t)ml->peer_count);
    return -1;
}

static int find_peer_by_disco_key(microlink_t *ml, const uint8_t *disco_key) {
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && memcmp(ml->peers[i].disco_key, disco_key, 32) == 0) {
            return i;
        }
    }
    return -1;
}

/* Shared DISCO secret with peer p, derived on first use and again after the
 * peer's disco key changed (see ml_peer_t.disco_shared). NULL on failure. */
static const uint8_t *disco_shared_key(microlink_t *ml, ml_peer_t *p) {
    if (!p->disco_shared_valid || memcmp(p->disco_shared_for, p->disco_key, 32) != 0) {
        if (nacl_box_beforenm(p->disco_shared, p->disco_key, ml->disco_private_key) != 0) {
            p->disco_shared_valid = false;
            return NULL;
        }
        memcpy(p->disco_shared_for, p->disco_key, 32);
        p->disco_shared_valid = true;
    }
    return p->disco_shared;
}

/* Does the box in a DISCO packet open with the key a directory record says the
 * sender holds? Proves the sender owns that disco key without touching the peer
 * table. */
static bool disco_authenticates(microlink_t *ml, const uint8_t *sender_key,
                                const uint8_t *nonce, const uint8_t *ciphertext,
                                size_t length) {
    uint8_t shared[32];
    if (length < NACL_BOX_MACBYTES ||
        nacl_box_beforenm(shared, sender_key, ml->disco_private_key) != 0)
        return false;
    uint8_t *plain = tdongle_heap_tag(TDONGLE_OWNER_OTHER, malloc(length - NACL_BOX_MACBYTES + 1));
    if (!plain)
        return false;
    bool ok = nacl_box_open_afternm(plain, ciphertext, length, nonce, shared) == 0;
    tdongle_heap_free(TDONGLE_OWNER_OTHER, plain);
    memset(shared, 0, sizeof(shared));
    return ok;
}

/* WireGuard has produced a session key for this peer: it proved it holds the
 * private key (initiation timestamp or handshake response). */
static bool wg_peer_authenticated(microlink_t *ml, int idx) {
#ifdef ESP_PLATFORM
    const ml_peer_t *p = &ml->peers[idx];
    struct netif *netif = (struct netif *)ml->wg_netif;
    if (!netif || !netif->state || p->wg_peer_index < 0 ||
        p->wg_peer_index >= WIREGUARD_MAX_PEERS)
        return false;
    const struct wireguard_peer *wp =
        wireguard_device_peer((struct wireguard_device *)netif->state, (uint8_t)p->wg_peer_index);
    return wp && wp->valid && (wp->curr_keypair.valid || wp->next_keypair.valid ||
                               wp->prev_keypair.valid);
#else
    (void)ml; (void)idx;
    return false;
#endif
}

#ifdef ESP_PLATFORM
/* A WireGuard initiation addressed to us: right size, type and mac1 for our
 * public key. mac1 is not authentication (anyone who knows our public key can
 * compute it); it screens out random and truncated input before any lookup. */
static bool wg_initiation_plausible(microlink_t *ml, const ml_rx_packet_t *pkt) {
    struct netif *netif = (struct netif *)ml->wg_netif;
    if (!netif || !netif->state ||
        pkt->len != sizeof(struct message_handshake_initiation) ||
        pkt->data[0] != MESSAGE_HANDSHAKE_INITIATION || pkt->data[1] || pkt->data[2] || pkt->data[3])
        return false;
    const size_t macs = 2 * WIREGUARD_COOKIE_LEN;
    return wireguard_check_mac1((struct wireguard_device *)netif->state, pkt->data,
                                pkt->len - macs, pkt->data + pkt->len - macs);
}
#endif
/* Changes whenever WireGuard accepts an authenticated packet from the peer
 * (data decrypted, or an initiation that passed its timestamp check). */
static uint32_t wg_peer_activity(microlink_t *ml, int idx) {
#ifdef ESP_PLATFORM
    const ml_peer_t *p = &ml->peers[idx];
    struct netif *netif = (struct netif *)ml->wg_netif;
    if (!netif || !netif->state || p->wg_peer_index < 0 ||
        p->wg_peer_index >= WIREGUARD_MAX_PEERS)
        return 0;
    const struct wireguard_peer *wp =
        wireguard_device_peer((struct wireguard_device *)netif->state, (uint8_t)p->wg_peer_index);
    return wp ? wp->last_rx + wp->last_initiation_rx : 0;
#else
    (void)ml; (void)idx;
    return 0;
#endif
}

static int find_peer_by_node_id(microlink_t *ml, uint64_t node_id) {
    if (node_id == 0) return -1;
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && ml->peers[i].node_id == node_id) {
            return i;
        }
    }
    return -1;
}

static int add_peer(microlink_t *ml, const ml_peer_update_t *update) {
    /* Peer allowlist filter: don't waste WG slots on non-allowed peers.
     * Still process updates for existing peers (they may become allowed later). */
    if (!ml_config_peer_is_allowed(ml->config_httpd, update->vpn_ip)) {
        return -1;  /* Silently skip — peer not in allowlist */
    }

    /* Check if peer already exists */
    int idx = find_peer_by_key(ml, update->public_key);
    if (idx >= 0) {
        ESP_LOGI(TAG, "Updating existing peer %s (idx=%d)", update->hostname, idx);
    } else {
        /* Find free slot */
        idx = -1;
        for (int i = 0; i < ML_MAX_PEERS; i++) {
            if (!ml->peers[i].active) {
                idx = i;
                break;
            }
        }

        /* Peer table full — evict LRU non-priority peer if incoming peer is priority */
        if (idx < 0 && ml->config.priority_peer_ip != 0 &&
            update->vpn_ip == ml->config.priority_peer_ip) {
            uint64_t oldest_ms = UINT64_MAX;
            int evict_idx = -1;
            for (int i = 0; i < ML_MAX_PEERS; i++) {
                if (!ml->peers[i].active) continue;
                if (ml->peers[i].vpn_ip == ml->config.priority_peer_ip) continue;
                uint64_t last_activity = ml->peers[i].last_send_ms;
                if (ml->peers[i].last_pong_recv_ms > last_activity)
                    last_activity = ml->peers[i].last_pong_recv_ms;
                if (last_activity < oldest_ms) {
                    oldest_ms = last_activity;
                    evict_idx = i;
                }
            }
            if (evict_idx >= 0) {
                char evict_ip[16];
                microlink_ip_to_str(ml->peers[evict_idx].vpn_ip, evict_ip);
                ESP_LOGW(TAG, "Evicting LRU peer %s (%s) for priority peer %s",
                         ml->peers[evict_idx].hostname, evict_ip, update->hostname);
                if (ml->peers[evict_idx].wg_peer_index >= 0 && ml->wg_netif) {
                    GATEWAY_WG_SITE(TDONGLE_LOCK_WG_PEER, wireguardif_remove_peer((struct netif *)ml->wg_netif,
                                            ml->peers[evict_idx].wg_peer_index));
                }
                ml->peers[evict_idx].active = false;
                idx = evict_idx;
            }
        }

        if (idx < 0) {
            ESP_LOGW(TAG, "Peer table full (%d slots), cannot add %s",
                     ML_MAX_PEERS, update->hostname);
            return -1;
        }
        if (idx >= ml->peer_count) {
            ml->peer_count = idx + 1;
        }
    }

    ml_peer_t *p = &ml->peers[idx];
    p->vpn_ip = update->vpn_ip;
    memcpy(p->public_key, update->public_key, 32);
    memcpy(p->disco_key, update->disco_key, 32);
    strncpy(p->hostname, update->hostname, sizeof(p->hostname) - 1);
    p->hostname[sizeof(p->hostname) - 1] = '\0';
    p->derp_region = update->derp_region;
    p->active = true;
    p->unconfirmed = false;

    /* Copy endpoints */
    p->endpoint_count = update->endpoint_count;
    for (int i = 0; i < update->endpoint_count && i < ML_MAX_ENDPOINTS; i++) {
        p->endpoints[i].ip = update->endpoints[i].ip;
        p->endpoints[i].port = update->endpoints[i].port;
        p->endpoints[i].is_ipv6 = update->endpoints[i].is_ipv6;
    }

    /* Initialize DISCO rate limiting state */
    p->last_ping_sent_ms = 0;
    p->last_pong_recv_ms = 0;
    p->trust_until_ms = 0;
    p->last_send_ms = 0;
    p->last_cmm_rx_ms = 0;
    p->best_last_pong_ms = 0;
    p->disco_shared_valid = false;
    p->last_upgrade_ms = 0;
    p->has_direct_path = false;
    p->best_ip = 0;
    p->best_port = 0;
    p->wg_peer_index = -1;
    p->peer_added_ms = ml_get_time_ms();
    p->derp_fallback_active = false;
    p->is_exit_node = update->is_exit_node;
    p->subnet_route_count = update->subnet_route_count;
    if (p->subnet_route_count > MICROLINK_MAX_PEER_ROUTES) {
        p->subnet_route_count = MICROLINK_MAX_PEER_ROUTES;
    }
    for (int r = 0; r < p->subnet_route_count; r++) {
        p->subnet_routes[r] = update->subnet_routes[r];
    }
    /* Liveness flag from control plane. has_online=false means the field was
     * absent in this MapResponse; default to true rather than offline so a
     * silent control plane doesn't grey out the whole peer list. */
    p->online = update->has_online ? update->online : true;
    if (update->has_node_id) {
        p->node_id = update->node_id;
    }

    char ip_str[16];
    microlink_ip_to_str(update->vpn_ip, ip_str);
    ESP_LOGI(TAG, "Peer added: %s (%s) idx=%d endpoints=%d derp=%d key=%02x%02x%02x%02x%02x%02x%02x%02x",
             p->hostname, ip_str, idx, p->endpoint_count, p->derp_region,
             p->public_key[0], p->public_key[1], p->public_key[2], p->public_key[3],
             p->public_key[4], p->public_key[5], p->public_key[6], p->public_key[7]);

    /* Add to wireguard-lwip */
    if (ml->wg_netif) {
        struct netif *netif = (struct netif *)ml->wg_netif;

        /* Convert peer public key to base64 */
        char peer_b64[64];
        key_to_base64(p->public_key, peer_b64, sizeof(peer_b64));

        struct wireguardif_peer wg_peer;
        wireguardif_peer_init(&wg_peer);

        wg_peer.public_key = peer_b64;
        wg_peer.preshared_key = NULL;

        /* Allowed IP: PEER's VPN IP
         * wireguard-lwip uses allowed_ip for TWO purposes:
         * 1. Outbound routing: peer_lookup_by_allowed_ip() matches DESTINATION
         *    IP to find which peer to route to (wireguardif.c:338)
         * 2. Inbound validation: checks decrypted packet SOURCE IP matches
         *    peer's allowed_source_ips (wireguardif.c:507)
         * Must be set to the PEER's VPN IP for both to work correctly. */
        uint8_t ip_a = (p->vpn_ip >> 24) & 0xFF;
        uint8_t ip_b = (p->vpn_ip >> 16) & 0xFF;
        uint8_t ip_c = (p->vpn_ip >> 8) & 0xFF;
        uint8_t ip_d = p->vpn_ip & 0xFF;
        IP4_ADDR(&wg_peer.allowed_ip.u_addr.ip4, ip_a, ip_b, ip_c, ip_d);
        IP4_ADDR(&wg_peer.allowed_mask.u_addr.ip4, 255, 255, 255, 255);

        /* Set endpoint if available, otherwise leave blank for DERP-only */
        if (p->endpoint_count > 0 && p->endpoints[0].ip != 0) {
            uint8_t ea = (p->endpoints[0].ip >> 24) & 0xFF;
            uint8_t eb = (p->endpoints[0].ip >> 16) & 0xFF;
            uint8_t ec = (p->endpoints[0].ip >> 8) & 0xFF;
            uint8_t ed = p->endpoints[0].ip & 0xFF;
            IP4_ADDR(&wg_peer.endpoint_ip.u_addr.ip4, ea, eb, ec, ed);
            wg_peer.endport_port = p->endpoints[0].port;
        } else {
            ip_addr_set_any(false, &wg_peer.endpoint_ip);
            wg_peer.endport_port = 0;
        }

        wg_peer.keep_alive = 25;

        u8_t wg_peer_idx = WIREGUARDIF_INVALID_INDEX;
        err_t wg_err = GATEWAY_WG_SITE(TDONGLE_LOCK_WG_PEER, wireguardif_add_peer(netif, &wg_peer, &wg_peer_idx));

        if (wg_err == ERR_OK && wg_peer_idx != WIREGUARDIF_INVALID_INDEX) {
            p->wg_peer_index = wg_peer_idx;

            /* Verify the WG internal peer key matches what we passed */
            struct wireguard_device *dev = (struct wireguard_device *)netif->state;
            struct wireguard_peer *wp = wireguard_device_peer(dev, wg_peer_idx);
            if (wp) {
                bool key_match = (memcmp(wp->public_key, p->public_key, 32) == 0);
                ESP_LOGI(TAG, "WG peer added: wg_idx=%d internal_key=%02x%02x%02x%02x %s",
                         wg_peer_idx,
                         wp->public_key[0], wp->public_key[1],
                         wp->public_key[2], wp->public_key[3],
                         key_match ? "KEY_OK" : "KEY_MISMATCH!");
            }

            /* DON'T initiate handshakes to all peers on add.
             * Tailscale uses lazy peer config: remote peers only add us to their
             * wireguard-go when they need to send traffic. Our handshake initiations
             * to idle peers get silently dropped (peer has no WG entry for us).
             * Instead, we wait for the peer to initiate when they need to reach us.
             * The WG session is established on-demand, matching Tailscale's model. */
            ESP_LOGI(TAG, "WG peer ready (passive), waiting for peer-initiated handshake");

            /* Phase 1.5e — if this peer is the configured exit node, attach
             * 0.0.0.0/0 to its allowed_source_ips so wireguard-lwip will
             * deliver/accept internet-bound traffic via this tunnel. */
            if (ml->config.exit_node_ip != 0 &&
                p->vpn_ip == ml->config.exit_node_ip &&
                p->is_exit_node) {
                ip_addr_t any_ip, any_mask;
                ip_addr_set_zero_ip4(&any_ip);
                ip_addr_set_zero_ip4(&any_mask);
                IP_SET_TYPE_VAL(any_ip, IPADDR_TYPE_V4);
                IP_SET_TYPE_VAL(any_mask, IPADDR_TYPE_V4);
                err_t r = GATEWAY_WG_CALL(wireguardif_add_allowed_ip(netif, wg_peer_idx,
                                                      &any_ip, &any_mask));
                ESP_LOGI(TAG, "Exit-node attach 0.0.0.0/0 for %s -> %d",
                         p->hostname, (int)r);

                /* Don't wait for the 30s DERP-only fallback timer or for the
                 * peer to send us an INITIATION first. The exit node is the
                 * one peer we positively need a session with on boot, and
                 * the 105-style hairpin-NAT peers never produce a direct-UDP
                 * PONG so the existing has_direct_path-gated handshake never
                 * fires. Fire one DERP handshake init right now. */
                GATEWAY_WG_CALL(wireguardif_connect_derp(netif, (u8_t)wg_peer_idx));
                p->derp_fallback_active = true;
                ESP_LOGW(TAG, "Exit-node DERP handshake init -> %s", p->hostname);
            }

            /* Accept-routes companion: attach any subnet routes the peer
             * advertises to its WG allowed_ips so the WG layer accepts
             * incoming packets with source in those CIDRs and (more
             * importantly) emits outgoing packets to those CIDRs over this
             * peer's tunnel. The project-side route hook only chooses the
             * WG netif as the egress — wireguard-lwip then picks the
             * matching peer using allowed_ips. Without this, the hook
             * would route to WG and WG would drop the packet because no
             * peer claims that prefix. */
            for (int r = 0; r < p->subnet_route_count; r++) {
                uint8_t plen = p->subnet_routes[r].prefix_len;
                if (plen == 0 || plen > 32) continue;
                uint32_t mask_hbo = (plen == 32) ? 0xFFFFFFFFUL
                                                 : (0xFFFFFFFFUL << (32 - plen));
                ip_addr_t net_ip, net_mask;
                IP_SET_TYPE_VAL(net_ip, IPADDR_TYPE_V4);
                IP_SET_TYPE_VAL(net_mask, IPADDR_TYPE_V4);
                ip4_addr_set_u32(ip_2_ip4(&net_ip),
                                 lwip_htonl(p->subnet_routes[r].network));
                ip4_addr_set_u32(ip_2_ip4(&net_mask), lwip_htonl(mask_hbo));
                err_t er = GATEWAY_WG_CALL(wireguardif_add_allowed_ip(netif, wg_peer_idx,
                                                      &net_ip, &net_mask));
                ESP_LOGI(TAG, "Subnet-route attach %lu.%lu.%lu.%lu/%u -> %s = %d",
                         (unsigned long)((p->subnet_routes[r].network >> 24) & 0xFF),
                         (unsigned long)((p->subnet_routes[r].network >> 16) & 0xFF),
                         (unsigned long)((p->subnet_routes[r].network >> 8)  & 0xFF),
                         (unsigned long)( p->subnet_routes[r].network        & 0xFF),
                         plen, p->hostname, (int)er);
            }
        } else {
            ESP_LOGW(TAG, "wireguardif_add_peer failed: %d", wg_err);
            p->wg_peer_index = -1;
        }
    }

    /* Persist to NVS for fast boot next time */


    /* Send CallMeMaybe to trigger peer-initiated handshake (NAT traversal).
     * Skip on cellular: our endpoints are behind carrier-grade NAT and
     * unreachable — all traffic goes through DERP relay. */
    if (!ml_at_socket_is_ready()) {
        disco_send_call_me_maybe(ml, idx);
    }

    /* Immediately probe known endpoints (throttled to avoid flooding with 100s of peers).
     * Only force-ping if fewer than 5 peers added in the last second;
     * the periodic probe (every 15s) will handle the rest.
     * Skip on cellular: direct probes fill DERP TX queue (~0.6s each on AT socket),
     * blocking time-critical WG handshake responses. */
    if (!ml_at_socket_is_ready()) {


        uint64_t add_now = ml_get_time_ms();
        if (add_now - ml->last_burst_ms > 1000) {
            ml->burst_count = 0;
            ml->last_burst_ms = add_now;
        }
        if (ml->burst_count < 5) {
            disco_send_ping_to_peer(ml, idx, true);
            ml->burst_count++;
        }
    }

    /* Notify app via callback */
    if (ml->peer_cb) {
        microlink_peer_info_t info = {
            .vpn_ip = p->vpn_ip,
            .online = true,
            .direct_path = false,
        };
        strncpy(info.hostname, p->hostname, sizeof(info.hostname) - 1);
        memcpy(info.public_key, p->public_key, 32);
        ml->peer_cb(ml, &info, ml->peer_cb_data);
    }

    return idx;
}

static void remove_peer(microlink_t *ml, const ml_peer_update_t *update) {
    /* PeersRemoved identifies the peer by NodeID (#42); the authoritative
     * sweep and the legacy nodekey form identify it by public key. */
    int idx = update->has_node_id ? find_peer_by_node_id(ml, update->node_id)
                                  : find_peer_by_key(ml, update->public_key);
    if (idx < 0) {
        if (update->has_node_id)
            ESP_LOGW(TAG, "PeersRemoved for unknown NodeID=%llu — ignored",
                     (unsigned long long)update->node_id);
        return;
    }

    /* Remove from wireguard-lwip */
    if (ml->wg_netif && ml->peers[idx].wg_peer_index >= 0) {
        struct netif *netif = (struct netif *)ml->wg_netif;
        GATEWAY_WG_SITE(TDONGLE_LOCK_WG_PEER, wireguardif_remove_peer(netif, (u8_t)ml->peers[idx].wg_peer_index));
    }

    char ip_str[16];
    microlink_ip_to_str(ml->peers[idx].vpn_ip, ip_str);
    ESP_LOGI(TAG, "Peer removed: %s (%s)", ml->peers[idx].hostname, ip_str);

    /* Drop the NVS cache entry too, or the peer resurrects at next boot
     * (#32 — removed/ACL-revoked peers must stay gone across reboots). */


    ml->peers[idx].active = false;

    /* Compact peer_count */
    while (ml->peer_count > 0 && !ml->peers[ml->peer_count - 1].active) {
        ml->peer_count--;
    }
}

static void apply_peer_update(microlink_t *ml, const ml_peer_update_t *update) {
    switch (update->action) {
    case ML_PEER_PACKET:
    case ML_PEER_BATCH:
        break; /* envelope handled by queue consumer */
    case ML_PEER_ADD:
        add_peer(ml, update);
        break;
    case ML_PEER_REMOVE:
        remove_peer(ml, update);
        break;
    case ML_PEER_UPDATE_ENDPOINT:
        /* Delta from PeersChangedPatch. Look up by NodeID first (the
         * canonical key in PeerChange), fall back to nodekey when the
         * patch carried a key rotation. is_exit_node is NOT touched
         * here — the patch doesn't carry AllowedIPs, so we'd otherwise
         * clobber the exit-node flag on any endpoint-only update. */
        {
            int idx = -1;
            if (update->has_node_id) {
                idx = find_peer_by_node_id(ml, update->node_id);
            }
            if (idx < 0) {
                /* All-zero public_key means "patch carried no Key"; skip
                 * lookup. */
                static const uint8_t zero_key[32] = {0};
                if (memcmp(update->public_key, zero_key, 32) != 0) {
                    idx = find_peer_by_key(ml, update->public_key);
                }
            }
            if (idx >= 0) {
                ml_peer_t *p = &ml->peers[idx];
                if (update->endpoint_count >= 0) {
                    p->endpoint_count = update->endpoint_count;
                    for (int i = 0;
                         i < update->endpoint_count && i < ML_MAX_ENDPOINTS;
                         i++) {
                        p->endpoints[i].ip = update->endpoints[i].ip;
                        p->endpoints[i].port = update->endpoints[i].port;
                        p->endpoints[i].is_ipv6 = update->endpoints[i].is_ipv6;
                    }
                }
                if (update->derp_region > 0) {
                    p->derp_region = update->derp_region;
                }
                if (update->has_online) {
                    p->online = update->online;
                }
                ESP_LOGI(
                    TAG,
                    "Peer patched: %s (NodeID=%llu eps=%d derp=%d online=%d)",
                    p->hostname, (unsigned long long)p->node_id,
                    p->endpoint_count, p->derp_region, p->online);
            } else {
                ESP_LOGW(TAG, "Patch for unknown peer (NodeID=%llu) — ignored",
                         (unsigned long long)update->node_id);
            }
        }
        break;
    }
}
#ifdef ESP_PLATFORM
/* ----------------------------------------------------------------------------
 * The global WireGuard peer-slot pool (P2). Every membership's WireGuard device draws its peer slots from ONE pool
 * with a hard cap (WIREGUARD_POOL_SLOTS), allocated on demand and tagged to the `wg` owner. A membership's own
 * eight-slot working set (ADR 0012) is unchanged; what is new is that the sum over memberships is capped, and the
 * cap is arbitrated here: when no slot is free the least recently used idle peer of ANY membership is evicted
 * (ml_peer_policy.h), never recent traffic. A refusal is counted and surfaces as the existing "activation
 * rejected" outcome.
 * -------------------------------------------------------------------------- */
static struct {
    uint32_t evictions_own;       /* the victim belonged to the membership asking for the slot */
    uint32_t evictions_other;     /* ...to another membership */
    uint32_t refused;             /* no eligible victim: the activation was rejected */
} pool_policy_stats;

_Static_assert(ML_MAX_PEERS * ML_MUX_MAX <= ML_POLICY_MAX_CANDIDATES,
               "the eviction scan must see every resident peer of every membership, or the LRU choice is not global");
typedef struct {
    ml_victim_candidate_t cand[ML_POLICY_MAX_CANDIDATES];
    struct { microlink_t *ml; int idx; } who[ML_POLICY_MAX_CANDIDATES];
    size_t n;
} victim_scan_t;

static void scan_member_peers(microlink_t *m, void *arg) {
    victim_scan_t *scan = arg;
    unsigned residents = 0;
    for (int i = 0; i < ML_MAX_PEERS; i++)
        if (m->peers[i].active && m->peers[i].wg_peer_index >= 0) residents++;
    for (int i = 0; i < ML_MAX_PEERS && scan->n < ML_POLICY_MAX_CANDIDATES; i++) {
        const ml_peer_t *p = &m->peers[i];
        if (!p->active || p->wg_peer_index < 0) continue;    /* holds no slot: evicting it frees nothing */
        scan->cand[scan->n] = (ml_victim_candidate_t){
            .last_used_ms = p->jit_used_ms,
            .owner_slots = residents,
            .pinned = m->config.priority_peer_ip != 0 && p->vpn_ip == m->config.priority_peer_ip,
            .trial = p->unconfirmed,
        };
        scan->who[scan->n].ml = m;
        scan->who[scan->n].idx = i;
        scan->n++;
    }
}

/* Make sure a WireGuard peer slot is free for `ml`. True when one is (free already, or after evicting a victim). */
static bool peer_pool_reserve(microlink_t *ml, uint64_t idle_ms) {
    wg_pool_stats_t st = wireguardif_pool_stats();
    if (st.used < st.capacity) return true;
    victim_scan_t scan = {.n = 0};
    ml_rt_wg_foreach_held(scan_member_peers, &scan);
    int victim = ml_policy_pick_victim(scan.cand, scan.n, ml_get_time_ms(), idle_ms);
    if (victim < 0) {
        pool_policy_stats.refused++;
        return false;
    }
    microlink_t *vm = scan.who[victim].ml;
    ml_peer_update_t rm = {.action = ML_PEER_REMOVE};
    memcpy(rm.public_key, vm->peers[scan.who[victim].idx].public_key, 32);
    ESP_LOGW(TAG, "WG peer pool full (%u/%u): evicting %s of membership %lu for membership %lu",
             (unsigned)st.used, (unsigned)st.capacity, vm->peers[scan.who[victim].idx].hostname,
             (unsigned long)vm->config.diagnostic_id, (unsigned long)ml->config.diagnostic_id);
    /* The victim's owner is this very task, but other tasks read its peers under the generation counter. */
    __atomic_add_fetch(&vm->peer_generation, 1, __ATOMIC_SEQ_CST);
    remove_peer(vm, &rm);
    __atomic_add_fetch(&vm->peer_generation, 1, __ATOMIC_SEQ_CST);
    vm->jit_evictions++;
    if (vm == ml) pool_policy_stats.evictions_own++; else pool_policy_stats.evictions_other++;
    if (vm->wg_netif) wireguardif_pool_note_eviction((const struct netif *)vm->wg_netif);
    return wireguardif_pool_stats().used < st.capacity;
}

void ml_wg_pool_status(ml_wg_pool_status_t *out) {
    wg_pool_stats_t st = wireguardif_pool_stats();
    out->capacity = st.capacity; out->used = st.used; out->peak = st.peak_used;
    out->refused_full = st.refused_full; out->refused_nomem = st.refused_nomem;
    out->evictions_own = pool_policy_stats.evictions_own;
    out->evictions_other = pool_policy_stats.evictions_other;
    out->rejected = pool_policy_stats.refused;
    out->refused_largest = slot_guard.refused_largest;
    out->refused_heap = slot_guard.refused_heap;
    out->largest_low = slot_guard.largest_low;
    out->slot_bytes = (uint32_t)sizeof(struct wireguard_peer);
    out->device_bytes = (uint32_t)sizeof(struct wireguard_device);
}
size_t ml_wg_slot_bytes(void) { return sizeof(struct wireguard_peer); }
size_t ml_wg_device_bytes(void) { return sizeof(struct wireguard_device); }

/* Called only by the peer owner. Keep hot peers; never evict recent traffic.
 * A peer idle for less than idle_ms is never evicted. */
static int directory_activate_idle(microlink_t *ml, const ml_peer_update_t *record, uint64_t idle_ms) {
    ROUTE_MARK(2);
    if(!ml->directory.session_valid)return -1;
    int idx=find_peer_by_key(ml,record->public_key);
    if(idx>=0) {ml->jit_hits++;ml->peers[idx].jit_used_ms=ml_get_time_ms();return idx;}
    ml->jit_misses++;
    bool full=true;
    for(int i=0;i<ML_MAX_PEERS;i++)if(!ml->peers[i].active)full=false;
    if(full) {
        int victim=-1;uint64_t oldest=UINT64_MAX,now=ml_get_time_ms();
        for(int i=0;i<ML_MAX_PEERS;i++) {
            uint64_t used=ml->peers[i].jit_used_ms;
            if(now-used>=idle_ms && used<oldest && ml->peers[i].vpn_ip!=ml->config.priority_peer_ip) {oldest=used;victim=i;}
        }
        if(victim<0){ml->jit_rejected++;return -1;}
        ml->jit_evictions++;
        ml_peer_update_t rm={.action=ML_PEER_REMOVE};
        memcpy(rm.public_key,ml->peers[victim].public_key,32);remove_peer(ml,&rm);
    }
    /* The pool of WireGuard slots is shared by every membership: a free peer entry is not enough. */
    if(!peer_pool_reserve(ml,idle_ms)){ml->jit_rejected++;return -1;}
    idx=add_peer(ml,record);
    if(idx>=0)ml->peers[idx].jit_used_ms=ml_get_time_ms();
    return idx;
}
/* Activation for traffic the local host or an authenticated packet asked for. */
static int directory_activate(microlink_t *ml, const ml_peer_update_t *record) {
    return directory_activate_idle(ml,record,10000);
}
/* ----------------------------------------------------------------------------
 * Activation on an unauthenticated claim.
 *
 * A DERP RecvPacket names its sender in a 32-byte field that nothing
 * authenticates: the relay (or anyone able to terminate or alter the TLS
 * stream) writes it. WireGuard cannot authenticate an initiation from a peer
 * it has no entry for, so the claim has to select a directory record and give
 * it a slot before the packet can be tested. What the claim must not do is buy
 * lasting state: a forged key must not evict warm peers, thrash flash, or keep
 * a slot. So an inbound activation is a trial:
 *
 *   - only a WireGuard initiation (the one message a non-resident peer can
 *     start a session with) with a valid mac1 for our key is eligible; the
 *     caller checks that, and everything else from an unknown key is dropped
 *     before any flash read;
 *   - one trial slot per membership. While it is held, other unknown keys are
 *     refused; a trial that does not authenticate within TRIAL_MS is removed and
 *     opens a cool-down before the next one;
 *   - a small token budget limits how often an unauthenticated packet can cost a
 *     directory lookup at all;
 *   - a trial uses a free slot, or evicts only a peer idle for TRIAL_EVICT_IDLE_MS
 *     (six times the idle window authenticated traffic needs);
 *   - the peer becomes ordinary (confirmed) only once WireGuard reports an
 *     authenticated session key for it.
 * -------------------------------------------------------------------------- */
#define TRIAL_MS 5000
#define TRIAL_COOLDOWN_MS 30000
#define TRIAL_EVICT_IDLE_MS 60000
#define TRIAL_TOKEN_BURST 3
#define TRIAL_TOKEN_REFILL_MS 1000
static bool directory_trial_token(microlink_t *ml, uint64_t now) {
    if(!ml->inbound_trial.refill_ms)ml->inbound_trial.tokens=TRIAL_TOKEN_BURST,ml->inbound_trial.refill_ms=now;
    uint64_t gained=(now-ml->inbound_trial.refill_ms)/TRIAL_TOKEN_REFILL_MS;
    if(gained) {
        unsigned tokens=ml->inbound_trial.tokens+(gained>TRIAL_TOKEN_BURST?TRIAL_TOKEN_BURST:gained);
        ml->inbound_trial.tokens=tokens>TRIAL_TOKEN_BURST?TRIAL_TOKEN_BURST:tokens;
        ml->inbound_trial.refill_ms+=gained*TRIAL_TOKEN_REFILL_MS;
    }
    if(!ml->inbound_trial.tokens){ml->inbound_trial.refused++;return false;}
    ml->inbound_trial.tokens--;
    return true;
}
/* Confirm or expire the trial peer. Cheap; call after any WireGuard input and
 * from the periodic loop. */
static void directory_trial_poll(microlink_t *ml) {
    unsigned slot=ml->inbound_trial.pending;
    if(!slot)return;
    int idx=(int)slot-1;
    ml_peer_t *peer=&ml->peers[idx];
    if(!peer->active || !peer->unconfirmed) {ml->inbound_trial.pending=0;return;} /* removed or replaced meanwhile */
    if(wg_peer_authenticated(ml,idx)) {
        peer->unconfirmed=false;ml->inbound_trial.pending=0;ml->inbound_trial.confirmed++;
        return;
    }
    uint64_t now=ml_get_time_ms();
    if(now>=ml->inbound_trial.deadline_ms) {
        ml_peer_update_t rm={.action=ML_PEER_REMOVE};
        memcpy(rm.public_key,peer->public_key,32);remove_peer(ml,&rm);
        ml->inbound_trial.pending=0;ml->inbound_trial.expired++;
        ml->inbound_trial.cooldown_until_ms=now+TRIAL_COOLDOWN_MS;
    }
}
/* May an unauthenticated packet cost a directory lookup and a trial now? */
static bool directory_trial_open(microlink_t *ml) {
    uint64_t now=ml_get_time_ms();
    directory_trial_poll(ml);
    if(ml->inbound_trial.pending || now<ml->inbound_trial.cooldown_until_ms) {ml->inbound_trial.refused++;return false;}
    return directory_trial_token(ml,now);
}
/* Give the record a trial slot. Returns the peer index or -1. */
static int directory_trial_start(microlink_t *ml, const ml_peer_update_t *record) {
    int idx=find_peer_by_key(ml,record->public_key);
    if(idx>=0)return idx; /* already resident: nothing to trial */
    idx=directory_activate_idle(ml,record,TRIAL_EVICT_IDLE_MS);
    if(idx<0)return -1;
    ml->peers[idx].unconfirmed=true;
    ml->inbound_trial.pending=(uint8_t)(idx+1);
    ml->inbound_trial.deadline_ms=ml_get_time_ms()+TRIAL_MS;
    ml->inbound_trial.started++;
    return idx;
}
/* Resolve the sender of a DERP-relayed WireGuard packet: the resident peer, or
 * a trial activation for a directory peer that opens with a plausible
 * initiation. -1 means drop the packet; nothing was activated. */
static int derp_sender_admit(microlink_t *ml, const ml_rx_packet_t *pkt) {
    int idx=find_peer_by_key(ml,pkt->src_pubkey);
    if(idx>=0)return idx;
    ml_peer_update_t record;
    if(!wg_initiation_plausible(ml,pkt) || !directory_trial_open(ml) ||
       !ml_directory_find(ml,0,pkt->src_pubkey,NULL,0,&record))return -1;
    return directory_trial_start(ml,&record);
}
/* DISCO: the sender is identified by a key inside the packet, which only the
 * holder of the matching private key can box correctly. Authenticate first
 * (one X25519 and one box open, bounded by the token budget), activate second:
 * a forged sender key never reaches the peer table. A resident sender is
 * handled by the caller exactly as before. */
static int directory_disco_admit(microlink_t *ml, const uint8_t *sender_key, const uint8_t *nonce,
                                 const uint8_t *ciphertext, size_t length) {
    int idx=find_peer_by_disco_key(ml,sender_key);
    if(idx>=0) {ml->peers[idx].jit_used_ms=ml_get_time_ms();return idx;}
    if(length<NACL_BOX_MACBYTES || !directory_trial_token(ml,ml_get_time_ms()))return -1;
    ml_peer_update_t record;
    if(!ml_directory_find(ml,0,NULL,sender_key,0,&record))return -1;
    if(!disco_authenticates(ml,sender_key,nonce,ciphertext,length)){ml->inbound_trial.refused++;return -1;}
    idx=directory_activate(ml,&record);
    if(idx>=0)ml->peers[idx].jit_used_ms=ml_get_time_ms();
    return idx;
}
static int directory_by_disco(microlink_t *ml,const uint8_t *key) {
    int idx=find_peer_by_disco_key(ml,key);
    if(idx<0) {ml_peer_update_t record;
        if(ml_directory_find(ml,0,NULL,key,0,&record))idx=directory_activate(ml,&record);}
    if(idx>=0)ml->peers[idx].jit_used_ms=ml_get_time_ms();
    return idx;
}
static void directory_reconcile(microlink_t *ml) {
    uint32_t generation=__atomic_load_n(&ml->directory.generation,__ATOMIC_ACQUIRE);
    if(generation==ml->directory_applied)return;
            for(int i=0;i<ML_MAX_PEERS;i++) {
                ml_peer_t *peer=&ml->peers[i];if(!peer->active)continue;
                ml_peer_update_t record;
                bool present=ml_directory_find(ml,0,NULL,NULL,peer->node_id,&record);
                if(!peer->node_id)present=ml_directory_find(ml,peer->vpn_ip,NULL,NULL,0,&record);
                if(!present || memcmp(peer->public_key,record.public_key,32) || peer->vpn_ip!=record.vpn_ip ||
                   peer->is_exit_node!=record.is_exit_node || peer->subnet_route_count!=record.subnet_route_count ||
                   memcmp(peer->subnet_routes,record.subnet_routes,sizeof(record.subnet_routes))) {
                    ml_peer_update_t rm={.action=ML_PEER_REMOVE};memcpy(rm.public_key,peer->public_key,32);remove_peer(ml,&rm);
                } else {
                    uint64_t used=peer->jit_used_ms;
                    ml_peer_update_t patch=record;patch.action=ML_PEER_UPDATE_ENDPOINT;
                    apply_peer_update(ml,&patch);
                    memcpy(peer->disco_key,record.disco_key,32);
                    peer->disco_shared_valid=false;peer->jit_used_ms=used;
                }
            }
    ml->directory_applied=generation;
}
/* ----------------------------------------------------------------------------
 * Egress: USB -> tunnel packets (docs/adr/0018-wg-mgr-packet-path.md)
 *
 * usb_routes builds the WireGuard datagram where it will be sent from: one lwIP RAM pbuf in the transport layout
 * [16 B header space][plaintext, zero padded to 16][16 B tag space], preceded by a small record (destination, enqueue
 * time) in its headroom. The pbuf pointer (bit 0 set, to tell it from a peer-update block) is the queue entry. wg_mgr
 * seals it in place and hands the same pbuf to the UDP pcb: one allocation and one copy per packet, where there were
 * six allocations and four copies (calloc+copy, pbuf+copy, transport pbuf+copy, linearising buffer+copy, SPIRAM wrapper
 * +copy). Network callbacks still never provision peers or read flash: a packet for a peer that is not resident waits in
 * a pending slot (at most ML_JIT_PENDING per membership including those still in the queue) while wg_mgr activates it.
 * ------------------------------------------------------------------------- */
typedef struct { uint32_t vpn_ip, enq_us; uint16_t len; } ml_egress_meta_t;
/* Units of work done in the current pass (packets, timers, drains): a pass that did none was idle. wg_mgr task only. */
static unsigned g_pass_work;
/* Arrival order of parked packets (wg_mgr task only): slots are reused in any order, so the flush goes by this, not by slot. */
static uint32_t g_park_seq;
unsigned ml_wg_pass_work_take(void) { unsigned n = g_pass_work; g_pass_work = 0; return n; }

esp_err_t ml_gateway_queue_packet(microlink_t *ml,uint32_t ip,const uint8_t *data,size_t len) {
    if(!ml || !data || !len || len>1400 || ml->state!=ML_STATE_CONNECTED)return ESP_ERR_INVALID_STATE;
    /* Pending packets are not charged to admission at all (ml_admission.h, elastic): they come from free heap
     * above the one elastic floor (ml_heap_budget.h, ADR 0022), and are refused (counted) here when they would not. */
    if(!ml_hb_ok(heap_caps_get_free_size(MALLOC_CAP_INTERNAL),WIREGUARDIF_DATA_ALLOC(len)+sizeof(ml_egress_meta_t)+sizeof(struct pbuf)+64)){ml_hb_refuse(ML_HB_JIT);return ESP_ERR_NO_MEM;}
    unsigned old=__atomic_fetch_add(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);
    if(old>=ML_JIT_PENDING) {__atomic_fetch_sub(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);return ESP_ERR_NO_MEM;}
    WGPERF_T(t);
    size_t padded=WIREGUARDIF_DATA_PAD(len);
    struct pbuf *packet=pbuf_alloc(PBUF_TRANSPORT,(u16_t)WIREGUARDIF_DATA_ALLOC(len),PBUF_RAM);
    if(!packet) {__atomic_fetch_sub(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);return ESP_ERR_NO_MEM;}
    uint8_t *wire=packet->payload;
    memset(wire,0,WIREGUARDIF_DATA_HDR);                                  /* header: filled when sealed */
    memcpy(wire+WIREGUARDIF_DATA_HDR,data,len);
    memset(wire+WIREGUARDIF_DATA_HDR+len,0,padded-len+WIREGUARD_AUTHTAG_LEN);   /* padding and tag space */
    if(pbuf_add_header(packet,sizeof(ml_egress_meta_t))) {pbuf_free(packet);__atomic_fetch_sub(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);return ESP_ERR_NO_MEM;}
    ml_egress_meta_t meta={.vpn_ip=ip,.enq_us=WGPERF_US_NOW(),.len=(uint16_t)len};
    memcpy(packet->payload,&meta,sizeof(meta));
    void *entry=ml_pu_tag_packet(packet);
    if(xQueueSend(ml->peer_update_queue,&entry,0)!=pdTRUE) {
        pbuf_free(packet);__atomic_fetch_sub(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);return ESP_ERR_NO_MEM;}
    WGPERF_COUNT(wakes,1);
    ml_rt_wake(ML_RT_TASK_WG_MGR);   /* event driven: the queue is serviced now, not at the next poll */
    WGPERF_LAP(t,prep);
    return ESP_OK;
}
/* Has WireGuard a session for this peer (either keypair)? The quiet form of ml_wg_mgr_peer_is_up: that one logs a line
 * per call, which on the data path was one line per packet. */
static bool wg_peer_session_up(microlink_t *ml,const ml_peer_t *peer) {
    if(!ml->wg_netif || peer->wg_peer_index<0)return false;
    return wireguardif_peer_is_up((struct netif *)ml->wg_netif,(u8_t)peer->wg_peer_index,NULL,NULL)==ERR_OK;
}
/* Seal and send one prepared packet, then drop the reference. The result is not used: as before, a packet that cannot be
 * sent now (no usable keypair, send error) is lost, and TCP above retransmits. */
static void gateway_send_packet(microlink_t *ml,struct pbuf *packet,uint32_t vpn_ip,uint16_t len) {
    struct netif *wg=ml->wg_netif;
    if(wg) {
        WGPERF_T(t);
        ip4_addr_t ip={.addr=htonl(vpn_ip)};
        /* ChaCha20-Poly1305 over up to 1.4 KB is ~62k cycles (0.26 ms): not under the core lock (as the receive direction,
         * PR #30). begin and commit hold it for the lookup, the nonce and the send; the seal in between touches only this
         * packet's pbuf and a private copy of the key (wireguardif.c, wireguardif_tx_begin). */
        struct wireguard_tx_job job;err_t result=ERR_CONN;int seal=0;
        ROUTE_MARK(4);
        WG_LOCKED(TDONGLE_LOCK_WG_OUTPUT, seal=wireguardif_tx_begin(wg,packet,len,&ip,&job,&result));
        if(seal) {
            wireguard_tx_seal(&job);
            WG_LOCKED(TDONGLE_LOCK_WG_COMMIT, result=wireguardif_tx_commit(wg,&job));
        }
        (void)result;
        ROUTE_MARK(0);
        WGPERF_LAP(t,send);
    }
    pbuf_free(packet);
}
static void gateway_release_slot(microlink_t *ml,unsigned i) {
    ml->jit_pending[i].packet=NULL;
    __atomic_fetch_sub(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);
}
static bool gateway_parked_for(const microlink_t *ml,uint32_t vpn_ip) {
    for(unsigned i=0;i<ML_JIT_PENDING;i++)if(ml->jit_pending[i].packet && ml->jit_pending[i].vpn_ip==vpn_ip)return true;
    return false;
}
/* One packet taken from the queue. A resident peer with a session and nothing waiting ahead of it for the same
 * destination is sent now, in this pass (what the pending slot and the flush that followed did for every packet, with
 * three more peer lookups and a log line); anything else is parked and the handshake started, as before. A peer that is
 * not resident is activated first (ADR-0012 amendment: JIT activation, eviction rules and the 5 s expiry unchanged). */
static void gateway_egress_packet(microlink_t *ml,struct pbuf *packet) {
    g_pass_work++;
    ml_egress_meta_t meta;
    memcpy(&meta,packet->payload,sizeof(meta));
    pbuf_remove_header(packet,sizeof(meta));
    WGPERF_ADD(q_latency,WGPERF_US_NOW()-meta.enq_us);
    WGPERF_T(t);
    ml_peer_update_t record;
    int idx=find_peer_by_ip(ml,meta.vpn_ip);
    if(idx>=0){ml->jit_hits++;ml->peers[idx].jit_used_ms=ml_get_time_ms();}
    else if(ml_directory_find(ml,meta.vpn_ip,NULL,NULL,0,&record)) {
        __atomic_add_fetch(&ml->peer_generation,1,__ATOMIC_SEQ_CST);
        idx=directory_activate(ml,&record);
        __atomic_add_fetch(&ml->peer_generation,1,__ATOMIC_SEQ_CST);
    }
    bool up=idx>=0 && wg_peer_session_up(ml,&ml->peers[idx]);
    WGPERF_LAP(t,lookup);
    if(up && !gateway_parked_for(ml,meta.vpn_ip)) {
        WGPERF_COUNT(out_direct,1);
        gateway_send_packet(ml,packet,meta.vpn_ip,meta.len);
        __atomic_fetch_sub(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);   /* the budget counts queued and parked packets only */
        return;
    }
    if(idx>=0)for(unsigned i=0;i<ML_JIT_PENDING;i++)if(!ml->jit_pending[i].packet) {
        ml->jit_pending[i].packet=packet;ml->jit_pending[i].expires=ml_get_time_ms()+5000;
        ml->jit_pending[i].vpn_ip=meta.vpn_ip;ml->jit_pending[i].len=meta.len;ml->jit_pending[i].seq=++g_park_seq;
        WGPERF_COUNT(out_parked,1);
        ROUTE_MARK(3);
        ml_wg_mgr_trigger_handshake(ml,meta.vpn_ip);ROUTE_MARK(0);
        return;
    }
    WGPERF_COUNT(out_discard,1);
    ml->jit_dropped++;pbuf_free(packet);__atomic_fetch_sub(&ml->jit_packet_count,1,__ATOMIC_ACQ_REL);
}
static void directory_flush_packets(microlink_t *ml) {
    /* In arrival order (oldest `seq` first), not slot order: a slot freed by one peer's packet is taken by the next packet
     * of any peer, so slot order is not arrival order and would send a peer's newer packet ahead of its older one. */
    unsigned done=0;
    for(;;) {
        int pick=-1;
        for(unsigned i=0;i<ML_JIT_PENDING;i++) {
            if(!ml->jit_pending[i].packet || (done&(1u<<i)))continue;
            if(pick<0 || (int32_t)(ml->jit_pending[i].seq-ml->jit_pending[pick].seq)<0)pick=(int)i;
        }
        if(pick<0)break;
        unsigned i=(unsigned)pick;done|=1u<<i;
        struct pbuf *packet=ml->jit_pending[i].packet;
        int idx=find_peer_by_ip(ml,ml->jit_pending[i].vpn_ip);
        bool discard=idx<0 || ml_get_time_ms()>=ml->jit_pending[i].expires;
        if(discard){ml->jit_dropped++;WGPERF_COUNT(out_discard,1);pbuf_free(packet);gateway_release_slot(ml,i);continue;}
        if(wg_peer_session_up(ml,&ml->peers[idx])) {
            WGPERF_COUNT(out_flushed,1);
            gateway_send_packet(ml,packet,ml->jit_pending[i].vpn_ip,ml->jit_pending[i].len);
            ml->peers[idx].jit_used_ms=ml_get_time_ms();
            gateway_release_slot(ml,i);
        }
    }
}
#endif
void ml_pu_free_entry(void *entry) {
    if (!entry) return;
    if (ml_pu_is_packet(entry)) pbuf_free(ml_pu_packet(entry));
    else tdongle_heap_free(TDONGLE_OWNER_PEER, entry);
}
static void process_peer_updates(microlink_t *ml) {
    ml_peer_update_t *update;
    while (xQueueReceive(ml->peer_update_queue, &update, 0) == pdTRUE) {
        if (!update)
            continue;
#ifdef ESP_PLATFORM
        /* An egress packet changes no peer metadata (an activation bumps the generation itself), so it takes no part in
         * the odd/even protocol that status readers use. */
        if(ml_pu_is_packet(update)) {gateway_egress_packet(ml,ml_pu_packet(update));continue;}
#endif
        __atomic_add_fetch(&ml->peer_generation,1,__ATOMIC_SEQ_CST);
        bool is_batch = update->action == ML_PEER_BATCH;
        if (is_batch) {
            ml_peer_batch_t *batch = (ml_peer_batch_t *)update;
#ifdef ESP_PLATFORM
            directory_reconcile(ml);
#else
            /* Authoritative omission is evaluated by the peer owner after
             * earlier batches, not against a stale coordination snapshot. */
            if (batch->authoritative) {
                for (int p = 0; p < ML_MAX_PEERS; p++) {
                    if (!ml->peers[p].active)
                        continue;
                    bool present = false;
                    for (size_t i = 0; i < batch->count; i++)
                        if (batch->updates[i].action == ML_PEER_ADD &&
                            !memcmp(batch->updates[i].public_key,
                                    ml->peers[p].public_key, 32)) {
                            present = true;
                            break;
                        }
                    if (!present) {
                        ml_peer_update_t rm = {.action = ML_PEER_REMOVE};
                        memcpy(rm.public_key, ml->peers[p].public_key, 32);
                        remove_peer(ml, &rm);
                    }
                }
            }
            for (size_t i = 0; i < batch->count; i++)
                if (batch->updates[i].action == ML_PEER_ADD)
                    apply_peer_update(ml, &batch->updates[i]);
            for (size_t i = 0; i < batch->count; i++)
                if (batch->updates[i].action != ML_PEER_ADD)
                    apply_peer_update(ml, &batch->updates[i]);
#endif
        } else
            apply_peer_update(ml, update);
        __atomic_add_fetch(&ml->peer_generation,1,__ATOMIC_SEQ_CST);
        tdongle_heap_free(ml_peer_update_owner(update), update);
        if (is_batch)
            __atomic_store_n(&ml->map_batch_pending, false, __ATOMIC_RELEASE);
    }
}

/* ============================================================================
 * DISCO Protocol
 * ========================================================================== */

static void disco_build_ping(microlink_t *ml, int peer_idx,
                               uint8_t *out, size_t *out_len) {
    ml_peer_t *p = &ml->peers[peer_idx];

    /* Plaintext: [type(1)][version(1)][txid(12)][nodekey(32)] = 46 bytes */
    uint8_t plaintext[46];
    plaintext[0] = DISCO_MSG_PING;
    plaintext[1] = 0;  /* version */

    /* Generate random transaction ID */
    uint8_t txid[DISCO_TXID_LEN];
    esp_fill_random(txid, DISCO_TXID_LEN);
    memcpy(plaintext + 2, txid, DISCO_TXID_LEN);
    memcpy(plaintext + 14, ml->wg_public_key, 32);

    /* Generate random nonce */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, DISCO_NONCE_LEN);

    /* Encrypt with NaCl box: our disco private key -> peer's disco public key */
    uint8_t ciphertext[46 + NACL_BOX_MACBYTES];
    const uint8_t *shared = disco_shared_key(ml, p);
    if (!shared) { *out_len = 0; return; }
    nacl_box_afternm(ciphertext, plaintext, sizeof(plaintext), nonce, shared);

    /* Build packet: magic(6) + our_disco_pubkey(32) + nonce(24) + ciphertext(62) = 124 bytes */
    size_t pos = 0;
    memcpy(out + pos, DISCO_MAGIC, 6); pos += 6;
    memcpy(out + pos, ml->disco_public_key, 32); pos += 32;
    memcpy(out + pos, nonce, DISCO_NONCE_LEN); pos += DISCO_NONCE_LEN;
    memcpy(out + pos, ciphertext, sizeof(ciphertext)); pos += sizeof(ciphertext);
    *out_len = pos;

    /* Track pending probe */
    bool registered = false;
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (!ml->pending_probes[i].active) {
            memcpy(ml->pending_probes[i].txid, txid, DISCO_TXID_LEN);
            ml->pending_probes[i].peer_index = peer_idx;
            ml->pending_probes[i].sent_ms = ml_get_time_ms();
            ml->pending_probes[i].active = true;
            registered = true;
            ESP_LOGD(TAG, "Probe registered slot=%d peer=%s txid=%02x%02x%02x%02x",
                     i, p->hostname, txid[0], txid[1], txid[2], txid[3]);
            break;
        }
    }
    if (!registered) {
        /* Rate-limited: when the table saturates this fires many times a second,
         * and the logging itself starves the task watchdog (observed: reboot
         * loop under a DISCO storm from a single busy peer). One line every
         * 10 s says the same thing without becoming the fault it is reporting.
         * (Throttle pattern lifted from timmills' #36 series.) */
        static uint64_t last_full_log_ms = 0;
        static uint32_t full_suppressed = 0;
        uint64_t now_ms = ml_get_time_ms();
        if (now_ms - last_full_log_ms > 10000) {
            ESP_LOGW(TAG, "DISCO probe table full (%d slots), pong will be unmatched"
                          " (%lu more suppressed in the last 10s)",
                     MAX_PENDING_PROBES, (unsigned long)full_suppressed);
            last_full_log_ms = now_ms;
            full_suppressed = 0;
        } else {
            full_suppressed++;
        }
    }
}

static void disco_build_pong(microlink_t *ml, int peer_idx,
                               const uint8_t *txid,
                               uint32_t src_ip, uint16_t src_port,
                               uint8_t *out, size_t *out_len) {
    ml_peer_t *p = &ml->peers[peer_idx];

    /* Plaintext: [type(1)][version(1)][txid(12)][src_addr(18)] = 32 bytes */
    /* src_addr: IPv6-mapped IPv4 (16 bytes) + port (2 bytes big-endian) */
    uint8_t plaintext[32];
    plaintext[0] = DISCO_MSG_PONG;
    plaintext[1] = 0;
    memcpy(plaintext + 2, txid, DISCO_TXID_LEN);

    /* IPv6-mapped IPv4: ::ffff:A.B.C.D */
    memset(plaintext + 14, 0, 10);
    plaintext[24] = 0xff;
    plaintext[25] = 0xff;
    plaintext[26] = (src_ip >> 24) & 0xFF;
    plaintext[27] = (src_ip >> 16) & 0xFF;
    plaintext[28] = (src_ip >> 8) & 0xFF;
    plaintext[29] = src_ip & 0xFF;
    plaintext[30] = (src_port >> 8) & 0xFF;
    plaintext[31] = src_port & 0xFF;

    /* Generate random nonce */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, DISCO_NONCE_LEN);

    /* Encrypt */
    uint8_t ciphertext[32 + NACL_BOX_MACBYTES];
    const uint8_t *shared = disco_shared_key(ml, p);
    if (!shared) { *out_len = 0; return; }
    nacl_box_afternm(ciphertext, plaintext, sizeof(plaintext), nonce, shared);

    /* Build packet */
    size_t pos = 0;
    memcpy(out + pos, DISCO_MAGIC, 6); pos += 6;
    memcpy(out + pos, ml->disco_public_key, 32); pos += 32;
    memcpy(out + pos, nonce, DISCO_NONCE_LEN); pos += DISCO_NONCE_LEN;
    memcpy(out + pos, ciphertext, sizeof(ciphertext)); pos += sizeof(ciphertext);
    *out_len = pos;
}

static void disco_send_ping_to_peer(microlink_t *ml, int peer_idx, bool force) {
    ml_peer_t *p = &ml->peers[peer_idx];
    uint64_t now = ml_get_time_ms();

    /* Rate limit: don't ping more often than DISCO_PING_INTERVAL_MS (skip if forced) */
    if (!force && now - p->last_ping_sent_ms < ML_DISCO_PING_INTERVAL_MS) {
        return;
    }

    uint8_t pkt[256];
    size_t pkt_len = 0;
    disco_build_ping(ml, peer_idx, pkt, &pkt_len);

    if (pkt_len == 0) return;

    bool direct_sent = false;

    /* If we have a known working direct path, send there FIRST.
     * This is critical for heartbeat pings to renew trust_until_ms.
     * A DERP pong would arrive with via_derp=true and NOT renew trust. */
    if (p->has_direct_path && p->best_ip != 0 && p->best_port != 0) {
        disco_udp_sendto(ml, pkt, pkt_len, p->best_ip, p->best_port);
        direct_sent = true;
    }

    /* Also try direct UDP to all known endpoints from MapResponse */
    {
        bool has_udp = disco_has_udp_path(ml);
        if (has_udp) {
            for (int i = 0; i < p->endpoint_count; i++) {
                if (!p->endpoints[i].is_ipv6 && p->endpoints[i].ip != 0) {
                    /* Skip if same as best_ip (already sent) */
                    if (p->endpoints[i].ip == p->best_ip &&
                        p->endpoints[i].port == p->best_port) continue;
                    int ret = disco_udp_sendto(ml, pkt, pkt_len, p->endpoints[i].ip, p->endpoints[i].port);
                    if (!direct_sent) {  /* Log only first direct send per peer */
                        ESP_LOGI(TAG, "  direct probe -> %d.%d.%d.%d:%d (%d eps, ret=%d)",
                                 (int)((p->endpoints[i].ip >> 24) & 0xFF),
                                 (int)((p->endpoints[i].ip >> 16) & 0xFF),
                                 (int)((p->endpoints[i].ip >> 8) & 0xFF),
                                 (int)(p->endpoints[i].ip & 0xFF),
                                 (int)p->endpoints[i].port,
                                 p->endpoint_count, ret);
                    }
                    direct_sent = true;
                }
            }
        }
        if (!has_udp) {
            ESP_LOGW(TAG, "  no UDP path for %s (sock4=%d)", p->hostname, ml->disco_sock4);
        } else if (!direct_sent && p->endpoint_count > 0) {
            ESP_LOGW(TAG, "  %s: %d eps but none usable (all IPv6?)", p->hostname, p->endpoint_count);
        }
    }

    /* Send via DERP as fallback (or always for initial probes).
     * Skip DERP for heartbeat pings when direct path is active to avoid
     * DERP pong stealing the probe match from the direct pong. */
    if (!p->has_direct_path || !direct_sent) {
        ml_derp_queue_send(ml, p->public_key, pkt, pkt_len);
        ESP_LOGD(TAG, "DISCO PING -> %s via DERP", p->hostname);
    } else {
        ESP_LOGD(TAG, "DISCO PING -> %s via direct %d.%d.%d.%d:%d",
                 p->hostname,
                 (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                 (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
                 (int)p->best_port);
    }

    p->last_ping_sent_ms = now;
}

static void process_disco_ping(microlink_t *ml, const ml_rx_packet_t *pkt,
                                 const uint8_t *sender_disco_key,
                                 const uint8_t *decrypted, size_t decrypted_len) {
    if (decrypted_len < 14) return;

    /* Extract txid from decrypted payload */
    const uint8_t *txid = decrypted + 2;

    /* Find peer by disco key */
    int peer_idx = directory_by_disco(ml, sender_disco_key);
    if (peer_idx < 0) {
        ESP_LOGW(TAG, "DISCO ping from unknown peer");
        return;
    }

    ml_peer_t *p = &ml->peers[peer_idx];

    ESP_LOGD(TAG, "DISCO PING from %s (via %s)",
             p->hostname, pkt->via_derp ? "DERP" : "direct");

    /* Nothing is sent from here beyond the PONG below -- a PING must not
     * trigger a PING, or two nodes chase each other. (The reference client
     * also files the source as a candidate endpoint; that is deliberately
     * not done here: without latency-based path selection a second
     * answering address makes best_ip/best_port flap between the two and,
     * with no data flowing, every flap forces a WireGuard handshake --
     * observed with a NAT'd container peer whose pings leave from a port
     * other than its listening one.) */

    /* Build PONG */
    uint8_t pong[256];
    size_t pong_len = 0;
    disco_build_pong(ml, peer_idx, txid, pkt->src_ip, pkt->src_port,
                     pong, &pong_len);

    if (pong_len == 0) return;

    /* One PONG, back to where the PING came from (reference client
     * handlePingLocked: a single sendDiscoMessage to the source -- the
     * source address for a direct PING, DERP for a DERP PING). The old
     * fan-out (source + every LAN endpoint of the peer + always a DERP copy)
     * cost the pinger an "unmatched PONG" per extra copy and a DERP round
     * trip per PING for nothing: a direct PING proves the direct return
     * path already, and a peer probing our LAN address gets its PONG from
     * that PING on its own. DERP only if the direct send itself fails. */
    if (!pkt->via_derp && pkt->src_ip != 0 && pkt->src_port != 0) {
        if (disco_udp_sendto(ml, pong, pong_len, pkt->src_ip, pkt->src_port) < 0) {
            ml_derp_queue_send(ml, p->public_key, pong, pong_len);
            ESP_LOGD(TAG, "PONG -> %s via DERP (direct send failed)", p->hostname);
        } else {
            ESP_LOGD(TAG, "PONG -> %s direct", p->hostname);
        }
    } else {
        ml_derp_queue_send(ml, p->public_key, pong, pong_len);
        ESP_LOGD(TAG, "PONG -> %s via DERP", p->hostname);
    }
}

static void process_disco_pong(microlink_t *ml, const ml_rx_packet_t *pkt,
                                 const uint8_t *sender_disco_key,
                                 const uint8_t *decrypted, size_t decrypted_len) {
    if (decrypted_len < 14) return;

    const uint8_t *txid = decrypted + 2;
    uint64_t now = ml_get_time_ms();

    /* Match transaction ID */
    bool matched = false;
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (!ml->pending_probes[i].active) continue;
        if (memcmp(ml->pending_probes[i].txid, txid, DISCO_TXID_LEN) != 0) continue;

        int peer_idx = ml->pending_probes[i].peer_index;
        if (peer_idx < 0 || peer_idx >= ml->peer_count) {
            ml->pending_probes[i].active = false;
            continue;
        }

        ml_peer_t *p = &ml->peers[peer_idx];
        uint64_t rtt_ms = now - ml->pending_probes[i].sent_ms;

        ESP_LOGD(TAG, "DISCO PONG from %s: RTT=%llu ms (via %s)",
                 p->hostname, (unsigned long long)rtt_ms,
                 pkt->via_derp ? "DERP" : "direct");

        p->last_pong_recv_ms = now;

        /* If direct reply, update best path -- but stick to the current one
         * while it still answers. A peer can answer from two addresses (its
         * LAN address and its public NAT mapping are both in the netmap and
         * both get our ping; a NAT may also flip ports), and following every
         * PONG made best_ip/best_port flap between them; with no data
         * flowing, every flap forced a WireGuard handshake below (measured:
         * one per 3 s toward such a peer). The reference client keeps
         * bestAddr while it is trusted (trustUDPAddrDuration, 6.5 s) and
         * only moves on clearly better latency; without per-endpoint
         * latency here the rule is: keep the best while it answered within
         * that window, let another address take over once it went quiet. */
        if (!pkt->via_derp && pkt->src_ip != 0 && p->has_direct_path &&
            (p->best_ip != pkt->src_ip || p->best_port != pkt->src_port) &&
            (now - p->best_last_pong_ms) < ML_DISCO_BEST_STICKY_MS) {
            ESP_LOGD(TAG, "PONG from %s via %d.%d.%d.%d:%d, keeping best %d.%d.%d.%d:%d (answered %llu ms ago)",
                     p->hostname,
                     (int)((pkt->src_ip >> 24) & 0xFF), (int)((pkt->src_ip >> 16) & 0xFF),
                     (int)((pkt->src_ip >> 8) & 0xFF), (int)(pkt->src_ip & 0xFF), (int)pkt->src_port,
                     (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                     (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF), (int)p->best_port,
                     (unsigned long long)(now - p->best_last_pong_ms));
            ml->pending_probes[i].active = false;
            matched = true;
            break;
        }
        if (!pkt->via_derp && pkt->src_ip != 0) {
            p->best_ip = pkt->src_ip;
            p->best_port = pkt->src_port;
            p->best_last_pong_ms = now;
            p->has_direct_path = true;
            p->trust_until_ms = now + ML_DISCO_TRUST_DURATION_MS;
            /* Phase 1.5g — a direct PONG arrived; clear the DERP-only flag so
             * we'll switch back to direct (handled by wireguardif_update_endpoint
             * a few lines below with the new pkt->src_ip:src_port). */
            p->derp_fallback_active = false;

            /* Update WireGuard endpoint to direct path.
             * Always update the stored endpoint. Only force a handshake if we
             * already have an active WG session (peer has us in their config).
             * For idle peers, the next incoming initiation will use this endpoint. */
            if (ml->wg_netif && p->wg_peer_index >= 0) {
                struct netif *netif = (struct netif *)ml->wg_netif;
                ip_addr_t ep_ip;
                IP_SET_TYPE_VAL(ep_ip, IPADDR_TYPE_V4);
                ip4_addr_set_u32(ip_2_ip4(&ep_ip), htonl(pkt->src_ip));
                GATEWAY_WG_CALL(wireguardif_update_endpoint(netif, (u8_t)p->wg_peer_index,
                                             &ep_ip, pkt->src_port));

                /* Only call connect (forces handshake) if:
                 * 1. Peer has an active WG session, AND
                 * 2. The endpoint actually changed (avoid re-handshake on every heartbeat PONG) */
                ip_addr_t cur_ip;
                u16_t cur_port;
                err_t is_up = wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index,
                                                       &cur_ip, &cur_port);
                if (is_up == ERR_OK) {
                    /* Check if endpoint actually changed */
                    uint32_t cur_ip_u32 = ip4_addr_get_u32(ip_2_ip4(&cur_ip));
                    uint32_t new_ip_u32 = htonl(pkt->src_ip);
                    if (cur_ip_u32 != new_ip_u32 || cur_port != pkt->src_port) {
                        /* Throughput-collapse fix (2026-05-24): peers behind
                         * carrier-grade NAT (here: dk-tailscale-lxc, observed
                         * port flipping every 30-60 s between :41641 and
                         * :41642) generate continuous endpoint-changed PONGs.
                         * The old code unconditionally re-handshaked on every
                         * flip — each handshake stalls TX ~5-15 s, which is
                         * what the user sees as "speedtest collapses to
                         * 0.07 Mbps".
                         *
                         * GATEWAY_WG_CALL(wireguardif_update_endpoint()) above already updated
                         * peer->ip:port — the next TX packet goes to the new
                         * endpoint with the EXISTING valid keypair. WireGuard
                         * authenticates by key, not by endpoint, so the peer
                         * still decrypts our packets correctly.
                         *
                         * Only force a fresh handshake when the encrypted
                         * data path is ALSO stale (no RX in 5+ s) — at that
                         * point the keypair may genuinely be out of sync. */
                        struct wireguard_device *dev = (struct wireguard_device *)netif->state;
                        uint32_t last_rx_age_ms = 0xFFFFFFFF;
                        struct wireguard_peer *wp = wireguard_device_peer(dev, (uint8_t)p->wg_peer_index);
                        if (wp) {
                            if (wp->last_rx) {
                                uint32_t now_wg = wireguard_sys_now();
                                uint32_t age = now_wg - wp->last_rx;
                                last_rx_age_ms = (age > 0x7FFFFFFFu) ? 0 : age;
                            }
                        }
                        bool data_alive = (last_rx_age_ms < 5000);
                        if (data_alive) {
                            ESP_LOGI(TAG, "WG endpoint port flip (NAT-rebind) for %s "
                                          "%d.%d.%d.%d:%d -> :%d; data alive "
                                          "(last_rx=%ums), reusing keypair (no handshake)",
                                     p->hostname,
                                     (int)((cur_ip_u32 >> 0) & 0xFF), (int)((cur_ip_u32 >> 8) & 0xFF),
                                     (int)((cur_ip_u32 >> 16) & 0xFF), (int)((cur_ip_u32 >> 24) & 0xFF),
                                     (int)cur_port, (int)pkt->src_port,
                                     (unsigned)last_rx_age_ms);
                        } else {
                            /* No data lately either -- still no reason for a
                             * handshake. WireGuard authenticates by key and
                             * roams by design: the existing keypair keeps
                             * working at the new address, and a peer that
                             * really lost the session is caught by the WG
                             * timers and by the DERP retry above (up != OK).
                             * The forced handshake that used to sit here
                             * fought wireguardif's own roaming on a
                             * dual-homed peer -- DISCO's best said one of its
                             * addresses, its WireGuard packets arrived from
                             * the other, so the endpoint changed on every
                             * heartbeat and re-handshaked every 3 s for ever.
                             * The reference client never handshakes on an
                             * endpoint change. */
                            ESP_LOGD(TAG, "WG endpoint re-pointed to direct: %d.%d.%d.%d:%d for %s "
                                          "(last_rx=%ums, session kept)",
                                     (int)((pkt->src_ip >> 24) & 0xFF), (int)((pkt->src_ip >> 16) & 0xFF),
                                     (int)((pkt->src_ip >> 8) & 0xFF), (int)(pkt->src_ip & 0xFF),
                                     (int)pkt->src_port, p->hostname,
                                     (unsigned)last_rx_age_ms);
                        }
                    }
                } else {
                    ESP_LOGD(TAG, "WG endpoint stored (no session): %d.%d.%d.%d:%d for %s",
                             (int)((pkt->src_ip >> 24) & 0xFF), (int)((pkt->src_ip >> 16) & 0xFF),
                             (int)((pkt->src_ip >> 8) & 0xFF), (int)(pkt->src_ip & 0xFF),
                             (int)pkt->src_port, p->hostname);
                    /* Direct-path discovered but no WG session yet. Fire a one-shot
                     * handshake init via direct UDP, but rate-limit so a dropped or
                     * unanswered init gets another try every INITIAL_HANDSHAKE_RETRY_MS.
                     * The original implementation set a single boolean and gave up —
                     * any peer whose first init was lost stayed forever without a
                     * session even though subsequent direct PONGs kept arriving.
                     * We still clear peer->active right after GATEWAY_WG_CALL(wireguardif_connect())
                     * so the WG layer doesn't busy-loop retries at 5 s; the retry
                     * cadence comes from this DISCO PONG handler instead. */
                    #define INITIAL_HANDSHAKE_RETRY_MS 30000ULL
                    bool first_try = (p->last_init_handshake_ms == 0);
                    bool retry_due = !first_try &&
                                     (now - p->last_init_handshake_ms > INITIAL_HANDSHAKE_RETRY_MS);
                    if (first_try || retry_due) {
                        p->last_init_handshake_ms = now;
                        GATEWAY_WG_CALL(wireguardif_update_endpoint(netif, (u8_t)p->wg_peer_index,
                                                     &ep_ip, pkt->src_port));
                        GATEWAY_WG_CALL(wireguardif_connect(netif, (u8_t)p->wg_peer_index));
                        {
                            struct wireguard_device *dev = (struct wireguard_device *)netif->state;
                            struct wireguard_peer *wp = wireguard_device_peer(dev, (uint8_t)p->wg_peer_index);
                            if (wp) {
                                wp->active = false;
                            }
                        }
                        ESP_LOGI(TAG, "WG direct handshake %s to %s",
                                 first_try ? "init" : "retry", p->hostname);
                    }
                    #undef INITIAL_HANDSHAKE_RETRY_MS
                }
            }
        }

        ml->pending_probes[i].active = false;
        matched = true;
        break;
    }

    if (!matched) {
        /* Rate-limited for the same reason as the probe-table-full warning
         * above: a peer retrying eagerly against us produces a continuous
         * unmatched-pong stream, and logging every one of them starved the
         * task watchdog into a reboot loop (field-observed on the bench under
         * fire from one aggressive peer). The lookup work is also skipped
         * while suppressed — it only feeds the log line. */
        static uint64_t last_unmatched_log_ms = 0;
        static uint32_t unmatched_suppressed = 0;
        uint64_t now_ms = ml_get_time_ms();
        if (now_ms - last_unmatched_log_ms > 10000) {
            /* Find peer by disco key for logging */
            int peer_idx = directory_by_disco(ml, sender_disco_key);
            const char *name = peer_idx >= 0 ? ml->peers[peer_idx].hostname : "?";
            int active_count = 0;
            for (int i = 0; i < MAX_PENDING_PROBES; i++) {
                if (ml->pending_probes[i].active) active_count++;
            }
            ESP_LOGW(TAG, "DISCO PONG unmatched from %s (via %s) txid=%02x%02x%02x%02x, active_probes=%d"
                          " (%lu more suppressed in the last 10s)",
                     name, pkt->via_derp ? "DERP" : "direct",
                     txid[0], txid[1], txid[2], txid[3], active_count,
                     (unsigned long)unmatched_suppressed);
            last_unmatched_log_ms = now_ms;
            unmatched_suppressed = 0;
        } else {
            unmatched_suppressed++;
        }
    }
}

static void process_disco_packet(microlink_t *ml, const ml_rx_packet_t *pkt) {
    if (pkt->len < 62) return;  /* magic(6) + key(32) + nonce(24) = 62 minimum */

    /* Verify DISCO magic */
    if (memcmp(pkt->data, DISCO_MAGIC, 6) != 0) return;

    ESP_LOGD(TAG, "DISCO RX: %d bytes via %s, disco_key=%02x%02x%02x%02x",
             (int)pkt->len, pkt->via_derp ? "DERP" : "direct",
             pkt->data[6], pkt->data[7], pkt->data[8], pkt->data[9]);

    /* Extract sender's disco public key */
    const uint8_t *sender_disco_key = pkt->data + 6;

    /* Extract nonce */
    const uint8_t *nonce = pkt->data + 38;

    /* Decrypt ciphertext */
    const uint8_t *ciphertext = pkt->data + 62;
    size_t ciphertext_len = pkt->len - 62;

    if (ciphertext_len < NACL_BOX_MACBYTES) return;

    /* Identify the sender by its disco key (reference client:
     * discoInfoForKnownPeerLocked only for keys that belong to a peer). A key
     * that matches no peer -- a rotation the netmap has not delivered yet, or
     * a stranger -- is dropped. A directory peer that is not resident is only
     * activated after its box opens (directory_disco_admit): the key in the
     * packet is a claim, and activation costs a slot. */
    int sender_idx = directory_disco_admit(ml, sender_disco_key, nonce, ciphertext, ciphertext_len);
    if (sender_idx < 0) {
        static uint64_t last_unknown_log_ms = 0;
        static uint32_t unknown_suppressed = 0;
        uint64_t now_ms = ml_get_time_ms();
        if (now_ms - last_unknown_log_ms > 10000) {
            ESP_LOGD(TAG, "DISCO from unknown disco key %02x%02x%02x%02x... via %s dropped"
                          " (%lu more in the last 10 s)",
                     sender_disco_key[0], sender_disco_key[1],
                     sender_disco_key[2], sender_disco_key[3],
                     pkt->via_derp ? "DERP" : "direct", (unsigned long)unknown_suppressed);
            last_unknown_log_ms = now_ms;
            unknown_suppressed = 0;
        } else {
            unknown_suppressed++;
        }
        return;
    }
    const uint8_t *shared = disco_shared_key(ml, &ml->peers[sender_idx]);
    if (!shared) return;

    size_t plaintext_len = ciphertext_len - NACL_BOX_MACBYTES;
    uint8_t *plaintext = tdongle_heap_tag(TDONGLE_OWNER_OTHER, malloc(plaintext_len));
    if (!plaintext) return;

    if (nacl_box_open_afternm(plaintext, ciphertext, ciphertext_len, nonce, shared) != 0) {
        /* The sender is a known peer, so a MAC failure means OUR key material
         * for it is stale (#31); the prefix lets it be correlated externally. */
        ESP_LOGW(TAG, "DISCO decrypt failed (from %s via %s, disco_key=%02x%02x%02x%02x...)",
                 ml->peers[sender_idx].hostname,
                 pkt->via_derp ? "DERP" : "direct",
                 sender_disco_key[0], sender_disco_key[1],
                 sender_disco_key[2], sender_disco_key[3]);
        tdongle_heap_free(TDONGLE_OWNER_OTHER, plaintext);
        return;
    }

    if (plaintext_len < 2) {
        tdongle_heap_free(TDONGLE_OWNER_OTHER, plaintext);
        return;
    }

    uint8_t msg_type = plaintext[0];
    switch (msg_type) {
    case DISCO_MSG_PING:
        process_disco_ping(ml, pkt, sender_disco_key, plaintext, plaintext_len);
        break;
    case DISCO_MSG_PONG:
        process_disco_pong(ml, pkt, sender_disco_key, plaintext, plaintext_len);
        break;
    case DISCO_MSG_CALL_ME_MAYBE:
        {
            /* CallMeMaybe: after type(1)+version(1), payload is N x 18-byte entries
             * Each entry: 16-byte IP (IPv6 or IPv4-mapped) + 2-byte port (big-endian) */
            int peer_idx = directory_by_disco(ml, sender_disco_key);
            if (peer_idx < 0) {
                ESP_LOGW(TAG, "CallMeMaybe from unknown peer");
                break;
            }

            const uint8_t *ep_data = plaintext + 2;
            size_t ep_data_len = plaintext_len - 2;
            int ep_count = ep_data_len / 18;

            ESP_LOGD(TAG, "CallMeMaybe from %s: %d endpoints (udp_path=%d, at_sock=%d)",
                     ml->peers[peer_idx].hostname, ep_count,
                     disco_has_udp_path(ml), ml_at_socket_is_ready());

            /* No CallMeMaybe in reply. The reference client (magicsock
             * handleCallMeMaybe) only pings the endpoints it was given; it
             * sends its own CallMeMaybe when IT has traffic for us and no
             * trusted direct path. microlink used to echo one back, so two
             * microlink nodes without a WireGuard session bounced
             * CallMeMaybe -> ping burst -> CallMeMaybe between each other for
             * ever (esphome-tailscale#46: ~9 DISCO packets/s from one peer).
             * The peer learns our address from the source of the pings below
             * and from the PONGs we send to its own pings; we learn its from
             * the PONGs to our probes of its netmap endpoints.
             *
             * Per-peer floor on the burst: a well-behaved peer sends at most
             * one CallMeMaybe per heartbeat (3 s); faster than that is an
             * older microlink echoing ours, and every probe below costs an
             * X25519. A suppressed burst is simply dropped: the peer's next
             * CallMeMaybe or our next probe round covers it. */
            ml_peer_t *cp = &ml->peers[peer_idx];
            uint64_t cmm_now = ml_get_time_ms();
            bool burst_ok = (cp->last_cmm_rx_ms == 0) ||
                            (cmm_now - cp->last_cmm_rx_ms >= ML_DISCO_CMM_BURST_FLOOR_MS);
            if (burst_ok) {
                cp->last_cmm_rx_ms = cmm_now;
            } else {
                ESP_LOGD(TAG, "CallMeMaybe burst from %s suppressed (%llu ms after the previous one)",
                         cp->hostname, (unsigned long long)(cmm_now - cp->last_cmm_rx_ms));
            }

            /* Probe each endpoint with a DISCO ping.
             * Skip on cellular: direct UDP impossible, saves TX queue capacity. */
            for (int i = 0; !ml_at_socket_is_ready() && i < ep_count && i < ML_MAX_ENDPOINTS; i++) {
                const uint8_t *entry = ep_data + (i * 18);
                uint16_t port = (entry[16] << 8) | entry[17];

                /* Check for IPv4-mapped IPv6: ::ffff:A.B.C.D */
                bool is_v4_mapped = true;
                for (int j = 0; j < 10; j++) {
                    if (entry[j] != 0) { is_v4_mapped = false; break; }
                }
                if (entry[10] != 0xff || entry[11] != 0xff) is_v4_mapped = false;

                ESP_LOGD(TAG, "  CMM ep[%d]: v4mapped=%d port=%d bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                         i, is_v4_mapped, port,
                         entry[0], entry[1], entry[2], entry[3],
                         entry[4], entry[5], entry[6], entry[7],
                         entry[8], entry[9], entry[10], entry[11],
                         entry[12], entry[13], entry[14], entry[15]);

                if (!is_v4_mapped || port == 0) continue;

                uint32_t ip = ((uint32_t)entry[12] << 24) |
                              ((uint32_t)entry[13] << 16) |
                              ((uint32_t)entry[14] << 8) |
                              (uint32_t)entry[15];

                if (!burst_ok) continue;

                /* Send DISCO ping to this endpoint */
                if (disco_has_udp_path(ml)) {
                    uint8_t ping_pkt[256];
                    size_t ping_len = 0;
                    disco_build_ping(ml, peer_idx, ping_pkt, &ping_len);

                    if (ping_len > 0) {
                        int ret = disco_udp_sendto(ml, ping_pkt, ping_len, ip, port);
                        ESP_LOGD(TAG, "CMM probe -> %d.%d.%d.%d:%d (%d bytes, ret=%d)",
                                 (int)((ip >> 24) & 0xFF), (int)((ip >> 16) & 0xFF),
                                 (int)((ip >> 8) & 0xFF), (int)(ip & 0xFF),
                                 (int)port, (int)ping_len, ret);
                    }
                } else {
                    ESP_LOGW(TAG, "CMM probe skipped: no UDP path (sock4=%d)", ml->disco_sock4);
                }
            }

            /* Also force-ping peer's known endpoints from MapResponse */
            if (burst_ok) {
                disco_send_ping_to_peer(ml, peer_idx, true);
            }
        }
        break;
    default:
        ESP_LOGW(TAG, "Unknown DISCO message type: 0x%02x", msg_type);
        break;
    }

    tdongle_heap_free(TDONGLE_OWNER_OTHER, plaintext);
    /* pkt->data is freed by the caller */
}

/* ============================================================================
 * WireGuard Packet Processing
 * ========================================================================== */

static esp_err_t wg_init_interface(microlink_t *ml) {
    LOCK_TCPIP_CORE();
    esp_err_t result = wg_init_interface_impl(ml);
    UNLOCK_TCPIP_CORE();
    return result;
}

/* Counters of the WireGuard receive path, for the serial `inbound` report (ml_rx_stats.h). */
unsigned ml_wg_rx_stat_count(void) { return WG_RXS_COUNT; }
uint32_t ml_wg_rx_stat(unsigned which) { return wireguard_rx_stat_get(which); }
const char *ml_wg_rx_stat_name(unsigned which) { return wireguard_rx_stat_name(which); }
unsigned ml_wg_replay_window(void) { return WIREGUARD_REPLAY_WINDOW_SIZE; }
unsigned ml_wg_rx_batch_size(void) { return ML_WG_RX_BATCH; }

/* ----------------------------------------------------------------------------
 * Inbound runs (ADR 0020)
 *
 * The drain below takes datagrams off wg_rx_queue, stages up to ML_WG_RX_BATCH of them (everything that used to precede the call
 * into wireguardif: the DERP sender check, the interface check, and wrapping the heap block the datagram already lives in as a
 * pbuf, with no allocation and no copy), then hands the run to ml_wg_rx_run (ml_wg_rx_batch.h): begin under ONE core-lock hold,
 * decrypt in place with the lock released, complete under ONE hold, then the router with the lock released. A message that is
 * not transport data (a handshake, a cookie) is never staged behind data: the data before it is finished first, then it is
 * processed alone, so state it changes is seen by later datagrams exactly as in the one-datagram path.
 *
 * Single consumer: everything here is touched by the wg_mgr task only (statics, not stack: the jobs array is ~800 B). */
typedef struct { struct pbuf_custom pc; uint8_t *data; } wg_rx_wrap_t;   /* pc first: the free callback receives the pbuf */
typedef struct { int sender; uint32_t sender_activity; bool keepalive_only; } wg_rx_meta_t;
static wg_rx_wrap_t g_rx_wrap[ML_WG_RX_BATCH];
static ml_wg_rx_item_t g_rx_items[ML_WG_RX_BATCH];
static struct wireguard_rx_job g_rx_jobs[ML_WG_RX_BATCH];
static wg_rx_meta_t g_rx_meta[ML_WG_RX_BATCH];
static unsigned g_rx_n;
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
static uint32_t g_rx_t0, g_rx_prep_cycles;
#endif

/* The pbuf wrapping a datagram frees the datagram's heap block with it, wherever the last reference goes (complete on a drop, the
 * router when it consumes the packet, wireguardif when the router refuses it). */
static void wg_rx_wrap_free(struct pbuf *p) {
    wg_rx_wrap_t *w = (wg_rx_wrap_t *)p;
    tdongle_heap_free(TDONGLE_OWNER_PACKET, w->data);
    w->data = NULL;
}

/* The core lock around a run's begin and complete, timed into the diagnostics ledger by the same sites as before. */
typedef struct {
    int64_t hold_start;
    uint32_t member;      /* diagnostic_id of the membership whose run this is (boot-health route marks) */
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
    uint32_t stamp;
#endif
} wg_rx_lk_t;
static wg_rx_lk_t g_rx_lk;
static void wg_rx_lock(void *ctx, unsigned site) {
    wg_rx_lk_t *l = ctx;
    (void)site;
    WGPERF_T(t);
    LOCK_TCPIP_CORE();
    WGPERF_LAP(t, lock_wait);
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
    l->stamp = t;
#endif
    l->hold_start = tdongle_lock_clock();
#ifdef ESP_PLATFORM
    gateway_route_mark(5, l->member);
#endif
}
static void wg_rx_unlock(void *ctx, unsigned site) {
    wg_rx_lk_t *l = ctx;
#ifdef ESP_PLATFORM
    gateway_route_mark(0, 0);
#endif
    tdongle_lock_hold(site == ML_WG_RX_SITE_COMMIT ? TDONGLE_LOCK_WG_COMMIT : TDONGLE_LOCK_WG_OTHER, (uint32_t)(tdongle_lock_clock() - l->hold_start));
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
    WGPERF_ADD(lock_hold, TDONGLE_WGPERF_CYCLES() - l->stamp);
#endif
    UNLOCK_TCPIP_CORE();
}
static const ml_wg_rx_lock_t g_rx_lock_ops = { wg_rx_lock, wg_rx_unlock, &g_rx_lk };

/* Is this popped datagram transport data (the only thing that is batched)? Same test wireguardif applies. */
static bool wg_rx_pkt_is_data(const ml_rx_packet_t *pkt) {
    return pkt->len >= sizeof(struct message_transport_data) + WIREGUARD_AUTHTAG_LEN && pkt->data[0] == MESSAGE_TRANSPORT_DATA &&
           pkt->data[1] == 0 && pkt->data[2] == 0 && pkt->data[3] == 0;
}

/* Stage one datagram into the run being built. Takes ownership of pkt->data: false = it was dropped (counted) and freed. */
static bool wg_rx_stage(microlink_t *ml, const ml_rx_packet_t *pkt) {
    WGPERF_T(t);
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
    if (!g_rx_n) { g_rx_t0 = t; g_rx_prep_cycles = 0; }
#endif
    WGPERF_COUNT(in_pkts, 1);
    ML_RX_STAT(wg_in);
    /* Handshake and cookie messages are logged; transport data (type 4, one per ACK or download segment) is not. */
    if (!(pkt->len >= 4 && pkt->data[0] == 0x04))
        ESP_LOGI(TAG, "WG RX: %d bytes, via_derp=%d, type=%d, from=%02x%02x%02x%02x",
                 (int)pkt->len, pkt->via_derp,
                 pkt->len >= 4 ? pkt->data[0] : -1,
                 pkt->src_pubkey[0], pkt->src_pubkey[1], pkt->src_pubkey[2], pkt->src_pubkey[3]);
    wg_rx_meta_t meta = { .sender = -1, .sender_activity = 0, .keepalive_only = false };
#ifdef ESP_PLATFORM
    if(pkt->via_derp) {
        /* The DERP source key is the relay's claim, not proof. A resident peer
         * is simply that peer. Otherwise only a WireGuard initiation can start
         * a session, so anything else from an unknown key is dropped before it
         * costs a flash read; an initiation gets a trial slot (see
         * directory_trial_*), kept only if WireGuard authenticates it. */
        meta.sender=derp_sender_admit(ml,pkt);
        if(meta.sender<0){ML_RX_STAT(wg_sender_unknown);tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt->data);return false;}
        /* The packet only counts as the peer's activity if WireGuard accepts it. */
        meta.sender_activity=wg_peer_activity(ml,meta.sender);
    }
#endif
    if (!ml->wg_netif) {
        ML_RX_STAT(wg_no_netif);
        tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt->data);
        return false;
    }
    struct netif *netif = (struct netif *)ml->wg_netif;
    if (!netif->state) {
        ML_RX_STAT(wg_no_netif);
        tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt->data);
        return false;
    }
    if (pkt->len > UINT16_MAX) {
        ML_RX_STAT(wg_pbuf_fail);
        tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt->data);
        return false;
    }
    /* The datagram stays where net_io (or the DERP loop) put it: a custom pbuf over that heap block, whose free callback releases
     * the block. wireguardif decrypts it in place and the router reads the same bytes, so there is no second buffer and no copy
     * (the pbuf used to be allocated and filled here, 21k cycles per datagram in wgperf `rx_prep`). */
    wg_rx_wrap_t *w = &g_rx_wrap[g_rx_n];
    struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, (u16_t)pkt->len, PBUF_REF, &w->pc, pkt->data, (u16_t)pkt->len);
    if (!p) {
        ML_RX_STAT(wg_pbuf_fail);
        tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt->data);
        return false;
    }
    w->pc.custom_free_function = wg_rx_wrap_free;
    w->data = pkt->data;
    /* A keepalive (transport data, empty plaintext: 16-byte header + 16-byte tag) is processed like any authenticated message
     * (endpoint, timers, keypair confirmation) but, as before it was decrypted at all, is not "use" of the peer for residency:
     * a peer's idle PersistentKeepalive must not keep its slot from eviction (directory_activate_idle). */
    meta.keepalive_only = pkt->len == 32 && pkt->data[0] == 0x04;
    ml_wg_rx_item_t *it = &g_rx_items[g_rx_n];
    it->p = p;
    it->port = pkt->src_port;
    if (pkt->via_derp) {
        ip_addr_set_any(false, &it->addr);
    } else {
        IP_SET_TYPE_VAL(it->addr, IPADDR_TYPE_V4);
        ip4_addr_set_u32(ip_2_ip4(&it->addr), htonl(pkt->src_ip));
    }
    g_rx_meta[g_rx_n] = meta;
    g_rx_n++;
    ML_RX_STAT(wg_to_wireguardif);
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
    g_rx_prep_cycles += TDONGLE_WGPERF_CYCLES() - t;
#endif
    return true;
}

/* Process the staged run and do, per datagram, what process_wg_packet did after it. */
static void wg_rx_flush(microlink_t *ml) {
    if (!g_rx_n) return;
    const unsigned n = g_rx_n;
    g_rx_n = 0;
    WGPERF_ADD(rx_prep, g_rx_prep_cycles);
    /* wireguardif_rx_begin_ex frees the datagram of anything it does not decrypt, so after the run nothing is owned here. */
    g_rx_lk.member = ml->config.diagnostic_id;
    ml_wg_rx_run((struct netif *)ml->wg_netif, g_rx_items, n, g_rx_jobs, &g_rx_lock_ops);
#ifdef ESP_PLATFORM
    for (unsigned i = 0; i < n; i++) {
        if (g_rx_meta[i].sender >= 0 && !g_rx_meta[i].keepalive_only && wg_peer_activity(ml, g_rx_meta[i].sender) != g_rx_meta[i].sender_activity)
            ml->peers[g_rx_meta[i].sender].jit_used_ms = ml_get_time_ms();
    }
    directory_trial_poll(ml);
#endif
    WGPERF_CHARGE(g_rx_t0, rx_pkt);
}

/* One datagram popped off wg_rx_queue: account the bytes the queue no longer holds. */
static bool wg_rx_pop(microlink_t *ml, ml_rx_packet_t *pkt) {
    if (xQueueReceive(ml->wg_rx_queue, pkt, 0) != pdTRUE) return false;
    ml_wgrx_release((unsigned)pkt->len);
    return true;
}

/* ============================================================================
 * SendCallMeMaybe (client-initiated NAT traversal)
 *
 * Sends our local endpoints (LAN + STUN) to a peer via DERP, telling them
 * "connect to me at these addresses". Peer will then initiate WireGuard
 * handshakes to each endpoint, bypassing NAT asymmetry.
 *
 * Reference: tailscale/wgengine/magicsock/magicsock.go (sendCallMeMaybe)
 * ========================================================================== */

static void disco_send_call_me_maybe(microlink_t *ml, int peer_idx) {
    ml_peer_t *p = &ml->peers[peer_idx];

    /* Build plaintext: [type(1)][version(1)][endpoints(N * 18)] */
    uint8_t plaintext[2 + 3 * 18];  /* Up to 3 endpoints */
    int pt_len = 0;
    int ep_count = 0;

    plaintext[pt_len++] = DISCO_MSG_CALL_ME_MAYBE;
    plaintext[pt_len++] = 0;  /* version */

    /* 1. Local LAN IP endpoint (critical for same-network peers) */
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            uint32_t local_ip = ntohl(ip_info.ip.addr);
            uint16_t local_port = ml->disco_local_port;

            if (local_port > 0) {
                /* IPv6-mapped IPv4: ::ffff:A.B.C.D */
                memset(plaintext + pt_len, 0, 10); pt_len += 10;
                plaintext[pt_len++] = 0xff;
                plaintext[pt_len++] = 0xff;
                plaintext[pt_len++] = (local_ip >> 24) & 0xFF;
                plaintext[pt_len++] = (local_ip >> 16) & 0xFF;
                plaintext[pt_len++] = (local_ip >> 8) & 0xFF;
                plaintext[pt_len++] = local_ip & 0xFF;
                plaintext[pt_len++] = (local_port >> 8) & 0xFF;
                plaintext[pt_len++] = local_port & 0xFF;
                ep_count++;

                ESP_LOGD(TAG, "CMM endpoint: LAN %lu.%lu.%lu.%lu:%u",
                         (unsigned long)((local_ip >> 24) & 0xFF),
                         (unsigned long)((local_ip >> 16) & 0xFF),
                         (unsigned long)((local_ip >> 8) & 0xFF),
                         (unsigned long)(local_ip & 0xFF), local_port);
            }
        }
    }

    /* 2. STUN public endpoint (for cross-NAT peers) */
    if (ml->stun_public_ip != 0) {
        uint32_t pub_ip = ml->stun_public_ip;
        uint16_t pub_port = (ml->stun_public_port != 0) ? ml->stun_public_port : ml->disco_local_port;

        memset(plaintext + pt_len, 0, 10); pt_len += 10;
        plaintext[pt_len++] = 0xff;
        plaintext[pt_len++] = 0xff;
        plaintext[pt_len++] = (pub_ip >> 24) & 0xFF;
        plaintext[pt_len++] = (pub_ip >> 16) & 0xFF;
        plaintext[pt_len++] = (pub_ip >> 8) & 0xFF;
        plaintext[pt_len++] = pub_ip & 0xFF;
        plaintext[pt_len++] = (pub_port >> 8) & 0xFF;
        plaintext[pt_len++] = pub_port & 0xFF;
        ep_count++;

        ESP_LOGD(TAG, "CMM endpoint: STUN %lu.%lu.%lu.%lu:%u",
                 (unsigned long)((pub_ip >> 24) & 0xFF),
                 (unsigned long)((pub_ip >> 16) & 0xFF),
                 (unsigned long)((pub_ip >> 8) & 0xFF),
                 (unsigned long)(pub_ip & 0xFF), pub_port);
    }

    if (ep_count == 0) {
        ESP_LOGW(TAG, "CMM: no endpoints available for %s", p->hostname);
        return;
    }

    /* Encrypt with NaCl box */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, DISCO_NONCE_LEN);

    uint8_t ciphertext[sizeof(plaintext) + NACL_BOX_MACBYTES];
    const uint8_t *shared = disco_shared_key(ml, p);
    if (!shared) return;
    nacl_box_afternm(ciphertext, plaintext, pt_len, nonce, shared);

    /* Build packet: magic(6) + disco_pubkey(32) + nonce(24) + ciphertext */
    uint8_t pkt[256];
    size_t pos = 0;
    memcpy(pkt + pos, DISCO_MAGIC, 6); pos += 6;
    memcpy(pkt + pos, ml->disco_public_key, 32); pos += 32;
    memcpy(pkt + pos, nonce, DISCO_NONCE_LEN); pos += DISCO_NONCE_LEN;
    size_t ct_len = pt_len + NACL_BOX_MACBYTES;
    memcpy(pkt + pos, ciphertext, ct_len); pos += ct_len;

    /* Send via DERP */
    esp_err_t err = ml_derp_queue_send(ml, p->public_key, pkt, pos);
    if (err == ESP_OK) {
        ESP_LOGD(TAG, "CallMeMaybe sent to %s (%d endpoints)", p->hostname, ep_count);
    } else {
        ESP_LOGW(TAG, "CallMeMaybe send failed for %s: %d", p->hostname, err);
    }
}

/* Public wrapper for UDP API to trigger CallMeMaybe.
 * Skip on cellular: our endpoints are behind CGNAT and unreachable. */
void ml_wg_mgr_send_cmm(microlink_t *ml, uint32_t peer_vpn_ip) {
    if (ml_at_socket_is_ready()) return;  /* cellular: CMM useless */
    int idx = find_peer_by_ip(ml, peer_vpn_ip);
    if (idx >= 0) {
        disco_send_call_me_maybe(ml, idx);
    }
}

/* On-demand WG handshake trigger (called from TCP/UDP API when session needed).
 *
 * Dual-path strategy:
 * 1. DERP: Always send via DERP relay (reliable, works through all NATs)
 * 2. Direct: If DISCO has discovered a direct endpoint, ALSO send the
 *    handshake init directly to the peer's UDP port. This is critical
 *    because the direct path hits magicsock's receiveIPv4() handler which
 *    calls noteRecvActivity() → maybeReconfigWireguardLocked() to re-add
 *    trimmed peers to wireguard-go. The DERP path alone does NOT trigger
 *    this re-add for WG handshake packets, so idle peers silently drop
 *    DERP-only handshake inits.
 *
 * The direct handshake arrives at the peer's magicsock UDP socket, wakes
 * the lazy peer, and wireguard-go processes the init and responds. */
esp_err_t ml_wg_mgr_trigger_handshake(microlink_t *ml, uint32_t dest_vpn_ip) {
    if (!ml || !ml->wg_netif) return ESP_ERR_INVALID_STATE;

    int idx = find_peer_by_ip(ml, dest_vpn_ip);
    if (idx < 0) return ESP_ERR_NOT_FOUND;

    ml_peer_t *p = &ml->peers[idx];
    if (p->wg_peer_index < 0) return ESP_ERR_INVALID_STATE;

    struct netif *netif = (struct netif *)ml->wg_netif;

    /* Don't destroy an existing valid session */
    err_t is_up = wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index, NULL, NULL);
    if (is_up == ERR_OK) return ESP_OK;

    /* Path 1: DERP (reliable fallback) */
    GATEWAY_WG_CALL(wireguardif_connect_derp(netif, (u8_t)p->wg_peer_index));
    ESP_LOGW(TAG, "WG handshake triggered (DERP) to %s", p->hostname);

    /* Path 2: Direct UDP (if DISCO has a known endpoint).
     * This wakes the peer's magicsock via receiveIPv4 → noteRecvActivity.
     * Set connect_ip first, then call wireguardif_connect which copies
     * connect_ip → ip and starts a second handshake to the direct endpoint. */
    if (p->best_ip != 0 && p->best_port != 0) {
        ip_addr_t ep_ip;
        IP_SET_TYPE_VAL(ep_ip, IPADDR_TYPE_V4);
        ip4_addr_set_u32(ip_2_ip4(&ep_ip), htonl(p->best_ip));
        GATEWAY_WG_CALL(wireguardif_update_endpoint(netif, (u8_t)p->wg_peer_index,
                                     &ep_ip, p->best_port));
        GATEWAY_WG_CALL(wireguardif_connect(netif, (u8_t)p->wg_peer_index));
        ESP_LOGW(TAG, "WG handshake triggered (direct) to %s at %d.%d.%d.%d:%d",
                 p->hostname,
                 (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                 (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
                 (int)p->best_port);
    }

    return ESP_OK;
}

bool ml_wg_mgr_peer_is_up(microlink_t *ml, uint32_t vpn_ip) {
    if (!ml || !ml->wg_netif) return false;
    int idx = find_peer_by_ip(ml, vpn_ip);
    if (idx < 0) return false;
    ml_peer_t *p = &ml->peers[idx];
    if (p->wg_peer_index < 0) return false;
    struct netif *netif = (struct netif *)ml->wg_netif;
    ip_addr_t cur_ip;
    u16_t cur_port;
    bool up = wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index, &cur_ip, &cur_port) == ERR_OK;
    if (up) {
        /* Verify WG internal peer key matches our DISCO peer */
        struct wireguard_device *dev = (struct wireguard_device *)netif->state;
        struct wireguard_peer *wp = wireguard_device_peer(dev, (uint8_t)p->wg_peer_index);
        if (wp) {
            bool key_match = (memcmp(wp->public_key, p->public_key, 32) == 0);
            ESP_LOGI(TAG, "WG peer UP: %s wg_idx=%d ep=%s:%u key=%02x%02x%02x%02x %s",
                     p->hostname, p->wg_peer_index,
                     ip_addr_isany(&cur_ip) ? "DERP" : ipaddr_ntoa(&cur_ip),
                     cur_port,
                     wp->public_key[0], wp->public_key[1],
                     wp->public_key[2], wp->public_key[3],
                     key_match ? "KEY_OK" : "KEY_MISMATCH!");
        }
    }
    return up;
}

/* ============================================================================
 * Periodic DISCO probing (rate-limited per tailscaled timing)
 * ========================================================================== */

/* Max upgrade probes per call to spread DISCO load across ticks.
 * With 16 allowed peers: full probe cycle = 8 ticks × 1s = 8s,
 * well within the 15s upgrade interval. */
#define DISCO_PROBES_PER_TICK 2



static void disco_periodic_probes(microlink_t *ml) {
    uint64_t now = ml_get_time_ms();
    int upgrade_probes_sent = 0;

    /* Rotate start index so we don't always process peers in the same order */
    int start = ml->disco_probe_start_idx;
    if (start >= ml->peer_count) start = 0;

    for (int n = 0; n < ml->peer_count; n++) {
        int i = (start + n) % ml->peer_count;
        ml_peer_t *p = &ml->peers[i];
        if (!p->active) continue;

        /* Peer allowlist filter: check early so we can skip expensive work.
         * Inbound DISCO pings from any peer are still answered (don't break remote). */
        bool peer_allowed = ml_config_peer_is_allowed(
            ml->config_httpd, p->vpn_ip);

        /* Check if direct path trust has expired (always runs, not throttled).
         *
         * Throughput-collapse fix (2026-05-24): the old code unconditionally
         * called GATEWAY_WG_CALL(wireguardif_connect_derp()) on trust-expiry, which ZEROES
         * peer->ip:port. Under heavy AP+STA radio contention (phone
         * speedtest), DISCO PINGs starve much sooner than the encrypted
         * WG data path. All 3-4 active peers' direct paths "expired" at
         * the same time even though encrypted data was still flowing on
         * the direct UDP endpoint. They were all forced onto the single
         * shared DERP TCP socket, whose send queue immediately overflowed
         * (ERR_WOULDBLOCK), and the speedtest TCP collapsed and stayed
         * collapsed because the back-off never recovered.
         *
         * New policy:
         *   1. Read peer->last_rx from the WG layer to see if encrypted
         *      data is still flowing on the direct endpoint.
         *   2. If data IS flowing (last_rx < 30 s old), KEEP the direct
         *      endpoint intact — only clear has_direct_path so the upgrade
         *      probe re-fires, and burst 3 DISCO PINGs to recover trust.
         *   3. If data is ALSO stale, then the path really is dead and the
         *      old behaviour (zero endpoint + DERP handshake) is correct.
         */
        if (p->has_direct_path && now > p->trust_until_ms) {
            /* Look up WG-side last_rx age before deciding. */
            uint32_t last_rx_age_ms = 0xFFFFFFFF;
            if (ml->wg_netif && p->wg_peer_index >= 0 &&
                p->wg_peer_index < WIREGUARD_MAX_PEERS) {
                struct netif *netif = (struct netif *)ml->wg_netif;
                struct wireguard_device *dev = (struct wireguard_device *)netif->state;
                struct wireguard_peer *wp = wireguard_device_peer(dev, (uint8_t)p->wg_peer_index);
                if (wp) {
                    if (wp->last_rx) {
                        uint32_t now_wg = wireguard_sys_now();
                        uint32_t age = now_wg - wp->last_rx;
                        /* Saturate against the unsigned wrap that fires
                         * when last_rx is updated mid-read. */
                        last_rx_age_ms = (age > 0x7FFFFFFFu) ? 0 : age;
                    }
                }
            }

            bool data_flowing = (last_rx_age_ms < 30000);

            p->has_direct_path = false;

            if (peer_allowed) {
                if (data_flowing) {
                    /* PINGs stale but data alive — KEEP the direct endpoint.
                     * Don't call GATEWAY_WG_CALL(wireguardif_connect_derp()): zeroing peer->ip
                     * here is the exact pessimisation that caused the
                     * throughput collapse. Send ONE re-probe (the 3-burst
                     * earlier version cost ~5 ms ChaCha20-Poly1305 per PING
                     * and with 11 peers triggering at the same tick blocked
                     * disco_periodic_probes for 280+ ms — that was the
                     * remaining stutter source the operator was seeing). */
                    ESP_LOGI(TAG, "Direct path PING-stale for %s but data flowing "
                                  "(last_rx=%ums) - keeping endpoint, single PING",
                             p->hostname, (unsigned)last_rx_age_ms);
                    if (!ml_at_socket_is_ready()) {
                        disco_send_ping_to_peer(ml, i, true);
                    }
                } else {
                    /* Encrypted data ALSO stopped — the direct path is really
                     * dead. Fall back to DERP. */
                    bool session_up = false;
                    if (ml->wg_netif && p->wg_peer_index >= 0) {
                        struct netif *netif = (struct netif *)ml->wg_netif;
                        session_up = (wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index,
                                                             NULL, NULL) == ERR_OK);
                        if (session_up) {
                            ESP_LOGI(TAG, "Direct path to %s expired (last_rx=%ums), "
                                          "reverting to DERP", p->hostname,
                                     (unsigned)last_rx_age_ms);
                            GATEWAY_WG_CALL(wireguardif_connect_derp(netif, (u8_t)p->wg_peer_index));
                            ESP_LOGI(TAG, "  WG session active, falling back to DERP for %s", p->hostname);
                        }
                    }
                    if (!session_up) {
                        /* No WireGuard session behind this path, nothing to
                         * fall back: this is the once-a-minute re-probe of a
                         * session-less peer (see the heartbeat gate below). */
                        ESP_LOGD(TAG, "Direct path to %s (no WG session): re-probe after %u s",
                                 p->hostname, (unsigned)(ML_DISCO_TRUST_DURATION_MS / 1000));
                    }
                    /* One force-ping to try re-establishing direct path. */
                    if (!ml_at_socket_is_ready()) {
                        disco_send_ping_to_peer(ml, i, true);
                    }
                }
            }
        }

        if (!peer_allowed) continue;

        /* Phase 1.5g / 1.9h — DERP-only fallback with periodic retry.
         * For peers with no direct UDP path (hairpin NAT, VLAN isolation),
         * we have to actively fire the WG handshake over DERP — they will
         * never INITIATE against us first. The original 1.5g logic was
         * single-shot, so a peer whose first INIT was dropped stayed
         * forever in `WG peer ready (passive)`. Now we retry every 30 s
         * until wireguardif_peer_is_up() reports the session is up.
         * Skips peers with a direct PONG (those use the regular endpoint
         * upgrade path), and clears the retry flag in process_disco_pong()
         * when a direct PONG eventually wins. */
        /* (2026-05-30) Gate on the WireGuard DATA plane (up != ERR_OK), NOT
         * the DISCO control-plane has_direct_path latch. A peer whose DISCO
         * PONGs keep arriving (has_direct_path stays true, trust_until_ms
         * re-armed every <60 s) but whose encrypted WG handshake never
         * completes (lastrx=never, hs_attempts climbing) was previously
         * skipped here forever — that is the exit-node-after-roam/reboot
         * wedge that black-holed all AP-client internet (direct=1, derp_fb=0,
         * lastrx=never). A healthy direct peer has a valid keypair
         * (up == ERR_OK) so it never enters this block; the 2026-05-24
         * throughput case (keypair valid, DISCO pings starved) is likewise
         * untouched. The 30 s attempt cadence is uniform so PONGs that clear
         * derp_fallback_active can't make us re-fire faster than every 30 s. */
        if (p->wg_peer_index >= 0 && ml->wg_netif && p->online &&
            now - p->peer_added_ms > 30000) {
            struct netif *netif = (struct netif *)ml->wg_netif;
            err_t up = wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index,
                                                NULL, NULL);
            bool first_attempt = !p->derp_fallback_active;
            bool attempt_due = (p->last_derp_attempt_ms == 0) ||
                               (now - p->last_derp_attempt_ms > 30000);
            if (up != ERR_OK && attempt_due) {
                GATEWAY_WG_CALL(wireguardif_connect_derp(netif, (u8_t)p->wg_peer_index));
                p->derp_fallback_active = true;
                p->last_derp_attempt_ms = now;
                ESP_LOGW(TAG, "DERP handshake %s -> %s (no WG session in %llus)",
                         first_attempt ? "init" : "retry",
                         p->hostname,
                         (unsigned long long)((now - p->peer_added_ms) / 1000));
            }
        }

        /* Probe for direct path upgrade (every UPGRADE_INTERVAL when on DERP).
         * Skip on cellular: direct paths impossible through carrier-grade NAT.
         * Throttled to DISCO_PROBES_PER_TICK to spread load and reduce jitter. */
        /* ... and not toward a peer the netmap marks offline: nobody answers,
         * each probe still costs an X25519 plus a DERP send, and on a
         * 13-peer router with 8 of them offline that alone kept every
         * 1 s tick above the 30 ms SLOW mark. p->online is the netmap
         * Node.Online tri-state (unknown => true), so this only skips peers
         * the control plane has explicitly reported offline; the next
         * PeersChanged delta that flips them back re-enables probing. */
        if (!ml_at_socket_is_ready() && !p->has_direct_path && p->online &&
            now - p->last_upgrade_ms > ML_DISCO_UPGRADE_INTERVAL_MS) {
            if (upgrade_probes_sent < DISCO_PROBES_PER_TICK) {
                disco_send_ping_to_peer(ml, i, false);
                p->last_upgrade_ms = now;
                upgrade_probes_sent++;
            }
        }

        /* Heartbeat on active direct paths (every HEARTBEAT interval).
         * MUST use force=true because HEARTBEAT_MS (3s) < PING_INTERVAL_MS (5s),
         * so the rate limiter would always block heartbeat pings.
         * Heartbeats are NEVER throttled — they're time-critical for trust_until_ms.
         *
         * Only behind a WireGuard session, though. The reference client
         * heartbeats a peer only while it has traffic for it
         * (sessionActiveTimeout) and sends an idle one nothing; here the
         * heartbeat protects the single data-plane endpoint of a live session,
         * so it runs for as long as the session does, but a peer that never
         * completed a handshake gets no heartbeat at all -- its address is
         * refreshed once a minute by the trust-expiry re-probe above. Before
         * this gate every session-less peer was pinged every 3 s for ever
         * (esphome-tailscale#46, direction 3). */
        if (p->has_direct_path &&
            now - p->last_ping_sent_ms > ml->t_disco_heartbeat_ms) {
            bool session_up = false;
            if (ml->wg_netif && p->wg_peer_index >= 0) {
                session_up = (wireguardif_peer_is_up((struct netif *)ml->wg_netif,
                                                     (u8_t)p->wg_peer_index, NULL, NULL) == ERR_OK);
            }
            if (session_up) {
                disco_send_ping_to_peer(ml, i, true);
            }
        }
    }

    /* Advance rotating start index for next call */
    ml->disco_probe_start_idx = (start + DISCO_PROBES_PER_TICK) % (ml->peer_count > 0 ? ml->peer_count : 1);

    /* Expire old pending probes.
     * MUST refresh 'now' because disco_send_ping_to_peer() above may have
     * registered probes with sent_ms NEWER than our stale 'now' from the top
     * of this function. Without refresh, now - sent_ms underflows to ~UINT64_MAX
     * which is always > PING_TIMEOUT_MS, causing immediate false expiry. */
    now = ml_get_time_ms();
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (ml->pending_probes[i].active &&
            now - ml->pending_probes[i].sent_ms > ML_DISCO_PING_TIMEOUT_MS) {
            ml->pending_probes[i].active = false;
        }
    }
}

/* ============================================================================
 * Throughput-collapse diagnostics — periodic state snapshot
 *
 * Logged every 10 s while the wg_mgr loop runs. Captures the full per-peer
 * WG session state plus the DISCO probe-pool depth so we can correlate the
 * 2-minute throughput collapse against rekey events, keypair destruction,
 * endpoint drift, and probe leakage.
 *
 * Output format is a single ESP_LOGW line per peer (greppable with [WG_SNAP])
 * and one summary line ([WG_SNAP_SUM]). Keep field order stable across
 * commits — the operator analyses logs by column position.
 * ========================================================================== */
static void dump_wg_state_snapshot(microlink_t *ml) {
    if (!ml || !ml->wg_netif) return;
    struct netif *netif = (struct netif *)ml->wg_netif;
    struct wireguard_device *dev = (struct wireguard_device *)netif->state;
    if (!dev) return;

    uint64_t now_ms = ml_get_time_ms();
    uint32_t now_wg = wireguard_sys_now();

    int active_probes = 0;
    uint64_t oldest_probe_age_ms = 0;
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (!ml->pending_probes[i].active) continue;
        active_probes++;
        uint64_t age = now_ms - ml->pending_probes[i].sent_ms;
        if (age > oldest_probe_age_ms) oldest_probe_age_ms = age;
    }

    int linkup_peers = 0;
    for (int i = 0; i < ml->peer_count; i++) {
        ml_peer_t *p = &ml->peers[i];
        if (!p->active) continue;
        int wgi = p->wg_peer_index;
        if (wgi < 0 || wgi >= WIREGUARD_MAX_PEERS) continue;
        struct wireguard_peer *wp = wireguard_device_peer(dev, (uint8_t)wgi);
        if (!wp) continue;

        /* Saturate wrap-around: WG-side timestamps can be updated in the
         * gap between our now_wg sample and the per-peer read, producing
         * a subtraction that wraps to 4294967xxx ms. Anything > INT32_MAX
         * is really "just happened". */
        #define SAT_AGE(ts) ((ts) ? \
            (((uint32_t)(now_wg - (ts)) > 0x7FFFFFFFu) ? 0 : (uint32_t)(now_wg - (ts))) \
            : 0xFFFFFFFF)
        uint32_t last_rx_age = SAT_AGE(wp->last_rx);
        uint32_t last_tx_age = SAT_AGE(wp->last_tx);
        uint32_t last_init_age = SAT_AGE(wp->last_initiation_tx);
        uint32_t curr_age = wp->curr_keypair.valid ? SAT_AGE(wp->curr_keypair.keypair_millis) : 0xFFFFFFFF;
        uint32_t prev_age = wp->prev_keypair.valid ? SAT_AGE(wp->prev_keypair.keypair_millis) : 0xFFFFFFFF;
        #undef SAT_AGE

        if (wp->curr_keypair.valid || wp->prev_keypair.valid) linkup_peers++;

        uint32_t ep_ip_u32 = ip_addr_isany(&wp->ip) ? 0 : ip4_addr_get_u32(ip_2_ip4(&wp->ip));
        uint64_t last_pong_age = p->last_pong_recv_ms ? (now_ms - p->last_pong_recv_ms) : 0;

        ESP_LOGW(TAG,
            "[WG_SNAP] %s wgi=%d ep=%u.%u.%u.%u:%u "
            "curr=%c(age=%lums cnt=%lu) prev=%c(age=%lums) "
            "lastrx=%lums lasttx=%lums lastinit=%lums "
            "send_hs=%d hs_attempts=%u "
            "direct=%d derp_fb=%d pong_age=%llums",
            p->hostname, wgi,
            (unsigned)((ep_ip_u32 >> 0) & 0xFF), (unsigned)((ep_ip_u32 >> 8) & 0xFF),
            (unsigned)((ep_ip_u32 >> 16) & 0xFF), (unsigned)((ep_ip_u32 >> 24) & 0xFF),
            (unsigned)wp->port,
            wp->curr_keypair.valid ? 'Y' : 'N', (unsigned long)curr_age,
            (unsigned long)wp->curr_keypair.sending_counter,
            wp->prev_keypair.valid ? 'Y' : 'N', (unsigned long)prev_age,
            (unsigned long)last_rx_age, (unsigned long)last_tx_age,
            (unsigned long)last_init_age,
            (int)wp->send_handshake, (unsigned)wp->handshake_attempts,
            (int)p->has_direct_path, (int)p->derp_fallback_active,
            (unsigned long long)last_pong_age);
    }

    ESP_LOGW(TAG,
        "[WG_SNAP_SUM] peers=%d linkup=%d active_probes=%d oldest_probe_age=%llums "
        "heap_internal_free=%u",
        ml->peer_count, linkup_peers, active_probes,
        (unsigned long long)oldest_probe_age_ms,
        (unsigned)esp_get_free_internal_heap_size());
}

/* ============================================================================
 * WG Manager Task
 * ========================================================================== */

/* ============================================================================
 * The shared wg_mgr task: one slice per membership
 *
 * This used to be a task per membership whose loop-locals (last probe times, one-shot flags, counters) lived on
 * its stack. With ONE task serving every membership they live in ml->wgm, and the loop body is member_service(),
 * called once per membership per pass (ml_mux.h). Waiting for registration is a stage, not a blocking wait, so a
 * membership that has not registered yet costs the others nothing.
 * ========================================================================== */

/* Per-iteration work budget (#46). This task runs at priority 7 on the same core as the host application's main
 * loop (ESPHome loopTask is priority 1 on core 1). The queue drains below used to run until the queues were
 * empty and only then sleep 10 ms; under a sustained DISCO exchange (a peer that keeps probing because its
 * WireGuard session never completes) packets arrived faster than one X25519 decrypt + reply, the drains never
 * ended, and the priority-1 loop got no CPU for >5 s -- the task watchdog then aborted the whole device. Now
 * each drain is bounded by a burst count and a time window and the iteration ALWAYS reaches the 10 ms sleep, so
 * lower-priority tasks are guaranteed a share of the core no matter how hard a peer pushes. The WireGuard
 * drains get their OWN windows, never charged for the DISCO work: the data plane must not lose frames because
 * discovery was busy. Excess packets wait in the queue for the next iteration (DISCO is lossy by design; the
 * queues are bounded and net_io drops on overflow).
 *
 * Shared task: the windows are per membership, and the drain time of a whole pass is capped at what one
 * membership could use before (the three windows together), so N memberships split that budget instead of
 * N-folding the time this priority-7 task holds the core. With one membership nothing changes. */
#define WG_MGR_DISCO_BUDGET_MS  40   /* DISCO drain: burst + time, whichever first */
#define WG_MGR_DISCO_BURST      8
#define WG_MGR_WG_BUDGET_MS     30   /* each WG drain: its OWN budget, never charged for DISCO */
#define WG_MGR_WG_BURST         64
#define WG_MGR_PASS_BUDGET_MS   (WG_MGR_DISCO_BUDGET_MS + 2 * WG_MGR_WG_BUDGET_MS)

/* Housekeeping that has no producer to wake the task (STUN finishing, the directory generation moving, a trial or
 * pending packet running out) is looked at at least this often. Everything else wakes the task or has its own timer. */
#define WG_MGR_HOUSEKEEPING_MS 250

void ml_wg_pass_begin(ml_wg_pass_t *pass) {
    pass->pass_start_ms = ml_get_time_ms();
    pass->drain_ms = 0;
    pass->next_due_ms = pass->pass_start_ms + WG_MGR_HOUSEKEEPING_MS;
}

static inline void wg_due(ml_wg_pass_t *pass, uint64_t when) {
    if (when < pass->next_due_ms) pass->next_due_ms = when;
}

/* One periodic cycle, in slices: the lwIP core lock is taken once per peer (timers and keepalives are microseconds) and an
 * initiation's X25519 runs with it released (wireguardif.c, "Periodic work in slices"). At most one initiation per cycle,
 * as before, so a cycle never costs N x 40 ms of CPU either. Called only from this task, which also owns the
 * membership's peers, so nothing else changes them between the slices except the lwIP thread's receive path, whose
 * effects the commit step re-validates. */
static void wg_periodic_sliced(microlink_t *ml) {
    struct netif *netif = (struct netif *)ml->wg_netif;
    if (!netif || !netif->state) return;
    uint8_t first = ((struct wireguard_device *)netif->state)->next_hs_peer;
    bool handshake_allowed = true;
    for (unsigned k = 0; k < WIREGUARD_MAX_PEERS; k++) {
        uint8_t idx = (uint8_t)((first + k) % WIREGUARD_MAX_PEERS);
        struct wireguard_initiation_job job;
        bool started = false;
        WG_LOCKED(TDONGLE_LOCK_WG_PERIODIC, { ROUTE_MARK(6); started = wireguardif_periodic_peer(netif, idx, handshake_allowed, &job); ROUTE_MARK(0); });
        if (started) {
            wireguard_initiation_compute(&job);                           /* no lock: ~40 ms of X25519 and AEAD */
            WG_LOCKED(TDONGLE_LOCK_WG_COMMIT, { ROUTE_MARK(6); wireguardif_periodic_commit(netif, idx, &job); ROUTE_MARK(0); });
            handshake_allowed = false;
        }
    }
    WG_LOCKED(TDONGLE_LOCK_WG_PERIODIC, wireguardif_periodic_end(netif));
}

/* When does this membership next need the task? Its own timers, a backlog the drain budgets left behind (one tick, so
 * lower priorities get the core between slices), packets waiting for a handshake or a trial deadline (polled at 10 ms
 * while they exist). */
static void wg_register_due(microlink_t *ml, ml_wg_pass_t *pass, uint64_t now) {
    ml_wg_loop_t *loop = &ml->wgm;
    wg_due(pass, loop->last_wg_periodic_ms + 400);
    wg_due(pass, loop->last_disco_probe_ms + 1000);
    wg_due(pass, loop->last_snapshot_ms + 10000);
    if (uxQueueMessagesWaiting(ml->wg_rx_queue) || uxQueueMessagesWaiting(ml->disco_rx_queue) ||
        uxQueueMessagesWaiting(ml->peer_update_queue))
        wg_due(pass, now + 1);
    if (ml->jit_packet_count || ml->inbound_trial.pending) wg_due(pass, now + 10);
}

/* Drain one membership's wg_rx_queue in runs: at most `burst` datagrams and while the window (its own, never charged for DISCO) and
 * the pass budget hold. The window is checked before each datagram is popped, so a run is at most ML_WG_RX_BATCH datagrams past it.
 * Returns the number of datagrams taken. */
static unsigned wg_rx_drain(microlink_t *ml, ml_wg_pass_t *pass, uint64_t window_start_ms, unsigned window_ms, unsigned burst) {
    ml_rx_packet_t pkt;
    unsigned taken = 0;
    if (uxQueueMessagesWaiting(ml->wg_rx_queue)) WGPERF_ADD(rx_qdepth, (uint32_t)uxQueueMessagesWaiting(ml->wg_rx_queue));   /* backlog at the start of a drain that has work */
    while (taken < burst && (ml_get_time_ms() - window_start_ms) < window_ms && pass->drain_ms < WG_MGR_PASS_BUDGET_MS && wg_rx_pop(ml, &pkt)) {
        taken++;
        if (!wg_rx_pkt_is_data(&pkt)) {
            /* a handshake or cookie: everything before it first, then it alone, then a new run */
            wg_rx_flush(ml);
            (void)wg_rx_stage(ml, &pkt);
            wg_rx_flush(ml);
            continue;
        }
        if (!wg_rx_stage(ml, &pkt)) continue;
        if (g_rx_n == ML_WG_RX_BATCH) wg_rx_flush(ml);
    }
    wg_rx_flush(ml);    /* the tail of the backlog: staged datagrams are owned by this task and must not wait for the next wake */
    return taken;
}

static void member_service(void *ctx, void *shared) {
    microlink_t *ml = ctx;
    ml_wg_pass_t *pass = shared;
    ml_wg_loop_t *loop = &ml->wgm;

    EventBits_t bits = xEventGroupGetBits(ml->events);
    if (bits & ML_EVT_SHUTDOWN_REQUEST)
        return;   /* detach runs member_teardown; until then there is nothing to do */

    if (loop->stage == ML_WG_STAGE_NEW) {
        ESP_LOGI(TAG, "WG Manager serving membership %lu (Core %d)",
                 (unsigned long)ml->config.diagnostic_id, xPortGetCoreID());
        memset(ml->pending_probes, 0, sizeof(ml->pending_probes));   /* probe tracking */
        loop->stage = ML_WG_STAGE_WAIT_REGISTRATION;
    }
    if (loop->stage == ML_WG_STAGE_WAIT_REGISTRATION) {
        if (!(bits & ML_EVT_COORD_REGISTERED))
            return;
        ESP_LOGI(TAG, "Coord registered, initializing WireGuard...");

        /* Initialize WireGuard interface (magicsock mode) */
        if (wg_init_interface(ml) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to init WireGuard, continuing without tunneling");
            strlcpy(ml->last_error, "WireGuard interface allocation failed; deactivate and retry", sizeof(ml->last_error));
        } else {
            /* Update VPN IP if coord already set it */
            wg_update_vpn_ip(ml);
            xEventGroupSetBits(ml->events, ML_EVT_WG_READY);
        }
        ESP_LOGI(TAG, "Accepting peer updates");
        loop->stage = ML_WG_STAGE_RUNNING;
    }

    /* A slice with nothing to do (a wake-up left behind by a burst, or a housekeeping deadline that was not ours) only
     * re-arms its timers: ml_wg_slice_idle is deliberately conservative, see ml_wg_idle.h. */
    {
        ml_wg_idle_t idle = {
            .queued = uxQueueMessagesWaiting(ml->wg_rx_queue) + uxQueueMessagesWaiting(ml->disco_rx_queue) +
                      uxQueueMessagesWaiting(ml->peer_update_queue),
            .packets_pending = ml->jit_packet_count != 0,
            .trial_pending = ml->inbound_trial.pending != 0,
            .directory_stale = __atomic_load_n(&ml->directory.generation, __ATOMIC_ACQUIRE) != ml->directory_applied,
            .stun_cmm_due = !loop->stun_cmm_sent && !ml_at_socket_is_ready() && ml->stun_public_ip != 0 && ml->peer_count > 0,
            .derp_changed = ((bits & ML_EVT_DERP_CONNECTED) != 0) != loop->derp_was_connected,
            .now_ms = ml_get_time_ms(),
            .periodic_at_ms = loop->last_wg_periodic_ms + 400,
            .probes_at_ms = loop->last_disco_probe_ms + 1000,
            .snapshot_at_ms = loop->last_snapshot_ms + 10000,
            .wg_ready = ml->wg_netif != NULL,
        };
#ifdef CONFIG_ML_ZERO_COPY_WG
        idle.queued += __atomic_load_n(&ml->zc.rx_tail, __ATOMIC_RELAXED) != __atomic_load_n(&ml->zc.rx_head, __ATOMIC_ACQUIRE);
#endif
        if (ml_wg_slice_idle(&idle)) {
            WGPERF_COUNT(passes_skipped, 1);
            wg_register_due(ml, pass, idle.now_ms);
            return;
        }
    }

    /* One drain window, charged to the pass as well as to its own limit. */
    uint64_t budget_start_ms = ml_get_time_ms();   /* DISCO budget window */
    #define WG_MGR_BUDGET_LEFT(ms) ((ml_get_time_ms() - budget_start_ms) < (ms) && pass->drain_ms < WG_MGR_PASS_BUDGET_MS)
    #define WG_MGR_CHARGE() (pass->drain_ms += (uint32_t)(ml_get_time_ms() - budget_start_ms))

    /* Process peer updates from coord task */
#ifdef ESP_PLATFORM
    directory_reconcile(ml);
#endif
    {
        WGPERF_T(tu);
        unsigned work_before = g_pass_work;
        process_peer_updates(ml);
        if (g_pass_work != work_before) WGPERF_CHARGE(tu, updates);
    }
#ifdef ESP_PLATFORM
    directory_trial_poll(ml);
    directory_flush_packets(ml);
#endif

    /* Track DERP connection state for DISCO.
     * Note: We DON'T re-initiate WG handshakes on DERP connect because
     * Tailscale peers use lazy config and would drop our initiations.
     * WG sessions are established on-demand when peers initiate to us. */
    {
        bool derp_connected_now = (bits & ML_EVT_DERP_CONNECTED) != 0;
        if (derp_connected_now && !loop->derp_was_connected) {
            ESP_LOGI(TAG, "DERP connected, %d peers ready for incoming handshakes",
                     ml->peer_count);
        }
        loop->derp_was_connected = derp_connected_now;
    }

    /* After STUN completes, broadcast CallMeMaybe to all peers.
     * Peers need to know our public endpoint (from STUN) to send direct
     * probes. Without this, our initial CMMs during peer-add have 0
     * endpoints because STUN hasn't finished yet. */
    if (!loop->stun_cmm_sent && !ml_at_socket_is_ready() &&
        ml->stun_public_ip != 0 && ml->peer_count > 0) {
        loop->stun_cmm_sent = true;
        int cmm_count = 0;
        for (int i = 0; i < ml->peer_count; i++) {
            if (!ml->peers[i].active) continue;
            if (ml->peers[i].has_direct_path) continue;
            disco_send_call_me_maybe(ml, i);
            cmm_count++;
        }
        ESP_LOGI(TAG, "STUN complete — sent CallMeMaybe to %d peers", cmm_count);
    }

    /* Process DISCO packets */
    WGPERF_T(tdisco);
    unsigned disco_before = loop->disco_rx_10s;
#ifdef CONFIG_ML_ZERO_COPY_WG
    /* Zero-copy mode: drain SPSC ring buffer (PCB callback → wg_mgr) */
    {
        uint8_t tail = __atomic_load_n(&ml->zc.rx_tail, __ATOMIC_RELAXED);
        uint8_t head = __atomic_load_n(&ml->zc.rx_head, __ATOMIC_ACQUIRE);
        int zc_n = 0;
        while (tail != head && zc_n++ < WG_MGR_DISCO_BURST && WG_MGR_BUDGET_LEFT(WG_MGR_DISCO_BUDGET_MS)) {
            ml_zc_disco_entry_t *entry = &ml->zc.rx_ring[tail];
            ml_rx_packet_t disco_pkt = {
                .data = entry->data,
                .len = entry->len,
                .src_ip = ntohl(entry->src_ip_nbo),
                .src_port = entry->src_port,
                .via_derp = false,
            };
            process_disco_packet(ml, &disco_pkt);
            loop->disco_rx_10s++;
            /* Don't free — data is in the ring buffer, not heap-allocated */
            tail = (tail + 1) % ML_ZC_DISCO_RING_SIZE;
            head = __atomic_load_n(&ml->zc.rx_head, __ATOMIC_ACQUIRE);
        }
        __atomic_store_n(&ml->zc.rx_tail, tail, __ATOMIC_RELEASE);
    }
#endif
    /* Queue-based path: DISCO from DERP relay + fallback when zero-copy disabled */
    ml_rx_packet_t disco_pkt;
    for (int n = 0; n < WG_MGR_DISCO_BURST && WG_MGR_BUDGET_LEFT(WG_MGR_DISCO_BUDGET_MS) &&
                    xQueueReceive(ml->disco_rx_queue, &disco_pkt, 0) == pdTRUE; n++) {
        process_disco_packet(ml, &disco_pkt);
        tdongle_heap_free(TDONGLE_OWNER_PACKET, disco_pkt.data);
        loop->disco_rx_10s++;
    }
    if (uxQueueMessagesWaiting(ml->disco_rx_queue) > 0) loop->budget_hits_10s++;
    WG_MGR_CHARGE();
    if (loop->disco_rx_10s != disco_before) { WGPERF_CHARGE(tdisco, disco_rx); g_pass_work++; }

    /* Process WireGuard packets */
    budget_start_ms = ml_get_time_ms();   /* WG data plane: fresh window, not charged for DISCO */
    WGPERF_T(tdrain);
    unsigned drained = wg_rx_drain(ml, pass, budget_start_ms, WG_MGR_WG_BUDGET_MS, WG_MGR_WG_BURST);
    if (drained) { WGPERF_CHARGE(tdrain, drain_wg); g_pass_work += drained; }
    WG_MGR_CHARGE();

    /* Run WireGuard periodic processing (handshakes, keepalives, rekeys).
     * This runs on OUR task stack (8KB) instead of the lwIP TCPIP thread (3-8KB),
     * preventing heavy crypto (X25519, ChaCha20-Poly1305) from monopolizing
     * the TCPIP thread and blocking all socket operations system-wide. */
    uint64_t now = ml_get_time_ms();
    if (ml->wg_netif && now - loop->last_wg_periodic_ms >= 400) {
        uint64_t t0 = now;
        WGPERF_T(tp);
        wg_periodic_sliced(ml);
        WGPERF_LAP(tp, periodic);
        g_pass_work++;
        uint64_t dt = ml_get_time_ms() - t0;
        loop->last_wg_periodic_ms = now;
        /* Throughput-collapse diag: only log when actually slow (>30ms),
         * routine fast ticks are noise. */
        if (dt > 30) {
            ESP_LOGW(TAG, "wireguardif_periodic SLOW: %llu ms",
                     (unsigned long long)dt);
        }
    }

    /* Periodic DISCO probes (every 1s check) */
    now = ml_get_time_ms();
    if (now - loop->last_disco_probe_ms > 1000) {
        uint64_t t0 = now;
        WGPERF_T(td);
        disco_periodic_probes(ml);
        WGPERF_LAP(td, disco_tick);
        g_pass_work++;
        uint64_t dt = ml_get_time_ms() - t0;
        loop->last_disco_probe_ms = now;
        if (dt > 30) {
            ESP_LOGW(TAG, "disco_periodic_probes SLOW: %llu ms",
                     (unsigned long long)dt);
        }
    }

    /* Re-drain WG RX after the (sometimes 30-66ms) periodic + disco work
     * above. This single task owns both the wg_rx_queue consumer AND the
     * slow crypto/probe paths; without this second drain, download frames
     * pile up in wg_rx_queue and overflow (→ DERP-RX drops → TCP backoff →
     * the sustained rate falls well below the burst peak) while the task
     * was busy. 2026-05-27. Bounded like the first drain, with its own
     * window so the slow periodic work above cannot starve it (#46). */
    budget_start_ms = ml_get_time_ms();
    WGPERF_RESTART(tdrain);
    drained = wg_rx_drain(ml, pass, budget_start_ms, WG_MGR_WG_BUDGET_MS, WG_MGR_WG_BURST);
    if (drained) { WGPERF_CHARGE(tdrain, drain_wg); g_pass_work += drained; }
    WG_MGR_CHARGE();
    #undef WG_MGR_CHARGE
    #undef WG_MGR_BUDGET_LEFT

    /* Throughput-collapse diag: full state snapshot every 10 s. */
    if (now - loop->last_snapshot_ms >= 10000) {
        dump_wg_state_snapshot(ml);
        /* One line per 10 s instead of 2-10 lines per packet: keeps a
         * DISCO storm visible (and attributable to the budget) at INFO
         * without the per-packet logging that helped starve the host
         * loop in the first place (#46). */
        if (loop->disco_rx_10s > 0) {
            ESP_LOGI(TAG, "DISCO: %lu packets in 10 s (%lu.%lu/s), %lu iterations budget-capped",
                     (unsigned long)loop->disco_rx_10s, (unsigned long)(loop->disco_rx_10s / 10),
                     (unsigned long)(loop->disco_rx_10s % 10), (unsigned long)loop->budget_hits_10s);
        }
        loop->disco_rx_10s = 0;
        loop->budget_hits_10s = 0;
        loop->last_snapshot_ms = now;
    }

    wg_register_due(ml, pass, ml_get_time_ms());
}

/* Runs under the wg_mgr mux lock after the membership left the table: shut the WireGuard interface down while
 * the shared task cannot be using it. ml->wg_netif goes NULL first so the zero-copy input path and the
 * accessors stop looking at the netif before it is torn down, not after it was freed. */
static void member_teardown(void *ctx, void *shared) {
    (void)shared;
    microlink_t *ml = ctx;
    if (ml->wg_netif) {
        struct netif *netif = (struct netif *)ml->wg_netif;
        LOCK_TCPIP_CORE();
        ml->wg_netif = NULL;
        wireguardif_shutdown(netif);
        netif_set_link_down(netif);
        netif_set_down(netif);
        netif_remove(netif);
        /* The struct wireguard_device behind netif->state (every peer's keypairs) was never released: only the
         * netif around it was, so each stop/start cycle leaked it. */
        wireguard_device_release(netif);
        tdongle_heap_free(TDONGLE_OWNER_WG, netif);
        UNLOCK_TCPIP_CORE();
    }
    memset(&ml->wgm, 0, sizeof(ml->wgm));
    ESP_LOGI(TAG, "WG Manager released membership %lu", (unsigned long)ml->config.diagnostic_id);
}

const ml_mux_ops_t ml_wg_mux_ops = {
    .service = member_service,
    .teardown = member_teardown,
};

static void gateway_release_cb(void *arg) {
    microlink_t *ml = arg;
    if (ml->wg_output_pcb) { udp_remove(ml->wg_output_pcb); ml->wg_output_pcb = NULL; }
    if (ml->wg_netif) {
        struct netif *n = ml->wg_netif;
        wireguardif_shutdown(n); netif_set_down(n); netif_remove(n); wireguard_device_release(n); tdongle_heap_free(TDONGLE_OWNER_WG, n);
        ml->wg_netif = NULL;
    }
}
void ml_gateway_release_netif(microlink_t *ml) {
    tcpip_callback_with_block(gateway_release_cb, ml, 1);
}
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
bool ml_wg_crypto_bench(size_t len, unsigned rounds, uint32_t *aead_ns, uint32_t *copy_ns) {
    uint8_t *packet = tdongle_heap_tag(TDONGLE_OWNER_OTHER, malloc(2 * (len + 16)));
    if (!packet || !rounds) {
        tdongle_heap_free(TDONGLE_OWNER_OTHER, packet);
        return false;
    }
    uint8_t key[32] = {1};
    memset(packet, 0x5a, len);
    int64_t started = esp_timer_get_time();
    for (unsigned i = 0; i < rounds; i++)
        chacha20poly1305_encrypt(packet + len + 16, packet, len, NULL, 0, i, key);
    *aead_ns = (uint32_t)((esp_timer_get_time() - started) * 1000 / rounds);
    started = esp_timer_get_time();
    for (unsigned i = 0; i < rounds; i++) {
        memcpy(packet + len + 16, packet, len);
        __asm__ __volatile__("" ::: "memory");
    }
    *copy_ns = (uint32_t)((esp_timer_get_time() - started) * 1000 / rounds);
    tdongle_heap_free(TDONGLE_OWNER_OTHER, packet);
    return true;
}

/* What one per-packet ESP_LOGI cost before it was removed: the same format as the old "WG UDP TX" line, as configured
 * (level, console channel, vprintf). Run from the console task; the line goes wherever logs go. */
bool ml_wg_log_bench(unsigned rounds, uint32_t *cycles_per_line) {
    if (!rounds) return false;
    uint32_t start = (uint32_t)esp_cpu_get_cycle_count();
    for (unsigned i = 0; i < rounds; i++)
        ESP_LOGI(TAG, "WG UDP TX: %d bytes -> %d.%d.%d.%d:%d type=%d", 1432, 100, 100, 5, 7, 41641, 4);
    *cycles_per_line = ((uint32_t)esp_cpu_get_cycle_count() - start) / rounds;
    return true;
}
#endif
