/**
 * @file microlink_internal.h
 * @brief MicroLink v2 Internal Types and Task Communication
 *
 * Architecture (ADR 0013 stage 1): three SHARED tasks serve every membership, and the
 * control plane keeps one task per membership.
 *
 * Shared (one instance, started with the first membership, stopped with the last):
 *   net_io   (Core 0, pri 7)  - one select() over every membership's UDP sockets
 *   derp     (Core 0, pri 5)  - every membership's DERP link (non-blocking TLS state machine)
 *   wg_mgr   (Core 1, pri 7)  - WireGuard + DISCO + peer management for every membership
 * Per membership:
 *   coord    (Core 1, pri 5)  - control plane (Noise, HTTP/2, registration, map)
 *
 * A membership's state is owned by exactly one task at a time per concern (its sockets by
 * net_io, its DERP link and TLS context by the derp task, its peers and WireGuard device by
 * wg_mgr, its control connection by its coord task). Shared tasks reach a membership only
 * through ml_mux_t (ml_mux.h), whose lock is the lifetime rule: after ml_mux_detach() returns,
 * no shared task touches the membership again. See ml_runtime.h.
 */

#pragma once

#include "microlink.h"
#include "ml_config_httpd.h"
#include "ml_published_name.h"
#include "ml_derp_cert.h"
#include "ml_derp_tls.h"
#include "ml_derp_link.h"
#include "ml_mux.h"
#include "ml_negotiation.h"
#include "ml_rng.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_heap_caps.h"
#include "tdongle_memory.h"
#include "ml_gateway_limits.h"
/* Forward-declare esp_tls_t so we can hold a pointer without pulling in
 * the full esp_tls.h header (esp-tls REQUIRES added in CMakeLists). */
struct esp_tls;
typedef struct esp_tls esp_tls_t;

#ifdef CONFIG_ML_ZERO_COPY_WG
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/* Task configuration.
 *
 * Stack sizes (FreeRTOS stacks are internal DRAM). Rule: size >= 2 x the highest stack use measured on
 * hardware, rounded up to 512 B, and never less than peak + 2 KiB. With shared tasks the rule is applied
 * to the worst path of ONE membership's service slice plus the worst CROSS-MEMBER path, because a shared
 * task visits memberships one after another and never nests them: the deepest stack is the deepest single
 * slice, whichever membership it serves.
 *
 * Evidence: firmware 0.2.22 on the T-Dongle-S3, 2026-10-05 (docs/diagnostics/baseline-0.2.22-2026-10-05.md),
 * uxTaskGetStackHighWaterMark after a join that included the DERP TLS handshake and 4x4-stream bidirectional
 * iperf over the direct path. Peak use: net_io 3,376, derp_tx 3,716, coord 4,152, wg_mgr 3,644.
 * The stack overflow canary stays on (CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY).
 *
 * Paths that capture did not run, bounded from the linked binary's frame sizes (tools/stack-frames.py prints
 * the frame of each function in the linked binary; they were added up along the real call chains):
 *   derp     DERP certificate verification runs in the handshake step (esp_crt_verify_callback + RSA/ECDSA
 *            verify): about +1.5 KB over the VERIFY_NONE handshake that was measured, so about 5.2 KB peak.
 *            The non-blocking link adds ml_derp_link_service (frames: ClientInfo scratch 192 B, receive
 *            scratch 64 B) on top of the same TLS chain: about +0.4 KB, so about 5.6 KB.
 *            The cross-member path is the DNS callback registration under the core lock and the negotiation
 *            token poll, both shallower than the handshake chain.
 *   coord    map re-fetch and reconnect repeat the measured map path; the custom-login-server key fetch
 *            (https) is shallower than that, about 3.8 KB. Unchanged by this stage.
 *   wg_mgr   inbound activation of an unknown peer adds derp_sender_admit 336 and directory_activate_idle 336
 *            on the paths JIT activation already walked. Stage 1 adds the CROSS-MEMBER path: when the peer pool
 *            is full a membership evicts the least recently used idle peer of ANOTHER membership
 *            (peer_pool_evict -> remove_peer -> wireguardif_remove_peer), about +0.9 KB, and runs the WireGuard
 *            interface init (wg_init_interface_impl, ~1.0 KB of frames) from the same task. Both replace, not
 *            nest, the 3,644 B path measured: about 5.6 KB.
 *   net_io   only socket receive and queue hand-off; the shared loop adds an fd_set for every membership's
 *            three sockets (about 128 B) and the same 1,564 B receive buffer.
 * Every size below leaves at least 2 KiB over the highest estimate and is at least twice the measured use.
 * They must be re-verified on the board: `stack_free_bytes` in /status reports the shared tasks' headroom. */
#define ML_TASK_NET_IO_STACK    (7168)       /* 3,376 B measured, ~3.6 KB est. -> 7,168 */
#define ML_TASK_NET_IO_PRIO     7
#define ML_TASK_NET_IO_CORE     0

#define ML_TASK_DERP_TX_STACK   (7680)       /* 3,716 B measured, ~5.6 KB est. with verification -> 7,680 */
#define ML_TASK_DERP_TX_PRIO    5
#define ML_TASK_DERP_TX_CORE    0

#define ML_TASK_COORD_STACK     (8704)       /* 4,152 B measured (per membership; stage 2 may share it) */
#define ML_TASK_COORD_PRIO      5
#define ML_TASK_COORD_CORE      1

#define ML_TASK_WG_MGR_STACK    (8192)       /* 3,644 B measured, ~5.6 KB est. with eviction -> 8,192 */
#define ML_TASK_WG_MGR_PRIO     7
#define ML_TASK_WG_MGR_CORE     1

/* The three tasks every membership shares: their stacks are paid once, by the first membership. */
#define ML_RT_SHARED_STACK_BYTES (ML_TASK_NET_IO_STACK + ML_TASK_DERP_TX_STACK + ML_TASK_WG_MGR_STACK)

/* Queue depths */
/* TX 16->64 (2026-05-27): absorb speedtest bursts so packets queue instead of
 * being dropped at enqueue; relay buffers are SPIRAM-backed (ml_psram_malloc),
 * the queue control struct itself is ~64×48B internal (negligible). */
#ifdef CONFIG_TDONGLE_QUEUE_DEPTH_SWEEP
#define ML_QUEUE_SWEEP CONFIG_TDONGLE_QUEUE_DEPTH_SWEEP
#else
#define ML_QUEUE_SWEEP 0
#endif
#if ML_QUEUE_SWEEP
#define ML_DERP_TX_QUEUE_DEPTH  ML_QUEUE_SWEEP
#define ML_DISCO_RX_QUEUE_DEPTH ML_QUEUE_SWEEP
#else
#define ML_DERP_TX_QUEUE_DEPTH  8
#define ML_DISCO_RX_QUEUE_DEPTH 8
#endif
/* WG RX queue slots. The slots are only the COUNT bound (an ml_rx_packet_t is 48 B); what a queued datagram costs is the heap block
 * it points to, and that is bounded in bytes across all memberships by ml_wg_rx_budget.h (ML_WG_RX_QUEUE_BYTES), which holds 9
 * full-size datagrams or, with these slots, 12 small ones (ACKs). 8 -> 12 (ADR 0020): a burst that net_io moves out of the socket
 * mailbox in one pass (up to 10, at most 16) must fit at once, and the old 8 slots lost 5 % of a 3 Mbit/s UDP stream. +192 B of
 * queue storage per membership, charged by admission through member_queue_bytes. */
#if ML_QUEUE_SWEEP
#define ML_WG_RX_QUEUE_DEPTH    ML_QUEUE_SWEEP
#define ML_STUN_RX_QUEUE_DEPTH  (ML_QUEUE_SWEEP < 4 ? ML_QUEUE_SWEEP : 4)
#else
#define ML_WG_RX_QUEUE_DEPTH    12
#define ML_STUN_RX_QUEUE_DEPTH  4
#endif
#define ML_COORD_CMD_QUEUE_DEPTH 4
#define ML_PEER_UPDATE_QUEUE_DEPTH 16

/* Outbound packets one membership may hold while the peer they are for is activated and its handshake runs
 * (ml_gateway_queue_packet). A per-membership budget, no longer a constant 4: at ~1,400 B each, 8 is 11,200 B at the
 * worst, only while a handshake is in flight, tagged to the `wg` owner (the packet pool of PR-B will own this memory).
 * Enqueueing wakes the wg_mgr task (ml_rt_wake), so the budget is what absorbs a burst, not a polling period. */
#define ML_JIT_PENDING 8
#define ML_JIT_PACKET_MAX 1400

/* Protocol limits */
#define ML_MAX_PEERS            CONFIG_ML_MAX_PEERS
#define ML_MAX_ENDPOINTS        8
#define ML_MAX_PACKET_SIZE      1500
/* Largest payload accepted in one DERP frame after the 32-byte source key of a
 * RecvPacket (and the cap for every other post-handshake frame). The DERP frame
 * header (type byte + 4 length bytes, derp.go frameHeaderLen) is not part of the
 * length field, and a RecvPacket's 32-byte source key is subtracted before this
 * cap applies. The largest WireGuard data message is a tunnel packet of up to
 * ML_MAX_PACKET_SIZE bytes padded to 16 plus 16 bytes of header and 16 of tag:
 * 1,500 -> 1,504 + 32 = 1,536 <= 1,564. Our netif MTU is 1,420 (1,456 on the
 * wire) and Tailscale's default 1,280 (1,312); handshake messages are < 150. */
_Static_assert(ML_DERP_MAX_FRAME == ML_MAX_PACKET_SIZE + 64, "ml_derp_link.h and the packet size must agree");
_Static_assert(ML_DERP_MAX_FRAME >= ((ML_MAX_PACKET_SIZE + 15) / 16) * 16 + 32,
               "a maximum-size WireGuard data message must fit one DERP frame");

/* DERP */
/* 2026-05-28: tried region 26 (Nuremberg, = tailscale-105's home DERP) to kill
 * the Frankfurt->Nuremberg mesh hop — but it BROKE the tailscale-105 session
 * (no WG handshake completed, both runtime-config and code-level). Frankfurt(4)
 * works (the mesh relays fine, ~0.3 Mbit). Reverted. The real fix needs proper
 * netcheck + per-peer home-region relaying, not a single hard-coded region. */
#define ML_DERP_REGION          4       /* Frankfurt (fra) - closer to EU + matches typical peer home DERP */
#define ML_DERP_HOST            "derp4.tailscale.com"
#define ML_DERP_PORT            443

/* Tailscale control plane */
#define ML_CTRL_HOST            "controlplane.tailscale.com"
#define ML_CTRL_PORT            443

/* Who vouches for the control server's Noise key (see ml_coord.c). */
#define ML_CTRL_KEY_NONE            0 /* nothing established yet */
#define ML_CTRL_KEY_PINNED_BUILTIN  1 /* Tailscale SaaS key compiled into ml_noise.c */
#define ML_CTRL_KEY_PINNED_CONFIG   2 /* ctrl_noise_key from the configuration */
#define ML_CTRL_KEY_TLS_VERIFIED    3 /* fetched over https, certificate verified */
#define ML_CTRL_KEY_PLAINTEXT       4 /* fetched over http: NOT authenticated */
#define CTRL_KEY_PINNED_BUILTIN ML_CTRL_KEY_PINNED_BUILTIN
#define CTRL_KEY_PINNED_CONFIG  ML_CTRL_KEY_PINNED_CONFIG
#define CTRL_KEY_TLS_VERIFIED   ML_CTRL_KEY_TLS_VERIFIED
#define CTRL_KEY_PLAINTEXT      ML_CTRL_KEY_PLAINTEXT
#define ML_CTRL_PROTOCOL_VER    131

/* Hostinfo.IPNVersion is supplied per-device via microlink_config_t.ipn_version
 * (the ESPHome `ipn_version:` option). Empty/NULL => the field is omitted, so the
 * admin console shows no client version. tailscale parses it as version.Long()
 * ("x.y.z-t<hash>-g<hash>", version/version.go:73-82); a string missing the hash
 * suffix is silently not displayed. Left unset it can trip "Device is too old" and
 * block device operations - see README (Troubleshooting). */

/* DISCO timing (from tailscaled - MUST match for correct behavior) */
#define ML_DISCO_PING_INTERVAL_MS       5000
#define ML_DISCO_HEARTBEAT_MS           3000
/* Bumped 15000 → 60000 (2026-05-24): under sustained AP+STA radio contention
 * (phone speedtest etc.), DISCO PINGs starve before the encrypted data path
 * does. 15 s of PING silence was enough to falsely trigger "direct path
 * expired → revert to DERP" on every active peer simultaneously, which
 * zeroed working endpoints and crashed throughput. 60 s gives 20 PINGs worth
 * of trust before we even consider falling back, and the smart-fallback
 * gate in disco_periodic_probes adds a second check on peer->last_rx. */
#define ML_DISCO_TRUST_DURATION_MS      60000
#define ML_DISCO_PING_TIMEOUT_MS        5000
#define ML_DISCO_UPGRADE_INTERVAL_MS    15000
#define ML_DISCO_SESSION_ACTIVE_MS      45000
/* Per-peer DISCO backoff (esphome-tailscale#46, direction 3). The reference
 * client heartbeats a peer only while it has traffic for it
 * (sessionActiveTimeout) and never answers a CallMeMaybe with one of its own.
 * microlink used to heartbeat every peer with a direct path every 3 s for
 * ever and to echo every CallMeMaybe, so two microlink nodes that never
 * completed a WireGuard session kept each other busy indefinitely. */
#define ML_DISCO_CMM_BURST_FLOOR_MS     2500    /* min spacing of CallMeMaybe-triggered ping bursts, per peer */
#define ML_DISCO_BEST_STICKY_MS         6500    /* keep best_ip/port while it answered this recently (trustUDPAddrDuration) */

/* STUN servers (Tailscale primary, Google fallback) */
#define ML_STUN_PRIMARY_HOST    "derp9.tailscale.com"
#define ML_STUN_PRIMARY_PORT    3478
#define ML_STUN_FALLBACK_HOST   "stun.l.google.com"
#define ML_STUN_FALLBACK_PORT   19302
#define ML_STUN_MAX_RETRIES     3
#define ML_STUN_RETRY_INTERVAL_MS   2000

/* STUN timing */
#define ML_STUN_RETRANSMIT_MS           100
#define ML_STUN_TOTAL_TIMEOUT_MS        5000
#define ML_STUN_RESTUN_INTERVAL_MS      23000

/* Control plane timing */
#define ML_CTRL_WATCHDOG_MS             120000
#define ML_CTRL_BACKOFF_MAX_MS          30000
#define ML_CTRL_KEEPALIVE_MS            60000
/* Stream-liveness watchdog: the mapSession sends a KeepAlive MapResponse
 * roughly every minute (we request KeepAlive=true), so this allows ~5
 * consecutive misses before declaring the session dead. Deliberately much
 * longer than ML_CTRL_WATCHDOG_MS — that one guards the whole transport,
 * this one guards the map stream specifically (#32). */
#define ML_CTRL_STREAM_STALE_MS         300000

/* DERP relay liveness (#33): the retry ladder, the receive watchdog and every per-record, per-write and
 * per-attempt deadline live in ml_derp_link.h (ML_DERP_RETRY_MIN_MS, ML_DERP_RETRY_MAX_MS, ML_DERP_STALE_MS, ...). */

/* Large tailnet buffer sizes (PSRAM-allocated, configurable via menuconfig) */
#define ML_H2_BUFFER_SIZE       (CONFIG_ML_H2_BUFFER_SIZE_KB * 1024)
#define ML_JSON_BUFFER_SIZE     (CONFIG_ML_JSON_BUFFER_SIZE_KB * 1024)

/* Noise protocol */
#define ML_NOISE_KEY_LEN        32
#define ML_NOISE_MAC_LEN        16
#define ML_NOISE_NONCE_LEN      12
#define ML_NOISE_HASH_LEN       32

/* ============================================================================
 * Zero-Copy WG Types (Kconfig: CONFIG_ML_ZERO_COPY_WG)
 *
 * When enabled, the DISCO UDP socket uses a raw lwIP PCB callback instead of
 * a BSD socket. WG packets go directly to wireguardif_network_rx() (zero copy).
 * DISCO packets are buffered in a lock-free SPSC ring for the wg_mgr task.
 * ========================================================================== */

#ifdef CONFIG_ML_ZERO_COPY_WG

#define ML_ZC_DISCO_RING_SIZE   16      /* Must be power of 2 */
#define ML_ZC_DISCO_MAX_PKT     256     /* Max DISCO packet size in ring */
#define ML_ZC_TX_POOL_SIZE      24      /* Outbound send pool depth */

/* SPSC ring entry for DISCO packets (PCB callback → wg_mgr task) */
typedef struct {
    uint8_t data[ML_ZC_DISCO_MAX_PKT];
    uint16_t len;
    uint32_t src_ip_nbo;    /* Network byte order (from lwIP) */
    uint16_t src_port;      /* Host byte order (from lwIP) */
} ml_zc_disco_entry_t;

/* Outbound TX context for tcpip_callback send */
typedef struct {
    struct udp_pcb *pcb;
    uint8_t data[ML_MAX_PACKET_SIZE];
    uint16_t len;
    ip_addr_t dest;
    uint16_t port;
} ml_zc_tx_ctx_t;

/* Zero-copy state embedded in microlink_s */
typedef struct {
    struct udp_pcb *pcb;            /* Raw UDP PCB (replaces disco_sock4) */
    uint16_t local_port;            /* Bound port */

    /* DISCO RX ring buffer (lock-free SPSC) */
    ml_zc_disco_entry_t rx_ring[ML_ZC_DISCO_RING_SIZE];
    volatile uint8_t rx_head;       /* Written by tcpip_thread */
    volatile uint8_t rx_tail;       /* Written by wg_mgr task */

    /* TX send pool (microlink → tcpip_thread) */
    ml_zc_tx_ctx_t tx_pool[ML_ZC_TX_POOL_SIZE];
    volatile uint8_t tx_head;       /* Written by wg_mgr task */
    volatile uint8_t tx_tail;       /* Written by tcpip_thread */
} ml_zerocopy_t;

#endif /* CONFIG_ML_ZERO_COPY_WG */

/* ============================================================================
 * Event Group Bits
 * ========================================================================== */

#define ML_EVT_WIFI_CONNECTED       BIT0
#define ML_EVT_COORD_REGISTERED     BIT1
#define ML_EVT_DERP_CONNECTED       BIT2
#define ML_EVT_WG_READY             BIT3
#define ML_EVT_PEERS_AVAILABLE      BIT4
#define ML_EVT_STUN_COMPLETE        BIT5
#define ML_EVT_SHUTDOWN_REQUEST     BIT6
#define ML_EVT_DERP_RECONNECT       BIT7
#define ML_EVT_DERP_CONNECT_REQ     BIT8

/* ============================================================================
 * Queue Message Types
 * ========================================================================== */

/* DERP TX queue item - packet to send via DERP relay */
typedef struct {
    uint8_t dest_pubkey[32];    /* Destination peer's public key */
    uint8_t *data;              /* Heap-allocated payload (caller frees on failure) */
    size_t len;                 /* Payload length */
    uint8_t frame_type;         /* DERP frame type (0x04 = SendPacket) */
} ml_derp_tx_item_t;

/* Received packet (from net_io to disco/wg queues) */
typedef struct {
    uint8_t *data;              /* Heap-allocated packet data */
    size_t len;                 /* Packet length */
    uint32_t src_ip;            /* Source IP (for UDP packets) */
    uint16_t src_port;          /* Source port (for UDP packets) */
    uint8_t src_pubkey[32];     /* Source peer key (for DERP packets) */
    bool via_derp;              /* true if received via DERP, false if direct UDP */
} ml_rx_packet_t;

/* Coordination command */
typedef enum {
    ML_CMD_CONNECT,             /* Start registration */
    ML_CMD_DISCONNECT,          /* Graceful disconnect */
    ML_CMD_UPDATE_ENDPOINTS,    /* Send endpoint update to control plane */
    ML_CMD_FORCE_RECONNECT,     /* Force reconnection (after DERP failure, etc.) */
} ml_coord_cmd_t;

/* Peer update (from coord to wg_mgr) */
typedef struct {
    enum {
        ML_PEER_ADD,
        ML_PEER_REMOVE,
        ML_PEER_UPDATE_ENDPOINT,
        ML_PEER_BATCH,
        ML_PEER_PACKET,
    } action;
    uint32_t vpn_ip;
    uint8_t public_key[32];
    uint8_t disco_key[32];
    char hostname[64];
    uint16_t derp_region;
    /* Endpoints */
    struct {
        uint32_t ip;
        uint16_t port;
        bool is_ipv6;
    } endpoints[ML_MAX_ENDPOINTS];
    int endpoint_count;
    bool is_exit_node;          /* Peer advertises 0.0.0.0/0 in AllowedIPs */
    /* Subnet routes advertised by the peer (non-CGNAT, non-0.0.0.0/0). */
    microlink_route_t subnet_routes[MICROLINK_MAX_PEER_ROUTES];
    uint8_t subnet_route_count;
    /* Tailscale netmap Node.Online tri-state. has_online=false means the
     * MapResponse did not include this field and the current value should be
     * preserved. has_online=true → online holds the authoritative value from
     * the control plane (true = peer is connected to tailnet, false = offline). */
    bool has_online;
    bool online;
    /* Tailscale NodeID — int64 in the wire format. Stored so PeersChangedPatch
     * deltas (which carry only NodeID, not Key) can be matched back to the
     * peer slot. has_node_id distinguishes "not parsed" from "parsed as 0". */
    bool has_node_id;
    uint64_t node_id;
} ml_peer_update_t;
typedef struct {
    ml_peer_update_t header;
    size_t count;
    bool authoritative;
    ml_peer_update_t updates[];
} ml_peer_batch_t;
/* Peer-update queue entries are of two kinds: heap blocks (map batches, endpoint updates: ml_peer_update_t, owner PEER) and
 * queued host packets, which are lwIP pbufs in the WireGuard transport layout (ml_wg_mgr.c, "Egress"). A pbuf pointer is
 * 4-aligned, so bit 0 tells the two apart; a packet entry must never be dereferenced as an update or freed with free(). */
struct pbuf;
static inline bool ml_pu_is_packet(const void *entry) { return ((uintptr_t)entry & 1u) != 0; }
static inline void *ml_pu_tag_packet(struct pbuf *packet) { return (void *)((uintptr_t)packet | 1u); }
static inline struct pbuf *ml_pu_packet(const void *entry) { return (struct pbuf *)((uintptr_t)entry & ~(uintptr_t)1u); }
static inline tdongle_owner ml_peer_update_owner(const ml_peer_update_t *update) { (void)update; return TDONGLE_OWNER_PEER; }
/* Free an entry taken from the queue (stop path). */
void ml_pu_free_entry(void *entry);

/* ============================================================================
 * Peer State (owned exclusively by wg_mgr task)
 * ========================================================================== */

typedef struct {
    /* Identity */
    uint64_t jit_used_ms;
    uint32_t vpn_ip;
    uint8_t public_key[32];
    uint8_t disco_key[32];
    char hostname[64];
    bool active;
    /* Activated because of an inbound claim nobody has authenticated yet (a
     * DERP source key). Set only while it holds the membership's single trial
     * slot; cleared when WireGuard authenticates this peer, or the peer is
     * removed when the trial expires. See directory_trial_* in ml_wg_mgr.c. */
    bool unconfirmed;

    /* Endpoints */
    struct {
        uint32_t ip;
        uint16_t port;
        bool is_ipv6;
    } endpoints[ML_MAX_ENDPOINTS];
    int endpoint_count;
    uint16_t derp_region;

    /* DISCO state (rate limiting) */
    uint64_t last_ping_sent_ms;     /* Last DISCO ping we sent */
    uint64_t last_pong_recv_ms;     /* Last DISCO pong we received */
    uint64_t trust_until_ms;        /* Direct path trusted until */
    uint64_t last_send_ms;          /* Last data sent to this peer */
    uint64_t last_upgrade_ms;       /* Last path upgrade attempt */
    uint64_t last_cmm_rx_ms;        /* Last CallMeMaybe-triggered ping burst (floor) */
    uint64_t best_last_pong_ms;     /* Last direct PONG that came from best_ip:best_port itself */

    /* DISCO shared secret with this peer (NaCl box beforenm of our disco
     * private key and the peer's disco key), derived once and reused for
     * every DISCO packet in both directions -- reference client:
     * discoInfo.sharedKey. It used to be recomputed per packet: one X25519,
     * ~16 ms on an ESP32-S3, which is what made every DISCO packet and every
     * manager tick with two heartbeats in it expensive. disco_shared_for[]
     * remembers the disco key it was derived from, so a rotation arriving by
     * any netmap path re-derives it on next use. */
    uint8_t disco_shared[32];
    uint8_t disco_shared_for[32];
    bool disco_shared_valid;

    /* Best direct path */
    uint32_t best_ip;
    uint16_t best_port;
    bool has_direct_path;

    /* WireGuard peer index in wireguard-lwip */
    int wg_peer_index;

    /* On-demand handshake retry timestamp. When a direct DISCO PONG arrives
     * for a peer without an active WG session, we fire a one-shot handshake
     * init. The original implementation set a single boolean and never tried
     * again — a lost or unanswered init left the session forever down.
     * Now: record ml_get_time_ms() of the last attempt and re-fire after
     * INITIAL_HANDSHAKE_RETRY_MS so dropped initiations get a second chance. */
    uint64_t last_init_handshake_ms;

    /* DERP-only fallback (Phase 1.5g): for peers where direct UDP is impossible
     * (e.g. both ends behind the same NAT with no hairpin, or VLAN-isolated). */
    uint64_t peer_added_ms;        /* When this peer entered our state */
    bool derp_fallback_active;     /* Endpoint forced to DERP via update_endpoint(0) */
    uint64_t last_derp_attempt_ms; /* Last wireguardif_connect_derp() retry, for periodic re-fire */

    /* Exit-node advertisement (Phase 1.5e): true if this peer carries
     * 0.0.0.0/0 in AllowedIPs (i.e. tailscale up --advertise-exit-node). */
    bool is_exit_node;

    /* Subnet routes the peer advertises (non-CGNAT, non-default-route).
     * Parsed from AllowedIPs in the netmap and used by the project-side
     * route hook to direct matching destinations into the tunnel. */
    microlink_route_t subnet_routes[MICROLINK_MAX_PEER_ROUTES];
    uint8_t subnet_route_count;

    /* Tailnet liveness from the control plane's Node.Online flag (the same
     * signal the official Tailscale UI uses). Defaults to true on peer
     * insertion until the first MapResponse field clears it. */
    bool online;

    /* Tailscale NodeID — primary key for PeersChangedPatch deltas, which
     * normally carry only NodeID (Key is only sent on key rotation). 0 means
     * we have not seen an ID for this peer yet. */
    uint64_t node_id;
} ml_peer_t;

/* ============================================================================
 * DERP Map Types (parsed from MapResponse, used by coord + STUN)
 * ========================================================================== */

/* Largest HTTP/2 frame we will attempt to reassemble. The wire field is 24-bit
 * (16 MB); anything beyond what fits in one read buffer can never complete. */
#define ML_H2_MAX_FRAME_LEN     32768

#define ML_MAX_DERP_REGIONS     4
#define ML_MAX_DERP_NODES       2

typedef struct {
    char hostname[64];
    char ipv4[16];
    char ipv6[46];
    uint16_t stun_port;     /* 0 = default 3478 */
    uint16_t derp_port;     /* 0 = default 443 */
    bool stun_only;         /* true if node only serves STUN, not DERP */
    ml_derp_cert_t cert;    /* how to authenticate the TLS server: from DERPNode.CertName */
} ml_derp_node_t;

typedef struct {
    uint16_t region_id;
    char code[8];           /* e.g. "dfw", "nyc", "sfo" */
    char name[24];          /* e.g. "Frankfurt", "New York" — from DERPMap RegionName */
    ml_derp_node_t nodes[ML_MAX_DERP_NODES];
    uint8_t node_count;
    bool avoid;             /* true if region should be avoided */
} ml_derp_region_t;

/* ============================================================================
 * Noise Protocol State (owned exclusively by coord task)
 * ========================================================================== */

typedef struct {
    uint8_t h[ML_NOISE_HASH_LEN];
    uint8_t ck[ML_NOISE_HASH_LEN];
    uint8_t local_static_private[32];
    uint8_t local_static_public[32];
    uint8_t local_ephemeral_private[32];
    uint8_t local_ephemeral_public[32];
    uint8_t remote_static_public[32];
    uint8_t tx_key[ML_NOISE_KEY_LEN];
    uint8_t rx_key[ML_NOISE_KEY_LEN];
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    bool handshake_complete;
} ml_noise_state_t;

/* ============================================================================
 * DERP Connection State
 * ========================================================================== */

struct derp_xport;                  /* connect-time scratch (ml_derp.c): heap, only while connecting */
typedef struct {
    int sockfd;                     /* Raw TCP socket */
    mbedtls_ssl_context ssl;        /* TLS context (touched only by the derp task, or by teardown under the mux lock) */
    mbedtls_ssl_config ssl_conf;
    bool tls_up;                    /* ssl and ssl_conf are initialised (and an ml_rng reference is held) */
    struct derp_xport *xport;       /* DNS, TCP and TLS progress of the attempt in flight; NULL otherwise */
    ml_derp_link_t link;            /* the relay protocol, as a non-blocking state machine */
    bool connected;                 /* mirrors link.state == READY for the other tasks */
    uint64_t last_recv_ms;          /* For keepalive watchdog */
    uint64_t connect_started_ms;    /* wall of the attempt that is in flight, for the timing log */
    uint32_t tls_verify_failures;   /* handshakes refused because the server did not authenticate */
    uint32_t tls_deferred;          /* connects postponed until the wall clock is set */
} ml_derp_conn_t;

/* ============================================================================
 * Main Context
 * ========================================================================== */

typedef struct {
    uint8_t txid[12];
    uint32_t dest_ip;
    uint16_t dest_port;
    uint64_t sent_ms;
    int peer_index;
    bool active;
} ml_disco_probe_t;


#include "ml_directory.h"

/* The wg_mgr loop's per-membership state. It used to be locals of a task function; with one shared wg_mgr
 * task every membership keeps its own in its context. */
typedef struct {
    enum { ML_WG_STAGE_NEW, ML_WG_STAGE_WAIT_REGISTRATION, ML_WG_STAGE_RUNNING } stage;
    uint64_t last_disco_probe_ms, last_wg_periodic_ms, last_snapshot_ms;
    bool derp_was_connected;
    bool stun_cmm_sent;             /* one-shot: send CallMeMaybe after the first STUN result */
    uint32_t disco_rx_10s, budget_hits_10s;
} ml_wg_loop_t;

struct microlink_s {
    uint8_t txid_v4[12], txid_v6[12];
    bool txid_v4_valid, txid_v6_valid;
    ml_disco_probe_t pending_probes[32];
    int disco_probe_start_idx, burst_count;
    uint64_t last_burst_ms;
    char identity_namespace[16];
    char auth_url[384];
    char last_error[64];
    char transport_error[64];
    unsigned noise_error, noise_frame_bytes;
    uint32_t read_expected, read_received, read_elapsed_ms, read_errno;
    int32_t read_tls_result, conn_tls_result;
    uint32_t control_stage;
    char h2_debug[49];
    uint32_t map_attempts, map_failures, map_bytes, map_declared_bytes, map_projected_bytes;
    uint32_t map_heap_before, map_heap_after, map_largest_before;
    unsigned map_error, map_stream_id, map_frame_type;
    uint32_t map_h2_error, map_h2_last_stream;

    uint8_t node_key_challenge[32];
    bool has_node_key_challenge;
    void *wg_output_pcb;
    uint64_t last_stun_ms, last_derp_keepalive_ms, last_expiry_check_ms, last_h2_ping_ms;
    uint8_t stream_header[9], stream_special[56];
    size_t stream_header_used, stream_special_used;
    uint32_t stream_remaining, stream_id;
    uint8_t stream_type, stream_flags, stream_padding;
    bool stream_padding_pending;
    unsigned map_generation;
    /* Configuration (immutable after init) */
    microlink_config_t config;

    /* State (atomic reads from any task, writes only from coord) */
    volatile microlink_state_t state;
    volatile uint32_t vpn_ip;
    /* MagicDNS name of this node. Written by the control task, read by the
     * status, LCD and DNS tasks: use ml_published_name_set/get, never the
     * text directly (it can be mid-rewrite). */
    ml_published_name_t self_dns_name;

    /* True when load_or_generate_keys() found every keypair in NVS at
     * boot (i.e. this device has a persistent node identity). False
     * when at least one keypair had to be freshly generated — the
     * common case is a never-registered board or one that just went
     * through microlink_factory_reset. */
    bool identity_persistent;

    /* Identity from the last RegisterResponse — for display only. A failed
     * registration is detected from RegisterResponse.Error / NodeKeyExpired /
     * AuthURL (the fields the reference client acts on), NOT from this block:
     * User.ID=0 is normal for auth-key and tag-owned nodes, and DisplayName is
     * documented as an override, so empty is the usual case.
     *
     * register_user_id semantics:
     *   -1 = no RegisterResponse parsed yet this boot
     *    0 = registered with no bound user (auth-key or tag-owned) — NORMAL
     *   >0 = a real user; register_user_name holds the display name */
    int  register_user_id;
    char register_user_name[48];

    /* Reconnect-cause counters (per boot; exported via microlink_diag_t so
     * telemetry can ship them). A single undifferentiated "connect count"
     * overcounts as a health signal — ordinary transport drops look the
     * same as watchdog saves (esphome-tailscale#32 field verification) —
     * so each detector counts separately. */
    volatile uint32_t rc_coord_stream_wd;  /* map-stream watchdog fired */
    volatile uint32_t rc_coord_transport;  /* established coord session died (ctrl watchdog / PING send / recv) */
    volatile uint32_t rc_derp_rx_wd;       /* DERP RX-liveness watchdog fired */
    volatile uint32_t rc_derp_retry;       /* failed DERP connect attempts on the backoff ladder */

    /* Event group (cross-task synchronization) */
    EventGroupHandle_t events;

    /* Task handles */
    TaskHandle_t coord_task;        /* the only per-membership task; net_io, derp and wg_mgr are shared (ml_runtime.h) */
    /* The coord task, if microlink_start() created it and it has not signed off yet
     * (ml_task_exiting). microlink_stop() waits for this to reach zero
     * instead of sleeping a fixed 3 s and hoping: a coord task still inside
     * poll_map_update() when microlink_destroy() freed the instance was a
     * use-after-free PANIC on the reference router (reconnect burst). */
    volatile int tasks_alive;
    bool rt_attached;               /* registered with the shared tasks (ml_rt_attach succeeded) */
    bool stop_incomplete;           /* a task outlived the stop wait, or a shared task still held this context: destroy must not free */

    /* Queues */
    QueueHandle_t derp_tx_queue;        /* -> derp_tx task */
    QueueHandle_t disco_rx_queue;       /* net_io -> wg_mgr */
    QueueHandle_t wg_rx_queue;          /* net_io -> wg_mgr */
    QueueHandle_t stun_rx_queue;        /* net_io -> coord */
    QueueHandle_t coord_cmd_queue;      /* any -> coord */
    volatile uint32_t peer_generation; /* even = peer metadata stable, odd = owner applying updates */
    struct { struct pbuf *packet; uint64_t expires; uint32_t vpn_ip; uint32_t seq; uint16_t len; } jit_pending[ML_JIT_PENDING];   /* prepared egress pbufs, see ml_wg_mgr.c */
    volatile unsigned jit_packet_count;
    uint32_t jit_hits,jit_misses,jit_evictions,jit_rejected,jit_dropped;
    uint32_t directory_applied;
    /* Budget for work an unauthenticated inbound packet can cause (flash
     * lookup, X25519, a peer slot). Owned by wg_mgr. */
    struct {
        uint8_t pending;              /* peer index + 1 holding the trial slot, 0 = free */
        uint8_t tokens;               /* lookups the next packets may still cause */
        uint64_t refill_ms;           /* last token refill */
        uint64_t deadline_ms;         /* the trial peer must authenticate by then */
        uint64_t cooldown_until_ms;   /* no new trial before this after a failed one */
        uint32_t started, confirmed, expired, refused;
    } inbound_trial;
    ml_directory_t directory;
    ml_wg_loop_t wgm;               /* shared wg_mgr task's per-membership loop state */
    volatile bool map_batch_pending; /* at most one owned semantic batch per membership */
    QueueHandle_t peer_update_queue;    /* coord -> wg_mgr */

    /* Keys (loaded at init, read-only after) */
    uint8_t machine_private_key[32];    /* Noise machine key */
    uint8_t machine_public_key[32];
    uint8_t wg_private_key[32];         /* WireGuard key */
    uint8_t wg_public_key[32];
    uint8_t disco_private_key[32];      /* DISCO key */
    uint8_t disco_public_key[32];

    /* DERP connection (owned exclusively by DERP I/O task after connect) */
    /* Connection setup by coord task, then handed to DERP I/O task */
    ml_derp_conn_t derp;

    /* Sockets for net_io select() loop */
    int disco_sock4;                    /* UDP socket for DISCO + direct WG */
    int disco_sock6;                    /* IPv6 UDP socket (-1 if unavailable) */
    int stun_sock;                      /* UDP socket for STUN */
    uint16_t disco_local_port;          /* Bound port for disco_sock4 */

    /* Coordination socket (owned exclusively by coord task) */
    int coord_sock;
    bool       use_tls;                 /* true if login_server URL is https:// */
    esp_tls_t *coord_tls;               /* NULL when use_tls is false */
    uint32_t h2_next_stream_id;         /* Next H2 stream ID for endpoint updates (odd, starts at 7) */

    /* WireGuard netif (owned exclusively by wg_mgr task) */
    void *wg_netif;

    /* Upstream (physical STA) netif to pin the ESP's OWN control-plane +
     * DERP sockets to, set by microlink_pin_wg_output_netif() in exit-node
     * mode. When an exit node is active main flips netif_default to the WG
     * tunnel; our self-origin control/DERP TCP must still egress the real
     * uplink (else errno EHOSTUNREACH / MBEDTLS_ERR_NET_SEND_FAILED). NULL
     * = exit-node off → netif_default is already the STA, no pin needed.
     * Mirrors tailscale Go's bindToDevice for the control + DERP dialers. */
    void *upstream_netif;

    /* Peers (owned exclusively by wg_mgr task) */
    ml_peer_t peers[ML_MAX_PEERS];
    int peer_count;

    /* STUN results (written by coord, read by coord only) */
    uint32_t stun_public_ip;
    uint16_t stun_public_port;
    uint32_t last_ep_update_hash;   /* FNV-1a of the last endpoint update sent to control; 0 = none this session */

    /* STUN server cache (pre-resolved IPs, host byte order) */
    uint32_t stun_primary_ip;       /* derp9.tailscale.com resolved IPv4 */
    uint32_t stun_fallback_ip;      /* stun.l.google.com resolved IPv4 */
    uint8_t stun_retry_count;       /* Retries on current server */
    bool stun_using_fallback;       /* true if probing fallback server */
    uint64_t stun_last_probe_ms;    /* Timestamp of last probe sent */

    /* IPv6 STUN */
    int stun_sock6;                 /* IPv6 UDP socket for STUN (-1 if unavailable) */
    uint8_t stun_primary_ip6[16];   /* derp9.tailscale.com resolved IPv6 */
    uint8_t stun_public_ip6[16];    /* Our public IPv6 from STUN */
    uint16_t stun_public_port6;     /* Our public IPv6 port from STUN */
    bool stun_has_ipv6;             /* true if IPv6 STUN result available */

    /* Symmetric NAT detection */
    uint16_t stun_secondary_port;   /* Mapped port from second STUN server */
    bool stun_nat_checked;          /* true if symmetric NAT check completed */
    bool nat_mapping_varies;        /* true = symmetric NAT (direct won't work) */

    /* DERP map (parsed from MapResponse, owned by coord task) */
    ml_derp_region_t derp_regions[ML_MAX_DERP_REGIONS];
    uint8_t derp_region_count;
    uint16_t derp_home_region;     /* Currently active region (netcheck override may have replaced the default) */
    uint16_t derp_region_default;  /* Configured default region — config.preferred_derp_region or ML_DERP_REGION fallback. The control plane itself does NOT send an independent suggestion; tailscale Go semantics. */

    /* Most recent netcheck RTT measurements per derp_regions[] slot.
     * Same index as derp_regions; 0 = no measurement / timed out. */
    uint16_t derp_rtt_ms[ML_MAX_DERP_REGIONS];

    /* ml_get_time_ms() value when state transitioned to CONNECTED. 0 means
     * not currently connected. Used for the GUI tailnet uptime row. */
    uint64_t connected_at_ms;

    /* ml_get_time_ms() captured at the top of the DERP I/O task's most
     * recent loop iteration. A frozen value means that task is wedged in
     * a socket call — external diagnostics watch the climbing age to catch
     * the silent control-plane stall. Written every loop by the DERP task,
     * read cross-task (volatile, 64-bit read may tear but a stale ms
     * sample is harmless for an age computation). */
    volatile uint64_t derp_last_heartbeat_ms;

    /* ml_get_time_ms() of the most recent frame RECEIVED from the control
     * plane on the long-poll H2 stream (PONG, server PING, SETTINGS,
     * keepalive, or a real MapResponse) — i.e. genuine proof the server is
     * still talking to us. Distinct from the coord task's last_activity_ms
     * watchdog, which is ALSO reset by our own 5 s PING *send* and therefore
     * stays fresh even when the connection has gone half-open / black-hole
     * (the 2026-05-26 wedge: web shows Connected while the control plane
     * marks us offline). The SD recorder samples now - ctrl_last_rx_ms as
     * coord_age, so a climbing value pinpoints exactly that silent stall. */
    volatile uint64_t ctrl_last_rx_ms;

    /* ml_get_time_ms() of the most recent DATA frame received on the
     * long-poll map stream (H2 stream 5) specifically — real MapResponses
     * and the ~60 s mapSession keepalives, NOTHING else. Unlike
     * ctrl_last_rx_ms this is NOT advanced by transport-level chatter
     * (PONGs to our own 5 s PINGs, SETTINGS), so it keeps climbing when a
     * front end / load balancer keeps the HTTP/2 connection alive while
     * the server-side mapSession is already gone — the #32 failure: node
     * "offline" in the admin console for hours, device thinks all is well.
     * The COORD_LONG_POLL stream watchdog reconnects off this clock. */
    volatile uint64_t ctrl_stream_rx_ms;

    /* Long-poll MapResponse reassembly buffer. The streamed map session is length-prefixed; see
     * tailscale/control/controlclient/direct.go:1304-1311, which reads a 4-byte LITTLE-ENDIAN size
     * and then exactly that many bytes. A message can span several H2 DATA frames and several Noise
     * frames, so the reader must accumulate — do_map_exchange already does, for the reason its own
     * comment gives ("a single H2 frame can span multiple Noise frames"); the long-poll path did not. */
    /* HTTP/2 frame reassembly for the long-poll socket. A DATA frame whose
     * payload is split across two reads must be completed, not dropped. */
    uint8_t *h2_acc;
    size_t   h2_acc_len;

    /* Never allocated in gateway mode: nothing assigns it, so only destroy ever frees it (docs/memory-diagnostics.md). */
    uint8_t *lp_acc;
    size_t   lp_acc_len;

    /* Key expiry (parsed from MapResponse self-node) */
    int64_t key_expiry_epoch;       /* Unix epoch seconds, 0 = no expiry */
    bool key_expired;               /* true if Node.Expired == true */

    /* Resolved timing (set during init from config, 0 = default) */
    uint32_t t_disco_heartbeat_ms;
    uint32_t t_stun_interval_ms;
    uint32_t t_ctrl_watchdog_ms;

    /* Callbacks */
    microlink_state_cb_t state_cb;
    void *state_cb_data;
    microlink_peer_cb_t peer_cb;
    void *peer_cb_data;
    microlink_data_cb_t data_cb;
    void *data_cb_data;

    /* HTTP Config Server (peer allowlist, runtime settings) */
    ml_config_ctx_t *config_httpd;

    /* NVS-backed config string storage (auth_key/device_name pointers in
     * microlink_config_t are redirected here when NVS settings exist) */
    char nvs_auth_key[96];
    char nvs_device_name[48];

    /* Control plane host override (empty = use ML_CTRL_HOST default).
     * Set from NVS at boot for Headscale/Ionscale/custom coordinators,
     * or from microlink_config_t.ctrl_host when supplied directly. */
    char ctrl_host[64];

    /* Parsed host and port from ctrl_host (filled lazily by do_tcp_connect).
     * ctrl_host_parsed is the bare hostname/IP, ctrl_port_str the port as
     * decimal string (default "80" http / "443" https), ctrl_host_hdr is the
     * value to use in HTTP "Host:" / HTTP/2 ":authority" (host, plus ":port"
     * iff non-default). */
    char ctrl_host_parsed[64];
    char ctrl_port_str[8];
    char ctrl_host_hdr[72];

    /* Noise server static public key fetched from the custom control plane
     * via GET /key?v=<ML_CTRL_PROTOCOL_VER>. Valid only when ctrl_noise_pubkey_valid is true;
     * otherwise ml_noise_init falls back to the hardcoded Tailscale SaaS
     * server key. */
    uint8_t ctrl_noise_pubkey[32];
    bool ctrl_noise_pubkey_valid;
    uint8_t ctrl_key_auth;           /* ML_CTRL_KEY_*: who vouches for the key above */
    uint8_t ctrl_key_failures;       /* consecutive Noise handshake failures with a fetched key */
    uint32_t ctrl_key_drop_backoff_ms; /* gap enforced between drops of the fetched key */
    uint64_t ctrl_key_next_drop_ms;  /* no drop before this (uptime ms) */
    uint32_t ctrl_key_refetches;     /* fetched keys dropped after failures */

    /* Subnet routes to advertise on register (Hostinfo.RoutableIPs).
     * Newline-separated CIDR string copied from microlink_config_t.advertise_routes.
     * Empty = no routes hirdetve. */
    char advertise_routes[256];

    /* Debug flags (bitmask from NVS, checked at runtime for verbose logging) */
    uint8_t debug_flags;  /* bit 0: DISCO, bit 1: WG, bit 2: DERP, bit 3: coord */

#ifdef CONFIG_ML_ZERO_COPY_WG
    /* Zero-copy WG: raw PCB replaces disco_sock4 BSD socket */
    ml_zerocopy_t zc;
#endif
};

/* Implemented by the gateway app. Writes are rate-limited and kept in a small
 * NVS ring so failures survive USB loss or reboot without a RAM log buffer. */
enum { GATEWAY_DIAG_MAP_FAILURE = 1, GATEWAY_DIAG_REGISTER_FAILURE = 2,
       GATEWAY_DIAG_CONNECTED = 3, GATEWAY_DIAG_START_BLOCKED = 4,
       GATEWAY_DIAG_START_ATTEMPT = 5, GATEWAY_DIAG_START_FAILED = 6,
       GATEWAY_DIAG_TCP_FAILURE = 7, GATEWAY_DIAG_NOISE_FAILURE = 8,
       GATEWAY_DIAG_H2_FAILURE = 9, GATEWAY_DIAG_SOCKET_FAILURE = 10,
       GATEWAY_DIAG_BOOT = 11, GATEWAY_DIAG_UPSTREAM = 12 };
void gateway_diag_membership(uint32_t member_id, uint32_t event, uint32_t detail);
void gateway_diag_record(const microlink_t *ml, uint32_t event,
                         uint32_t detail);

/* ============================================================================
 * Internal Function Declarations (per-module)
 * ========================================================================== */

/* ml_net_io.c: the shared loop's body. One call = one select() over every attached membership's sockets
 * (at most 50 ms), then the packets that arrived are classified and queued. `scratch` is the task's
 * receive buffer (ML_NET_IO_SCRATCH_BYTES). */
#define ML_NET_IO_SCRATCH_BYTES (ML_MAX_PACKET_SIZE + 64)
void ml_net_io_pass(ml_mux_t *mux, uint8_t *scratch);

/* ml_derp.c: the per-membership hooks of the shared DERP task (see ml_runtime.c). */
extern const ml_mux_ops_t ml_derp_mux_ops;
/* Wire a freshly allocated membership to the DERP machinery. Allocation-free. */
void ml_derp_member_init(microlink_t *ml);

/* Every microlink task calls this as its LAST statement before
 * vTaskDelete(NULL): after it returns the task must not touch ml again,
 * because microlink_stop() may already be tearing the instance down. */
void ml_task_exiting(microlink_t *ml);
esp_err_t ml_derp_queue_send(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len);

/* ml_coord.c */
void ml_coord_task(void *arg);
/* Pin a freshly-created BSD socket (control-plane or DERP) to ml->upstream_netif
 * via SO_BINDTODEVICE so the ESP's own self-origin traffic always egresses the
 * physical uplink, never the exit-node WG tunnel. No-op when no upstream is
 * pinned (exit-node off). Defined in ml_coord.c, also called from ml_derp.c. */
void ml_bind_sock_to_upstream(microlink_t *ml, int fd);

/* ml_wg_mgr.c: the per-membership hooks of the shared wg_mgr task (see ml_runtime.c). */
extern const ml_mux_ops_t ml_wg_mux_ops;
/* Global WireGuard peer-slot pool, for /status (ml_wg_mgr.c). */
typedef struct {
    uint32_t capacity, used, peak, refused_full, refused_nomem;
    uint32_t evictions_own, evictions_other, rejected;
    uint32_t refused_largest;   /* slots refused because they would have taken the largest free block under the TLS floor */
    uint32_t largest_low;       /* smallest largest-free-block seen right after a slot allocation (UINT32_MAX: none yet) */
    uint32_t slot_bytes, device_bytes;
} ml_wg_pool_status_t;
void ml_wg_pool_status(ml_wg_pool_status_t *out);
size_t ml_wg_slot_bytes(void);       /* sizeof(struct wireguard_peer): the slot the pool hands out */
size_t ml_wg_device_bytes(void);     /* sizeof(struct wireguard_device): a membership's WireGuard device */

/* The shared wg_mgr task's scratch: one pass visits every membership, and the work windows below the
 * per-membership drains (#46) are bounded by the pass as a whole, so N memberships share what one used to have. */
typedef struct { uint64_t pass_start_ms; uint32_t drain_ms; uint64_t next_due_ms; } ml_wg_pass_t;
typedef struct { uint32_t wait_ms; bool active; } ml_derp_pass_t;   /* shortest wait any link asks for, UINT32_MAX = none */
void ml_wg_pass_begin(ml_wg_pass_t *pass);
/* Units of work the last pass did (packets moved, timers run); reset by the call. wg_mgr task only. */
unsigned ml_wg_pass_work_take(void);
void ml_wg_mgr_send_cmm(microlink_t *ml, uint32_t peer_vpn_ip);
esp_err_t ml_wg_mgr_trigger_handshake(microlink_t *ml, uint32_t dest_vpn_ip);
bool ml_wg_mgr_peer_is_up(microlink_t *ml, uint32_t vpn_ip);

/* ml_stun.c */
esp_err_t ml_stun_resolve_servers(microlink_t *ml);
esp_err_t ml_stun_send_probe(microlink_t *ml, const char *server, uint16_t port);
esp_err_t ml_stun_send_probe_to(microlink_t *ml, uint32_t server_ip, uint16_t port);
esp_err_t ml_stun_send_probe_ipv6(microlink_t *ml, const uint8_t *server_ip6, uint16_t port);

/* DERP region latency probe. Pings every region (one node each) with
 * a STUN binding request in parallel, measures RTT, returns the
 * region_id with the lowest RTT. Returns 0 if nothing responded. */
uint16_t ml_netcheck_pick_best_derp(microlink_t *ml);
bool ml_stun_parse_response(microlink_t *ml, const uint8_t *data, size_t len,
                             uint32_t *out_ip, uint16_t *out_port);
bool ml_stun_parse_response_ipv6(microlink_t *ml, const uint8_t *data, size_t len,
                                  uint8_t *out_ip6, uint16_t *out_port);

/* ml_noise.c */
void ml_noise_init(ml_noise_state_t *state,
                    const uint8_t *local_private, const uint8_t *local_public,
                    const uint8_t *remote_public);
esp_err_t ml_noise_write_msg1(ml_noise_state_t *state, uint8_t *out, size_t *out_len);
esp_err_t ml_noise_read_msg2(ml_noise_state_t *state, const uint8_t *msg, size_t len);
esp_err_t ml_noise_encrypt(const uint8_t *key, uint64_t nonce,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *ciphertext);
esp_err_t ml_noise_decrypt(const uint8_t *key, uint64_t nonce,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *ciphertext, size_t ct_len,
                            uint8_t *plaintext);

/* ml_h2.c */
int ml_h2_build_headers_frame(uint8_t *out, size_t out_size,
                               const char *method, const char *path,
                               const char *authority, const char *content_type,
                               uint32_t stream_id, bool end_stream);
int ml_h2_build_data_frame(uint8_t *out, size_t out_size,
                            const uint8_t *data, size_t data_len,
                            uint32_t stream_id, bool end_stream);
int ml_h2_build_preface(uint8_t *out, size_t out_size);
int ml_h2_build_settings_ack(uint8_t *out, size_t out_size);
int ml_h2_build_window_update(uint8_t *out, size_t out_size,
                               uint32_t stream_id, uint32_t increment);

/* ml_peer_nvs.c */
esp_err_t ml_peer_nvs_init(void);
void ml_peer_nvs_deinit(void);
esp_err_t ml_peer_nvs_save(const ml_peer_t *peer);
int ml_peer_nvs_load_all(ml_peer_t *peers, int max_peers);
esp_err_t ml_peer_nvs_remove(const uint8_t public_key[32]);
esp_err_t ml_peer_nvs_clear(void);

#ifdef CONFIG_ML_ZERO_COPY_WG
/* ml_zerocopy.c */
esp_err_t ml_zerocopy_init(microlink_t *ml);
void ml_zerocopy_deinit(microlink_t *ml);
esp_err_t ml_zerocopy_send(microlink_t *ml, const uint8_t *data, size_t len,
                            uint32_t dest_ip, uint16_t dest_port);
#endif

/* Utility */
uint64_t ml_get_time_ms(void);

/* ============================================================================
 * Network Socket Wrappers — Route through AT sockets when cellular active
 *
 * These inline functions check ml_at_socket_is_ready() and route socket calls
 * to either the normal BSD socket API (WiFi/lwIP) or the AT socket bridge
 * (cellular SIM7600 internal TCP/IP stack).
 * ========================================================================== */

#include "ml_at_socket.h"

#ifdef CONFIG_ML_ENABLE_CELLULAR
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

static inline int ml_socket(int domain, int type, int protocol) {
    if (ml_at_socket_is_ready() && (domain == AF_INET || domain == AF_INET6))
        return ml_at_socket(domain, type, protocol);
    return socket(domain, type, protocol);
}

static inline int ml_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_connect(fd, addr, len);
    return connect(fd, addr, len);
}

static inline ssize_t ml_send(int fd, const void *buf, size_t len, int flags) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_send(fd, buf, len, flags);
    return send(fd, buf, len, flags);
}

static inline ssize_t ml_recv(int fd, void *buf, size_t len, int flags) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_recv(fd, buf, len, flags);
    return recv(fd, buf, len, flags);
}

static inline ssize_t ml_sendto(int fd, const void *buf, size_t len, int flags,
                                 const struct sockaddr *addr, socklen_t addrlen) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_sendto(fd, buf, len, flags, addr, addrlen);
    return sendto(fd, buf, len, flags, addr, addrlen);
}

static inline ssize_t ml_recvfrom(int fd, void *buf, size_t len, int flags,
                                    struct sockaddr *addr, socklen_t *addrlen) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_recvfrom(fd, buf, len, flags, addr, addrlen);
    return recvfrom(fd, buf, len, flags, addr, addrlen);
}

static inline int ml_close_sock(int fd) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_close(fd);
    return close(fd);
}

static inline int ml_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_bind(fd, addr, len);
    return bind(fd, addr, len);
}

static inline int ml_setsockopt(int fd, int level, int optname,
                                  const void *optval, socklen_t optlen) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_setsockopt(fd, level, optname, optval, optlen);
    return setsockopt(fd, level, optname, optval, optlen);
}

static inline int ml_fcntl(int fd, int cmd, int arg) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_fcntl(fd, cmd, arg);
    return fcntl(fd, cmd, arg);
}

static inline int ml_select_fds(int nfds, fd_set *rd, fd_set *wr,
                                  fd_set *ex, struct timeval *tv) {
    /* If any FD in the sets is an AT socket, use AT select */
    if (ml_at_socket_is_ready() && nfds > ML_AT_SOCK_FD_BASE)
        return ml_at_select(nfds, rd, wr, ex, tv);
    return select(nfds, rd, wr, ex, tv);
}

static inline int ml_getaddrinfo(const char *host, const char *svc,
                                   const struct addrinfo *hints,
                                   struct addrinfo **res) {
    if (ml_at_socket_is_ready())
        return ml_at_getaddrinfo(host, svc, hints, res);
    return getaddrinfo(host, svc, hints, res);
}

static inline void ml_freeaddrinfo(struct addrinfo *res) {
    /* AT socket addrinfo is also malloc'd, free works for both */
    if (ml_at_socket_is_ready()) {
        ml_at_freeaddrinfo(res);
        return;
    }
    freeaddrinfo(res);
}

/* write/read for mbedTLS BIO compatibility */
static inline ssize_t ml_write_sock(int fd, const void *buf, size_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_write(fd, buf, len);
    return write(fd, buf, len);
}

static inline ssize_t ml_read_sock(int fd, void *buf, size_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_read(fd, buf, len);
    return read(fd, buf, len);
}

#else
/* Non-cellular builds: direct pass-through (zero overhead) */
#define ml_socket       socket
#define ml_connect      connect
#define ml_send         send
#define ml_recv         recv
#define ml_sendto       sendto
#define ml_recvfrom     recvfrom
#define ml_close_sock   close
#define ml_bind         bind
#define ml_setsockopt   setsockopt
#define ml_fcntl        fcntl
#define ml_select_fds   select
#define ml_getaddrinfo  getaddrinfo
#define ml_freeaddrinfo freeaddrinfo
#define ml_write_sock   write
#define ml_read_sock    read
#endif /* CONFIG_ML_ENABLE_CELLULAR */

/* PSRAM allocation helper */
static inline void *ml_psram_malloc(size_t size) {
    void *ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ptr) ptr = malloc(size);
    return ptr;
}

static inline void *ml_psram_calloc(size_t n, size_t size) {
    void *ptr = heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ptr) ptr = calloc(n, size);
    return ptr;
}

#ifdef __cplusplus
}
#endif

#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
/* Times the WireGuard cipher (ChaCha20-Poly1305) and a plain copy of len-byte packets. */
bool ml_wg_crypto_bench(size_t len, unsigned rounds, uint32_t *aead_ns, uint32_t *copy_ns);
#endif
esp_err_t ml_gateway_queue_packet(microlink_t *ml, uint32_t ip, const uint8_t *data, size_t len);
