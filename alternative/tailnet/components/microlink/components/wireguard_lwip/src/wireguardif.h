/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */


#ifndef _WIREGUARDIF_H_
#define _WIREGUARDIF_H_

#include "lwip/arch.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "wireguard.h"  // For wireguard_derp_output_fn typedef

// Default MTU for WireGuard is 1420 bytes
#define WIREGUARDIF_MTU (1420)

#define WIREGUARDIF_DEFAULT_PORT		(51820)
#define WIREGUARDIF_KEEPALIVE_DEFAULT	(0xFFFF)

struct wireguardif_init_data {
    // Required: the private key of this WireGuard network interface
    const char *private_key;
    // Required: What UDP port to listen on
    u16_t listen_port;
    // Optional: restrict send/receive of encapsulated WireGuard traffic to this network interface only (NULL to use routing table)
    struct netif *bind_netif;
};

struct wireguardif_peer {
    const char *public_key;
    // Optional pre-shared key (32 bytes) - make sure this is NULL if not to be used
    const uint8_t *preshared_key;
    // tai64n of largest timestamp we have seen during handshake to avoid replays
    uint8_t greatest_timestamp[12];

    // Allowed ip/netmask (can add additional later but at least one is required)
    ip_addr_t allowed_ip;
    ip_addr_t allowed_mask;

    // End-point details (may be blank)
    ip_addr_t endpoint_ip;
    u16_t endport_port;
    u16_t keep_alive;
};

#define WIREGUARDIF_INVALID_INDEX (0xFF)

/* static struct netif wg_netif_struct = {0};
 * struct wireguard_interface wg;
 * wg.private_key = "abcdefxxx..xxxxx=";
 * wg.listen_port = 51820;
 * wg.bind_netif = NULL; // Pass netif to listen on, NULL for all interfaces
 *
 * netif = netif_add(&netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);
 *
 * netif_set_up(wg_net);
 *
 * struct wireguardif_peer peer;
 * wireguardif_peer_init(&peer);
 * peer.public_key = "apoehc...4322abcdfejg=;
 * peer.preshared_key = NULL;
 * peer.allowed_ip = allowed_ip;
 * peer.allowed_mask = allowed_mask;
 *
 * // If you want to enable output connection
 * peer.endpoint_ip = peer_ip;
 * peer.endport_port = 12345;
 *
 * uint8_t wireguard_peer_index;
 * wireguardif_add_peer(netif, &peer, &wireguard_peer_index);
 *
 * if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
 *   // Start outbound connection to peer
 *   wireguardif_connect(wg_net, wireguard_peer_index);
 * }
 *
 */

// Initialise a new WireGuard network interface (netif)
err_t wireguardif_init(struct netif *netif);

// Helper to initialise the peer struct with defaults
void wireguardif_peer_init(struct wireguardif_peer *peer);

// Add a new peer to the specified interface - see wireguard.h for maximum number of peers allowed
// On success the peer_index can be used to reference this peer in future function calls
err_t wireguardif_add_peer(struct netif *netif, struct wireguardif_peer *peer, u8_t *peer_index);

// Remove the given peer from the network interface; its pool slot is wiped and returned.
err_t wireguardif_remove_peer(struct netif *netif, u8_t peer_index);

// Peer slots come from ONE process-wide pool shared by every wireguard netif (see
// wireguard_pool.h); wireguardif_add_peer() returns ERR_MEM when the device's table is
// full OR the pool is at capacity / out of memory. The caller can tell the pool apart
// via wireguardif_pool_stats().refused_full / .refused_nomem. The eviction policy (which
// peer to drop to make room) lives in the caller. Everything here runs under the lwIP
// core lock, like the rest of this API.

// Re-size the pool (1..WG_POOL_MAX_SLOTS slots, default WIREGUARD_POOL_SLOTS) and install
// allocator hooks (both NULL = malloc/free). Returns false, changing nothing, if any peer
// is live. Call at boot, before the first wireguardif_init()/add_peer.
bool wireguardif_pool_configure(size_t capacity, wg_pool_alloc_fn alloc, wg_pool_free_fn free_fn);

// Snapshot of the pool counters: capacity, used, peak_used, acquired, released,
// refused_full, refused_nomem, evictions.
wg_pool_stats_t wireguardif_pool_stats(void);

// Tell the pool that the caller evicted a peer of this netif's device to make room.
void wireguardif_pool_note_eviction(const struct netif *netif);

// Number of peers (pool slots) currently held by this netif's device.
uint8_t wireguardif_device_peer_count(const struct netif *netif);

// Update the "connect" IP of the given peer
err_t wireguardif_update_endpoint(struct netif *netif, u8_t peer_index, const ip_addr_t *ip, u16_t port);

// Add an additional allowed IP/mask to an existing peer (e.g. 0.0.0.0/0 for
// exit-node routing). The peer's primary allowed_ip set via wireguardif_add_peer
// remains intact; this just adds another entry to allowed_source_ips[].
err_t wireguardif_add_allowed_ip(struct netif *netif, u8_t peer_index,
                                  const ip_addr_t *ip, const ip_addr_t *mask);

// Pin the WG UDP socket to a specific upstream netif (typically the STA).
// Without this, when netif_default is flipped to the WG netif (for exit-node
// routing) the encapsulated UDP packets loop back into the WG tunnel. Calling
// this with the STA netif makes the encapsulated traffic always leave via
// the real upstream. Pass NULL to unpin.
err_t wireguardif_set_upstream_netif(struct netif *wg_netif,
                                      const struct netif *upstream);

// Try and connect to the given peer
err_t wireguardif_connect(struct netif *netif, u8_t peer_index);

// Stop trying to connect to the given peer
err_t wireguardif_disconnect(struct netif *netif, u8_t peer_index);

// Is the given peer "up"? A peer is up if it has a valid session key it can communicate with
err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);

// Register a DERP relay output callback for peers without direct endpoints
// This callback is invoked when a WireGuard packet needs to be sent to a peer
// that has no direct IP endpoint (ip is 0.0.0.0 or port is 0)
// fn: callback function, ctx: user context passed to callback
void wireguardif_set_derp_output(struct netif *netif, wireguard_derp_output_fn fn, void *ctx);

// Force initiation of handshake to a DERP-only peer
// Use this for peers where connect() would fail due to no direct endpoint
// The handshake will be routed through the DERP callback if set
err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index);

// Inject a received packet into the WireGuard interface (for magicsock demux)
// This allows an external unified socket to receive all packets and route
// WireGuard packets to this interface. The packet data is copied internally.
// src_ip: source IP in network byte order (0 for DERP)
// src_port: source port in host byte order
// data: raw packet data
// len: packet length
err_t wireguardif_inject_packet(struct netif *netif, uint32_t src_ip, uint16_t src_port,
                                 const uint8_t *data, size_t len);

// Check if packet looks like a WireGuard packet (type 1-4)
// Returns true if this appears to be a WireGuard packet
bool wireguardif_is_wireguard_packet(const uint8_t *data, size_t len);

// Shutdown WireGuard interface - cancels all timers before freeing resources
// MUST be called before netif_remove/mem_free to prevent use-after-free in wireguardif_tmr
void wireguardif_shutdown(struct netif *netif);

// Release the WireGuard device behind the netif (the struct wireguard_device
// wireguardif_init allocated: every peer's keypairs and handshake state).
// Cancels the timer, removes the internal UDP PCB if the device owns one,
// zeroes the key material and frees the struct; netif->state becomes NULL.
// Call after the netif is down and removed, before freeing the netif itself.
// Safe to call twice.
void wireguardif_free(struct netif *netif);

// Run WireGuard periodic processing (handshakes, keepalives, rekeys) from caller's task.
// In magicsock mode, the internal sys_timeout timer is disabled to avoid running heavy
// crypto (X25519, ChaCha20-Poly1305) on the lwIP TCPIP thread. Call this every ~400ms.
void wireguardif_periodic(struct netif *netif);

// Sliced periodic processing with the handshake crypto outside the lwIP core lock (see wireguardif.c). The caller takes
// the core lock for each call EXCEPT wireguard_initiation_compute(), which needs none.
bool wireguardif_periodic_peer(struct netif *netif, u8_t peer_index, bool allow_handshake, struct wireguard_initiation_job *job);
err_t wireguardif_periodic_commit(struct netif *netif, u8_t peer_index, struct wireguard_initiation_job *job);
void wireguardif_periodic_end(struct netif *netif);

// Receive path with the decryption outside the lwIP core lock. begin (lock held) returns 1 with `job` ready for transport
// data, 0 when the packet was handled; then wireguard_rx_decrypt(job) with NO lock; then complete (lock held).
int wireguardif_rx_begin(struct netif *netif, struct pbuf *p, const ip_addr_t *addr, u16_t port, struct wireguard_rx_job *job);
void wireguardif_rx_complete(struct netif *netif, const ip_addr_t *addr, u16_t port, struct wireguard_rx_job *job);

// Batched, in-place form (the wg_mgr task). Same begin / decrypt / complete steps and locking, with three differences:
//  * WIREGUARDIF_RX_INPLACE: `p` is exclusively owned, writable and one segment; the plaintext replaces the ciphertext inside it (no
//    second buffer: the ChaCha20-Poly1305 open verifies the tag before it writes anything) and `p` itself becomes the packet that is
//    delivered. Without the flag a separate plaintext pbuf is allocated, as in wireguardif_rx_begin.
//  * wireguardif_rx_complete_deferred does everything wireguardif_rx_complete does EXCEPT the call to netif->input: an accepted
//    packet is left in job->deliver, trimmed to its inner IP length (the 16 B padding is gone), counted by wireguardif_rx_deliver.
//  * wireguardif_rx_deliver hands job[i].deliver of the first `n` jobs, in order, to the router: through the batch callback set by
//    wireguardif_set_rx_batch if there is one, else netif->input one by one. It needs NO lock (the router takes the core lock itself
//    for the one step that needs it). Counts rx_delivered / rx_input_fail per packet, frees what the router refused, returns the
//    number delivered.
// The decision cryptokey routing makes about a decrypted packet, on raw bytes (exported so it is tested without a pbuf):
// bad version/short header, source not in the peer's AllowedIPs of its family (IPv4: ALLOWED_IP, IPv6: ALLOWED_IP6), length field wrong, or a well formed
// packet of a version this gateway does not deliver. On OK, *ip_len is the inner packet's own length.
typedef enum { WG_INNER_OK = 0, WG_INNER_BAD_IP, WG_INNER_ALLOWED_IP, WG_INNER_ALLOWED_IP6, WG_INNER_BAD_LENGTH, WG_INNER_IPV6_UNSUPPORTED } wg_inner_verdict_t;
wg_inner_verdict_t wireguardif_inner_check(const struct wireguard_peer *peer, bool ipv6_ok, const uint8_t *pkt, size_t len, size_t *ip_len);
#define WIREGUARDIF_RX_INPLACE 1u
int wireguardif_rx_begin_ex(struct netif *netif, struct pbuf *p, const ip_addr_t *addr, u16_t port, struct wireguard_rx_job *job, unsigned flags);
void wireguardif_rx_complete_deferred(struct netif *netif, const ip_addr_t *addr, u16_t port, struct wireguard_rx_job *job);
unsigned wireguardif_rx_deliver(struct netif *netif, struct wireguard_rx_job *jobs, unsigned n);
void wireguardif_set_rx_batch(struct netif *netif, wireguard_rx_batch_fn fn);
// Allow delivery of authenticated inner IPv6 packets whose source passed the AllowedIPs check (default: off, counted rx_ipv6_unsupported).
void wireguardif_set_rx_ipv6(struct netif *netif, bool enabled);

// Disable WireGuard's internal UDP socket binding
// Call before wireguardif_init to prevent WireGuard from binding its own socket.
// The caller is then responsible for receiving packets and calling wireguardif_inject_packet.
void wireguardif_disable_socket_bind(void);

// Set the UDP output callback for magicsock mode
// When socket binding is disabled, this callback is used to send packets
// via an external unified socket instead of the internal lwIP UDP PCB.
void wireguardif_set_udp_output(struct netif *netif, wireguard_udp_output_fn fn, void *ctx);
/* Optional zero-copy variant, used instead of the copying callback while set (keeps the ctx given above). */
void wireguardif_set_udp_output_pbuf(struct netif *netif, wireguard_udp_output_pbuf_fn fn);

/* Prepared egress (wireguardif_output_prepared): the pbuf is [16 B header space][plaintext, zero padded to 16][16 B tag]. */
#define WIREGUARDIF_DATA_HDR 16
#define WIREGUARDIF_DATA_PAD(n) ((((size_t)(n)) + 15) & ~(size_t)15)
#define WIREGUARDIF_DATA_ALLOC(n) (WIREGUARDIF_DATA_HDR + WIREGUARDIF_DATA_PAD(n) + WIREGUARD_AUTHTAG_LEN)
err_t wireguardif_output_prepared(struct netif *netif, struct pbuf *wg, uint16_t plain_len, const ip4_addr_t *ipaddr);
/* The same in three steps, the seal outside the lwIP core lock (see wireguardif.c): begin and commit need the lock. */
int wireguardif_tx_begin(struct netif *netif, struct pbuf *wg, uint16_t plain_len, const ip4_addr_t *ipaddr, struct wireguard_tx_job *job, err_t *result);
err_t wireguardif_tx_commit(struct netif *netif, struct wireguard_tx_job *job);

/* Diagnostics builds: per-stage cycle sink, set by the microlink manager (tdongle_wgperf). Compiled out otherwise. */
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
#include "esp_cpu.h"
enum { WGIF_STAGE_LOOKUP, WGIF_STAGE_SEAL, WGIF_STAGE_UDP };
typedef void (*wireguardif_stage_fn)(unsigned stage, uint32_t cycles);
extern wireguardif_stage_fn wireguardif_stage_sink;
#define WGIF_T(t) uint32_t t = (uint32_t)esp_cpu_get_cycle_count()
#define WGIF_LAP(t, stage) do { uint32_t now_ = (uint32_t)esp_cpu_get_cycle_count(); \
    wireguardif_stage_fn sink_ = wireguardif_stage_sink; \
    if (sink_) { sink_((stage), now_ - (t)); } \
    (t) = now_; } while (0)
#else
#define WGIF_T(t) ((void)0)
#define WGIF_LAP(t, stage) ((void)0)
#endif

// Force all peer output through DERP relay callback (cellular mode).
// When enabled, peer_output always uses DERP even if peer has a direct endpoint.
void wireguardif_force_derp_output(struct netif *netif, bool force);

#endif /* _WIREGUARDIF_H_ */
