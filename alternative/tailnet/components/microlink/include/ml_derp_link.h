/**
 * @file ml_derp_link.h
 * @brief One membership's DERP relay connection as a non-blocking state machine.
 *
 * ADR 0013: ONE DERP task serves every membership. That is only sound if no step of
 * a link can wait on its server. The old per-membership task blocked inside
 * mbedtls_ssl_read for up to 5 s per frame, inside mbedtls_ssl_write for up to 3 s,
 * and inside connect (DNS, TCP, TLS, HTTP upgrade, ServerKey/ClientInfo/ServerInfo)
 * for 10 s per step. Shared, any of those would stall every other membership's relay.
 *
 * This module is the same DERP client (derp/derphttp: GET /derp with Upgrade: DERP,
 * ServerKey, ClientInfo, ServerInfo, NotePreferred, then RecvPacket/SendPacket/Ping/
 * Pong/PeerGone frames) restructured so that each call does a bounded amount of work
 * and returns:
 *
 *   - reads and writes never wait: the transport reports "would block" and the link
 *     keeps the half-read record or half-written frame and resumes on the next call;
 *   - every wait has a deadline kept in the link (a stalled record fails the link
 *     after ML_DERP_RX_FRAME_MS, a stalled write after ML_DERP_TX_STALL_MS, a connect
 *     after ML_DERP_CONNECT_MS), so one dead server costs its own membership a
 *     reconnect and nobody else anything;
 *   - the platform (TLS, sockets, DNS, the negotiation token, packet memory) arrives
 *     through ml_derp_link_ops_t, so the same code runs in the firmware and in host
 *     tests with a scripted server.
 *
 * Calls for one link must be serialised (the DERP task, or the mux lock). Nothing here
 * allocates except through ops->alloc, so a packet pool can replace malloc later.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ml_derp_pace.h"

/* DERP frame types (tailscale derp/derp.go). */
#define ML_DERP_FRAME_SERVER_KEY    0x01
#define ML_DERP_FRAME_CLIENT_INFO   0x02
#define ML_DERP_FRAME_SERVER_INFO   0x03
#define ML_DERP_FRAME_SEND_PACKET   0x04
#define ML_DERP_FRAME_RECV_PACKET   0x05
#define ML_DERP_FRAME_KEEP_ALIVE    0x06
#define ML_DERP_FRAME_NOTE_PREFERRED 0x07
#define ML_DERP_FRAME_PEER_GONE     0x08
#define ML_DERP_FRAME_PING          0x12
#define ML_DERP_FRAME_PONG          0x13

/* Largest payload accepted in one DERP frame after the 32-byte source key of a RecvPacket (and the
 * cap for every other post-handshake frame). See the derivation in microlink_internal.h. */
#ifndef ML_DERP_MAX_FRAME
#define ML_DERP_MAX_FRAME (1500 + 64)
#endif

/* Deadlines. They are the old blocking limits, now enforced without blocking. */
#define ML_DERP_RX_FRAME_MS      5000   /* a record that started must finish within this */
#define ML_DERP_TX_STALL_MS      3000   /* a write that makes no progress for this long is a dead link */
#define ML_DERP_PHASE_MS        10000   /* one handshake phase (upgrade, ServerKey, ServerInfo) */
#define ML_DERP_CONNECT_MS      30000   /* whole attempt, token granted to READY */
#define ML_DERP_STALE_MS        90000   /* nothing received at all (server keepalives come every ~15-60 s) */
#define ML_DERP_RETRY_MIN_MS     5000
#define ML_DERP_RETRY_MAX_MS    60000
#define ML_DERP_HTTP_MAX          512   /* upgrade response header bytes */
#define ML_DERP_PONG_MAX           64   /* server ping payloads we echo (the protocol uses 8) */
#define ML_DERP_SKIP_MAX         65536  /* largest frame we are willing to read and discard */

/* Work per service call, so one membership cannot hold the shared task. */
#define ML_DERP_TX_BURST          4
#define ML_DERP_RX_BURST          8
#define ML_DERP_SLICE_MS         30

enum { ML_DERP_T_PENDING = 0, ML_DERP_T_DONE = 1, ML_DERP_T_FAIL = -1 };

typedef enum {
    ML_DERP_IDLE,         /* not wanted */
    ML_DERP_WAITING,      /* wanted; backoff, burst spacing or the wall clock */
    ML_DERP_TOKEN,        /* wanted and ready; waiting for the negotiation token */
    ML_DERP_TRANSPORT,    /* DNS, TCP, TLS (platform steps) */
    ML_DERP_UPGRADE_TX,   /* GET /derp ... Upgrade: DERP */
    ML_DERP_UPGRADE_RX,   /* HTTP/1.1 101 */
    ML_DERP_SERVER_KEY,   /* ServerKey frame */
    ML_DERP_CLIENT_INFO,  /* our ClientInfo frame going out */
    ML_DERP_SERVER_INFO,  /* ServerInfo frame */
    ML_DERP_READY         /* relaying */
} ml_derp_link_state_t;

typedef enum {
    ML_DERP_EV_CONNECTED,       /* READY entered */
    ML_DERP_EV_DISCONNECTED,    /* READY left */
    ML_DERP_EV_CONNECT_FAILED,  /* an attempt ended before READY */
    ML_DERP_EV_RX_STALE,        /* the staleness watchdog fired (also followed by DISCONNECTED) */
    ML_DERP_EV_CLOCK_DEFERRED   /* the first attempt is held back for the wall clock */
} ml_derp_event_t;

typedef struct {
    uint8_t dest[32];
    uint8_t *data;       /* ownership passes to the link; released with ops->release */
    size_t len;
    uint8_t frame_type;  /* ML_DERP_FRAME_SEND_PACKET, or another frame the caller built */
} ml_derp_out_t;

typedef struct {
    /* Time and memory. alloc may return NULL; the link counts and recovers. */
    uint64_t (*now_ms)(void *user);
    void *(*alloc)(void *user, size_t bytes);
    void (*release)(void *user, void *block);

    /* Established transport (TLS). >0 bytes moved, 0 would block, <0 the connection is gone. */
    int (*io_read)(void *user, uint8_t *buf, size_t len);
    int (*io_write)(void *user, const uint8_t *buf, size_t len);

    /* Transport bring-up (DNS, TCP connect, TLS handshake), advanced one bounded step per call. */
    int (*transport_open)(void *user);                    /* <0: cannot even start */
    int (*transport_step)(void *user, uint64_t now_ms);   /* ML_DERP_T_* */
    void (*transport_close)(void *user);                  /* idempotent; also used for teardown */
    bool (*clock_valid)(void *user);                      /* certificates cannot be judged without a wall clock */

    /* HTTP upgrade request text (fills `out`, returns its length, 0 on failure). */
    size_t (*make_upgrade_request)(void *user, uint8_t *out, size_t cap);
    /* ClientInfo payload: node key, nonce and the sealed box for the server key. */
    bool (*make_client_info)(void *user, const uint8_t server_key[32], uint8_t *out, size_t cap, size_t *len);

    /* Packets to relay, oldest first; false when none. */
    bool (*tx_pop)(void *user, ml_derp_out_t *item);
    /* A RecvPacket: ownership of `payload` passes to the callee. */
    void (*deliver)(void *user, const uint8_t src[32], uint8_t *payload, size_t len);
    void (*event)(void *user, ml_derp_event_t ev);

    /* Negotiation token (ml_negotiation.h). token_try is polled until it returns true. */
    bool (*token_try)(void *user);
    void (*token_release)(void *user);
} ml_derp_link_ops_t;

typedef struct {
    uint32_t frames_rx, frames_tx;
    uint32_t connects, connect_failures;
    uint32_t rx_timeouts, tx_stalls, oversize, alloc_drops, protocol_errors, stale;
    uint32_t pings_answered, pings_dropped;
} ml_derp_link_stats_t;

typedef struct ml_derp_link {
    const ml_derp_link_ops_t *ops;
    void *user;
    ml_derp_link_state_t state;
    bool wanted;
    ml_derp_pace_t pace;
    uint8_t burst_left;           /* quick retries before the backoff ladder */
    uint32_t burst_gap_ms;
    uint64_t next_attempt_ms;
    uint64_t connect_started_ms, phase_started_ms, last_recv_ms;
    bool token_held;
    bool transport_open;

    /* Handshake scratch, live only before READY. */
    struct {
        uint8_t tail[4];           /* last four header bytes seen */
        uint8_t line[16];          /* start of the status line */
        uint16_t seen;             /* header bytes consumed */
        uint8_t key[40];           /* ServerKey: magic + key */
        uint8_t key_used;
        bool key_ok;
    } hs;

    /* Receive: one frame at a time, resumable. */
    struct {
        uint8_t hdr[5];
        uint8_t hdr_used;
        uint8_t type;
        uint32_t remaining;        /* payload bytes still to come (after the source key) */
        uint8_t src[32];
        uint8_t src_used;
        bool want_src;
        uint8_t *sink;             /* payload being collected, or NULL to discard */
        size_t sink_len, sink_used;
        uint64_t started_ms;       /* 0 = between frames */
    } rx;

    /* Transmit: one frame in flight; control frames queue behind it. */
    struct {
        uint8_t *buf;
        size_t len, off;
        bool owned;                /* buf came from ops->alloc (false: it is ctl.frame) */
        uint64_t progress_ms;
    } tx;
    /* Control frames (Pong, NotePreferred) are built in place: no allocation, so they cannot fail
     * under memory pressure. One at a time; a ping that arrives while one is queued is dropped. */
    struct {
        enum { ML_DERP_CTL_NONE, ML_DERP_CTL_QUEUED, ML_DERP_CTL_SENDING } state;
        uint8_t frame[5 + ML_DERP_PONG_MAX];
        uint8_t len;               /* bytes of frame in use */
    } ctl;

    ml_derp_link_stats_t stats;
} ml_derp_link_t;

void ml_derp_link_init(ml_derp_link_t *l, const ml_derp_link_ops_t *ops, void *user);

/* The control plane wants a relay (first connect, ML_EVT_DERP_CONNECT_REQ). */
void ml_derp_link_connect(ml_derp_link_t *l);
/* Drop the current connection and dial again (ML_EVT_DERP_RECONNECT). */
void ml_derp_link_reconnect(ml_derp_link_t *l);
/* Tear down and stop wanting a relay. Releases the token and every buffer. Idempotent. */
void ml_derp_link_close(ml_derp_link_t *l);

/* Bounded work: advance the state machine, move frames. Never blocks. */
void ml_derp_link_service(ml_derp_link_t *l);

static inline bool ml_derp_link_ready(const ml_derp_link_t *l) { return l->state == ML_DERP_READY; }
const char *ml_derp_link_state_name(ml_derp_link_state_t s);
