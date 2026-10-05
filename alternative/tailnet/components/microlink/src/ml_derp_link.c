#include "ml_derp_link.h"
#include <string.h>

static const uint8_t DERP_MAGIC[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};

static inline uint64_t now_of(const ml_derp_link_t *l) { return l->ops->now_ms(l->user); }

const char *ml_derp_link_state_name(ml_derp_link_state_t s) {
    switch (s) {
    case ML_DERP_IDLE: return "idle";
    case ML_DERP_WAITING: return "waiting";
    case ML_DERP_TOKEN: return "token";
    case ML_DERP_TRANSPORT: return "transport";
    case ML_DERP_UPGRADE_TX: return "upgrade_tx";
    case ML_DERP_UPGRADE_RX: return "upgrade_rx";
    case ML_DERP_SERVER_KEY: return "server_key";
    case ML_DERP_CLIENT_INFO: return "client_info";
    case ML_DERP_SERVER_INFO: return "server_info";
    case ML_DERP_READY: return "ready";
    }
    return "?";
}

void ml_derp_link_init(ml_derp_link_t *l, const ml_derp_link_ops_t *ops, void *user) {
    memset(l, 0, sizeof(*l));
    l->ops = ops;
    l->user = user;
    l->state = ML_DERP_IDLE;
    ml_derp_pace_reset(&l->pace, ML_DERP_RETRY_MIN_MS);
}

/* ---------------------------------------------------------------------------
 * Buffers and teardown
 * ------------------------------------------------------------------------- */

static void rx_reset(ml_derp_link_t *l) {
    if (l->rx.sink && l->rx.sink != l->ctl.frame + 5 && l->rx.sink != l->hs.key)
        l->ops->release(l->user, l->rx.sink);
    memset(&l->rx, 0, sizeof(l->rx));
}

static void tx_reset(ml_derp_link_t *l) {
    if (l->tx.buf && l->tx.owned) l->ops->release(l->user, l->tx.buf);
    memset(&l->tx, 0, sizeof(l->tx));
}

/* Release everything the current connection held: transport, buffers, token. */
static void teardown(ml_derp_link_t *l) {
    if (l->transport_open) {
        l->ops->transport_close(l->user);
        l->transport_open = false;
    }
    rx_reset(l);
    tx_reset(l);
    l->ctl.state = ML_DERP_CTL_NONE;
    memset(&l->hs, 0, sizeof(l->hs));
    if (l->token_held) {
        l->ops->token_release(l->user);
        l->token_held = false;
    }
}

static void emit(ml_derp_link_t *l, ml_derp_event_t ev) {
    if (l->ops->event) l->ops->event(l->user, ev);
}

static void set_state(ml_derp_link_t *l, ml_derp_link_state_t s, uint64_t t) {
    l->state = s;
    l->phase_started_ms = t;
}

/* An attempt or an established connection ended. Schedule what comes next. */
static void fail(ml_derp_link_t *l, uint64_t t) {
    bool was_ready = l->state == ML_DERP_READY;
    teardown(l);
    if (was_ready) {
        emit(l, ML_DERP_EV_DISCONNECTED);
        /* A transient flap costs sub-second: 200 ms, then three attempts 500 ms apart, then the ladder. */
        ml_derp_pace_reset(&l->pace, ML_DERP_RETRY_MIN_MS);
        l->burst_left = 2;
        l->burst_gap_ms = 500;
        l->next_attempt_ms = t + 200;
    } else {
        l->stats.connect_failures++;
        emit(l, ML_DERP_EV_CONNECT_FAILED);
        if (l->burst_left) {
            l->burst_left--;
            l->next_attempt_ms = t + l->burst_gap_ms;
        } else {
            ml_derp_pace_failed(&l->pace, t, ML_DERP_RETRY_MAX_MS);
        }
    }
    set_state(l, l->wanted ? ML_DERP_WAITING : ML_DERP_IDLE, t);
}

void ml_derp_link_connect(ml_derp_link_t *l) {
    uint64_t t = now_of(l);
    if (l->state == ML_DERP_READY) return;
    l->wanted = true;
    if (l->state == ML_DERP_IDLE || l->state == ML_DERP_WAITING) {
        ml_derp_pace_reset(&l->pace, ML_DERP_RETRY_MIN_MS);
        l->burst_left = 2;      /* three attempts, two seconds apart, before the ladder */
        l->burst_gap_ms = 2000;
        l->next_attempt_ms = t;
        set_state(l, ML_DERP_WAITING, t);
    }
}

void ml_derp_link_reconnect(ml_derp_link_t *l) {
    uint64_t t = now_of(l);
    bool was_ready = l->state == ML_DERP_READY;
    teardown(l);
    if (was_ready) emit(l, ML_DERP_EV_DISCONNECTED);
    l->wanted = true;
    ml_derp_pace_reset(&l->pace, ML_DERP_RETRY_MIN_MS);
    l->burst_left = 2;
    l->burst_gap_ms = 500;
    l->next_attempt_ms = t + 200;
    set_state(l, ML_DERP_WAITING, t);
}

void ml_derp_link_close(ml_derp_link_t *l) {
    bool was_ready = l->state == ML_DERP_READY;
    l->wanted = false;
    teardown(l);
    l->state = ML_DERP_IDLE;
    if (was_ready) emit(l, ML_DERP_EV_DISCONNECTED);
}

/* ---------------------------------------------------------------------------
 * Transmit
 * ------------------------------------------------------------------------- */

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* Write what is in tx. 1 = frame fully written (tx cleared), 0 = would block, -1 = dead link. */
static int tx_flush(ml_derp_link_t *l, uint64_t t) {
    while (l->tx.off < l->tx.len) {
        int n = l->ops->io_write(l->user, l->tx.buf + l->tx.off, l->tx.len - l->tx.off);
        if (n < 0) return -1;
        if (n == 0) {
            if (t - l->tx.progress_ms > ML_DERP_TX_STALL_MS) {
                l->stats.tx_stalls++;
                return -1;
            }
            return 0;
        }
        l->tx.off += (size_t)n;
        l->tx.progress_ms = t;
    }
    if (l->tx.buf == l->ctl.frame) l->ctl.state = ML_DERP_CTL_NONE;
    tx_reset(l);
    return 1;
}

static void ctl_queue(ml_derp_link_t *l, uint8_t type, const uint8_t *payload, size_t len) {
    l->ctl.frame[0] = type;
    put_be32(l->ctl.frame + 1, (uint32_t)len);
    if (len) memcpy(l->ctl.frame + 5, payload, len);
    l->ctl.len = (uint8_t)(5 + len);
    l->ctl.state = ML_DERP_CTL_QUEUED;
}

/* Start the next frame: a queued control frame first, else the oldest relay packet.
 * Returns 1 when a frame is now in tx, 0 when there is nothing (or nothing can be built now). */
static int tx_begin(ml_derp_link_t *l, uint64_t t) {
    if (l->ctl.state == ML_DERP_CTL_QUEUED) {
        l->tx.buf = l->ctl.frame;
        l->tx.len = l->ctl.len;
        l->tx.off = 0;
        l->tx.owned = false;
        l->tx.progress_ms = t;
        l->ctl.state = ML_DERP_CTL_SENDING;
        return 1;
    }
    ml_derp_out_t item;
    if (!l->ops->tx_pop(l->user, &item)) return 0;
    bool packet = item.frame_type == ML_DERP_FRAME_SEND_PACKET;
    size_t body = (packet ? 32 : 0) + item.len;
    uint8_t *frame = body <= ML_DERP_MAX_FRAME + 32 ? l->ops->alloc(l->user, 5 + body) : NULL;
    if (!frame) {
        /* Memory pressure or an impossible size: this packet is dropped and counted; the link stays up. */
        l->stats.alloc_drops++;
        l->ops->release(l->user, item.data);
        return 1;   /* consumed an item; ask again */
    }
    frame[0] = item.frame_type;
    put_be32(frame + 1, (uint32_t)body);
    if (packet) memcpy(frame + 5, item.dest, 32);
    if (item.len) memcpy(frame + 5 + (packet ? 32 : 0), item.data, item.len);
    l->ops->release(l->user, item.data);
    l->tx.buf = frame;
    l->tx.len = 5 + body;
    l->tx.off = 0;
    l->tx.owned = true;
    l->tx.progress_ms = t;
    return 1;
}

/* One step of the transmit side. 1 = a frame finished, 0 = idle or blocked, -1 = dead link. */
static int tx_step(ml_derp_link_t *l, uint64_t t) {
    if (!l->tx.buf) {
        int begun = tx_begin(l, t);
        if (begun == 0) return 0;
        if (!l->tx.buf) return 1;   /* an item was consumed and dropped */
    }
    int r = tx_flush(l, t);
    if (r > 0) l->stats.frames_tx++;
    return r;
}

/* ---------------------------------------------------------------------------
 * Receive
 * ------------------------------------------------------------------------- */

/* Decide, from the header just read, where the payload goes. 0 ok, -1 protocol violation. */
static int rx_header_done(ml_derp_link_t *l) {
    uint8_t type = l->rx.hdr[0];
    uint32_t len = ((uint32_t)l->rx.hdr[1] << 24) | ((uint32_t)l->rx.hdr[2] << 16) |
                   ((uint32_t)l->rx.hdr[3] << 8) | l->rx.hdr[4];
    l->rx.type = type;
    if (l->state == ML_DERP_SERVER_KEY) {
        if (type != ML_DERP_FRAME_SERVER_KEY || len < sizeof(l->hs.key) || len > ML_DERP_MAX_FRAME) {
            l->stats.protocol_errors++;
            return -1;
        }
        l->rx.sink = l->hs.key;
        l->rx.sink_len = sizeof(l->hs.key);
        l->rx.remaining = len;
        return 0;
    }
    /* The length field is read before anything authenticates it. Bound it by what this firmware can
     * carry: a relayed packet is at most ML_DERP_MAX_FRAME bytes after the 32-byte source key, and every
     * other frame this client acts on is a few dozen bytes. An oversize frame is a protocol violation or a
     * corrupted stream: drop the connection (the caller reconnects) rather than reading on. */
    bool relayed = type == ML_DERP_FRAME_RECV_PACKET;
    if (relayed ? (len <= 32 || len - 32 > ML_DERP_MAX_FRAME) : len > ML_DERP_MAX_FRAME) {
        l->stats.oversize++;
        return -1;
    }
    if (relayed) {
        l->rx.want_src = true;
        len -= 32;
        l->rx.sink = l->ops->alloc(l->user, len);
        if (l->rx.sink) l->rx.sink_len = len;
        else l->stats.alloc_drops++;   /* read it off the wire and drop it; the stream stays in sync */
    } else if (type == ML_DERP_FRAME_PING) {
        if (len <= ML_DERP_PONG_MAX && l->ctl.state == ML_DERP_CTL_NONE) {
            l->rx.sink = l->ctl.frame + 5;
            l->rx.sink_len = len;
        } else {
            l->stats.pings_dropped++;
        }
    }
    l->rx.remaining = len;
    return 0;
}

/* Next complete frame. 1 = frame complete (rx describes it), 0 = need more bytes, -1 = dead link. */
static int rx_next(ml_derp_link_t *l, uint64_t t) {
    if (l->rx.started_ms && t - l->rx.started_ms > ML_DERP_RX_FRAME_MS) {
        l->stats.rx_timeouts++;
        return -1;
    }
    for (;;) {
        if (l->rx.hdr_used < sizeof(l->rx.hdr)) {
            int n = l->ops->io_read(l->user, l->rx.hdr + l->rx.hdr_used, sizeof(l->rx.hdr) - l->rx.hdr_used);
            if (n < 0) return -1;
            if (n == 0) return 0;
            if (!l->rx.started_ms) l->rx.started_ms = t ? t : 1;
            l->last_recv_ms = t;
            l->rx.hdr_used = (uint8_t)(l->rx.hdr_used + n);
            if (l->rx.hdr_used < sizeof(l->rx.hdr)) continue;
            if (rx_header_done(l) < 0) return -1;
        }
        if (l->rx.want_src && l->rx.src_used < sizeof(l->rx.src)) {
            int n = l->ops->io_read(l->user, l->rx.src + l->rx.src_used, sizeof(l->rx.src) - l->rx.src_used);
            if (n < 0) return -1;
            if (n == 0) return 0;
            l->last_recv_ms = t;
            l->rx.src_used = (uint8_t)(l->rx.src_used + n);
            continue;
        }
        if (l->rx.remaining) {
            uint8_t scratch[64];
            uint8_t *into;
            size_t want;
            if (l->rx.sink && l->rx.sink_used < l->rx.sink_len) {
                into = l->rx.sink + l->rx.sink_used;
                want = l->rx.sink_len - l->rx.sink_used;
            } else {
                into = scratch;
                want = sizeof(scratch);
            }
            if (want > l->rx.remaining) want = l->rx.remaining;
            int n = l->ops->io_read(l->user, into, want);
            if (n < 0) return -1;
            if (n == 0) return 0;
            l->last_recv_ms = t;
            if (into != scratch) l->rx.sink_used += (size_t)n;
            l->rx.remaining -= (uint32_t)n;
            continue;
        }
        return 1;
    }
}

static void enter_ready(ml_derp_link_t *l, uint64_t t) {
    memset(&l->hs, 0, sizeof(l->hs));
    set_state(l, ML_DERP_READY, t);
    l->last_recv_ms = t;
    l->stats.connects++;
    ml_derp_pace_reset(&l->pace, ML_DERP_RETRY_MIN_MS);
    l->burst_left = 0;
    if (l->token_held) {
        l->ops->token_release(l->user);
        l->token_held = false;
    }
    /* This is our preferred DERP. */
    if (l->ctl.state == ML_DERP_CTL_NONE) {
        static const uint8_t preferred = 0x01;
        ctl_queue(l, ML_DERP_FRAME_NOTE_PREFERRED, &preferred, 1);
    }
    emit(l, ML_DERP_EV_CONNECTED);
}

/* A complete frame in the data phase. Returns 1 when it was ServerInfo (handshake complete). */
static int rx_dispatch(ml_derp_link_t *l) {
    int server_info = 0;
    switch (l->rx.type) {
    case ML_DERP_FRAME_RECV_PACKET:
        if (l->rx.sink) {
            uint8_t *payload = l->rx.sink;
            size_t len = l->rx.sink_len;
            l->rx.sink = NULL;                    /* ownership moves to the consumer */
            l->ops->deliver(l->user, l->rx.src, payload, len);
        }
        break;
    case ML_DERP_FRAME_PING:
        if (l->rx.sink == l->ctl.frame + 5) {
            l->ctl.frame[0] = ML_DERP_FRAME_PONG;
            put_be32(l->ctl.frame + 1, (uint32_t)l->rx.sink_len);
            l->ctl.len = (uint8_t)(5 + l->rx.sink_len);
            l->ctl.state = ML_DERP_CTL_QUEUED;
            l->stats.pings_answered++;
        }
        break;
    case ML_DERP_FRAME_SERVER_INFO:
        server_info = 1;
        break;
    default:   /* KeepAlive, PeerGone, anything newer: nothing to act on */
        break;
    }
    l->stats.frames_rx++;
    rx_reset(l);
    return server_info;
}

/* ---------------------------------------------------------------------------
 * Handshake pieces
 * ------------------------------------------------------------------------- */

/* Read the HTTP response a byte at a time, so nothing of the DERP stream behind it is consumed.
 * 1 = complete 101, 0 = need more, -1 = refused or malformed. */
static int upgrade_rx(ml_derp_link_t *l, uint64_t t) {
    for (;;) {
        uint8_t byte;
        int n = l->ops->io_read(l->user, &byte, 1);
        if (n < 0) return -1;
        if (n == 0) return 0;
        l->last_recv_ms = t;
        if (l->hs.seen < sizeof(l->hs.line)) l->hs.line[l->hs.seen] = byte;
        l->hs.seen++;
        memmove(l->hs.tail, l->hs.tail + 1, 3);
        l->hs.tail[3] = byte;
        if (l->hs.seen >= 4 && memcmp(l->hs.tail, "\r\n\r\n", 4) == 0) {
            /* "HTTP/1.x 101": the status code, not any "101" somewhere in the headers. */
            bool ok = l->hs.seen >= 12 && memcmp(l->hs.line, "HTTP/1.", 7) == 0 && l->hs.line[8] == ' ' &&
                      memcmp(l->hs.line + 9, "101", 3) == 0;
            if (!ok) l->stats.protocol_errors++;
            return ok ? 1 : -1;
        }
        if (l->hs.seen >= ML_DERP_HTTP_MAX) {
            l->stats.protocol_errors++;
            return -1;
        }
    }
}

/* ---------------------------------------------------------------------------
 * The service step
 * ------------------------------------------------------------------------- */

static void service_ready(ml_derp_link_t *l, uint64_t t) {
    /* Transmit first, in a bounded burst, then receive. Neither side can starve the other and
     * neither can wait: a blocked direction simply resumes on the next call. */
    for (unsigned i = 0; i < ML_DERP_TX_BURST && now_of(l) - t < ML_DERP_SLICE_MS; i++) {
        int r = tx_step(l, t);
        if (r < 0) { fail(l, t); return; }
        if (r == 0) break;
    }
    for (unsigned i = 0; i < ML_DERP_RX_BURST && now_of(l) - t < ML_DERP_SLICE_MS; i++) {
        int r = rx_next(l, t);
        if (r < 0) { fail(l, t); return; }
        if (r == 0) break;
        rx_dispatch(l);
    }
    /* A Pong answered above goes out now rather than on the next pass. */
    if (l->ctl.state == ML_DERP_CTL_QUEUED && !l->tx.buf) {
        if (tx_step(l, t) < 0) { fail(l, t); return; }
    }
    if (l->last_recv_ms && t > l->last_recv_ms && t - l->last_recv_ms > ML_DERP_STALE_MS) {
        /* Server keepalives arrive every ~15-60 s: prolonged silence means the relay is gone even though
         * TCP looks alive (the same self-fed-liveness class as the control stream watchdog). */
        l->stats.stale++;
        emit(l, ML_DERP_EV_RX_STALE);
        fail(l, t);
    }
}

void ml_derp_link_service(ml_derp_link_t *l) {
    uint64_t t = now_of(l);
    for (unsigned guard = 0; guard < 16; guard++) {
        if (l->state >= ML_DERP_TRANSPORT && l->state < ML_DERP_READY && t - l->connect_started_ms > ML_DERP_CONNECT_MS) {
            fail(l, t);
            continue;
        }
        switch (l->state) {
        case ML_DERP_IDLE:
            return;

        case ML_DERP_WAITING: {
            bool clock = l->ops->clock_valid(l->user);
            if (!clock || l->burst_left == 0) {
                /* The ladder. A wall clock that is not set holds the connect back without counting as a
                 * relay failure (ml_derp_pace.h). */
                uint32_t deferrals = l->pace.deferrals;
                bool due = ml_derp_pace_due(&l->pace, t, clock, ML_DERP_RETRY_MIN_MS);
                if (!clock) {
                    if (l->pace.deferrals != deferrals) emit(l, ML_DERP_EV_CLOCK_DEFERRED);
                    return;
                }
                if (!due) return;
            } else if (t < l->next_attempt_ms) {
                return;
            }
            set_state(l, ML_DERP_TOKEN, t);
            continue;
        }

        case ML_DERP_TOKEN:
            /* Only one membership negotiates at a time (ml_negotiation.h). Waiting is not a failure and
             * costs nothing: the shared task keeps serving everyone else. */
            if (!l->ops->token_try(l->user)) return;
            l->token_held = true;
            l->connect_started_ms = t;
            set_state(l, ML_DERP_TRANSPORT, t);
            continue;

        case ML_DERP_TRANSPORT: {
            if (!l->transport_open) {
                if (l->ops->transport_open(l->user) < 0) { fail(l, t); continue; }
                l->transport_open = true;
            }
            int r = l->ops->transport_step(l->user, t);
            if (r == ML_DERP_T_PENDING) return;
            if (r < 0) { fail(l, t); continue; }
            set_state(l, ML_DERP_UPGRADE_TX, t);
            continue;
        }

        case ML_DERP_UPGRADE_TX: {
            if (!l->tx.buf) {
                uint8_t *buf = l->ops->alloc(l->user, 256);
                if (!buf) { fail(l, t); continue; }
                size_t n = l->ops->make_upgrade_request(l->user, buf, 256);
                if (!n) { l->ops->release(l->user, buf); fail(l, t); continue; }
                l->tx.buf = buf; l->tx.len = n; l->tx.off = 0; l->tx.owned = true; l->tx.progress_ms = t;
            }
            int r = tx_flush(l, t);
            if (r < 0) { fail(l, t); continue; }
            if (r == 0) return;
            set_state(l, ML_DERP_UPGRADE_RX, t);
            continue;
        }

        case ML_DERP_UPGRADE_RX: {
            int r = upgrade_rx(l, t);
            if (r < 0) { fail(l, t); continue; }
            if (r == 0) {
                if (t - l->phase_started_ms > ML_DERP_PHASE_MS) { fail(l, t); continue; }
                return;
            }
            memset(&l->hs, 0, sizeof(l->hs));
            set_state(l, ML_DERP_SERVER_KEY, t);
            continue;
        }

        case ML_DERP_SERVER_KEY: {
            int r = rx_next(l, t);
            if (r < 0) { fail(l, t); continue; }
            if (r == 0) {
                if (t - l->phase_started_ms > ML_DERP_PHASE_MS) { l->stats.rx_timeouts++; fail(l, t); continue; }
                return;
            }
            if (memcmp(l->hs.key, DERP_MAGIC, sizeof(DERP_MAGIC)) != 0) {
                l->stats.protocol_errors++;
                fail(l, t);
                continue;
            }
            uint8_t server_key[32];
            memcpy(server_key, l->hs.key + 8, 32);
            rx_reset(l);
            uint8_t info[192];
            size_t info_len = 0;
            if (!l->ops->make_client_info(l->user, server_key, info, sizeof(info), &info_len)) { fail(l, t); continue; }
            uint8_t *frame = l->ops->alloc(l->user, 5 + info_len);
            if (!frame) { fail(l, t); continue; }
            frame[0] = ML_DERP_FRAME_CLIENT_INFO;
            put_be32(frame + 1, (uint32_t)info_len);
            memcpy(frame + 5, info, info_len);
            memset(info, 0, sizeof(info));
            l->tx.buf = frame; l->tx.len = 5 + info_len; l->tx.off = 0; l->tx.owned = true; l->tx.progress_ms = t;
            set_state(l, ML_DERP_CLIENT_INFO, t);
            continue;
        }

        case ML_DERP_CLIENT_INFO: {
            int r = tx_flush(l, t);
            if (r < 0) { fail(l, t); continue; }
            if (r == 0) return;
            set_state(l, ML_DERP_SERVER_INFO, t);
            continue;
        }

        case ML_DERP_SERVER_INFO: {
            int r = rx_next(l, t);
            if (r < 0) { fail(l, t); continue; }
            if (r > 0) {
                if (rx_dispatch(l)) enter_ready(l, t);
                continue;   /* another frame type before ServerInfo is read and ignored */
            }
            if (t - l->phase_started_ms > ML_DERP_PHASE_MS) {
                /* No ServerInfo: carry on, as the blocking client did. Mid-frame it would desync the stream. */
                if (l->rx.hdr_used) { l->stats.rx_timeouts++; fail(l, t); }
                else enter_ready(l, t);
                continue;
            }
            return;
        }

        case ML_DERP_READY:
            service_ready(l, t);
            return;
        }
    }
}
