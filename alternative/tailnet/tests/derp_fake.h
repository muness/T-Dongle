/* A scripted DERP world for host tests: byte pipes with controllable stalls, and a server that speaks
 * the DERP protocol (HTTP upgrade, ServerKey, ClientInfo, ServerInfo, then data frames) over them.
 * Time is virtual: the test advances `fake_now` and calls fake_server_poll / the link under test. */
#pragma once
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_derp_link.h"

typedef struct {
    uint8_t *d;
    size_t n, cap, rd, visible;
    bool hold;                  /* bytes pushed while held are not readable until release */
} fpipe_t;

static void fpipe_reset(fpipe_t *p) { free(p->d); memset(p, 0, sizeof(*p)); }
static void fpipe_push(fpipe_t *p, const void *data, size_t len) {
    if (p->n + len > p->cap) { p->cap = (p->n + len) * 2 + 64; p->d = realloc(p->d, p->cap); }
    memcpy(p->d + p->n, data, len);
    p->n += len;
    if (!p->hold) p->visible = p->n;
}
static void fpipe_release(fpipe_t *p) { p->hold = false; p->visible = p->n; }
static size_t fpipe_avail(const fpipe_t *p) { return p->visible - p->rd; }

typedef struct {
    const char *name;
    uint64_t *clock;            /* virtual milliseconds */
    fpipe_t s2c, c2s;
    size_t read_chunk, write_chunk;     /* 0 = unlimited per call */
    bool write_blocked;
    bool http_silent;                   /* server never answers the upgrade */
    bool no_server_info;                /* server never sends ServerInfo */
    uint64_t transport_delay_ms;
    bool transport_hang;
    uint64_t transport_started;
    int transports_opened, transports_closed, transport_steps;
    /* server */
    enum { SV_WAIT_REQ, SV_WAIT_CI, SV_READY } sv;
    size_t parsed;
    unsigned note_preferred, pongs_seen, ci_seen;
    /* relay queue of packets the client must send */
    struct { uint8_t *data; size_t len; } q[256];
    unsigned qh, qt;
    /* measurements */
    unsigned delivered, delivered_bad, server_saw, server_bad;
    uint64_t max_rx_latency, max_tx_latency, last_rx_ms, last_tx_ms;
    unsigned connected_events, disconnected_events, failed_events, deferred_events;
    long live_allocs;
    bool alloc_fail;
    /* negotiation token (shared pointer; NULL = free pass) */
    int *token_owner;           /* shared between fakes: 0 = free, else holder id */
    int my_id;
    ml_derp_link_t link;
} fake_t;

static uint64_t fake_time(void *u) { return *((fake_t *)u)->clock; }
static void *fake_alloc(void *u, size_t n) { fake_t *f = u; if (f->alloc_fail) return NULL; f->live_allocs++; return malloc(n); }
static void fake_release_block(void *u, void *p) { fake_t *f = u; if (p) { f->live_allocs--; free(p); } }

static int fake_read(void *u, uint8_t *buf, size_t len) {
    fake_t *f = u;
    size_t n = fpipe_avail(&f->s2c);
    if (!n) return 0;
    if (n > len) n = len;
    if (f->read_chunk && n > f->read_chunk) n = f->read_chunk;
    memcpy(buf, f->s2c.d + f->s2c.rd, n);
    f->s2c.rd += n;
    return (int)n;
}
static int fake_write(void *u, const uint8_t *buf, size_t len) {
    fake_t *f = u;
    if (f->write_blocked) return 0;
    size_t n = len;
    if (f->write_chunk && n > f->write_chunk) n = f->write_chunk;
    fpipe_push(&f->c2s, buf, n);
    return (int)n;
}
static int fake_transport_open(void *u) {
    fake_t *f = u;
    f->transports_opened++;
    fpipe_reset(&f->s2c); fpipe_reset(&f->c2s);
    f->sv = SV_WAIT_REQ; f->parsed = 0;
    f->transport_started = *f->clock;
    return 0;
}
static int fake_transport_step(void *u, uint64_t now) {
    fake_t *f = u;
    f->transport_steps++;
    if (f->transport_hang) return ML_DERP_T_PENDING;
    return now - f->transport_started >= f->transport_delay_ms ? ML_DERP_T_DONE : ML_DERP_T_PENDING;
}
static void fake_transport_close(void *u) { ((fake_t *)u)->transports_closed++; }
static bool fake_clock_valid(void *u) { (void)u; return true; }
static size_t fake_upgrade(void *u, uint8_t *out, size_t cap) {
    (void)u;
    const char *r = "GET /derp HTTP/1.1\r\nHost: derp.test\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n";
    size_t n = strlen(r);
    if (n > cap) return 0;
    memcpy(out, r, n);
    return n;
}
static bool fake_client_info(void *u, const uint8_t key[32], uint8_t *out, size_t cap, size_t *len) {
    (void)u; (void)key;
    if (cap < 118) return false;
    for (unsigned i = 0; i < 118; i++) out[i] = (uint8_t)(0xC0 + i);
    *len = 118;
    return true;
}
static bool fake_tx_pop(void *u, ml_derp_out_t *item) {
    fake_t *f = u;
    if (f->qh == f->qt) return false;
    unsigned i = f->qh++ % 256;
    memset(item, 0, sizeof(*item));
    memset(item->dest, 0xD0, 32);
    item->data = f->q[i].data;       /* queue-owned allocation handed to the link */
    item->len = f->q[i].len;
    item->frame_type = ML_DERP_FRAME_SEND_PACKET;
    return true;
}
static void fake_enqueue(fake_t *f, uint64_t ts, uint32_t seq, size_t len) {
    assert(f->qt - f->qh < 256);
    uint8_t *d = malloc(len);
    f->live_allocs++;
    memcpy(d, &ts, 8); memcpy(d + 8, &seq, 4);
    for (size_t i = 12; i < len; i++) d[i] = (uint8_t)(seq * 31 + i);
    f->q[f->qt++ % 256] = (typeof(f->q[0])){d, len};
}
static void fake_deliver(void *u, const uint8_t src[32], uint8_t *p, size_t len) {
    fake_t *f = u;
    uint64_t ts; uint32_t seq;
    memcpy(&ts, p, 8); memcpy(&seq, p + 8, 4);
    bool ok = len >= 12 && src[0] == 0xAA;
    for (size_t i = 12; ok && i < len; i++) ok = p[i] == (uint8_t)(seq * 31 + i);
    if (ok) {
        f->delivered++;
        uint64_t lat = *f->clock - ts;
        if (lat > f->max_rx_latency) f->max_rx_latency = lat;
        f->last_rx_ms = *f->clock;
    } else f->delivered_bad++;
    fake_release_block(u, p);
}
static void fake_event(void *u, ml_derp_event_t ev) {
    fake_t *f = u;
    switch (ev) {
    case ML_DERP_EV_CONNECTED: f->connected_events++; break;
    case ML_DERP_EV_DISCONNECTED:
        f->disconnected_events++;
        while (f->qh != f->qt) { free(f->q[f->qh++ % 256].data); f->live_allocs--; }   /* the glue drains the queue */
        break;
    case ML_DERP_EV_CONNECT_FAILED: f->failed_events++; break;
    case ML_DERP_EV_CLOCK_DEFERRED: f->deferred_events++; break;
    default: break;
    }
}
static bool fake_token_try(void *u) {
    fake_t *f = u;
    if (!f->token_owner) return true;
    if (*f->token_owner == 0 || *f->token_owner == f->my_id) { *f->token_owner = f->my_id; return true; }
    return false;
}
static void fake_token_release(void *u) {
    fake_t *f = u;
    if (f->token_owner && *f->token_owner == f->my_id) *f->token_owner = 0;
}

static const ml_derp_link_ops_t fake_ops = {
    .now_ms = fake_time, .alloc = fake_alloc, .release = fake_release_block,
    .io_read = fake_read, .io_write = fake_write,
    .transport_open = fake_transport_open, .transport_step = fake_transport_step, .transport_close = fake_transport_close,
    .clock_valid = fake_clock_valid, .make_upgrade_request = fake_upgrade, .make_client_info = fake_client_info,
    .tx_pop = fake_tx_pop, .deliver = fake_deliver, .event = fake_event,
    .token_try = fake_token_try, .token_release = fake_token_release,
};

static void fake_init(fake_t *f, const char *name, uint64_t *clock, int id) {
    memset(f, 0, sizeof(*f));
    f->name = name; f->clock = clock; f->my_id = id;
    ml_derp_link_init(&f->link, &fake_ops, f);
}

/* Server -> client: a RecvPacket carrying a stamped, patterned payload. */
static size_t fake_server_frame(uint8_t *out, uint64_t ts, uint32_t seq, size_t plen) {
    uint32_t body = 32 + (uint32_t)plen;
    out[0] = ML_DERP_FRAME_RECV_PACKET;
    out[1] = body >> 24; out[2] = body >> 16; out[3] = body >> 8; out[4] = body;
    memset(out + 5, 0xAA, 32);
    memcpy(out + 37, &ts, 8); memcpy(out + 45, &seq, 4);
    for (size_t i = 12; i < plen; i++) out[37 + i] = (uint8_t)(seq * 31 + i);
    return 5 + body;
}
static void fake_server_send(fake_t *f, uint64_t ts, uint32_t seq, size_t plen) {
    uint8_t *frame = malloc(5 + 32 + plen);
    size_t n = fake_server_frame(frame, ts, seq, plen);
    fpipe_push(&f->s2c, frame, n);
    free(frame);
}

static void fake_server_poll(fake_t *f) {
    if (!f->c2s.d) return;
    for (;;) {
        size_t avail = f->c2s.n - f->parsed;
        switch (f->sv) {
        case SV_WAIT_REQ: {
            size_t end = 0;
            for (size_t i = f->parsed; i + 4 <= f->c2s.n; i++)
                if (!memcmp(f->c2s.d + i, "\r\n\r\n", 4)) { end = i + 4; break; }
            if (!end) return;
            f->parsed = end;
            if (f->http_silent) return;
            const char *resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
            fpipe_push(&f->s2c, resp, strlen(resp));
            uint8_t key[5 + 40] = {ML_DERP_FRAME_SERVER_KEY, 0, 0, 0, 40, 0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
            for (unsigned i = 0; i < 32; i++) key[13 + i] = (uint8_t)(0x10 + i);
            fpipe_push(&f->s2c, key, sizeof(key));
            f->sv = SV_WAIT_CI;
            continue;
        }
        case SV_WAIT_CI: {
            if (avail < 5) return;
            uint32_t len = (f->c2s.d[f->parsed + 1] << 24) | (f->c2s.d[f->parsed + 2] << 16) | (f->c2s.d[f->parsed + 3] << 8) | f->c2s.d[f->parsed + 4];
            if (avail < 5 + len) return;
            assert(f->c2s.d[f->parsed] == ML_DERP_FRAME_CLIENT_INFO && len == 118);
            f->parsed += 5 + len;
            f->ci_seen++;
            if (!f->no_server_info) {
                uint8_t info[5 + 20] = {ML_DERP_FRAME_SERVER_INFO, 0, 0, 0, 20};
                fpipe_push(&f->s2c, info, sizeof(info));
            }
            f->sv = SV_READY;
            continue;
        }
        case SV_READY: {
            if (avail < 5) return;
            uint8_t type = f->c2s.d[f->parsed];
            uint32_t len = (f->c2s.d[f->parsed + 1] << 24) | (f->c2s.d[f->parsed + 2] << 16) | (f->c2s.d[f->parsed + 3] << 8) | f->c2s.d[f->parsed + 4];
            if (avail < 5 + len) return;
            const uint8_t *body = f->c2s.d + f->parsed + 5;
            if (type == ML_DERP_FRAME_NOTE_PREFERRED) f->note_preferred++;
            else if (type == ML_DERP_FRAME_PONG) f->pongs_seen++;
            else if (type == ML_DERP_FRAME_SEND_PACKET) {
                uint64_t ts; uint32_t seq;
                memcpy(&ts, body + 32, 8); memcpy(&seq, body + 40, 4);
                bool ok = len >= 44 && body[0] == 0xD0;
                for (size_t i = 12; ok && i < len - 32; i++) ok = body[32 + i] == (uint8_t)(seq * 31 + i);
                if (ok) {
                    f->server_saw++;
                    uint64_t lat = *f->clock - ts;
                    if (lat > f->max_tx_latency) f->max_tx_latency = lat;
                    f->last_tx_ms = *f->clock;
                } else f->server_bad++;
            }
            f->parsed += 5 + len;
            continue;
        }
        }
    }
}
