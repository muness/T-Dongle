/* The slicing check with real threads, real sockets and a real clock (built with ASan/UBSan and TSan).
 *
 * One "DERP task" thread runs ml_mux_pass() every 10 ms over two memberships. Each membership talks to a
 * server thread over a socketpair that speaks the DERP protocol. Server A sends the first 100 bytes of a
 * record and then sleeps 5 s mid-record; server B streams stamped packets to us every 20 ms and timestamps
 * what we send. Producer threads enqueue relay packets from outside the DERP task, and a churn thread
 * attaches and detaches a third membership throughout. B's latency is measured on the wall clock. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ml_derp_link.h"
#include "ml_mux.h"

#define STALL_MS 5000
#define MAX_LAT_MS 120          /* wall clock under sanitizers on a loaded machine; the stall is 5000 */

typedef struct {
    const char *name;
    int fd;                      /* our end */
    int sfd;                     /* server end */
    ml_derp_link_t link;
    pthread_mutex_t qlock;
    struct { uint8_t *d; size_t n; } q[512];
    unsigned qh, qt;
    atomic_uint delivered, delivered_bad, server_saw, server_bad, connected, disconnected;
    atomic_ullong max_rx_lat, max_tx_lat;
    atomic_long live;
    int stall_server;            /* server A */
    atomic_bool stop;
} member_t;

static uint64_t now_ms(void *u) { (void)u; return ml_port_mono_ms(); }
static void *m_alloc(void *u, size_t n) { atomic_fetch_add(&((member_t *)u)->live, 1); return malloc(n); }
static void m_release(void *u, void *p) { if (p) { atomic_fetch_sub(&((member_t *)u)->live, 1); free(p); } }
static int m_read(void *u, uint8_t *b, size_t n) {
    ssize_t r = read(((member_t *)u)->fd, b, n);
    if (r > 0) return (int)r;
    if (r < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    return -1;
}
static int m_write(void *u, const uint8_t *b, size_t n) {
    ssize_t r = write(((member_t *)u)->fd, b, n);
    if (r >= 0) return (int)r;
    return (errno == EAGAIN || errno == EINTR) ? 0 : -1;
}
static int m_open(void *u) { (void)u; return 0; }
static int m_step(void *u, uint64_t t) { (void)u; (void)t; return ML_DERP_T_DONE; }
static void m_close(void *u) { (void)u; }
static bool m_clock(void *u) { (void)u; return true; }
static size_t m_req(void *u, uint8_t *o, size_t cap) {
    (void)u;
    const char *r = "GET /derp HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n";
    size_t n = strlen(r);
    if (n > cap) return 0;
    memcpy(o, r, n);
    return n;
}
static bool m_info(void *u, const uint8_t k[32], uint8_t *o, size_t cap, size_t *len) {
    (void)u; (void)k;
    if (cap < 118) return false;
    memset(o, 0xC1, 118);
    *len = 118;
    return true;
}
static bool m_pop(void *u, ml_derp_out_t *it) {
    member_t *m = u;
    bool got = false;
    pthread_mutex_lock(&m->qlock);
    if (m->qh != m->qt) {
        unsigned i = m->qh++ % 512;
        memset(it, 0, sizeof(*it));
        memset(it->dest, 0xD0, 32);
        it->data = m->q[i].d; it->len = m->q[i].n; it->frame_type = ML_DERP_FRAME_SEND_PACKET;
        got = true;
    }
    pthread_mutex_unlock(&m->qlock);
    return got;
}
static void note_max(atomic_ullong *a, unsigned long long v) {
    unsigned long long cur = atomic_load(a);
    while (v > cur && !atomic_compare_exchange_weak(a, &cur, v)) {}
}
static void m_deliver(void *u, const uint8_t src[32], uint8_t *p, size_t len) {
    member_t *m = u;
    uint64_t ts; memcpy(&ts, p, 8);
    if (len >= 12 && src[0] == 0xAA) { atomic_fetch_add(&m->delivered, 1); note_max(&m->max_rx_lat, ml_port_mono_ms() - ts); }
    else atomic_fetch_add(&m->delivered_bad, 1);
    m_release(u, p);
}
static void m_event(void *u, ml_derp_event_t e) {
    member_t *m = u;
    if (e == ML_DERP_EV_CONNECTED) atomic_fetch_add(&m->connected, 1);
    if (e == ML_DERP_EV_DISCONNECTED) atomic_fetch_add(&m->disconnected, 1);
}
static pthread_mutex_t token_lock = PTHREAD_MUTEX_INITIALIZER;
static member_t *token_holder;
static bool m_token(void *u) {
    bool ok;
    pthread_mutex_lock(&token_lock);
    ok = !token_holder || token_holder == u;
    if (ok) token_holder = u;
    pthread_mutex_unlock(&token_lock);
    return ok;
}
static void m_untoken(void *u) {
    pthread_mutex_lock(&token_lock);
    if (token_holder == u) token_holder = NULL;
    pthread_mutex_unlock(&token_lock);
}
static const ml_derp_link_ops_t ops = {
    .now_ms = now_ms, .alloc = m_alloc, .release = m_release, .io_read = m_read, .io_write = m_write,
    .transport_open = m_open, .transport_step = m_step, .transport_close = m_close, .clock_valid = m_clock,
    .make_upgrade_request = m_req, .make_client_info = m_info, .tx_pop = m_pop, .deliver = m_deliver,
    .event = m_event, .token_try = m_token, .token_release = m_untoken,
};

typedef struct { atomic_int serviced; } churn_t;
static bool is_churn(void *c);
static void churn_svc(void *c) { atomic_fetch_add(&((churn_t *)c)->serviced, 1); }
static void svc(void *c, void *s) { (void)s; if (is_churn(c)) churn_svc(c); else ml_derp_link_service(&((member_t *)c)->link); }
static const ml_mux_ops_t mux_ops = {.service = svc};
static ml_mux_t mux;
static atomic_bool stop_all;

/* ---- servers ---- */
static void full_read(int fd, uint8_t *b, size_t n) {
    size_t used = 0;
    while (used < n) {
        ssize_t r = read(fd, b + used, n - used);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; pthread_exit(NULL); }
        used += (size_t)r;
    }
}
static void full_write(int fd, const void *b, size_t n) {
    size_t used = 0;
    while (used < n) {
        ssize_t r = write(fd, (const uint8_t *)b + used, n - used);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; pthread_exit(NULL); }
        used += (size_t)r;
    }
}
static size_t build_recv(uint8_t *out, uint64_t ts, uint32_t seq, size_t plen) {
    uint32_t body = 32 + (uint32_t)plen;
    out[0] = ML_DERP_FRAME_RECV_PACKET; out[1] = body >> 24; out[2] = body >> 16; out[3] = body >> 8; out[4] = (uint8_t)body;
    memset(out + 5, 0xAA, 32);
    memcpy(out + 37, &ts, 8); memcpy(out + 45, &seq, 4);
    for (size_t i = 12; i < plen; i++) out[37 + i] = (uint8_t)(seq * 31 + i);
    return 5 + body;
}
static void *server(void *arg) {
    member_t *m = arg;
    int fd = m->sfd;
    uint8_t b[4096];
    size_t n = 0;
    while (n < 4 || memcmp(b + n - 4, "\r\n\r\n", 4)) full_read(fd, b + n++, 1);
    const char *resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
    full_write(fd, resp, strlen(resp));
    uint8_t key[45] = {ML_DERP_FRAME_SERVER_KEY, 0, 0, 0, 40, 0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
    full_write(fd, key, sizeof(key));
    full_read(fd, b, 5);
    uint32_t len = (b[1] << 24) | (b[2] << 16) | (b[3] << 8) | b[4];
    full_read(fd, b, len);
    uint8_t info[25] = {ML_DERP_FRAME_SERVER_INFO, 0, 0, 0, 20};
    full_write(fd, info, sizeof(info));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    uint64_t started = ml_port_mono_ms(), next = started + 200;
    uint32_t seq = 0;
    bool stalled = false;
    uint8_t acc[8192]; size_t have = 0;
    while (!atomic_load(&m->stop)) {
        uint64_t t = ml_port_mono_ms();
        if (m->stall_server && !stalled && t - started > 1000) {
            stalled = true;
            uint8_t frame[1100];
            size_t fl = build_recv(frame, t, 99, 1000);
            full_write(fd, frame, 100);
            usleep(STALL_MS * 1000);                 /* mid-record, 5 s */
            full_write(fd, frame + 100, fl - 100);
        }
        if (t >= next) {
            uint8_t frame[1100];
            size_t fl = build_recv(frame, t, seq, 200 + (seq % 5) * 100);
            seq++;
            full_write(fd, frame, fl);
            next = t + 20;
        }
        ssize_t r = read(fd, acc + have, sizeof(acc) - have);
        if (r > 0) have += (size_t)r;
        while (have >= 5) {
            uint32_t fl = (acc[1] << 24) | (acc[2] << 16) | (acc[3] << 8) | acc[4];
            if (have < 5 + fl) break;
            if (acc[0] == ML_DERP_FRAME_SEND_PACKET && fl >= 44) {
                uint64_t ts; memcpy(&ts, acc + 5 + 32, 8);
                atomic_fetch_add(&m->server_saw, 1);
                note_max(&m->max_tx_lat, ml_port_mono_ms() - ts);
            }
            memmove(acc, acc + 5 + fl, have - 5 - fl);
            have -= 5 + fl;
        }
        usleep(1000);
    }
    return NULL;
}

/* ---- the shared DERP task ---- */
static void *derp_task(void *arg) {
    (void)arg;
    while (!atomic_load(&stop_all)) {
        ml_mux_pass(&mux);
        usleep(10000);
    }
    return NULL;
}
/* ---- producers push relay packets from other threads ---- */
static void *producer(void *arg) {
    member_t *m = arg;
    uint32_t seq = 0;
    while (!atomic_load(&stop_all)) {
        size_t len = 300 + (seq % 5) * 100;
        uint8_t *d = m_alloc(m, len);
        uint64_t ts = ml_port_mono_ms();
        memcpy(d, &ts, 8); memcpy(d + 8, &seq, 4);
        for (size_t i = 12; i < len; i++) d[i] = (uint8_t)(seq * 31 + i);
        seq++;
        pthread_mutex_lock(&m->qlock);
        if (m->qt - m->qh < 500) { unsigned slot = m->qt++ % 512; m->q[slot].d = d; m->q[slot].n = len; }
        else m_release(m, d);
        pthread_mutex_unlock(&m->qlock);
        usleep(20000);
    }
    return NULL;
}
/* ---- churn: a third membership comes and goes while the other two relay ---- */
static member_t *members_base;
static bool is_churn(void *c) { return !((member_t *)c >= members_base && (member_t *)c < members_base + 2); }
static void *churn(void *arg) {
    (void)arg;
    unsigned cycles = 0;
    while (!atomic_load(&stop_all)) {
        churn_t *c = calloc(1, sizeof(*c));
        assert(ml_mux_attach(&mux, c) == 0);
        usleep(30000);
        assert(ml_mux_detach(&mux, c, 1000));
        memset(c, 0xEE, sizeof(*c));          /* poison: a late touch from the shared task would be seen */
        free(c);
        cycles++;
        usleep(20000);
    }
    printf("  churn: %u attach/detach cycles of a third membership while two relayed\n", cycles);
    return NULL;
}

int main(void) {
    static member_t M[2];
    members_base = M;
    pthread_t srv[2], prod[2], task, ch;
    ml_mux_init(&mux, &mux_ops, NULL, ml_port_mono_ms);
    for (int i = 0; i < 2; i++) {
        member_t *m = &M[i];
        memset(m, 0, sizeof(*m));
        m->name = i ? "B" : "A";
        pthread_mutex_init(&m->qlock, NULL);
        int sv[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        m->fd = sv[0]; m->sfd = sv[1];
        fcntl(m->fd, F_SETFL, fcntl(m->fd, F_GETFL) | O_NONBLOCK);
        m->stall_server = i == 0;
        ml_derp_link_init(&m->link, &ops, m);
        assert(ml_mux_attach(&mux, m) == 0);
        pthread_create(&srv[i], NULL, server, m);
        ml_derp_link_connect(&m->link);   /* before the task starts: link calls are serialised by the mux lock afterwards */
    }
    pthread_create(&task, NULL, derp_task, NULL);
    for (int i = 0; i < 2; i++) pthread_create(&prod[i], NULL, producer, &M[i]);
    pthread_create(&ch, NULL, churn, NULL);

    usleep((1000 + STALL_MS + 2500) * 1000);

    atomic_store(&stop_all, true);
    pthread_join(prod[0], NULL); pthread_join(prod[1], NULL);
    pthread_join(ch, NULL);
    pthread_join(task, NULL);
    for (int i = 0; i < 2; i++) { atomic_store(&M[i].stop, true); }
    for (int i = 0; i < 2; i++) { shutdown(M[i].fd, SHUT_RDWR); pthread_join(srv[i], NULL); }

    member_t *a = &M[0], *b = &M[1];
    printf("  A (server stalled %d ms mid-record, not reading): delivered %u, record timeouts %u, write stalls %u, redials %u\n", STALL_MS,
           atomic_load(&a->delivered), a->link.stats.rx_timeouts, a->link.stats.tx_stalls, atomic_load(&a->disconnected));
    printf("  B: delivered %u (max latency %llu ms), server saw %u (max latency %llu ms), redials %u\n",
           atomic_load(&b->delivered), (unsigned long long)atomic_load(&b->max_rx_lat), atomic_load(&b->server_saw),
           (unsigned long long)atomic_load(&b->max_tx_lat), atomic_load(&b->disconnected));
    assert(atomic_load(&b->delivered) > 300 && atomic_load(&b->server_saw) > 300);
    assert(atomic_load(&b->delivered_bad) == 0 && atomic_load(&b->disconnected) == 0);
    assert(atomic_load(&b->max_rx_lat) <= MAX_LAT_MS && atomic_load(&b->max_tx_lat) <= MAX_LAT_MS);
    assert(atomic_load(&a->delivered_bad) == 0);
    assert(atomic_load(&a->delivered) + a->link.stats.rx_timeouts >= 1);   /* completed at the boundary, or redialled */
    assert(ml_mux_detach(&mux, &M[0], 1000) && ml_mux_detach(&mux, &M[1], 1000));
    for (int i = 0; i < 2; i++) {
        ml_derp_link_close(&M[i].link);
        while (M[i].qh != M[i].qt) { m_release(&M[i], M[i].q[M[i].qh++ % 512].d); }
        assert(atomic_load(&M[i].live) == 0);
        close(M[i].fd); close(M[i].sfd);
    }
    ml_mux_destroy(&mux);
    puts("shared DERP (real time): B kept its latency bound through A's 5 s mid-record stall; no leaks, no races");
    return 0;
}
