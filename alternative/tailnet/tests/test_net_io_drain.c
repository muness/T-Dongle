/* net_io's socket drain (ml_net_io_drain.h, the real code): what it reads, in which order, with which counters; and the
 * mechanism of the silent loss it fixes, modelled on lwIP's socket mailbox.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra \
 *      -I components/microlink/include tests/test_net_io_drain.c -o build-host/test_net_io_drain */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_net_io_drain.h"

ml_rx_stats_t ml_rx_stats;

/* ---- lwIP's per-socket receive mailbox: fixed slots, a full mailbox frees the datagram and counts NOTHING (api_msg.c recv_udp) ---- */
typedef struct { uint32_t slot[64]; unsigned head, count, size; uint32_t posted, silently_dropped; } mbox_t;
static void mbox_post(mbox_t *m, uint32_t id) {
    m->posted++;
    if (m->count == m->size) { m->silently_dropped++; return; }
    m->slot[(m->head + m->count++) % 64] = id;
}
static int mbox_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t *ip, uint16_t *port) {
    mbox_t *m = ctx; (void)cap; (void)ip; (void)port;
    if (!m->count) return ML_DRAIN_EMPTY;
    uint32_t id = m->slot[m->head]; m->head = (m->head + 1) % 64; m->count--;
    memcpy(buf, &id, 4);
    return 4;
}
static uint32_t sunk[1 << 16]; static unsigned nsunk;
static void sink(void *ctx, const uint8_t *data, int len, uint32_t ip, uint16_t port) {
    (void)ctx; (void)ip; (void)port; assert(len == 4); memcpy(&sunk[nsunk++], data, 4);
}

/* One select() pass of the old loop: ONE datagram per ready socket. */
static void old_pass(mbox_t *m) {
    uint8_t buf[8]; uint32_t ip; uint16_t port;
    if (!m->count) return;
    int n = mbox_recv(m, buf, sizeof(buf), &ip, &port);
    ML_RX_STAT(udp_rx);
    sink(NULL, buf, n, 0, 0);
}

static uint64_t rs = 99;
static unsigned rnd(unsigned n) { rs = rs * 6364136223846793005ull + 1442695040888963407ull; return (unsigned)(rs >> 33) % n; }

/* Arrival model: the Wi-Fi/tcpip tasks hand net_io bursts; net_io gets to run once after each. */
static void simulate(unsigned mbox_size, unsigned max_burst, unsigned passes, bool new_loop, uint32_t *lost, uint32_t *sent, bool *ordered) {
    mbox_t m = {.size = mbox_size};
    nsunk = 0; ml_rx_stats_reset();
    uint32_t id = 0;
    for (unsigned round = 0; round < 4000; round++) {
        unsigned burst = 1 + rnd(max_burst);
        for (unsigned i = 0; i < burst; i++) mbox_post(&m, id++);
        if (new_loop) { uint8_t buf[8]; ml_net_io_drain(mbox_recv, sink, &m, buf, sizeof(buf), ML_NET_IO_DRAIN_CAP); }
        else for (unsigned p = 0; p < passes; p++) old_pass(&m);      /* each pass reads ONE datagram, however many wait */
    }
    /* flush what is left so every datagram is accounted for */
    while (m.count) { uint8_t buf[8]; ml_net_io_drain(mbox_recv, sink, &m, buf, sizeof(buf), ML_NET_IO_DRAIN_CAP); }
    *lost = m.silently_dropped; *sent = id;
    *ordered = true;
    for (unsigned i = 1; i < nsunk; i++) if (sunk[i] <= sunk[i - 1]) *ordered = false;
    assert(nsunk + m.silently_dropped == id);
}

/* ---- scripted socket for the counter tests ---- */
typedef struct { int result[64]; unsigned n, at; } script_t;
static int script_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t *ip, uint16_t *port) {
    script_t *s = ctx; (void)cap;
    if (s->at >= s->n) return ML_DRAIN_EMPTY;
    int r = s->result[s->at]; *ip = 0x0a000001 + s->at; *port = (uint16_t)(1000 + s->at);
    if (r > 0) memset(buf, (int)s->at, (size_t)r);
    s->at++;
    return r;
}
static unsigned sink_calls; static uint32_t sink_ip[64]; static int sink_len[64];
static void script_sink(void *ctx, const uint8_t *data, int len, uint32_t ip, uint16_t port) {
    (void)ctx; (void)data; (void)port; sink_ip[sink_calls] = ip; sink_len[sink_calls] = len; sink_calls++;
}

static void only(const char *what, unsigned a, unsigned b) { if (a != b) { fprintf(stderr, "%s: %u != %u\n", what, a, b); abort(); } }

int main(void) {
    /* ---- counters and edge cases ---- */
    uint8_t buf[2048];
    {   /* empty socket */
        script_t s = {.n = 0}; ml_rx_stats_reset(); sink_calls = 0;
        assert(ml_net_io_drain(script_recv, script_sink, &s, buf, sizeof(buf), 16) == 0);
        only("udp_rx", ml_rx_stat_get(ML_RXS_udp_rx), 0); only("drain_calls", ml_rx_stat_get(ML_RXS_drain_calls), 1);
        only("capped", ml_rx_stat_get(ML_RXS_drain_capped), 0); only("udp_recv_err", ml_rx_stat_get(ML_RXS_udp_recv_err), 0);
    }
    {   /* three datagrams, one empty: all counted, the empty one discarded, the others sunk in order */
        script_t s = {.result = {100, 0, 1400}, .n = 3}; ml_rx_stats_reset(); sink_calls = 0;
        assert(ml_net_io_drain(script_recv, script_sink, &s, buf, sizeof(buf), 16) == 3);
        only("udp_rx", ml_rx_stat_get(ML_RXS_udp_rx), 3); only("udp_rx_empty", ml_rx_stat_get(ML_RXS_udp_rx_empty), 1);
        only("sink_calls", sink_calls, 2); assert(sink_len[0] == 100 && sink_len[1] == 1400 && sink_ip[0] < sink_ip[1]);
        only("burst_max", atomic_load(&ml_rx_stats.drain_burst_max), 3); only("capped", ml_rx_stat_get(ML_RXS_drain_capped), 0);
        only("deep", ml_rx_stat_get(ML_RXS_drain_deep), 0);
    }
    {   /* "deep" = the mailbox was nearly full: 7 is not, 8 is */
        for (unsigned depth = 0; depth <= 16; depth++) {
            script_t s = {.n = depth}; for (unsigned i = 0; i < depth; i++) s.result[i] = 20;
            ml_rx_stats_reset(); sink_calls = 0;
            assert(ml_net_io_drain(script_recv, script_sink, &s, buf, sizeof(buf), 16) == depth);
            only("deep", ml_rx_stat_get(ML_RXS_drain_deep), depth >= ML_NET_IO_DEEP ? 1 : 0);
        }
    }
    {   /* a receive error stops the drain without counting a datagram, and is counted */
        script_t s = {.result = {50, ML_DRAIN_ERROR, 60}, .n = 3}; ml_rx_stats_reset(); sink_calls = 0;
        assert(ml_net_io_drain(script_recv, script_sink, &s, buf, sizeof(buf), 16) == 1);
        only("udp_rx", ml_rx_stat_get(ML_RXS_udp_rx), 1); only("udp_recv_err", ml_rx_stat_get(ML_RXS_udp_recv_err), 1); only("sink_calls", sink_calls, 1);
        assert(s.at == 2);                       /* the third was left for the next pass */
    }
    {   /* the cap: reads exactly `max`, reports it, and leaves the rest */
        script_t s = {.n = 40}; for (unsigned i = 0; i < 40; i++) s.result[i] = 10 + (int)i;
        ml_rx_stats_reset(); sink_calls = 0;
        assert(ml_net_io_drain(script_recv, script_sink, &s, buf, sizeof(buf), 16) == 16 && s.at == 16 && sink_calls == 16);
        only("capped", ml_rx_stat_get(ML_RXS_drain_capped), 1); only("burst_max", atomic_load(&ml_rx_stats.drain_burst_max), 16);
        for (unsigned i = 0; i < 16; i++) assert(sink_len[i] == 10 + (int)i);       /* order preserved */
        assert(ml_net_io_drain(script_recv, script_sink, &s, buf, sizeof(buf), 16) == 16 && s.at == 32);
        assert(ml_net_io_drain(script_recv, script_sink, &s, buf, sizeof(buf), 16) == 8 && s.at == 40);
        only("capped", ml_rx_stat_get(ML_RXS_drain_capped), 2); only("deep", ml_rx_stat_get(ML_RXS_drain_deep), 3); only("udp_rx", ml_rx_stat_get(ML_RXS_udp_rx), 40); only("drain_calls", ml_rx_stat_get(ML_RXS_drain_calls), 3);
        only("sink_calls", sink_calls, 40);
    }
    printf("net_io drain: counters, cap, errors, empty datagrams ok\n");

    /* ---- the loss mechanism ----
     * lwIP's mailbox holds `mbox` datagrams; the old loop read one datagram per select pass; net_io (priority 7) runs only in the
     * gaps the Wi-Fi and tcpip tasks leave on its core, so how many passes it gets between two bursts is what bounds the old
     * loop: a burst longer than the passes available leaves a backlog, the backlog fills the mailbox, and lwIP drops the rest
     * without counting them. The new loop reads until the socket is empty, so one pass per burst is enough. The burst and pass
     * numbers below are a model, not a measurement: they show the mechanism and that the fix removes its dependence on `passes`. */
    printf("  bursts of 1..B datagrams (mean (B+1)/2), N net_io passes between bursts, 4000 bursts; ordered delivery asserted:\n");
    printf("  %-44s %8s %8s %7s\n", "configuration", "sent", "lost", "loss");
    struct { const char *name; unsigned mbox, burst, passes; bool new_loop; } cfg[] = {
        {"old loop, mailbox 6, B=6, 2 passes", 6, 6, 2, false},
        {"old loop, mailbox 6, B=6, 3 passes", 6, 6, 3, false},
        {"old loop, mailbox 6, B=6, 4 passes", 6, 6, 4, false},
        {"old loop, mailbox 6, B=6, 6 passes", 6, 6, 6, false},
        {"NEW loop, mailbox 6, B=6, 1 pass", 6, 6, 1, true},
        {"NEW loop, mailbox 6, B=10 (exceeds the mailbox)", 6, 10, 1, true},
        {"NEW loop, mailbox 10, B=10", 10, 10, 1, true},
        {"NEW loop, mailbox 10, B=16 (exceeds the mailbox)", 10, 16, 1, true},
    };
    for (size_t i = 0; i < sizeof(cfg) / sizeof(cfg[0]); i++) {
        uint32_t lost, sent; bool ordered;
        simulate(cfg[i].mbox, cfg[i].burst, cfg[i].passes, cfg[i].new_loop, &lost, &sent, &ordered);
        printf("  %-44s %8u %8u %6.2f%%\n", cfg[i].name, sent, lost, 100.0 * lost / sent);
        assert(ordered);                                                    /* nothing is ever delivered out of order */
        if (!cfg[i].new_loop && cfg[i].passes < cfg[i].burst) assert(lost > 0);   /* fewer passes than the longest burst: it overflows */
        if (cfg[i].new_loop && cfg[i].burst <= cfg[i].mbox) assert(lost == 0);    /* the new loop loses nothing a mailbox can hold */
    }
    printf("net_io drain ok\n");
    return 0;
}
