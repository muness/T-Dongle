/* ADR 0013 adversarial slicing check.
 *
 * Two memberships share ONE DERP service loop (the real ml_derp_link state machine, scheduled by the real
 * ml_mux). Member A's DERP server misbehaves in each way a server can: it stalls 5 s in the middle of a
 * record, it stops reading our writes, it never answers the TLS handshake, it never answers the HTTP
 * upgrade. Member B's relay traffic, in both directions, must keep flowing with bounded latency throughout,
 * and A must recover on its own. Time is virtual (10 ms per pass, the real task's cadence), so the checks
 * are exact and the run takes milliseconds. test_shared_derp_realtime.c repeats the 5 s stall with real
 * threads, sockets and a real clock.
 *
 * The bound asserted for B is one pass period plus the slice (MAX_LAT_MS): what the old per-membership
 * design guaranteed for a lone membership. If a stalled server could hold the shared task, B's latency here
 * would equal the stall. */
#include "derp_fake.h"
#include "ml_mux.h"

static uint64_t vnow = 1000;
#define PASS_MS 10
#define MAX_LAT_MS 15      /* data pushed mid-pass-period is read by the next pass: <= PASS_MS */

static void service_fake(void *ctx, void *shared) { (void)shared; ml_derp_link_service(&((fake_t *)ctx)->link); }
static const ml_mux_ops_t mux_ops = {.service = service_fake};

static fake_t A, B;
static ml_mux_t mux;
static int token;
static fake_t *extra;     /* a third member, polled like the others */
static uint32_t b_seq_rx, b_seq_tx;
static uint64_t next_b_rx, next_b_tx;

static void begin(size_t read_chunk, size_t write_chunk, bool shared_token) {
    vnow = 1000; token = 0; b_seq_rx = b_seq_tx = 0;
    fake_init(&A, "A", &vnow, 1);
    fake_init(&B, "B", &vnow, 2);
    A.read_chunk = B.read_chunk = read_chunk;
    A.write_chunk = B.write_chunk = write_chunk;
    A.transport_delay_ms = B.transport_delay_ms = 30;
    if (shared_token) { A.token_owner = B.token_owner = &token; }
    ml_mux_init(&mux, &mux_ops, NULL, NULL);
    assert(ml_mux_attach(&mux, &A) == 0 && ml_mux_attach(&mux, &B) == 0);
    next_b_rx = next_b_tx = 0;
}

/* One pass period of virtual time: traffic arrives and is queued mid-period, then the shared loop runs. */
static void tick(void) {
    vnow += PASS_MS / 2;
    if (B.link.state == ML_DERP_READY) {
        if (vnow >= next_b_rx) { uint32_t q = b_seq_rx++; fake_server_send(&B, vnow, q, 200 + (q % 5) * 100); next_b_rx = vnow + 20; }
        if (vnow >= next_b_tx) { uint32_t q = b_seq_tx++; fake_enqueue(&B, vnow, q, 150 + (q % 7) * 90); next_b_tx = vnow + 20; }
    }
    fake_server_poll(&A);
    fake_server_poll(&B);
    if (extra) fake_server_poll(extra);
    vnow += PASS_MS / 2;
    ml_mux_pass(&mux);
    fake_server_poll(&A);
    fake_server_poll(&B);
    if (extra) fake_server_poll(extra);
}
static void run(uint64_t ms) { uint64_t end = vnow + ms; while (vnow < end) tick(); }

static void connect_both(void) {
    ml_derp_link_connect(&A.link);
    ml_derp_link_connect(&B.link);
    run(500);
    assert(A.link.state == ML_DERP_READY && B.link.state == ML_DERP_READY);
    assert(A.note_preferred == 1 && B.note_preferred == 1);
}
static void end_checks(void) {
    ml_derp_link_close(&A.link); ml_derp_link_close(&B.link);
    assert(ml_mux_detach(&mux, &A, 100) && ml_mux_detach(&mux, &B, 100));
    ml_mux_destroy(&mux);
    while (A.qh != A.qt) { free(A.q[A.qh++ % 256].data); A.live_allocs--; }
    while (B.qh != B.qt) { free(B.q[B.qh++ % 256].data); B.live_allocs--; }
    assert(A.live_allocs == 0 && B.live_allocs == 0);
    fpipe_reset(&A.s2c); fpipe_reset(&A.c2s); fpipe_reset(&B.s2c); fpipe_reset(&B.c2s);
}
static void b_bounded(const char *what) {
    assert(B.delivered_bad == 0 && B.server_bad == 0);
    assert(B.link.state == ML_DERP_READY);
    assert(B.disconnected_events == 0);
    assert(B.max_rx_latency <= MAX_LAT_MS);
    assert(B.max_tx_latency <= MAX_LAT_MS);
    assert(B.delivered > 20 && B.server_saw > 20);
    printf("  B during %s: rx %u (max latency %llu ms), tx %u (max latency %llu ms), link never dropped\n", what,
           B.delivered, (unsigned long long)B.max_rx_latency, B.server_saw, (unsigned long long)B.max_tx_latency);
}

/* A's server sends the first 100 bytes of a 1,000-byte record, then goes silent for `stall_ms`. */
static void stall_mid_record(uint64_t stall_ms, bool expect_recovery_without_reconnect) {
    connect_both();
    run(1000);
    A.s2c.hold = false;
    uint8_t *frame = malloc(5 + 32 + 1000);
    size_t n = fake_server_frame(frame, vnow, 7, 1000);
    fpipe_push(&A.s2c, frame, 100);
    A.s2c.hold = true;
    fpipe_push(&A.s2c, frame + 100, n - 100);       /* invisible until released */
    free(frame);
    unsigned a_conn = A.connected_events;
    uint64_t t0 = vnow;
    while (vnow < t0 + stall_ms) tick();
    if (expect_recovery_without_reconnect) {
        fpipe_release(&A.s2c);
        run(100);
        assert(A.delivered == 1 && A.delivered_bad == 0);
        assert(A.link.state == ML_DERP_READY && A.link.stats.rx_timeouts == 0 && A.disconnected_events == 0);
    } else {
        /* the 5 s record deadline fired exactly once: A dropped and redialled by itself */
        assert(A.link.stats.rx_timeouts == 1 && A.disconnected_events == 1);
        run(3000);
        assert(A.link.state == ML_DERP_READY && A.connected_events == a_conn + 1);
        assert(A.delivered == 0);      /* the torn record was never delivered half-way */
    }
}

static void scenario_stall_recovers(size_t rc, size_t wc) {
    begin(rc, wc, true);
    stall_mid_record(4500, true);
    b_bounded("A stalled 4.5 s mid-record, then resumed");
    end_checks();
}
static void scenario_stall_5s(size_t rc, size_t wc) {
    begin(rc, wc, true);
    stall_mid_record(5200, false);
    b_bounded("A stalled past 5 s mid-record (A redialled)");
    end_checks();
}
static void scenario_exactly_5s(void) {
    /* The adversarial case as the plan states it: the server stalls 5 s mid-record. The record deadline is
     * 5 s from its first byte, so this lands on the boundary. Either outcome (completed or redialled) is
     * acceptable for A; what is not acceptable is any effect on B. */
    begin(0, 0, true);
    connect_both();
    run(1000);
    uint8_t *frame = malloc(5 + 32 + 1000);
    size_t n = fake_server_frame(frame, vnow, 9, 1000);
    fpipe_push(&A.s2c, frame, 100);
    A.s2c.hold = true;
    fpipe_push(&A.s2c, frame + 100, n - 100);
    free(frame);
    uint64_t t0 = vnow;
    while (vnow < t0 + 5000) tick();
    fpipe_release(&A.s2c);
    run(1000);
    assert(A.delivered + A.link.stats.rx_timeouts == 1);
    assert(A.link.state == ML_DERP_READY || A.link.state == ML_DERP_WAITING || A.link.state == ML_DERP_TRANSPORT || A.link.state == ML_DERP_TOKEN);
    b_bounded("A stalled exactly 5 s mid-record");
    end_checks();
}
static void scenario_write_blocked(void) {
    begin(0, 0, true);
    connect_both();
    run(500);
    A.write_blocked = true;            /* the server stops reading: our send buffer fills */
    for (unsigned i = 0; i < 40; i++) fake_enqueue(&A, vnow, 100 + i, 300);
    uint64_t t0 = vnow;
    while (vnow < t0 + 2900) tick();
    assert(A.link.state == ML_DERP_READY);       /* backpressure under 3 s is not a dead link */
    while (vnow < t0 + 3300) tick();
    assert(A.link.stats.tx_stalls == 1 && A.disconnected_events == 1);
    A.write_blocked = false;
    run(3000);
    assert(A.link.state == ML_DERP_READY);
    b_bounded("A's writes blocked for 3 s");
    end_checks();
}
static void scenario_handshake_hang(void) {
    /* B is relaying; A's TLS handshake never completes. A must give up on its own deadline, B must not notice. */
    begin(0, 0, true);
    B.transport_delay_ms = 30;
    ml_derp_link_connect(&B.link);
    run(500);
    assert(B.link.state == ML_DERP_READY);
    A.transport_hang = true;
    ml_derp_link_connect(&A.link);
    run(ML_DERP_CONNECT_MS + 1500);
    assert(A.failed_events >= 1 && A.transports_closed >= 1);
    assert(token == 0 || token == 1);           /* A never leaks the token */
    b_bounded("A's TLS handshake hung 30 s");
    A.transport_hang = false;
    run(30000);
    assert(A.link.state == ML_DERP_READY);
    end_checks();
}
static void scenario_http_silent(void) {
    begin(0, 0, true);
    ml_derp_link_connect(&B.link);
    run(500);
    A.http_silent = true;
    ml_derp_link_connect(&A.link);
    run(ML_DERP_PHASE_MS + 500);
    assert(A.failed_events >= 1);
    b_bounded("A's server ignoring the HTTP upgrade");
    A.http_silent = false;
    run(60000);
    assert(A.link.state == ML_DERP_READY);
    end_checks();
}
static void scenario_negotiation_serialised(void) {
    /* The token is the one place a stalled member DOES delay another: only the other's JOIN, never its
     * steady-state relay. A's handshake hangs holding the token; C (a third link) waits for it; B relays on. */
    begin(0, 0, true);
    static fake_t C;
    fake_init(&C, "C", &vnow, 3);
    C.token_owner = &token; C.transport_delay_ms = 30;
    assert(ml_mux_attach(&mux, &C) == 0);
    extra = &C;
    ml_derp_link_connect(&B.link);
    run(500);
    A.transport_hang = true;
    ml_derp_link_connect(&A.link);
    run(100);
    ml_derp_link_connect(&C.link);
    run(5000);
    assert(C.link.state == ML_DERP_TOKEN && token == 1);   /* C queued behind A's negotiation */
    run(ML_DERP_CONNECT_MS - 5000 + 200);                  /* A hits its connect deadline and releases */
    A.transport_hang = false;
    run(3000);
    assert(C.link.state == ML_DERP_READY);                 /* ...and C gets its turn */
    b_bounded("A hanging the negotiation token while C waited");
    ml_derp_link_close(&C.link);
    assert(ml_mux_detach(&mux, &C, 100));
    extra = NULL;
    fpipe_reset(&C.s2c); fpipe_reset(&C.c2s);
    assert(C.live_allocs == 0);
    end_checks();
}
static void scenario_pings_and_oversize(void) {
    begin(7, 5, true);
    connect_both();
    /* Server PING is answered with a PONG carrying the same bytes, while B relays. */
    uint8_t ping[5 + 8] = {ML_DERP_FRAME_PING, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    fpipe_push(&A.s2c, ping, sizeof(ping));
    run(100);
    assert(A.pongs_seen == 1 && A.link.stats.pings_answered == 1);
    /* A frame larger than the protocol cap drops the link instead of being read. */
    uint8_t huge[5] = {ML_DERP_FRAME_KEEP_ALIVE, 0x00, 0x10, 0x00, 0x00};
    fpipe_push(&A.s2c, huge, sizeof(huge));
    run(100);
    assert(A.link.stats.oversize == 1 && A.disconnected_events == 1);
    run(3000);
    assert(A.link.state == ML_DERP_READY);
    /* An allocation failure drops the packet, not the connection. */
    A.alloc_fail = true;
    fake_server_send(&A, vnow, 1, 300);
    run(50);
    A.alloc_fail = false;
    assert(A.link.state == ML_DERP_READY && A.link.stats.alloc_drops == 1 && A.delivered == 0);
    fake_server_send(&A, vnow, 2, 300);
    run(50);
    assert(A.delivered == 1 && A.delivered_bad == 0);   /* the stream stayed in sync */
    b_bounded("A's ping, oversize frame and allocation failure");
    end_checks();
}
static void scenario_detach_midstream(void) {
    /* Removing a member while its peers keep relaying: nobody touches it afterwards (ASan proves it). */
    begin(0, 0, true);
    connect_both();
    run(300);
    ml_derp_link_close(&A.link);
    assert(ml_mux_detach(&mux, &A, 100));
    fake_t *dead = &A;
    (void)dead;
    run(500);
    assert(ml_mux_count(&mux) == 1);
    b_bounded("A removed mid-stream");
    ml_mux_detach(&mux, &A, 100);
    end_checks();
}


/* Negative control: the old per-record behaviour (wait for the record, up to 5 s) run on the SHARED loop.
 * The harness must see B starve; otherwise the bounds asserted above would prove nothing. */
static void blocking_service(void *ctx, void *shared) {
    (void)shared;
    fake_t *f = ctx;
    ml_derp_link_service(&f->link);
    if (f != &A) return;
    uint64_t start = vnow;
    while (f->link.state == ML_DERP_READY && f->link.rx.hdr_used && vnow - start < ML_DERP_RX_FRAME_MS) {
        vnow += PASS_MS;                      /* vTaskDelay(10) inside derp_read_exact */
        fake_server_poll(&A);
        ml_derp_link_service(&f->link);
        if (!f->link.rx.hdr_used) break;
    }
}
static void scenario_negative_control(void) {
    static const ml_mux_ops_t blocking_ops = {.service = blocking_service};
    begin(0, 0, true);
    ml_mux_destroy(&mux);
    ml_mux_init(&mux, &blocking_ops, NULL, NULL);
    assert(ml_mux_attach(&mux, &A) == 0 && ml_mux_attach(&mux, &B) == 0);
    connect_both();
    run(500);
    uint8_t *frame = malloc(5 + 32 + 1000);
    size_t n = fake_server_frame(frame, vnow, 3, 1000);
    fpipe_push(&A.s2c, frame, 100);
    A.s2c.hold = true;
    fpipe_push(&A.s2c, frame + 100, n - 100);
    free(frame);
    run(6000);
    assert(B.max_rx_latency >= 3000);          /* a blocking wait on A really does starve B */
    printf("  negative control (blocking read on the shared loop): B's worst latency %llu ms -> the harness sees stalls\n",
           (unsigned long long)B.max_rx_latency);
    end_checks();
}

int main(void) {
    printf("shared DERP loop, two memberships, virtual time\n");
    size_t chunks[][2] = {{0, 0}, {1, 1}, {7, 37}, {64, 5}};
    for (unsigned i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        printf(" transport chunking read=%zu write=%zu\n", chunks[i][0], chunks[i][1]);
        scenario_stall_recovers(chunks[i][0], chunks[i][1]);
        scenario_stall_5s(chunks[i][0], chunks[i][1]);
    }
    scenario_exactly_5s();
    scenario_write_blocked();
    scenario_handshake_hang();
    scenario_http_silent();
    scenario_negotiation_serialised();
    scenario_pings_and_oversize();
    scenario_detach_midstream();
    scenario_negative_control();
    puts("shared DERP: a stalled or hostile server costs its own membership a redial and nobody else any latency");
    return 0;
}
