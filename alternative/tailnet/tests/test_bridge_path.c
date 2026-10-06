/* The transparent bridge end to end on the host: the REAL USB transmit ring (tinyusb_net.c), the REAL bridge (l2.c), the REAL Wi-Fi TX budget
 * (wifi_pins.inc over wifi_pin_budget.h), the REAL CPU-frequency burst/activity code and the REAL status counters (bridge_status.inc), over
 * strict mocks of FreeRTOS, TinyUSB and the Wi-Fi driver. Assembled and built by tools/test-bridge-path.py (ASan/UBSan, 1 ms and 10 ms ticks).
 *
 * What it pins down (ADR 0023):
 *   1. DHCP/ARP/IPv6 bytes and both MAC addresses cross the bridge untouched, in both directions, in order, exactly once.
 *   2. Neither callback ever waits, allocates, defers or calls the Wi-Fi driver: the mocks assert it (in_producer), through every case below.
 *   3. Backpressure: a full ring and a full driver pool drop frames, count each one in one named counter, and never block a callback.
 *   4. Link changes: frames queued under the old Wi-Fi association never reach the new one; a USB detach flushes the ring.
 *   5. The Wi-Fi budget works in bridge mode (no netif): the accounting identity, the heap floor, the degraded path, driver errors.
 *   6. DFS: the clock is at its maximum whenever a frame is handed over, idle drops it, neighbours' chatter never pins it, every lock pairs.
 *   7. The status lines and the diagnostics report list every counter, every line fits, the identities hold in the numbers they print. */
#include <sched.h>
#include <unistd.h>

static unsigned long long rng_state = 88172645463325252ull;
static unsigned rnd(unsigned n) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return (unsigned)(rng_state % n); }

static uint8_t frame_buf[1600];
static uint32_t wseq, hseq;     /* the next sequence number, per direction */
static esp_err_t send_to_host(uint16_t len, int kind) { build_frame(frame_buf, len, false, kind, wseq++); return wifi_rx(frame_buf, len); }
static esp_err_t send_to_wifi(uint16_t len, int kind) { build_frame(frame_buf, len, true, kind, hseq++); return host_tx(frame_buf, len); }
static void restart_sequences(void) { wseq = hseq = 1; }

static void test_install_and_config(void) {
    world_reset(HEAP_BRIDGE, true);
    /* The budget is installed with no netif and its tx-done callback is registered: the same mechanism as the tailnet mode, installed once. */
    assert(wifi_pins_installed && wifi_pins_tx_done_ok && !wifi_pins_rx_hooked && drv_done_cb == wifi_pins_tx_done);
    wifi_pins_hook_rx(); wifi_pins_link_changed();              /* nothing to hook, nothing to crash */
    assert(!wifi_pins_rx_hooked);
    tinyusb_net_tx_stats_t r = ring_stats();
    assert(r.base_bytes == 8 * TINYUSB_NET_TX_SLAB_BYTES && r.max_bytes == 32 * TINYUSB_NET_TX_SLAB_BYTES && r.ring_bytes == r.base_bytes);
    assert(s_tx.cfg.gate == NULL && s_tx.cfg.pm_begin == pm_usb_begin);
    /* Nothing flows before the Wi-Fi link is up, and what arrives is counted. */
    restart_sequences();
    assert(drv_rxcb == NULL && send_to_host(100, KIND_UNICAST) == ESP_FAIL);
    assert(send_to_wifi(100, KIND_UNICAST) == ESP_ERR_INVALID_STATE && l2_stats().h2w_link_down == 1);
    wifi_connect();
    assert(drv_rxcb == receive && atomic_load(&host_carrier) == 1);
    check_world();
    wifi_disconnect();
    assert(drv_rxcb == NULL && atomic_load(&host_carrier) == 0 && atomic_load(&host_carrier_changes) == 2);
    check_world();
}

static void test_bytes_both_directions(void) {
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    atomic_store(&air_must_be_max, false);          /* host broadcasts do not raise the clock (see test_dfs) */
    static const uint16_t sizes[] = {24, 60, 99, 342, 590, 1000, 1400, 1500, 1514};
    unsigned w = 0, h = 0;
    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        for (int kind = KIND_UNICAST; kind <= KIND_MCAST; kind++) {
            assert(send_to_host(sizes[i], kind) == ESP_OK); w++;
            assert(send_to_wifi(sizes[i], kind == KIND_MCAST ? KIND_BCAST : kind) == ESP_OK); h++;
            pump_ring(); usb_bus(); pump_l2(); drv_complete(1);
            check_world(); check_ring_pm();
        }
    settle();
    check_world();
    assert(atomic_load(&usb_delivered) == w && atomic_load(&air_delivered) == h);       /* every frame, once, intact (the observers checked each byte) */
    tdongle_l2_stats_t s = l2_stats();
    assert(s.w2h_forwarded == w && s.h2w_sent == h && s.w2h_ring_full == 0 && s.h2w_queue_full == 0 && s.h2w_tx_failed == 0);
    /* Filters, each counted once: our own MAC as the source (the host's frame echoed back), a runt, an oversize frame. */
    build_frame(frame_buf, 200, true, KIND_UNICAST, 999999);     /* source = the STA MAC */
    assert(wifi_rx(frame_buf, 200) == ESP_OK && l2_stats().w2h_own_mac == 1);
    assert(wifi_rx(frame_buf, 13) == ESP_OK && wifi_rx(frame_buf, TDONGLE_L2_FRAME_MAX + 1) == ESP_OK && l2_stats().w2h_invalid == 2);
    build_frame(frame_buf, 200, false, KIND_UNICAST, 999999);    /* source = another station: the host speaks only for the STA MAC */
    assert(host_tx(frame_buf, 200) == ESP_OK && l2_stats().h2w_foreign_mac == 1);
    assert(host_tx(frame_buf, 13) == ESP_ERR_INVALID_ARG && host_tx(frame_buf, TDONGLE_L2_FRAME_MAX + 1) == ESP_ERR_INVALID_ARG && l2_stats().h2w_invalid == 2);
    settle();
    check_world();
    assert(atomic_load(&usb_delivered) == w && atomic_load(&air_delivered) == h);
}

/* The USB side stops taking frames (every NTB in flight): the ring grows to its cap, then drops, counted, without ever blocking the Wi-Fi task. */
static void test_ring_backpressure(void) {
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    ntb_credit = 0;
    for (int i = 0; i < 200; i++) {
        send_to_host(1514, KIND_UNICAST);           /* one frame per slab: the ring's capacity in frames is its slab count */
        pump_ring();
        check_world(); check_ring_pm();
    }
    tdongle_l2_stats_t s = l2_stats();
    tinyusb_net_tx_stats_t r = ring_stats();
    assert(s.w2h_forwarded == 32 && s.w2h_ring_full == 168);      /* the original bridge's 32 frames, 8 of them permanent */
    assert(r.ring_bytes == r.max_bytes && r.dropped_full == 168 && r.grow_events == 12 && r.grow_denied_heap == 0);
    assert(atomic_load(&usb_delivered) == 0);
    ntb_credit = -1;
    settle();
    check_world();
    assert(atomic_load(&usb_delivered) == 32 && ring_stats().flushed_link_down == 0);     /* all 32, in order */
    /* The elastic part goes back to the heap when the burst is over; the permanent part stays. */
    for (int i = 0; i < 40; i++) { advance_ms(600); pump_ring(); }
    assert(s_tx.chunks_present == 0 && heap_live_blocks == 1 && ring_stats().shrink_events == 12 && ring_stats().ring_bytes == r.base_bytes);
    check_world();

    /* A tight heap: growth stops at the floor (counted), the ring drops instead, and the heap never goes below the floor. */
    world_reset(ML_HB_FLOOR + 8 * TINYUSB_NET_TX_SLAB_BYTES + 9000, true);
    heap_must_stay_above = ML_HB_FLOOR;
    restart_sequences();
    wifi_connect();
    ntb_credit = 0;
    for (int i = 0; i < 100; i++) { send_to_host(1514, KIND_UNICAST); pump_ring(); check_world(); }
    s = l2_stats(); r = ring_stats();
    assert(s.w2h_forwarded == 12 && s.w2h_ring_full == 88 && r.chunks == 2 && r.grow_denied_heap > 0);
    assert(heap_free_now() >= ML_HB_FLOOR);
    ntb_credit = -1;
    settle();
    assert(atomic_load(&usb_delivered) == 12);
}

/* The Wi-Fi driver stops completing frames (a stall, poor signal): its pool fills, the bridge's queue fills, then frames are dropped, counted. */
static unsigned delays_seen, injected, refused_full, complete_on_delay;
static void while_worker_waits(void) {            /* runs inside the worker's vTaskDelay: the TinyUSB task keeps delivering frames */
    clock_tick_hook();
    if (++delays_seen == complete_on_delay) drv_complete(1);       /* the pool frees one buffer on this tick */
    if (delays_seen <= 12) { if (send_to_wifi(500, KIND_UNICAST) == ESP_OK) injected++; else refused_full++; }
}
static void test_wifi_backpressure(void) {
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    atomic_store(&air_must_be_max, true);           /* only unicast below: the clock must be up whenever the driver is called */
    for (int i = 0; i < 40; i++) {
        assert(send_to_wifi(1000, KIND_UNICAST) == ESP_OK);
        pump_l2();
        check_world();
    }
    tdongle_l2_stats_t s = l2_stats();
    const unsigned budget = pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS) ? pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS) : 1;
    assert(s.h2w_sent == 16 && drv_depth() == 16 && s.h2w_tx_failed == 24 && s.h2w_tx_retries == 24u * budget);
    assert(atomic_load(&wifi_pins.tx_refused_pool) == 24u * (budget + 1) && gw_wtx_outstanding(&wifi_pins) == 16 && atomic_load(&wifi_pins.tx_high_water) == 16);
    assert(s.h2w_last_tx_error == ESP_ERR_NO_MEM);
    /* The retry window is time, not frames: a stuck frame costs the worker one window, then the next frame gets its own chance. */
    drv_complete(16);
    assert(send_to_wifi(1000, KIND_UNICAST) == ESP_OK);
    pump_l2();
    assert(l2_stats().h2w_sent == 17);
    check_world();
    settle();
    check_world();

    /* Callbacks keep running while the worker waits: frames keep arriving (queued, or dropped when the queue is full) and nothing blocks. */
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    for (int i = 0; i < 16; i++) assert(send_to_wifi(500, KIND_UNICAST) == ESP_OK);
    pump_l2();
    assert(drv_depth() == 16);
    assert(send_to_wifi(500, KIND_UNICAST) == ESP_OK);
    delays_seen = injected = refused_full = 0;
    complete_on_delay = pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS) >= 3 ? 3 : 1;      /* within the window: 20 ms is 20 ticks at 1 ms, 2 at the firmware's 10 ms */
    delay_hook = while_worker_waits;
    {   /* the worker takes the one waiting frame (the oldest) and nothing else, so the hook's arrivals stay queued */
        const unsigned tail = atomic_load(&l2.tail);
        deliver(&l2.slots[tail & SLOT_MASK]);
        atomic_store(&l2.tail, tail + 1u);
    }
    delay_hook = clock_tick_hook;
    tdongle_l2_stats_t t = l2_stats();
    assert(t.h2w_sent == 17 && t.h2w_tx_retries == complete_on_delay && t.h2w_tx_failed == 0);   /* the retry succeeded on the tick the pool freed a buffer */
    assert(injected > 0 && t.h2w_queue_depth == injected);                             /* the callback queued frames while the worker waited */
    check_world();
    settle();
    check_world();
    assert(atomic_load(&air_delivered) == 17 + injected);
    (void)refused_full;
}

static void test_link_flap(void) {
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    ntb_credit = 0;                                 /* USB stalled: frames pile up in the ring */
    for (int i = 0; i < 8; i++) { send_to_host(600, KIND_UNICAST); pump_ring(); }
    for (int i = 0; i < 4; i++) { send_to_wifi(600, KIND_UNICAST); pump_l2(); }      /* 4 frames held by the driver (nothing completes) */
    for (int i = 0; i < 6; i++) send_to_wifi(600, KIND_UNICAST);                     /* 6 more waiting in the bridge's queue */
    assert(drv_depth() == 4 && l2_stats().h2w_queue_depth == 6 && s_tx.frames_queued == 8);
    check_world();
    wifi_disconnect();                              /* the association ends */
    ntb_credit = -1;
    assert(atomic_load(&host_carrier) == 0);
    pump_ring(); usb_bus(); pump_l2();
    tdongle_l2_stats_t s = l2_stats();
    assert(atomic_load(&usb_delivered) == 0 && ring_stats().flushed_link_down == 8);   /* frames from the old association never reach the host */
    assert(s.h2w_link_down_queued == 6 && drv_cleared == 4);
    assert(gw_wtx_outstanding(&wifi_pins) == 0 && atomic_load(&wifi_pins.tx_flushed) == 4);     /* the driver's cleared queue: charges released */
    check_world(); check_ring_pm();
    /* While down: the callbacks are not registered (the driver drops frames itself); a frame that races the disconnect is counted. */
    assert(send_to_host(200, KIND_UNICAST) == ESP_FAIL && send_to_wifi(200, KIND_UNICAST) == ESP_ERR_INVALID_STATE);
    check_world();
    /* Back up: both directions work, and frames queued in the dark are gone. */
    wifi_connect();
    for (int i = 0; i < 3; i++) { send_to_host(300, KIND_UNICAST); send_to_wifi(300, KIND_UNICAST); }
    settle();
    check_world();
    assert(atomic_load(&usb_delivered) == 3 && atomic_load(&air_delivered) == 3);
    /* A flap that comes and goes before the worker runs: what was queued under the first association is stale, whatever the link says now. */
    ntb_credit = 0;
    for (int i = 0; i < 5; i++) { send_to_host(300, KIND_UNICAST); pump_ring(); }
    for (int i = 0; i < 3; i++) send_to_wifi(300, KIND_UNICAST);
    wifi_disconnect(); wifi_connect();
    ntb_credit = -1;
    settle();
    check_world();
    s = l2_stats();
    assert(s.h2w_stale == 3 && ring_stats().flushed_link_down == 8 + 5 && atomic_load(&usb_delivered) == 3 && atomic_load(&air_delivered) == 3);
    assert(send_to_host(300, KIND_UNICAST) == ESP_OK && send_to_wifi(300, KIND_UNICAST) == ESP_OK);
    settle();
    assert(atomic_load(&usb_delivered) == 4 && atomic_load(&air_delivered) == 4);
    check_world();
    /* A re-association with no disconnect event in between (roaming): the driver clears its TX queues when the link comes up, so the CONNECTED
     * event alone must release the charges of the frames it dropped. */
    for (int i = 0; i < 4; i++) { send_to_wifi(300, KIND_UNICAST); pump_l2(); }
    assert(drv_depth() == 4 && gw_wtx_outstanding(&wifi_pins) == 4);
    const unsigned flushed_before = atomic_load(&wifi_pins.tx_flushed), cleared_before = drv_cleared;
    wifi_connect();
    assert(gw_wtx_outstanding(&wifi_pins) == 0 && atomic_load(&wifi_pins.tx_flushed) == flushed_before + 4 && drv_cleared == cleared_before + 4);
    check_world();
}

static void test_usb_detach(void) {
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    ntb_credit = 0;
    for (int i = 0; i < 5; i++) { send_to_host(400, KIND_UNICAST); pump_ring(); check_ring_pm(); }
    assert(atomic_load(&usb_txq_lock) == 1);        /* queued frames hold the clock */
    usb_ready = 0;                                  /* cable pulled (usb_event: TINYUSB_EVENT_DETACHED) */
    tinyusb_net_tx_ring_link_down();
    pump_ring();
    assert(ring_stats().flushed_link_down == 5 && atomic_load(&usb_txq_lock) == 0);     /* flushed, and the clock released */
    assert(send_to_host(400, KIND_UNICAST) == ESP_OK && send_to_host(400, KIND_UNICAST) == ESP_OK);
    tdongle_l2_stats_t s = l2_stats();
    assert(s.w2h_usb_not_ready == 2 && s.w2h_forwarded == 5);                          /* counted, not queued for a host that is gone */
    check_world();
    usb_ready = 1; ntb_credit = -1;                 /* plugged back in */
    assert(send_to_host(400, KIND_UNICAST) == ESP_OK);
    settle();
    check_world();
    assert(atomic_load(&usb_delivered) == 1);       /* only the new frame: none of the five from before the cable was pulled */
}

static void test_wifi_budget(void) {
    /* (b) Tight heap: the band the floor pays for (4 in flight), then refusals for the heap, each counted; the heap stays above the floor's margin. */
    world_reset(ML_HB_FLOOR + 8 * TINYUSB_NET_TX_SLAB_BYTES + 3000, true);
    heap_must_stay_above = ML_HB_FLOOR - GATEWAY_WIFI_BAND_TOTAL * ML_HB_PIN_BUF_BYTES;
    restart_sequences();
    wifi_connect();
    for (int i = 0; i < 10; i++) { send_to_wifi(1000, KIND_UNICAST); pump_l2(); check_world(); }
    assert(drv_depth() == GATEWAY_WIFI_TX_BAND_MAX && atomic_load(&wifi_pins.tx_band) == GATEWAY_WIFI_TX_BAND_MAX && atomic_load(&wifi_pins.tx_elastic) == 0);
    assert(atomic_load(&wifi_pins.tx_refused_heap) > 0 && l2_stats().h2w_tx_failed == 6);
    drv_complete(4);
    send_to_wifi(1000, KIND_UNICAST); pump_l2();
    assert(drv_depth() == 1 && l2_stats().h2w_sent == 5);                                  /* the band is free again */
    settle();
    check_world();
    assert(atomic_load(&wifi_pins.tx_high_water) == GATEWAY_WIFI_TX_BAND_MAX);

    /* Ample heap: the elastic part, up to the driver's pool, and no further. */
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    for (int i = 0; i < 20; i++) { send_to_wifi(1000, KIND_UNICAST); pump_l2(); check_world(); }
    assert(drv_depth() == GATEWAY_WIFI_TX_POOL && atomic_load(&wifi_pins.tx_band) == GATEWAY_WIFI_TX_BAND_MAX);
    assert(atomic_load(&wifi_pins.tx_elastic) == GATEWAY_WIFI_TX_POOL - GATEWAY_WIFI_TX_BAND_MAX && atomic_load(&wifi_pins.tx_refused_pool) > 0);
    settle();
    check_world();

    /* (d) The driver refuses a frame it was asked to send: the charge is aborted (no tx-done will come), the bridge does not retry a final error. */
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    drv_force_error = ESP_FAIL;
    send_to_wifi(500, KIND_UNICAST); pump_l2();
    tdongle_l2_stats_t s = l2_stats();
    assert(atomic_load(&wifi_pins.tx_aborted) == 1 && gw_wtx_outstanding(&wifi_pins) == 0 && s.h2w_tx_failed == 1 && s.h2w_tx_retries == 0 && s.h2w_last_tx_error == ESP_FAIL);
    check_world();
    drv_force_error = 0;
    send_to_wifi(500, KIND_UNICAST); pump_l2(); drv_complete(1);
    check_world();
    assert(atomic_load(&wifi_pins.tx_done) == 1 && atomic_load(&air_delivered) == 1);

    /* The driver completes frames the budget no longer knows (a flush released them): counted as unmatched, nothing goes negative. */
    for (int i = 0; i < 3; i++) { send_to_wifi(500, KIND_UNICAST); pump_l2(); }
    assert(gw_wtx_outstanding(&wifi_pins) == 3);
    gw_wtx_flush(&wifi_pins);                       /* e.g. a link event the driver did not mirror */
    drv_complete(3);
    assert(gw_wtx_outstanding(&wifi_pins) == 0 && atomic_load(&wifi_pins.tx_unmatched) == 3);
    check_world();

    /* A charge older than the lease is released by the next admission (a done that never came). */
    for (int i = 0; i < 2; i++) { send_to_wifi(500, KIND_UNICAST); pump_l2(); }
    advance_ms(GW_WTX_LEASE_MS + 100);
    send_to_wifi(500, KIND_UNICAST); pump_l2();
    assert(atomic_load(&wifi_pins.tx_stale) == 2);
    settle();
    check_world();

    /* (c) Degraded: the tx-done callback could not be registered. Nothing is counted, so nothing can leak; big frames still honour the floor. */
    world_reset(ML_HB_FLOOR + 8 * TINYUSB_NET_TX_SLAB_BYTES + 3000, true);
    drv_cb_result = ESP_FAIL; drv_done_cb = NULL; wifi_pins_tx_done_ok = false;
    wifi_pins_start();
    assert(!wifi_pins_tx_done_ok);
    restart_sequences();
    wifi_connect();
    send_to_wifi(200, KIND_UNICAST); pump_l2();                       /* small: exempt from the floor (free is FLOOR + 3000) */
    send_to_wifi(1400, KIND_UNICAST); pump_l2();                      /* 1,592 B with the driver's overhead: free was FLOOR + 2608, so it fits */
    assert(l2_stats().h2w_sent == 2 && drv_depth() == 2);
    send_to_wifi(1400, KIND_UNICAST); pump_l2();                      /* free is now FLOOR + 1016: this one would cross the floor */
    assert(l2_stats().h2w_sent == 2 && l2_stats().h2w_tx_failed == 1 && atomic_load(&wifi_pins.tx_refused_heap) > 0);
    assert(atomic_load(&wifi_pins.tx_charged) == 0 && gw_wtx_outstanding(&wifi_pins) == 0);       /* nothing counted, nothing to leak */
    assert(heap_free_now() >= ML_HB_FLOOR);
    drv_complete(2);
    send_to_wifi(1400, KIND_UNICAST); pump_l2();
    assert(l2_stats().h2w_sent == 3);                                  /* the floor is the only gate: space came back, the frame goes */
    drv_complete(1);
    assert(drv_depth() == 0);
}

/* DFS (ADR 0016, 0023). The clock is raised in the callback, before any worker runs; it is at its maximum whenever a frame is handed over;
 * neighbours' broadcast and multicast chatter never pins it; it drops when traffic stops; every lock pairs. */
static void test_dfs(void) {
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    assert(!cpu_max());                             /* idle: 80 MHz */
    atomic_store(&air_must_be_max, true);
    /* Wi-Fi to host, unicast. The activity note raises the clock inside the callback; the ring's own lock follows from its worker. */
    assert(send_to_host(800, KIND_UNICAST) == ESP_OK);
    assert(atomic_load(&fwd_lock) == 1 && atomic_load(&usb_txq_lock) == 0);          /* before pump_ring: only the callback has run */
    tx_worker_step();                               /* the ring's worker wakes: it takes its own lock, then asks TinyUSB to drain */
    assert(atomic_load(&usb_txq_lock) == 1 && pending == 1);
    run_deferred(); tx_worker_step();               /* usb_observe asserts the clock is up as the frame enters the NTB */
    assert(atomic_load(&usb_delivered) == 1 && atomic_load(&usb_txq_lock) == 0 && atomic_load(&fwd_lock) == 1);
    advance_ms(190); assert(cpu_max());
    advance_ms(30); assert(!cpu_max());             /* TDONGLE_PM_ACTIVITY_HOLD_US after the last frame */
    /* Host to Wi-Fi, unicast: the same, with the Wi-Fi driver as the observer. */
    assert(send_to_wifi(800, KIND_UNICAST) == ESP_OK);
    assert(atomic_load(&fwd_lock) == 1);
    pump_l2(); drv_complete(1);
    assert(atomic_load(&air_delivered) == 1);
    advance_ms(250); assert(!cpu_max());
    atomic_store(&air_must_be_max, false);
    /* A stream: one hold for the whole stream, not one per packet. */
    const unsigned acquires = atomic_load(&fwd_burst.acquires);
    for (int i = 0; i < 40; i++) { send_to_host(300, KIND_UNICAST); pump_ring(); usb_bus(); pump_ring(); advance_ms(50); assert(atomic_load(&fwd_lock) == 1); }
    assert(atomic_load(&fwd_burst.acquires) == acquires + 1);
    advance_ms(250); assert(!cpu_max());
    /* Chatter: 100 broadcast and multicast frames from the neighbours, 50 ms apart: forwarded (each raises the ring's lock for its few
     * microseconds) but the forwarding-activity hold is never taken, so the CPU is not pinned at 240 MHz by other people's ARP. */
    const unsigned fwd_before = atomic_load(&fwd_burst.acquires), delivered = atomic_load(&usb_delivered);
    for (int i = 0; i < 100; i++) {
        assert(send_to_host(120, i & 1 ? KIND_BCAST : KIND_MCAST) == ESP_OK);
        pump_ring(); usb_bus(); pump_ring();
        advance_ms(50);
        assert(!atomic_load(&usb_txq_lock) && !atomic_load(&fwd_lock));
    }
    assert(atomic_load(&usb_delivered) == delivered + 100 && atomic_load(&fwd_burst.acquires) == fwd_before);
    /* Frames that are filtered or dropped are not forwarding: they do not raise the clock either. */
    wifi_disconnect();
    send_to_wifi(120, KIND_UNICAST);                                                   /* link down */
    wifi_connect();
    build_frame(frame_buf, 200, true, KIND_UNICAST, 5); wifi_rx(frame_buf, 200);       /* own MAC */
    wifi_rx(frame_buf, 10);
    assert(!cpu_max() && atomic_load(&fwd_burst.acquires) == fwd_before);
    settle();
    advance_ms(300);
    check_world();
    /* Pairing. */
    tdongle_pm_burst_stats_t a, b;
    tdongle_pm_burst_stats(&usb_tx_pm, &a);
    tdongle_pm_burst_stats(&fwd_burst, &b);
    assert(a.acquires == a.releases && a.underflows == 0 && a.forced_releases == 0 && a.depth == 0 && a.max_depth == 1);
    assert(b.acquires == b.releases && b.underflows == 0 && b.forced_releases == 0 && b.depth == 0 && a.acquires > 100 && b.acquires >= 3);
    assert(atomic_load(&usb_txq_lock) == 0 && atomic_load(&fwd_lock) == 0 && !cpu_max());
}

/* mgmt_write: the serial console, captured. */
static char serial_out[8192];
static size_t serial_used;
void mgmt_write(const char *s) { const size_t n = strlen(s); assert(serial_used + n < sizeof(serial_out)); memcpy(serial_out + serial_used, s, n + 1); serial_used += n; }
typedef struct { char section[24], name[40]; int64_t value; } seen_field;
static seen_field seen[96];
static unsigned seen_n;
static void collect(void *ctx, const char *section, const char *name, int64_t value) {
    (void)ctx;
    assert(seen_n < sizeof(seen) / sizeof(seen[0]));
    snprintf(seen[seen_n].section, sizeof(seen[0].section), "%s", section);
    snprintf(seen[seen_n].name, sizeof(seen[0].name), "%s", name);
    seen[seen_n++].value = value;
}
static int64_t seen_value(const char *section, const char *name) {
    for (unsigned i = 0; i < seen_n; i++) if (!strcmp(seen[i].section, section) && !strcmp(seen[i].name, name)) return seen[i].value;
    assert(0 && "field missing");
    return -1;
}
static void test_status_lines(void) {
    world_reset(HEAP_BRIDGE, true);
    restart_sequences();
    wifi_connect();
    /* Some of everything: forwarded, filtered, dropped, retried, flushed. */
    for (int i = 0; i < 30; i++) { send_to_host(700, KIND_UNICAST); send_to_wifi(700, KIND_UNICAST); pump_ring(); usb_bus(); pump_l2(); drv_complete(1); }
    build_frame(frame_buf, 200, true, KIND_UNICAST, 5); wifi_rx(frame_buf, 200); wifi_rx(frame_buf, 10);
    build_frame(frame_buf, 200, false, KIND_UNICAST, 5); host_tx(frame_buf, 200);
    ntb_credit = 0;
    for (int i = 0; i < 40; i++) { send_to_host(1514, KIND_UNICAST); pump_ring(); }
    drv_force_error = ESP_ERR_NO_MEM;
    send_to_wifi(500, KIND_UNICAST); pump_l2();
    drv_force_error = 0;
    wifi_disconnect();
    wifi_connect();
    settle();
    check_world();
    seen_n = 0;
    bridge_visit(collect, NULL);
    /* The identities, read from the numbers the report prints (not from the internals). */
    assert(seen_value("to_host", "frames") == seen_value("to_host", "forwarded") + seen_value("to_host", "invalid") + seen_value("to_host", "own_mac") +
               seen_value("to_host", "link_down") + seen_value("to_host", "usb_not_ready") + seen_value("to_host", "ring_full"));
    assert(seen_value("to_wifi", "frames") == seen_value("to_wifi", "queued") + seen_value("to_wifi", "invalid") + seen_value("to_wifi", "foreign_mac") +
               seen_value("to_wifi", "link_down") + seen_value("to_wifi", "queue_full"));
    assert(seen_value("to_wifi", "queued") == seen_value("to_wifi", "sent") + seen_value("to_wifi", "stale") + seen_value("to_wifi", "link_down_queued") +
               seen_value("to_wifi", "tx_failed") + seen_value("to_wifi", "queue_depth"));
    assert(seen_value("wifi_tx", "charged") == seen_value("wifi_tx", "done") + seen_value("wifi_tx", "aborted") + seen_value("wifi_tx", "flushed") +
               seen_value("wifi_tx", "stale") + seen_value("wifi_tx", "inflight"));
    assert(seen_value("usb_ring", "enqueued") == seen_value("to_host", "forwarded") && seen_value("to_host", "ring_full") > 0 && seen_value("to_wifi", "tx_failed") == 1);
    assert(seen_value("usb_ring", "flushed_link_down") > 0 && seen_value("to_wifi", "last_tx_error") == ESP_ERR_NO_MEM && seen_value("link", "changes") == 3);
    /* No two fields share a name within a section. */
    for (unsigned i = 0; i < seen_n; i++)
        for (unsigned j = i + 1; j < seen_n; j++) assert(strcmp(seen[i].section, seen[j].section) || strcmp(seen[i].name, seen[j].name));
    /* The serial lines: one per section, every field present (none was dropped for length), each line within the buffer, none an old line. */
    serial_used = 0; serial_out[0] = 0;
    bridge_status_lines();
    static const char *const sections[] = {"link", "to_host", "to_wifi", "usb_ring", "wifi_tx"};
    unsigned lines = 0, fields = 0;
    for (char *line = serial_out; *line;) {
        char *end = strstr(line, "\r\n");
        assert(end && (size_t)(end - line) < BRIDGE_LINE_MAX - 2);
        assert(!strncmp(line, "bridge_", 7) && lines < 5 && !strncmp(line + 7, sections[lines], strlen(sections[lines])));
        for (char *p = line; p < end; p++) if (*p == '=') fields++;
        lines++;
        line = end + 2;
    }
    assert(lines == 5 && fields == seen_n);
    assert(strstr(serial_out, "bridge_to_host frames=") && strstr(serial_out, " ring_full=") && strstr(serial_out, " last_tx_error=") && strstr(serial_out, "bridge_wifi_tx installed=1"));
    /* The diagnostics report, built the way memory_diagnostics.inc builds it, is the same set. */
    assert(seen_n == 3 + 7 + 14 + 11 + 12);
}

/* A long random run: every operation, in any order, with the checks after each one. */
static void soak(unsigned seed, long total, bool dfs, unsigned steps, unsigned tight) {
    rng_state = 88172645463325252ull ^ ((unsigned long long)seed * 0x9e3779b97f4a7c15ull);
    world_reset(total, dfs);
    if (tight) heap_must_stay_above = ML_HB_FLOOR - GATEWAY_WIFI_BAND_TOTAL * ML_HB_PIN_BUF_BYTES - ML_HB_SLACK_BYTES;
    restart_sequences();
    wifi_connect();
    unsigned flaps = 0, unplugs = 0, errors = 0;
    bool unplugged = false;
    for (unsigned step = 0; step < steps; step++) {
        const unsigned r = rnd(100);
        const uint16_t len = rnd(4) == 0 ? (uint16_t)(24 + rnd(80)) : rnd(3) == 0 ? (uint16_t)(1400 + rnd(115)) : (uint16_t)(24 + rnd(1491));
        bool ring_step = false;
        if (r < 28) {
            const unsigned k = rnd(100);
            if (k < 3) { build_frame(frame_buf, len, true, KIND_UNICAST, wseq++); wifi_rx(frame_buf, len); }          /* our own MAC echoed */
            else if (k < 5) wifi_rx(frame_buf, (uint16_t)(rnd(2) ? 13 : TDONGLE_L2_FRAME_MAX + 1));
            else send_to_host(len, k < 75 ? KIND_UNICAST : k < 88 ? KIND_BCAST : KIND_MCAST);
        } else if (r < 52) {
            const unsigned k = rnd(100);
            if (k < 3) { build_frame(frame_buf, len, false, KIND_UNICAST, hseq++); host_tx(frame_buf, len); }          /* a foreign source */
            else if (k < 5) host_tx(frame_buf, (uint16_t)(rnd(2) ? 13 : TDONGLE_L2_FRAME_MAX + 1));
            else send_to_wifi(len, k < 85 ? KIND_UNICAST : KIND_BCAST);
        } else if (r < 66) {
            ntb_credit = rnd(8) == 0 ? -1 : (int)rnd(3);
            pump_ring(); ring_step = true;
            if (rnd(2)) usb_bus(); else { tx_worker_step(); run_deferred(); }
        } else if (r < 76) pump_l2();
        else if (r < 88) drv_complete(1 + rnd(6));
        else if (r < 93) advance_ms(rnd(10) == 0 ? 3500 : 1 + rnd(40));
        else if (r < 94) { if (rnd(3) == 0) { wifi_disconnect(); flaps++; } else if (!wifi_up) wifi_connect(); }
        else if (r < 95) { if (!unplugged) { usb_ready = 0; tinyusb_net_tx_ring_link_down(); unplugged = true; unplugs++; } else { usb_ready = 1; unplugged = false; } }
        else if (r < 97) drv_force_error = rnd(4) == 0 ? (rnd(2) ? ESP_FAIL : ESP_ERR_NO_MEM) : 0;
        else if (r < 98) drv_pool = drv_pool == GATEWAY_WIFI_TX_POOL ? 3 + rnd(6) : GATEWAY_WIFI_TX_POOL;
        else if (r < 99) { if (wifi_up && rnd(2)) { wifi_disconnect(); wifi_connect(); flaps++; } }
        else allow_tx = !allow_tx || rnd(2);
        if (drv_force_error) errors++;
        check_world();
        if (ring_step) check_ring_pm();
    }
    if (!wifi_up) wifi_connect();
    drv_pool = GATEWAY_WIFI_TX_POOL;
    allow_tx = 1;
    settle();
    advance_ms(400);
    pump_ring();
    check_world();
    check_final();
    const tdongle_l2_stats_t s = l2_stats();
    const tinyusb_net_tx_stats_t t = ring_stats();
    if (dfs) check_pm_idle();                                       /* idle again: 80 MHz, every lock released and paired */
    printf("  soak seed %u (%s heap, DFS %s): %u steps; to host %u/%u forwarded (%u ring-full, %u flushed), to Wi-Fi %u/%u sent (%u queue-full, %u refused, %u stale), %u flaps, %u unplugs, %u driver errors\n",
           seed, tight ? "tight" : "ample", dfs ? "on" : "off", steps, s.w2h_forwarded, s.w2h_frames, s.w2h_ring_full, t.flushed_link_down, s.h2w_sent, s.h2w_frames,
           s.h2w_queue_full, s.h2w_tx_failed, s.h2w_stale, flaps, unplugs, errors);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    tinyusb_net_config_t cfg = {0};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    test_install_and_config(); puts("  install ok");
    test_bytes_both_directions();
    test_ring_backpressure();
    test_wifi_backpressure();
    test_link_flap();
    test_usb_detach();
    test_wifi_budget();
    test_dfs();
    test_status_lines();
    for (unsigned seed = 1; seed <= 6; seed++) soak(seed, HEAP_BRIDGE, true, 60000, 0);
    for (unsigned seed = 11; seed <= 16; seed++) soak(seed, ML_HB_FLOOR + 8 * TINYUSB_NET_TX_SLAB_BYTES + 6000, true, 60000, 1);
    for (unsigned seed = 21; seed <= 22; seed++) soak(seed, HEAP_BRIDGE, false, 60000, 0);
    printf("PASS: transparent bridge end to end (%d ms tick): bytes intact both ways, no callback waits, every drop counted once, link flaps and USB detach flush, Wi-Fi TX budget in bridge mode, DFS pairing, status lines\n", TEST_TICK_MS);
    return 0;
}
