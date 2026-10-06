/* The part AFTER the sources: frames with a checkable payload, the observers on both sides, the world's reset, the operations and the checks.
 * A frame carries a sequence number and a pattern derived from it, so an observer proves each delivered frame is intact and that the frames
 * of one direction arrive in order, none repeated (a flush may skip some, never reorder). */
static const uint8_t sta_mac[6] = {2, 1, 2, 3, 4, 5}, peer_mac[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
static const uint8_t dst_peer[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, dst_bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                     dst_mcast[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x16};
enum { KIND_UNICAST, KIND_BCAST, KIND_MCAST };
/* Wi-Fi to host frames come from `peer_mac` to the STA MAC, host to Wi-Fi frames from the STA MAC. Ethertype follows the sequence: ARP, IPv4, IPv6. */
static uint16_t build_frame(uint8_t *f, uint16_t len, bool from_host, int kind, uint32_t seq) {
    assert(len >= 24 && len <= TDONGLE_L2_FRAME_MAX);
    memcpy(f, kind == KIND_UNICAST ? (from_host ? dst_peer : sta_mac) : kind == KIND_BCAST ? dst_bcast : dst_mcast, 6);
    memcpy(f + 6, from_host ? sta_mac : peer_mac, 6);
    static const uint8_t ethertype[3][2] = {{0x08, 0x06}, {0x08, 0x00}, {0x86, 0xdd}};
    memcpy(f + 12, ethertype[seq % 3], 2);
    memcpy(f + 14, &seq, 4);
    f[18] = (uint8_t)(len >> 8); f[19] = (uint8_t)len;
    for (uint16_t i = 20; i < len; i++) f[i] = (uint8_t)(seq * 7 + len + i);
    return len;
}
static uint32_t check_frame(const uint8_t *f, uint16_t len, bool from_host) {
    assert(len >= 24 && !memcmp(f + 6, from_host ? sta_mac : peer_mac, 6));
    uint32_t seq;
    memcpy(&seq, f + 14, 4);
    assert(f[18] == (uint8_t)(len >> 8) && f[19] == (uint8_t)len);
    for (uint16_t i = 20; i < len; i++) assert(f[i] == (uint8_t)(seq * 7 + len + i));
    return seq;
}

/* ---- observers ---- */
static uint32_t usb_last_seq, air_last_seq;
static bool usb_have, air_have;
static _Atomic unsigned usb_delivered, air_delivered;
static void usb_observe(const uint8_t *f, uint16_t len) {              /* inside tud_network_xmit: the frame enters an NTB */
    const uint32_t seq = check_frame(f, len, false);
    assert(!usb_have || seq > usb_last_seq);                           /* in order, none repeated */
    usb_have = true; usb_last_seq = seq;
    if (atomic_load(&pm_must_be_max)) assert(cpu_max());
    atomic_fetch_add(&usb_delivered, 1);
}
static void air_observe(const uint8_t *f, uint16_t len) {              /* the pp task: a frame leaves the antenna */
    const uint32_t seq = check_frame(f, len, true);
    assert(!air_have || seq > air_last_seq);
    air_have = true; air_last_seq = seq;
    atomic_fetch_add(&air_delivered, 1);
}

/* ---- the world ---- */
#define HEAP_BRIDGE 140000L         /* about what the bridge image has free: no tailnet runtime, no membership */
static bool wifi_up;
static size_t heap_must_stay_above = ML_HB_RESERVE;   /* the lowest free heap any operation may leave (a case with a deliberately tiny heap lowers it) */
static void clock_tick_hook(void) {                /* every vTaskDelay(1) is one tick of real time */
    atomic_fetch_add(&mock_us, TEST_TICK_MS * 1000u);
#ifndef BRIDGE_THREADS
    pm_timer_poll();                               /* with threads the timer has its own (esp_timer) */
#endif
}
static void world_reset(long total, bool dfs) {
    /* the USB ring: the same configuration gateway_main.c gives it in bridge mode */
    for (unsigned i = 0; i < TINYUSB_NET_TX_MAX_CHUNKS; i++) heap_caps_free(s_tx.chunk[i].mem);
    heap_caps_free(s_tx.base);
    memset(&s_tx, 0, sizeof(s_tx));
    pending = 0; atomic_store(&notify_count, 0); usb_ready = 1; ntb_credit = -1; allow_tx = 1; schedule = 0;
    frag_next = 0; malloc_fail = 0; malloc_hook = NULL; pre_copy_hook = NULL; delay_hook = clock_tick_hook;
    atomic_store(&mock_tick, 0); atomic_store(&mock_us, 1000000);
    atomic_store(&heap_live_bytes, 0); atomic_store(&mock_largest, 100000);
    assert(heap_live_blocks == 0);
    atomic_store(&heap_total, total);
    heap_must_stay_above = ML_HB_RESERVE;
    /* the Wi-Fi driver and the observers */
    pthread_mutex_lock(&drv_lock); drv_n = 0; pthread_mutex_unlock(&drv_lock);
    drv_pool = GATEWAY_WIFI_TX_POOL; drv_force_error = 0; drv_cb_result = 0; drv_done_cb = NULL; atomic_store(&drv_rxcb, NULL);
    drv_accepted = drv_aired = drv_cleared = drv_refused_pool = drv_calls = 0;
    atomic_store(&rx_frees, 0);
    usb_have = air_have = false; atomic_store(&usb_delivered, 0); atomic_store(&air_delivered, 0);
    atomic_store(&host_carrier, 0); atomic_store(&host_carrier_changes, 0);
    xmit_hook = usb_observe;
    /* CPU-frequency locks: the real burst and activity objects */
    atomic_store(&usb_txq_lock, 0); atomic_store(&fwd_lock, 0);
    tdongle_pm_burst_init(&usb_tx_pm, "usb_txq", &pm_ops, &usb_txq_lock);
    tdongle_pm_burst_init(&fwd_burst, "fwd_activity", &pm_ops, &fwd_lock);
    tdongle_pm_activity_init(&fwd_activity, &fwd_burst, TDONGLE_PM_ACTIVITY_HOLD_US, pm_arm, NULL);
    timer_armed = false;
    atomic_store(&pm_must_be_max, dfs); atomic_store(&air_must_be_max, false);
    /* the Wi-Fi budget, installed the bridge way: no netif */
    memset(&wifi_pins, 0, sizeof(wifi_pins));
    pthread_mutex_init(&wifi_pins.lock, NULL);
    wifi_pins_tx_done_ok = false; wifi_pins_installed = false; wifi_pins_rx_hooked = false;
    wifi_pins_install(NULL);
    wifi_pins_start();
    assert(wifi_pins_installed && wifi_pins_tx_done_ok && drv_done_cb == wifi_pins_tx_done);
    /* the ring, then the bridge, in the order gateway_main.c starts them */
    const tinyusb_net_tx_config_t tx = {.base_frames = 8, .max_chunks = 12, .priority = 10, .work_priority = 6, .core = 1,
                                        .floor_free = ML_HB_FLOOR, .floor_largest = ML_ADM_LARGEST_BLOCK, .idle_ms = 10000, .gate = NULL,
                                        .pm_begin = pm_usb_begin, .pm_end = pm_usb_end};
    assert(tinyusb_net_tx_ring_start(&tx) == ESP_OK);
    free(l2.slots);
    memset(&l2, 0, sizeof(l2));
    const tdongle_l2_config_t bridge = {.wifi_tx = wifi_pins_tx, .task_priority = 8, .task_core = 1, .task_stack = 3072};
    assert(tdongle_l2_start(sta_mac, &bridge) == ESP_OK);
    wifi_up = false;
}
/* wifi_event() in gateway_main.c, for the bridge. The driver clears its TX queues on a link change, silently. */
static void wifi_connect(void) { drv_clear(); wifi_pins_link_changed(); tdongle_l2_link(true); wifi_up = true; }
static void wifi_disconnect(void) { drv_clear(); tdongle_l2_link(false); wifi_pins_link_changed(); wifi_up = false; }

/* ---- operations. The two callbacks run with in_producer set: the mocks assert they never wait, allocate, defer or call a task ---- */
static esp_err_t wifi_rx(const uint8_t *f, uint16_t len) {           /* the Wi-Fi task delivers a received frame */
    const rxcb_t cb = atomic_load(&drv_rxcb);
    if (!cb) return ESP_FAIL;                                         /* no callback registered: the driver drops it itself */
    const unsigned before = atomic_load(&rx_frees);
    in_producer = 1;
    const esp_err_t r = cb((void *)f, len, (void *)f);
    in_producer = 0;
    assert(atomic_load(&rx_frees) > before);                          /* the driver buffer was freed before the callback returned (once per call: checked exactly when single-threaded) */
#ifndef BRIDGE_THREADS
    assert(atomic_load(&rx_frees) == before + 1);
#endif
    return r;
}
static esp_err_t host_tx(const uint8_t *f, uint16_t len) {           /* the TinyUSB task delivers a frame the host sent */
    in_producer = 1;
    const esp_err_t r = tdongle_l2_host((void *)f, len);
    in_producer = 0;
    return r;
}
static void pump_ring(void) { tx_worker_step(); run_deferred(); tx_worker_step(); }   /* usb_txq: notify, defer, and the edge it causes */
static void usb_bus(void) { __wrap_netd_xfer_cb(0, 0x81, 0, 64); }                    /* the host took an NTB: the IN completion drains again */
static void pump_l2(void) { drain(); }                                               /* the host -> Wi-Fi worker */
static void advance_ms(unsigned ms) { atomic_fetch_add(&mock_us, ms * 1000u); atomic_fetch_add(&mock_tick, ms / TEST_TICK_MS); pm_timer_poll(); }
static tinyusb_net_tx_stats_t ring_stats(void) { tinyusb_net_tx_stats_t s; tinyusb_net_tx_ring_stats(&s); return s; }
static tdongle_l2_stats_t l2_stats(void) { tdongle_l2_stats_t s; tdongle_l2_stats(&s); return s; }
static size_t heap_free_now(void) { return heap_caps_get_free_size(MALLOC_CAP_INTERNAL); }
/* Everything in flight finishes: both queues, the ring, the driver. */
static void settle(void) {
    ntb_credit = -1; allow_tx = 1; usb_ready = 1; drv_force_error = 0;
    for (int i = 0; i < 400; i++) {
        drv_complete(GATEWAY_WIFI_TX_POOL); pump_l2(); pump_ring(); usb_bus();      /* the air first: frames the driver holds must leave before the queue pushes more */
        if (!s_tx.frames_queued && l2_stats().h2w_queue_depth == 0 && !drv_depth() && !pending) break;
    }
    pump_ring();
    assert(!s_tx.frames_queued && l2_stats().h2w_queue_depth == 0 && !drv_depth());
}

/* ---- checks that hold between any two operations ---- */
static void check_world(void) {
    const tdongle_l2_stats_t s = l2_stats();
    assert(s.w2h_frames == s.w2h_forwarded + s.w2h_invalid + s.w2h_own_mac + s.w2h_link_down + s.w2h_usb_not_ready + s.w2h_ring_full);
    assert(s.h2w_frames == s.h2w_queued + s.h2w_invalid + s.h2w_foreign_mac + s.h2w_link_down + s.h2w_queue_full);
    assert(s.h2w_queued == s.h2w_sent + s.h2w_stale + s.h2w_link_down_queued + s.h2w_tx_failed + s.h2w_queue_depth);
    assert(s.h2w_queue_depth <= TDONGLE_L2_HOST_SLOTS && s.h2w_queue_high_water <= TDONGLE_L2_HOST_SLOTS);
    /* The ring: every frame the bridge handed it is queued, delivered to an NTB or flushed, and the USB side saw exactly the delivered ones. */
    const tinyusb_net_tx_stats_t r = ring_stats();
    assert(s.w2h_forwarded == r.enqueued_frames);
    assert(r.enqueued_frames == r.sent_frames + r.flushed_link_down + s_tx.frames_queued);
    assert(r.sent_frames == atomic_load(&usb_delivered));
    assert(r.ring_bytes <= 32 * TINYUSB_NET_TX_SLAB_BYTES && r.max_bytes == 32 * TINYUSB_NET_TX_SLAB_BYTES);
    assert(heap_live_blocks == 1 + (long)s_tx.chunks_present);
    /* The Wi-Fi budget (wifi_pin_budget.h): the accounting identity, in bridge mode. */
    const unsigned charged = atomic_load(&wifi_pins.tx_charged), inflight = gw_wtx_outstanding(&wifi_pins);
    assert(charged == atomic_load(&wifi_pins.tx_done) + atomic_load(&wifi_pins.tx_aborted) + atomic_load(&wifi_pins.tx_flushed) +
                      atomic_load(&wifi_pins.tx_stale) + inflight);
    assert(inflight <= GATEWAY_WIFI_TX_POOL);
    assert(charged == drv_calls && charged == drv_accepted + atomic_load(&wifi_pins.tx_aborted));     /* every charge reached the driver; a refusal was aborted */
    assert(s.h2w_sent == drv_accepted && drv_accepted == drv_aired + drv_cleared + drv_depth());
    assert(drv_aired <= atomic_load(&wifi_pins.tx_done) + atomic_load(&wifi_pins.tx_unmatched));       /* every aired frame produced a tx-done event */
    /* The heap: nothing here takes it below the recovery reserve, whatever the Wi-Fi driver and the ring do together. */
    assert(heap_free_now() >= heap_must_stay_above);
}
/* After a worker pass: the CPU-max lock of the ring is held exactly while frames are queued. */
static void check_ring_pm(void) {
    if (atomic_load(&pm_must_be_max)) assert((atomic_load(&usb_txq_lock) != 0) == (s_tx.frames_queued > 0));
}

/* Everything has finished (settle() ran): nothing was lost without a name, nothing duplicated, everything accepted was delivered or flushed. */
static void check_final(void) {
    const tdongle_l2_stats_t s = l2_stats();
    const tinyusb_net_tx_stats_t t = ring_stats();
    assert(t.enqueued_frames == t.sent_frames + t.flushed_link_down && t.sent_frames == atomic_load(&usb_delivered) && s.w2h_forwarded == t.enqueued_frames);
    assert(s.h2w_queued == s.h2w_sent + s.h2w_stale + s.h2w_link_down_queued + s.h2w_tx_failed && s.h2w_sent == drv_accepted);
    assert(drv_accepted == drv_aired + drv_cleared && atomic_load(&air_delivered) == drv_aired && gw_wtx_outstanding(&wifi_pins) == 0);
    assert(atomic_load(&wifi_pins.tx_charged) == atomic_load(&wifi_pins.tx_done) + atomic_load(&wifi_pins.tx_aborted) + atomic_load(&wifi_pins.tx_flushed) + atomic_load(&wifi_pins.tx_stale));
    assert(atomic_load(&rx_frees) == s.w2h_frames);                 /* the driver's RX buffer: freed exactly once per frame it handed over */
}
/* Idle: every CPU-max lock released and paired. */
static void check_pm_idle(void) {
    assert(!cpu_max());
    tdongle_pm_burst_stats_t a, b;
    tdongle_pm_burst_stats(&usb_tx_pm, &a);
    tdongle_pm_burst_stats(&fwd_burst, &b);
    assert(a.acquires == a.releases && a.underflows == 0 && b.acquires == b.releases && b.underflows == 0 && a.forced_releases == 0 && b.forced_releases == 0);
    const tinyusb_net_tx_stats_t t = ring_stats();
    assert(t.pm_acquired == t.pm_released && t.pm_held == 0);
}
