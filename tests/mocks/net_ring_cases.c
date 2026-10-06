// SPDX-License-Identifier: MIT
/* Cases for the non-blocking, elastic transmit ring in the real tinyusb_net.c.
 * Each frame carries a sequence number and a length-derived fill pattern, so the USB-side
 * observer proves every accepted frame is delivered exactly once, in order, uncorrupted.
 * check_invariants() re-derives the ring's bookkeeping from the bytes after every operation of the soak. */
#define SLAB TINYUSB_NET_TX_SLAB_BYTES
#define CHUNK_FRAMES TINYUSB_NET_TX_CHUNK_SLABS
#define FLOOR_FREE 30000u
#define FLOOR_LARGEST 20000u
#define IDLE_MS 2000u

static bool gate_busy;
static bool gate_cb(void *ctx) { (void)ctx; return gate_busy; }
static int free_count_ring;
static void released_ring(void *cookie, void *ctx) { (void)ctx; assert(cookie); free(cookie); free_count++; free_count_ring++; }
static unsigned long long rng = 88172645463325252ull;
static unsigned rnd(unsigned n) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)(rng % n); }

static uint32_t next_seq, delivered_seq, delivered_frames;
static void observe(const uint8_t *p, uint16_t n) {
    uint32_t seq;
    memcpy(&seq, p, sizeof(seq));
    assert(seq == delivered_seq);                    /* in order, none skipped, none repeated */
    for (uint16_t i = 4; i < n; i++) assert(p[i] == (uint8_t)(seq + n + i));
    delivered_seq++;
    delivered_frames++;
}
static esp_err_t send_frame(uint16_t n, uint32_t *accepted_seq) {
    uint8_t f[1518];
    memcpy(f, &next_seq, sizeof(next_seq));
    for (uint16_t i = 4; i < n; i++) f[i] = (uint8_t)(next_seq + n + i);
    in_producer = 1;
    esp_err_t e = tinyusb_net_tx_ring_send(f, n);
    in_producer = 0;
    if (e == ESP_OK) { *accepted_seq = next_seq; next_seq++; }
    return e;
}
/* Frames that were refused never reach USB, so they do not consume a sequence number. */
static esp_err_t send_len(uint16_t n) { uint32_t s; return send_frame(n, &s); }
static void in_complete(void) { __wrap_netd_xfer_cb(0, 0x81, 0, 64); }   /* the host took an NTB */
/* One worker wakeup, the TinyUSB callbacks it queued, and the wakeup the consumer's "queue emptied" edge causes. */
static void pump(void) { tx_worker_step(); run_deferred(); tx_worker_step(); }
static void reset_counters(void) { delivered_seq = next_seq = delivered_frames = 0; }
static void drain_all(void) {
    ntb_credit = -1;
    for (int i = 0; i < 64 && s_tx.frames_queued; i++) { pump(); in_complete(); }
    pump();
    assert(s_tx.frames_queued == 0);
}
static unsigned popc(uint32_t m) { return (unsigned)__builtin_popcount(m); }
static unsigned capacity_slabs(void) { return s_tx.base_slabs + s_tx.chunks_live * CHUNK_FRAMES; }
static unsigned max_slabs(void) { return s_tx.base_slabs + s_tx.cfg.max_chunks * CHUNK_FRAMES; }

/* Everything the ring believes, recomputed from the bytes. */
static void check_invariants(void) {
    unsigned base = s_tx.base_slabs;
    uint32_t in_fifo = 0, frames = 0, bytes = 0;
    unsigned chunk_used[TINYUSB_NET_TX_MAX_CHUNKS] = {0};
    assert(s_tx.fifo_n <= 32 && s_tx.reading == -1 && !in_crit);
    for (unsigned i = 0; i < s_tx.fifo_n; i++) {
        unsigned s = s_tx.fifo[(s_tx.fifo_head + i) & 31];
        assert(!((in_fifo >> s) & 1));
        in_fifo |= 1u << s;
        const tx_slab_t *sl = &s_tx.slab[s];
        assert(sl->rd <= sl->fill && sl->fill <= sl->resv && sl->resv <= SLAB);
        if (i + 1 < s_tx.fifo_n) assert(sl->resv == sl->fill);          /* sealed: nothing reserved beyond what was committed */
        if (s >= base) { unsigned c = (s - base) / CHUNK_FRAMES; assert(s_tx.chunk[c].mem); chunk_used[c]++; }
        uint32_t off = sl->rd;
        while (off < sl->fill) {
            uint16_t len; memcpy(&len, tx_slab_ptr(s) + off, 2);
            assert(len >= 14 && len <= 1518);
            off += 4 + ((len + 3u) & ~3u); frames++; bytes += 4 + ((len + 3u) & ~3u);
        }
        assert(off == sl->fill);
    }
    assert(frames == s_tx.frames_queued && bytes == s_tx.used_bytes);
    assert((s_tx.alloc_mask & in_fifo) == 0);
    if (s_tx.frames_queued == 0) assert(s_tx.fifo_n <= 1);
    unsigned present = 0, live = 0;
    for (unsigned c = 0; c < TINYUSB_NET_TX_MAX_CHUNKS; c++) {
        const tx_chunk_t *ch = &s_tx.chunk[c];
        if (!ch->mem) { assert(ch->used == 0 && !ch->retiring); assert((s_tx.alloc_mask & tx_chunk_mask(c)) == 0); continue; }
        present++; if (!ch->retiring) live++;
        assert(ch->used == chunk_used[c]);
        if (ch->retiring) assert((s_tx.alloc_mask & tx_chunk_mask(c)) == 0);
    }
    assert(present == s_tx.chunks_present && live == s_tx.chunks_live && present <= s_tx.cfg.max_chunks);
    /* A slab that exists, is not queued and is not retiring must be allocatable, and nothing else is. */
    for (unsigned s = 0; s < base + TINYUSB_NET_TX_MAX_CHUNKS * CHUNK_FRAMES; s++) {
        bool exists = s < base || s_tx.chunk[(s - base) / CHUNK_FRAMES].mem;
        bool retiring = s >= base && s_tx.chunk[(s - base) / CHUNK_FRAMES].retiring;
        bool queued = (in_fifo >> s) & 1;
        bool allocatable = (s_tx.alloc_mask >> s) & 1;
        assert(allocatable == (exists && !retiring && !queued));
    }
    assert(atomic_load(&s_tx.pm_want) == (s_tx.frames_queued > 0));
    assert(heap_live_blocks == 1 + (long)present);
    assert(capacity_slabs() <= max_slabs());
    assert(atomic_load(&s_tx.present_mirror) == present);
}
/* After a worker wakeup, the CPU-frequency lock is held exactly while frames are queued. */
static void check_pm(void) {
#if CONFIG_PM_ENABLE
    assert(mock_pm.held == (s_tx.frames_queued > 0));
    assert(pm_acquires - pm_releases == mock_pm.held);
    assert((unsigned)pm_acquires == atomic_load(&s_tx.pm_acquired) && (unsigned)pm_releases == atomic_load(&s_tx.pm_released));
#endif
}

static tinyusb_net_tx_config_t cfg_with(unsigned base, unsigned chunks) {
    return (tinyusb_net_tx_config_t){ .base_frames = base, .max_chunks = chunks, .priority = 5, .core = 0,
                                      .floor_free = FLOOR_FREE, .floor_largest = FLOOR_LARGEST, .idle_ms = IDLE_MS,
                                      .gate = gate_cb
#if CONFIG_PM_ENABLE
                                      , .pm_begin = mock_pm_begin, .pm_end = mock_pm_end
#endif
    };
}
/* A fresh ring with a fresh world around it. */
static void ring_reset(tinyusb_net_tx_config_t c) {
    for (unsigned i = 0; i < TINYUSB_NET_TX_MAX_CHUNKS; i++) heap_caps_free(s_tx.chunk[i].mem);
    heap_caps_free(s_tx.base);
    mock_pm.held = 0;
    memset(&s_tx, 0, sizeof(s_tx));
    pending = 0; atomic_store(&notify_count, 0); usb_ready = 1; ntb_credit = -1; allow_tx = 1; schedule = 0;
    gate_busy = false; frag_next = 0; malloc_fail = 0; malloc_hook = NULL; delay_hook = NULL; pre_copy_hook = NULL;
    pm_acquires = pm_releases = 0; atomic_store(&malloc_calls, 0);
    heap_total = 200000; mock_largest = 100000;
    reset_counters();
    xmit_hook = observe;
    assert(heap_live_blocks == 0);
    assert(tinyusb_net_tx_ring_start(&c) == ESP_OK);
    check_invariants();
}
static tinyusb_net_tx_stats_t stats(void) { tinyusb_net_tx_stats_t st; tinyusb_net_tx_ring_stats(&st); return st; }

static void test_lifecycle(void) {
    uint8_t f[100] = {0};
    tinyusb_net_tx_config_t c = cfg_with(3, 10);
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);   /* not started */
    assert(tinyusb_net_tx_ring_start(NULL) == ESP_ERR_INVALID_ARG);
    c.base_frames = 1;  assert(tinyusb_net_tx_ring_start(&c) == ESP_ERR_INVALID_ARG);   /* below two frames */
    c.base_frames = 9;  assert(tinyusb_net_tx_ring_start(&c) == ESP_ERR_INVALID_ARG);
    c.base_frames = 3; c.max_chunks = 13; assert(tinyusb_net_tx_ring_start(&c) == ESP_ERR_INVALID_ARG);
    c.max_chunks = 10;
    assert(heap_live_blocks == 0 && s_tx.base == NULL);
    task_create_fail = 1;
    assert(tinyusb_net_tx_ring_start(&c) == ESP_ERR_NO_MEM && s_tx.base == NULL);
    assert(heap_live_blocks == 0);                           /* the ring and the PM lock were given back */
    task_create_fail = 0;
    assert(tinyusb_net_tx_ring_start(&c) == ESP_OK && task_created >= 1 && task_prio == 5 && task_core == 0);
    int created = task_created;
    assert(task_stack == 1536 && heap_live_blocks == 1 && heap_live_bytes == 3 * 1524);
    assert(tinyusb_net_tx_ring_start(&c) == ESP_OK && task_created == created);   /* idempotent */
    tinyusb_net_tx_config_t other = c; other.max_chunks = 9;
    assert(tinyusb_net_tx_ring_start(&other) == ESP_ERR_INVALID_STATE);
    other = c; other.floor_free += 1;
    assert(tinyusb_net_tx_ring_start(&other) == ESP_ERR_INVALID_STATE);
    assert(tinyusb_net_tx_ring_send(NULL, 100) == ESP_ERR_INVALID_ARG);
    assert(tinyusb_net_tx_ring_send(f, 13) == ESP_ERR_INVALID_ARG);
    assert(tinyusb_net_tx_ring_send(f, 1519) == ESP_ERR_INVALID_ARG);
    usb_ready = 0;
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);
    usb_ready = 1;
    tinyusb_net_tx_stats_t st = stats();
    assert(st.ring_bytes == 3 * 1524 && st.base_bytes == 3 * 1524 && st.max_bytes == 23 * 1524);
    assert(st.dropped_invalid == 3 && st.dropped_link_down == 1 && st.enqueued_frames == 0 && st.chunks == 0);
    assert(st.worker_stack_free == 777 && st.elastic_held_bytes == 0);
    tinyusb_net_deinit();                                                /* stops accepting */
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);
    tinyusb_net_config_t ncfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&ncfg) == ESP_OK);            /* deinit cleared the callbacks */
    assert(tinyusb_net_tx_ring_start(&c) == ESP_OK);      /* same ring is re-enabled, nothing reallocated */
    assert(heap_live_blocks == 1);
    /* No PM hooks: the ring works and holds nothing. */
    c = cfg_with(3, 4); c.pm_begin = NULL; c.pm_end = NULL;
    ring_reset(c);
    assert(send_len(300) == ESP_OK); pump();
    assert(pm_acquires == 0 && stats().pm_acquired == 0 && delivered_frames == 1);
    ring_reset(cfg_with(3, 4));
}

static void test_basic_and_no_blocking(void) {
    ring_reset(cfg_with(3, 0));
    int pend = pending;
    unsigned long crit0 = crit_total;
    for (int i = 0; i < 3; i++) assert(send_len(200 + i) == ESP_OK);
    /* Producer: two short critical sections per frame (reserve, commit), nothing else shared. */
    assert(crit_total - crit0 == 6);
    /* The producer only notified the worker: it did not touch TinyUSB's queue and nothing ran yet. */
    assert(pending == pend && delivered_frames == 0 && notify_count == 3);
#if CONFIG_PM_ENABLE
    assert(pm_acquires == 0);                            /* the producer never takes the PM lock; the worker does */
#endif
    check_invariants();
    tx_worker_step();
#if CONFIG_PM_ENABLE
    assert(pm_acquires == 1 && pm_releases == 0);        /* the producer woke the worker, which took the lock */
#endif
    run_deferred();
    assert(delivered_frames == 3 && s_tx.frames_queued == 0 && !s_tx.blocked);
    check_invariants();
    tx_worker_step();                                    /* the "queue emptied" wakeup */
    check_pm();
#if CONFIG_PM_ENABLE
    assert(pm_acquires == 1 && pm_releases == 1);
#endif
    /* With nothing queued and no elastic memory the worker sleeps indefinitely. */
    notify_count = 0;
    tx_worker_step();
    assert(last_notify_wait == portMAX_DELAY);
    tinyusb_net_tx_stats_t st = stats();
    assert(st.enqueued_frames == 3 && st.sent_frames == 3 && st.sent_bytes == 200 + 201 + 202 && st.dropped_full == 0);
    /* Idle worker with an empty ring does not queue a callback. */
    notify_count = 1;
    tx_worker_step();
    assert(pending == 0);
}

/* A fixed ring (no elastic chunks) holds exactly its slabs of full frames, and many small frames per slab. */
static void test_fixed_capacity_and_packing(void) {
    ring_reset(cfg_with(3, 0));
    ntb_credit = 0;                                    /* every NTB is in flight: hold everything in the ring */
    for (int i = 0; i < 3; i++) assert(send_len(1518) == ESP_OK);
    assert(send_len(1518) == ESP_ERR_NO_MEM && send_len(14) == ESP_ERR_NO_MEM);   /* no room even for a small one */
    assert(stats().dropped_full == 2);
    check_invariants();
    drain_all(); check_pm();
    assert(delivered_frames == 3);
    /* 64-byte frames: 68-byte records, 22 per slab, 66 in three slabs. */
    ring_reset(cfg_with(3, 0));
    ntb_credit = 0;
    int n = 0;
    while (send_len(64) == ESP_OK) n++;
    assert(n == 3 * (1524 / 68));
    /* Records of 1004 and 520 bytes fill a slab to the last byte: three such pairs fill three slabs. */
    drain_all();
    ntb_credit = 0;
    for (int i = 0; i < 3; i++) { assert(send_len(1000) == ESP_OK); assert(send_len(516) == ESP_OK); }
    assert(send_len(14) == ESP_ERR_NO_MEM);
    /* Mid-size frames: 1280-byte tunnel frames, 1284-byte records: one per slab (240 B left over: a 200-byte frame fits). */
    drain_all();
    ntb_credit = 0;
    for (int i = 0; i < 3; i++) assert(send_len(1280) == ESP_OK);
    assert(send_len(200) == ESP_OK);                   /* fits behind the newest 1280 in its slab: 1284 + 204 <= 1524 */
    assert(send_len(300) == ESP_ERR_NO_MEM);
    check_invariants();
    /* Space returns the moment a slab is handed to USB, whatever the write position. */
    ntb_credit = 1; in_complete(); check_invariants();
    assert(send_len(1280) == ESP_OK);
    assert(send_len(1280) == ESP_ERR_NO_MEM);
    drain_all();
    check_invariants();
    tinyusb_net_tx_stats_t st = stats();
    assert(st.grow_events == 0 && st.chunks == 0 && st.ring_bytes == st.max_bytes);
    /* Open slab restarts at offset 0 when the ring runs empty: a full frame fits again after small ones. */
    for (int i = 0; i < 5; i++) assert(send_len(100) == ESP_OK);
    drain_all();
    for (int i = 0; i < 3; i++) assert(send_len(1518) == ESP_OK);
    drain_all();
}

/* The point of the change: a burst up to the cap is absorbed with no drop; beyond it, a counted drop. */
static void test_burst_absorption(void) {
    ring_reset(cfg_with(3, 10));                       /* 3 + 10 x 2 = 23 frames */
    ntb_credit = 0;
    long free0 = (long)heap_caps_get_free_size(0);
    for (int i = 0; i < 23; i++) {
        assert(send_len(1518) == ESP_OK);
        tx_worker_step();                              /* the worker wakes on every enqueue, as in the product */
        check_invariants();
    }
    tinyusb_net_tx_stats_t st = stats();
    assert(st.dropped_full == 0 && st.chunks == 10 && st.grow_events == 10 && st.ring_bytes == st.max_bytes);
    assert(st.high_water_slabs == 23 && st.high_water_bytes == 23 * 1524 && st.elastic_held_bytes == 10 * 3048);
    assert(free0 - (long)heap_caps_get_free_size(0) == 10 * 3048);
    notify_count = 0;
    assert(send_len(1518) == ESP_ERR_NO_MEM && stats().dropped_full == 1);       /* the cap */
    assert(notify_count == 1);                         /* a refusal still wakes the worker */
    assert(send_len(14) == ESP_ERR_NO_MEM);
    long mc = malloc_calls;
    tx_worker_step();
    assert(stats().grow_events == 10 && malloc_calls == mc);   /* at the cap: no further growth, no attempt */
    check_invariants();
    drain_all();
    assert(delivered_frames == 23);
    check_pm();
    /* Growth keeps ahead of an ongoing burst only because the worker wakes: without it the ring is the base. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0;
    for (int i = 0; i < 3; i++) assert(send_len(1518) == ESP_OK);
    assert(send_len(1518) == ESP_ERR_NO_MEM);          /* the producer never allocates */
    assert(heap_live_blocks == 1);
    tx_worker_step();                                  /* the drop asked for growth */
    assert(stats().chunks >= 1 && send_len(1518) == ESP_OK);
    drain_all();
    /* The producer's own critical sections stay at two per accepted frame while growing. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0;
    for (int i = 0; i < 12; i++) {
        unsigned long c0 = crit_total;
        esp_err_t e = send_len(1518);
        assert(e == ESP_OK && crit_total - c0 == 2);
        tx_worker_step();
    }
    drain_all();
}

static void fill_pressure(int frames) {          /* get the ring to ask for growth without letting it succeed */
    ntb_credit = 0;
    for (int i = 0; i < frames; i++) (void)send_len(1518);
}
static void open_gate_during_grow(void) { gate_busy = true; }
static void test_growth_denied(void) {
    /* Free heap below the floor: no growth, counted, and the heap is untouched. */
    ring_reset(cfg_with(3, 10));
    long live = heap_live_bytes;
    heap_total = live + FLOOR_FREE + 3048 + 16 - 1;      /* one byte short */
    fill_pressure(3);
    tx_worker_step();
    tinyusb_net_tx_stats_t st = stats();
    assert(st.grow_events == 0 && st.grow_denied_heap == 1 && heap_live_blocks == 1);
    /* Denials are rate limited: a flood of pressure does not hammer the allocator. */
    for (int i = 0; i < 50; i++) { (void)send_len(1518); tx_worker_step(); }
    assert(stats().grow_denied_heap == 1);
    /* After the retry interval, with the heap back, growth resumes. */
    heap_total = 200000;
    atomic_fetch_add(&mock_tick, 100);
    (void)send_len(1518); tx_worker_step();
    assert(stats().grow_events >= 1);
    /* Exactly at the floor is allowed: free after growth equals floor_free. */
    ring_reset(cfg_with(3, 10));
    live = heap_live_bytes;
    heap_total = live + FLOOR_FREE + 3048 + 16;
    fill_pressure(3); tx_worker_step();
    assert(stats().grow_events == 1);
    assert(heap_caps_get_free_size(0) >= FLOOR_FREE);
    for (int i = 0; i < 20; i++) { atomic_fetch_add(&mock_tick, 100); (void)send_len(1518); tx_worker_step(); }
    assert(heap_caps_get_free_size(0) >= FLOOR_FREE);    /* a second chunk would go below the floor: refused */
    assert(stats().grow_events == 1 && stats().grow_denied_heap >= 1);
    drain_all();
    /* Largest block already below the floor. */
    ring_reset(cfg_with(3, 10));
    mock_largest = FLOOR_LARGEST - 1;
    fill_pressure(3); tx_worker_step();
    st = stats();
    assert(st.grow_events == 0 && st.grow_denied_largest == 1 && heap_live_blocks == 1);
    assert(malloc_calls == 1);                           /* only the ring itself: the check came before any allocation */
    /* This allocation is the one that takes the largest block below the floor: undone. */
    ring_reset(cfg_with(3, 10));
    mock_largest = FLOOR_LARGEST + 1000;
    frag_next = FLOOR_LARGEST - 500;
    fill_pressure(3); tx_worker_step();
    st = stats();
    assert(st.grow_events == 0 && st.grow_denied_largest == 1 && heap_live_blocks == 1 && heap_live_bytes == 3 * 1524);
    /* Allocator failure. */
    ring_reset(cfg_with(3, 10));
    malloc_fail = 1;
    fill_pressure(3); tx_worker_step();
    assert(stats().grow_denied_nomem == 1 && stats().grow_events == 0);
    /* Gate closed (a negotiation or admission is running): no growth. */
    ring_reset(cfg_with(3, 10));
    gate_busy = true;
    fill_pressure(3); tx_worker_step();
    st = stats();
    assert(st.grow_denied_gate >= 1 && st.grow_events == 0 && heap_live_blocks == 1);
    assert(malloc_calls == 1);                           /* refused before allocating */
    /* The gate opens: growth after the retry interval. */
    gate_busy = false;
    atomic_fetch_add(&mock_tick, 100);
    (void)send_len(1518); tx_worker_step();
    assert(stats().grow_events >= 1);
    drain_all();
    /* A negotiation takes the token while the worker is allocating (after its gate check): the chunk is undone. */
    gate_busy = false;
    ring_reset(cfg_with(3, 10));
    malloc_hook = open_gate_during_grow;
    fill_pressure(3); tx_worker_step();
    st = stats();
    assert(st.grow_events == 0 && st.grow_denied_gate == 1 && heap_live_blocks == 1 && malloc_calls == 2);
    gate_busy = false;
    /* No elastic chunks configured: pressure never allocates. */
    ring_reset(cfg_with(3, 0));
    fill_pressure(10); tx_worker_step();
    assert(heap_live_blocks == 1 && stats().grow_events == 0 && stats().grow_denied_heap == 0);
    drain_all();
}

static void grow_to(int frames) {
    for (int i = 0; i < frames; i++) { assert(send_len(1518) == ESP_OK); tx_worker_step(); }
}
static void reclaim_drain_hook(void) { ntb_credit = -1; in_complete(); }     /* the TinyUSB task alone */
static int mid_copy_reclaims;
static void reclaim_mid_copy(void) { if (mid_copy_reclaims++ == 0) (void)tinyusb_net_tx_elastic_reclaim(0); }
static int copies, deinit_at;
static void deinit_mid_copy(void) { if (++copies == deinit_at) tinyusb_net_deinit(); }
static void reclaim_during_grow(void) { (void)tinyusb_net_tx_elastic_reclaim(0); }

/* Admission needs the heap: idle chunks go at once, chunks with frames in them drain first, nothing in flight is lost. */
static void test_reclaim_for_admission(void) {
    ring_reset(cfg_with(3, 10));
    long free0 = (long)heap_caps_get_free_size(0);
    ntb_credit = 0;
    grow_to(23);
    assert(stats().chunks == 10);
    /* Admission: the token is held (gate), then reclaim, then the heap is measured. */
    gate_busy = true;
    size_t held = tinyusb_net_tx_elastic_reclaim(0);
    tinyusb_net_tx_stats_t st = stats();
    assert(held == 10 * 3048 && st.reclaim_events == 1 && st.chunks == 0 && st.reclaimed_chunks == 0);   /* all hold frames */
    assert(st.elastic_held_bytes == 10 * 3048 && st.ring_bytes == 3 * 1524);
    check_invariants();
    /* No new frame goes into a retiring chunk, and nothing grows while the gate is closed. */
    assert(send_len(1518) == ESP_ERR_NO_MEM);
    tx_worker_step();
    assert(stats().chunks == 0 && heap_live_blocks == 11);
    /* The host takes the frames; each retiring chunk is freed when its last frame left. */
    ntb_credit = -1;
    for (int i = 0; i < 40 && s_tx.frames_queued; i++) { in_complete(); check_invariants(); }
    assert(s_tx.frames_queued == 0 && delivered_frames == 23);
    tx_worker_step();                                  /* the consumer's wakeup: reap */
    check_invariants();
    st = stats();
    assert(heap_live_blocks == 1 && st.reclaimed_chunks == 10 && st.elastic_held_bytes == 0);
    assert((long)heap_caps_get_free_size(0) == free0);   /* admission measures the heap with nothing borrowed */
    check_pm();
    gate_busy = false;
    drain_all();

    /* The wait form: reclaim sleeps while TinyUSB drains the chunks in the background. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23);
    gate_busy = true;
    delay_hook = reclaim_drain_hook;
    assert(tinyusb_net_tx_elastic_reclaim(1000) == 0);
    delay_hook = NULL;
    assert(heap_live_blocks == 1 && delivered_frames == 23 && stats().reclaimed_chunks == 10);
    /* A reclaim that times out reports what it still holds. */
    gate_busy = false;
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23);
    gate_busy = true;
    assert(tinyusb_net_tx_elastic_reclaim(5) == 10 * 3048);
    drain_all();
    assert(heap_live_blocks == 1);

    /* Idle chunks (no frames queued) are freed immediately. */
    gate_busy = false;
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23);
    drain_all();
    assert(stats().chunks == 10);
    gate_busy = true;
    assert(tinyusb_net_tx_elastic_reclaim(0) == 0 && heap_live_blocks == 1);
    assert(stats().reclaim_events == 1 && stats().reclaimed_chunks == 10);
    assert(tinyusb_net_tx_elastic_reclaim(0) == 0 && stats().reclaim_events == 1);   /* nothing to retire: not an event */

    /* The consumer is in the middle of copying a frame out of an elastic chunk when admission reclaims. The copy must
     * read live memory (the mock poisons freed memory, ASan traps it), and the frame is delivered intact. */
    gate_busy = false;
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23);
    gate_busy = true;
    mid_copy_reclaims = 0;
    pre_copy_hook = reclaim_mid_copy;
    ntb_credit = -1;
    drain_all();
    pre_copy_hook = NULL;
    assert(delivered_frames == 23 && heap_live_blocks == 1 && stats().reclaimed_chunks == 10);

    /* Teardown while the consumer is copying a frame out of a chunk (the 8th: slab 7, in an elastic chunk): the queue is
     * flushed and the chunks retired under it. The copy reads live memory, the chunk is freed only afterwards, and the
     * consumer's advance finds the queue already flushed. */
    gate_busy = false;
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23);
    copies = 0; deinit_at = 8;
    pre_copy_hook = deinit_mid_copy;
    ntb_credit = -1;
    in_complete();
    pre_copy_hook = NULL;
    assert(delivered_frames == 8 && s_tx.frames_queued == 0 && s_tx.flushed == 15 && s_tx.fifo_n == 0);
    assert(s_tx.chunks_present > 0);                   /* the chunk holding the frame being copied outlived the teardown */
    assert(s_tx.reap_pending);                         /* the consumer's advance released the last slab: reap is due */
    tx_worker_step(); check_invariants();
    assert(s_tx.chunks_present == 0 && heap_live_blocks == 1);
    {   tinyusb_net_config_t ncfg = {.free_tx_buffer = released_ring};
        assert(tinyusb_net_init(&ncfg) == ESP_OK); }
    assert(tinyusb_net_tx_ring_start(&(const tinyusb_net_tx_config_t[]){ cfg_with(3, 10) }[0]) == ESP_OK);

    /* A growth that allocated before admission started and publishes after it is discarded (epoch). */
    gate_busy = false;
    ring_reset(cfg_with(3, 10));
    fill_pressure(3);
    malloc_hook = reclaim_during_grow;
    tx_worker_step();
    tinyusb_net_tx_stats_t s2 = stats();
    assert(s2.grow_raced == 1 && s2.grow_events == 0 && heap_live_blocks == 1 && s2.chunks == 0);
    drain_all();
}

/* Idle shrink is staged: each worker pass frees at most one chunk. */
static void shrink_passes(int n) { for (int i = 0; i < n; i++) tx_worker_step(); }

static void test_idle_shrink(void) {
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23);
    drain_all();
    tinyusb_net_tx_stats_t st = stats();
    assert(st.chunks == 10 && st.shrink_events == 0);
    /* Chunks wait for the idle period, measured from the last frame they held. */
    atomic_fetch_add(&mock_tick, IDLE_MS - 1);
    tx_worker_step();
    assert(stats().chunks == 10 && stats().shrink_events == 0);
    atomic_fetch_add(&mock_tick, 1);
    tx_worker_step();
    st = stats();
    /* Staged: one chunk per pass, the highest first, so a burst of frees never hits the heap at once. */
    assert(st.chunks == 9 && st.shrink_events == 1 && !s_tx.chunk[9].mem && s_tx.chunk[8].mem);
    shrink_passes(9);
    st = stats();
    assert(st.chunks == 0 && st.shrink_events == 10 && heap_live_blocks == 1 && st.ring_bytes == 3 * 1524);
    assert(st.reclaim_events == 0);                    /* idle is not an admission reclaim */
    check_invariants();
    tx_worker_step();
    assert(last_notify_wait == portMAX_DELAY);         /* nothing elastic left: no timer */

    /* Light load keeps only what it uses: four frames held (3 base + 1 chunk slab); the rest go. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23);
    drain_all();
    ntb_credit = 0;
    for (int i = 0; i < 4; i++) assert(send_len(1518) == ESP_OK);
    atomic_fetch_add(&mock_tick, IDLE_MS + 10);
    shrink_passes(12);
    st = stats();
    assert(st.chunks == 1 && st.shrink_events == 9 && s_tx.chunk[0].mem && !s_tx.chunk[1].mem);
    /* Frames in flight keep their chunk however long it has been. */
    atomic_fetch_add(&mock_tick, 10 * IDLE_MS);
    tx_worker_step();
    assert(stats().chunks == 1);
    check_invariants();
    drain_all();
    /* An empty open slab inside a chunk does not pin it. */
    atomic_fetch_add(&mock_tick, IDLE_MS + 10);
    shrink_passes(2);
    assert(stats().chunks == 0 && heap_live_blocks == 1);
    check_invariants();

    /* Lowest slab first: a trickle of traffic never touches the chunks, so they all age out. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(23); drain_all();
    for (int round = 0; round < 8; round++) {
        atomic_fetch_add(&mock_tick, 400);
        assert(send_len(500) == ESP_OK); pump();
        assert(round >= 4 || stats().shrink_events == 0);  /* before 2000 ticks idle nothing goes */
    }
    shrink_passes(10);
    assert(stats().chunks == 0 && stats().shrink_events == 10);
    /* Growth after a shrink works (the slots are free again). */
    ntb_credit = 0; grow_to(23);
    assert(stats().chunks == 10 && stats().dropped_full == 0);
    drain_all();

    /* The worker's wait: a timer only while elastic memory exists. */
    ring_reset(cfg_with(3, 10));
    notify_count = 0; tx_worker_step(); assert(last_notify_wait == portMAX_DELAY);
    ntb_credit = 0; grow_to(5); drain_all();
    notify_count = 0; tx_worker_step(); assert(last_notify_wait == pdMS_TO_TICKS(500));

    /* A negotiation starts (gate closes) with idle chunks and no traffic at all: a kick is enough. */
    gate_busy = true;
    tinyusb_net_tx_elastic_kick();
    tx_worker_step();
    st = stats();
    assert(st.chunks == 0 && heap_live_blocks == 1 && st.reclaim_events == 1 && st.shrink_events == 0);
    gate_busy = false;
}

static void test_exactly_once_and_triggers(void) {
    ring_reset(cfg_with(3, 4));
    ntb_credit = 0;
    for (int i = 0; i < 4; i++) { assert(send_len(1400) == ESP_OK); tx_worker_step(); }
    pump();                                            /* drain stops, frames stay queued */
    assert(delivered_frames == 0 && s_tx.blocked && stats().ntb_blocked >= 1);
    uint32_t ev = s_tx.blocked_events;
    /* Nothing re-drains on a timer: with no new frame and no completion nothing moves. */
    for (int i = 0; i < 20; i++) { atomic_fetch_add(&mock_tick, 300); notify_count = 0; tx_worker_step(); }
    run_deferred();
    assert(delivered_frames == 0 && s_tx.blocked_events == ev);
    check_pm();
    /* The host takes one NTB: its completion event moves exactly one frame, in order. */
    ntb_credit = 1;
    int calls = real_xfer_calls;
    in_complete();
    assert(real_xfer_calls == calls + 1);              /* the real driver ran first */
    assert(delivered_frames == 1 && s_tx.blocked && pending == 0);
    ntb_credit = -1;
    in_complete();
    assert(delivered_frames == stats().enqueued_frames && !s_tx.blocked && s_tx.frames_queued == 0);
    check_invariants();

    /* OUT completions are not transmit events; an IN completion drains with no worker and no deferred callback. */
    reset_counters();
    ring_reset(cfg_with(3, 4));
    ntb_credit = 0;
    assert(send_len(300) == ESP_OK);
    ntb_credit = -1;
    calls = real_xfer_calls;
    __wrap_netd_xfer_cb(0, 0x01, 0, 64);
    assert(real_xfer_calls == calls + 1 && delivered_frames == 0);
    int pend = pending;
    in_complete();
    assert(delivered_frames == 1 && pending == pend && stats().xfer_events >= 1);
    in_complete();                                     /* empty ring: a cheap no-op */
    assert(delivered_frames == 1);
    tx_worker_step(); check_pm();

    /* Duplicate and stale drain callbacks (timed-out wakeups, retries racing a drain) are harmless. */
    ring_reset(cfg_with(3, 4));
    for (int i = 0; i < 4; i++) assert(send_len(300) == ESP_OK);
    pump();
    assert(delivered_frames == 4);
    for (int i = 0; i < 20; i++) do_drain(NULL);
    for (int i = 0; i < 20; i++) in_complete();
    assert(delivered_frames == 4);
    assert(send_len(300) == ESP_OK);
    for (int i = 0; i < 5; i++) do_drain(NULL);        /* replay with a new frame queued: delivered once */
    assert(delivered_frames == 5);
    pump();
    assert(pending == 0 && delivered_frames == 5);
    /* The worker defers once per outstanding request, not once per frame. */
    for (int i = 0; i < 3; i++) assert(send_len(300) == ESP_OK);
    tx_worker_step(); tx_worker_step(); tx_worker_step();
    assert(pending == 1);
    run_deferred();
    assert(delivered_frames == 8);
    /* Delayed callbacks: frames are committed, completions arrive late and in bursts, in any mix. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0;
    for (int i = 0; i < 20; i++) { assert(send_len(1000 + i) == ESP_OK); tx_worker_step(); }
    for (int i = 0; i < 100 && s_tx.frames_queued; i++) {
        ntb_credit = (int)rnd(3);
        if (rnd(2)) in_complete(); else { tx_worker_step(); run_deferred(); }
        for (int k = rnd(3); k > 0; k--) do_drain(NULL);
        check_invariants();
        if (!(i % 7)) ntb_credit = -1;
    }
    drain_all();
    assert(delivered_frames == 20 && stats().sent_frames == 20 && stats().flushed_link_down == 0);
}

static void test_sync_and_ring_share_the_pipe(void) {
    ring_reset(cfg_with(3, 4));
    int frees = free_count;
    for (int i = 0; i < 20; i++) {
        assert(send_len(150) == ESP_OK);
        uint8_t *p = malloc(100);
        memset(p, 7, 100);
        xmit_hook = NULL;
        schedule = 0; allow_tx = 1;
        esp_err_t e = tinyusb_net_send_sync(p, 100, p, 20);
        assert(e == ESP_OK);                             /* released by the free callback, once */
        xmit_hook = observe;
        pump();
    }
    assert(delivered_frames == 20);
    assert(free_count == frees + 20);                    /* ring frames never call the free callback */
}

static void test_link_loss(void) {
    /* Frames queued across the base and elastic chunks, cable pulled and replugged with no drain in between: the
     * producer notices on its next attempt and the stale frames never reach the new host. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0;
    grow_to(12);
    pump();
    assert(s_tx.blocked && delivered_frames == 0 && stats().chunks >= 4);
    check_pm();
    uint32_t flushed = s_tx.flushed;
    usb_ready = 0;
    notify_count = 0;
    assert(send_len(500) == ESP_ERR_INVALID_STATE);
    assert(notify_count == 1);                           /* stale frames are queued: the worker is woken to flush them */
    assert(send_len(500) == ESP_ERR_INVALID_STATE);      /* one generation bump per outage */
    assert(s_tx.gen == 1);
    pump();                                              /* the worker's drain discards them while the link is down */
    assert(s_tx.flushed == flushed + 12 && s_tx.frames_queued == 0);
    check_pm();                                          /* ... and the CPU-frequency lock is released */
    check_invariants();
    usb_ready = 1;
    ntb_credit = -1;
    delivered_seq = next_seq;                            /* the stale frames are never observed */
    assert(send_len(500) == ESP_OK);
    pump();
    assert(delivered_frames == 1 && s_tx.gen == 1);

    /* The same, but replugged before anyone looked: the generation check on the producer side is what catches it. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0;
    grow_to(8);
    usb_ready = 0;
    assert(send_len(500) == ESP_ERR_INVALID_STATE);
    usb_ready = 1;
    ntb_credit = -1;
    delivered_seq = next_seq;
    assert(send_len(500) == ESP_OK);
    pump(); in_complete(); pump();
    assert(delivered_frames == 1 && s_tx.flushed == 8 && s_tx.frames_queued == 0);
    check_pm(); check_invariants();

    /* Silent loss: nobody sends, no event arrives. The worker's link check (it is polling because frames are queued)
     * discards the frames and lets go of the CPU-frequency lock. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(10); pump();
    usb_ready = 0;
    notify_count = 0;
    tx_worker_step();                                    /* timed out, no notification */
    assert(last_notify_wait == pdMS_TO_TICKS(200));
    run_deferred(); tx_worker_step();
    assert(s_tx.frames_queued == 0 && s_tx.flushed == 10 && s_tx.gen == 1);
    check_pm(); check_invariants();
    usb_ready = 1; ntb_credit = -1; delivered_seq = next_seq;
    assert(send_len(300) == ESP_OK); pump();
    assert(delivered_frames == 1 && s_tx.gen == 1);

    /* The detach event (usb_event DETACHED) flushes without waiting for a poll. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(6); pump();
    usb_ready = 0;
    tinyusb_net_tx_ring_link_down();
    tinyusb_net_tx_ring_link_down();                     /* idempotent */
    assert(s_tx.gen == 1);
    pump();
    assert(s_tx.frames_queued == 0 && s_tx.flushed == 6);
    check_pm();
    usb_ready = 1; ntb_credit = -1; delivered_seq = next_seq;
    /* link_down on a ring that was never started or is stopped does nothing. */
    tinyusb_net_deinit();
    tinyusb_net_tx_ring_link_down();
    tinyusb_net_config_t ncfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&ncfg) == ESP_OK);

    /* A drain that finds USB down discards what is queued (no producer, no poll). */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(5); pump();
    flushed = s_tx.flushed;
    usb_ready = 0;
    in_complete();                                     /* the consumer is the first to look: no generation bump yet */
    assert(s_tx.flushed == flushed + 5 && s_tx.frames_queued == 0 && !s_tx.blocked && s_tx.gen == 0);
    usb_ready = 1; ntb_credit = -1; delivered_seq = next_seq;
    assert(send_len(500) == ESP_OK); pump();
    assert(delivered_frames == 1);
    check_invariants(); check_pm();

    /* Teardown with frames queued and chunks held: everything is discarded and given back, the lock is released. */
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(15); pump();
    check_pm();
#if CONFIG_PM_ENABLE
    assert(mock_pm.held == 1);
#endif
    tinyusb_net_deinit();
    assert(s_tx.frames_queued == 0 && heap_live_blocks == 1 && s_tx.flushed == 15);
    tx_worker_step();
    check_pm();
#if CONFIG_PM_ENABLE
    assert(mock_pm.held == 0 && pm_acquires == pm_releases);
#endif
    check_invariants();
    assert(tinyusb_net_init(&ncfg) == ESP_OK);
    assert(tinyusb_net_tx_ring_start(&(const tinyusb_net_tx_config_t[]){ cfg_with(3, 10) }[0]) == ESP_OK);
    delivered_seq = next_seq;
    ntb_credit = -1;
    assert(send_len(300) == ESP_OK); pump();
    assert(delivered_frames == 1);
}

/* The receive path's backpressure: a callback that holds a datagram makes the class driver keep it (recv_cb false, no renew); tinyusb_net_rx_resume()
 * defers ONE renew to the TinyUSB task however many times it is asked; a consumed datagram renews as before. */
static esp_err_t rx_result;
static unsigned rx_calls;
static esp_err_t hold_cb(void *buffer, uint16_t len, void *ctx) { (void)buffer; (void)len; (void)ctx; rx_calls++; return rx_result; }
static void test_rx_hold(void) {
    tinyusb_net_deinit();
    tinyusb_net_config_t ncfg = {.on_recv_callback = hold_cb};
    assert(tinyusb_net_init(&ncfg) == ESP_OK);
    uint8_t d[100] = {0};
    recv_renew_calls = 0; pending = 0;
    rx_result = ESP_OK;
    assert(tud_network_recv_cb(d, 100) && recv_renew_calls == 1);             /* consumed: renewed */
    rx_result = TUSB_NET_RX_HOLD;
    assert(!tud_network_recv_cb(d, 100) && recv_renew_calls == 1 && rx_calls == 2);    /* held: refused, NOT renewed (the class keeps it) */
    rx_result = ESP_ERR_NO_MEM;
    assert(tud_network_recv_cb(d, 100) && recv_renew_calls == 2);             /* any other error: the datagram was dropped by the callee, move on */
    tinyusb_net_rx_resume(); tinyusb_net_rx_resume(); tinyusb_net_rx_resume();
    assert(pending == 1 && recv_renew_calls == 2);                            /* coalesced into one deferred call, nothing renewed in the caller */
    run_deferred();
    assert(pending == 0 && recv_renew_calls == 3);
    tinyusb_net_rx_resume();                                                  /* and it can be asked again afterwards */
    assert(pending == 1);
    run_deferred();
    assert(recv_renew_calls == 4);
    tinyusb_net_deinit();
    tinyusb_net_config_t again = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&again) == ESP_OK);
}

/* The elastic cap as a run-time knob: lowering retires the chunks above it (frames in them drain first), raising lets the worker grow again. */
static void advance_mock_idle(void) { atomic_fetch_add(&mock_tick, pdMS_TO_TICKS(IDLE_MS + 600)); }
static void test_set_max_chunks(void) {
    ring_reset(cfg_with(3, 10));
    assert(tinyusb_net_tx_ring_max_chunks() == 10 && stats().max_bytes == (3 + 10 * CHUNK_FRAMES) * SLAB);
    ntb_credit = 0; grow_to(14); pump();
    assert(stats().chunks >= 5);
    assert(tinyusb_net_tx_ring_set_max_chunks(13) == ESP_ERR_INVALID_ARG);
    assert(tinyusb_net_tx_ring_set_max_chunks(2) == ESP_OK && tinyusb_net_tx_ring_max_chunks() == 2 && stats().max_bytes == (3 + 2 * CHUNK_FRAMES) * SLAB);
    check_invariants();
    assert(delivered_frames == 0);                                   /* nothing was dropped by lowering the cap */
    ntb_credit = -1;
    drain_all();
    for (int i = 0; i < 10; i++) { pump(); advance_mock_idle(); }
    assert(s_tx.chunks_present <= 2 && s_tx.chunks_live <= 2 && s_tx.flushed == 0);
    check_invariants();
    ntb_credit = 0;
    for (int i = 0; i < 40; i++) { send_len(1500); pump(); }         /* growth now stops at the new cap */
    assert(stats().chunks <= 2);
    ntb_credit = -1; drain_all();
    assert(tinyusb_net_tx_ring_set_max_chunks(10) == ESP_OK);        /* ... and raising it lets the ring grow again */
    ntb_credit = 0;
    for (int i = 0; i < 40; i++) { send_len(1500); pump(); }
    assert(stats().chunks > 2 && stats().chunks <= 10);
    ntb_credit = -1; drain_all();
    assert(tinyusb_net_tx_ring_set_max_chunks(0) == ESP_OK && tinyusb_net_tx_ring_max_chunks() == 0);
    for (int i = 0; i < 10; i++) pump();
    check_invariants();
}

/* Receive evidence: NTBs and bytes from the OUT completion, per-datagram dwell, hold episodes and how long the host waited. */
static esp_err_t rx_script;
static esp_err_t evid_cb(void *buffer, uint16_t len, void *ctx) { (void)buffer; (void)len; (void)ctx; return rx_script; }
static void test_rx_evidence(void) {
    tinyusb_net_deinit();
    tinyusb_net_config_t ncfg = {.on_recv_callback = evid_cb};
    assert(tinyusb_net_init(&ncfg) == ESP_OK);
    ring_reset(cfg_with(3, 4));                                       /* the ring being enabled turns the evidence on */
    tinyusb_net_rx_stats_t before; tinyusb_net_rx_stats(&before);
    uint8_t d[100] = {0};
    atomic_store(&mock_us, 5000000);
    __wrap_netd_xfer_cb(0, 0x01, 0, 3000);                            /* an OUT NTB of 3,000 B (the real callback is a stub) */
    atomic_store(&mock_us, 5000400);
    rx_script = TUSB_NET_RX_HOLD;
    assert(!tud_network_recv_cb(d, 100));                             /* 400 us after the NTB: held */
    atomic_store(&mock_us, 5002400);
    assert(!tud_network_recv_cb(d, 100));                             /* offered again, still held: one episode */
    atomic_store(&mock_us, 5009400);
    rx_script = ESP_OK;
    assert(tud_network_recv_cb(d, 100));                              /* taken after 9,000 us of hold */
    tinyusb_net_rx_stats_t st; tinyusb_net_rx_stats(&st);
    assert(st.ntbs == before.ntbs + 1 && st.ntb_bytes == before.ntb_bytes + 3000 && st.ntb_max_bytes >= 3000 && st.datagrams == before.datagrams + 3);
    assert(st.holds == before.holds + 1 && st.hold_us_sum == before.hold_us_sum + 9000 && st.hold_us_max == 9000);
    assert(st.dwell_us_max == 9400 && st.dwell_us_sum == before.dwell_us_sum + 400 + 2400 + 9400);
    tinyusb_net_deinit();
    tinyusb_net_config_t again = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&again) == ESP_OK);
}

/* tinyusb_net_tx_ring_flush(): the producer's own source changed (the transparent bridge's Wi-Fi link). Queued frames are stale, frames queued
 * after the call are not, and it never blocks. */
static void test_producer_flush(void) {
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0; grow_to(6); pump();
    assert(s_tx.frames_queued == 6 && s_tx.gen == 0);
    uint32_t flushed = s_tx.flushed;
    notify_count = 0;
    in_producer = 1;                                     /* the bridge calls it from its event task: it must not wait or defer */
    tinyusb_net_tx_ring_flush();
    in_producer = 0;
    assert(s_tx.gen == 1 && notify_count == 1);          /* the generation moved and the worker was woken to flush */
    ntb_credit = -1;
    delivered_seq = next_seq;                            /* the stale frames are never observed */
    assert(send_len(300) == ESP_OK);                     /* a frame after the call carries the new generation */
    pump(); in_complete(); pump();
    assert(delivered_frames == 1 && s_tx.flushed == flushed + 6 && s_tx.frames_queued == 0);
    check_pm(); check_invariants();
    /* On an empty ring it is harmless; frames after it are delivered. */
    tinyusb_net_tx_ring_flush();
    delivered_seq = next_seq;
    assert(send_len(300) == ESP_OK);
    pump(); in_complete(); pump();
    assert(delivered_frames == 2 && s_tx.gen == 2 && s_tx.flushed == flushed + 6);
    /* A stopped ring ignores it. */
    tinyusb_net_deinit();
    uint16_t gen = s_tx.gen;
    tinyusb_net_tx_ring_flush();
    assert(s_tx.gen == gen);
    tinyusb_net_config_t ncfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&ncfg) == ESP_OK);
}

#if CONFIG_PM_ENABLE
/* The CPU-frequency lock follows the queue: acquired by the worker after the first frame, released by the worker
 * after the last one left, never doubled, and not touched by producer or consumer. */
static void test_pm_lock(void) {
    ring_reset(cfg_with(3, 10));
    ntb_credit = 0;
    assert(send_len(400) == ESP_OK);
    assert(pm_acquires == 0);
    tx_worker_step();
    assert(pm_acquires == 1 && pm_releases == 0 && last_notify_wait == pdMS_TO_TICKS(200));   /* polling the link while queued */
    for (int i = 0; i < 10; i++) { assert(send_len(400) == ESP_OK); tx_worker_step(); }
    assert(pm_acquires == 1);                            /* one lock for the whole burst */
    run_deferred(); in_complete();
    assert(pm_releases == 0);                            /* blocked: still queued, still held */
    ntb_credit = -1; in_complete();
    assert(s_tx.frames_queued == 0 && pm_releases == 0); /* the consumer does not release: it wakes the worker */
    assert(notify_count > 0);
    tx_worker_step();
    assert(pm_acquires == 1 && pm_releases == 1 && mock_pm.held == 0);
    /* The next burst takes it again. */
    assert(send_len(400) == ESP_OK); pump();
    assert(pm_acquires == 2 && pm_releases == 2);
    /* Reclaim and elastic housekeeping never touch it. */
    gate_busy = true; tinyusb_net_tx_elastic_reclaim(0); tx_worker_step();
    assert(pm_acquires == 2 && pm_releases == 2);
    gate_busy = false;
}
#endif

/* Random everything: sizes, NTB availability, link flaps, gate, heap level, tick, reclaims, allocator failures,
 * duplicate callbacks. Invariant: accepted == delivered + flushed, in order, bytes intact; bookkeeping re-derived
 * from the bytes after every operation. */
static void soak_once(unsigned base, unsigned chunks, int rounds) {
    ring_reset(cfg_with(base, chunks));
    unsigned long accepted = 0, dropped = 0, grew = 0, shrank = 0, reclaimed = 0;
    uint32_t sent0 = s_tx.sent_frames, flushed0 = s_tx.flushed;
    unsigned maxslabs = base + chunks * CHUNK_FRAMES;
    for (int round = 0; round < rounds; round++) {
        unsigned op = rnd(20);
        if (op < 8) {
            uint16_t n = (rnd(4) == 0) ? 14 + rnd(60) : (rnd(3) == 0 ? 1200 + rnd(319) : 14 + rnd(1505));
            esp_err_t e = send_len(n);
            if (e == ESP_OK) accepted++; else { assert(e == ESP_ERR_NO_MEM); dropped++; }
            if (rnd(2)) tx_worker_step();
        } else if (op < 10) {
            ntb_credit = rnd(3) == 0 ? 0 : (int)rnd(6);
            if (rnd(4) == 0) ntb_credit = -1;
            pump();
        } else if (op == 10) {
            do_drain(NULL);
        } else if (op < 13) {
            if (rnd(3) == 0) ntb_credit = -1;
            in_complete();
        } else if (op == 13) {
            atomic_fetch_add(&mock_tick, rnd(3) ? rnd(300) : IDLE_MS + rnd(500));
            tx_worker_step();
        } else if (op == 14) {
            gate_busy = rnd(3) == 0;
            if (rnd(2)) tinyusb_net_tx_elastic_kick();
            tx_worker_step();
        } else if (op == 15) {
            heap_total = heap_live_bytes + (rnd(3) ? 200000 : (long)FLOOR_FREE + rnd(8000));
            mock_largest = rnd(4) ? 100000 : FLOOR_LARGEST - 1 + rnd(3000);
            malloc_fail = rnd(10) == 0;
            if (rnd(8) == 0) frag_next = FLOOR_LARGEST - 1 + rnd(2);
        } else if (op == 16) {
            if (rnd(2)) { gate_busy = true; (void)tinyusb_net_tx_elastic_reclaim(0); }
            else { gate_busy = true; delay_hook = reclaim_drain_hook; (void)tinyusb_net_tx_elastic_reclaim(rnd(60)); delay_hook = NULL; }
            gate_busy = rnd(2);
        } else if (op == 17 && rnd(6) == 0) {
            /* An outage: seen by the producer, by a drain, by the detach event, or by nobody until the poll. */
            usb_ready = 0;
            switch (rnd(4)) {
            case 0: (void)send_len(100); break;
            case 1: pump(); break;
            case 2: tinyusb_net_tx_ring_link_down(); pump(); break;
            default: notify_count = 0; tx_worker_step(); run_deferred(); break;
            }
            usb_ready = 1;
            /* Everything queued before the outage is stale or flushed; the host that comes back sees none of it. */
            ntb_credit = -1;
            if (rnd(2)) { usb_ready = 0; in_complete(); usb_ready = 1; }
            tx_worker_step();
            delivered_seq = next_seq;
        } else if (op >= 18) {
            do_drain(NULL);
            in_complete();
        }
        if (pending > 4) run_deferred();                   /* the TinyUSB task keeps up with its queue */
        check_invariants();
        assert(capacity_slabs() <= maxslabs && s_tx.fifo_n <= maxslabs);
        assert(heap_caps_get_free_size(0) < 1000000);
    }
    gate_busy = false; malloc_fail = 0; frag_next = 0;
    drain_all();
    check_invariants(); check_pm();
    tinyusb_net_tx_stats_t st = stats();
    grew = st.grow_events; shrank = st.shrink_events; reclaimed = st.reclaimed_chunks;
    uint32_t sent = s_tx.sent_frames - sent0, flushed = s_tx.flushed - flushed0;
    assert(accepted == sent + flushed);                    /* every accepted frame left the ring exactly once */
    assert(delivered_frames == sent);
    assert(sent > 500);
    assert(st.high_water_slabs <= maxslabs);
    printf("  soak base=%u chunks=%u: %lu accepted, %u sent, %u flushed, %lu dropped (full); %lu grown, %lu idle-freed, %lu reclaimed; high water %u slabs\n",
           base, chunks, accepted, sent, flushed, dropped, grew, shrank, reclaimed, st.high_water_slabs);
}
static void test_soak(void) {
    soak_once(3, 10, 200000);
    soak_once(2, 4, 100000);
    soak_once(4, 0, 100000);
    soak_once(8, 12, 100000);
}

/* ---- hardening: heap-walk cost, churn hysteresis, teardown during growth, one PM mechanism ---- */
static int hook_begin, hook_end, hook_open;
static void pm_begin_hook(void *ctx) { assert(!in_crit && !in_producer); assert(ctx == &hook_open); assert(!hook_open); hook_open = 1; hook_begin++; }
static void pm_end_hook(void *ctx) { assert(!in_crit && !in_producer); assert(ctx == &hook_open); assert(hook_open); hook_open = 0; hook_end++; }
static void deinit_in_grow(void) { tinyusb_net_deinit(); }

static void test_hardening(void) {
    /* Refusals back off exponentially, a growth resets it; the cheap O(1) free-size check runs before the heap walk. */
    ring_reset(cfg_with(3, 10));
    heap_total = (long)heap_live_bytes + FLOOR_FREE;      /* far below the floor */
    atomic_store(&largest_calls, 0);
    fill_pressure(3); tx_worker_step();
    assert(stats().grow_denied_heap == 1 && atomic_load(&largest_calls) == 0);   /* no walk for a total that already fails */
    uint32_t denied = 1;
    static const unsigned waits[] = { 100, 200, 400, 800, 1600, 1600 };
    for (unsigned i = 0; i < sizeof(waits) / sizeof(waits[0]); i++) {
        atomic_fetch_add(&mock_tick, waits[i] - 1);
        (void)send_len(1518); tx_worker_step();
        assert(stats().grow_denied_heap == denied);        /* one tick early: still backing off */
        atomic_fetch_add(&mock_tick, 1);
        (void)send_len(1518); tx_worker_step();
        assert(stats().grow_denied_heap == ++denied);
    }
    heap_total = 200000;
    atomic_fetch_add(&mock_tick, 1600);
    (void)send_len(1518); tx_worker_step();
    assert(stats().grow_events >= 1);
    drain_all();
    /* after a growth the back-off starts again at 100 ms */
    heap_total = (long)heap_live_bytes + FLOOR_FREE;
    ntb_credit = 0;
    for (int i = 0; i < 40; i++) (void)send_len(1518);     /* fill whatever exists, then the next growth is refused */
    tx_worker_step();
    uint32_t d0 = stats().grow_denied_heap;
    atomic_fetch_add(&mock_tick, 100);
    (void)send_len(1518); tx_worker_step();
    assert(stats().grow_denied_heap == d0 + 1);
    drain_all();

    /* Largest-block floor: a walk happens (before and after the allocation) only when the total allows a growth. */
    ring_reset(cfg_with(3, 10));
    atomic_store(&largest_calls, 0);
    fill_pressure(3); tx_worker_step();
    assert(stats().grow_events == 1 && atomic_load(&largest_calls) == 2);
    drain_all();

    /* Bursts every 5 s with a 10 s idle period: the chunks stay, the heap is not cycled (the 2 s default would
     * free and re-allocate all ten chunks per burst). */
    tinyusb_net_tx_config_t c = cfg_with(3, 10); c.idle_ms = 10000;
    ring_reset(c);
    ntb_credit = 0; grow_to(23); drain_all();
    long mallocs = atomic_load(&malloc_calls);
    for (int burst = 0; burst < 8; burst++) {
        atomic_fetch_add(&mock_tick, 5000);
        tx_worker_step();
        ntb_credit = 0; grow_to(23); drain_all();
    }
    tinyusb_net_tx_stats_t st = stats();
    assert(st.shrink_events == 0 && st.chunks == 10 && atomic_load(&malloc_calls) == mallocs && st.dropped_full == 0);
    /* a quiet spell longer than the idle period gives the memory back, one chunk per pass */
    atomic_fetch_add(&mock_tick, 10000);
    shrink_passes(1);
    assert(stats().chunks == 9);
    shrink_passes(12);
    assert(stats().chunks == 0 && stats().shrink_events == 10 && heap_live_blocks == 1);
    check_invariants();

    /* Teardown while a growth is allocating: the chunk is discarded, nothing is published after deinit. */
    ring_reset(cfg_with(3, 10));
    malloc_hook = deinit_in_grow;
    fill_pressure(3); tx_worker_step();
    st = stats();
    assert(st.grow_events == 0 && st.grow_raced == 1 && st.chunks == 0 && heap_live_blocks == 1);
    assert(tinyusb_net_tx_ring_start(&(const tinyusb_net_tx_config_t[]){ cfg_with(3, 10) }[0]) == ESP_OK);
    drain_all();

    /* One PM mechanism: with hooks the ring takes no lock of its own and the hooks alternate begin/end. */
    c = cfg_with(3, 10); c.pm_begin = pm_begin_hook; c.pm_end = pm_end_hook; c.pm_ctx = &hook_open;
    hook_begin = hook_end = hook_open = 0;
    ring_reset(c);
    assert(pm_acquires == 0);                            /* the caller's hooks, not the default ones, are in use */
    ntb_credit = 0;
    assert(send_len(400) == ESP_OK); pump();
    assert(hook_begin == 1 && hook_end == 0 && hook_open);
    for (int i = 0; i < 6; i++) { assert(send_len(400) == ESP_OK); tx_worker_step(); }
    assert(hook_begin == 1);                              /* one hold for the whole burst */
    ntb_credit = -1; in_complete(); tx_worker_step();
    assert(hook_begin == 1 && hook_end == 1 && !hook_open && stats().pm_held == 0 && stats().pm_acquired == 1);
    ntb_credit = 0;                                       /* link loss with frames queued ends the hold too */
    assert(send_len(400) == ESP_OK); pump();
    assert(hook_open);
    usb_ready = 0; tinyusb_net_tx_ring_link_down(); tx_worker_step(); run_deferred(); tx_worker_step();
    assert(!hook_open && hook_begin == 2 && hook_end == 2);
    usb_ready = 1;
    assert(send_len(400) == ESP_OK); pump();             /* and teardown */
    tinyusb_net_deinit(); tx_worker_step();
    assert(!hook_open && hook_begin == hook_end);
    /* the same hooks twice is a no-op restart, a different set is refused */
    assert(tinyusb_net_tx_ring_start(&c) == ESP_OK);
    c.pm_end = NULL; assert(tinyusb_net_tx_ring_start(&c) == ESP_ERR_INVALID_STATE);
    tinyusb_net_config_t ncfg = {.free_tx_buffer = released_ring};     /* deinit cleared the sync-path callbacks */
    assert(tinyusb_net_init(&ncfg) == ESP_OK);
}


/* ADR 0022: the evidence counters (NTB size, frames per drain, completion gaps, cold-start latency) and the worker's
 * priority split (relay high, heap work low, only when there is heap work). */
static void test_drain_evidence_and_priority(void) {
    tinyusb_net_tx_config_t c = cfg_with(3, 4);
    c.priority = 10; c.work_priority = 6;
    ring_reset(c);
    prio_sets = 0;
    /* No elastic memory and no growth wanted: the relay pass never touches the priority. */
    assert(send_len(300) == ESP_OK);
    atomic_store(&mock_us, 1000);
    pump();
    assert(prio_sets == 0 && stats().worker_demotions == 0);
    drain_all();
    /* Cold start: committed at t=5000 us, handed over by the consumer at t=5700 us. */
    ring_reset(c);
    atomic_store(&mock_us, 5000);
    assert(send_len(400) == ESP_OK);
    assert(send_len(500) == ESP_OK);          /* not a new edge: the queue was already non-empty */
    atomic_store(&mock_us, 5700);
    pump();
    tinyusb_net_tx_stats_t st = stats();
    assert(st.cold_starts == 1 && st.cold_us_sum == 700 && st.cold_us_max == 700);
    assert(st.drains_sent[1] == 1 && st.drains_sent[0] == 0);       /* both frames in one pass */
    /* A second edge after the queue emptied is measured again, and a stale (flushed) frame is not a cold start. */
    atomic_store(&mock_us, 9000);
    assert(send_len(600) == ESP_OK);
    atomic_store(&mock_us, 9100);
    pump();
    st = stats();
    assert(st.cold_starts == 2 && st.cold_us_sum == 800 && st.cold_us_max == 700 && st.drains_sent[0] == 1);
    /* Completions: sizes, a ZLP, and gaps counted only while frames are queued. */
    ring_reset(c);
    ntb_credit = 0;                            /* every NTB in flight: frames stay queued */
    assert(send_len(700) == ESP_OK);
    pump();
    assert(s_tx.frames_queued == 1);
    atomic_store(&mock_us, 10000); __wrap_netd_xfer_cb(0, 0x81, 0, 3000);      /* first completion: no previous one */
    atomic_store(&mock_us, 10900); __wrap_netd_xfer_cb(0, 0x81, 0, 2500);      /* 0.9 ms */
    atomic_store(&mock_us, 13000); __wrap_netd_xfer_cb(0, 0x81, 0, 0);         /* 2.1 ms, a ZLP */
    atomic_store(&mock_us, 30000); __wrap_netd_xfer_cb(0, 0x81, 0, 64);        /* 17 ms */
    st = stats();
    assert(st.ntb_xfers == 3 && st.ntb_zlp == 1 && st.ntb_bytes == 3000 + 2500 + 64 && st.ntb_max_bytes == 3000);
    assert(st.gap_count == 3 && st.gap_us_sum == 900 + 2100 + 17000 && st.gap_us_max == 17000);
    assert(st.gap_hist[0] == 1 && st.gap_hist[2] == 1 && st.gap_hist[4] == 1 && st.gap_hist[1] == 0);
    ntb_credit = -1;
    drain_all();
    /* Idle completions (nothing queued) do not produce gaps. */
    atomic_store(&mock_us, 50000); __wrap_netd_xfer_cb(0, 0x81, 0, 64);
    atomic_store(&mock_us, 90000); __wrap_netd_xfer_cb(0, 0x81, 0, 64);
    assert(stats().gap_count == 3);
    /* Heap work: growth demotes the worker for the growth and restores the relay priority, once per pass. */
    ring_reset(c);
    prio_sets = 0;
    fill_pressure(3);
    int before_prio = prio_sets;
    tx_worker_step();
    assert(prio_sets == before_prio + 2 && prio_cur == 10);                  /* down, then back up */
    assert(stats().worker_demotions >= 1);
    drain_all();
    /* Housekeeping with an elastic chunk present but no growth wanted (an idle pass) is not demoted. */
    ring_reset(c);
    fill_pressure(3);
    tx_worker_step();                          /* grows a chunk */
    drain_all();
    prio_sets = 0;
    assert(s_tx.chunks_present != 0 && !atomic_load(&s_tx.grow_wanted));
    tx_worker_step();
    assert(prio_sets == 0 && prio_cur == 10);
    /* Equal or unset work priority: never a call. */
    c.work_priority = 0; ring_reset(c);
    prio_sets = 0;
    fill_pressure(3);
    tx_worker_step();
    assert(prio_sets == 0);
    c.work_priority = 10; ring_reset(c);
    fill_pressure(3);
    tx_worker_step();
    assert(prio_sets == 0);
    drain_all();
}

int main(void) {
    tinyusb_net_config_t cfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    test_lifecycle();
    test_basic_and_no_blocking();
    test_fixed_capacity_and_packing();
    test_burst_absorption();
    test_growth_denied();
    test_reclaim_for_admission();
    test_idle_shrink();
    test_hardening();
    test_exactly_once_and_triggers();
    test_sync_and_ring_share_the_pipe();
    test_link_loss();
    test_producer_flush();
    test_rx_hold();
    test_set_max_chunks();
    test_rx_evidence();
    test_drain_evidence_and_priority();
#if CONFIG_PM_ENABLE
    test_pm_lock();
#endif
    test_soak();
    printf("PASS: TinyUSB elastic transmit ring: non-blocking producer, burst absorption to the cap, growth denied under low heap/largest block/gate, reclaim for admission with frames in flight, idle shrink, exactly-once delivery, link-generation flush, CPU-frequency lock pairing\n");
}
