#ifndef ML_WG_RX_BUDGET_H
#define ML_WG_RX_BUDGET_H
/* Memory bound on the datagrams waiting for wg_mgr (ADR 0020).
 *
 * What a queued datagram costs. The datagram is copied out of the Wi-Fi RX buffer into a heap block by the producer (net_io for
 * the direct path, the DERP loop for relayed traffic), and the pointer goes into wg_rx_queue. So a waiting datagram pins HEAP
 * (len + allocator overhead, ~1.3 KB for a 1,264 byte WireGuard datagram), not a Wi-Fi RX buffer: the RX buffers (6 static +
 * 16 dynamic) are held only by the lwIP socket mailbox (CONFIG_LWIP_UDP_RECVMBOX_SIZE, ADR 0019) until net_io copies the
 * datagram out, and moving a datagram from the mailbox into this queue RELEASES its RX buffer. Heap is what is scarce: the
 * elastic USB transmit ring (ADR 0015) stops growing at the same free-heap floor, and the first membership leaves ~3 KB of
 * admission margin (ADR 0019), so the number of slots alone says nothing: sixteen 1.3 KB datagrams are 20 KB, sixteen ACKs
 * are 1 KB.
 *
 * So the queue is bounded by BYTES, across every membership (one counter: N memberships do not multiply it), and by the free
 * heap: a datagram is refused when it would take the bytes past ML_WG_RX_QUEUE_BYTES, or leave less free internal heap than the
 * recovery reserve (ML_ADM_RECOVERY_BYTES, what HTTP/control recovery cannot do without). Each refusal is counted
 * (ml.q_wg_bytes, ml.q_wg_heap), the slots stay as the count bound (ML_WG_RX_QUEUE_DEPTH, in microlink_internal.h).
 *
 * Sizing (the arithmetic, so the number can be changed with the evidence of a board run):
 *   - A burst arrives as a step. net_io empties the socket mailbox (at most CONFIG_LWIP_UDP_RECVMBOX_SIZE = 10 datagrams, and
 *     at most ML_NET_IO_DRAIN_CAP = 16 per pass) into the queue within microseconds, long before wg_mgr, on the other core, is
 *     even awake. Datagrams that do not fit in the queue at that instant are lost, whatever wg_mgr's speed afterwards. Board run
 *     (UDP -R, 1,200 byte payload, 3 Mbit/s): 153 of 3,045 offered datagrams (5 %) found the 8-slot queue full.
 *   - 12 KiB holds 9 full-size datagrams (the old 8 slots held 8) and, by the 16-slot count bound, 16 small ones (ACKs, DNS,
 *     keepalives), which the old 8 slots did not; wg_mgr pops them in runs of ML_WG_RX_BATCH, which frees their slots at once.
 *   - Larger would be cheap in code but is paid in heap that the transmit ring needs at the same moment: the ring's last growth
 *     step is denied at 32 KB free, so the headroom shared by both is a few KB, and the budget keeps the queue's share to what it
 *     had. The run in progress (at most ML_WG_RX_BATCH datagrams, already popped) is the only memory outside this budget.
 *   `wgperf` stage rx_qdepth (queue depth at the start of every drain: mean and maximum) is the number that says whether the
 *   bound is right: a maximum that stays at the cap while ml.q_wg_bytes / q_wg_full rise means the bursts are bigger than the
 *   heap can hold, and the remedy is elsewhere (the transmit ring, the mailbox), not here. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include "ml_admission.h"

#define ML_WG_RX_QUEUE_BYTES 12288u
#define ML_WG_RX_FLOOR_FREE  ML_ADM_RECOVERY_BYTES
/* While a join is in progress (the negotiation token is held) the floor is the one the USB transmit ring obeys (gateway_main.c,
 * GATEWAY_USB_TX_FLOOR_FREE): recovery reserve plus one negotiation peak. The queue is ELASTIC memory: it exists only while datagrams
 * wait, and it must not be what takes the heap a DERP TLS handshake needs (16,000 B above steady, ml_admission.h). Outside a join
 * the recovery reserve is the only floor, as before. */
#define ML_WG_RX_JOIN_FLOOR_FREE (ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES)
#define ML_WG_RX_OVERHEAD    16u      /* allocator header and rounding, charged per datagram */

typedef struct { atomic_uint bytes; atomic_uint peak; } ml_wgrx_budget_t;
extern ml_wgrx_budget_t ml_wgrx_budget;

typedef enum { ML_WGRX_OK = 0, ML_WGRX_BYTES, ML_WGRX_HEAP } ml_wgrx_verdict_t;

/* Reserve `len` bytes for a datagram about to be queued; the caller releases them when it is popped or freed. `free_internal` is
 * the free internal heap measured by the caller (so the host tests inject it). `join_busy` (may be NULL) says whether a join is in
 * progress; it is asked only when the free heap is between the two floors, so the common case never takes the negotiation lock. */
typedef bool (*ml_wgrx_busy_fn)(void);
bool ml_wgrx_join_busy(void);   /* ml_net_io.c: ml_neg_busy(ml_rt_negotiation()) */
static inline ml_wgrx_verdict_t ml_wgrx_admit_gated(ml_wgrx_budget_t *b, size_t len, size_t free_internal, ml_wgrx_busy_fn join_busy) {
    const unsigned cost = (unsigned)len + ML_WG_RX_OVERHEAD;
    if (free_internal < (size_t)ML_WG_RX_FLOOR_FREE + cost) return ML_WGRX_HEAP;
    if (free_internal < (size_t)ML_WG_RX_JOIN_FLOOR_FREE + cost && join_busy && join_busy()) return ML_WGRX_HEAP;
    unsigned seen = atomic_load_explicit(&b->bytes, memory_order_relaxed);
    do {
        if (seen + cost > ML_WG_RX_QUEUE_BYTES) return ML_WGRX_BYTES;
    } while (!atomic_compare_exchange_weak_explicit(&b->bytes, &seen, seen + cost, memory_order_relaxed, memory_order_relaxed));
    unsigned now = seen + cost, peak = atomic_load_explicit(&b->peak, memory_order_relaxed);
    while (now > peak && !atomic_compare_exchange_weak_explicit(&b->peak, &peak, now, memory_order_relaxed, memory_order_relaxed)) {
    }
    return ML_WGRX_OK;
}
static inline ml_wgrx_verdict_t ml_wgrx_admit(ml_wgrx_budget_t *b, size_t len, size_t free_internal) {
    return ml_wgrx_admit_gated(b, len, free_internal, NULL);
}
/* Bytes waiting now: admission counts them as free heap (they drain as soon as wg_mgr runs; same rule as the elastic USB ring,
 * which is reclaimed before the measurement), so a burst in the queue at the moment of a join cannot make the join look short. */
static inline size_t ml_wgrx_queued(const ml_wgrx_budget_t *b) { return atomic_load_explicit(&b->bytes, memory_order_relaxed); }
static inline void ml_wgrx_release_to(ml_wgrx_budget_t *b, size_t len) {
    atomic_fetch_sub_explicit(&b->bytes, (unsigned)len + ML_WG_RX_OVERHEAD, memory_order_relaxed);
}
static inline void ml_wgrx_release(size_t len) { ml_wgrx_release_to(&ml_wgrx_budget, len); }

#endif
