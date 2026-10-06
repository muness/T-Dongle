#ifndef ML_HEAP_BUDGET_H
#define ML_HEAP_BUDGET_H
/* One heap budget for everything that grows under traffic (ADR 0022).
 *
 * The finding. Board, UDP iperf3 -R, 6 Mbit/s, release and diagnostics builds: free heap steady 36-38 KB, minimum free 3,040-3,140 B.
 * Three kinds of consumer draw on the ~20 KB above the 16 KiB recovery reserve, and they did not know about each other:
 *   1. CHECKED, elastic: the USB ring's growth chunks (floor 32,384 B then; recovery + negotiation peak now), the WireGuard receive
 *      queue (floor: the recovery reserve only, 16,384 B), the router queue (same), pending outbound packets (same).
 *   2. UNCHECKED, latent: the Wi-Fi driver's dynamic buffers. A datagram that has reached lwIP's socket mailbox pins the driver's
 *      RX buffer (a heap block of about the frame size plus a header) until net_io reads it, and CONFIG_LWIP_UDP_RECVMBOX_SIZE
 *      = 10 allowed ten of them, ~16 KB, arriving within microseconds (one A-MPDU), before net_io could run. Nothing checks the
 *      heap when the driver allocates them. The same holds for the TCP receive window (8 segments) and for the driver's TX buffers
 *      (upload: 16 dynamic, ~26 KB).
 *   Every checked consumer looks at the free heap NOW and stops at its own floor, so each is correct alone. Together: the ring stops
 *   at 32.4 KB, the queue (floor 16.4 KB) then fills its 12 KB below that, and the next burst pins ten RX buffers below THAT:
 *   37 - 5 (ring) - 12 (queue) - 16 (pins) = 4 KB. That is the board's 3 KB. Nothing was refusing anything; the arithmetic
 *   simply promised the same bytes three times.
 *
 * The bound. A consumer that checks the free heap must leave, in addition to the recovery reserve, whatever can still be taken
 * from the heap AFTER the check without a check of its own: the pinned buffers of the largest burst a socket can hold, plus
 * the allocations of the other checkers that race this check (two: net_io and the DERP loop on one core, the USB side on the
 * other, each at most one full buffer). So
 *
 *     ML_HB_FLOOR >= ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES
 *
 * and every elastic consumer uses ONE floor, the one admission already defines for the long-lived elastic memory
 * (ml_adm_elastic_floor(true): recovery reserve + one negotiation peak). The static assertion below makes the inequality a
 * build error, and sets the largest burst the unchecked claimants may be configured to produce (ML_HB_PIN_BUFFERS), which
 * gateway_main.c, tcp_window_budget.h and tools/test-heap-budget.py hold the lwIP and Wi-Fi settings to. When the negotiation peak
 * shrinks again (it was 16,000 B, is 13,500 B), the largest allowed burst shrinks with it, loudly, at build time.
 *
 * Wi-Fi buffers (amendment 2, 2026-10-06). The pool of dynamic Wi-Fi buffers is larger than ML_HB_PIN_BUFFERS (6): 16 RX and 16 TX. Each
 * unchecked source (the UDP mailbox, the TCP window, the tcpip mailbox, the TX pool) was held to 6 on its own and nothing held them
 * together, and the board's minimum under a 6 Mbit/s UDP download plus TCP download was 5,000 B. They are now counted where they
 * start and admitted to the same budget (main/wifi_pin_budget.h): a shared BAND of ML_HB_PIN_BUFFERS - 1 buffers (5, at most 4 per direction, plus 1 for the RX frame under
 * check) that the floor pays for, and anything beyond it only while the free heap stays at or above ML_HB_FLOOR. TX: the STA netif's
 * transmit, released by the driver's tx-done callback. RX: where the frame enters lwIP, released when its pbuf is freed.
 * The remaining unchecked allocations on the data path are each one block at a time, inside the racing-checker slack: the DERP link's
 * transmit frame (one per link, built from a queue entry that is released at once), the router's output pbuf (replaces the datagram
 * it was made from), and the WireGuard datagram copy for a pbuf chain (never built here, checked anyway).
 *
 * Every refusal is counted (ml_hb_refused[], /status `heap_budget`), never silent, never a crash: the datagram or frame is dropped
 * and TCP or the sender treats it as loss.
 */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ml_admission.h"

#define ML_HB_RESERVE ML_ADM_RECOVERY_BYTES
/* The long-lived elastic floor: ONE number for the USB ring's growth, the WireGuard receive queue (always, not only during a join:
 * a flood is when it matters), the router queue above its two-packet minimum, pending outbound packets, USB receive frames and
 * the DERP relay's transmit queue. */
#define ML_HB_FLOOR (ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES)

/* What a pinned Wi-Fi RX buffer costs: the frame (<= 1,514 B plus the 802.11 and driver headers) rounded up, and the allocator
 * header. The driver sizes dynamic buffers by frame, so a full-size WireGuard datagram is the case that matters. */
#define ML_HB_PIN_BUF_BYTES 1664u
/* Allocators that can pass their floor check before another has allocated: net_io, the DERP loop, usb_rx, the USB ring worker. */
#define ML_HB_SLACK_BYTES (2u * ML_HB_PIN_BUF_BYTES)
/* The largest burst of Wi-Fi buffers any one socket may pin: the greatest N with
 *   ML_HB_RESERVE + N * ML_HB_PIN_BUF_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR. */
#define ML_HB_PIN_BUFFERS ((unsigned)((ML_HB_FLOOR - ML_HB_RESERVE - ML_HB_SLACK_BYTES) / ML_HB_PIN_BUF_BYTES))
#define ML_HB_PIN_BYTES (ML_HB_PIN_BUFFERS * ML_HB_PIN_BUF_BYTES)

_Static_assert(ML_HB_PIN_BUFFERS >= 4, "the elastic floor leaves room for fewer than four pinned Wi-Fi buffers: the receive path cannot be sized");
_Static_assert(ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR,
               "the elastic floor must cover the recovery reserve, the pinned Wi-Fi buffers of the largest burst and the racing checkers");
_Static_assert(ML_HB_FLOOR == ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES, "one elastic floor: the one admission defines for long-lived elastic memory");

/* The check every elastic consumer makes: after taking `cost` bytes, at least ML_HB_FLOOR must remain free. */
static inline bool ml_hb_ok(size_t free_internal, size_t cost) { return free_internal >= (size_t)ML_HB_FLOOR + cost; }

/* A datagram or relay frame about to be copied into a heap block that then waits in a queue the receiver reads (net_io, the DERP link):
 * the elastic check, with one exemption so a path can still be discovered and kept alive in a flood: a small datagram (DISCO pings and
 * pongs are ~150 B, STUN responses ~100 B, CallMeMaybe a few hundred) is taken when its destination queue is EMPTY, which costs at most
 * one such block per queue (two queues and the DERP receive buffer per membership) below the floor. WireGuard data has no exemption
 * (ml_wgrx_admit_gated is the check there, bytes as well as heap). */
#define ML_HB_RX_SMALL_BYTES 512u
static inline bool ml_hb_rx_ok(size_t free_internal, size_t len, bool destination_empty) {
    return (destination_empty && len <= ML_HB_RX_SMALL_BYTES) || ml_hb_ok(free_internal, len + 16u);
}

/* Where a refusal happened. Always on (one relaxed increment on a path that is already dropping a packet). */
/* The WireGuard receive queue (ml.q_wg_heap) and the router queue (route.* drops) already count their own refusals. */
typedef enum {
    ML_HB_JIT,          /* packet pending a peer handshake */
    ML_HB_DERP_TX,      /* relay transmit queue */
    ML_HB_RX_CTRL,      /* DISCO or STUN datagram from the UDP socket, refused before its copy was made */
    ML_HB_DERP_RX,      /* relayed frame refused before its receive buffer was allocated */
    ML_HB_WG_COPY,      /* WireGuard datagram copy for a pbuf chain refused */
    ML_HB_SITE_COUNT
} ml_hb_site_t;
extern atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];
static inline void ml_hb_refuse(ml_hb_site_t site) { atomic_fetch_add_explicit(&ml_hb_refused[site], 1, memory_order_relaxed); }

#endif
