/* Admission from measured constants (ml_admission.h). Sizes below are the xtensa sizeof values of this tree. */
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include "ml_admission.h"

int main(void) {
    /* sizes of this tree on the target: queues = 1,500 B + 4 more WG RX slots (4 x 48 B, ADR 0020), wg_device 228 B + rx_batch_fn and rx_ipv6 (8 B) */
    ml_adm_sizes_t s = {.context = 10256, .coord_stack = 8704, .task_tcb = 340, .queues = 1500 + 192, .wg_device = 228 + 8,
                        .wg_slot = 1096, .shared_stacks = 7168 + 7680 + 8192, .shared_tasks = 3, .route_queue_min = 2800};
    ml_adm_budget_t first, next;
    ml_adm_budget(&s, false, &first);
    ml_adm_budget(&s, true, &next);
    /* The shared tasks are charged once: the first membership pays for them, later ones do not. */
    assert(first.shared_runtime == 23040 + 3 * 340 && next.shared_runtime == 0);
    assert(first.required - next.required == first.shared_runtime);
    assert(first.shared_runtime == 24060 && first.member_steady == 20992 + 18664 + 0 && first.required == 96400);
    /* One negotiation peak and one recovery reserve, however many memberships there are. */
    assert(first.negotiation == ML_ADM_NEG_PEAK_BYTES && next.negotiation == first.negotiation);
    assert(next.member_steady == next.member_start + next.member_growth);
    assert(next.member_start == 10256 + 8704 + 340 + 1692);
    assert(next.member_growth == 236 + ML_ADM_PEER_SLOTS * 1096 + ML_ADM_TLS_LIVE_BYTES + ML_ADM_LWIP_BYTES + ML_ADM_OTHER_BYTES);
    assert(next.required == next.member_steady + ML_ADM_NEG_PEAK_BYTES + 16384 + 2800 && next.router == 2800);
    /* The negotiation peak is the handshake WITHOUT the RSA-4096 cross-signature check (ml_derp_tls.c trust anchor match):
     * the board's 15,964 B above steady less the 2,780 B the board measured (not the host's 5,824 B). The coord stack is held by the rule in microlink_internal.h. */
    assert(ML_ADM_NEG_PEAK_BYTES == 13500 && 15964 - 2780 <= ML_ADM_NEG_PEAK_BYTES);
    /* Decisions: budget first, then the contiguous block. */
    assert(ml_adm_decide(&next, next.required, 24000) == ML_ADM_OK);
    assert(ml_adm_decide(&next, next.required - 1, 99999) == ML_ADM_REFUSED_BUDGET);
    assert(ml_adm_decide(&next, 999999, 23999) == ML_ADM_REFUSED_LARGEST);
    /* The old gate charged 108,200 B to every membership; the first now needs less, and the second needs the
     * marginal cost only. */
    assert(first.required < 108200 && next.required < first.required);
    printf("admission: first membership needs %zu B free, each further one %zu B (steady %zu + negotiation %zu + reserve %zu)\n",
           first.required, next.required, next.member_steady, next.negotiation, next.recovery);
    /* Peer-slot allocation guard: a slot may not be the allocation that takes the largest free block under the TLS floor. */
    const size_t floor = ML_ADM_TLS_BLOCK_FLOOR;
    assert(ml_adm_slot_alloc_ok(24576, 24576 - 1096, floor));            /* the measured steady block, one slot out of it: fine */
    assert(ml_adm_slot_alloc_ok(24576, 24576, floor));                   /* carved from a small hole: no effect */
    assert(!ml_adm_slot_alloc_ok(floor + 100, floor + 100 - 1096, floor)); /* this slot is the one that breaks the floor */
    assert(!ml_adm_slot_alloc_ok(floor, floor - 1, floor));
    assert(ml_adm_slot_alloc_ok(floor - 1, floor - 1096, floor));         /* already below: not this allocation's doing */
    /* Why the pool is not static: 12 slots resident for ever against the four admission charges per membership. */
    const size_t static_extra = (12 - ML_ADM_PEER_SLOTS) * s.wg_slot;
    assert(static_extra == 10 * 1096 && static_extra > 576);                  /* 576 B = the measured margin of the largest block */
    printf("peer pool: a static pool would take %zu B more than the %d slots charged; free after boot ~107,000 B leaves the first membership %zd B of margin instead of %zd B\n",
           static_extra, ML_ADM_PEER_SLOTS, (ssize_t)107000 - (ssize_t)first.required - (ssize_t)static_extra,
           (ssize_t)107000 - (ssize_t)first.required);

    /* ---- The first membership's margin (ADR 0020 "Admission margin"). Boot free heap is ~107,000 B (ADR 0013/0015/0019; it varies
     * by about 5 KB between boots, so the margin is judged at 107,000 and at 102,000). ---- */
    const ssize_t boot = 107000, boot_low = 102000;
    /* What it was: ADR 0019 left 3,180 B; ADR 0020 as first submitted (+192 B of queue, +8 B of device) 2,980 B. The old terms were four
     * charged resident slots and two "typical" pending packets. */
    const size_t old_required = first.required + (16000 - ML_ADM_NEG_PEAK_BYTES) + (4 - ML_ADM_PEER_SLOTS) * 1096 + 2 * 1464;   /* with the 16,000 B peak of then */
    assert(old_required == 104020 && boot - (ssize_t)old_required == 2980 && boot_low - (ssize_t)old_required < 0);   /* refused on a low boot */
    /* What it is: both terms are elastic and refused at allocation time instead of reserved. */
    const ssize_t margin = boot - (ssize_t)first.required, margin_low = boot_low - (ssize_t)first.required;
    assert(margin >= 8000 && margin_low >= 3000);
    /* The static DRAM the inbound run adds (g_rx_* in ml_wg_mgr.c: 1,148 B of symbols, 1,184 B of `.bss` measured by `idf.py size`) is not in the 107,000 measured before it: counted
     * against the margin it is still above the bar this change was asked to meet minus that cost, and the board reads the real figure. */
    const ssize_t statics = 1184;
    assert(margin - statics >= 6900);
    printf("margin: first membership needs %zu B (was %zu); at 107,000 B free %zd B (was %zd), at 102,000 B %zd B (was %zd); net of the %zd B of run statics %zd B\n",
           first.required, old_required, margin, boot - (ssize_t)old_required, margin_low, boot_low - (ssize_t)old_required, statics, margin - statics);
    /* Elastic floors: the recovery reserve for everything, one negotiation peak more for what persists or must not starve a join. */
    assert(ml_adm_elastic_floor(false) == 16384 && ml_adm_elastic_floor(true) == 16384 + 13500 && ml_adm_elastic_floor(true) == 29884);
    /* Peer slots: the guaranteed ones keep the recovery reserve, the others a negotiation peak as well. */
    const size_t slot = 1096;
    assert(ML_ADM_PEER_SLOTS == 2);
    assert(ml_adm_slot_heap_ok(0, 16384 + slot, slot) && !ml_adm_slot_heap_ok(0, 16384 + slot - 1, slot));
    assert(ml_adm_slot_heap_ok(1, 16384 + slot, slot) && !ml_adm_slot_heap_ok(1, 16384 + slot - 1, slot));
    assert(!ml_adm_slot_heap_ok(2, 16384 + slot, slot) && ml_adm_slot_heap_ok(2, (16384 + 13500) + slot, slot) && !ml_adm_slot_heap_ok(2, (16384 + 13500) + slot - 1, slot));
    /* How many slots a first membership can actually hold beyond the guaranteed ones, from the free heap that is left after it has
     * started (boot free less the steady cost of the model above, with the guaranteed slots resident): at 107,000 B and at 102,000 B. */
    for (int b = 0; b < 2; b++) {
        ssize_t free_heap = (b ? boot_low : boot) - (ssize_t)(first.shared_runtime + first.member_steady);
        unsigned live = ML_ADM_PEER_SLOTS, extra = 0;
        while (live < 12 && ml_adm_slot_heap_ok(live, (size_t)free_heap, slot)) { free_heap -= slot; live++; extra++; }
        printf("peer slots: with %zd B boot free the guaranteed %d slots plus %u elastic ones (%u of the 12-slot pool) can be resident\n",
               b ? (ssize_t)boot_low : (ssize_t)boot, ML_ADM_PEER_SLOTS, extra, live);
        assert(live >= 5);   /* the exit node and several destinations, even on a low boot: LRU eviction makes up the rest */
    }
    return 0;
}
