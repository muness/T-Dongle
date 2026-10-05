/* Admission from measured constants (ml_admission.h). Sizes below are the xtensa sizeof values of this tree. */
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include "ml_admission.h"

int main(void) {
    ml_adm_sizes_t s = {.context = 10256, .coord_stack = 8704, .task_tcb = 340, .queues = 1500, .wg_device = 228,
                        .wg_slot = 904, .shared_stacks = 7168 + 7680 + 8192, .shared_tasks = 3, .route_queue_min = 2800};
    ml_adm_budget_t first, next;
    ml_adm_budget(&s, false, &first);
    ml_adm_budget(&s, true, &next);
    /* The shared tasks are charged once: the first membership pays for them, later ones do not. */
    assert(first.shared_runtime == 23040 + 3 * 340 && next.shared_runtime == 0);
    assert(first.required - next.required == first.shared_runtime);
    /* One negotiation peak and one recovery reserve, however many memberships there are. */
    assert(first.negotiation == ML_ADM_NEG_PEAK_BYTES && next.negotiation == first.negotiation);
    assert(next.member_steady == next.member_start + next.member_growth);
    assert(next.member_start == 10256 + 8704 + 340 + 1500);
    assert(next.member_growth == 228 + 4 * 904 + ML_ADM_TLS_LIVE_BYTES + ML_ADM_LWIP_BYTES + ML_ADM_OTHER_BYTES + 2 * 1464);
    assert(next.required == next.member_steady + ML_ADM_NEG_PEAK_BYTES + ML_ADM_RECOVERY_BYTES + 2800 && next.router == 2800);
    /* The negotiation peak is the handshake WITHOUT the RSA-4096 cross-signature check (ml_derp_tls.c trust anchor match):
     * the board's 15,964 B above steady less the estimated 4,500 B. The coord stack is held by the rule in microlink_internal.h. */
    assert(ML_ADM_NEG_PEAK_BYTES == 11500 && 15964 - 4500 <= ML_ADM_NEG_PEAK_BYTES);
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
    assert(ml_adm_slot_alloc_ok(24576, 24576 - 904, floor));            /* the measured steady block, one slot out of it: fine */
    assert(ml_adm_slot_alloc_ok(24576, 24576, floor));                   /* carved from a small hole: no effect */
    assert(!ml_adm_slot_alloc_ok(floor + 100, floor + 100 - 904, floor)); /* this slot is the one that breaks the floor */
    assert(!ml_adm_slot_alloc_ok(floor, floor - 1, floor));
    assert(ml_adm_slot_alloc_ok(floor - 1, floor - 904, floor));         /* already below: not this allocation's doing */
    /* Why the pool is not static: 12 slots resident for ever against the four admission charges per membership. */
    const size_t static_extra = (12 - ML_ADM_PEER_SLOTS) * s.wg_slot;
    assert(static_extra == 7232 && static_extra > 576);                  /* 576 B = the measured margin of the largest block */
    printf("peer pool: a static pool would take %zu B more than the %d slots charged; free after boot ~107,000 B leaves the first membership %zd B of margin instead of %zd B\n",
           static_extra, ML_ADM_PEER_SLOTS, (ssize_t)107000 - (ssize_t)first.required - (ssize_t)static_extra,
           (ssize_t)107000 - (ssize_t)first.required);
    return 0;
}
