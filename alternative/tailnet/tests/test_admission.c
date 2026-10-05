/* Admission from measured constants (ml_admission.h). Sizes below are the xtensa sizeof values of this tree. */
#include <assert.h>
#include <stdio.h>
#include "ml_admission.h"

int main(void) {
    ml_adm_sizes_t s = {.context = 10256, .coord_stack = 8704, .task_tcb = 340, .queues = 1500, .wg_device = 228,
                        .wg_slot = 904, .shared_stacks = 7168 + 7680 + 8192, .shared_tasks = 3};
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
    assert(next.member_growth == 228 + 4 * 904 + ML_ADM_TLS_LIVE_BYTES + ML_ADM_LWIP_BYTES + ML_ADM_OTHER_BYTES);
    assert(next.required == next.member_steady + 16000 + 16384);
    /* Decisions: budget first, then the contiguous block. */
    assert(ml_adm_decide(&next, next.required, 24000) == ML_ADM_OK);
    assert(ml_adm_decide(&next, next.required - 1, 99999) == ML_ADM_REFUSED_BUDGET);
    assert(ml_adm_decide(&next, 999999, 23999) == ML_ADM_REFUSED_LARGEST);
    /* The old gate charged 108,200 B to every membership; the first now needs less, and the second needs the
     * marginal cost only. */
    assert(first.required < 108200 && next.required < first.required);
    printf("admission: first membership needs %zu B free, each further one %zu B (steady %zu + negotiation %zu + reserve %zu)\n",
           first.required, next.required, next.member_steady, next.negotiation, next.recovery);
    return 0;
}
