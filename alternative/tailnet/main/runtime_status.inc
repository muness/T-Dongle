/* /status: the shared runtime. Everything an admission decision, a stalled join or a pool eviction is judged by:
 * the admission arithmetic, the shared tasks (stack headroom, longest slice, detach timeouts), the negotiation
 * token, the global WireGuard peer-slot pool and the shared random generator. Bounded, no allocation. */
static void status_shared_runtime(jw_writer *w) {
#define RNUM(name, value) do { jw_key(w, name); jw_number(w, (uint32_t)(value)); jw_char(w, ','); } while (0)
    ml_adm_budget_t b = admission_budget();
    jw_raw(w, "\"admission\":{");
    RNUM("required_bytes", b.required);
    RNUM("shared_runtime_bytes", b.shared_runtime);
    RNUM("member_start_bytes", b.member_start);
    RNUM("member_growth_bytes", b.member_growth);
    RNUM("member_steady_bytes", b.member_steady);
    RNUM("negotiation_reserve_bytes", b.negotiation);
    RNUM("recovery_reserve_bytes", b.recovery);
    RNUM("largest_block_required", b.largest_block);
    RNUM("peer_slots_charged", ML_ADM_PEER_SLOTS);
    jw_key(w, "peer_slot_bytes"); jw_number(w, (uint32_t)ml_wg_slot_bytes());
    jw_raw(w, "},");

    ml_rt_status_t rt;
    ml_rt_status(&rt);
    static const char *const task_names[ML_RT_TASK_COUNT] = {"net_io", "derp", "wg_mgr"};
    jw_raw(w, "\"shared_runtime\":{");
    jw_key(w, "running"); jw_bool(w, rt.running); jw_char(w, ',');
    RNUM("members", rt.members);
    RNUM("starts", rt.starts);
    RNUM("stops", rt.stops);
    RNUM("attach_failures", rt.attach_failures);
    RNUM("detach_failures", rt.detach_failures);
    jw_raw(w, "\"tasks\":{");
    for (unsigned t = 0; t < ML_RT_TASK_COUNT; t++) {
        if (t) jw_char(w, ',');
        jw_key(w, task_names[t]);
        jw_char(w, '{');
        RNUM("stack_bytes", rt.stack_bytes[t]);
        jw_key(w, "stack_free");
        if (rt.stack_free[t] == UINT32_MAX) jw_raw(w, "null"); else jw_number(w, rt.stack_free[t]);
        jw_char(w, ',');
        RNUM("passes", rt.passes[t]);
        RNUM("max_slice_ms", rt.max_service_ms[t]);
        RNUM("slow_slices", rt.slow_services[t]);
        jw_key(w, "detach_timeouts"); jw_number(w, rt.detach_timeouts[t]);
        jw_char(w, '}');
    }
    jw_raw(w, "}},");

    jw_raw(w, "\"negotiation\":{");
    jw_key(w, "holder"); jw_string(w, rt.negotiation.holder ? ml_neg_phase_name(rt.negotiation.phase) : "none"); jw_char(w, ',');
    RNUM("held_ms", rt.negotiation.held_ms);
    RNUM("waiting", rt.negotiation.waiting);
    RNUM("grants", rt.negotiation.grants);
    RNUM("timeouts", rt.negotiation.timeouts);
    RNUM("lease_expired", rt.negotiation.lease_expired);
    RNUM("stale_dropped", rt.negotiation.stale_dropped);
    RNUM("refused_full", rt.negotiation.refused_full);
    RNUM("max_wait_ms", rt.negotiation.max_wait_ms);
    jw_key(w, "max_hold_ms"); jw_number(w, rt.negotiation.max_hold_ms);
    jw_raw(w, "},");

    ml_wg_pool_status_t pool;
    ml_wg_pool_status(&pool);
    jw_raw(w, "\"wg_pool\":{");
    RNUM("capacity", pool.capacity);
    RNUM("used", pool.used);
    RNUM("peak", pool.peak);
    RNUM("refused_full", pool.refused_full);
    RNUM("refused_nomem", pool.refused_nomem);
    RNUM("evictions_own", pool.evictions_own);
    RNUM("evictions_other", pool.evictions_other);
    RNUM("rejected", pool.rejected);
    RNUM("refused_largest", pool.refused_largest);
    jw_key(w, "largest_low"); if (pool.largest_low == UINT32_MAX) jw_raw(w, "null"); else jw_number(w, pool.largest_low); jw_char(w, ',');
    RNUM("slot_bytes", pool.slot_bytes);
    jw_key(w, "device_bytes"); jw_number(w, pool.device_bytes);
    jw_raw(w, "},");

    ml_rng_stats_t rng;
    ml_rng_stats(&rng);
    jw_raw(w, "\"shared_rng\":{");
    RNUM("users", rng.users);
    RNUM("resident_bytes", rng.bytes_resident);
    RNUM("seedings", rng.seedings);
    jw_key(w, "failures"); jw_number(w, rng.failures);
    jw_raw(w, "},");
#undef RNUM
}
