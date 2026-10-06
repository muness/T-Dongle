//! The `/status` body of `status()` in gateway_main.c and the two sections of runtime_status.inc, key for key and in the same order.

use crate::input::*;
use crate::jw::{ChunkSink, JsonWriter, ip_to_str};

/// Write the whole `/status` JSON to `sink` in the C's chunks. Returns false if the sink failed at any point (the C answers `ESP_FAIL` then and sends
/// no terminating chunk; the caller does the same).
pub fn write_status(sink: &mut dyn ChunkSink, s: &Status<'_>) -> bool {
    let mut w = JsonWriter::new(sink);
    status_into(&mut w, s);
    w.flush()
}

/// The same into an existing writer (for tests and for embedding).
pub fn status_into(w: &mut JsonWriter<'_>, s: &Status<'_>) {
    w.raw(b"{");
    w.str("firmware", s.firmware);
    w.str("mode", s.mode);
    let t = &s.chip_temperature;
    w.raw(b"\"chip_temperature\":{");
    w.bool("valid", t.valid);
    w.num_i32_wrapping("current_tenths_c", t.current_tenths);
    w.num_i32_wrapping("peak_tenths_c", t.peak_tenths);
    w.num("sampled_at_uptime_ms", t.sampled_at_ms.into());
    w.num("samples", t.samples.into());
    w.num("changed_at_uptime_ms", t.changed_at_ms.into());
    w.num("step_tenths_c", TEMPERATURE_STEP_TENTHS.into());
    w.key("age_ms");
    if t.samples != 0 {
        w.number(t.age_ms.into());
    } else {
        w.raw(b"null");
    }
    w.ch(b',');
    w.key("errors");
    w.number(t.errors.into());
    w.raw(b"},");
    w.bool("recovery", s.recovery);
    w.num("membership_start_budget", s.membership_start_budget);
    w.num("membership_context_bytes", s.membership_context_bytes);
    shared_runtime(w, s);
    power(w, &s.power);
    let k = &s.sockets;
    w.num("socket_limit", k.limit.into());
    w.num("socket_recovery_reserve", k.recovery_reserve.into());
    w.num("sockets_open", k.open.into());
    w.num("sockets_peak", k.peak.into());
    w.num("socket_failures", k.failures.into());
    w.num("socket_last_errno", k.last_errno.into());
    w.num("socket_last_operation", k.last_operation.into());
    w.num("socket_last_at_ms", k.last_at_ms.into());
    w.num("reset_reason", s.reset_reason.into());
    w.bool("wifi", s.wifi);
    if let Some(link) = s.wifi_link {
        w.key("wifi_link");
        w.raw(link);
        w.ch(b',');
    }
    w.raw(b"\"clock\":{");
    w.str("state", s.clock.state);
    w.bool("valid", s.clock.valid);
    w.num("sntp_restarts", s.clock.sntp_restarts.into());
    w.num("retry_in_ms", s.clock.retry_in_ms.into());
    w.key("server");
    w.string(s.clock.server);
    w.raw(b"},");
    w.raw(b"\"saved_wifi\":[");
    for (i, ssid) in s.saved_wifi.iter().enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.string(ssid);
    }
    w.raw(b"],");
    w.bool("route_storage_ok", s.route_storage_ok);
    w.num("free_memory", s.free_memory.into());
    w.num("largest_free_block", s.largest_free_block.into());
    w.num("minimum_free_memory", s.minimum_free_memory.into());
    heap_budget(w, &s.heap_budget);
    wifi_pins(w, &s.wifi_pins);
    w.raw(b"\"members\":[");
    for (i, m) in s.members.iter().enumerate() {
        if w.failed() {
            break;
        }
        if i > 0 {
            w.ch(b',');
        }
        member(w, m);
    }
    w.raw(b"]}");
}

fn heap_budget(w: &mut JsonWriter<'_>, h: &HeapBudget) {
    w.raw(b"\"heap_budget\":{");
    w.num("floor", h.floor.into());
    w.num("reserve", h.reserve.into());
    w.num("pin_buffers", h.pin_buffers.into());
    w.num("refused_usb_rx", h.refused_usb_rx.into());
    w.num("refused_pending", h.refused_pending.into());
    w.num("refused_derp_tx", h.refused_derp_tx.into());
    w.num("refused_rx_ctrl", h.refused_rx_ctrl.into());
    w.num("refused_derp_rx", h.refused_derp_rx.into());
    w.key("refused_wg_copy");
    w.number(h.refused_wg_copy.into());
    w.raw(b"},");
}

fn wifi_pins(w: &mut JsonWriter<'_>, p: &WifiPins) {
    w.raw(b"\"wifi_pins\":{");
    w.bool("installed", p.installed);
    w.bool("tx_done_cb", p.tx_done_cb);
    w.bool("rx_hooked", p.rx_hooked);
    w.num("tx_pool", p.tx_pool.into());
    w.num("band_total", p.band_total.into());
    w.num("tx_band_max", p.tx_band_max.into());
    w.num("rx_band_max", p.rx_band_max.into());
    w.num("tx_inflight", p.tx_inflight.into());
    w.num("tx_high_water", p.tx_high_water.into());
    w.num("tx_charged", p.tx_charged.into());
    w.num("tx_done", p.tx_done.into());
    w.num("tx_aborted", p.tx_aborted.into());
    w.num("tx_flushed", p.tx_flushed.into());
    w.num("tx_stale", p.tx_stale.into());
    w.num("tx_unmatched", p.tx_unmatched.into());
    w.num("tx_band_admits", p.tx_band.into());
    w.num("tx_elastic_admits", p.tx_elastic.into());
    w.num("tx_refused_pool", p.tx_refused_pool.into());
    w.num("tx_refused_heap", p.tx_refused_heap.into());
    w.num("rx_inflight", p.rx_inflight.into());
    w.num("rx_high_water", p.rx_high_water.into());
    w.num("rx_band_admits", p.rx_band.into());
    w.num("rx_elastic_admits", p.rx_elastic.into());
    w.num("rx_released", p.rx_released.into());
    w.num("rx_unmatched", p.rx_unmatched.into());
    w.key("rx_dropped");
    w.number(p.rx_dropped.into());
    w.raw(b"},");
}

/// `status_shared_runtime` of runtime_status.inc: admission, shared_runtime, negotiation, wg_pool, shared_rng.
fn shared_runtime(w: &mut JsonWriter<'_>, s: &Status<'_>) {
    let b = &s.admission;
    w.raw(b"\"admission\":{");
    w.num("required_bytes", b.required.into());
    w.num("shared_runtime_bytes", b.shared_runtime.into());
    w.num("member_start_bytes", b.member_start.into());
    w.num("member_growth_bytes", b.member_growth.into());
    w.num("member_steady_bytes", b.member_steady.into());
    w.num("negotiation_reserve_bytes", b.negotiation.into());
    w.num("recovery_reserve_bytes", b.recovery.into());
    w.num("largest_block_required", b.largest_block.into());
    w.num("peer_slots_charged", b.peer_slots_charged.into());
    w.key("peer_slot_bytes");
    w.number(b.peer_slot_bytes.into());
    w.raw(b"},");

    let rt = &s.shared_runtime;
    w.raw(b"\"shared_runtime\":{");
    w.key("running");
    w.boolean(rt.running);
    w.ch(b',');
    w.num("members", rt.members.into());
    w.num("starts", rt.starts.into());
    w.num("stops", rt.stops.into());
    w.num("attach_failures", rt.attach_failures.into());
    w.num("detach_failures", rt.detach_failures.into());
    w.raw(b"\"tasks\":{");
    for (t, name) in RT_TASK_NAMES.iter().enumerate() {
        if t > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.ch(b'{');
        w.num("stack_bytes", rt.stack_bytes[t].into());
        w.num_or_null("stack_free", rt.stack_free[t], u32::MAX, true);
        w.num("passes", rt.passes[t].into());
        w.num("max_slice_ms", rt.max_service_ms[t].into());
        w.num("slow_slices", rt.slow_services[t].into());
        w.key("detach_timeouts");
        w.number(rt.detach_timeouts[t].into());
        w.ch(b'}');
    }
    w.raw(b"}},");

    let n = &rt.negotiation;
    w.raw(b"\"negotiation\":{");
    w.key("holder");
    w.string(n.holder.map_or("none", NegPhase::name).as_bytes());
    w.ch(b',');
    w.num("held_ms", n.held_ms.into());
    w.num("waiting", n.waiting.into());
    w.num("grants", n.grants.into());
    w.num("timeouts", n.timeouts.into());
    w.num("lease_expired", n.lease_expired.into());
    w.num("stale_dropped", n.stale_dropped.into());
    w.num("refused_full", n.refused_full.into());
    w.num("max_wait_ms", n.max_wait_ms.into());
    w.key("max_hold_ms");
    w.number(n.max_hold_ms.into());
    w.raw(b"},");

    let p = &s.wg_pool;
    w.raw(b"\"wg_pool\":{");
    w.num("capacity", p.capacity.into());
    w.num("used", p.used.into());
    w.num("peak", p.peak.into());
    w.num("refused_full", p.refused_full.into());
    w.num("refused_nomem", p.refused_nomem.into());
    w.num("evictions_own", p.evictions_own.into());
    w.num("evictions_other", p.evictions_other.into());
    w.num("rejected", p.rejected.into());
    w.num("refused_largest", p.refused_largest.into());
    w.num("refused_heap", p.refused_heap.into());
    w.num_or_null("largest_low", p.largest_low, u32::MAX, true);
    w.num("slot_bytes", p.slot_bytes.into());
    w.key("device_bytes");
    w.number(p.device_bytes.into());
    w.raw(b"},");

    let r = &s.shared_rng;
    w.raw(b"\"shared_rng\":{");
    w.num("users", r.users.into());
    w.num("resident_bytes", r.bytes_resident.into());
    w.num("seedings", r.seedings.into());
    w.key("failures");
    w.number(r.failures.into());
    w.raw(b"},");
}

/// `status_power` of runtime_status.inc.
fn power(w: &mut JsonWriter<'_>, p: &Power<'_>) {
    w.raw(b"\"power\":{");
    w.bool("scaling", p.scaling);
    w.num("cpu_mhz", p.cpu_mhz.into());
    w.num("max_mhz", p.max_mhz.into());
    w.num("min_mhz", p.min_mhz.into());
    w.signed("configure_error", p.configure_error);
    w.num("lock_create_failures", p.lock_create_failures.into());
    w.signed("wifi_ps", p.wifi_ps);
    w.raw(b"\"locks\":{");
    for (i, b) in p.locks.iter().take(PM_MAX_BURSTS).enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.string(cstr(b.name));
        w.ch(b':');
        w.ch(b'{');
        w.num("depth", b.depth.into());
        w.num("acquires", b.acquires.into());
        w.num("releases", b.releases.into());
        w.num("held_us", b.held_us.into());
        w.num("max_depth", b.max_depth.into());
        w.num("underflows", b.underflows.into());
        w.num("forced_releases", b.forced_releases.into());
        w.num("backend_failures", b.backend_failures.into());
        w.key("isr_rejects");
        w.number(b.isr_rejects.into());
        w.ch(b'}');
    }
    w.raw(b"}},");
}

fn cstr(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())]
}

fn member(w: &mut JsonWriter<'_>, v: &Member<'_>) {
    w.ch(b'{');
    w.num("id", v.id.into());
    w.num("start_heap_before", v.start_heap_before);
    w.num("start_heap_after", v.start_heap_after);
    w.str("label", v.label);
    w.bool("enabled", v.enabled);
    w.str("error", v.error);
    w.num("state", v.state.into());
    w.key("routing_ready");
    w.boolean(v.routing_ready);
    if let Some(c) = &v.client {
        w.ch(b',');
        if c.vpn_ip != 0 {
            let (ip, n) = ip_to_str(c.vpn_ip);
            w.str("tailnet_ip", &ip[..n]);
        }
        if !cstr(c.dns).is_empty() {
            w.str("tailnet_dns_name", c.dns);
        }
        w.raw(b"\"map_diagnostics\":{");
        for (d, name) in DIAGNOSTIC_NAMES.iter().enumerate() {
            if d > 0 {
                w.ch(b',');
            }
            w.key(name);
            if d == 20 {
                // `%ld` of (long)(int32_t): signed decimal.
                let mut buf = [0u8; 12];
                let n = format_i32(c.diagnostics[d] as i32, &mut buf);
                w.raw(&buf[..n]);
            } else {
                w.number(c.diagnostics[d].into());
            }
        }
        w.raw(b"},\"stack_free_bytes\":{");
        for (t, name) in STACK_NAMES.iter().enumerate() {
            if t > 0 {
                w.ch(b',');
            }
            w.num_or_null(name, c.stack_free[t], u32::MAX, false);
        }
        w.raw(b"},");
        w.str("login_url", c.login_url);
        w.str("protocol_error", c.protocol_error);
        w.str("h2_debug", c.h2_debug);
        w.num("control_stage", c.control_stage.into());
        w.num("derp_tls_verify_failures", c.derp_tls_verify_failures.into());
        w.num("derp_tls_deferred", c.derp_tls_deferred.into());
        w.raw(b"\"derp_link\":{");
        w.str("state", c.derp_state);
        w.num("frames_rx", c.frames_rx.into());
        w.num("frames_tx", c.frames_tx.into());
        w.num("record_timeouts", c.record_timeouts.into());
        w.num("write_stalls", c.write_stalls.into());
        w.num("alloc_drops", c.alloc_drops.into());
        w.key("connects");
        w.number(c.connects.into());
        w.raw(b"},");
        w.num("control_key_auth", c.control_key_auth.into());
        w.num("jit_hits", c.jit_hits.into());
        w.num("jit_misses", c.jit_misses.into());
        w.num("jit_evictions", c.jit_evictions.into());
        w.num("jit_rejected", c.jit_rejected.into());
        w.num("jit_dropped", c.jit_dropped.into());
        w.num("directory_records", c.directory_records.into());
        w.num("next_peer_offset", c.next_peer_offset.into());
        w.num("peer_page_start", c.peer_page_start.into());
        w.raw(b"\"peers\":[");
        for (j, p) in c.peers.iter().enumerate() {
            if w.failed() {
                break;
            }
            if j > 0 {
                w.ch(b',');
            }
            w.ch(b'{');
            w.str("name", p.name);
            // `qualifiedName`: the first label of the hostname, ".", the membership label, ".tailnet" (snprintf into a 128-byte buffer).
            let short = cstr(p.name);
            let short = &short[..short.iter().position(|&b| b == b'.').unwrap_or(short.len()).min(63)];
            let mut q = [0u8; 127];
            let mut n = 0;
            for part in [short, b".", cstr(v.label), b".tailnet"] {
                for &b in part {
                    if n < q.len() {
                        q[n] = b;
                        n += 1;
                    }
                }
            }
            w.str("qualifiedName", &q[..n]);
            let (ip, n) = ip_to_str(p.address);
            w.key("address");
            w.string(&ip[..n]);
            w.ch(b'}');
        }
        w.ch(b']');
    }
    w.ch(b'}');
}

fn format_i32(v: i32, out: &mut [u8; 12]) -> usize {
    let mut tmp = [0u8; 11];
    let mut i = tmp.len();
    let mut m = i64::from(v).unsigned_abs();
    loop {
        i -= 1;
        tmp[i] = b'0' + (m % 10) as u8;
        m /= 10;
        if m == 0 {
            break;
        }
    }
    let mut n = 0;
    if v < 0 {
        out[0] = b'-';
        n = 1;
    }
    out[n..n + tmp.len() - i].copy_from_slice(&tmp[i..]);
    n + tmp.len() - i
}
