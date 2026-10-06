#!/usr/bin/env python3
"""Generate the golden files of tdongle-tailnet-admission from the REAL C sources.

Nothing here transcribes C behaviour. Every expected output is produced by compiling and running C that is either

  * a real header or source of the firmware (ml_admission.h, ml_heap_budget.h, ml_rx_stats.h, ml_wg_rx_budget.h, ml_negotiation.c ...), or
  * text cut programmatically out of the real source files (function bodies and statement blocks, by marker and brace matching) from
    main/runtime_status.inc, main/gateway_main.c and main/memory_diagnostics.inc,

plus stubs for what those use (plain variables and one-line functions, driven by the scenarios). The only edit made to extracted text is
the substitution of the C owner names by this crate's (the Rust ledger has `noise`/`wireguard` where the C has `control`/`wg`).

Outputs (tests/golden/):
  scenarios.txt        one line per scenario: `<kind> <name> key=value ...` (the Rust tests read the inputs from here)
  status.golden        the fragments: container of `@@@@ SCENARIO <kind>/<name> LEN <n> @@@@\\n<n bytes>\\n@@@@ END @@@@\\n`
  neg_ops_<i>.txt      the operations of a random trace of the negotiation token (seeded)
  neg_trace_<i>.golden the real ml_negotiation.c's result and status after every operation

Run: `sh tools/regen.sh`. Needs `cc` and python3. The output is checked in; review the diff when a C source or a scenario changes.
"""
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "tests" / "golden"
TAILNET = HERE.parents[3] / "alternative" / "tailnet"
MAIN = TAILNET / "main"
INC = TAILNET / "components" / "microlink" / "include"
SRC = TAILNET / "components" / "microlink" / "src"


# ---- extraction helpers (brace/paren matching that skips strings, chars and comments) ----
def skip_token(s, i):
    if s.startswith("//", i):
        j = s.find("\n", i)
        return len(s) if j < 0 else j
    if s.startswith("/*", i):
        return s.index("*/", i) + 2
    if s[i] in "\"'":
        q, j = s[i], i + 1
        while s[j] != q:
            j += 2 if s[j] == "\\" else 1
        return j + 1
    return None


def match_close(s, open_idx):
    opener = s[open_idx]
    closer = {"(": ")", "{": "}", "[": "]"}[opener]
    depth, i = 0, open_idx
    while i < len(s):
        skipped = skip_token(s, i)
        if skipped is not None:
            i = skipped
            continue
        if s[i] == opener:
            depth += 1
        elif s[i] == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced")


def extract_function(src, signature):
    start = src.index(signature)
    brace = src.index("{", start)
    return src[start : match_close(src, brace) + 1]


def between(src, start_marker, end_marker, include_end=False):
    a = src.index(start_marker)
    b = src.index(end_marker, a + len(start_marker))
    return src[a : b + (len(end_marker) if include_end else 0)]


def line_with(src, prefix):
    a = src.index(prefix)
    return src[a : src.index("\n", a)]


def regex(src, pattern):
    return re.search(pattern, src, re.S).group(0)


runtime_status = (MAIN / "runtime_status.inc").read_text()
gateway_main = (MAIN / "gateway_main.c").read_text()
memdiag = (MAIN / "memory_diagnostics.inc").read_text()

RNUM_DEFINE = line_with(runtime_status, "#define RNUM")
NUM_DEFINE = regex(gateway_main, r"#define NUM\(name, value\).*?while \(0\)")
ADMISSION_BLOCK = between(runtime_status, "ml_adm_budget_t b = admission_budget();", "ml_rt_status_t rt;")
NEGOTIATION_BLOCK = between(runtime_status, 'jw_raw(w, "\\"negotiation\\":{");', "ml_wg_pool_status_t pool;")
HEAP_BUDGET_BLOCK = between(gateway_main, 'jw_raw(w, "\\"heap_budget\\":{");', 'jw_raw(w, "},");', include_end=True)
REPORT_FUNCS = "\n".join(
    extract_function(memdiag, f"static void {n}(") for n in ("report_begin", "report_end", "report_field", "report_admission")
)
VERDICT_NAMES = line_with(memdiag, "static const char *const verdict_names")
INBOUND = extract_function(memdiag, "static void report_inbound(jw_writer *w)")
INBOUND_HEAD = between(INBOUND, 'report_begin(w, "inbound");', "#if LWIP_STATS")
INBOUND_ML = between(INBOUND, 'jw_raw(w, ",\\"ml\\":{");', 'jw_raw(w, "},\\"wg\\":{");')
HEAP = extract_function(memdiag, "static void report_heap(jw_writer *w)")
OWNERS_BLOCK = between(HEAP, 'jw_raw(w, ",\\"owners\\":{");', "static const char *const drop_names")
WG_QUEUE_DEPTH = regex((INC / "microlink_internal.h").read_text(), r"#define ML_WG_RX_QUEUE_DEPTH\s+12")
RECVMBOX = "#define CONFIG_LWIP_UDP_RECVMBOX_SIZE 6"
RUST_OWNERS = ["other", "tls", "noise", "map", "peer", "wireguard", "packet"]

random.seed(0x7a11_0001)


# ---- scenarios ----
def rnd(lo, hi):
    return random.randint(lo, hi)


SIZE_KEYS = ["context", "coord_stack", "task_tcb", "queues", "wg_device", "wg_slot", "shared_stacks", "shared_tasks", "route_queue_min"]
C_REF = dict(context=10256, coord_stack=8704, task_tcb=340, queues=1692, wg_device=236, wg_slot=1096, shared_stacks=23040, shared_tasks=3, route_queue_min=2800)

scenarios = []  # (kind, name, dict)
for running in (0, 1):
    scenarios.append(("admission", f"c_reference_running{running}", dict(C_REF, running=running, slot_bytes=1096)))
for i in range(40):
    sz = dict(
        context=rnd(0, 20000), coord_stack=rnd(0, 12000), task_tcb=rnd(0, 600), queues=rnd(0, 4000), wg_device=rnd(0, 500),
        wg_slot=rnd(0, 2000), shared_stacks=rnd(0, 40000), shared_tasks=rnd(0, 5), route_queue_min=rnd(0, 6000),
    )
    scenarios.append(("admission", f"random{i}", dict(sz, running=rnd(0, 1), slot_bytes=rnd(0, 1500))))

NEG_KEYS = ["holder", "phase", "held_ms", "waiting", "grants", "timeouts", "lease_expired", "stale_dropped", "refused_full", "max_wait_ms", "max_hold_ms"]
scenarios.append(("negotiation", "idle", dict(holder=0, phase=0, held_ms=0, waiting=0, grants=0, timeouts=0, lease_expired=0, stale_dropped=0, refused_full=0, max_wait_ms=0, max_hold_ms=0)))
for ph, name in ((1, "start"), (2, "control"), (3, "derp")):
    scenarios.append(("negotiation", f"held_{name}", dict(holder=7, phase=ph, held_ms=1234, waiting=2, grants=9, timeouts=1, lease_expired=2, stale_dropped=3, refused_full=4, max_wait_ms=555, max_hold_ms=66666)))
scenarios.append(("negotiation", "holder_with_phase_none", dict(holder=3, phase=0, held_ms=1, waiting=0, grants=1, timeouts=0, lease_expired=0, stale_dropped=0, refused_full=0, max_wait_ms=0, max_hold_ms=0)))
scenarios.append(("negotiation", "max", {k: 4294967295 for k in NEG_KEYS}))
for i in range(20):
    scenarios.append(("negotiation", f"random{i}", dict(holder=rnd(0, 3) and rnd(1, 2**31), phase=rnd(0, 3), **{k: rnd(0, 2**32 - 1) for k in NEG_KEYS[2:]})))

HB_KEYS = ["refused_usb_rx", "refused_pending", "refused_derp_tx", "refused_rx_ctrl", "refused_derp_rx", "refused_wg_copy"]
scenarios.append(("heap_budget", "zero", {k: 0 for k in HB_KEYS}))
scenarios.append(("heap_budget", "max", {k: 4294967295 for k in HB_KEYS}))
for i in range(10):
    scenarios.append(("heap_budget", f"random{i}", {k: rnd(0, 2**32 - 1) for k in HB_KEYS}))

VERDICTS = 7
for override in (0, 1):
    scenarios.append(("admission_report", f"empty_override{override}", dict(override=override, guard_floor=16384, slot_evictions=0, records="")))
    for i in range(6):
        recs = []
        for _ in range(rnd(1, 8)):
            recs.append(":".join(str(v) for v in (rnd(0, 2**32 - 1), rnd(0, 20), rnd(0, 200000), rnd(0, 60000), rnd(0, 120000), rnd(0, 20), rnd(8, 32), rnd(0, 3), rnd(0, VERDICTS - 1))))
        scenarios.append(("admission_report", f"random{i}_override{override}", dict(override=override, guard_floor=rnd(0, 40000), slot_evictions=rnd(0, 99), records=";".join(recs))))

RXS = "udp_rx udp_rx_empty udp_unclassified udp_alloc_fail udp_recv_err udp_wg udp_disco udp_stun q_wg_full q_disco_full q_stun_full derp_rx_wg derp_q_wg_full q_wg_bytes q_wg_heap drain_calls drain_capped drain_deep wg_in wg_sender_unknown wg_no_netif wg_pbuf_fail wg_to_wireguardif".split()
scenarios.append(("inbound", "zero", dict(queued=0, peak=0, replay=0, burst=0, counters=",".join("0" for _ in RXS))))
for i in range(10):
    scenarios.append(("inbound", f"random{i}", dict(queued=rnd(0, 12288), peak=rnd(0, 12288), replay=rnd(0, 2048), burst=rnd(0, 16), counters=",".join(str(rnd(0, 2**32 - 1)) for _ in RXS))))

OWN_FIELDS = 6
for i in range(10):
    scenarios.append(("owners", f"random{i}", dict(values=",".join(str(rnd(0, 2**32 - 1)) for _ in range(7 * OWN_FIELDS)))))
scenarios.append(("owners", "zero", dict(values=",".join("0" for _ in range(7 * OWN_FIELDS)))))


def line_of(kind, name, d):
    return f"{kind} {name} " + " ".join(f"{k}={v}" for k, v in d.items())


# ---- the C harness ----
def c_harness(override):
    parts = []
    add = parts.append
    add("""#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
""")
    add(f"{RECVMBOX}\n{WG_QUEUE_DEPTH}\n")
    if override:
        add("#define CONFIG_TDONGLE_MEMORY_DIAGNOSTICS 1\n#define CONFIG_TDONGLE_MEMORY_ADMISSION_OVERRIDE 1\n")
    add('#include "ml_admission.h"\n#include "ml_heap_budget.h"\n#include "ml_negotiation.h"\n#include "ml_wg_rx_budget.h"\n#include "ml_wg_rx_batch_consts.h"\n#include "ml_net_io_drain.h"\n')
    add('#include "json_writer.inc"\n')
    add("""typedef struct { char *data; size_t len, cap; } outbuf;
static int out_sink(void *ctx, const char *p, size_t n) {
    outbuf *o = ctx;
    if (o->len + n + 1 > o->cap) { o->cap = (o->len + n + 1) * 2; o->data = realloc(o->data, o->cap); }
    memcpy(o->data + o->len, p, n); o->len += n; o->data[o->len] = 0; return 0;
}
atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];
ml_wgrx_budget_t ml_wgrx_budget;
ml_rx_stats_t ml_rx_stats;
typedef struct { ml_neg_status_t negotiation; } rt_t;
static rt_t rt;
static ml_adm_budget_t g_budget;
static size_t g_slot_bytes;
static ml_adm_budget_t admission_budget(void) { return g_budget; }
static size_t ml_wg_slot_bytes(void) { return g_slot_bytes; }
static unsigned g_replay;
unsigned ml_wg_replay_window(void) { return g_replay; }
unsigned ml_wg_rx_batch_size(void) { return ML_WG_RX_BATCH; }
typedef struct { unsigned usb_dropped_heap; } usb_t;
static struct { atomic_uint dropped_heap; } usb_rx_budget;
""")
    add(RNUM_DEFINE + "\n" + NUM_DEFINE + "\n")
    add(VERDICT_NAMES + "\n")
    # report_admission stubs
    add("""typedef struct { uint32_t uptime_ms, member_id, free_bytes, largest_bytes, budget_bytes, sockets_open, sockets_limit, active, verdict; } tdongle_admission_record;
static unsigned g_guard, g_evict, g_nrec; static tdongle_admission_record g_rec[16];
static unsigned tdongle_heap_guard_floor(void) { return g_guard; }
static unsigned tdongle_memory_slot_evictions(void) { return g_evict; }
static unsigned tdongle_memory_admission_count(void) { return g_nrec; }
static tdongle_admission_record tdongle_memory_admission_get(unsigned i) { return g_rec[i]; }
""")
    add(REPORT_FUNCS + "\n")
    # owners
    names = ", ".join(f'"{n}"' for n in RUST_OWNERS)
    add(f"""#define TDONGLE_OWNER_COUNT 7
static const char *const owner_names[TDONGLE_OWNER_COUNT] = {{{names}}};
typedef unsigned tdongle_owner;
typedef struct {{ uint32_t live, peak, allocs, frees, failed, denied; }} tdongle_owner_stats;
static tdongle_owner_stats g_owner[7];
static tdongle_owner_stats tdongle_heap_owner(unsigned i) {{ return g_owner[i]; }}
""")
    # emit functions
    add("static void emit_admission(jw_writer *w) {\n" + ADMISSION_BLOCK + "\n}\n")
    add("static void emit_negotiation(jw_writer *w) {\n" + NEGOTIATION_BLOCK + "\n}\n")
    add("static void emit_heap_budget(jw_writer *w) {\n" + HEAP_BUDGET_BLOCK + "\n}\n")
    add("static void emit_inbound(jw_writer *w) {\n" + INBOUND_HEAD + "\n" + INBOUND_ML + "\n    jw_char(w, '}');\n}\n")
    add("static void emit_owners(jw_writer *w) {\n" + OWNERS_BLOCK + "\n}\n")
    # main: read scenarios from argv[1] and write the golden container to stdout
    add(r"""
static char *tok(char **s) { while (**s == ' ') (*s)++; if (!**s) return NULL; char *t = *s; while (**s && **s != ' ') (*s)++; if (**s) *(*s)++ = 0; return t; }
static const char *get(char **kv, int n, const char *key) {
    size_t l = strlen(key);
    for (int i = 0; i < n; i++) if (!strncmp(kv[i], key, l) && kv[i][l] == '=') return kv[i] + l + 1;
    fprintf(stderr, "missing %s\n", key); exit(2);
}
static unsigned long long u(char **kv, int n, const char *key) { return strtoull(get(kv, n, key), NULL, 10); }
static void emit(const char *label, outbuf *o) {
    printf("@@@@ SCENARIO %s LEN %zu @@@@\n", label, o->len);
    fwrite(o->data, 1, o->len, stdout);
    printf("\n@@@@ END @@@@\n");
    o->len = 0;
}
int main(int argc, char **argv) {
    (void)argc;
    FILE *f = fopen(argv[1], "r"); char line[8192];
    outbuf o = {0};
    jw_writer w = {.context = &o, .sink = out_sink};
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = 0;
        char *p = line; char *kind = tok(&p), *name = tok(&p); if (!kind || !name) continue;
        char *kv[64]; int n = 0; char *t; while ((t = tok(&p))) kv[n++] = t;
        char label[160]; snprintf(label, sizeof label, "%s/%s", kind, name);
        w.used = 0; w.failed = false;
        if (!strcmp(kind, "admission")) {
            ml_adm_sizes_t s = {.context = u(kv, n, "context"), .coord_stack = u(kv, n, "coord_stack"), .task_tcb = u(kv, n, "task_tcb"), .queues = u(kv, n, "queues"),
                .wg_device = u(kv, n, "wg_device"), .wg_slot = u(kv, n, "wg_slot"), .shared_stacks = u(kv, n, "shared_stacks"), .shared_tasks = (unsigned)u(kv, n, "shared_tasks"),
                .route_queue_min = u(kv, n, "route_queue_min")};
            ml_adm_budget(&s, u(kv, n, "running") != 0, &g_budget); g_slot_bytes = u(kv, n, "slot_bytes");
            emit_admission(&w); jw_flush(&w); emit(label, &o);
        } else if (!strcmp(kind, "negotiation")) {
            ml_neg_status_t *s = &rt.negotiation;
            s->holder = (uintptr_t)u(kv, n, "holder"); s->phase = (ml_neg_phase_t)u(kv, n, "phase"); s->held_ms = u(kv, n, "held_ms"); s->waiting = u(kv, n, "waiting");
            s->grants = u(kv, n, "grants"); s->timeouts = u(kv, n, "timeouts"); s->lease_expired = u(kv, n, "lease_expired"); s->stale_dropped = u(kv, n, "stale_dropped");
            s->refused_full = u(kv, n, "refused_full"); s->max_wait_ms = u(kv, n, "max_wait_ms"); s->max_hold_ms = u(kv, n, "max_hold_ms");
            emit_negotiation(&w); jw_flush(&w); emit(label, &o);
        } else if (!strcmp(kind, "heap_budget")) {
            atomic_store(&usb_rx_budget.dropped_heap, u(kv, n, "refused_usb_rx"));
            atomic_store(&ml_hb_refused[ML_HB_JIT], u(kv, n, "refused_pending")); atomic_store(&ml_hb_refused[ML_HB_DERP_TX], u(kv, n, "refused_derp_tx"));
            atomic_store(&ml_hb_refused[ML_HB_RX_CTRL], u(kv, n, "refused_rx_ctrl")); atomic_store(&ml_hb_refused[ML_HB_DERP_RX], u(kv, n, "refused_derp_rx"));
            atomic_store(&ml_hb_refused[ML_HB_WG_COPY], u(kv, n, "refused_wg_copy"));
            emit_heap_budget(&w); jw_flush(&w); emit(label, &o);
        } else if (!strcmp(kind, "admission_report")) {
            g_guard = u(kv, n, "guard_floor"); g_evict = u(kv, n, "slot_evictions"); g_nrec = 0;
            char *r = (char *)get(kv, n, "records"); if (strlen(r)) {
                char *rec = strtok(r, ";");
                while (rec) { unsigned long long v[9]; sscanf(rec, "%llu:%llu:%llu:%llu:%llu:%llu:%llu:%llu:%llu", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8]);
                    g_rec[g_nrec++] = (tdongle_admission_record){v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]}; rec = strtok(NULL, ";"); } }
            report_admission(&w); jw_flush(&w); emit(label, &o);
        } else if (!strcmp(kind, "inbound")) {
            atomic_store(&ml_wgrx_budget.bytes, u(kv, n, "queued")); atomic_store(&ml_wgrx_budget.peak, u(kv, n, "peak")); g_replay = u(kv, n, "replay");
            ml_rx_stats_reset(); char *c = (char *)get(kv, n, "counters"); char *e = strtok(c, ",");
            for (unsigned i = 0; e && i < ML_RXS_COUNT; i++) { atomic_store(&ml_rx_stats.c[i], strtoull(e, NULL, 10)); e = strtok(NULL, ","); }
            atomic_store(&ml_rx_stats.drain_burst_max, u(kv, n, "burst"));
            emit_inbound(&w); jw_flush(&w); emit(label, &o);
        } else if (!strcmp(kind, "owners")) {
            char *c = (char *)get(kv, n, "values"); char *e = strtok(c, ",");
            for (unsigned i = 0; i < 7; i++) { uint32_t *x = (uint32_t *)&g_owner[i]; for (unsigned j = 0; j < 6; j++) { x[j] = (uint32_t)strtoull(e, NULL, 10); e = strtok(NULL, ","); } }
            emit_owners(&w); jw_flush(&w); emit(label, &o);
        }
    }
    return 0;
}
""")
    return "\n".join(parts)


def build_and_run(override, scen_lines, tmp):
    consts = tmp / "ml_wg_rx_batch_consts.h"
    consts.write_text("#define ML_WG_RX_BATCH %s\n" % regex((INC / "ml_wg_rx_batch.h").read_text(), r"#define ML_WG_RX_BATCH\s+(\d+)").split()[-1])
    src = tmp / f"golden{override}.c"
    src.write_text(c_harness(override))
    exe = tmp / f"golden{override}"
    subprocess.run(["cc", "-std=c11", "-O0", "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-const-variable", "-I", str(tmp), "-I", str(INC), "-I", str(MAIN),
                    str(src), str(SRC / "ml_negotiation.c"), "-o", str(exe)], check=True)
    sf = tmp / f"scen{override}.txt"
    sf.write_text("\n".join(scen_lines) + "\n")
    return subprocess.run([str(exe), str(sf)], check=True, stdout=subprocess.PIPE).stdout


# ---- negotiation traces ----
def neg_trace(i, cfg, steps):
    """Operations of one random trace (seeded). `R now key prio phase` request, `L now key` release, `S now` status."""
    rs = random.Random(0xA110 + i)
    now = 1000
    ops = []
    for _ in range(steps):
        now += rs.choice([0, 1, 5, 10, 100, 500, 2500, 20000, 70000]) if rs.random() < 0.5 else rs.randint(0, 30)
        key = rs.randint(1, 9)
        r = rs.random()
        if r < 0.6:
            ops.append(f"R {now} {key} {rs.randint(0, 2)} {rs.randint(1, 3)}")
        elif r < 0.85:
            ops.append(f"L {now} {key}")
        else:
            ops.append(f"S {now}")
    return ops


NEG_TRACE_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_negotiation.h"
static uint64_t g_now; static uint64_t clk(void) { return g_now; }
static unsigned obs; static unsigned busy_calls; static ml_neg_t *g_n;
static void observer(void *ctx) { (void)ctx; obs++; busy_calls += g_n->holder != 0; }
int main(int argc, char **argv) {
    unsigned lease = atoi(argv[2]), stale = atoi(argv[3]), aging = atoi(argv[4]);
    FILE *f = fopen(argv[1], "r"); char op; ml_neg_t n; g_n = &n;
    ml_neg_init(&n, clk, lease, stale, aging); ml_neg_set_observer(&n, observer, NULL);
    unsigned long long now, key; int prio, phase; unsigned idx = 0;
    while (fscanf(f, " %c %llu", &op, &now) == 2) {
        g_now = now; const char *res = "-";
        if (op == 'R') { fscanf(f, "%llu %d %d", &key, &prio, &phase); ml_neg_result_t r = ml_neg_request(&n, key, prio, phase); res = r == ML_NEG_GRANTED ? "G" : r == ML_NEG_QUEUED ? "Q" : "F"; }
        else if (op == 'L') { fscanf(f, "%llu", &key); res = ml_neg_release(&n, key) ? "T" : "N"; }
        idx++;
        if (op != 'S' && idx % 8 != 0) { printf("%c %s obs=%u\n", op, res, obs); continue; }
        ml_neg_status_t s; ml_neg_status(&n, &s);
        printf("%c %s holder=%llu phase=%s held=%u waiting=%u grants=%u timeouts=%u lease=%u stale=%u full=%u maxwait=%u maxhold=%u obs=%u busy=%u busynow=%d\n", op, res,
               (unsigned long long)s.holder, ml_neg_phase_name(s.phase), s.held_ms, s.waiting, s.grants, s.timeouts, s.lease_expired, s.stale_dropped, s.refused_full,
               s.max_wait_ms, s.max_hold_ms, obs, busy_calls, ml_neg_busy(&n));
    }
    return 0;
}
"""


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        lines = [line_of(*s) for s in scenarios]
        (OUT / "scenarios.txt").write_text("\n".join(lines) + "\n")
        no_override = [l for l, s in zip(lines, scenarios) if s[0] != "admission_report" or s[2]["override"] == 0]
        with_override = [l for l, s in zip(lines, scenarios) if s[0] == "admission_report" and s[2]["override"] == 1]
        gold = build_and_run(0, no_override, tmp) + build_and_run(1, with_override, tmp)
        (OUT / "status.golden").write_bytes(gold)
        # negotiation traces
        c = tmp / "neg.c"
        c.write_text(NEG_TRACE_C)
        exe = tmp / "neg"
        subprocess.run(["cc", "-std=gnu11", "-O0", "-I", str(INC), str(c), str(SRC / "ml_negotiation.c"), "-o", str(exe)], check=True)
        for i, cfg in enumerate([(0, 0, 0), (5000, 500, 2000), (60000, 2000, 20000)]):
            ops = neg_trace(i, cfg, 1500)
            (OUT / f"neg_ops_{i}.txt").write_text(f"# lease stale aging = {cfg[0]} {cfg[1]} {cfg[2]}\n" + "\n".join(ops) + "\n")
            of = tmp / f"ops{i}.txt"
            of.write_text("\n".join(ops) + "\n")
            res = subprocess.run([str(exe), str(of), *map(str, cfg)], check=True, stdout=subprocess.PIPE).stdout
            (OUT / f"neg_trace_{i}.golden").write_bytes(res)
    print("wrote", OUT)


if __name__ == "__main__":
    sys.exit(main())
