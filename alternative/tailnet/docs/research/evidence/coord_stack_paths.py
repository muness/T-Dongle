#!/usr/bin/env python3
"""Stack paths of the ml_coord task from GCC's own frame sizes (byte-recovery R3, docs/adr/0016).

  idf.py -B build-stack -D IDF_TARGET=esp32s3 -D SDKCONFIG=$PWD/build-stack/sdkconfig \\
         -D CMAKE_C_FLAGS=-fcallgraph-info=su build
  python3 coord_stack_paths.py build-stack

-fcallgraph-info=su writes one .ci (VCG) file per object: every function's frame ("N bytes (static)") and every direct
call edge. Calls through function pointers are NOT edges, and newlib's prebuilt vfprintf has no .ci, so this is a sum of
the application and IDF frames along named paths, to be read next to the one number measured on the board (4,152 B,
all phases). The 'calibration' line is the measured deepest path (DERP-map activation: netcheck on the coord task)
against its static frames; the remainder is what the sum does not see (exception frame, newlib printf, lwIP/FreeRTOS
internals behind function pointers) and is added to every path below.
"""
import collections, glob, re, sys

build = sys.argv[1] if len(sys.argv) > 1 else "build-stack"
CJSON_LIMIT = 32            # TDONGLE_CJSON_NESTING_LIMIT (top-level CMakeLists.txt): what the build allows
DEPTH_KEY, DEPTH_REGISTER = 4, 16   # ML_JSON_DEPTH_KEY / ML_JSON_DEPTH_REGISTER (ml_coord.c): what the coord task allows
MEASURED = 4152             # uxTaskGetStackHighWaterMark of ml_coord, firmware 0.2.22, board, all phases
nre = re.compile(r'node: \{ title: "([^"]+)" label: "([^"]*)"')
ere = re.compile(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"')
frame, edges = {}, collections.defaultdict(set)
for f in glob.glob(build + "/**/*.ci", recursive=True):
    for line in open(f, errors="replace"):
        m = nre.match(line)
        if m:
            mm = re.search(r"(\d+) bytes \(", m.group(2))
            if mm: frame[m.group(1)] = max(frame.get(m.group(1), 0), int(mm.group(1)))
            continue
        m = ere.match(line)
        if m: edges[m.group(1)].add(m.group(2))

def title(name):
    c = [t for t in frame if t == name or t.endswith(":" + name)]
    if not c: sys.exit("no frame for " + name + " (was the build made with -fcallgraph-info=su?)")
    return max(c, key=lambda t: frame[t])

def f(name): return frame[title(name)]

def deepest(name):
    """Largest sum of frames along direct calls below function `name` (cycles cut)."""
    def walk(t, seen):
        best, bp = 0, []
        for e in edges.get(t, ()):
            if e in seen or e == t: continue
            d, p = walk(e, seen | {t})
            if d > best: best, bp = d, p
        return frame.get(t, 0) + best, [t.split(":")[-1]] + bp
    return walk(title(name), frozenset())

def show(label, parts, extra=0):
    total = sum(parts.values()) + extra
    print("%-62s %6d" % (label, total))
    return total

cj_malloc = deepest("cjson_psram_malloc")[0]
def cj_chain(levels):
    """cJSON_Parse -> ParseWithLengthOpts -> parse_value once per level (parse_object/array are inlined) -> parse_string."""
    return f("cJSON_ParseWithOpts") + f("cJSON_ParseWithLengthOpts") + (levels + 1) * f("parse_value") + f("parse_string") + f("parse_hex4")
print("frames (B): ml_coord_task %d, do_register_locked %d, key_tls_open %d, cJSON parse_value %d (x%d levels)" %
      (f("ml_coord_task"), f("do_register_locked"), f("key_tls_open"), f("parse_value"), CJSON_LIMIT + 1))
netcheck = [f(n) for n in ("ml_coord_task", "do_map_exchange", "gateway_read_map", "activate_derp_regions", "ml_netcheck_pick_best_derp")]
net_static = sum(netcheck) + 80 + 64 + 96            # + lwip_recvfrom / lwip_recv_tcp / esp_log frames (one socket call, one log line)
unseen = max(MEASURED - net_static, 0)
print("calibration: measured deepest path %d B = static frames %d (coord task, map exchange, read map, activate regions, netcheck %d, "
      "one lwIP call, one log line) + %d not visible in .ci (exception frame, newlib printf, internals behind function pointers)" %
      (MEASURED, net_static, f("ml_netcheck_pick_best_derp"), unseen))
print()
print("path (static frames + unseen %d B)" % unseen)
def line(label, levels, **parts):
    return show(label, dict(parts, **{"cJSON chain (%d levels)" % levels: cj_chain(levels), "malloc under cJSON": cj_malloc}), unseen)
register = line("register response: JSON bounded to %d levels (authenticated server)" % DEPTH_REGISTER, DEPTH_REGISTER,
                task=f("ml_coord_task"), do_register_locked=f("do_register_locked"))
keyfetch = line("/key over plain HTTP: JSON bounded to %d levels (unauthenticated)" % DEPTH_KEY, DEPTH_KEY,
                task_with_key_fetch_inlined=f("ml_coord_task"))
register_unbounded = line("  (for comparison) register response at the build's limit of %d levels" % CJSON_LIMIT, CJSON_LIMIT,
                          task=f("ml_coord_task"), do_register_locked=f("do_register_locked"))
tls_depth, tls_path = deepest("esp_tls_conn_new_sync")
tls = show("TLS control key fetch / connect (esp_tls handshake, direct calls only)",
           {"task": f("ml_coord_task"), "key_tls_open": f("key_tls_open"), "esp_tls handshake": tls_depth}, unseen)
print("   esp_tls_conn_new_sync deepest direct chain: " + " > ".join(tls_path[:9]) + " ...")
print()
worst = max(register, keyfetch, tls)

print("worst analysed path                                  %6d" % worst)
print("rule: stack >= 2 x measured (%d) = %d ; stack >= worst analysed + 2048 = %d" % (MEASURED, 2 * MEASURED, worst + 2048))
