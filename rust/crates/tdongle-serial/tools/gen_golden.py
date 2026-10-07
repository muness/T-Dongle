#!/usr/bin/env python3
"""Generate the golden files of tdongle-serial from the REAL C sources.

Nothing here transcribes C behaviour: every expected output is produced by compiling and running C code that is either

  * a real header of the firmware (wifi_link.h, clock_sync.h, wifi_meta.h, traffic.h, tdongle_temperature.h, tdongle_memory.h,
    tdongle_pm.h, tdongle_l2.h, tinyusb_net.h) or
  * text cut programmatically out of the real source files (function bodies by brace matching, statements by parenthesis matching),
    with `mgmt_write(` replaced by a capture function,

plus stubs for everything those use (the stubs are plain variables and one-line functions, driven by the scenarios).

Outputs (all under tests/golden/):
  scenarios.json       the scenario tables the Rust tests read (generated here, seeded: reproducible)
  status.golden        serial_status() over every `status` scenario
  wifi_link.golden     wifi_link_line / wifi_link_json (and the boundary capacities)
  clock.golden         gw_clock_step/poll/state traces
  texts.golden         help, capabilities, unknown command, greeting (bridge/tailnet x release/diagnostics image)
  replies.golden       the formatted replies: `OK saved to slot`, `OK switching to`, list, display, scan lines
  pm.golden            pm_report()
  memory_log.golden    the real components/tdongle_runtime/memory.c over note sequences
  strtol.golden        the C library's strtol/strtoul on ~1500 inputs (the number parsing of use/del/setup)
  bridge_status.golden bridge_status_lines() over the bridge scenarios
  bridge_emit.golden   bridge_line_emit/flush over synthetic (section,name,value) sequences
  bridge_schema.golden the (section, name) pairs of every E("section","name",...) line, in order
  fixed_replies.golden every literal mgmt_write("...") of control.c, serial_setup.inc, console.c (decoded)
  constants.golden     constants of the C headers

Container format of *.golden (except the plain text schema and constants files): for every entry
    @@@@ SCENARIO <name> LEN <n> @@@@\\n<n bytes>\\n@@@@ END @@@@\\n
Run through tools/regen.sh. Needs a C compiler (`cc`) and python3 only.
"""
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
REPO = HERE.parents[3]
TAILNET = REPO / "alternative/tailnet/main"
MAIN = REPO / "main"
RUNTIME_INC = REPO / "components/tdongle_runtime/include"
TINYUSB_INC = REPO / "components/esp_tinyusb/include"
GOLDEN = CRATE / "tests/golden"

U32 = 0xFFFFFFFF
I32_MIN = -(2**31)
I32_MAX = 2**31 - 1


# ----------------------------------------------------------------------------------------------------------------------
# Extracting text from the C sources
# ----------------------------------------------------------------------------------------------------------------------
def skip_token(s, i):
    """If a string, char literal or comment starts at s[i], return the index just past it; else None."""
    c = s[i]
    if c in "\"'":
        j = i + 1
        while s[j] != c:
            j += 2 if s[j] == "\\" else 1
        return j + 1
    if s.startswith("/*", i):
        return s.index("*/", i + 2) + 2
    if s.startswith("//", i):
        j = s.find("\n", i)
        return len(s) if j < 0 else j + 1
    return None


def match_close(s, open_idx):
    """Index of the bracket closing the one at s[open_idx] ((), {} or []), skipping literals and comments."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    opener = s[open_idx]
    closer = pairs[opener]
    depth = 0
    i = open_idx
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
    """The text of the function whose definition starts with `signature` (e.g. 'static void serial_status(void)')."""
    start = src.index(signature)
    brace = src.index("{", start)
    return src[start : match_close(src, brace) + 1]


def extract_call(src, prefix):
    """The text of the call that starts with `prefix` (which ends just before the opening parenthesis or includes it)."""
    start = src.index(prefix)
    paren = src.index("(", start)
    return src[start : match_close(src, paren) + 1]


def extract_block_after(src, marker):
    """The `{...}` block that begins at the first '{' at or after `marker`."""
    start = src.index(marker)
    brace = src.index("{", start)
    return src[brace : match_close(src, brace) + 1]


def c_decode(literal):
    """Decode the body of a C string literal (simple escapes only, which is all the firmware uses)."""
    out = bytearray()
    i = 0
    while i < len(literal):
        c = literal[i]
        if c == "\\":
            i += 1
            e = literal[i]
            m = {"r": 13, "n": 10, "t": 9, '"': 34, "\\": 92, "'": 39, "0": 0}
            if e not in m:
                raise ValueError("unsupported escape \\" + e)
            out.append(m[e])
        else:
            out += c.encode()
        i += 1
    return bytes(out)


def clit(v):
    """A C integer literal for an int that may be any 64 bit value."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if v == I32_MIN:
        return "(-2147483647-1)"
    if v == -(2**63):
        return "(-9223372036854775807LL-1)"
    if v < 0:
        return "(%dLL)" % v if v < I32_MIN else "(%d)" % v
    if v > I32_MAX:
        return "%dULL" % v
    return "%d" % v


def cstr(data):
    """A C string literal for bytes (hex escapes, split so a following digit cannot extend one)."""
    return '"' + "".join('\\x%02x""' % b for b in data) + '"' if data else '""'


def cinit(d, keys):
    return ",".join(".%s=%s" % (k, clit(d[k])) for k in keys)


# ----------------------------------------------------------------------------------------------------------------------
# C harness plumbing
# ----------------------------------------------------------------------------------------------------------------------
COMMON = r"""
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
static char out_buf[1 << 17];
static size_t out_len;
static void capture_write(const char *s) {
    size_t n = strlen(s);
    if (out_len + n >= sizeof(out_buf)) { fputs("capture overflow\n", stderr); exit(2); }
    memcpy(out_buf + out_len, s, n);
    out_len += n;
    out_buf[out_len] = 0;
}
static void entry(const char *name) {
    printf("@@@@ SCENARIO %s LEN %zu @@@@\n", name, out_len);
    fwrite(out_buf, 1, out_len, stdout);
    printf("\n@@@@ END @@@@\n");
    out_len = 0;
    out_buf[0] = 0;
}
"""

STUB_ESP_ERR = "#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n"


class Workspace:
    def __init__(self, root):
        self.root = Path(root)
        self.stub = self.root / "stub"
        self.stub.mkdir()
        (self.stub / "esp_err.h").write_text(STUB_ESP_ERR)
        (self.stub / "sdkconfig.h").write_text("/* host: every CONFIG_ option is off */\n")
        # What components/tdongle_runtime/memory.c includes, as one-line stubs driven by the harness.
        (self.stub / "esp_heap_caps.h").write_text(
            "#pragma once\n#include <stddef.h>\n#include <stdint.h>\n#define MALLOC_CAP_INTERNAL 1\n"
            "extern size_t g_free, g_min, g_largest;\n"
            "static inline size_t heap_caps_get_free_size(uint32_t c) { (void)c; return g_free; }\n"
            "static inline size_t heap_caps_get_minimum_free_size(uint32_t c) { (void)c; return g_min; }\n"
            "static inline size_t heap_caps_get_largest_free_block(uint32_t c) { (void)c; return g_largest; }\n")
        (self.stub / "esp_timer.h").write_text("#pragma once\n#include <stdint.h>\nextern int64_t g_timer_us;\nstatic inline int64_t esp_timer_get_time(void) { return g_timer_us; }\n")
        (self.stub / "freertos").mkdir()
        (self.stub / "freertos/FreeRTOS.h").write_text(
            "#pragma once\ntypedef int portMUX_TYPE;\n#define portMUX_INITIALIZER_UNLOCKED 0\n"
            "#define portENTER_CRITICAL(m) ((void)(m))\n#define portEXIT_CRITICAL(m) ((void)(m))\n")
        self.includes = [self.stub, TAILNET, MAIN, RUNTIME_INC, TINYUSB_INC]

    def run(self, name, source, extra_flags=()):
        c_file = self.root / (name + ".c")
        c_file.write_text(source)
        exe = self.root / name
        cmd = ["cc", "-std=c11", "-Wall", "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-const-variable"]
        for inc in self.includes:
            cmd += ["-I", str(inc)]
        cmd += list(extra_flags) + [str(c_file), "-o", str(exe)]
        subprocess.run(cmd, check=True)
        result = subprocess.run([str(exe)], check=True, stdout=subprocess.PIPE)
        return result.stdout


def write_golden(name, data):
    GOLDEN.mkdir(parents=True, exist_ok=True)
    (GOLDEN / name).write_bytes(data)


def entries(data):
    """Parse the container format (to measure things while generating)."""
    result = []
    i = 0
    header = re.compile(rb"@@@@ SCENARIO (\S+) LEN (\d+) @@@@\n")
    while i < len(data):
        m = header.match(data, i)
        assert m, "bad container at %d" % i
        n = int(m.group(2))
        body = data[m.end() : m.end() + n]
        end = m.end() + n
        assert data[end : end + 15] == b"\n@@@@ END @@@@\n", "bad entry end"
        result.append((m.group(1).decode(), body))
        i = end + 15
    return result


# ----------------------------------------------------------------------------------------------------------------------
# Scenarios
# ----------------------------------------------------------------------------------------------------------------------
LINK_KEYS = ["connected", "rssi_valid", "rssi", "channel", "secondary", "phy", "bw_cfg_mhz", "ap_bw_mhz", "ap_modes", "ps",
             "tx_power_valid", "tx_power_qdbm", "selected_slot", "pinned", "pin_failed_slot"]
EVENT_KEYS = ["connects", "disconnects", "beacon_timeouts", "last_disconnect_ms", "last_reason", "last_disconnect_rssi", "roams"]
TEMP_KEYS = ["valid", "current_tenths", "peak_tenths", "sampled_at_ms", "errors", "samples", "changed_at_ms", "age_ms"]
CLOCK_KEYS = ["synced", "server", "restarts", "backoff_ms", "next_retry_ms", "retry_in_ms"]
MEM_KEYS = ["uptime_ms", "operation", "requested", "free_bytes", "minimum_bytes", "largest_bytes", "failed"]
TRAFFIC_KEYS = ["down_bytes", "up_bytes", "down_frames", "up_frames"]

VERSION = "0.3.0-golden"
LONG_VERSION = "9.99.999-" + "x" * 150   # long enough to cut the first status block in the 448 byte buffer


def link(**kw):
    base = dict(connected=False, rssi_valid=False, rssi=0, channel=0, secondary=0, phy=0, bw_cfg_mhz=0, ap_bw_mhz=0, ap_modes=0, ps=0,
                tx_power_valid=False, tx_power_qdbm=0, selected_slot=0, pinned=False, pin_failed_slot=0)
    base.update(kw)
    return base


def events(**kw):
    base = dict(connects=0, disconnects=0, beacon_timeouts=0, last_disconnect_ms=0, last_reason=0, last_disconnect_rssi=0, roams=0)
    base.update(kw)
    return base


def temperature(**kw):
    base = dict(valid=False, current_tenths=0, peak_tenths=0, sampled_at_ms=0, errors=0, samples=0, changed_at_ms=0, age_ms=U32)
    base.update(kw)
    return base


def clock(**kw):
    base = dict(synced=False, server=0, restarts=0, backoff_ms=0, next_retry_ms=0, retry_in_ms=0)
    base.update(kw)
    return base


def status_scenario(name, **kw):
    sc = dict(
        name=name, version=VERSION, setup_active=False, tailnet=False, wifi_current=-1, online=False,
        link=link(), events=events(), usb_mounted=False, usb_ready=False, uptime_ms=1234567, free_heap=219640,
        temperature=temperature(), clock=clock(), clock_valid=False,
        prefs=dict(saved=0, preferred=-1, priorities=[], roaming_assist=True),
        display=dict(brightness=60, rotation=0, dim_seconds=60, page=0),
        setup=dict(ap_name="TDongle-AB0CF9", seconds_left=0),
        traffic=dict(down_bytes=0, up_bytes=0, down_frames=0, up_frames=0, down_kbps=0, up_kbps=0, usb_resets=0, control_stack_free=1234),
        memory=[],
    )
    sc.update(kw)
    return sc


WIDE_LINK = link(connected=True, rssi_valid=True, rssi=-128, channel=255, secondary=2, phy=7, bw_cfg_mhz=255, ap_bw_mhz=255, ap_modes=255, ps=2,
                 tx_power_valid=True, tx_power_qdbm=-128, selected_slot=255, pinned=True, pin_failed_slot=255)
MAX_EVENTS = events(connects=U32, disconnects=U32, beacon_timeouts=U32, last_disconnect_ms=U32, last_reason=65535, last_disconnect_rssi=-128, roams=U32)
FULL_LINK = link(connected=True, rssi_valid=True, rssi=-61, channel=6, secondary=1, phy=5, bw_cfg_mhz=40, ap_bw_mhz=40, ap_modes=7, ps=0,
                 tx_power_valid=True, tx_power_qdbm=78, selected_slot=2, pinned=True)


def mem_record(i, failed=0):
    return dict(uptime_ms=1000 * (i + 1), operation=i % 7, requested=64 * i, free_bytes=100000 - 1000 * i, minimum_bytes=90000 - 1500 * i,
                largest_bytes=50000 - 100 * i, failed=failed)


def make_status_scenarios():
    s = []
    s.append(status_scenario("adapter_offline"))
    s.append(status_scenario("adapter_online", online=True, wifi_current=0, usb_mounted=True, usb_ready=True,
                             link=link(connected=True, rssi_valid=True, rssi=-61, channel=6, selected_slot=1),
                             temperature=temperature(valid=True, current_tenths=553, peak_tenths=600, sampled_at_ms=1200000, samples=120,
                                                     changed_at_ms=900000, age_ms=4000)))
    s.append(status_scenario("tailnet_online", tailnet=True, online=True, wifi_current=2, usb_mounted=True, usb_ready=True, link=FULL_LINK,
                             clock_valid=True, clock=clock(synced=True)))
    s.append(status_scenario("tailnet_offline_clock_waiting", tailnet=True))
    s.append(status_scenario("setup_mode", setup_active=True, setup=dict(ap_name="TDongle-AB0CF9", seconds_left=287)))
    s.append(status_scenario("setup_mode_over_tailnet", setup_active=True, tailnet=True, setup=dict(ap_name="TDongle-0102", seconds_left=0)))
    s.append(status_scenario("setup_ap_name_not_active", setup_active=False, setup=dict(ap_name="TDongle-ZZZZZZ", seconds_left=99)))
    s.append(status_scenario("setup_ap_name_15_chars", setup_active=True, setup=dict(ap_name="123456789012345", seconds_left=U32)))
    # rssi: unknown vs value, and the connected/valid corner cases
    for i, (conn, valid, rssi) in enumerate([(True, True, -128), (True, True, 127), (True, True, 0), (True, False, -50), (False, True, -50), (False, False, 0)]):
        s.append(status_scenario("rssi_%d" % i, online=conn, link=link(connected=conn, rssi_valid=valid, rssi=rssi, channel=1)))
    # online/offline x usb flags x mode
    for mode_name, kw in (("adapter", {}), ("tailnet", dict(tailnet=True)), ("setup", dict(setup_active=True))):
        for online in (False, True):
            for mounted in (False, True):
                for ready in (False, True):
                    s.append(status_scenario("usb_%s_%s_%d%d" % (mode_name, "up" if online else "joining", mounted, ready), online=online,
                                             usb_mounted=mounted, usb_ready=ready, **kw))
    # wifi_current
    for wc in (-1, 0, 1, 7, 8, 100):
        s.append(status_scenario("wifi_current_%d" % wc, wifi_current=wc))
    # temperature
    s.append(status_scenario("temp_invalid", temperature=temperature()))
    s.append(status_scenario("temp_invalid_after_samples", temperature=temperature(valid=False, current_tenths=410, peak_tenths=510, sampled_at_ms=70000, errors=3,
                                                                                     samples=7, changed_at_ms=60000, age_ms=15000)))
    s.append(status_scenario("temp_valid", temperature=temperature(valid=True, current_tenths=619, peak_tenths=701, sampled_at_ms=3600000, errors=0,
                                                                     samples=360, changed_at_ms=3590000, age_ms=999)))
    s.append(status_scenario("temp_negative", temperature=temperature(valid=True, current_tenths=-123, peak_tenths=-50, sampled_at_ms=5, samples=1,
                                                                        changed_at_ms=5, age_ms=1)))
    s.append(status_scenario("temp_min_int", temperature=temperature(valid=True, current_tenths=I32_MIN, peak_tenths=I32_MIN, sampled_at_ms=1)))
    s.append(status_scenario("temp_max_int", temperature=temperature(valid=True, current_tenths=I32_MAX, peak_tenths=I32_MAX, sampled_at_ms=U32,
                                                                       errors=U32, samples=U32, changed_at_ms=U32, age_ms=U32)))
    s.append(status_scenario("temp_age_uint32_max_before_first_sample", temperature=temperature(valid=False, age_ms=U32)))
    s.append(status_scenario("temp_age_zero", temperature=temperature(valid=True, current_tenths=300, peak_tenths=300, age_ms=0, samples=1)))
    # uptime and heap
    for i, up in enumerate([0, 1, 999, 2**31, U32, U32 + 1, 2**32 + 5, 5 * 2**32 + 123456, 2**40, 9223372036854775]):
        s.append(status_scenario("uptime_%d" % i, uptime_ms=up))
    for i, heap in enumerate([0, 1, 219640, 2**31, U32]):
        s.append(status_scenario("heap_%d" % i, free_heap=heap))
    # clock states
    s.append(status_scenario("clock_synced", online=True, clock_valid=True, clock=clock(synced=True, server=2, restarts=4)))
    s.append(status_scenario("clock_waiting", online=False, clock=clock(server=1)))
    s.append(status_scenario("clock_syncing", online=True, clock=clock(next_retry_ms=1000, backoff_ms=30000, retry_in_ms=29000)))
    s.append(status_scenario("clock_failing", online=True, clock=clock(server=2, restarts=3, backoff_ms=240000, next_retry_ms=2**40, retry_in_ms=U32)))
    s.append(status_scenario("clock_server_out_of_range", online=True, clock=clock(server=255, restarts=1)))
    # wifi_link: connected and disconnected, with events
    s.append(status_scenario("link_connected_full", online=True, link=FULL_LINK, events=events(connects=3, disconnects=2, beacon_timeouts=1, last_reason=200, roams=4)))
    s.append(status_scenario("link_widest", online=True, link=WIDE_LINK, events=MAX_EVENTS, tailnet=True))
    s.append(status_scenario("link_disconnected_pinned", link=link(pinned=True, selected_slot=3), events=events(connects=1, disconnects=1)))
    s.append(status_scenario("link_disconnected_failed", link=link(pin_failed_slot=2), events=events(disconnects=9, last_reason=15)))
    s.append(status_scenario("link_disconnected_widest", link=link(pinned=True, selected_slot=255, pin_failed_slot=255), events=MAX_EVENTS))
    # saved networks and priorities
    for count in range(0, 9):
        prios = [(7 * i + 13 * count) % 101 for i in range(count)]
        s.append(status_scenario("prefs_saved_%d" % count, prefs=dict(saved=count, preferred=-1, priorities=prios, roaming_assist=bool(count % 2))))
    s.append(status_scenario("prefs_priorities_100", prefs=dict(saved=8, preferred=7, priorities=[100] * 8, roaming_assist=True)))
    s.append(status_scenario("prefs_priorities_255", prefs=dict(saved=8, preferred=7, priorities=[255] * 8, roaming_assist=False)))
    s.append(status_scenario("prefs_priorities_zero", prefs=dict(saved=8, preferred=0, priorities=[0] * 8, roaming_assist=True)))
    s.append(status_scenario("prefs_priorities_short_slice", prefs=dict(saved=5, preferred=2, priorities=[70, 80], roaming_assist=True)))
    for pref in [-1] + list(range(8)):
        s.append(status_scenario("prefs_preferred_%d" % pref, prefs=dict(saved=8, preferred=pref, priorities=[10 * (i + 1) for i in range(8)], roaming_assist=True),
                                 events=events(roams=pref + 2)))
    s.append(status_scenario("roams_max", events=events(roams=U32)))
    # display, setup, traffic extremes
    s.append(status_scenario("display_default", display=dict(brightness=60, rotation=0, dim_seconds=60, page=2)))
    s.append(status_scenario("display_extremes", display=dict(brightness=255, rotation=255, dim_seconds=65535, page=U32)))
    s.append(status_scenario("display_zero", display=dict(brightness=0, rotation=0, dim_seconds=0, page=0)))
    s.append(status_scenario("setup_seconds_max", setup_active=True, setup=dict(ap_name="TDongle-AB0CF9", seconds_left=U32)))
    s.append(status_scenario("traffic_zero", traffic=dict(down_bytes=0, up_bytes=0, down_frames=0, up_frames=0, down_kbps=0, up_kbps=0, usb_resets=0, control_stack_free=0)))
    s.append(status_scenario("traffic_typical", traffic=dict(down_bytes=123456789, up_bytes=9876543, down_frames=81234, up_frames=51234, down_kbps=1234, up_kbps=56,
                                                           usb_resets=3, control_stack_free=1234)))
    s.append(status_scenario("traffic_max", traffic=dict(down_bytes=U32, up_bytes=U32, down_frames=U32, up_frames=U32, down_kbps=U32, up_kbps=U32, usb_resets=U32,
                                                       control_stack_free=U32)))
    # memory_pressure: 0..16 records
    for n in range(0, 17):
        s.append(status_scenario("memory_%d" % n, memory=[mem_record(i, failed=1 if i % 5 == 4 else 0) for i in range(n)]))
    s.append(status_scenario("memory_max_values", memory=[dict(uptime_ms=U32, operation=U32, requested=U32, free_bytes=U32, minimum_bytes=U32, largest_bytes=U32, failed=U32)] * 3))
    # everything at its widest at once, then truncation of the first block by a very long firmware version
    s.append(status_scenario(
        "widest_everything", setup_active=True, tailnet=True, wifi_current=7, online=True, usb_mounted=True, usb_ready=True, uptime_ms=9223372036854775, free_heap=U32,
        link=WIDE_LINK, events=MAX_EVENTS,
        temperature=temperature(valid=True, current_tenths=I32_MIN, peak_tenths=I32_MAX, sampled_at_ms=U32, errors=U32, samples=U32, changed_at_ms=U32, age_ms=U32),
        clock=clock(synced=True, server=2, restarts=U32, backoff_ms=U32, next_retry_ms=2**64 - 1, retry_in_ms=U32), clock_valid=False,
        prefs=dict(saved=8, preferred=7, priorities=[255] * 8, roaming_assist=True),
        display=dict(brightness=255, rotation=255, dim_seconds=65535, page=U32),
        setup=dict(ap_name="123456789012345", seconds_left=U32),
        traffic=dict(down_bytes=U32, up_bytes=U32, down_frames=U32, up_frames=U32, down_kbps=U32, up_kbps=U32, usb_resets=U32, control_stack_free=U32),
        memory=[dict(uptime_ms=U32, operation=U32, requested=U32, free_bytes=U32, minimum_bytes=U32, largest_bytes=U32, failed=1)] * 16))
    s.append(status_scenario("long_version_cuts_first_block", version=LONG_VERSION, online=True,
                             temperature=temperature(valid=True, current_tenths=553, peak_tenths=600, sampled_at_ms=1200000, samples=120, changed_at_ms=900000, age_ms=4000)))
    s.append(status_scenario("version_empty", version=""))
    # a seeded spread of combinations
    rng = random.Random(20260517)
    for i in range(80):
        count = rng.randint(0, 8)
        sc = status_scenario(
            "random_%02d" % i, setup_active=rng.random() < 0.15, tailnet=rng.random() < 0.4, wifi_current=rng.randint(-1, 7), online=rng.random() < 0.6,
            usb_mounted=rng.random() < 0.7, usb_ready=rng.random() < 0.5, uptime_ms=rng.choice([rng.randint(0, 10**7), rng.randint(0, 2**45)]),
            free_heap=rng.choice([rng.randint(0, 400000), rng.randint(0, U32)]),
            link=link(connected=rng.random() < 0.7, rssi_valid=rng.random() < 0.8, rssi=rng.randint(-128, 127), channel=rng.choice([1, 6, 11, 36, 149, 255]),
                      secondary=rng.choice([0, 1, 2, 3, 255]), phy=rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 255]), bw_cfg_mhz=rng.choice([0, 20, 40, 255]),
                      ap_bw_mhz=rng.choice([0, 20, 40, 80, 255]), ap_modes=rng.randint(0, 255), ps=rng.choice([0, 1, 2, 3, 255]),
                      tx_power_valid=rng.random() < 0.7, tx_power_qdbm=rng.randint(-128, 127), selected_slot=rng.randint(0, 8),
                      pinned=rng.random() < 0.3, pin_failed_slot=rng.choice([0, 0, 0, rng.randint(1, 8)])),
            events=events(connects=rng.randint(0, 50), disconnects=rng.randint(0, 50), beacon_timeouts=rng.randint(0, 20), last_disconnect_ms=rng.randint(0, U32),
                          last_reason=rng.choice([0, 8, 15, 200, 65535]), last_disconnect_rssi=rng.randint(-128, 127), roams=rng.randint(0, 99)),
            temperature=temperature(valid=rng.random() < 0.8, current_tenths=rng.randint(-200, 900), peak_tenths=rng.randint(0, 950),
                                    sampled_at_ms=rng.randint(0, U32), errors=rng.randint(0, 9), samples=rng.randint(0, 99999), changed_at_ms=rng.randint(0, U32),
                                    age_ms=rng.choice([0, 1000, U32])),
            clock=clock(synced=rng.random() < 0.5, server=rng.randint(0, 2), restarts=rng.randint(0, 40), backoff_ms=rng.choice([0, 30000, 600000]),
                        next_retry_ms=rng.randint(0, 2**40), retry_in_ms=rng.randint(0, 600000)),
            clock_valid=rng.random() < 0.5,
            prefs=dict(saved=count, preferred=rng.randint(-1, 7), priorities=[rng.randint(0, 100) for _ in range(count)], roaming_assist=rng.random() < 0.5),
            display=dict(brightness=rng.randint(5, 100), rotation=rng.randint(0, 1), dim_seconds=rng.randint(10, 3600), page=rng.randint(0, 5)),
            setup=dict(ap_name="TDongle-%06X" % rng.randint(0, 0xFFFFFF), seconds_left=rng.randint(0, 600)),
            traffic=dict(down_bytes=rng.randint(0, U32), up_bytes=rng.randint(0, U32), down_frames=rng.randint(0, U32), up_frames=rng.randint(0, U32),
                         down_kbps=rng.randint(0, 12000), up_kbps=rng.randint(0, 12000), usb_resets=rng.randint(0, 9), control_stack_free=rng.randint(0, 5000)),
            memory=[mem_record(j, failed=int(rng.random() < 0.3)) for j in range(rng.randint(0, 16))])
        s.append(sc)
    return s


def make_wifi_link_scenarios():
    rng = random.Random(7)
    phys = list(range(8)) + [8, 255]
    seconds = [0, 1, 2, 3, 255]
    ps = [0, 1, 2, 3, 255]
    modes = list(range(16)) + [255]
    rssis = [-128, -61, -1, 0, 1, 127]
    channels = [0, 1, 6, 11, 14, 36, 165, 255]
    bws = [0, 20, 40, 255]
    powers = [-128, 0, 78, 127]
    slots = [0, 1, 2, 3, 8, 255]
    out = []
    for i in range(68):
        out.append(dict(name="connected_%02d" % i, link=link(
            connected=True, rssi_valid=i % 5 != 4, rssi=rssis[i % len(rssis)], channel=channels[(3 * i) % len(channels)],
            secondary=seconds[i % len(seconds)], phy=phys[i % len(phys)], bw_cfg_mhz=bws[i % len(bws)], ap_bw_mhz=bws[(i + 1) % len(bws)],
            ap_modes=modes[i % len(modes)], ps=ps[(2 * i) % len(ps)], tx_power_valid=i % 3 != 2, tx_power_qdbm=powers[i % len(powers)],
            selected_slot=slots[i % len(slots)], pinned=i % 2 == 0, pin_failed_slot=slots[(i + 3) % len(slots)] if i % 7 == 0 else 0)))
    for j, (pinned, failed) in enumerate([(False, 0), (True, 0), (False, 3), (True, 3), (False, 255), (True, 255)]):
        out.append(dict(name="disconnected_%d" % j, link=link(pinned=pinned, pin_failed_slot=failed, selected_slot=j,
                                                              rssi_valid=True, rssi=-70, channel=6, phy=4)))
    out.append(dict(name="all_zero", link=link()))
    out.append(dict(name="all_unknown", link=link(connected=True, secondary=255, phy=255, ps=255)))
    out.append(dict(name="widest", link=WIDE_LINK))
    out.append(dict(name="widest_disconnected", link=link(pinned=True, selected_slot=255, pin_failed_slot=255)))
    out.append(dict(name="full", link=FULL_LINK))
    event_sets = [events(), events(connects=3, disconnects=2, beacon_timeouts=1, last_disconnect_ms=9000, last_reason=200, last_disconnect_rssi=-85),
                  MAX_EVENTS, events(last_reason=65535, last_disconnect_rssi=127)]
    for k, sc in enumerate(out):
        sc["events"] = event_sets[0] if k % 4 else event_sets[(k // 4) % len(event_sets)]
        if sc["name"] in ("widest", "widest_disconnected"):
            sc["events"] = MAX_EVENTS
        if sc["name"] == "full":
            sc["events"] = event_sets[1]
    return out


def make_clock_scenarios():
    scs = []
    # the schedule of the C test, to the ceiling
    steps = [["poll", 5000, 0, 0]]
    t = 5000
    steps.append(["poll", t, 0, 1])
    steps.append(["poll", t + 29999, 0, 1])
    t += 30000
    steps.append(["poll", t, 0, 1])
    backoff = 60000
    for _ in range(20):
        t += backoff
        steps.append(["poll", t - 1, 0, 1])
        steps.append(["poll", t, 0, 1])
        backoff = min(backoff * 2, 600000)
    steps += [["poll", t + 1, 0, 0], ["poll", t + 2, 0, 1], ["poll", t + 3, 1, 1], ["poll", t + 4, 0, 1]]
    scs.append(dict(name="backoff_to_ceiling", initial=clock(), steps=steps))
    scs.append(dict(name="step_only", initial=clock(), steps=[["step", 100, 0, 1], ["step", 30100, 0, 1], ["step", 30101, 0, 1], ["step", 90100, 1, 1]]))
    scs.append(dict(name="uplink_flapping", initial=clock(restarts=2, server=1, backoff_ms=120000),
                    steps=[["poll", 1000, 0, 1], ["poll", 1001, 0, 0], ["poll", 1002, 0, 1], ["poll", 31002, 0, 1], ["poll", 31003, 0, 0], ["poll", 40000, 1, 0]]))
    scs.append(dict(name="clock_valid_first", initial=clock(next_retry_ms=5, backoff_ms=7), steps=[["poll", 10, 1, 1], ["poll", 11, 0, 1]]))
    scs.append(dict(name="huge_times", initial=clock(), steps=[["poll", 2**40, 0, 1], ["poll", 2**40 + 30000, 0, 1], ["poll", 2**40 + 90000, 0, 1], ["poll", 2**50, 0, 1]]))
    scs.append(dict(name="backoff_just_below_half", initial=clock(next_retry_ms=1, backoff_ms=299999), steps=[["poll", 2, 0, 1], ["poll", 600000, 0, 1]]))
    scs.append(dict(name="backoff_at_half", initial=clock(next_retry_ms=1, backoff_ms=300000), steps=[["poll", 2, 0, 1]]))
    scs.append(dict(name="backoff_huge", initial=clock(next_retry_ms=1, backoff_ms=U32), steps=[["poll", 2, 0, 1], ["poll", 999999999, 0, 1]]))
    scs.append(dict(name="server_wraps", initial=clock(next_retry_ms=1, backoff_ms=30000, server=2), steps=[["poll", 2, 0, 1], ["poll", 70000, 0, 1], ["poll", 700000, 0, 1]]))
    scs.append(dict(name="server_out_of_range", initial=clock(next_retry_ms=1, backoff_ms=30000, server=255), steps=[["poll", 2, 0, 1]]))
    scs.append(dict(name="retry_in_truncates", initial=clock(), steps=[["poll", 1, 0, 1], ["poll", 2**32, 0, 1]]))
    states = [dict(restarts=r, valid=v, up=u) for r in (0, 1, U32) for v in (0, 1) for u in (0, 1)]
    return scs, states


def make_list_scenarios():
    def net(name, ssid, priority):
        return dict(name_hex=name.hex(), ssid_hex=ssid.hex(), priority=priority)

    cases = [
        ("empty", -1, []),
        ("one", 0, [net(b"Home", b"HomeNet", 80)]),
        ("one_not_current", -1, [net(b"Home", b"HomeNet", 80)]),
        ("two_second_current", 1, [net(b"Home sweet", b"HomeNet", 80), net(b"Car", b"CarWifi", 10)]),
        ("empty_name_and_ssid", 0, [net(b"", b"", 0)]),
        ("widest_name_ssid", 7, [net(b"N" * 24, b"S" * 32, 255)] * 8),
        ("utf8_ssid", 0, [net(b"Caf\xc3\xa9", "Café ☕".encode(), 50)]),
        ("non_utf8_ssid", 0, [net(b"raw", b"\xff\xfe\x80 ssid", 100)]),
        ("current_out_of_range", 9, [net(b"a", b"b", 1)]),
        ("eight_priorities", 3, [net(("n%d" % i).encode(), ("ssid%d" % i).encode(), i * 14) for i in range(8)]),
    ]
    return [dict(name=n, current=c, networks=nets) for n, c, nets in cases]


def make_display_scenarios():
    values = [(60, 0, 60), (5, 0, 10), (100, 1, 3600), (0, 0, 0), (255, 255, 65535), (35, 1, 900), (7, 0, 12345)]
    return [dict(name="d%d" % i, brightness=b, rotation=r, dim_seconds=d) for i, (b, r, d) in enumerate(values)]


def make_scan_scenarios():
    def ap(name, ssid, rssi, auth):
        return dict(name=name, ssid_hex=(ssid + b"\0" * 32)[:32].hex(), rssi=rssi, auth=auth)

    return [
        ap("plain", b"HomeNet", -61, 3),
        ap("empty", b"", -90, 0),
        ap("full_32", b"0123456789abcdef0123456789abcdef", -128, 7),
        ap("controls", b"a\tb\x01c\x7fd\xffe", 127, 9),
        ap("high_bytes", b"\xc3\xa9\xe2\x98\x95", 0, 1),
        ap("nul_then_text", b"ab\0cd", -1, 2),
        ap("all_nonprintable", bytes(range(1, 32)) + b"\x7f", -77, 4),
        ap("space_and_tilde", b" ~ ", -70, 6),
    ]


def make_pm_scenarios():
    def lock(name, base):
        return dict(name=name, depth=base, acquires=base + 1, releases=base + 2, held_us=base * 1000, max_depth=base + 3, underflows=0, forced_releases=base % 2,
                    backend_failures=0, isr_rejects=base % 3)

    table = "Lock stats:\n  APB_FREQ_MAX  0  0\n  CPU_FREQ_MAX  1  42\nTotal: 2\n"
    ladder = [lock("lock_%d" % i, i * 7) for i in range(8)]
    big = dict(name="x" * 20, depth=U32, acquires=U32, releases=U32, held_us=U32, max_depth=U32, underflows=U32, forced_releases=U32, backend_failures=U32,
               isr_rejects=U32)
    return [
        dict(name="idle", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[], dump=None),
        dict(name="busy_with_locks", power=dict(scaling=True, configure_error=0, cpu_mhz=240, max_mhz=240, min_mhz=80, lock_create_failures=0),
             locks=[lock("usb_tx", 3), lock("wifi_rx", 0)], dump=table),
        dict(name="scaling_off", power=dict(scaling=False, configure_error=-258, cpu_mhz=240, max_mhz=0, min_mhz=0, lock_create_failures=2), locks=[], dump=table),
        dict(name="eight_locks", power=dict(scaling=True, configure_error=0, cpu_mhz=240, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=ladder, dump=None),
        dict(name="widest", power=dict(scaling=True, configure_error=I32_MIN, cpu_mhz=U32, max_mhz=U32, min_mhz=U32, lock_create_failures=U32), locks=[big], dump=table),
        dict(name="name_cuts_line", power=dict(scaling=True, configure_error=0, cpu_mhz=1, max_mhz=2, min_mhz=3, lock_create_failures=4),
             locks=[dict(lock("n", 5), name="L" * 150)], dump=None),
        dict(name="dump_no_trailing_newline", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[],
             dump="first\nsecond"),
        dict(name="dump_blank_lines", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[],
             dump="\n\nthird\n\n"),
        dict(name="dump_only_newline", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[], dump="\n"),
        dict(name="dump_line_117", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[],
             dump="a" * 117 + "\nnext\n"),
        dict(name="dump_line_118", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[],
             dump="b" * 118 + "\nnext\n"),
        dict(name="dump_line_300_loses_bytes", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[],
             dump="".join(chr(ord("a") + i % 26) for i in range(300)) + "\ntail\n"),
        dict(name="dump_long_without_newline", power=dict(scaling=True, configure_error=0, cpu_mhz=80, max_mhz=240, min_mhz=80, lock_create_failures=0), locks=[],
             dump="c" * 400),
    ]


def make_memory_log_scenarios():
    rng = random.Random(99)

    def step(uptime, requested, free, minimum, largest, failed):
        return dict(uptime_ms=uptime, operation=requested % 7, requested=requested, free_bytes=free, minimum_bytes=minimum, largest_bytes=largest, failed=failed)

    scs = []
    scs.append(dict(name="falling_minimum", steps=[step(i * 10, 64, 90000 - 100 * i, 80000 - 100 * i, 40000, 0) for i in range(40)]))
    scs.append(dict(name="flat_minimum", steps=[step(i, 8, 5000, 3000, 2000, 0) for i in range(10)]))
    scs.append(dict(name="failures_among_flat", steps=[step(i, 8, 5000, 3000, 2000, 1 if i in (0, 3, 4, 9) else 0) for i in range(12)]))
    scs.append(dict(name="failures_only", steps=[step(i, 8, 5000, 3000, 2000, 1) for i in range(40)]))
    scs.append(dict(name="rising_after_fall", steps=[step(i, 1, 9000, m, 100, 0) for i, m in enumerate([5000, 4000, 4500, 4000, 3999, 6000, 3000, 3000, 2999])]))
    scs.append(dict(name="extremes", steps=[step(2**32 - 1, 2**32 - 1, 2**32 - 1, 2**32 - 1, 2**32 - 1, 1), step(0, 0, 0, 0, 0, 0), step(1, 1, 1, 0, 1, 1)]))
    scs.append(dict(name="non_boolean_failed_flag", steps=[step(1, 1, 1, 100, 1, 77), step(2, 1, 1, 100, 1, 0)]))
    for k in range(6):
        minimum = 100000
        steps = []
        for i in range(300):
            minimum = max(0, minimum - rng.choice([0, 0, 0, 0, 1, 5, 400]) + rng.choice([0, 0, 0, 3000]))
            steps.append(step(i * 7, rng.randint(0, 5000), minimum + rng.randint(0, 9999), minimum, rng.randint(0, 60000), 1 if rng.random() < 0.08 else 0))
        scs.append(dict(name="random_%d" % k, steps=steps))
    return scs


def make_strtol_inputs():
    rng = random.Random(5)
    fixed = ["", " ", "0", "1", "-1", "+1", "00", "007", "42abc", "  42", "\t\n\v\f\r 7", "- 1", "+ 1", "--1", "+-1", "abc", "  abc", "x1", "0x10", "1e3", "1.5", "2147483647",
             "2147483648", "-2147483648", "-2147483649", "4294967295", "4294967296", "-4294967296", "99999999999999999999999999", "-99999999999999999999999999",
             "9223372036854775807", "9223372036854775808", "1 2", "1 ", " 1 ", "+", "-", "0-0", "1,2", "12\x01", "\x0bx", "3x", "8 "]
    inputs = [s.encode() for s in fixed]
    alphabet = b" \t+-0123456789xa."
    for _ in range(1500):
        inputs.append(bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 9))))
    return [x.hex() for x in inputs]


def make_bridge_scenarios(fields):
    l2, ring, rx, wifi_tx = fields

    def build(value_of):
        return dict(l2={f: value_of("l2", f, i) for i, f in enumerate(l2)}, ring={f: value_of("ring", f, i) for i, f in enumerate(ring)},
                    rx={f: value_of("rx", f, i) for i, f in enumerate(rx)}, wifi_tx={f: value_of("wifi_tx", f, i) for i, f in enumerate(wifi_tx)})

    flags = {"linked", "installed", "tx_done_cb"}
    scs = []
    scs.append(dict(name="zero", **build(lambda g, f, i: 0)))
    scs.append(dict(name="distinct", **build(lambda g, f, i: (1 if f in flags else 1000 + 7 * i + {"l2": 0, "ring": 300, "rx": 600, "wifi_tx": 900}[g]))))
    scs.append(dict(name="ones", **build(lambda g, f, i: 1)))
    scs.append(dict(name="max_u32", **build(lambda g, f, i: 1 if f in flags else I32_MAX if f == "h2w_last_tx_error" else U32)))
    scs.append(dict(name="max_u32_with_error_min", **build(lambda g, f, i: 1 if f in flags else I32_MIN if f == "h2w_last_tx_error" else U32)))
    scs.append(dict(name="max_u32_with_error_max", **build(lambda g, f, i: 1 if f in flags else I32_MAX if f == "h2w_last_tx_error" else U32)))
    scs.append(dict(name="negative_error", **build(lambda g, f, i: -12 if f == "h2w_last_tx_error" else 5)))
    scs.append(dict(name="ten_digits_each", **build(lambda g, f, i: 1 if f in flags else 1000000000 + i)))
    scs.append(dict(name="nine_digits_each", **build(lambda g, f, i: 1 if f in flags else 100000000 + i)))
    # identities that hold at rest (checked by the Rust test): frames add up
    ident = build(lambda g, f, i: 0)
    ident["l2"].update(linked=1, w2h_forwarded=900, w2h_invalid=1, w2h_own_mac=2, w2h_link_down=3, w2h_usb_not_ready=4, w2h_ring_full=5, w2h_frames=915,
                       h2w_queued=800, h2w_invalid=6, h2w_foreign_mac=7, h2w_link_down=8, h2w_frames=821,
                       h2w_sent=760, h2w_stale=1, h2w_sojourn_drop=2, h2w_link_down_queued=3, h2w_tx_failed=4, h2w_codel_drop=5, h2w_queue_depth=25)
    ident["wifi_tx"].update(installed=1, tx_done_cb=1, charged=100, done=90, aborted=3, flushed=2, stale=1, inflight=4)
    ident["l2"]["worker_stack_free"] = 1500
    scs.append(dict(name="identities", **ident))
    return scs


def make_bridge_emit_scenarios():
    big = 2**63 - 1
    small = -(2**63)
    seqs = []

    def seq(name, items):
        seqs.append(dict(name=name, seq=[list(x) for x in items]))

    seq("empty", [])
    seq("one_field", [("link", "linked", 1)])
    seq("two_sections", [("link", "a", 1), ("link", "b", 2), ("to_host", "frames", 3)])
    seq("section_repeats_not_adjacent", [("a", "x", 1), ("b", "y", 2), ("a", "z", 3)])
    seq("i64_extremes", [("s", "max", big), ("s", "min", small), ("s", "neg", -1), ("s", "zero", 0)])
    seq("negative_values", [("s", "a", -12), ("s", "b", -2147483648)])
    # a line that fills up: 10 character names with the widest values (22 bytes a field) overflow after 19 fields
    seq("overflow_drops_fields", [("big", "n%09d" % i, small) for i in range(30)])
    # a field that does not fit is left out whole, a later shorter one still fits
    seq("skip_then_shorter_fits", [("t", "f%02d" % i, small) for i in range(18)] + [("t", "this_name_is_long_enough_to_not_fit_x", small), ("t", "s", 1)])
    # exactly at the boundary: header "bridge_s" is 8 bytes; fill to 445 exactly and one more
    fill = []
    used = len("bridge_s")
    while True:
        name = "k%02d" % len(fill)
        field = " %s=%d" % (name, 1)
        if used + len(field) > 445:
            break
        fill.append(("s", name, 1))
        used += len(field)
    pad = 445 - used
    if pad >= 4:
        fill.append(("s", "p" * (pad - 3), 1))   # " " + name + "=1" -> exactly pad bytes
        used = 445
    seq("fits_exactly_445", fill)
    seq("one_over_445", fill + [("s", "z", 1)])
    seq("long_section_name", [("x" * 100, "n", 1), ("x" * 100, "m", 2)])
    seq("many_sections", [("s%d" % i, "v", i) for i in range(12)])
    seq("empty_name", [("s", "", 5), ("s", "ok", 6)])
    return seqs


# ----------------------------------------------------------------------------------------------------------------------
# Generators: each returns golden bytes
# ----------------------------------------------------------------------------------------------------------------------
def gen_status(ws, scenarios):
    src = (TAILNET / "serial_setup.inc").read_text()
    body = extract_function(src, "static void serial_status(void)")
    body = body.replace("mgmt_write(", "capture_write(")
    versions = sorted({sc["version"] for sc in scenarios})
    funcs = []
    for k, v in enumerate(versions):
        fn = body.replace("serial_status(", "serial_status_v%d(" % k, 1)
        funcs.append('#undef GATEWAY_VERSION\n#define GATEWAY_VERSION %s\n%s\n' % ('"' + v + '"', fn))
    prelude = COMMON + r"""
#include "wifi_link.h"
#include "clock_sync.h"
#include "wifi_meta.h"
#include "traffic.h"
#include "tdongle_temperature.h"
#include "tdongle_memory.h"

static bool setup_active, tailnet_mode, online, roaming_v, clock_valid_v, mounted_v, ready_v;
static int wifi_current;
static int64_t timer_us;
static uint32_t free_heap_v;
static tdongle_temperature temp_v;
static wifi_link_info link_v;
static wifi_link_events wifi_link_stats;
static gw_clock_t sntp_clock;
static struct { unsigned count; } wifi_saved;
static wifi_meta_set wifi_meta;
static struct { uint8_t brightness, rotation; uint16_t dim_seconds; } display_settings;
static struct { unsigned page; struct { uint32_t down_kbps, up_kbps; } traffic; } ui;
static char setup_ap_name[16];
typedef struct { int unused; } setup_session;
static setup_session setup_clock;
static uint32_t seconds_left_v;
static traffic_counters traffic_v;
static unsigned usb_resets_v, stack_free_v;
static tdongle_memory_record mem_v[16];
static unsigned mem_count_v;

static bool gateway_tailnet_mode(void) { return tailnet_mode; }
static bool tud_mounted(void) { return mounted_v; }
static bool tud_ready(void) { return ready_v; }
static int64_t esp_timer_get_time(void) { return timer_us; }
static uint32_t esp_get_free_heap_size(void) { return free_heap_v; }
tdongle_temperature tdongle_temperature_snapshot(void) { return temp_v; }
static wifi_link_info wifi_link_read(void) { return link_v; }
static bool ml_derp_clock_valid(void) { return clock_valid_v; }
static bool wifi_roaming_assist(void) { return roaming_v; }
static uint32_t setup_session_seconds_left(const setup_session *s, uint32_t now_ms) { (void)s; (void)now_ms; return seconds_left_v; }
traffic_counters traffic_read(void) { return traffic_v; }
static unsigned gateway_usb_health(unsigned i) { return i == 8 ? usb_resets_v : 0; }
#define uxTaskGetStackHighWaterMark(x) (stack_free_v)
unsigned tdongle_memory_count(void) { return mem_count_v; }
tdongle_memory_record tdongle_memory_get(unsigned i) { return mem_v[i]; }
"""
    main = ["int main(void) {"]
    for sc in scenarios:
        k = versions.index(sc["version"])
        p = sc["prefs"]
        lines = [
            "{",
            "memset(&wifi_meta, 0, sizeof(wifi_meta)); memset(mem_v, 0, sizeof(mem_v));",
            "setup_active=%s; tailnet_mode=%s; online=%s; wifi_current=%s;" % (clit(sc["setup_active"]), clit(sc["tailnet"]), clit(sc["online"]), clit(sc["wifi_current"])),
            "link_v=(wifi_link_info){%s};" % cinit(sc["link"], LINK_KEYS),
            "wifi_link_stats=(wifi_link_events){%s};" % cinit(sc["events"], EVENT_KEYS),
            "mounted_v=%s; ready_v=%s; timer_us=(int64_t)%s*1000; free_heap_v=%s;" % (clit(sc["usb_mounted"]), clit(sc["usb_ready"]), clit(sc["uptime_ms"]), clit(sc["free_heap"])),
            "temp_v=(tdongle_temperature){%s};" % cinit(sc["temperature"], TEMP_KEYS),
            "sntp_clock=(gw_clock_t){%s}; clock_valid_v=%s;" % (cinit(sc["clock"], CLOCK_KEYS), clit(sc["clock_valid"])),
            "wifi_saved.count=%s; wifi_meta.preferred=%s; roaming_v=%s;" % (clit(p["saved"]), clit(p["preferred"]), clit(p["roaming_assist"])),
        ]
        assert p["saved"] <= 8 and len(p["priorities"]) <= 8
        for i, pr in enumerate(p["priorities"]):
            lines.append("wifi_meta.slot[%d].priority=%d;" % (i, pr))
        d, su, t = sc["display"], sc["setup"], sc["traffic"]
        lines += [
            "display_settings.brightness=%s; display_settings.rotation=%s; display_settings.dim_seconds=%s; ui.page=%s;" % tuple(clit(d[x]) for x in ("brightness", "rotation", "dim_seconds", "page")),
            "ui.traffic.down_kbps=%s; ui.traffic.up_kbps=%s;" % (clit(t["down_kbps"]), clit(t["up_kbps"])),
            "strcpy(setup_ap_name, %s); seconds_left_v=%s;" % (cstr(su["ap_name"].encode()), clit(su["seconds_left"])),
            "traffic_v=(traffic_counters){%s}; usb_resets_v=%s; stack_free_v=%s;" % (cinit(t, TRAFFIC_KEYS), clit(t["usb_resets"]), clit(t["control_stack_free"])),
            "mem_count_v=%d;" % len(sc["memory"]),
        ]
        assert len(su["ap_name"]) <= 15 and len(sc["memory"]) <= 16
        for i, m in enumerate(sc["memory"]):
            lines.append("mem_v[%d]=(tdongle_memory_record){%s};" % (i, cinit(m, MEM_KEYS)))
        lines += ["serial_status_v%d();" % k, 'entry("%s");' % sc["name"], "}"]
        main += lines
    main += ["return 0; }"]
    return ws.run("status", prelude + "\n".join(funcs) + "\n" + "\n".join(main))


def gen_wifi_link(ws, scenarios):
    prelude = COMMON + r"""
#include "wifi_link.h"
static void render(const char *name, const wifi_link_info *l, const wifi_link_events *e) {
    char big[2048];
    size_t line_n = wifi_link_line(big, sizeof(big), l, e);
    size_t line_caps[8]; unsigned nc = 0;
    line_caps[nc++] = WIFI_LINK_LINE_MAX; line_caps[nc++] = line_n; line_caps[nc++] = line_n + 1; if (line_n > 1) line_caps[nc++] = line_n - 1;
    for (unsigned i = 0; i < nc; i++) {
        bool dup = false; for (unsigned j = 0; j < i; j++) dup |= line_caps[j] == line_caps[i];
        if (dup) continue;
        char buf[2048]; memset(buf, 'x', sizeof(buf));
        size_t n = wifi_link_line(buf, line_caps[i], l, e);
        capture_write(n ? buf : "");
        if (n && n != strlen(buf)) { fputs("line length mismatch\n", stderr); exit(2); }
        char label[96]; snprintf(label, sizeof(label), "%s/line@%zu", name, line_caps[i]); entry(label);
    }
    size_t json_n = wifi_link_json(big, sizeof(big), l, e);
    size_t json_caps[8]; nc = 0;
    json_caps[nc++] = WIFI_LINK_JSON_MAX; json_caps[nc++] = json_n; json_caps[nc++] = json_n + 1; if (json_n > 1) json_caps[nc++] = json_n - 1;
    for (unsigned i = 0; i < nc; i++) {
        bool dup = false; for (unsigned j = 0; j < i; j++) dup |= json_caps[j] == json_caps[i];
        if (dup) continue;
        char buf[2048]; memset(buf, 'x', sizeof(buf));
        size_t n = wifi_link_json(buf, json_caps[i], l, e);
        capture_write(n ? buf : "");
        if (n && n != strlen(buf)) { fputs("json length mismatch\n", stderr); exit(2); }
        char label[96]; snprintf(label, sizeof(label), "%s/json@%zu", name, json_caps[i]); entry(label);
    }
    /* the rssi token and the names, for every raw value */
    char token[5]; capture_write(wifi_link_rssi_text(l, token)); char label[96]; snprintf(label, sizeof(label), "%s/rssi_text", name); entry(label);
}
int main(void) {
"""
    main = []
    for sc in scenarios:
        main.append("{ wifi_link_info l=(wifi_link_info){%s}; wifi_link_events e=(wifi_link_events){%s}; render(\"%s\", &l, &e); }" %
                    (cinit(sc["link"], LINK_KEYS), cinit(sc["events"], EVENT_KEYS), sc["name"]))
    main.append(r"""
    /* names for every raw value 0..299 (phy/secondary/ps/join), and the modes text for every bit pattern */
    for (unsigned v = 0; v < 300; v++) {
        char label[64]; char modes[6]; wifi_link_modes_text(v & 255, modes);
        char text[160]; snprintf(text, sizeof(text), "phy=%s secondary=%s ps=%s join=%s modes=%s", wifi_link_phy_name(v), wifi_link_secondary_name(v), wifi_link_ps_name(v), wifi_link_join_name(v), modes);
        capture_write(text); snprintf(label, sizeof(label), "names/%u", v); entry(label);
    }
    for (int r = -128; r <= 127; r++) {
        wifi_link_info l = {.connected = true, .rssi_valid = true, .rssi = (int8_t)r}; char token[5];
        capture_write(wifi_link_rssi_text(&l, token)); char label[64]; snprintf(label, sizeof(label), "rssi/%d", r); entry(label);
    }
    return 0; }
""")
    return ws.run("wifi_link", prelude + "\n".join(main))


def gen_clock(ws, scenarios, states):
    prelude = COMMON + r"""
#include "clock_sync.h"
static void dump(gw_clock_t *c, int step, gw_clock_action a, bool valid, bool up) {
    char line[256];
    snprintf(line, sizeof(line), "step=%d action=%d synced=%d server=%u restarts=%u backoff_ms=%u next_retry_ms=%llu retry_in_ms=%u state=%s\n", step, (int)a,
             c->synced, (unsigned)c->server, (unsigned)c->restarts, (unsigned)c->backoff_ms, (unsigned long long)c->next_retry_ms, (unsigned)c->retry_in_ms,
             gw_clock_state(c, valid, up));
    capture_write(line);
}
int main(void) {
    char head[256];
    snprintf(head, sizeof(head), "servers=%d first_retry_ms=%u max_retry_ms=%u names=%s,%s,%s\n", GW_CLOCK_SERVERS, GW_CLOCK_FIRST_RETRY_MS, GW_CLOCK_MAX_RETRY_MS,
             gw_clock_server_name[0], gw_clock_server_name[1], gw_clock_server_name[2]);
    capture_write(head); entry("constants");
"""
    main = []
    for sc in scenarios:
        main.append("{ gw_clock_t c=(gw_clock_t){%s}; int step=0; (void)step;" % cinit(sc["initial"], CLOCK_KEYS))
        for kind, now, valid, up in sc["steps"]:
            fn = "gw_clock_poll" if kind == "poll" else "gw_clock_step"
            main.append("{ gw_clock_action a=%s(&c, %s, %s, %s); dump(&c, step++, a, %s, %s); }" % (fn, clit(now), clit(valid), clit(up), clit(valid), clit(up)))
        main.append('entry("%s"); }' % sc["name"])
    main.append("{ gw_clock_t c; memset(&c,0,sizeof c); char line[160];")
    for st in states:
        main.append("c.restarts=%s; snprintf(line,sizeof line,\"restarts=%%u valid=%%d up=%%d state=%%s\\n\",(unsigned)c.restarts,%d,%d,gw_clock_state(&c,%s,%s)); capture_write(line);" %
                    (clit(st["restarts"]), st["valid"], st["up"], clit(st["valid"]), clit(st["up"])))
    main.append('entry("states"); }')
    main.append("return 0; }")
    return ws.run("clock", prelude + "\n".join(main))


def control_text():
    return (TAILNET / "control.c").read_text()


def gen_texts(ws):
    """help / capabilities / unknown command (control.c) and the greeting (console.c), release and diagnostics image."""
    control = control_text()
    console = (TAILNET / "console.c").read_text()
    macro_start = control.index("#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS")
    macro_end = control.index("#endif", macro_start) + len("#endif")
    macros = control[macro_start:macro_end]
    # find the statements by their anchors instead of by whitespace
    h = control.index('if (!strcmp(line, "help"))')
    help_call = extract_call(control[h:], "mgmt_write")
    c = control.index('else if (!strcmp(line, "capabilities"))')
    caps_call = extract_call(control[c:], "mgmt_write")
    u = control.index('mgmt_write(gateway_tailnet_mode()?"ERR Unknown command')
    unknown_call = extract_call(control[u:], "mgmt_write")
    g = console.index('mgmt_write(gateway_tailnet_mode()?"T-Dongle-S3 tailnet')
    greeting_call = extract_call(console[g:], "mgmt_write")
    result = b""
    for diag in (False, True):
        prelude = COMMON + '\n#define GATEWAY_VERSION "1.2.3-golden"\n'
        if diag:
            prelude += "#define CONFIG_TDONGLE_MEMORY_DIAGNOSTICS 1\n"
        prelude += "static bool tailnet; static bool gateway_tailnet_mode(void){return tailnet;}\n" + macros + "\n"
        prelude += "#define mgmt_write capture_write\n"
        body = ["int main(void){"]
        for tailnet in (0, 1):
            for label, call in (("help", help_call), ("capabilities", caps_call), ("unknown", unknown_call), ("greeting", greeting_call)):
                body.append("tailnet=%d; %s; entry(\"%s/%s/%s\");" % (tailnet, call, label, "tailnet" if tailnet else "bridge", "diagnostics" if diag else "release"))
        body.append("return 0;}")
        result += ws.run("texts_%d" % diag, prelude + "\n".join(body))
    return result


def gen_replies(ws, list_scenarios, display_scenarios, scan_scenarios):
    serial = (TAILNET / "serial_setup.inc").read_text()
    list_for = None
    marker = 'if(!strcmp(line,"list"))'
    i = serial.index(marker) + len(marker)
    f = serial.index("for", i)
    paren = serial.index("(", f)
    brace = serial.index("{", match_close(serial, paren))
    list_for = serial[f : match_close(serial, brace) + 1].replace("mgmt_write(", "capture_write(")
    display_block = extract_block_after(serial, "if(!line[7])").replace("mgmt_write(", "capture_write(")
    scan_block = extract_block_after(serial, "{char ssid[33];memcpy(ssid,ap.ssid,32)").replace("mgmt_write(", "capture_write(")
    saved_call = extract_call(serial, 'snprintf(reply,sizeof(reply),"OK saved to slot')
    switching_call = extract_call(serial, "snprintf(reply,sizeof(reply),kept?")
    prelude = COMMON + r"""
#include "wifi_meta.h"
typedef struct {char ssid[33], password[64];} wifi_profile;
static struct { unsigned count; wifi_profile profiles[8]; } wifi_saved;
static wifi_meta_set wifi_meta;
static int wifi_current;
static struct { uint8_t brightness, rotation; uint16_t dim_seconds; } display_settings;
static void list_networks(void) {
    char reply[160];
    %s
}
static void display_show(void) {
    char reply[96];
    %s
}
static struct { uint8_t ssid[33]; int8_t rssi; int authmode; } ap;
static void scan_one(void) {
    char reply[128]; unsigned count = 0;
    %s
}
static void saved_reply(int slot) { char reply[64]; %s; capture_write(reply); }
static void switching_reply(long slot, bool kept) { char reply[160]; %s; capture_write(reply); }
static void unhex(char *dst, size_t cap, const char *hex) {
    size_t n = strlen(hex) / 2; if (n >= cap) { fputs("too long\n", stderr); exit(2); }
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(hex + 2 * i, "%%2x", &v); dst[i] = (char)v; }
    dst[n] = 0;
}
int main(void) {
""" % (list_for, display_block, scan_block, saved_call, switching_call)
    main = []
    for sc in list_scenarios:
        assert len(sc["networks"]) <= 8
        main.append("{ memset(&wifi_saved,0,sizeof wifi_saved); memset(&wifi_meta,0,sizeof wifi_meta); wifi_current=%d; wifi_saved.count=%d;" % (sc["current"], len(sc["networks"])))
        for i, n in enumerate(sc["networks"]):
            main.append('unhex(wifi_meta.slot[%d].name, sizeof wifi_meta.slot[%d].name, "%s"); unhex(wifi_saved.profiles[%d].ssid, sizeof wifi_saved.profiles[%d].ssid, "%s"); wifi_meta.slot[%d].priority=%d;' %
                        (i, i, n["name_hex"], i, i, n["ssid_hex"], i, n["priority"]))
        main.append('list_networks(); entry("list/%s"); }' % sc["name"])
    for sc in display_scenarios:
        main.append('{ display_settings.brightness=%d; display_settings.rotation=%d; display_settings.dim_seconds=%d; display_show(); entry("display/%s"); }' %
                    (sc["brightness"], sc["rotation"], sc["dim_seconds"], sc["name"]))
    for sc in scan_scenarios:
        main.append('{ memset(&ap,0,sizeof ap); { char tmp[40]; unhex(tmp, sizeof tmp, "%s"); memcpy(ap.ssid, tmp, 32); } ap.rssi=%d; ap.authmode=%d; scan_one(); entry("scan/%s"); }' %
                    (sc["ssid_hex"], sc["rssi"], sc["auth"], sc["name"]))
    # NB: unhex stops at the first NUL only for printing; the 32 raw bytes are copied above (ssid_hex is padded to 32 bytes).
    for slot in [0, 1, 2, 7, 8, 9, 100, -1, I32_MAX - 1, 2147483646]:
        main.append('saved_reply(%d); entry("saved/%d");' % (slot, slot))
    for slot in [0, 1, 2, 8, 9, -3, I32_MAX, I32_MIN, 12345]:
        for kept in (1, 0):
            main.append('switching_reply(%s, %d); entry("switching/%d/%d");' % (clit(slot), kept, slot, kept))
    main.append("return 0; }")
    return ws.run("replies", prelude + "\n".join(main))


def gen_memory_log(ws, scenarios):
    """The real components/tdongle_runtime/memory.c, #included into the harness (so its static ring is visible), with heap stubs."""
    real = REPO / "components/tdongle_runtime/memory.c"
    prelude = COMMON + r"""
#include <stddef.h>
size_t g_free, g_min, g_largest;
int64_t g_timer_us;
#include "%s"
static void dump_state(void) {
    char line[256];
    snprintf(line, sizeof line, "count=%%u\n", tdongle_memory_count()); capture_write(line);
    for (unsigned i = 0; i < tdongle_memory_count(); i++) {
        tdongle_memory_record r = tdongle_memory_get(i);
        snprintf(line, sizeof line, "%%u %%u %%u %%u %%u %%u %%u\n", r.uptime_ms, r.operation, r.requested, r.free_bytes, r.minimum_bytes, r.largest_bytes, r.failed);
        capture_write(line);
    }
    tdongle_memory_record beyond = tdongle_memory_get(tdongle_memory_count());
    snprintf(line, sizeof line, "beyond %%u %%u\n", beyond.uptime_ms, beyond.failed); capture_write(line);
}
int main(void) {
    char line[64];
""" % real
    main = []
    for sc in scenarios:
        main.append("memset(entries, 0, sizeof entries); count = 0; next = 0;")
        for st in sc["steps"]:
            main.append("g_timer_us=(int64_t)%s*1000; g_free=%s; g_min=%s; g_largest=%s; { unsigned before=next; tdongle_memory_note(%s, %s, %s); snprintf(line, sizeof line, \"kept=%%d\\n\", next != before); capture_write(line); }" %
                        (clit(st["uptime_ms"]), clit(st["free_bytes"]), clit(st["minimum_bytes"]), clit(st["largest_bytes"]), clit(st["operation"]), clit(st["requested"]), clit(st["failed"])))
        main.append('dump_state(); entry("%s");' % sc["name"])
    main.append("return 0; }")
    return ws.run("memory_log", prelude + "\n".join(main))


def gen_strtol(ws, inputs_hex):
    """The real libc strtol/strtoul on every input (a 64 bit `long` on this Mac: the Rust test applies the 32 bit saturation)."""
    prelude = COMMON + r"""
static void unhex(char *dst, size_t cap, const char *hex) {
    size_t n = strlen(hex) / 2; if (n >= cap) { fputs("too long\n", stderr); exit(2); }
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(hex + 2 * i, "%2x", &v); dst[i] = (char)v; }
    dst[n] = 0;
}
static void one(const char *name, const char *hex) {
    char text[64]; unhex(text, sizeof text, hex);
    char *end; long v = strtol(text, &end, 10); size_t rest = strlen(end);
    char *end2; unsigned long u = strtoul(text, &end2, 10); size_t rest2 = strlen(end2);
    char line[256];
    snprintf(line, sizeof line, "%ld %zu %lu %zu\n", v, rest, u, rest2); capture_write(line); entry(name);
}
int main(void) {
"""
    main = ['one("%d", "%s");' % (i, h) for i, h in enumerate(inputs_hex)]
    main.append("return 0; }")
    return ws.run("strtol", prelude + "\n".join(main))


def gen_pm(ws, scenarios):
    control = control_text()
    pm_fn = extract_function(control, "static void pm_report(void)").replace("mgmt_write(", "capture_write(")
    prelude = COMMON + r"""
#include "tdongle_pm.h"
static tdongle_pm_status_t pm_v;
static const char *dump_v;
void tdongle_pm_status(tdongle_pm_status_t *out) { *out = pm_v; }
size_t tdongle_pm_dump_locks(char *buf, size_t size) {
    if (!dump_v) return 0;
    size_t n = strlen(dump_v); if (n >= size) n = size - 1;
    memcpy(buf, dump_v, n); buf[n] = 0; return n;
}
""" + pm_fn + "\nint main(void) {\n"
    main = []
    for sc in scenarios:
        p = sc["power"]
        main.append("{ memset(&pm_v,0,sizeof pm_v); pm_v.scaling=%s; pm_v.configure_error=%s; pm_v.max_mhz=%s; pm_v.min_mhz=%s; pm_v.cpu_mhz=%s; pm_v.lock_create_failures=%s;" %
                    tuple(clit(p[k]) for k in ("scaling", "configure_error", "max_mhz", "min_mhz", "cpu_mhz", "lock_create_failures")))
        assert len(sc["locks"]) <= 8
        main.append("pm_v.bursts=%d;" % len(sc["locks"]))
        for i, b in enumerate(sc["locks"]):
            main.append("pm_v.burst[%d]=(tdongle_pm_burst_stats_t){.name=%s,%s};" % (i, cstr(b["name"].encode()),
                        cinit(b, ["depth", "acquires", "releases", "held_us", "max_depth", "underflows", "forced_releases", "backend_failures", "isr_rejects"])))
        main.append("dump_v=%s;" % ("NULL" if sc["dump"] is None else cstr(sc["dump"].encode())))
        main.append('pm_report(); entry("%s"); }' % sc["name"])
    main.append("return 0; }")
    return ws.run("pm", prelude + "\n".join(main))


def bridge_fields():
    """Field names of each stats group, in the order the visitor reads them, from the E(...) lines."""
    src = (TAILNET / "bridge_status.inc").read_text()
    pairs = re.findall(r'E\("(\w+)",\s*"(\w+)",\s*([^;]+?)\);', src)
    groups = {"l2": [], "ring": [], "rx": [], "wifi_tx": []}
    pins = {"wifi_pins_installed": "installed", "wifi_pins_tx_done_ok": "tx_done_cb", "wifi_pins_tx_outstanding()": "inflight"}
    for _, _, expr in pairs:
        expr = expr.strip()
        m = re.fullmatch(r"w->(l2|ring|rx)\.(\w+)", expr)
        if m:
            if m.group(2) not in groups[m.group(1)]:
                groups[m.group(1)].append(m.group(2))
        elif expr in pins:
            groups["wifi_tx"].append(pins[expr])
        else:
            m = re.fullmatch(r"atomic_load\(&wifi_pins\.tx_(\w+)\)", expr)
            assert m, expr
            groups["wifi_tx"].append(m.group(1))
    return pairs, (groups["l2"], groups["ring"], groups["rx"], groups["wifi_tx"])


def gen_bridge(ws, scenarios, emit_scenarios):
    src = (TAILNET / "bridge_status.inc").read_text()
    real = src[: src.index("#ifdef GATEWAY_BRIDGE_TUNE")]
    prelude = COMMON + r"""
#include <stdatomic.h>
#include "tdongle_l2.h"
typedef uint32_t TickType_t; /* tinyusb_net.h names the FreeRTOS tick type */
#include "tinyusb_net.h"
static tdongle_l2_stats_t g_l2;
static tinyusb_net_tx_stats_t g_ring;
static tinyusb_net_rx_stats_t g_rx;
void tdongle_l2_stats(tdongle_l2_stats_t *out) { *out = g_l2; }
void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *out) { *out = g_ring; }
void tinyusb_net_rx_stats(tinyusb_net_rx_stats_t *out) { *out = g_rx; }
static volatile bool wifi_pins_installed, wifi_pins_tx_done_ok;
static struct { atomic_uint tx_charged, tx_done, tx_aborted, tx_flushed, tx_stale, tx_unmatched, tx_high_water, tx_refused_pool, tx_refused_heap; } wifi_pins;
static unsigned g_inflight;
static unsigned wifi_pins_tx_outstanding(void) { return g_inflight; }
void mgmt_write(const char *s) { capture_write(s); }
"""
    main = ["int main(void) {"]
    for sc in scenarios:
        main.append("{ memset(&g_l2,0,sizeof g_l2); memset(&g_ring,0,sizeof g_ring); memset(&g_rx,0,sizeof g_rx);")
        for f, v in sc["l2"].items():
            main.append("g_l2.%s=%s;" % (f, clit(v)))
        for f, v in sc["ring"].items():
            main.append("g_ring.%s=%s;" % (f, clit(v)))
        for f, v in sc["rx"].items():
            main.append("g_rx.%s=%s;" % (f, clit(v)))
        w = sc["wifi_tx"]
        main.append("wifi_pins_installed=%s; wifi_pins_tx_done_ok=%s; g_inflight=%s;" % (clit(w["installed"]), clit(w["tx_done_cb"]), clit(w["inflight"])))
        for f in ("charged", "done", "aborted", "flushed", "stale", "unmatched", "high_water", "refused_pool", "refused_heap"):
            main.append("atomic_store(&wifi_pins.tx_%s, %s);" % (f, clit(w[f])))
        main.append('bridge_status_lines(); entry("%s"); }' % sc["name"])
    main.append("return 0; }")
    status = ws.run("bridge_status", prelude + real + "\n" + "\n".join(main))
    prelude2 = COMMON + r"""
#include <stdatomic.h>
#include "tdongle_l2.h"
typedef uint32_t TickType_t; /* tinyusb_net.h names the FreeRTOS tick type */
#include "tinyusb_net.h"
void tdongle_l2_stats(tdongle_l2_stats_t *out) { memset(out, 0, sizeof *out); }
void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *out) { memset(out, 0, sizeof *out); }
void tinyusb_net_rx_stats(tinyusb_net_rx_stats_t *out) { memset(out, 0, sizeof *out); }
static volatile bool wifi_pins_installed, wifi_pins_tx_done_ok;
static struct { atomic_uint tx_charged, tx_done, tx_aborted, tx_flushed, tx_stale, tx_unmatched, tx_high_water, tx_refused_pool, tx_refused_heap; } wifi_pins;
static unsigned wifi_pins_tx_outstanding(void) { return 0; }
void mgmt_write(const char *s) { capture_write(s); }
"""
    main = ["int main(void) {"]
    for sc in emit_scenarios:
        main.append("{ bridge_line_ctx c = {.used = 0, .section = NULL};")
        for section, name, value in sc["seq"]:
            main.append("bridge_line_emit(&c, %s, %s, %s);" % (cstr(section.encode()), cstr(name.encode()), clit(value)))
        main.append('bridge_line_flush(&c); entry("%s"); }' % sc["name"])
    main.append("return 0; }")
    emit = ws.run("bridge_emit", prelude2 + real + "\n" + "\n".join(main))
    return status, emit


def gen_fixed_replies():
    """Every literal mgmt_write("...") (decoded), file by file, in source order."""
    out = bytearray()
    index = 0
    for fname in ("control.c", "serial_setup.inc", "console.c"):
        src = (TAILNET / fname).read_text()
        for m in re.finditer(r'mgmt_write\("((?:[^"\\]|\\.)*)"\)', src):
            body = c_decode(m.group(1))
            out += b"@@@@ SCENARIO %s:%d LEN %d @@@@\n" % (fname.replace(".", "_").encode(), index, len(body)) + body + b"\n@@@@ END @@@@\n"
            index += 1
    diag = (TAILNET / "memory_diagnostics.inc").read_text()
    m = re.search(r'mgmt_write\("(ERR memory guard takes[^"]*)"\)', diag)
    body = c_decode(m.group(1))
    out += b"@@@@ SCENARIO memory_diagnostics_inc:%d LEN %d @@@@\n" % (index, len(body)) + body + b"\n@@@@ END @@@@\n"
    return bytes(out)


def gen_constants(ws):
    lines = []
    clock = (TAILNET / "clock_sync.h").read_text()
    for name in ("GW_CLOCK_SERVERS", "GW_CLOCK_FIRST_RETRY_MS", "GW_CLOCK_MAX_RETRY_MS"):
        m = re.search(r"#define %s (\d+)u?" % name, clock)
        lines.append("%s=%s" % (name, m.group(1)))
    # every WIFI_LINK_* enumerator of the real header, evaluated by the compiler
    wl = (TAILNET / "wifi_link.h").read_text()
    names = sorted(n for n in set(re.findall(r"\b(WIFI_LINK_[A-Z0-9_]+)\b", wl)) if not n.endswith("_"))
    program = COMMON + '#include "wifi_link.h"\nint main(void) {\n' + "".join('printf("%s=%%d\\n", (int)%s);\n' % (n, n) for n in names) + "return 0; }\n"
    lines += ws.run("constants", program).decode().splitlines()
    bridge = (TAILNET / "bridge_status.inc").read_text()
    lines.append("BRIDGE_LINE_MAX=%s" % re.search(r"BRIDGE_LINE_MAX = (\d+)", bridge).group(1))
    console = (TAILNET / "console.c").read_text()
    lines.append("CONSOLE_LINE=%s" % re.search(r"static char line\[(\d+)\]", console).group(1))
    lines.append("MGMT_CHUNK_MAX=%d" % (int(re.search(r"char b\[(\d+)\] = \{0\}", console).group(1)) - 1))
    serial = (TAILNET / "serial_setup.inc").read_text()
    lines.append("STATUS_REPLY=%s" % re.search(r"__attribute__\(\(noinline\)\) static void serial_status\(void\)\{\n char reply\[(\d+)\]", serial).group(1))
    meta = (MAIN / "wifi_meta.h").read_text()
    lines.append("WIFI_META_SLOTS=%s" % re.search(r"WIFI_META_SLOTS = (\d+)", meta).group(1))
    temperature = (REPO / "components/tdongle_runtime/include/tdongle_temperature.h").read_text()
    lines.append("TDONGLE_TEMPERATURE_STEP_TENTHS=%s" % re.search(r"#define TDONGLE_TEMPERATURE_STEP_TENTHS (\d+)", temperature).group(1))
    return ("\n".join(lines) + "\n").encode()


def main():
    status_scenarios = make_status_scenarios()
    wifi_link_scenarios = make_wifi_link_scenarios()
    clock_scenarios, clock_states = make_clock_scenarios()
    list_scenarios = make_list_scenarios()
    display_scenarios = make_display_scenarios()
    scan_scenarios = make_scan_scenarios()
    pm_scenarios = make_pm_scenarios()
    memory_log_scenarios = make_memory_log_scenarios()
    strtol_inputs = make_strtol_inputs()
    pairs, fields = bridge_fields()
    bridge_scenarios = make_bridge_scenarios(fields)
    emit_scenarios = make_bridge_emit_scenarios()
    scenarios = dict(
        status=status_scenarios, wifi_link=wifi_link_scenarios, clock=clock_scenarios, clock_states=clock_states, list=list_scenarios,
        display=display_scenarios, scan=scan_scenarios, pm=pm_scenarios, memory_log=memory_log_scenarios, strtol=strtol_inputs, bridge=bridge_scenarios, bridge_emit=emit_scenarios,
        bridge_fields=dict(l2=fields[0], ring=fields[1], rx=fields[2], wifi_tx=fields[3]),
    )
    write_golden("scenarios.json", (json.dumps(scenarios, indent=1, sort_keys=True) + "\n").encode())
    with tempfile.TemporaryDirectory() as tmp:
        ws = Workspace(tmp)
        status = gen_status(ws, status_scenarios)
        write_golden("status.golden", status)
        write_golden("wifi_link.golden", gen_wifi_link(ws, wifi_link_scenarios))
        write_golden("clock.golden", gen_clock(ws, clock_scenarios, clock_states))
        write_golden("texts.golden", gen_texts(ws))
        write_golden("replies.golden", gen_replies(ws, list_scenarios, display_scenarios, scan_scenarios))
        write_golden("pm.golden", gen_pm(ws, pm_scenarios))
        write_golden("memory_log.golden", gen_memory_log(ws, memory_log_scenarios))
        write_golden("strtol.golden", gen_strtol(ws, strtol_inputs))
        bridge_status, bridge_emit = gen_bridge(ws, bridge_scenarios, emit_scenarios)
        write_golden("bridge_status.golden", bridge_status)
        write_golden("bridge_emit.golden", bridge_emit)
        write_golden("constants.golden", gen_constants(ws))
    write_golden("bridge_schema.golden", ("".join("%s %s\n" % (s, n) for s, n, _ in pairs)).encode())
    write_golden("fixed_replies.golden", gen_fixed_replies())
    
    longest = max(len(line) for _, body in entries((GOLDEN / "status.golden").read_bytes()) for line in body.split(b"\n"))
    print("status scenarios: %d (longest line %d bytes)" % (len(status_scenarios), longest))
    for name, body in entries((GOLDEN / "bridge_status.golden").read_bytes()):
        lines = body.split(b"\r\n")[:-1]
        print("bridge %-28s %d lines, longest %d bytes" % (name, len(lines), max((len(l) + 2 for l in lines), default=0)))
    print("golden files written to", GOLDEN)


if __name__ == "__main__":
    sys.exit(main())
