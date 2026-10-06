#!/usr/bin/env python3
"""Worst-case stack of the gateway_control task, from the compiled frame sizes, and a margin the build enforces.

The control task (control.c command_task, a static 4,096 B stack) runs every serial command, the button menu's commands and the whole front panel
poll (device_ui.inc), and sits above printf. A board run measured 76 B free once, so the margin is a build error now, not a hope.

Method: recompile the control task's translation units with -fcallgraph-info=su (the same flags as the build), merge the call graphs, and take the
deepest path from command_task, adding each function's static frame. Functions without a frame (libc, ESP-IDF drivers) cost the table below, measured
from the linked ELF (xtensa objdump `entry`) where noted, otherwise a deliberately high default. Indirect calls are followed by the table EDGES.

Usage: check-control-stack.py BUILD_DIR   Fails when the worst path leaves less than MARGIN of STACK."""
import json, re, shlex, subprocess, sys, tempfile
from pathlib import Path

STACK = 4096
MARGIN = 1024
ROOT = 'command_task'
UNITS = ('control.c', 'gateway_main.c', 'lcd.c', 'lcd_view.c', 'console.c', 'menu.c', 'led.c', 'traffic.c', 'wifi_meta.c', 'ui_settings.c', 'setup_boot.c', 'health.c')
DEFAULT_EXTERNAL = 256
# vsnprintf 64 + _vsnprintf_r 144 + _svfprintf_r 800 + __ssprint_r 48 = 1,056 (ELF, 2026-10-06); nvs_* frames are 32 to 48 but call into the NVS storage (estimate 600);
# esp_lcd + SPI master queue/poll (estimate 700); FreeRTOS queue calls 200.
EXTERNAL = {'snprintf': 1056, 'vsnprintf': 1056, 'sprintf': 1056, 'printf': 1056, 'nvs_set_blob': 600, 'nvs_get_blob': 600, 'nvs_commit': 600, 'nvs_erase_key': 600,
            'nvs_erase_all': 600, 'nvs_open': 600, 'nvs_close': 200, 'esp_lcd_panel_draw_bitmap': 700, 'esp_lcd_panel_mirror': 700, 'xQueueGenericSend': 200,
            'xQueueReceive': 200, 'xQueueGenericReceive': 200, 'xTaskCreate': 400, 'esp_restart': 300, 'ledc_set_duty': 200, 'ledc_update_duty': 200,
            'tinyusb_cdcacm_write_queue': 300, 'tinyusb_cdcacm_write_flush': 300, 'esp_wifi_scan_start': 600, 'esp_wifi_scan_get_ap_record': 300,
            'wg_crypto_bench_run': 1200, 'strlcpy': 64, 'memcpy': 32, 'memset': 32, 'strlen': 32, 'strcmp': 32, 'strncmp': 32, 'strtol': 200, 'malloc': 300, 'free': 200,
            'calloc': 300, 'heap_caps_malloc': 300}
EDGES = {'boot_sink': ['mgmt_write']}   # function-pointer sinks
build = Path(sys.argv[1])
# The diagnostics image adds its own evidence commands (memory, wifistats: a 512 B line buffer plus printf), which are not shipped: it only has to stay clear.
if 'diagnostics' in build.name: MARGIN = 128
commands = {Path(c['file']).name: c for c in json.load(open(build / 'compile_commands.json')) if '/tailnet/main/' in c['file'] or '/IDF_PROJECT/main/' in c['file'] or c['file'].count('/main/') and not c['file'].endswith('esp32s3.c')}
frame, calls = {}, {}
with tempfile.TemporaryDirectory() as tmp:
    for unit in UNITS:
        entry = commands[unit]
        cmd = shlex.split(entry['command'])
        out = cmd.index('-o')
        cmd[out + 1] = f'{tmp}/{unit}.o'
        run = subprocess.run(cmd + ['-fcallgraph-info=su'], cwd=entry['directory'], capture_output=True, text=True)
        if run.returncode: sys.exit(f'{unit} did not compile for the stack analysis:\n{run.stderr[-1500:]}')
        text = Path(f'{tmp}/{unit}.ci').read_text()
        for m in re.finditer(r'node: \{ title: "([^"]*)" label: "([^"]*)"', text):
            title = m.group(1).split(':')[-1]
            size = re.search(r'(\d+) bytes \(static\)', m.group(2))
            if size: frame[title] = int(size.group(1))
        for m in re.finditer(r'edge: \{ sourcename: "([^"]*)" targetname: "([^"]*)"', text):
            calls.setdefault(m.group(1).split(':')[-1], set()).add(m.group(2).split(':')[-1])
for k, v in EDGES.items(): calls.setdefault(k, set()).update(v)
sys.setrecursionlimit(10000)
cache = {}
def depth(name, stack=()):
    if name in cache: return cache[name]
    if name in stack: return (0, [])   # recursion: none in this task
    own = frame.get(name, EXTERNAL.get(name, DEFAULT_EXTERNAL if name not in frame else 0))
    best = (0, [])
    for callee in calls.get(name, ()):
        got = depth(callee, stack + (name,))
        if got[0] > best[0]: best = got
    result = (own + best[0], [f'{name}={own}'] + best[1])
    cache[name] = result
    return result
total, path = depth(ROOT)
# interrupt/task-switch context saved on the task stack by FreeRTOS on Xtensa
# Calibration: the same analysis of the build that a board run measured at 76 B free (command_task 1,264 + gateway_serial_command 1,136 + printf 1,056 + 400)
# predicted about 240 B free, so the model is about 170 B optimistic: 256 B is added on top of the context.
OVERHEAD = 400 + 256
need = total + OVERHEAD
print(f'gateway_control worst path: {total} B + {OVERHEAD} B context and calibration = {need} B of {STACK} B (margin {STACK - need} B, required {MARGIN} B)')
print('  ' + ' > '.join(path))
if STACK - need < MARGIN:
    sys.exit(f'The control task stack margin {STACK - need} B is below {MARGIN} B: shrink a frame on the path above, or move a buffer off the stack')
