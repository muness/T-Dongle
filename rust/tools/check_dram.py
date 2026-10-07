#!/usr/bin/env python3
"""DRAM budget of a built image, from its ELF: what the linker laid out, and the tailnet heap's own arithmetic.

Usage: check_dram.py ELF [--stack-min BYTES] [--objdump-prefix xtensa-esp32s3-elf-]

Prints the sections of the 341,760-byte DRAM (`0x3FC88000..0x3FCDB700`): the IRAM overlap (`.rwdata_dummy`: the Wi-Fi blobs' IRAM code and the vectors, DRAM that the
instruction RAM takes), `.data`, `.bss` (heap regions that live in it are listed separately), and the stack, which is what is left. Fails when the stack is under the
minimum, or a heap region does not sit where the build says (dram2, the data cache's 32 KB).
"""
import re
import subprocess
import sys

DRAM_START, DRAM_END = 0x3FC88000, 0x3FCDB700
DRAM2 = (0x3FCDB700, 0x3FCED710)
DCACHE = (0x3FCF0000, 0x3FCF8000)

elf = sys.argv[1]
stack_min = 0
prefix = 'xtensa-esp32s3-elf-'
a = sys.argv[2:]
while a:
    x = a.pop(0)
    if x == '--stack-min':
        stack_min = int(a.pop(0))
    elif x == '--objdump-prefix':
        prefix = a.pop(0)


def run(tool, *args):
    return subprocess.run([prefix + tool, *args], capture_output=True, text=True, check=True).stdout


sec = {}
for l in run('size', '-A', elf).splitlines():
    m = re.match(r'^(\.\S+)\s+(\d+)\s+(\d+)', l)
    if m:
        sec[m.group(1)] = (int(m.group(3)), int(m.group(2)))
syms = {}
for l in run('nm', elf).splitlines():
    p = l.split()
    if len(p) == 3:
        syms[p[2]] = int(p[0], 16)
heaps = []
for l in run('nm', '-S', '--size-sort', '-r', elf).splitlines():
    p = l.split()
    if len(p) == 4 and p[3].endswith('HEAP') and int(p[1], 16) >= 4096:
        heaps.append((int(p[0], 16), int(p[1], 16)))
total = DRAM_END - DRAM_START
overlap = sec.get('.rwdata_dummy', (0, 0))[1]
data = sec.get('.data', (0, 0))[1] + sec.get('.data.wifi', (0, 0))[1]
bss = sec.get('.bss', (0, 0))[1]
heap_in_dram = sum(n for a_, n in heaps if DRAM_START <= a_ < DRAM_END)
stack = syms['_stack_start'] - syms['_stack_end']
print(f'DRAM {total} B: IRAM overlap {overlap}, .data {data}, .bss {bss} (of which heap {heap_in_dram}), stack {stack}')
print(f'statics (without heap) {overlap + data + bss - heap_in_dram}; heap regions: ' + ', '.join(f'{n} @ {a_:#x}' for a_, n in sorted(heaps)))
assert overlap + data + bss + stack <= total + 8, 'sections overflow DRAM'
heap_total = sum(n for _, n in heaps)
print(f'heap in all {heap_total} (dram2 {sum(n for a_, n in heaps if DRAM2[0] <= a_ < DRAM2[1])}, data cache {sum(n for a_, n in heaps if DCACHE[0] <= a_ < DCACHE[1])}, regular {heap_in_dram})')
if stack < stack_min:
    print(f'FAIL: stack {stack} < {stack_min}')
    sys.exit(1)
print(f'ok: stack {stack} >= {stack_min}')
