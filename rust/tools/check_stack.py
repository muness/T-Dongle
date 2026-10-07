#!/usr/bin/env python3
"""Stack frames of the built image, from its disassembly (the xtensa backend has no -Z emit-stack-sizes): no function may need a frame over a limit.

Usage: check_stack.py ELF [--limit BYTES] [--top N] [--objdump PATH]

An Xtensa prologue is `entry a1, N` (N up to 32 KB in the instruction) and, for a larger frame, a further `sub aX, a1, aK` + `movsp a1, aX` (K loaded by
`movi` / `l32r`) or `addmi a1, a1, -N`. This reads those, so the figure is the whole frame (locals plus spills plus the outgoing-call area), not a guess. The async tasks' poll
functions are the ones that matter: a future's state is in .bss, but whatever a poll builds on the stack (a large value returned by a constructor) is here.
Exit status 1 if a frame is over the limit (default 12 KB: a stack of 40 KB must hold the deepest chain of such frames, and the executor's poll is one of
them).
"""
import re
import subprocess
import sys


def frames(elf, objdump):
    out = subprocess.run([objdump, '-d', '--no-show-raw-insn', elf], capture_output=True, text=True, check=True).stdout
    cur, lines, res = None, [], []

    def flush():
        if cur and lines:
            for i, l in enumerate(lines[:14]):
                m = re.search(r'\bentry\s+a1,\s*(\d+)', l)
                if not m:
                    continue
                size = int(m.group(1))
                regs = {}
                for l2 in lines[i + 1:i + 14]:
                    m2 = re.search(r'\bmovi(?:\.n)?\s+(a\d+),\s*(-?\d+)', l2)
                    if m2:
                        regs[m2.group(1)] = int(m2.group(2))
                    m2 = re.search(r'\bl32r\s+(a\d+),.*\(([0-9a-f]+)[ >]', l2)
                    if m2:
                        regs[m2.group(1)] = int(m2.group(2), 16)
                    m2 = re.search(r'\bsub\s+a1,\s*a1,\s*(a\d+)', l2)
                    if m2 and m2.group(1) in regs:
                        size += regs[m2.group(1)]
                        break
                    # the compiler's usual form for a big frame: `sub aX, a1, aK` then `movsp a1, aX`
                    m2 = re.search(r'\bsub\s+(a\d+),\s*a1,\s*(a\d+)', l2)
                    if m2 and m2.group(2) in regs:
                        size += regs[m2.group(2)]
                        break
                    m2 = re.search(r'\baddmi\s+a1,\s*a1,\s*(-?\d+)', l2)
                    if m2:
                        size += -int(m2.group(1))
                        break
                    m2 = re.search(r'\baddi\s+a1,\s*a1,\s*(-\d+)', l2)
                    if m2:
                        size += -int(m2.group(1))
                        break
                res.append((size, cur))
                break

    for l in out.splitlines():
        m = re.match(r'^[0-9a-f]+ <(.+)>:$', l)
        if m:
            flush()
            cur, lines = m.group(1), []
        elif cur:
            lines.append(l)
    flush()
    return res


def short(s):
    return re.sub(r'_R[A-Za-z0-9_]*?(tdongle_[a-z_0-9]+)', r'\1::', s)[:120]


def main():
    args = sys.argv[1:]
    elf = args.pop(0)
    limit, top, objdump = 12 * 1024, 15, 'xtensa-esp32s3-elf-objdump'
    while args:
        a = args.pop(0)
        if a == '--limit':
            limit = int(args.pop(0))
        elif a == '--top':
            top = int(args.pop(0))
        elif a == '--objdump':
            objdump = args.pop(0)
    rows = sorted(frames(elf, objdump), reverse=True)
    print(f'{len(rows)} functions with a frame; largest {top}:')
    for n, s in rows[:top]:
        print(f'  {n:>7}  {short(s)}')
    over = [r for r in rows if r[0] > limit]
    if over:
        print(f'FAIL: {len(over)} function(s) with a frame over {limit} bytes')
        sys.exit(1)
    print(f'ok: no frame over {limit} bytes')


main()
