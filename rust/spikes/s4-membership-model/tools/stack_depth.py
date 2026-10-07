#!/usr/bin/env python3
"""Static worst-case stack depth from the linked Xtensa ELF (no board needed).

Method: disassemble, take each function's frame from its `entry aX, N` (windowed ABI: N includes the 16 B register-save area),
build the DIRECT call graph (call0/4/8/12), and report max over paths of sum(frame). Indirect calls (callx*) are NOT followed:
they are counted and listed per function, so the number is a lower bound whenever a path crosses one (dyn Cipher/Hash in snow,
the mbedtls hooks). Recursion is cut. Usage: stack_depth.py <elf> <regex-of-root-symbols>...
"""
import re, subprocess, sys, collections, os

elf = sys.argv[1]
SKIP = re.compile(os.environ.get('SKIP', r'^$'))
roots_re = [re.compile(r) for r in sys.argv[2:]]
objdump = os.path.expanduser("~/.rustup/toolchains/esp/xtensa-esp-elf/esp-15.2.0_20250920/xtensa-esp-elf/bin/xtensa-esp32s3-elf-objdump")
out = subprocess.run([objdump, "-d", "-C", "--no-show-raw-insn", elf], capture_output=True, text=True, check=True).stdout

lines = out.splitlines()
targets = set()
for line in lines:
    m0 = re.match(r"^\s*[0-9a-f]+:\s+(\S+)\s+(.*)$", line)
    if m0 and re.match(r"^(b|j$|j\.l|loop)", m0.group(1)):
        t = re.findall(r"\b([0-9a-f]{8})\b", m0.group(2))
        if t:
            targets.add(int(t[-1], 16))
NODEF = re.compile(r"^(s8i|s16i|s32i|s32ri|s32c1i|s32e|b|j|call|ret|nop|wsr|xsr|memw|dsync|isync|extw|entry|loop|waiti|rsync|esync|rsil|rfe|break|syscall|dhwb|dhi|dii|ihi|iii|ipf|dpf|l32e)")
frame = {}
calls = collections.defaultdict(set)
indirect = collections.Counter()
cur = None
regtgt = {}
addr2name = {}
fhdr = re.compile(r"^([0-9a-f]+) <(.+)>:$")
ins = re.compile(r"^\s*[0-9a-f]+:\s+(\S+)\s*(.*)$")
for line in lines:
    m = fhdr.match(line)
    if m:
        cur = m.group(2)
        regtgt.clear()
        addr2name[int(m.group(1), 16)] = cur
        frame.setdefault(cur, 0)
        continue
    if cur is None:
        continue
    m = ins.match(line)
    if not m:
        continue
    op, rest = m.group(1), m.group(2)
    a_addr = int(line.split(":")[0].strip(), 16)
    if a_addr in targets:
        regtgt.clear()
    if op in ("entry", "entry.n"):
        mm = re.search(r"a1,\s*(0x[0-9a-f]+|\d+)", rest)
        if mm:
            frame[cur] = int(mm.group(1), 0)
    elif op in ("call0", "call4", "call8", "call12"):
        mm = re.match(r"([0-9a-f]+)\s+<(.*)>$", rest.strip())
        if mm:
            t = re.sub(r"\+0x[0-9a-f]+$", "", mm.group(2))
            if t != cur:
                calls[cur].add(t)
    elif op == "l32r":
        mm = re.match(r"(a\d+),\s*[0-9a-f]+\s+<[^>]*>\s*\(([0-9a-f]+)\s+<(.*)>\)$", rest.strip())
        if mm:
            regtgt[mm.group(1)] = re.sub(r"\+0x[0-9a-f]+$", "", mm.group(3))
        else:
            mm2 = re.match(r"(a\d+),", rest.strip())
            if mm2:
                regtgt.pop(mm2.group(1), None)
    elif op in ("callx0", "callx4", "callx8", "callx12"):
        r = rest.strip()
        t = regtgt.get(r)
        if t and not t.startswith("."):
            calls[cur].add(t)
        else:
            indirect[cur] += 1
    if op != "l32r" and not NODEF.match(op):
        m1 = re.match(r"(a\d+)", rest.strip())
        if m1:
            regtgt.pop(m1.group(1), None)
    if op.startswith("call"):
        regtgt.clear()

sys.setrecursionlimit(100000)
memo = {}
def depth(f, stack=()):
    if f in memo:
        return memo[f]
    if f in stack:
        return (0, [f + " (recursion cut)"], 0)
    best = (0, [], 0)
    for c in calls.get(f, ()):
        if SKIP.search(c):
            continue
        d = depth(c, stack + (f,))
        if d[0] > best[0]:
            best = d
    ind = indirect.get(f, 0) + best[2]
    r = (frame.get(f, 0) + best[0], [f"{f} [{frame.get(f,0)}]"] + best[1], ind)
    memo[f] = r
    return r

for rr in roots_re:
    names = [n for n in frame if rr.search(n)]
    print(f"== {rr.pattern}: {len(names)} symbols")
    res = sorted(((depth(n), n) for n in names), key=lambda x: -x[0][0])[:3]
    for (d, path, ind), n in res:
        print(f"  {d:6d} B  (indirect calls on the path: {ind})  {n[:100]}")
        for p in (path if os.environ.get('FULL') else [q for q in path if int(q.rsplit('[',1)[1][:-1])>=512][:14]):
            print("        ", p[:120])
