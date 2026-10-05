#!/usr/bin/env python3
"""R1 of membership-bytes.md: attribute live heap to callers from ESP-IDF heap_trace_dump output, and diff two dumps.

Build the diagnostics image with CONFIG_HEAP_TRACING_STANDALONE=y and CONFIG_HEAP_TRACING_STACK_DEPTH=6, call
heap_trace_start(HEAP_TRACE_LEAKS) at N=0 steady, heap_trace_dump() -> n0.txt; start the first membership, wait for
steady state, heap_trace_dump() -> n1.txt (leaks mode lists only blocks still live). Then

  python3 heap_trace_attribute.py --elf build/tdongle_tailnet.elf n1.txt            # live bytes by caller
  python3 heap_trace_attribute.py --elf build/tdongle_tailnet.elf --base n0.txt n1.txt   # growth by caller

Dump line format (esp-idf 5.5 components/heap/heap_trace_standalone.c):
  "  1024 bytes (@ 0x3fc9a2b0) allocated CPU 0 ccount 0x1ee8ab9c caller 0x42001234:0x42005678:..."
The allocation wrappers are skipped so the first frame that is application or library code names the owner."""
import argparse, collections, re, subprocess, sys

LINE = re.compile(r'\s*(\d+) bytes \(@ (0x[0-9a-fA-F]+)\).*?caller ([0-9a-fx:]+)')
WRAPPERS = ('heap_caps_', 'malloc', 'calloc', 'realloc', 'pvPortMalloc', '_malloc_r', '_calloc_r', 'mem_malloc',
            'mem_calloc', 'memp_malloc', 'tdongle_heap_tag', 'esp_mbedtls_mem', 'mbedtls_calloc', 'ml_psram_',
            'sys_mbox_new', 'sys_sem_new', 'xQueueGenericCreate', 'xEventGroupCreate', 'xTaskCreate')

def parse(path):
    blocks = []
    for line in open(path):
        m = LINE.match(line)
        if m: blocks.append((int(m[1]), [int(a, 16) for a in m[3].split(':') if a not in ('', '0x0')]))
    return blocks

def symbolise(elf, addresses):
    out = {}
    uniq = sorted(set(addresses))
    for i in range(0, len(uniq), 256):
        chunk = uniq[i:i + 256]
        res = subprocess.run(['xtensa-esp32s3-elf-addr2line', '-pfC', '-e', elf] + [hex(a) for a in chunk],
                             capture_output=True, text=True, check=True).stdout.splitlines()
        for a, text in zip(chunk, res): out[a] = re.sub(r'^(\S+) at ', r'\1 ', text).strip()
    return out

def owner(frames, names):
    for a in frames:
        n = names.get(a, '?')
        if not n.startswith(WRAPPERS) and '?' not in n.split()[0]: return n
    return names.get(frames[0], '?') if frames else '?'

def totals(blocks, names):
    t = collections.Counter(); c = collections.Counter()
    for size, frames in blocks:
        k = owner(frames, names); t[k] += size; c[k] += 1
    return t, c

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('dump'); ap.add_argument('--base'); ap.add_argument('--elf', required=True)
    ap.add_argument('--top', type=int, default=40); a = ap.parse_args()
    cur = parse(a.dump); base = parse(a.base) if a.base else []
    names = symbolise(a.elf, [f for _, fr in cur + base for f in fr])
    t1, c1 = totals(cur, names); t0, c0 = totals(base, names)
    keys = set(t1) | set(t0)
    rows = sorted(((t1[k] - t0[k], c1[k] - c0[k], k) for k in keys), reverse=True)
    print(f'{"bytes":>8} {"blocks":>6}  owner' + ('   (growth vs --base)' if a.base else ''))
    for d, n, k in rows[:a.top]: print(f'{d:8d} {n:6d}  {k}')
    print(f'{sum(r[0] for r in rows):8d} {sum(r[1] for r in rows):6d}  TOTAL')

if __name__ == '__main__': main()
