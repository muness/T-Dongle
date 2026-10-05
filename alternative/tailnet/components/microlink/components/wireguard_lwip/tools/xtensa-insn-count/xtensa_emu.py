#!/usr/bin/env python3
"""Minimal Xtensa LX7 (windowed ABI) instruction-set emulator that counts executed instructions.

Purpose: measure the *compiled* ESP32-S3 code (exact compiler, flags and source) without
hardware, and check that it computes the right answer. It decodes the text of
`xtensa-esp-elf-objdump -d` for a linked ELF, so it supports only the opcodes GCC emits for
the crypto code (see OPS); an unknown opcode is a hard error rather than a silent miscount.

Cycle estimate (documented assumptions, not a hardware measurement):
    cycles ~= instructions + LOAD_USE * (load whose result is used by the next instruction)
                           + MUL_USE  * (mull/muluh result used by the next instruction)
                           + BR_TAKEN * (taken conditional branch / jump)
Hardware `loop` instructions cost nothing. Instruction fetch is assumed to hit the cache.
"""
import re
import subprocess
import sys
from collections import Counter

import os
TRACE = bool(os.environ.get('XEMU_TRACE'))
M32 = 0xFFFFFFFF
LOAD_USE, MUL_USE, BR_TAKEN = 1, 1, 2
CODE_LIMIT = 0x40000000


def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


class Emu:
    def __init__(self, elf, objdump, nm, objcopy, flat=None):
        self.mem = bytearray(0x100000)
        self.sym = {}
        self.syms_sorted = []
        for line in subprocess.check_output([nm, '-n', elf], text=True).splitlines():
            p = line.split()
            if len(p) == 3:
                self.sym[p[2]] = int(p[0], 16)
                self.syms_sorted.append((int(p[0], 16), p[2], p[1]))
        # Load every allocated section of the ELF at its link address.
        sec = subprocess.check_output([objdump, '-h', elf], text=True).splitlines()
        for i, line in enumerate(sec):
            m = re.match(r'\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
            if m and 'ALLOC' in sec[i + 1] and 'CONTENTS' in sec[i + 1]:
                name, size, vma = m.group(1), int(m.group(2), 16), int(m.group(3), 16)
                import tempfile
                with tempfile.NamedTemporaryFile() as tf:
                    subprocess.check_call([objcopy, '-O', 'binary', '--only-section=' + name, elf, tf.name])
                    out = open(tf.name, 'rb').read()
                self.mem[vma:vma + len(out)] = out
        self.insn = {}
        txt = subprocess.check_output([objdump, '-d', elf], text=True)
        for line in txt.splitlines():
            m = re.match(r'\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(\S+)\s*(.*)$', line)
            if m and not m.group(3).startswith('.'):
                addr = int(m.group(1), 16)
                nbytes = len(m.group(2).replace(' ', '')) // 2
                ops = re.sub(r'\s*<[^>]*>', '', m.group(4)).split(';')[0].strip()
                ops = re.sub(r'\s*\([^)]*\)\s*$', '', ops)
                self.insn[addr] = (m.group(3), [o.strip() for o in ops.split(',')] if ops else [], nbytes)

    def func_of(self, addr):
        best = None
        for a, n, t in self.syms_sorted:
            if a <= addr and t.lower() in ('t', 'w'):
                best = n
            elif a > addr:
                break
        return best

    # ---- memory helpers
    def ld(self, a, n):
        return int.from_bytes(self.mem[a:a + n], 'little')

    def st(self, a, v, n):
        self.mem[a:a + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')

    def run(self, func, args=(), max_steps=50_000_000):
        """Run `func` (windowed ABI, args in a2..) to completion; return (a2, stats)."""
        ar = [0] * 64
        wb = 0
        sar = 0
        callinc = 1
        lbeg = lend = lcount = 0
        sentinel = 0x1000
        sp = 0xF0000
        reg = lambda i: (wb * 4 + i) % 64
        R = lambda i: ar[reg(i)]

        def W(i, v):
            ar[reg(i)] = v & M32

        # Behave like a caller in window 0 that executed call4: callee's a0 is the caller's a4.
        W(1, sp)
        W(4, sentinel | (1 << 30))
        for i, a in enumerate(args):
            W(6 + i, a)
        callinc = 1
        pc = self.sym[func]
        stats = Counter()
        l8f = Counter()
        per_func = Counter()
        per_func_cyc = Counter()
        cycles = 0
        prev_load = prev_mul = None  # dest register index written by the previous insn
        n = 0
        while True:
            if pc == sentinel:
                break
            if pc not in self.insn:
                raise RuntimeError('pc %#x not an instruction (in %s)' % (pc, self.func_of(pc)))
            op, o, ln = self.insn[pc]
            n += 1
            if n > max_steps:
                raise RuntimeError('step limit')
            stats[op] += 1
            if op == 'l8ui': l8f[self.func_of(pc)] += 1
            if TRACE:
                print('%6x %-8s %-28s a2=%x a3=%x a4=%x a8=%x sp=%x wb=%d' % (pc, op, ','.join(o), R(2), R(3), R(4), R(8), R(1), wb))
            per_func[self.func_of(pc)] += 1
            nxt = pc + ln
            cyc = 1
            srcs = ()

            def rr(x):
                return int(x[1:])

            def imm(x):
                return int(x, 0)

            taken = False
            wrote = None
            kind = None
            if op in ('add', 'add.n'):
                W(rr(o[0]), R(rr(o[1])) + R(rr(o[2]))); srcs = (o[1], o[2]); wrote = o[0]
            elif op in ('sub',):
                W(rr(o[0]), R(rr(o[1])) - R(rr(o[2]))); srcs = (o[1], o[2]); wrote = o[0]
            elif op == 'addx4':
                W(rr(o[0]), (R(rr(o[1])) << 2) + R(rr(o[2]))); srcs = (o[1], o[2]); wrote = o[0]
            elif op in ('addi', 'addi.n'):
                W(rr(o[0]), R(rr(o[1])) + imm(o[2])); srcs = (o[1],); wrote = o[0]
            elif op == 'neg':
                W(rr(o[0]), -R(rr(o[1]))); srcs = (o[1],); wrote = o[0]
            elif op in ('and', 'or', 'xor'):
                a, b = R(rr(o[1])), R(rr(o[2]))
                W(rr(o[0]), a & b if op == 'and' else a | b if op == 'or' else a ^ b); srcs = (o[1], o[2]); wrote = o[0]
            elif op == 'slli':
                W(rr(o[0]), R(rr(o[1])) << imm(o[2])); srcs = (o[1],); wrote = o[0]
            elif op == 'srli':
                W(rr(o[0]), R(rr(o[1])) >> imm(o[2])); srcs = (o[1],); wrote = o[0]
            elif op == 'srai':
                W(rr(o[0]), s32(R(rr(o[1]))) >> imm(o[2])); srcs = (o[1],); wrote = o[0]
            elif op == 'extui':
                W(rr(o[0]), (R(rr(o[1])) >> imm(o[2])) & ((1 << imm(o[3])) - 1)); srcs = (o[1],); wrote = o[0]
            elif op == 'ssai':
                sar = imm(o[0]) & 31
            elif op == 'ssa8l':
                sar = 8 * (R(rr(o[0])) & 3); srcs = (o[0],)
            elif op == 'ssa8b':
                sar = 32 - 8 * (R(rr(o[0])) & 3); srcs = (o[0],)
            elif op == 'ssr':
                sar = R(rr(o[0])) & 31; srcs = (o[0],)
            elif op == 'ssl':
                sar = 32 - (R(rr(o[0])) & 31); srcs = (o[0],)
            elif op == 'srl':
                W(rr(o[0]), R(rr(o[1])) >> sar); srcs = (o[1],); wrote = o[0]
            elif op == 'sra':
                W(rr(o[0]), s32(R(rr(o[1]))) >> sar); srcs = (o[1],); wrote = o[0]
            elif op == 'sll':
                W(rr(o[0]), R(rr(o[1])) << (32 - sar)); srcs = (o[1],); wrote = o[0]
            elif op == 'src':
                v = (R(rr(o[1])) << 32) | R(rr(o[2]))
                W(rr(o[0]), (v >> sar) & M32); srcs = (o[1], o[2]); wrote = o[0]
            elif op == 'nsau':
                v = R(rr(o[1])); W(rr(o[0]), 32 - v.bit_length()); srcs = (o[1],); wrote = o[0]
            elif op == 'minu':
                W(rr(o[0]), min(R(rr(o[1])), R(rr(o[2])))); srcs = (o[1], o[2]); wrote = o[0]
            elif op == 'max':
                W(rr(o[0]), max(s32(R(rr(o[1]))), s32(R(rr(o[2]))))); srcs = (o[1], o[2]); wrote = o[0]
            elif op in ('salt', 'saltu'):
                a, b = R(rr(o[1])), R(rr(o[2]))
                W(rr(o[0]), 1 if ((s32(a) < s32(b)) if op == 'salt' else (a < b)) else 0)
                srcs = (o[1], o[2]); wrote = o[0]
            elif op in ('moveqz', 'movnez', 'movltz', 'movgez'):
                c = s32(R(rr(o[2])))
                if {'moveqz': c == 0, 'movnez': c != 0, 'movltz': c < 0, 'movgez': c >= 0}[op]:
                    W(rr(o[0]), R(rr(o[1])))
                srcs = (o[1], o[2], o[0]); wrote = o[0]
            elif op in ('mov.n',):
                W(rr(o[0]), R(rr(o[1]))); srcs = (o[1],); wrote = o[0]
            elif op in ('movi', 'movi.n'):
                W(rr(o[0]), imm(o[1])); wrote = o[0]
            elif op == 'mull':
                W(rr(o[0]), R(rr(o[1])) * R(rr(o[2]))); srcs = (o[1], o[2]); wrote = o[0]; kind = 'mul'
            elif op == 'muluh':
                W(rr(o[0]), (R(rr(o[1])) * R(rr(o[2]))) >> 32); srcs = (o[1], o[2]); wrote = o[0]; kind = 'mul'
            elif op in ('l32i', 'l32i.n', 'l8ui', 'l16ui'):
                m = re.match(r'(a\d+),\s*(a\d+),\s*(-?\w+)', ', '.join(o))
                size = 4 if op.startswith('l32') else 1 if op == 'l8ui' else 2
                a = (R(rr(m.group(2))) + imm(m.group(3))) & M32
                W(rr(o[0]), self.ld(a, size)); srcs = (o[1],); wrote = o[0]; kind = 'load'
            elif op == 'l32r':
                W(rr(o[0]), self.ld(imm('0x' + o[1]), 4)); wrote = o[0]; kind = 'load'
            elif op in ('s32i', 's32i.n', 's8i', 's16i'):
                size = 4 if op.startswith('s32') else 1 if op == 's8i' else 2
                a = (R(rr(o[1])) + imm(o[2])) & M32
                self.st(a, R(rr(o[0])), size); srcs = (o[0], o[1])
            elif op in ('beqz', 'beqz.n', 'bnez', 'bnez.n', 'bltz', 'bgez'):
                v = s32(R(rr(o[0]))); srcs = (o[0],)
                t = {'beqz': v == 0, 'beqz.n': v == 0, 'bnez': v != 0, 'bnez.n': v != 0, 'bltz': v < 0, 'bgez': v >= 0}[op]
                if t:
                    nxt = int(o[1], 16); taken = True
            elif op in ('beq', 'bne', 'bgeu', 'bltu', 'bge', 'blt'):
                a, b = R(rr(o[0])), R(rr(o[1])); srcs = (o[0], o[1])
                t = {'beq': a == b, 'bne': a != b, 'bgeu': a >= b, 'bltu': a < b, 'bge': s32(a) >= s32(b), 'blt': s32(a) < s32(b)}[op]
                if t:
                    nxt = int(o[2], 16); taken = True
            elif op in ('beqi', 'bnei', 'bgeui', 'bltui', 'bgei', 'blti'):
                a, b = R(rr(o[0])), imm(o[1]); srcs = (o[0],)
                t = {'beqi': a == b, 'bnei': a != b, 'bgeui': a >= b, 'bltui': a < b, 'bgei': s32(a) >= b, 'blti': s32(a) < b}[op]
                if t:
                    nxt = int(o[2], 16); taken = True
            elif op in ('bbci', 'bbsi'):
                bit = (R(rr(o[0])) >> imm(o[1])) & 1; srcs = (o[0],)
                if bit == (1 if op == 'bbsi' else 0):
                    nxt = int(o[2], 16); taken = True
            elif op == 'j':
                nxt = int(o[0], 16); taken = True
            elif op == 'loop':
                lcount = R(rr(o[0])) - 1; lbeg = nxt; lend = int(o[1], 16); cyc = 1
            elif op in ('nop', 'nop.n', 'excw', 'memw', 'isync', 'dsync', 'extw'):
                pass
            elif op == 'entry':
                old_sp = R(1)
                wb = (wb + callinc) % 16
                W(1, old_sp - imm(o[1]))
            elif op in ('retw', 'retw.n'):
                a0 = R(0)
                ci = (a0 >> 30) & 3
                pc = a0 & 0x3FFFFFFF
                wb = (wb - ci) % 16
                cycles += cyc + BR_TAKEN
                prev_load = prev_mul = None
                continue
            elif op in ('call8', 'callx8'):
                tgt = int(o[0], 16) if op == 'call8' else R(rr(o[0]))
                ar[reg(8)] = (nxt & 0x3FFFFFFF) | (2 << 30)
                callinc = 2
                nxt = tgt; taken = True
            elif op in ('call4', 'callx4'):
                tgt = int(o[0], 16) if op == 'call4' else R(rr(o[0]))
                ar[reg(4)] = (nxt & 0x3FFFFFFF) | (1 << 30)
                callinc = 1
                nxt = tgt; taken = True
            elif op == 'call12' or op == 'callx12':
                tgt = int(o[0], 16) if op == 'call12' else R(rr(o[0]))
                ar[reg(12)] = (nxt & 0x3FFFFFFF) | (3 << 30)
                callinc = 3
                nxt = tgt; taken = True
            else:
                raise RuntimeError('unsupported opcode %s %s at %#x (%s)' % (op, o, pc, self.func_of(pc)))
            # hazards
            if prev_load and prev_load in srcs:
                cyc += LOAD_USE
            if prev_mul and prev_mul in srcs:
                cyc += MUL_USE
            if taken:
                cyc += BR_TAKEN
            prev_load = wrote if kind == 'load' else None
            prev_mul = wrote if kind == 'mul' else None
            cycles += cyc
            per_func_cyc[self.func_of(pc)] += cyc
            # zero-overhead hardware loop
            if lend and nxt == lend and op not in ('j',) and not taken:
                if lcount > 0:
                    lcount -= 1
                    nxt = lbeg
            pc = nxt
        return R(6), dict(instructions=n, cycles_est=cycles, by_op=stats, by_func=per_func, by_func_cyc=per_func_cyc, l8f=l8f)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('elf')
    ap.add_argument('--prefix', default='xtensa-esp-elf-')
    ap.add_argument('--len', type=int, default=1400)
    ap.add_argument('--off', type=int, default=0)
    ap.add_argument('--refgen', required=True, help='path of the host refgen binary')
    ap.add_argument('--phases', default='phase_chacha20,phase_poly1305,phase_seal,phase_open')
    a = ap.parse_args()
    e = Emu(a.elf, a.prefix + 'objdump', a.prefix + 'nm', a.prefix + 'objcopy')
    ref = dict(l.split('=') for l in subprocess.check_output([a.refgen, str(a.len), str(a.off)], text=True).split())
    for ph in a.phases.split(','):
        # re-load pristine memory image per phase
        e2 = Emu(a.elf, a.prefix + 'objdump', a.prefix + 'nm', a.prefix + 'objcopy') if ph != a.phases.split(',')[0] else e
        S = e2.sym
        e2.mem[S['g_key']:S['g_key'] + 32] = bytes.fromhex(ref['key'])
        e2.mem[S['g_in']:S['g_in'] + 1424] = bytes.fromhex(ref['in'])
        e2.st(S['g_len'], a.len, 4)
        e2.st(S['g_off'], a.off, 4)
        if ph == 'phase_open':
            e2.mem[S['g_ref']:S['g_ref'] + 1424] = bytes.fromhex(ref['sealed'])
        elif ph == 'phase_seal':
            e2.mem[S['g_ref']:S['g_ref'] + 1424] = bytes.fromhex(ref['sealed'])
        else:
            e2.mem[S['g_ref']:S['g_ref'] + 1424] = bytes.fromhex(ref['chacha'])
        e2.mem[S['g_tag']:S['g_tag'] + 16] = bytes.fromhex(ref['tag'])
        e2.st(S['result'], 0xFFFFFFFF, 4)
        _, st = e2.run(ph)
        res = e2.ld(S['result'], 4)
        harness = lambda f: f is None or f.startswith('phase_') or f in ('same', 'memcpy', 'memset', 'memcmp')
        lib_i = sum(v for f, v in st['by_func'].items() if not harness(f))
        lib_c = sum(v for f, v in st['by_func_cyc'].items() if not harness(f))
        top = ', '.join('%s=%d' % kv for kv in st['by_func'].most_common(5) if not harness(kv[0]))
        print('%-9s len=%4d off=%d %s lib_insn=%7d (%6.2f/B) lib_cyc_est=%7d (%6.2f/B)  [%s]' % (
            ph[6:], a.len, a.off, 'OK  ' if res == 0 else 'FAIL(%d)' % res, lib_i,
            lib_i / a.len, lib_c, lib_c / a.len, top))
        if os.environ.get('XEMU_MIX'):
            print('   mix:', dict(st['by_op'].most_common(14)), 'l8ui by func', dict(st['l8f']))
        if res != 0:
            print('  got   ', bytes(e2.mem[S['g_out']:S['g_out'] + 16]).hex(), '\n  want  ', bytes(e2.mem[S['g_tag']:S['g_tag'] + 16]).hex())
            sys.exit(1)


if __name__ == '__main__':
    main()
