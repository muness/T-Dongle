#!/usr/bin/env python3
"""Model of the NCM IN pipe (ring -> NTB -> USB full speed), to size the NTB and to read the board's counters.

The device can have ONE IN transfer on the bus at a time. When it completes, the TinyUSB task must run (ISR -> event
queue -> task) before the next NTB is handed to the controller; until then the host's polls are NAKed. So

    cycle  = bus time of one NTB  +  idle time before the next one starts
    rate   = datagrams per NTB / cycle

Bus time: 64 byte packets, 19 per 1 ms frame (1.216 MB/s), plus a zero-length packet when the NTB is a multiple of 64.
Idle time: the TinyUSB task's wake latency L after the completion; a host behind a transaction translator retries a NAKed
bulk IN on the next 1 ms frame, so the idle time is L rounded UP to whole frames (--no-quantise models a host that polls
continuously). NTB contents follow ncm_device.c: 12 B header + 16 B NDP header + 4 B per datagram entry (and a terminator),
each datagram padded to 4, at most CFG_TUD_NCM_IN_MAX_DATAGRAMS_PER_NTB = 8 datagrams, never past the NTB size.

Used two ways: `usb_drain_model.py` prints the table that sized the NTB (ADR 0022); `--check` asserts the properties the
design rests on (run by tools/test-gateway.sh). The board's usb.ntb_* / usb.gap_* counters give L and the mean NTB: feed them
back with `--from-counters`.
"""
import argparse
import math
import sys

PKT = 64
PKTS_PER_MS = 19
MAX_DATAGRAMS = 8
FIXED = 12 + 16 + 4          # NTH16 + NDP16 header + the NDP terminator entry; each datagram adds 4 more


def align4(n):
    return (n + 3) & ~3


def datagrams_per_ntb(size, frame):
    n = 0
    used = FIXED
    while n < MAX_DATAGRAMS and used + 4 + align4(frame) <= size:
        used += 4 + align4(frame)
        n += 1
    return n, used


def bus_ms(nbytes):
    packets = math.ceil(nbytes / PKT)
    if nbytes % PKT == 0:
        packets += 1          # the ZLP that ends the transfer
    return packets / PKTS_PER_MS


def idle_ms(latency_ms, quantise):
    if latency_ms <= 0:
        return 0.0
    return math.ceil(latency_ms) if quantise else latency_ms


def capacity(size, frame, latency_ms, quantise=True):
    """Saturated drain: (datagrams per NTB, Mbit/s of Ethernet frames)."""
    n, used = datagrams_per_ntb(size, frame)
    if n == 0:
        return 0, 0.0
    cycle = bus_ms(used) + idle_ms(latency_ms, quantise)
    return n, n * frame * 8 / cycle / 1000.0     # bits per ms -> kbit/s -> Mbit/s


SIZES = (3200, 3900, 4608, 5120, 6400)
LATENCIES = (0.0, 0.3, 1.0, 3.0, 6.0)


def table(frame, quantise):
    lines = ['frame %d B (%s), NTB size -> datagrams per NTB, saturated Mbit/s at TinyUSB-task wake latency L (ms)' %
             (frame, 'quantised to 1 ms frames' if quantise else 'continuous polling')]
    lines.append('%8s %4s ' % ('NTB', 'n') + ' '.join('L=%-4.1f' % l for l in LATENCIES))
    for size in SIZES:
        n, _ = capacity(size, frame, 0, quantise)
        lines.append('%8d %4d ' % (size, n) + ' '.join('%6.2f' % capacity(size, frame, l, quantise)[1] for l in LATENCIES))
    return lines


def from_counters(ntb_bytes, ntb_xfers, frame, gap_us_sum, gap_count):
    mean = ntb_bytes / ntb_xfers
    per = max(1.0, (mean - FIXED) / (frame + 4 + 4))
    gap = gap_us_sum / gap_count / 1000.0
    bus = bus_ms(mean)
    return mean, per, gap, bus, max(0.0, gap - bus)


def check():
    for quantise in (True, False):
        for frame in (60, 590, 1242, 1514):
            for size in SIZES:
                prev = None
                for l in LATENCIES:
                    n, rate = capacity(size, frame, l, quantise)
                    assert n >= 1 and rate > 0
                    assert prev is None or rate <= prev + 1e-9, 'throughput must not rise with latency'
                    prev = rate
            for l in LATENCIES:
                rates = [capacity(s, frame, l, quantise)[1] for s in SIZES]
                # a larger NTB may lose a hair to the ZLP when its size is a multiple of 64 (at zero latency), never more than 2 %
                assert all(b >= a * 0.98 for a, b in zip(rates, rates[1:])), 'a larger NTB must not drain slower'
    # The board's number: 2 datagrams of 1,242 B per 3,200 B NTB.
    assert datagrams_per_ntb(3200, 1242)[0] == 2
    assert datagrams_per_ntb(3200, 1514)[0] == 2
    assert datagrams_per_ntb(4608, 1514)[0] == 3 and datagrams_per_ntb(4608, 1242)[0] == 3
    assert datagrams_per_ntb(6400, 1242)[0] == 5 and datagrams_per_ntb(6400, 1514)[0] == 4
    assert datagrams_per_ntb(2 * 1522 + 64, 1514)[0] == 2           # the build-time floor of two frames per NTB
    # Free-running bus: at full speed one 1,242 B frame is 1.0 ms of bus time (the line rate is about 9 Mbit/s).
    n, rate = capacity(6400, 1242, 0.0, False)
    assert 8.5 < rate < 9.8, rate
    # The ADR's claim: with 2 frames per NTB a wake latency of a few ms caps the pipe near the measured 2.6 Mbit/s,
    # and a larger NTB with the latency removed is above the 6 Mbit/s offered.
    _, starved = capacity(3200, 1242, 6.0, True)
    _, fixed = capacity(4608, 1242, 0.3, True)
    assert 2.0 < starved < 3.0, starved
    assert fixed > 6.0, fixed
    # Counters round trip.
    mean, per, gap, bus, wake = from_counters((2 * 1250 + 40) * 100, 100, 1242, 7400 * 99, 99)
    assert abs(per - 2.0) < 0.1 and abs(gap - 7.4) < 1e-6 and wake > 4
    print('usb_drain_model: properties hold (monotone in latency and NTB size, 2 per 3,200 B, 2.6 Mbit/s at 6 ms wake)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--no-quantise', action='store_true')
    ap.add_argument('--from-counters', nargs=5, type=float, metavar=('NTB_BYTES', 'NTB_XFERS', 'FRAME', 'GAP_US_SUM', 'GAP_COUNT'))
    a = ap.parse_args()
    if a.check:
        check()
        return
    if a.from_counters:
        mean, per, gap, bus, wake = from_counters(*a.from_counters)
        print('mean NTB %.0f B = %.2f datagrams; mean completion gap %.2f ms; bus time of that NTB %.2f ms; '
              'wake latency implied %.2f ms' % (mean, per, gap, bus, wake))
        return
    for frame in (1242, 1514):
        print('\n'.join(table(frame, not a.no_quantise)))
        print()


if __name__ == '__main__':
    sys.exit(main())
