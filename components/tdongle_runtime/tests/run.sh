#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
for test in sensors mode_store; do
 cc -std=c11 -fsanitize=address,undefined -g -I stubs -I ../include "test_${test}.c" -lm -o "/tmp/tdongle-test-${test}"
 "/tmp/tdongle-test-${test}"
done
# Bridge forwarding (l2.c): every branch and counter, with a 1 ms tick and with the firmware's 10 ms tick (CONFIG_FREERTOS_HZ=100). The same code
# with the real USB ring, the real Wi-Fi budget and real threads is alternative/tailnet/tests/test_bridge_path.c (tools/test-gateway.sh).
for tick in 1 10; do
 cc -std=c11 -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all -g -DTEST_TICK_MS=$tick -I stubs -I ../include test_l2.c -o "/tmp/tdongle-test-l2-$tick"
 "/tmp/tdongle-test-l2-$tick"
done
# CoDel and ECN marking (portable C): the schedule against the analytic RFC 8289 reference, checksums recomputed from the bytes.
cc -std=c11 -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all -g -I ../include test_aqm.c -lm -o /tmp/tdongle-test-aqm
/tmp/tdongle-test-aqm
# PM burst counter: portable C, run under ASan/UBSan and TSan (its nesting depth is shared between tasks).
for san in address,undefined thread; do
 cc -std=c11 -Wall -Wextra -fsanitize=$san -fno-sanitize-recover=all -g -pthread -I ../include test_pm_burst.c -o "/tmp/tdongle-test-pm_burst-${san%%,*}"
 "/tmp/tdongle-test-pm_burst-${san%%,*}"
done
# wg_mgr stage accounting: portable atomics, ASan/UBSan and TSan; the release macros must compile to nothing.
for san in address,undefined thread; do
 cc -std=c11 -Wall -Wextra -fsanitize=$san -fno-sanitize-recover=all -g -pthread -I stubs -I ../include test_wgperf.c -o "/tmp/tdongle-test-wgperf-${san%%,*}"
 "/tmp/tdongle-test-wgperf-${san%%,*}"
done
cc -std=c11 -Wall -Wextra -Werror -DRELEASE_CHECK -I ../include test_wgperf.c -o /tmp/tdongle-test-wgperf-release && /tmp/tdongle-test-wgperf-release
cc -std=c11 -fsanitize=address,undefined -g -DCONFIG_TDONGLE_MEMORY_DIAGNOSTICS=1 -DCONFIG_TDONGLE_MEMORY_GUARD_FLOOR_BYTES=12288 -I stubs -I ../include test_memory_diagnostics.c -o /tmp/tdongle-test-memory_diagnostics
/tmp/tdongle-test-memory_diagnostics
printf '%s\n' 'Runtime: transparent bridge forwarding (filters, counted drops, queue, stale links, bounded retry), allocation failure cleanup, sensor recovery and bounded low-water records, owner ledger, phase capture and allocation-free recording passed.'
