#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
for test in l2 sensors mode_store; do
 cc -std=c11 -fsanitize=address,undefined -g -I stubs -I ../include "test_${test}.c" -lm -o "/tmp/tdongle-test-${test}"
 "/tmp/tdongle-test-${test}"
done
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
printf '%s\n' 'Runtime: transparent frames, backpressure, stale link epochs, allocation failure cleanup, sensor recovery and bounded low-water records, owner ledger, phase capture and allocation-free recording passed.'
