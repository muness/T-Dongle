#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
for test in l2 sensors mode_store; do
 cc -std=c11 -fsanitize=address,undefined -g -I stubs -I ../include "test_${test}.c" -lm -o "/tmp/tdongle-test-${test}"
 "/tmp/tdongle-test-${test}"
done
cc -std=c11 -fsanitize=address,undefined -g -DCONFIG_TDONGLE_MEMORY_DIAGNOSTICS=1 -DCONFIG_TDONGLE_MEMORY_GUARD_FLOOR_BYTES=12288 -I stubs -I ../include test_memory_diagnostics.c -o /tmp/tdongle-test-memory_diagnostics
/tmp/tdongle-test-memory_diagnostics
printf '%s\n' 'Runtime: transparent frames, backpressure, stale link epochs, allocation failure cleanup, sensor recovery and bounded low-water records, owner ledger, phase capture and allocation-free recording passed.'
