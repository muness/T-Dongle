#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
for test in l2 sensors mode_store; do
 cc -std=c11 -fsanitize=address,undefined -g -I stubs -I ../include "test_${test}.c" -lm -o "/tmp/tdongle-test-${test}"
 "/tmp/tdongle-test-${test}"
done
printf '%s\n' 'Runtime: transparent frames, backpressure, stale link epochs, allocation failure cleanup, sensor recovery and bounded low-water records passed.'
