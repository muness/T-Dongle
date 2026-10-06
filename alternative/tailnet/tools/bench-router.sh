#!/usr/bin/env bash
# Host micro-benchmark of the router hot path: old (tests/reference/router_v1.c) vs new (main/router.c).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build-host
F="-std=gnu11 -O2 -I tests -I main -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter"
cc $F -DIMPL_OLD -c tests/router_impl.c -o build-host/bench_old.o
cc $F -DIMPL_NEW -c tests/router_impl.c -o build-host/bench_new.o
cc $F tests/bench_router.c build-host/bench_old.o build-host/bench_new.o -o build-host/bench_router
build-host/bench_router
