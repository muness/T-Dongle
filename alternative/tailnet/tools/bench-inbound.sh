#!/usr/bin/env bash
# Host micro-benchmark of the inbound path (ADR 0020): the datagram-at-a-time path against the run, on the real wireguardif.c and router.c.
# Relative structure (allocations, copies, lock takes, time inside the lock) carries to the board; the nanoseconds do not.
# Usage: tools/bench-inbound.sh [rounds]
set -euo pipefail
cd "$(dirname "$0")/.."
W=components/microlink/components/wireguard_lwip/src
mkdir -p build-host
cc -std=gnu11 -O2 -DWIREGUARD_CRYPTO_REFC=1 -w -I tests/host/wg_lwip -I tests/host_esp -I tests -I main -I components/microlink/include -I ../../components/tdongle_runtime/include \
   -I "$W" -I "$W/crypto" -I "$W/crypto/refc" tests/bench_inbound.c tests/host/wg_lwip/wg_host_lwip.c "$W/wireguard.c" "$W/wireguardif.c" "$W/wireguard_pool.c" "$W/crypto.c" \
   "$W/crypto/refc/blake2s.c" "$W/crypto/refc/chacha20.c" "$W/crypto/refc/chacha20poly1305.c" "$W/crypto/refc/poly1305-donna.c" "$W/crypto/refc/x25519.c" -o build-host/bench_inbound
build-host/bench_inbound "${1:-20000}"
