#!/usr/bin/env bash
# Host benchmark of the WireGuard ChaCha20-Poly1305 (optimised vs legacy original).
# Relative host numbers only: the target is Xtensa LX7; the authoritative figures come
# from `crypto bench` on the board. Usage: tools/bench-wg-crypto.sh [-O2|-Os|-O3]
set -euo pipefail
cd "$(dirname "$0")/.."
OPT="${1:--O2}"
W=components/microlink/components/wireguard_lwip/src
mkdir -p build-host
cc -std=gnu11 "$OPT" -DCONFIG_WG_CRYPTO_BENCH_BASELINE=1 \
   -I "$W" -I "$W/crypto" -I "$W/crypto/refc" tests/bench_wg_crypto.c "$W/crypto/wg_crypto_bench.c" \
   "$W/crypto/refc/chacha20.c" "$W/crypto/refc/poly1305-donna.c" "$W/crypto/refc/chacha20poly1305.c" \
   "$W/crypto/legacy/wg_crypto_legacy.c" "$W/crypto.c" -o build-host/bench_wg_crypto
build-host/bench_wg_crypto
