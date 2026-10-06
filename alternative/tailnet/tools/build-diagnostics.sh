#!/usr/bin/env bash
# Build the memory-diagnostics image (never a release): owner-tagged heap, per-phase join capture,
# admission override and the serial "memory" / "members" commands. See docs/memory-diagnostics.md.
#   tools/build-diagnostics.sh [--queue-depth 1|2|4|8|12|16]   # depth overrides DERP TX / DISCO RX / WG RX (STUN RX <= 4)
# Output: <repo>/build-diagnostics[-q<N>]/ ; the flash command is printed by idf.py.
set -euo pipefail
cd "$(dirname "$0")/../../.."
: "${IDF_PATH:?Source pinned ESP-IDF v5.5.5 (. ~/.cache/tdongle/esp-idf-v5.5.5/export.sh)}"
[[ "$(git -C "$IDF_PATH" rev-parse HEAD)" == b774170ff46c393eeb5e495ea37936038d3f4f4f ]] || { echo 'Wrong ESP-IDF commit' >&2; exit 1; }
depth=0
if [[ "${1:-}" == --queue-depth ]]; then
 depth="${2:?--queue-depth needs 1, 2, 4, 8, 12 or 16}"
 [[ "$depth" =~ ^(1|2|4|8|12|16)$ ]] || { echo 'queue depth must be 1, 2, 4, 8, 12 or 16' >&2; exit 2; }
elif [[ $# -gt 0 ]]; then
 echo 'Usage: tools/build-diagnostics.sh [--queue-depth 1|2|4|8|12|16]' >&2; exit 2
fi
build=build-diagnostics; [[ $depth != 0 ]] && build="build-diagnostics-q$depth"
mkdir -p "$build"
# Each variant keeps its own sdkconfig so cached options never leak between images.
defaults="$PWD/alternative/tailnet/sdkconfig.defaults;$PWD/alternative/tailnet/sdkconfig.diagnostics"
if [[ $depth != 0 ]]; then
 echo "CONFIG_TDONGLE_QUEUE_DEPTH_SWEEP=$depth" > "$build/sweep.defaults"
 defaults="$defaults;$PWD/$build/sweep.defaults"
fi
idf.py -B "$build" -D IDF_TARGET=esp32s3 -D "SDKCONFIG=$PWD/$build/sdkconfig" -D "SDKCONFIG_DEFAULTS=$defaults" build size
