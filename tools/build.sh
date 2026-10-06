#!/usr/bin/env bash
# Build the one T-Dongle firmware (Wi-Fi bridge + tailnet gateway, chosen at runtime), check it and package it.
#   tools/build.sh [release]                         -> build-release/, dist/tdongle-VERSION/
#   tools/build.sh diagnostics [--queue-depth N]     -> build-diagnostics[-qN]/ (memory evidence image; never ship)
# Version: the VERSION file, or TDONGLE_VERSION when set (the release workflow sets it from the git tag).
set -euo pipefail
cd "$(dirname "$0")/.."
: "${IDF_PATH:?Run tools/bootstrap.sh and source the pinned ESP-IDF export.sh first}"
[[ "$(git -C "$IDF_PATH" rev-parse HEAD)" == b774170ff46c393eeb5e495ea37936038d3f4f4f ]] || { echo 'Wrong ESP-IDF commit' >&2; exit 1; }
variant="${1:-release}"; [[ $# -gt 0 ]] && shift
depth=0
case "$variant" in
 release) [[ $# -eq 0 ]] || { echo 'Usage: tools/build.sh [release|diagnostics [--queue-depth 1|2|4|8|12|16]]' >&2; exit 2; };;
 diagnostics)
  if [[ "${1:-}" == --queue-depth ]]; then
   depth="${2:?--queue-depth needs 1, 2, 4, 8, 12 or 16}"
   [[ "$depth" =~ ^(1|2|4|8|12|16)$ ]] || { echo 'queue depth must be 1, 2, 4, 8, 12 or 16' >&2; exit 2; }
  elif [[ $# -gt 0 ]]; then
   echo 'Usage: tools/build.sh diagnostics [--queue-depth 1|2|4|8|12|16]' >&2; exit 2
  fi;;
 *) echo 'Usage: tools/build.sh [release|diagnostics [--queue-depth N]]' >&2; exit 2;;
esac
build="build-$variant"; [[ $depth != 0 ]] && build="build-diagnostics-q$depth"
mkdir -p "$build"
defaults="$PWD/alternative/tailnet/sdkconfig.defaults;$PWD/sdkconfig.defaults"
if [[ $variant == diagnostics ]]; then
 defaults="$defaults;$PWD/alternative/tailnet/sdkconfig.diagnostics"
 if [[ $depth != 0 ]]; then
  echo "CONFIG_TDONGLE_QUEUE_DEPTH_SWEEP=$depth" > "$build/sweep.defaults"
  defaults="$defaults;$PWD/$build/sweep.defaults"
 fi
fi
# Each build directory keeps its own sdkconfig so cached options never leak between images.
idf.py -B "$build" -D "SDKCONFIG=$PWD/$build/sdkconfig" -D "SDKCONFIG_DEFAULTS=$defaults" -D IDF_TARGET=esp32s3 build size
python3 tools/check_build.py "$build" "$variant"
python3 alternative/tailnet/tools/check-startup-stack.py "$build"
if [[ $depth == 0 ]]; then
 python3 tools/package.py "$build" "$variant"
fi
