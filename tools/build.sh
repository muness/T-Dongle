#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${IDF_PATH:?Run tools/bootstrap.sh and source the pinned ESP-IDF export.sh first}"
[[ "$(git -C "$IDF_PATH" rev-parse HEAD)" == b774170ff46c393eeb5e495ea37936038d3f4f4f ]] || { echo 'Wrong ESP-IDF commit' >&2; exit 1; }
variant="${1:-full}"
case "$variant" in
 full) defaults=sdkconfig.defaults;;
 headless) defaults='sdkconfig.defaults;sdkconfig.headless';;
 network-only) defaults='sdkconfig.defaults;sdkconfig.network-only';;
 *) echo 'Usage: tools/build.sh [full|headless|network-only]' >&2; exit 2;;
esac
mkdir -p "build-$variant"
# Per-variant SDKCONFIG prevents cached options leaking between builds.
idf.py -D TDONGLE_LEGACY_BRIDGE=ON -B "build-$variant" -D "SDKCONFIG=$PWD/build-$variant/sdkconfig" -D "SDKCONFIG_DEFAULTS=$defaults" -D IDF_TARGET=esp32s3 build
python3 tools/check_build.py "build-$variant" "$variant"
python3 tools/package.py "build-$variant" "$variant"
