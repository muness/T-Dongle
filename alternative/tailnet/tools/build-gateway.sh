#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${IDF_PATH:?Source pinned ESP-IDF v5.5.5}"
[[ "$(git -C "$IDF_PATH" rev-parse HEAD)" == b774170ff46c393eeb5e495ea37936038d3f4f4f ]] || { echo 'Wrong ESP-IDF commit' >&2; exit 1; }
idf.py -B build -D IDF_TARGET=esp32s3 build size
tools/test-gateway.sh
python tools/package.py
