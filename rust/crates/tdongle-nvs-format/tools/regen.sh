#!/bin/sh
# Rebuild tests/golden/*.bin from the real C sources. Needs a host C compiler and ESP-IDF's cJSON (default ~/esp/esp-idf-v5.5.5, override with IDF_PATH).
# The output is checked in; run this only when a C layout or rule changes, and review the diff of the .bin files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
idf=${IDF_PATH:-$HOME/esp/esp-idf-v5.5.5}
cjson=$idf/components/json/cJSON
out=$here/../tests/golden
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"
cc -std=gnu11 -O1 -Wall -Wno-unused-function -I"$repo/main" -I"$cjson" "$here/gen_golden.c" "$cjson/cJSON.c" -lm -o "$tmp/gen_golden"
"$tmp/gen_golden" "$out"
