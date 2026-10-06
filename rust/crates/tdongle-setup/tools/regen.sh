#!/bin/sh
# Rebuild tests/golden/*.golden from the real C sources: main/captive_dns.c, setup_access.c, setup_boot.c, scan_list.c and ESP-IDF's cJSON
# (default ~/esp/esp-idf-v5.5.5, override with IDF_PATH). Needs a host C compiler only. The output is checked in; review the diff.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
idf=${IDF_PATH:-$HOME/esp/esp-idf-v5.5.5}
cjson=$idf/components/json/cJSON
out=$here/../tests/golden
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"
cc -std=gnu11 -O1 -Wall -Wno-unused-function -I"$repo/main" -I"$cjson" "$here/gen_golden.c" \
  "$repo/main/captive_dns.c" "$repo/main/setup_access.c" "$repo/main/setup_boot.c" "$repo/main/scan_list.c" "$cjson/cJSON.c" -lm -o "$tmp/gen_golden"
"$tmp/gen_golden" "$out"
