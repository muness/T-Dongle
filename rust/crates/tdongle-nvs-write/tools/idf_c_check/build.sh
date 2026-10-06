#!/bin/sh
# Build idf_c_check from ESP-IDF's own nvs_flash sources (unchanged) and a memory-backed nvs::Partition. Output: $1 (default ./idf_c_check).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
idf=${IDF_PATH:-$HOME/.cache/tdongle/esp-idf-v5.5.5}
n=$idf/components/nvs_flash
out=${1:-$here/idf_c_check}
cxx=${CXX:-c++}
exec "$cxx" -std=c++17 -O1 -w -DESP_TEE_BUILD=1 -DLINUX_TARGET -DNO_DEBUG_STORAGE \
  -I"$here/stubs" -I"$n/include" -I"$n/private_include" -I"$n/src" -I"$idf/components/esp_common/include" \
  "$here/main.cpp" "$n/src/nvs_page.cpp" "$n/src/nvs_pagemanager.cpp" "$n/src/nvs_storage.cpp" "$n/src/nvs_types.cpp" "$n/src/nvs_item_hash_list.cpp" \
  -o "$out"
