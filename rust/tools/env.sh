#!/usr/bin/env bash
# Source this (`. rust/tools/env.sh`) before building the firmware. It activates the pinned ESP-IDF v5.5.5 (the same checkout the C firmware
# builds with: tools/bootstrap.sh) and adds only what the Xtensa Rust toolchain needs on top: libclang for bindgen.
#
# espup's own export script also PREPENDS its GCC 15.2 to PATH; that must not be used here: ESP-IDF v5.5.5 checks its toolchain version and
# wants the GCC 14.2 that its own export.sh puts on PATH.
IDF_ROOT="${IDF_PATH:-$HOME/.cache/tdongle/esp-idf-v5.5.5}"
[ -f "$IDF_ROOT/export.sh" ] || { echo "ESP-IDF not found at $IDF_ROOT: run tools/bootstrap.sh" >&2; return 1; }
. "$IDF_ROOT/export.sh" >/dev/null || return 1
if [ -z "${LIBCLANG_PATH:-}" ]; then
  for d in "$HOME"/.rustup/toolchains/esp/xtensa-esp32-elf-clang/*/esp-clang/lib; do [ -d "$d" ] && LIBCLANG_PATH="$d"; done
  export LIBCLANG_PATH
fi
