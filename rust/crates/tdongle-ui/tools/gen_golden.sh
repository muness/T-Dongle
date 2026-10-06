#!/bin/sh
# Regenerate tests/golden/*.trace from the REAL C firmware sources. The C reference lives on main: this script reads it with `git show`, so it
# needs a git checkout that has $C_REF (default origin/main) and a C compiler. Usage: tools/gen_golden.sh   (from anywhere in the repo)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
ref=${C_REF:-origin/main}
out="$here/../tests/golden"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for f in main/menu.c main/menu.h main/led.c main/led.h main/core.c main/core.h main/health.h main/health.c main/traffic.c main/traffic.h main/ui_settings.c main/ui_settings.h \
         main/setup_boot.c main/setup_boot.h main/board.h alternative/tailnet/main/device_ui.inc alternative/tailnet/main/lcd_view.h; do
    mkdir -p "$work/$(dirname "$f")"
    git -C "$repo" show "$ref:$f" > "$work/$f"
done
git -C "$repo" rev-parse "$ref" > "$out/C_REF"
cc -std=gnu11 -O1 -g -Wall -Wno-unused-function -fsanitize=address,undefined -I"$work/main" -I"$work/alternative/tailnet/main" \
   -DDEVICE_UI_INC="\"$work/alternative/tailnet/main/device_ui.inc\"" \
   "$here/ui_trace.c" "$work/main/menu.c" "$work/main/led.c" "$work/main/core.c" "$work/main/traffic.c" "$work/main/ui_settings.c" "$work/main/setup_boot.c" "$work/main/health.c" \
   -o "$work/ui_trace"
for scn in "$out"/*.scn; do
    "$work/ui_trace" "$scn" > "${scn%.scn}.trace"
done
"$work/ui_trace" --led-sweep > "$out/led_sweep.trace"
wc -l "$out"/*.trace
