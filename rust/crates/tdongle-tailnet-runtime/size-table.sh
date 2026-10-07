#!/bin/sh
# The runtime's memory table on the device target (M-elf): sizes of the top-level futures and the statics, from rustc's own layout of the xtensa build,
# for every slot count the firmware can be built with (features `slots-1`, `slots-2`, default 3).
#   rust/crates/tdongle-tailnet-runtime/size-table.sh            (all of 1 2 3; needs the esp toolchain, `cargo +esp`)
#   rust/crates/tdongle-tailnet-runtime/size-table.sh 3          (just one)
# The host figures (M-host) are printed by `cargo test -p tdongle-tailnet-host --test memory -- --nocapture`.
set -e
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/tdongle-tailnet-target}"
export CARGO_INCREMENTAL=0
OUTDIR="${TMPDIR:-/tmp}"
SLOTS="${*:-1 2 3}"
for n in $SLOTS; do
    case "$n" in
        1) FEAT="size-probe,slots-1" ;;
        2) FEAT="size-probe,slots-2" ;;
        3) FEAT="size-probe" ;;
        *) echo "slots must be 1, 2 or 3" >&2; exit 2 ;;
    esac
    # rustc prints the layouts only when it runs: make sure it does
    touch crates/tdongle-tailnet-runtime/src/lib.rs
    RUSTFLAGS="-Zprint-type-sizes" cargo +esp rustc -p tdongle-tailnet-runtime --lib --target xtensa-esp32s3-none-elf \
        -Zbuild-std=core,alloc --features "$FEAT" > "$OUTDIR/tdongle-runtime-typesizes-$n.txt" 2>&1
done
python3 "$(dirname "$0")/size_table.py" "$OUTDIR" $SLOTS
