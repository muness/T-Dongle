#!/usr/bin/env bash
# Build the no_std Rust firmware and make the flashable images. Never flashes.
#   rust/tools/build.sh   -> rust/dist/tdongle-rust-VERSION/{app.bin,app-diagnostics.bin,merged.bin,bootloader.bin,partition-table.bin,SHA256SUMS}
# app.bin goes at 0x20000 (keeps NVS). merged.bin is the full 16 MB layout (wipes NVS): only when a bootloader is available (RESCUE_BOOTLOADER or dist file).
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/target-xtensa}
if [ -z "${LIBCLANG_PATH:-}" ]; then LIBCLANG_PATH=$(ls -d ~/.rustup/toolchains/esp/xtensa-esp32-elf-clang/*/esp-clang/lib); export LIBCLANG_PATH; fi
if ! command -v xtensa-esp-elf-gcc >/dev/null; then PATH=$(ls -d ~/.rustup/toolchains/esp/xtensa-esp-elf/*/xtensa-esp-elf/bin):$PATH; export PATH; fi
version=$(sed -n 's/^version = "\(.*\)"/\1/p' firmware/Cargo.toml | head -1)
dist=dist/tdongle-rust-$version
rm -rf "$dist"; mkdir -p "$dist"
elf=$CARGO_TARGET_DIR/xtensa-esp32s3-none-elf/release/tdongle-fw
flags=(--chip esp32s3 --flash-mode dio --flash-freq 40mhz --flash-size 16mb)
bl=${RESCUE_BOOTLOADER:-spikes/dist/bootloader-rescue.bin}
build() { # features outname
  (cd firmware && cargo build --release ${1:+--features $1})
  espflash save-image "${flags[@]}" "$elf" "$dist/$2"
  local want got
  want=$(shasum -a 256 "$elf" | cut -d' ' -f1)
  got=$(python3 -c "d=open('$dist/$2','rb').read();print(d[176:208].hex())")
  [ "$want" = "$got" ] || { echo "ELF SHA MISMATCH $want vs $got"; exit 1; }
  echo "$2 elf sha256 $want"
}
build diagnostics app-diagnostics.bin
build "" app.bin
cp "$elf" "$dist/tdongle-fw.elf"
if [ -f "$bl" ]; then
  espflash save-image "${flags[@]}" --merge --bootloader "$bl" --partition-table firmware/partitions.csv "$elf" "$dist/merged.bin"
  cp "$bl" "$dist/bootloader.bin"
fi
python3 tools/check_boot_order.py firmware/src/main.rs
python3 tools/check_rescue_first.py
(cd "$dist" && shasum -a 256 ./*.bin > SHA256SUMS && cat SHA256SUMS)
