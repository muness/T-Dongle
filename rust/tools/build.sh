#!/usr/bin/env bash
# Build the Rust firmware, make the flashable images and check them.
#   rust/tools/build.sh            -> rust/dist/tdongle-rust-VERSION/{app.bin,merged.bin,bootloader.bin,partition-table.bin,SHA256SUMS}
# Needs: the pinned ESP-IDF (tools/bootstrap.sh), the Xtensa Rust toolchain (rust-toolchain.toml), ldproxy, espflash. Never flashes.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=env.sh
. tools/env.sh
(cd firmware && cargo build --release)
elf=target/xtensa-esp32s3-espidf/release/tdongle-fw
idf_out=$(ls -dt target/xtensa-esp32s3-espidf/release/build/esp-idf-sys-*/out | head -1)
version=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="tdongle-fw"))')
dist=dist/tdongle-rust-$version
rm -rf "$dist"; mkdir -p "$dist"
# The same flash parameters as the C image: DIO, 40 MHz (QIO at 80 MHz boot-loops this board), 16 MB; the C firmware's partition table.
flags=(--chip esp32s3 --flash-mode dio --flash-freq 40mhz --flash-size 16mb --bootloader "$idf_out/build/bootloader/bootloader.bin" --partition-table firmware/partitions.csv)
espflash save-image "${flags[@]}" "$elf" "$dist/app.bin"
espflash save-image "${flags[@]}" --merge "$elf" "$dist/merged.bin"
cp "$idf_out/build/bootloader/bootloader.bin" "$dist/bootloader.bin"
python3 tools/check_image.py "$dist" "$elf" "$idf_out"
(cd "$dist" && shasum -a 256 ./*.bin > SHA256SUMS)
ls -l "$dist"
