#!/usr/bin/env bash
# Offline after dependencies/tools are installed. Builds only; never accesses a device.
set -euo pipefail
cd "$(dirname "$0")/../c5-firmware"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/cargo-target}"
ESPFLASH_BIN="${ESPFLASH_BIN:-espflash}"
"$ESPFLASH_BIN" --version | grep -q '4.6.0' || { echo 'Install espflash 4.6.0 for the pinned C5 bootloader.' >&2; exit 1; }
cargo build --locked --release
out=../dist/tdongle-c5-vpn-0.4.0-rc2
mkdir -p "$out"
elf="$CARGO_TARGET_DIR/riscv32imac-unknown-none-elf/release/tdongle-c5-vpn"
cp "$elf" "$out/firmware.elf"
flags=(--chip esp32c5 --flash-mode dio --flash-freq 40mhz --flash-size 16mb --partition-table partitions.csv --skip-update-check)
"$ESPFLASH_BIN" save-image "${flags[@]}" "$elf" "$out/app.bin"
"$ESPFLASH_BIN" save-image "${flags[@]}" --merge --skip-padding "$elf" "$out/merged.bin"
cp partitions.csv "$out/partitions.csv"
(cd "$out" && sha256sum app.bin merged.bin firmware.elf partitions.csv > SHA256SUMS)
