#!/usr/bin/env bash
# Build a spike as an APP-ONLY image (flash at 0x20000 under the C package's IDF v5.5.5 bootloader + partition table; never a merged image,
# which would wipe NVS). No credentials are built in: S1/S3 read the saved networks from NVS.
# Usage: build-app.sh s2-usb-ncm|s3-bridge|s1-wifi-l2 [cargo features] [output suffix]   e.g.  build-app.sh s2-usb-ncm stock-out -stock
set -euo pipefail
cd "$(dirname "$0")/$1"
export LIBCLANG_PATH=$(ls -d ~/.rustup/toolchains/esp/xtensa-esp32-elf-clang/*/esp-clang/lib)
export PATH=$(ls -d ~/.rustup/toolchains/esp/xtensa-esp-elf/*/xtensa-esp-elf/bin):$PATH
feat=${2:+--features $2}
cargo build --release $feat
mkdir -p ../dist
espflash save-image --chip esp32s3 --flash-mode dio --flash-freq 40mhz --flash-size 16mb "target/xtensa-esp32s3-none-elf/release/$1" "../dist/${1%%-*}${3:-}-app.bin"
elf=$(shasum -a 256 "target/xtensa-esp32s3-none-elf/release/$1" | cut -d' ' -f1)
img=$(python3 -c "d=open('../dist/${1%%-*}${3:-}-app.bin','rb').read();print(d[176:208].hex())")
[ "$elf" = "$img" ] && echo "elf sha256 in app descriptor matches: $elf" || { echo "ELF SHA MISMATCH $elf vs $img"; exit 1; }
