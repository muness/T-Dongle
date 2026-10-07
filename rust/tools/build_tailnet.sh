#!/usr/bin/env bash
# Build the tailnet-gateway image of the Rust firmware (`--features tailnet,members-1`) and check it. Never flashes.
#   rust/tools/build_tailnet.sh   -> rust/dist/tdongle-rust-VERSION-tailnet/{app-tailnet.bin,tdongle-fw.elf,SHA256SUMS}
# app-tailnet.bin goes at 0x20000 like the bridge image (keeps NVS).
#
# Two build settings are part of the image's memory layout and are set HERE, not in .cargo/config.toml (which every image shares):
#   ESP_HAL_CONFIG_DATA_CACHE_SIZE=32KB          the C's own cache size; gives 32 KB of DRAM (0x3FCF0000..0x3FCF8000) back, which the tailnet heap uses. Without it the
#                                                heap's `.dcache_reclaimed_uninit` section does not fit and the link fails.
#   ESP_HAL_CONFIG_ENSURE_MAIN_STACK_MINIMUM=40960   the linker asserts the stack (what DRAM leaves after the statics and the heap) is at least 40 KB.
# and the heap is a build-time budget (`tailnet::budget` in firmware/src/tailnet.rs: const asserts that it holds the Wi-Fi driver, the ring, the gateway's own
# state and ML_HB_FLOOR).
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/target-xtensa}
export ESP_HAL_CONFIG_DATA_CACHE_SIZE=32KB ESP_HAL_CONFIG_ENSURE_MAIN_STACK_MINIMUM=40960
if [ -z "${LIBCLANG_PATH:-}" ]; then LIBCLANG_PATH=$(ls -d ~/.rustup/toolchains/esp/xtensa-esp32-elf-clang/*/esp-clang/lib); export LIBCLANG_PATH; fi
if ! command -v xtensa-esp32s3-elf-gcc >/dev/null; then PATH=$(ls -d ~/.espressif/tools/xtensa-esp-elf/*/xtensa-esp-elf/bin | tail -1):$PATH; export PATH; fi
version=$(sed -n 's/^version = "\(.*\)"/\1/p' firmware/Cargo.toml | head -1)
dist=dist/tdongle-rust-$version-tailnet
rm -rf "$dist"; mkdir -p "$dist"
elf=$CARGO_TARGET_DIR/xtensa-esp32s3-none-elf/release/tdongle-fw
(cd firmware && cargo +esp build --release --features "tailnet,${MEMBERS:-members-1}")
espflash save-image --chip esp32s3 --flash-mode dio --flash-freq 40mhz --flash-size 16mb "$elf" "$dist/app-tailnet.bin"
cp "$elf" "$dist/tdongle-fw.elf"
want=$(shasum -a 256 "$elf" | cut -d' ' -f1)
got=$(python3 -c "d=open('$dist/app-tailnet.bin','rb').read();print(d[176:208].hex())")
[ "$want" = "$got" ] || { echo "ELF SHA MISMATCH $want vs $got"; exit 1; }
python3 tools/check_boot_order.py firmware/src/main.rs
python3 tools/check_rescue_first.py
# no frame over 12 KB, no direct-call chain over 36 KB (the stack is at least 40 KB)
python3 tools/check_stack.py "$elf" --depth 36000
# DRAM budget as the linker laid it out
python3 tools/check_dram.py "$elf" --stack-min 40960
(cd "$dist" && shasum -a 256 app-tailnet.bin tdongle-fw.elf | tee SHA256SUMS)
if command -v esptool.py >/dev/null || python3 -c "import esptool" 2>/dev/null; then python3 -m esptool image_info --version 2 "$dist/app-tailnet.bin" | sed -n '1,12p;/Segments information/,/^$/p;/Checksum/,/Validation/p'; fi
