#!/usr/bin/env bash
# Count executed Xtensa instructions for the compiled crypto code, without hardware.
#   run.sh [-O2|-Os|-O3] [len] [off] [new|legacy|mbedtls]    (PHASES=phase_seal,... selects phases)
# Builds harness + crypto sources for ESP32-S3 with the Espressif GCC, links a bare ELF and
# runs each phase in xtensa_emu.py, checking the output against a host oracle.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../../src"
OPT="${1:--Os}"; LEN="${2:-1400}"; OFF="${3:-0}"; WHICH="${4:-new}"
TC="${XTENSA_TOOLCHAIN:-$(ls -d "$HOME"/.espressif/tools/xtensa-esp-elf/*/xtensa-esp-elf | sort | tail -1)}"
export PATH="$TC/bin:$PATH"
export XTENSA_GNU_CONFIG="$TC/lib/xtensa_esp32s3.so"   # lets objdump decode the ESP32-S3 instruction set (saltu, ...)
B="${TMPDIR:-/tmp}/xtensa-insn-count.$$"; mkdir -p "$B"; trap 'rm -rf "$B"' EXIT
CF=(-mdynconfig="$TC/lib/xtensa_esp32s3.so" -mlongcalls -ffunction-sections -fdata-sections "$OPT" -I"$SRC" -I"$SRC/crypto" -I"$SRC/crypto/refc")
if [ "$WHICH" = mbedtls ]; then
  # IDF's mbedTLS (CONFIG_MBEDTLS_CHACHAPOLY_C): the generic C implementation, built with the same flags.
  MB="${IDF_PATH:?source ESP-IDF}/components/mbedtls/mbedtls"
  cat > "$B/mbedtls_cfg.h" <<'CFG'
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_PLATFORM_MEMORY_NONE
CFG
  CF+=(-DHARNESS_MBEDTLS -DMBEDTLS_CONFIG_FILE=\"$B/mbedtls_cfg.h\" -I"$MB/include" -I"$MB/library")
  SRCS=("$MB/library/chacha20.c" "$MB/library/poly1305.c" "$MB/library/chachapoly.c" "$MB/library/platform_util.c" "$MB/library/constant_time.c")
elif [ "$WHICH" = legacy ]; then
  CF+=(-DHARNESS_LEGACY)
  SRCS=("$SRC/crypto/legacy/wg_crypto_legacy.c" "$SRC/crypto.c")
else
  SRCS=("$SRC/crypto/refc/chacha20.c" "$SRC/crypto/refc/poly1305-donna.c" "$SRC/crypto/refc/chacha20poly1305.c" "$SRC/crypto.c")
fi
xtensa-esp-elf-gcc "${CF[@]}" -nostdlib -Wl,-Ttext=0x10000 -Wl,-Tdata=0x40000 -Wl,-e,phase_seal \
  "$HERE/harness.c" "${SRCS[@]}" -o "$B/t.elf"
cc -std=gnu11 -O1 -I"$SRC/crypto" "$HERE/refgen.c" "$SRC/crypto/legacy/wg_crypto_legacy.c" "$SRC/crypto.c" -I"$SRC" -o "$B/refgen"
python3 "$HERE/xtensa_emu.py" "$B/t.elf" --len "$LEN" --off "$OFF" --refgen "$B/refgen" ${PHASES:+--phases "$PHASES"} ${PHASES:+--phases "$PHASES"}
xtensa-esp-elf-size "$B/t.elf" | tail -1
# Constant-time structure check: the secret-dependent arithmetic must contain no conditional
# branches except loop control (expect 1-3 per function: the 10-round / per-block loop).
echo "conditional branches (loop control only is expected):"
for f in chacha20_block_words poly1305_blocks_aligned poly1305_finish legacy_poly1305_blocks legacy_INNER_BLOCK; do
  n=$(xtensa-esp-elf-objdump -d "$B/t.elf" | awk -v f="<$f>:" '$2==f{p=1;next} /^$/{p=0} p' | grep -cE $'\t(b[a-z]+(\\.n)?|loop[a-z]*)\t' || true)
  [ "$n" -gt 0 ] || xtensa-esp-elf-objdump -d "$B/t.elf" | grep -q "<$f>:" || continue
  echo "  $f: $n"
done
