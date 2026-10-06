#!/usr/bin/env bash
# Reflash a T-Dongle-S3 without touching BOOT. Retries the `bootloader` console command until the
# chip reboots into the ROM download mode (its console is only reliably alive shortly after a
# boot, so a plain unplug/replug while this is running is enough), then writes the package.
# Usage: tools/flash.sh [package-dir] [seconds-to-wait]   (user-authorized writes only)
# The package is dist/tdongle-VERSION from tools/build.sh; by default the newest release package. No erase is done, so saved
# Wi-Fi networks and tailnet identities (NVS at 0x9000) survive.
# Targets exactly one dongle by chip MAC: TDONGLE_SERIAL=30EDA0D788BC (or 30:ED:...) when more
# than one T-Dongle is attached. Other Espressif boards on the host are never selected.
set -euo pipefail
cd "$(dirname "$0")/.."
wait_s="${2:-120}"
if [[ -n "${1:-}" ]]; then dir="$1"; else dir="$(ls -dt dist/tdongle-*/ 2>/dev/null | grep -v -e '-diagnostics/$' | head -1 || true)"; fi
[[ -n "$dir" && -f "$dir/app.bin" ]] || { echo 'Build first: tools/build.sh' >&2; exit 1; }
port="$(python3 tools/flash_wait.py "$wait_s")" || { echo 'Could not reach the console in time. Unplug and replug the dongle while this runs, or use BOOT.' >&2; exit 1; }
sleep 1
cd "$dir"
python -m esptool --chip esp32s3 --port "$port" --after watchdog_reset write_flash --flash_mode dio --flash_freq 40m --flash_size 16MB \
  0x0 bootloader.bin 0x8000 partition-table.bin 0x20000 app.bin
