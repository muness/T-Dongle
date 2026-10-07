#!/usr/bin/env bash
# Flash or recover the T-Dongle without wedging it.
#   tools/flash.sh <package-dir|app.bin>   flash a package (bootloader+table+app) or an app image
#   tools/flash.sh --recover <...>         same, but wait (up to 10 min) for the board to appear in
#                                          ROM download mode (hold BOOT while plugging in)
# Env: TDONGLE_MAC (default 30:ed:a0:d7:88:bc). Refuses any board with a different MAC.
#
# Why this exists:
#   - esptool's default --before reset kicks the chip OUT of download mode: always --before no_reset.
#   - --after hard_reset (RTS) re-enters download mode (boot:0x0) and looks like a boot loop:
#     always --after watchdog_reset.
#   - A leftover serial reader holding the port makes esptool hang: we kill holders first.
set -euo pipefail
MAC="${TDONGLE_MAC:-30:ed:a0:d7:88:bc}"
ESPTOOL="${ESPTOOL:-$HOME/.espressif/python_env/idf5.5_py3.12_env/bin/esptool.py}"
APP_PORT="/dev/cu.usbmodem$(echo "$MAC" | tr -d : | tr a-f A-F)1"
ROM_PORT=""
recover=0
[[ "${1:-}" == --recover ]] && { recover=1; shift; }
src="${1:?usage: tools/flash.sh [--recover] <package-dir|app.bin>}"

if [[ -d "$src" ]]; then
  (cd "$src" && shasum -a256 -c SHA256SUMS >/dev/null) || { echo "checksum mismatch in $src" >&2; exit 1; }
  images=(0x0 "$src/bootloader.bin" 0x8000 "$src/partition-table.bin" 0x20000 "$src/app.bin")
else
  images=(0x20000 "$src")
fi

free_port() { local p; for p in /dev/cu.usbmodem*; do lsof -t "$p" 2>/dev/null | xargs -r kill -9 2>/dev/null || true; done; }
mac_of() { "$ESPTOOL" --chip esp32s3 --port "$1" --before no_reset --after no_reset read_mac 2>/dev/null | grep -m1 -io 'MAC: [0-9a-f:]*' | cut -d' ' -f2; }

find_rom_port() {
  local p
  for p in /dev/cu.usbmodem*; do
    [[ "$p" == "$APP_PORT" ]] && continue
    [[ "$(mac_of "$p" | tr A-F a-f)" == "$MAC" ]] && { ROM_PORT="$p"; return 0; }
  done
  return 1
}

free_port
if ! find_rom_port; then
  if [[ -e "$APP_PORT" ]]; then
    echo "app running: asking it to reboot into download mode"
    python3 -c "import os,time;fd=os.open('$APP_PORT',os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK);os.write(fd,b'\r\nbootloader\r\n');time.sleep(1);os.close(fd)" || true
  fi
  deadline=$(( SECONDS + (recover ? 600 : 20) ))
  [[ $recover == 1 ]] && echo "waiting for the board in download mode (hold BOOT and plug it in)..."
  until find_rom_port; do
    (( SECONDS < deadline )) || { echo "board $MAC never appeared in download mode; rerun with --recover and hold BOOT while plugging in" >&2; exit 1; }
    sleep 1
  done
fi
echo "download mode on $ROM_PORT ($MAC)"

"$ESPTOOL" --chip esp32s3 --port "$ROM_PORT" --before no_reset --after watchdog_reset \
  write_flash --flash_mode dio --flash_freq 40m --flash_size 16MB "${images[@]}"

echo "waiting for the firmware to come up..."
for _ in $(seq 60); do
  if ping -c1 -t1 192.168.77.1 >/dev/null 2>&1 || [[ -e "$APP_PORT" ]]; then echo "UP: $APP_PORT / 192.168.77.1"; exit 0; fi
  sleep 1
done
echo "flashed, but the firmware did not come up within 60 s (boot crash?). Recover with a known-good image:" >&2
echo "  tools/flash.sh --recover <known-good app.bin or package>" >&2
exit 2
