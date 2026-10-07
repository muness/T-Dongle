#!/usr/bin/env bash
# Flash or recover the T-Dongle without wedging it.
#   tools/flash.sh <package-dir|app.bin>   flash a package (bootloader+table+app) or an app image
#   tools/flash.sh --recover <...>         same, but wait (up to 10 min) for the board to appear in
#                                          ROM download mode (hold BOOT while plugging in)
# Pinned to MAC 30:ed:a0:d7:88:bc. An override naming another board is refused.
#
# Why this exists:
#   - esptool's default --before reset kicks the chip OUT of download mode: always --before no_reset.
#   - --after hard_reset (RTS) re-enters download mode (boot:0x0) and looks like a boot loop:
#     always --after watchdog_reset.
#   - A leftover serial reader holding the port makes esptool hang: we kill holders first.
set -euo pipefail
MAC="30:ed:a0:d7:88:bc"
[[ "$(printf '%s' "${TDONGLE_MAC:-$MAC}" | tr A-F a-f)" == "$MAC" ]] || { echo "refusing TDONGLE_MAC override: this script is pinned to $MAC" >&2; exit 1; }
TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
ESPTOOL="${ESPTOOL:-$HOME/.espressif/python_env/idf5.5_py3.12_env/bin/esptool.py}"
APP_PORT="/dev/cu.usbmodem$(echo "$MAC" | tr -d : | tr a-f A-F)1"
ESPTOOL_PYTHON="$(dirname "$ESPTOOL")/python"
ROM_PORT=""
recover=0
[[ "${1:-}" == --recover ]] && { recover=1; shift; }
src="${1:?usage: tools/flash.sh [--recover] <package-dir|app.bin>}"

if [[ -d "$src" ]]; then
  (cd "$src" && shasum -a256 -c SHA256SUMS >/dev/null) || { echo "checksum mismatch in $src" >&2; exit 1; }
  images=(0x0 "$src/bootloader.bin" 0x8000 "$src/partition-table.bin" 0x20000 "$src/app.bin")
else
  [[ -f "$src" && -r "$src" && -s "$src" ]] || { echo "app image is missing, empty or unreadable: $src" >&2; exit 1; }
  images=(0x20000 "$src")
fi

# Resolve only this board from live USB serial metadata. Never
# probe unrelated serial devices: read_mac can change their running state.
board_ports() {
  "$ESPTOOL_PYTHON" - "$MAC" <<'PORTS'
from serial.tools import list_ports
import sys
mac = sys.argv[1].replace(':', '').lower()
for port in list_ports.comports():
    if port.vid == 0x303a and (port.serial_number or '').replace(':', '').lower() == mac:
        print(port.device)
PORTS
}
free_port() { local p; while IFS= read -r p; do [[ -n "$p" ]] && { lsof -t "$p" 2>/dev/null | xargs -r kill -9 2>/dev/null || true; }; done < <(board_ports); }
mac_of() { "$ESPTOOL" --chip esp32s3 --port "$1" --before no_reset --after no_reset read_mac 2>/dev/null | grep -m1 -io 'MAC: [0-9a-f:]*' | cut -d' ' -f2; }

find_rom_port() {
  local p
  while IFS= read -r p; do
    [[ -z "$p" || "$p" == "$APP_PORT" ]] && continue
    [[ "$(mac_of "$p" | tr A-F a-f)" == "$MAC" ]] && { ROM_PORT="$p"; return 0; }
  done < <(board_ports)
  return 1
}

free_port
if ! find_rom_port; then
  if [[ -e "$APP_PORT" ]]; then
    echo "app running: asking it to reboot into download mode"
    "$ESPTOOL_PYTHON" "$TOOLS_DIR/flash_console.py" poke "$APP_PORT" || true
  fi
  deadline=$(( SECONDS + (recover ? 600 : 20) ))
  [[ $recover == 1 ]] && echo "waiting for the board in download mode (hold BOOT and plug it in)..."
  until find_rom_port; do
    if [[ -e "$APP_PORT" ]]; then
      "$ESPTOOL_PYTHON" "$TOOLS_DIR/flash_console.py" poke "$APP_PORT" || true
    fi
    (( SECONDS < deadline )) || { echo "board $MAC never appeared in download mode; rerun with --recover and hold BOOT while plugging in" >&2; exit 1; }
    sleep 1
  done
fi
echo "download mode on $ROM_PORT ($MAC)"

# macOS needs a moment to release the port after the MAC probe. Retry only
# transient ownership errors; a failed write or reset needs explicit recovery.
flash_log="$(mktemp)"
trap 'rm -f "$flash_log"' EXIT
for attempt in 1 2 3 4 5; do
  sleep 1
  if "$ESPTOOL" --chip esp32s3 --port "$ROM_PORT" --before no_reset --after watchdog_reset \
      write_flash --flash_mode dio --flash_freq 40m --flash_size 16MB "${images[@]}" >"$flash_log" 2>&1; then
    cat "$flash_log"
    break
  fi
  cat "$flash_log" >&2
  if ! grep -Eiq 'resource busy|device or resource busy|port is busy|could not open port.*busy|errno 16' "$flash_log"; then
    echo "flash failed; recover with a known-good image before retrying" >&2
    exit 1
  fi
  (( attempt < 5 )) || { echo "flash failed after 5 busy attempts" >&2; exit 1; }
  echo "port busy; retrying ($attempt)..."; free_port
done

echo "waiting for the firmware to come up..."
deadline=$((SECONDS + 60))
ready=0
while (( SECONDS < deadline )); do
  # Port enumeration and ICMP alone also occur during a crash loop or may refer
  # to another host. Require two fresh console status replies from this dongle.
  if [[ -e "$APP_PORT" ]] && "$ESPTOOL_PYTHON" "$TOOLS_DIR/flash_console.py" ready "$APP_PORT"; then
    ready=$((ready + 1))
    if (( ready >= 2 )); then echo "UP: $APP_PORT (two fresh firmware status replies)"; exit 0; fi
  else
    ready=0
  fi
  sleep 1
done
echo "flashed, but the firmware did not come up within 60 s (boot crash?). Recover with a known-good image:" >&2
echo "  tools/flash.sh --recover <known-good app.bin or package>" >&2
exit 2
