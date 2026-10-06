#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build-host
# CC may be a compiler plus arguments, e.g. 'zig cc'.
read -r -a compiler <<< "${CC:-cc}"
if [[ "${TEST_CFLAGS:-}" == *address* ]]; then
  "${compiler[@]}" ${TEST_CFLAGS:-} tests/sanitizer_probe.c -o build-host/sanitizer_probe
  build-host/sanitizer_probe
fi
"${compiler[@]}" -std=c11 -Wall -Wextra -Werror ${TEST_CFLAGS:-} -I main -I legacy main/core.c legacy/view.c tests/test_core.c -lm -o build-host/test_core
build-host/test_core
# The device UI and setup modules (main/): display settings, saved-network metadata, the v0.1.x import, the setup boot decision and access
# rules, captive DNS, the nearby-network list, the button menu, the status light, the traffic counters (also under TSan) and the health tallies.
cflags=(-std=c11 -Wall -Wextra -Werror ${TEST_CFLAGS:-} -I main)
while read -r name sources; do
  "${compiler[@]}" "${cflags[@]}" -pthread "tests/test_${name}.c" ${sources} -o "build-host/test_${name}"
  "build-host/test_${name}"
done <<'LIST'
ui_settings main/ui_settings.c
wifi_meta main/wifi_meta.c
legacy_import main/legacy_import.c main/wifi_meta.c main/ui_settings.c
setup_boot main/setup_boot.c
setup_access main/setup_access.c
captive_dns main/captive_dns.c
scan_list main/scan_list.c
menu main/menu.c
led main/led.c
health main/health.c
traffic main/traffic.c
traffic_hooks main/traffic_hooks.c main/traffic.c
LIST
"${compiler[@]}" -std=c11 -Wall -Wextra -Werror -fsanitize=thread -g -pthread -I main tests/test_traffic.c main/traffic.c -o build-host/test_traffic_tsan
build-host/test_traffic_tsan
python3 tools/test_flash_wait.py
python3 tools/test_net.py
python3 tools/test_settings.py
python3 tools/test_profile.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
