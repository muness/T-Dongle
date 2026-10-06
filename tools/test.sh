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
"${compiler[@]}" -std=c11 -Wall -Wextra -Werror ${TEST_CFLAGS:-} -I main main/core.c main/view.c tests/test_core.c -lm -o build-host/test_core
build-host/test_core
"${compiler[@]}" -std=c11 -I main main/core.c main/view.c tests/preview.c -o build-host/preview
build-host/preview > build-host/preview.txt
python3 tools/preview.py
python3 tools/test_flash_wait.py
python3 tools/test_net.py
python3 tools/test_settings.py
python3 tools/test_profile.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
