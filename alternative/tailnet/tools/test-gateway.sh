#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build-host
cc -std=c11 -fsanitize=address,undefined -g -I tests tests/test_router.c -o build-host/test_router
build-host/test_router
: "${IDF_PATH:?Source ESP-IDF for the same cJSON used by the firmware}"
cc -std=c11 -fsanitize=address,undefined -g -I "$IDF_PATH/components/json/cJSON" tests/test_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_stream
build-host/test_stream

python - <<'PYCODE'
from pathlib import Path
source=Path('components/microlink/src/microlink.c').read_text()
a=source.index('static void generate_keypair(')
b=source.index('/* ============================================================================\n * cJSON',a)
Path('build-host/identity_core.inc').write_text(source[a:b])
PYCODE
cc -std=c11 -fsanitize=address,undefined -g -I build-host tests/test_identity.c -o build-host/test_identity
build-host/test_identity
