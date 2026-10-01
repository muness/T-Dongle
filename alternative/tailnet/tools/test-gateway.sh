#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build-host
cc -std=c11 -fsanitize=address,undefined -g -I tests tests/test_router.c -o build-host/test_router
build-host/test_router
: "${IDF_PATH:?Source ESP-IDF for the same cJSON used by the firmware}"
cc -std=c11 -fsanitize=address,undefined -g -I "$IDF_PATH/components/json/cJSON" tests/test_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_stream
cc -std=c11 -fsanitize=address,undefined -g -I "$IDF_PATH/components/json/cJSON" tests/test_projection.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_projection
build-host/test_projection
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

python - <<'PYCODE'
from pathlib import Path
source=Path('components/microlink/src/ml_noise.c').read_text()
a=source.index('static int chacha20poly1305_encrypt(')
b=source.index('/* ============================================================================',a)
Path('build-host/noise_aead.inc').write_text(source[a:b])
PYCODE
mbed="$IDF_PATH/components/mbedtls/mbedtls"
cc -std=c11 -fsanitize=address,undefined -g -I build-host -I "$mbed/include" -I "$mbed/library" tests/test_noise_inplace.c "$mbed/library/chacha20.c" "$mbed/library/poly1305.c" "$mbed/library/chachapoly.c" "$mbed/library/platform_util.c" "$mbed/library/constant_time.c" -o build-host/test_noise_inplace
build-host/test_noise_inplace
python tools/test-usb-peer.py

python - <<'PYCODE'
from pathlib import Path
source=Path('components/microlink/src/ml_coord.c').read_text()
a=source.index('static int do_start_long_poll(')
b=source.index('/* Send a "lite" endpoint update',a)
Path('build-host/map_request.inc').write_text(source[a:b])
PYCODE
cc -std=c11 -fsanitize=address,undefined -g -I build-host -I "$IDF_PATH/components/json/cJSON" tests/test_map_request.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_map_request
build-host/test_map_request
