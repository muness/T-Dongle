#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build-host
cc -std=c11 -fsanitize=address,undefined -g -I tests tests/test_router.c -o build-host/test_router
build-host/test_router
: "${IDF_PATH:?Source ESP-IDF for the same cJSON used by the firmware}"
cc -std=c11 -fsanitize=address,undefined -g -pthread -I "$IDF_PATH/components/json/cJSON" tests/test_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_stream
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
cc -std=c11 -fsanitize=address,undefined -g -I "$IDF_PATH/components/json/cJSON" tests/test_project_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_project_stream
build-host/test_project_stream
python - <<'PYCODE'
from pathlib import Path
s=Path('components/microlink/src/ml_derp.c').read_text();a=s.index('static int derp_read_exact(');b=s.index('/* ============================================================================',a)
Path('build-host/derp_receive.inc').write_text(s[a:b])
PYCODE
cc -std=c11 -fsanitize=address,undefined -g -I build-host tests/test_derp_receive.c -o build-host/test_derp_receive
build-host/test_derp_receive
python - <<'PYCODE'
from pathlib import Path
s=Path('main/gateway_main.c').read_text();a=s.index('#include "json_writer.inc"');b=s.index('static esp_err_t command(',a)
Path('build-host/status_stream.inc').write_text(s[a:b]);Path('build-host/json_writer.inc').write_text(Path('main/json_writer.inc').read_text())
PYCODE
cc -std=c11 -fsanitize=address,undefined -g -I build-host -I "$IDF_PATH/components/json/cJSON" tests/test_status_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_status_stream
build-host/test_status_stream
python - <<'PYCODE'
from pathlib import Path
h=Path('components/microlink/include/microlink_internal.h').read_text();a=h.index('/* Peer update (from coord');b=h.index('/* ============================================================================',a);c=h.index('typedef struct {',h.index('#define ML_MAX_DERP_NODES'));d=h.index('/* ============================================================================',c)
Path('build-host/semantic_types.inc').write_text(h[a:b]+h[c:d])
s=Path('components/microlink/src/ml_coord.c').read_text();a=s.index('static void parse_peers_from_map_response(');b=s.index('/* Add Endpoints',a);c=s.index('static void decode_derp_regions(');d=s.index('static bool activate_derp_regions(',c)
Path('build-host/semantic_consumers.inc').write_text(s[a:b]+s[c:d])
w=Path('components/microlink/src/ml_wg_mgr.c').read_text();a=w.index('static void process_peer_updates(');b=w.index('/* ============================================================================',a);Path('build-host/batch_consumer.inc').write_text(w[a:b])
PYCODE
cc -std=c11 -fsanitize=address,undefined -g -I build-host -I "$IDF_PATH/components/json/cJSON" tests/test_semantic_map.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_semantic_map
build-host/test_semantic_map
python - <<'PYCODE'
from pathlib import Path
s=Path('components/microlink/src/ml_coord.c').read_text();a=s.index('static int coord_send(');b=s.index('static int coord_recv(',a);c=s.index('static int noise_send_owned(');d=s.index('/* Receive and decrypt',c)
Path('build-host/control_send.inc').write_text(s[a:b]+s[c:d])
PYCODE
cc -std=c11 -fsanitize=address,undefined -g -pthread -I build-host -I "$mbed/include" -I "$mbed/library" tests/test_control_send.c "$mbed/library/chacha20.c" "$mbed/library/poly1305.c" "$mbed/library/chachapoly.c" "$mbed/library/platform_util.c" "$mbed/library/constant_time.c" -o build-host/test_control_send
build-host/test_control_send

python - <<'PYCODE'
from pathlib import Path
s=Path('components/microlink/src/ml_coord.c').read_text()
a=s.index('static int coord_recv(');b=s.index('/* ============================================================================\n * Noise-encrypted',a)
c=s.index('static int noise_recv_buffer(');d=s.index('/* ============================================================================\n * State: DNS_RESOLVE',c)
e=s.index('static int do_h2_preface(');f=s.index('/* ============================================================================\n * State: REGISTER',e)
Path('build-host/receive_core.inc').write_text(s[a:b]+s[c:d])
Path('build-host/h2_preface.inc').write_text(s[e:f])
h=Path('components/microlink/src/ml_h2.c').read_text();Path('build-host/h2_core.inc').write_text(h[h.index('static const char *TAG'):])
PYCODE
cc -std=c11 -fsanitize=address,undefined -g -pthread -I build-host -I "$IDF_PATH/components/json/cJSON" -I "$mbed/include" -I "$mbed/library" tests/test_h2_handshake.c "$IDF_PATH/components/json/cJSON/cJSON.c" "$mbed/library/chacha20.c" "$mbed/library/poly1305.c" "$mbed/library/chachapoly.c" "$mbed/library/platform_util.c" "$mbed/library/constant_time.c" -o build-host/test_h2_handshake
build-host/test_h2_handshake
python tools/test-sockets.py
python tools/test-control-interop.py
python tools/test-journal.py

cc -std=c11 -fsanitize=address,undefined -g -I build-host -I components/microlink/include tests/test_peer_directory.c -o build-host/test_peer_directory
build-host/test_peer_directory
cc -std=c11 -fsanitize=address,undefined -g -I build-host -I components/microlink/include -I "$IDF_PATH/components/json/cJSON" tests/test_semantic_directory.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_semantic_directory
build-host/test_semantic_directory

python - <<'PYJIT'
from pathlib import Path
s=Path('components/microlink/src/ml_wg_mgr.c').read_text();a=s.index('static int directory_activate(');b=s.index('/* The queue owns copies',a);Path('build-host/jit_activation.inc').write_text(s[a:b])
PYJIT
cc -std=c11 -fsanitize=address,undefined -g -I build-host -I components/microlink/include tests/test_jit_directory.c -o build-host/test_jit_directory
build-host/test_jit_directory

python - <<'PYQUEUE'
from pathlib import Path
s=Path('components/microlink/src/ml_wg_mgr.c').read_text();a=s.index('esp_err_t ml_gateway_queue_packet(');b=s.index('#endif',a);Path('build-host/jit_queue.inc').write_text(s[a:b])
PYQUEUE
cc -std=c11 -fsanitize=address,undefined -g -I build-host tests/test_jit_queue.c -o build-host/test_jit_queue
build-host/test_jit_queue

python tools/test-resilience.py
