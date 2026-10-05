#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
../../components/tdongle_runtime/tests/run.sh
mkdir -p build-host
# Host builds see no ESP-IDF configuration (tests/sdkconfig.h) and the real allocator-tag header.
TD_INC="-I tests -I components/microlink/include -I ../../components/tdongle_runtime/include"
python - <<'PYWIFI'
from pathlib import Path
s=Path('main/wifi_profiles.inc').read_text();a=s.index('/* Scanning and reconnecting');Path('build-host/wifi_store.inc').write_text(s[:a]);Path('build-host/wifi_worker.inc').write_text(s[a:])
PYWIFI
for name in coord_read wifi_policy wifi_profiles; do
 cc $TD_INC -std=gnu11 -I build-host -fsanitize=address,undefined -g tests/test_${name}.c -o build-host/test_${name}
 build-host/test_${name}
done
# The USB wrapper is shared with the original bridge; test its real code too.
(cd ../.. && TEST_CFLAGS="-fsanitize=address,undefined -g" python3 tools/test_net.py)
cc $TD_INC -std=c11 -fsanitize=address,undefined -g tests/test_usb_identity.c -o build-host/test_usb_identity
build-host/test_usb_identity
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I tests tests/test_router.c -o build-host/test_router
build-host/test_router
: "${IDF_PATH:?Source ESP-IDF for the same cJSON used by the firmware}"
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -pthread -I "$IDF_PATH/components/json/cJSON" tests/test_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_stream
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I "$IDF_PATH/components/json/cJSON" tests/test_projection.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_projection
build-host/test_projection
build-host/test_stream

python - <<'PYCODE'
from pathlib import Path
source=Path('components/microlink/src/microlink.c').read_text()
a=source.index('static void generate_keypair(')
b=source.index('/* ============================================================================\n * cJSON',a)
Path('build-host/identity_core.inc').write_text(source[a:b])
PYCODE
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host tests/test_identity.c -o build-host/test_identity
build-host/test_identity

python - <<'PYCODE'
from pathlib import Path
source=Path('components/microlink/src/ml_noise.c').read_text()
a=source.index('static int chacha20poly1305_encrypt(')
b=source.index('/* ============================================================================',a)
Path('build-host/noise_aead.inc').write_text(source[a:b])
PYCODE
mbed="$IDF_PATH/components/mbedtls/mbedtls"
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I "$mbed/include" -I "$mbed/library" tests/test_noise_inplace.c "$mbed/library/chacha20.c" "$mbed/library/poly1305.c" "$mbed/library/chachapoly.c" "$mbed/library/platform_util.c" "$mbed/library/constant_time.c" -o build-host/test_noise_inplace
build-host/test_noise_inplace

# WireGuard data-path ChaCha20-Poly1305 (wireguard_lwip): RFC 8439 vectors, then thousands of random
# lengths/alignments/tag failures against the original implementation and mbedTLS, sanitised, at two
# optimisation levels (the aligned fast paths are only exercised for real by -fsanitize=alignment).
wg=components/microlink/components/wireguard_lwip/src
for opt in -O1 -O3; do
 cc -std=gnu11 $opt -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra -Wno-unused-const-variable \
    -I tests -I "$wg" -I "$wg/crypto" -I "$wg/crypto/refc" -I "$wg/crypto/legacy" -I "$mbed/include" -I "$mbed/library" \
    tests/test_wg_crypto.c "$wg/crypto/refc/chacha20.c" "$wg/crypto/refc/poly1305-donna.c" "$wg/crypto/refc/chacha20poly1305.c" \
    "$wg/crypto.c" "$wg/crypto/legacy/wg_crypto_legacy.c" "$wg/crypto/wg_crypto_bench.c" "$mbed/library/chacha20.c" "$mbed/library/poly1305.c" \
    "$mbed/library/chachapoly.c" "$mbed/library/platform_util.c" "$mbed/library/constant_time.c" -o build-host/test_wg_crypto
 build-host/test_wg_crypto 8000
done
python tools/test-usb-peer.py

python - <<'PYCODE'
from pathlib import Path
source=Path('components/microlink/src/ml_coord.c').read_text()
a=source.index('static int do_start_long_poll(')
b=source.index('/* Send a "lite" endpoint update',a)
Path('build-host/map_request.inc').write_text(source[a:b])
PYCODE
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I "$IDF_PATH/components/json/cJSON" tests/test_map_request.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_map_request
build-host/test_map_request
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I "$IDF_PATH/components/json/cJSON" tests/test_project_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_project_stream
build-host/test_project_stream
python - <<'PYCODE'
from pathlib import Path
s=Path('main/gateway_main.c').read_text();a=s.index('#include "json_writer.inc"');b=s.index('static esp_err_t command(',a)
Path('build-host/status_stream.inc').write_text(s[a:b]);Path('build-host/json_writer.inc').write_text(Path('main/json_writer.inc').read_text());Path('build-host/runtime_status.inc').write_text(Path('main/runtime_status.inc').read_text())
PYCODE
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I "$IDF_PATH/components/json/cJSON" tests/test_status_stream.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_status_stream
build-host/test_status_stream
python - <<'PYCODE'
from pathlib import Path
h=Path('components/microlink/include/microlink_internal.h').read_text();a=h.index('/* Peer update (from coord');b=h.index('/* ============================================================================',a);c=h.index('typedef struct {',h.index('#define ML_MAX_DERP_NODES'));d=h.index('/* ============================================================================',c)
Path('build-host/semantic_types.inc').write_text('#include "ml_derp_cert.h"\n'+h[a:b]+h[c:d])
s=Path('components/microlink/src/ml_coord.c').read_text();a=s.index('static void parse_peers_from_map_response(');b=s.index('/* Add Endpoints',a);c=s.index('static void decode_derp_regions(');d=s.index('static bool activate_derp_regions(',c)
Path('build-host/semantic_consumers.inc').write_text(s[a:b]+s[c:d])
w=Path('components/microlink/src/ml_wg_mgr.c').read_text();a=w.index('static void process_peer_updates(');b=w.index('/* ============================================================================',a);Path('build-host/batch_consumer.inc').write_text(w[a:b])
PYCODE
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I "$IDF_PATH/components/json/cJSON" tests/test_semantic_map.c components/microlink/src/ml_derp_cert.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_semantic_map
build-host/test_semantic_map
python - <<'PYCODE'
from pathlib import Path
s=Path('components/microlink/src/ml_coord.c').read_text();a=s.index('static int coord_send(');b=s.index('#include "coord_read.inc"',a);c=s.index('static int noise_send_owned(');d=s.index('/* Receive and decrypt',c)
Path('build-host/control_send.inc').write_text(s[a:b]+s[c:d])
PYCODE
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -pthread -I build-host -I "$mbed/include" -I "$mbed/library" tests/test_control_send.c "$mbed/library/chacha20.c" "$mbed/library/poly1305.c" "$mbed/library/chachapoly.c" "$mbed/library/platform_util.c" "$mbed/library/constant_time.c" -o build-host/test_control_send
build-host/test_control_send

python - <<'PYCODE'
from pathlib import Path
s=Path('components/microlink/src/ml_coord.c').read_text()
a=s.index('#include "coord_read.inc"');b=s.index('/* ============================================================================\n * Noise-encrypted',a)
c=s.index('static int noise_recv_buffer(');d=s.index('/* ============================================================================\n * State: DNS_RESOLVE',c)
e=s.index('static int do_h2_preface(');f=s.index('/* ============================================================================\n * State: REGISTER',e)
Path('build-host/receive_core.inc').write_text(s[a:b]+s[c:d]);Path('build-host/coord_read.inc').write_text(Path('components/microlink/src/coord_read.inc').read_text())
Path('build-host/h2_preface.inc').write_text(s[e:f])
h=Path('components/microlink/src/ml_h2.c').read_text();Path('build-host/h2_core.inc').write_text(h[h.index('static const char *TAG'):])
PYCODE
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -pthread -I build-host -I "$IDF_PATH/components/json/cJSON" -I "$mbed/include" -I "$mbed/library" tests/test_h2_handshake.c "$IDF_PATH/components/json/cJSON/cJSON.c" "$mbed/library/chacha20.c" "$mbed/library/poly1305.c" "$mbed/library/chachapoly.c" "$mbed/library/platform_util.c" "$mbed/library/constant_time.c" -o build-host/test_h2_handshake
build-host/test_h2_handshake
python tools/test-sockets.py
python tools/test-control-interop.py
python tools/test-journal.py

cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I components/microlink/include tests/test_peer_directory.c -o build-host/test_peer_directory
build-host/test_peer_directory
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I components/microlink/include -I "$IDF_PATH/components/json/cJSON" tests/test_semantic_directory.c components/microlink/src/ml_derp_cert.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_semantic_directory
build-host/test_semantic_directory

python - <<'PYJIT'
from pathlib import Path
s=Path('components/microlink/src/ml_wg_mgr.c').read_text();a=s.index('static int directory_activate_idle(');b=s.index('/* The queue owns copies',a);Path('build-host/jit_activation.inc').write_text(s[a:b])
a=s.index('static bool wg_initiation_plausible(');b=s.index('#endif',a);Path('build-host/wg_initiation.inc').write_text(s[a:b])
PYJIT
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I components/microlink/include tests/test_jit_directory.c -o build-host/test_jit_directory
build-host/test_jit_directory
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I components/microlink/include tests/test_inbound_trial.c -o build-host/test_inbound_trial
cc -std=c11 -fsanitize=address,undefined -g -I build-host tests/test_wg_initiation.c -o build-host/test_wg_initiation
build-host/test_wg_initiation
build-host/test_inbound_trial

python - <<'PYQUEUE'
from pathlib import Path
s=Path('components/microlink/src/ml_wg_mgr.c').read_text();a=s.index('esp_err_t ml_gateway_queue_packet(');b=s.index('#endif',a);Path('build-host/jit_queue.inc').write_text(s[a:b])
PYQUEUE
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host tests/test_jit_queue.c -o build-host/test_jit_queue
build-host/test_jit_queue

python tools/test-resilience.py

python tools/test-lcd.py
python3 tools/test-measurement-scripts.py
python3 tools/test-memory-report.py

# self_dns_name publication (seqlock) under a concurrent writer: address/undefined and thread sanitizers.
cc -std=c11 -Wall -Wextra -fsanitize=address,undefined -g -pthread tests/test_published_name.c -o build-host/test_published_name
build-host/test_published_name
cc -std=c11 -Wall -Wextra -fsanitize=thread -g -pthread tests/test_published_name.c -o build-host/test_published_name_tsan
build-host/test_published_name_tsan

# DERP TLS server authentication: real mbedTLS handshakes (TLS 1.2, peer certificate not kept, as on the
# device) through ml_derp_tls.c and the ESP-IDF esp_crt_bundle.c trust store, both compiled unchanged.
derp_tls_lib=build-host/mbedtls-derp
if [ ! -f "$derp_tls_lib/libmbedtls_derp.a" ] || [ tests/derp_tls_host_config.h -nt "$derp_tls_lib/libmbedtls_derp.a" ]; then
  rm -rf "$derp_tls_lib"; mkdir -p "$derp_tls_lib"
  ls "$mbed"/library/*.c | xargs -P 8 -I{} sh -c 'cc -O1 -w -DMBEDTLS_CONFIG_FILE="\"derp_tls_host_config.h\"" -I tests -I "$1/include" -I "$1/library" -c "$2" -o "$3/$(basename "$2" .c).o"' _ "$mbed" {} "$derp_tls_lib"
  ar rcs "$derp_tls_lib/libmbedtls_derp.a" "$derp_tls_lib"/*.o
fi
python tests/derp_pki.py build-host/derp-pki "$IDF_PATH/components/mbedtls/esp_crt_bundle/gen_crt_bundle.py"
cc -std=gnu11 -DCONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS=200 -fsanitize=address,undefined -g -DMBEDTLS_CONFIG_FILE='"derp_tls_host_config.h"' -I tests/host_esp -I tests \
  -I components/microlink/include -I "$mbed/include" -I "$mbed/library" -I "$IDF_PATH/components/mbedtls/esp_crt_bundle/include" \
  tests/test_derp_tls.c components/microlink/src/ml_derp_tls.c components/microlink/src/ml_derp_cert.c "$IDF_PATH/components/mbedtls/esp_crt_bundle/esp_crt_bundle.c" \
  "$derp_tls_lib/libmbedtls_derp.a" -o build-host/test_derp_tls
build-host/test_derp_tls build-host/derp-pki

# Shared entropy: ONE seeded CTR-DRBG for every membership (real mbedTLS), thread-safe, resident only while used.
for san in address,undefined thread; do
 cc -std=gnu11 -fsanitize=$san -g -Wall -Wextra -pthread -DMBEDTLS_CONFIG_FILE='"derp_tls_host_config.h"' -I tests -I components/microlink/include -I "$mbed/include" -I "$mbed/library" \
  tests/test_rng.c components/microlink/src/ml_rng.c "$derp_tls_lib/libmbedtls_derp.a" -o build-host/test_rng_${san%%,*}
 build-host/test_rng_${san%%,*}
done

# Control-plane Noise key: who vouches for it (real parse/fetch core of ml_coord.c, mock transport).
python - <<'PYKEY'
from pathlib import Path
s=Path('components/microlink/src/ml_coord.c').read_text()
a=s.index('/* Parse "[http[s]://]host[:port]" into bare host');b=s.index('/* --- end of the key-fetch core')
Path('build-host/key_fetch.inc').write_text(s[a:b])
h=Path('components/microlink/include/microlink_internal.h').read_text()
a=h.index('#define ML_CTRL_KEY_NONE');b=h.index('#define CTRL_KEY_PLAINTEXT');b=h.index('\n',b)
Path('build-host/ctrl_key_defs.inc').write_text(h[a:b]+'\n')
PYKEY
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I build-host -I "$IDF_PATH/components/json/cJSON" tests/test_control_key.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_control_key
build-host/test_control_key

# SNTP supervision and DERP pacing: a missing clock is retried, visible, and gates nothing else.
cc $TD_INC -std=c11 -fsanitize=address,undefined -g -I . tests/test_clock_sync.c -o build-host/test_clock_sync
build-host/test_clock_sync

# cJSON depth: the same limit the firmware build sets (CMakeLists.txt). No sanitizer here:
# it inflates frames and this test measures the parser's stack.
CJSON_LIMIT=$(sed -n 's/^set(TDONGLE_CJSON_NESTING_LIMIT \([0-9][0-9]*\)).*/\1/p' ../../CMakeLists.txt)
[[ -n "$CJSON_LIMIT" ]] || { echo 'TDONGLE_CJSON_NESTING_LIMIT not found in CMakeLists.txt' >&2; exit 1; }
cc $TD_INC -std=c11 -O1 -g -DCJSON_NESTING_LIMIT="$CJSON_LIMIT" -I "$IDF_PATH/components/json/cJSON" tests/test_json_depth.c "$IDF_PATH/components/json/cJSON/cJSON.c" -o build-host/test_json_depth
build-host/test_json_depth
