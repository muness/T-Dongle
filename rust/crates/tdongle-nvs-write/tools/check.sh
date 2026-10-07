#!/bin/sh
# Run every check of this crate against ESP-IDF itself, failing (not skipping) when IDF's python environment or a C++ compiler is missing:
#   - tools/verify_with_idf.py (nvs_parser.py + nvs_check.py) on every image the tests export,
#   - tools/idf_c_check (ESP-IDF's own C++ NVS engine, built from $IDF_PATH) as reader and as writer,
# and the power-loss sweeps at every cut point (NVS_SWEEP_STRIDE=1; a cut during the mounting repair is tried for every 23rd crash image,
# NVS_MOUNT_CUT_EVERY=1 for all: hours). The default `cargo test` run samples and takes about 30 s.
# Usage: tools/check.sh [extra cargo test args]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
export TDONGLE_REQUIRE_IDF=1
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$here/../../../target-host}
cd "$here/../../.."
NVS_SWEEP_STRIDE=${NVS_SWEEP_STRIDE:-1} NVS_MOUNT_CUT_EVERY=${NVS_MOUNT_CUT_EVERY:-23} NVS_C_SAMPLES=${NVS_C_SAMPLES:-300} NVS_IDF_SAMPLES=${NVS_IDF_SAMPLES:-60} \
  exec cargo +stable test -p tdongle-nvs-write --release "$@"
