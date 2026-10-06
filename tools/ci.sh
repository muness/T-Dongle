#!/usr/bin/env bash
# What CI runs, runnable locally with the pinned ESP-IDF sourced:
#   tools/ci.sh [all|release]
# all      host tests, tailnet gateway tests, release firmware, diagnostics firmware (pull requests, main)
# release  host tests, tailnet gateway tests, release firmware (the release workflow)
# TDONGLE_VERSION, when set, becomes the firmware and package version (see tools/build.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
: "${IDF_PATH:?Source the pinned ESP-IDF export.sh first}"
scope="${1:-all}"
[[ "$scope" == all || "$scope" == release ]] || { echo 'Usage: tools/ci.sh [all|release]' >&2; exit 2; }
# The control-protocol interoperability test runs a Go program.
command -v go >/dev/null || { echo 'Go is required (alternative/tailnet/tools/test-control-interop.py)' >&2; exit 1; }
TEST_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' tools/test.sh
alternative/tailnet/tools/test-gateway.sh
tools/build.sh release
[[ "$scope" == all ]] && tools/build.sh diagnostics
exit 0
