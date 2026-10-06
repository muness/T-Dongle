#!/bin/sh
# Rebuild tests/golden/* from the real C sources. Needs a host C compiler (`cc`) and python3; nothing else (no ESP-IDF).
# The output is checked in; run this only when a C source or a scenario changes, and review the diff of the .golden files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
exec python3 "$here/gen_golden.py" "$@"
