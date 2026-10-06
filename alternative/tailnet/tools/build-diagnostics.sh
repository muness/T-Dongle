#!/usr/bin/env bash
# Build the memory-diagnostics image (never a release): owner-tagged heap, per-phase join capture,
# admission override and the serial "memory" / "members" commands. See docs/memory-diagnostics.md.
#   alternative/tailnet/tools/build-diagnostics.sh [--queue-depth 1|2|4|8|12|16]
# Same as tools/build.sh diagnostics. Output: <repo>/build-diagnostics[-q<N>]/
exec "$(dirname "$0")/../../../tools/build.sh" diagnostics "$@"
