#!/usr/bin/env bash
# Run the Android app's own management client (its unmodified Java sources) against the Rust firmware's console replies. Never touches a board.
#   rust/tools/android_replay.sh [APP_CORE_SRC]
# APP_CORE_SRC is the app's core/src/main/java (default: ~/src/tdongle-android/.worktrees/multi-tailnet/core/src/main/java). Needs a JDK 17 (javac, java).
# Set EXPECT_NEGATIVE_TEMPERATURE=1 for an app build that shows chip temperatures below zero.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=${1:-$HOME/src/tdongle-android/.worktrees/multi-tailnet/core/src/main/java}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
(cd "$here/.." && TDONGLE_ANDROID_REPLAY_OUT="$out" cargo +stable test -q -p tdongle-serial --test android_app write_replay_fixtures >/dev/null)
mkdir -p "$out/classes"
javac -d "$out/classes" $(find "$src/com/muness/tdongle/core" -name '*.java') "$here/android_replay/Replay.java"
java ${EXPECT_NEGATIVE_TEMPERATURE:+-DexpectNegativeTemperature=1} -cp "$out/classes" com.muness.tdongle.core.Replay "$out/replies.fixture"
