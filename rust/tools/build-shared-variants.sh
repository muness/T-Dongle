#!/usr/bin/env bash
# Build the two board images from one checkout and the same shared crate sources.
# Requires the toolchains in rust/rust-toolchain.toml and c5-firmware/rust-toolchain.toml.
# Never accesses USB devices or flashes hardware.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/cargo-target}"
cargo +1.98.1 test --locked -p tdongle-wifi-policy -p tdongle-serial-ip -p tdongle-tailnet-usbnet -p tdongle-tailnet-wifimux -- --test-threads=1
tools/build-c5.sh
tools/build_tailnet.sh
# Record source provenance beside both image sets, without claiming hardware validation.
python3 - <<'PYTHON'
import json, os, pathlib, subprocess
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip())
record = {'commit': revision, 'workingTreeDirty': dirty, 'hardwareTested': False,
          'variants': ['c5-serial-ip', 's3-tailnet-' + os.environ.get('MEMBERS', 'members-1')]}
pathlib.Path('dist/shared-variants.json').write_text(json.dumps(record, indent=2) + '\n')
PYTHON
