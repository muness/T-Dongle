#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assemble the browser flash site from a built package.

Usage: tools/site.py DIST_PACKAGE_DIR VERSION OUT_DIR

Writes OUT_DIR/index.html, OUT_DIR/manifest.json and OUT_DIR/firmware/vVERSION/*.bin. The manifest
lists bootloader, partition table and app at their own offsets. A merged image is deliberately not
used: it would write blank bytes over the settings partition at 0x9000 and wipe saved networks on
every update.
"""
import json
import shutil
import sys
from pathlib import Path

PARTS = [('bootloader.bin', 0x0), ('partition-table.bin', 0x8000), ('app.bin', 0x20000)]


def main():
    package, version, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    fw = out / 'firmware' / f'v{version}'
    fw.mkdir(parents=True, exist_ok=True)
    for name, _ in PARTS:
        shutil.copyfile(package / name, fw / name)
    shutil.copyfile(Path(__file__).resolve().parent.parent / 'site' / 'index.html', out / 'index.html')
    manifest = {
        'name': 'T-Dongle',
        'version': version,
        'new_install_prompt_erase': True,
        'builds': [{'chipFamily': 'ESP32-S3',
                    'parts': [{'path': f'firmware/v{version}/{name}', 'offset': offset}
                              for name, offset in PARTS]}],
    }
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (out / '.nojekyll').write_text('')


if __name__ == '__main__':
    main()
