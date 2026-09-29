#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package only successfully built files; never flash a device."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import gzip
import os

def notice_sources(paths, project, idf):
    # IDF metadata includes empty entries for virtual components. Never interpret
    # those as the project root (which also contains the generated package).
    allowed=[project.resolve()/'components',project.resolve()/'managed_components',idf.resolve()/'components']
    seen=set()
    for component in paths:
        if not component:
            continue
        root=Path(component).resolve()
        if root in seen or not any(root.is_relative_to(base) and root!=base for base in allowed):
            continue
        seen.add(root)
        for item in root.rglob('*'):
            if item.is_file() and item.name.lower().startswith(('license','licence','copying','notice')):
                yield root,item


def archive_path(out):
    return out.parent / (out.name + ".tar.gz")


def main():
    build, variant = Path(sys.argv[1]), sys.argv[2]
    # Local builds stay 0.1.0 so tools/flash.sh finds dist/tdongle-0.1.0-*; the release workflow
    # sets TDONGLE_VERSION from the git tag.
    version = os.environ.get('TDONGLE_VERSION', '0.1.0')
    out = Path('dist') / f'tdongle-{version}-{variant}'
    files = {'tdongle_adapter.bin': 'app.bin', 'bootloader/bootloader.bin': 'bootloader.bin',
             'partition_table/partition-table.bin': 'partition-table.bin',
             'tdongle_adapter.elf': 'tdongle_adapter.elf', 'sdkconfig': 'sdkconfig',
             'flasher_args.json': 'flasher_args.original.json'}
    for source in files:
        if not (build / source).is_file():
            raise SystemExit(f'Missing build result: {source}; no package created')
    out.mkdir(parents=True, exist_ok=True)
    for source, target in files.items():
        shutil.copyfile(build / source, out / target)
    for source in ['dependencies.lock', 'LICENSE', 'docs/SOURCE_AUDIT.md', 'docs/THIRD_PARTY.md']:
        shutil.copyfile(source, out / Path(source).name)
    shutil.copytree('licenses', out / 'licenses', dirs_exist_ok=True)
    description=json.loads((build/'project_description.json').read_text())
    for root,item in notice_sources(description['build_component_paths'],Path.cwd(),Path(description['idf_path'])):
        target=out/'dependency-notices'/root.name/item.relative_to(root)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(item,target)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip())
    (out / 'manifest.json').write_text(json.dumps({'version': version, 'variant': variant, 'git_commit': revision, 'dirty': dirty,
        'idf_commit': 'b774170ff46c393eeb5e495ea37936038d3f4f4f', 'target': 'esp32s3', 'flash_bytes': 16*1024*1024,
        'offsets': {'bootloader.bin': '0x0', 'partition-table.bin': '0x8000', 'app.bin': '0x20000'},
        'hardware_tested': False}, indent=2)+'\n')
    (out / 'FLASH.txt').write_text('Original T-Dongle-S3 only; hardware not validated. Confirm chip/flash before flashing.\n'
        'User-authorized flash only. Use tools/flash.sh (no button needed once the firmware runs); or hold BOOT while plugging in for ROM mode.\n'
        'python -m esptool --chip esp32s3 --port PORT write_flash --flash_mode dio --flash_freq 40m --flash_size 16MB '
        '0x0 bootloader.bin 0x8000 partition-table.bin 0x20000 app.bin\n')
    checksums=[]
    for p in sorted(out.rglob('*')):
        if p.is_file() and p.name != 'SHA256SUMS':
            checksums.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out)}')
    (out / 'SHA256SUMS').write_text('\n'.join(checksums)+'\n')
    archive=archive_path(out)
    with archive.open('wb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as zipped:
            with tarfile.open(fileobj=zipped,mode='w') as tar:
                for item in sorted(out.rglob('*')):
                    if item.is_file():
                        info=tar.gettarinfo(str(item),str(Path(out.name)/item.relative_to(out)))
                        info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
                        with item.open('rb') as data:tar.addfile(info,data)
    Path(str(archive)+'.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
    print(f'Built firmware package: {out} and {archive}')


if __name__ == "__main__":
    main()
