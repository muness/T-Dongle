#!/usr/bin/env python3
"""Package the Rust image in the C package's layout (bootloader.bin 0x0, partition-table.bin 0x8000, app.bin 0x20000, manifest.json, SHA256SUMS, tar.gz). Never flashes.

Usage: package.py VERSION APP_BIN ELF [OUT_DIR]   (the rescue bootloader is rust/bootloader/bootloader-rescue.bin, checked against rust/bootloader/SHA256)
TDONGLE_FIRMWARE_SOURCE selects the commit used to build the supplied image (defaults to HEAD).
Example: TDONGLE_FIRMWARE_SOURCE=fb43561 python3 rust/tools/package.py 0.4.0-rc2 APP_BIN ELF OUT_DIR
manifest.json records firmware_git_commit separately from git_commit, the packaging checkout.
This records the declared build source; the caller must supply the corresponding image and ELF.
"""
import gzip, hashlib, json, os, struct, subprocess, sys, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TYPES = {'app': 0, 'data': 1}
SUBTYPES = {'factory': 0, 'nvs': 2, 'phy': 1, 'fat': 0x81, 'coredump': 3}


def partition_table(csv: Path) -> bytes:
    out = b''
    for line in csv.read_text().splitlines():
        line = line.split('#')[0].strip()
        if not line:
            continue
        name, typ, sub, off, size, *flags = [f.strip() for f in line.split(',')]
        out += struct.pack('<HBBLL16sL', 0x50AA, TYPES[typ], SUBTYPES[sub], int(off, 0), int(size, 0), name.encode(), 0)
    md5 = hashlib.md5(out).digest()
    out += b'\xeb\xeb' + b'\xff' * 14 + md5
    return out + b'\xff' * (0xC00 - len(out))


def main():
    version, app, elf = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    out = Path(sys.argv[4]) if len(sys.argv) > 4 else ROOT / 'dist' / f'tdongle-rust-{version}-package' / f'tdongle-{version}'
    # Resolve provenance before writing any package files. Pin Git to this
    # checkout, even when packaging is invoked from another working directory.
    git = ['git', '-C', str(ROOT.parent)]
    rev = subprocess.check_output(git + ['rev-parse', '--verify', 'HEAD^{commit}'], text=True).strip()
    source = os.environ.get('TDONGLE_FIRMWARE_SOURCE', 'HEAD')
    firmware_rev = subprocess.check_output(git + ['rev-parse', '--verify', '--end-of-options', source + '^{commit}'], text=True).strip()
    dirty = bool(subprocess.check_output(git + ['status', '--porcelain'], text=True).strip())
    boot = ROOT / 'bootloader' / 'bootloader-rescue.bin'
    assert hashlib.sha256(boot.read_bytes()).hexdigest() == (ROOT / 'bootloader' / 'SHA256').read_text().split()[0], 'bootloader hash is not the recorded one'
    for name, data in (('bootloader', boot.read_bytes()), ('app', app.read_bytes())):
        assert data[0] == 0xE9 and data[2:4] == b'\x02\x40', f'{name}: not DIO / 40 MHz / 16 MB'
    assert f'firmware={version}'.encode() in app.read_bytes() or f'{version}'.encode() in app.read_bytes(), 'the version is not in the app image'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'app.bin').write_bytes(app.read_bytes())
    (out / 'bootloader.bin').write_bytes(boot.read_bytes())
    (out / 'partition-table.bin').write_bytes(partition_table(ROOT / 'firmware' / 'partitions.csv'))
    (out / 'tdongle.elf').write_bytes(elf.read_bytes())
    for f in ('LICENSE',):
        src = ROOT.parent / f
        if src.exists():
            (out / f).write_bytes(src.read_bytes())
    (out / 'manifest.json').write_text(json.dumps({'version': version, 'variant': 'rust', 'git_commit': rev, 'firmware_git_commit': firmware_rev, 'dirty': dirty, 'target': 'esp32s3', 'flash_bytes': 16 * 1024 * 1024,
        'flash_mode': 'dio', 'flash_freq': '40m', 'default_mode': 'wifi_bridge', 'firmware': 'rust-no_std',
        'offsets': {'bootloader.bin': '0x0', 'partition-table.bin': '0x8000', 'app.bin': '0x20000'}, 'hardware_tested': False}, indent=2) + '\n')
    images = [dict(name=n, offset=o, sha256=hashlib.sha256((out / n).read_bytes()).hexdigest()) for n, o in (('bootloader.bin', 0), ('partition-table.bin', 0x8000), ('app.bin', 0x20000))]
    (out / 'android-firmware.json').write_text(json.dumps(dict(schema=1, board='tdongle-s3-original', managementProtocol=1, layout='factory-nvs-v1', version=version, variant='rust', hardwareQualified=False, images=images), indent=2) + '\n')
    (out / 'FLASH.txt').write_text('Original T-Dongle-S3 only.\nFrom the repository root, flash this package with:\n  rust/tools/flash.sh /absolute/path/to/this/package-directory\nThe helper checks the designated dongle MAC, enters download mode, uses --before no_reset and --after watchdog_reset, closes serial handles, and verifies a healthy running boot.\nNever use esptool --after hard_reset: it re-enters download mode on this board.\nDo not erase_flash for an update: saved networks live in NVS at 0x9000.\nIf boot fails, immediately use rust/tools/flash.sh --recover with the known-good image; hold BOOT while replugging only if the helper asks.\n')
    (out / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(out.iterdir()) if p.is_file() and p.name != 'SHA256SUMS'))
    archive = out.parent / (out.name + '.tar.gz')
    with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as z, tarfile.open(fileobj=z, mode='w') as tar:
        for item in sorted(out.rglob('*')):
            if item.is_file():
                info = tar.gettarinfo(str(item), str(Path(out.name) / item.relative_to(out)))
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                with item.open('rb') as d:
                    tar.addfile(info, d)
    Path(str(archive) + '.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
    print(f'package: {out} and {archive}')


if __name__ == '__main__':
    main()
