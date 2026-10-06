#!/usr/bin/env python3
"""Inspect the built Rust image itself, not source guesses (the counterpart of tools/check_build.py for the C image).

Usage: check_image.py DIST_DIR ELF IDF_OUT_DIR

Checks: the flash parameters in the bootloader and app image headers (DIO, 40 MHz, 16 MB: the tested T-Dongle-S3 boot-loops at QIO 80 MHz), the
effective sdkconfig, the partition table in the merged image against the C firmware's partitions.csv (saved Wi-Fi networks live in NVS at 0x9000 and
must not move), the app size against the factory partition, the USB identity symbols in the ELF, and that the Wi-Fi tx-done callback (which the
driver runs while the flash cache is off) calls nothing outside IRAM.
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

dist, elf, idf_out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
repo = Path(__file__).resolve().parents[2]

FLASH_MODES = {0: 'qio', 1: 'qout', 2: 'dio', 3: 'dout'}
FLASH_FREQS = {0x0: '40m', 0x1: '26m', 0x2: '20m', 0xF: '80m'}
FLASH_SIZES = {0x0: '1MB', 0x1: '2MB', 0x2: '4MB', 0x3: '8MB', 0x4: '16MB'}


def header(data, name):
    assert data[0] == 0xE9, f'{name}: not an ESP image'
    found = dict(mode=FLASH_MODES[data[2]], freq=FLASH_FREQS[data[3] & 0xF], size=FLASH_SIZES[data[3] >> 4])
    assert found == dict(mode='dio', freq='40m', size='16MB'), f'{name} header {found}: must be DIO, 40 MHz, 16 MB'


header((dist / 'bootloader.bin').read_bytes(), 'bootloader.bin')
header((dist / 'app.bin').read_bytes(), 'app.bin')
merged = (dist / 'merged.bin').read_bytes()
assert len(merged) == 16 * 1024 * 1024, 'the merged image must cover the whole 16 MB flash'
header(merged[0x0:], 'merged.bin bootloader (offset 0)')
assert merged[0x20000] == 0xE9, 'the app image must sit at the factory offset 0x20000'
header(merged[0x20000:], 'merged.bin app (offset 0x20000)')

# Partition table: parse the one in the merged image (0x8000) and compare with the C firmware's CSV.
table = merged[0x8000:0x8000 + 0xC00]
parts = {}
for i in range(0, len(table) - 32, 32):
    magic, kind, subtype, offset, size = struct.unpack_from('<HBBII', table, i)
    if magic != 0x50AA:
        break
    parts[table[i + 12:i + 28].split(b'\0')[0].decode()] = (kind, subtype, offset, size)
csv = {}
for line in (repo / 'partitions.csv').read_text().splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    name, _kind, _sub, offset, size, *_ = [f.strip() for f in line.split(',')]
    csv[name] = (int(offset, 0), int(size, 0))
for name, (offset, size) in csv.items():
    assert parts[name][2:] == (offset, size), f'partition {name}: {parts[name]} differs from partitions.csv'
assert parts['nvs'] == (1, 2, 0x9000, 0x10000), parts['nvs']
assert parts['factory'] == (0, 0, 0x20000, 0x400000), parts['factory']
app_size = (dist / 'app.bin').stat().st_size
assert app_size <= 0x400000, f'app.bin {app_size} bytes does not fit the factory partition'

# Effective sdkconfig of the ESP-IDF build under the Rust crate.
config = (idf_out / 'sdkconfig').read_text()
for option in ('CONFIG_ESPTOOLPY_FLASHMODE_DIO=y', 'CONFIG_ESPTOOLPY_FLASHFREQ_40M=y', 'CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y', '# CONFIG_SPIRAM is not set',
               'CONFIG_PM_ENABLE=y', 'CONFIG_FREERTOS_HZ=100', 'CONFIG_ESP_WIFI_11KV_SUPPORT=y', 'CONFIG_ESP_WIFI_RRM_SUPPORT=y',
               'CONFIG_ESP_WIFI_WNM_SUPPORT=y', 'CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y', 'CONFIG_APP_REPRODUCIBLE_BUILD=y'):
    assert option in config, f'{option} missing from the effective sdkconfig'

# Symbols that must be linked in.
nm = subprocess.run(['nm', str(elf)], capture_output=True, text=True)
symbols = nm.stdout if nm.returncode == 0 else subprocess.run(['xtensa-esp32s3-elf-nm', str(elf)], capture_output=True, text=True, check=True).stdout
for needed in ('tud_descriptor_configuration_cb', 'tud_descriptor_string_cb', 'tud_network_recv_cb', 'tud_network_xmit_cb', '__wrap_netd_xfer_cb', 'tud_cdc_rx_cb'):
    assert re.search(rf'\b{needed}\b', symbols), f'{needed} is not in the ELF'

# IRAM rule (ADR 0001 rule 4): the tx-done callback runs in the pp task while the flash cache may be off, so it must live in IRAM and call only
# IRAM code. Rust function names are mangled; the callback is `wifi::pins::tx_done`.
tool = lambda name: name if subprocess.run(['which', name], capture_output=True).returncode == 0 else 'xtensa-esp32s3-elf-' + name
sized = subprocess.run([tool('nm'), '-S', str(elf)], capture_output=True, text=True, check=True).stdout
match = re.search(r'^([0-9a-f]{8}) ([0-9a-f]{8}) [tT] _R\w*4wifi4pins7tx_done$', sized, re.M)
if not match:
    sys.exit('the tx-done callback (wifi::pins::tx_done) is not in the ELF')
start, size = int(match.group(1), 16), int(match.group(2), 16)
IRAM = range(0x40370000, 0x403E0000)
assert start in IRAM, f'the tx-done callback is at {start:#x}, outside IRAM: its #[link_section] was lost'
disassembly = subprocess.run(['xtensa-esp32s3-elf-objdump', '-d', '--no-show-raw-insn', f'--start-address={start:#x}', f'--stop-address={start + size:#x}', str(elf)],
                             capture_output=True, text=True, check=True).stdout
# Direct calls, and indirect ones through a literal (`l32r aN, ... (ADDR <symbol>)` then `callxN aN`): every code address the function loads must be
# in IRAM or in the ROM (below 0x40060000), never in flash-mapped code (0x42xxxxxx).
for target in re.findall(r'\bcall\d+\s+(0x[0-9a-f]+)', disassembly):
    assert int(target, 16) in IRAM, f'the tx-done callback calls {target}, outside IRAM (a callee that is not #[inline(always)])'
for address, symbol in re.findall(r'l32r\s+a\d+, [^(]*\(([0-9a-f]{8}) <([^>]+)>\)', disassembly):
    value = int(address, 16)
    if 0x40000000 <= value < 0x50000000:
        assert value < 0x40060000 or value in IRAM, f'the tx-done callback reaches {symbol} at {address}, outside IRAM'
print(f'tx-done callback: {size} bytes at {start:#x} (IRAM), direct calls all IRAM')
print(f'image ok: app.bin {app_size} bytes (C image: 1,333,360), DIO 40 MHz 16 MB, partition table = partitions.csv')
