#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect the built firmware itself, not source guesses.

Usage: check_build.py BUILD_DIR VARIANT   (VARIANT: release or diagnostics)

Checks the effective sdkconfig, the flash parameters written into the bootloader and app image
headers, the partition table layout (saved Wi-Fi networks and tailnet identities live in NVS at
0x9000: it must not move) and the USB descriptors linked into the ELF.
"""
import json
from pathlib import Path
import struct
import sys
from elftools.elf.elffile import ELFFile

build = Path(sys.argv[1]); variant = sys.argv[2]
assert variant in ('release', 'diagnostics'), variant
config = (build / 'sdkconfig').read_text()
for opt in ('CONFIG_IDF_TARGET="esp32s3"', 'CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y', '# CONFIG_SPIRAM is not set',
            'CONFIG_TINYUSB_NET_MODE_NCM=y', 'CONFIG_TINYUSB_CDC_ENABLED=y', 'CONFIG_TINYUSB_CDC_COUNT=1',
            'CONFIG_APP_REPRODUCIBLE_BUILD=y',
            # The tested W25Q128 boot-loops at QIO 80 MHz; ESP-IDF's own default is 80 MHz.
            'CONFIG_ESPTOOLPY_FLASHMODE_DIO=y', 'CONFIG_ESPTOOLPY_FLASHFREQ_40M=y',
            'CONFIG_PARTITION_TABLE_CUSTOM=y', 'CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y',
            # Roaming assist (802.11k/v) is built into the one image; the station asks for it per mode (sdkconfig.defaults).
            'CONFIG_ESP_WIFI_11KV_SUPPORT=y', 'CONFIG_ESP_WIFI_RRM_SUPPORT=y', 'CONFIG_ESP_WIFI_WNM_SUPPORT=y',
            # The setup access point is open by owner decision (tests/test_open_ap.py guards the source).
            'CONFIG_TDONGLE_SETUP_AP_OPEN=y'):
    # Kconfig silently drops a default whose dependency is off or that a stale cached sdkconfig overrides.
    assert opt in config, f'{opt} missing from the effective sdkconfig (stale build directory sdkconfig?)'
diagnostics_option = 'CONFIG_TDONGLE_MEMORY_DIAGNOSTICS=y' in config
assert diagnostics_option == (variant == 'diagnostics'), 'diagnostics options must be on in the diagnostics image and only there'

# Image header (esp_image_header_t): byte 0 magic 0xE9, byte 2 flash mode (2 = DIO), byte 3 = size nibble << 4 | freq nibble.
FLASH_MODES = {0: 'qio', 1: 'qout', 2: 'dio', 3: 'dout'}
FLASH_FREQS = {0x0: '40m', 0x1: '26m', 0x2: '20m', 0xF: '80m'}
FLASH_SIZES = {0x0: '1MB', 0x1: '2MB', 0x2: '4MB', 0x3: '8MB', 0x4: '16MB'}
def header(path):
    data = Path(path).read_bytes()
    assert data[0] == 0xE9, f'{path}: not an ESP image'
    return dict(mode=FLASH_MODES[data[2]], freq=FLASH_FREQS[data[3] & 0xF], size=FLASH_SIZES[data[3] >> 4])
images = {}
for name, source in (('bootloader.bin', 'bootloader/bootloader.bin'), ('app.bin', 'tdongle.bin')):
    images[name] = header(build / source)
    assert images[name] == dict(mode='dio', freq='40m', size='16MB'), f'{name} header {images[name]}: must be DIO, 40 MHz, 16 MB'

# Partition table: NVS and the app keep their v0.1.x offsets, so updating without erase keeps saved data.
table = (build / 'partition_table/partition-table.bin').read_bytes()
partitions = {}
for i in range(0, len(table) - 32, 32):
    magic, kind, subtype, offset, size = struct.unpack_from('<HBBII', table, i)
    if magic != 0x50AA:
        break
    partitions[table[i + 12:i + 28].split(b'\0')[0].decode()] = (kind, subtype, offset, size)
assert partitions['nvs'] == (1, 2, 0x9000, 0x10000), partitions.get('nvs')
assert partitions['phy_init'][2:] == (0x19000, 0x1000), partitions.get('phy_init')
assert partitions['factory'] == (0, 0, 0x20000, 0x400000), partitions.get('factory')
app_size = (build / 'tdongle.bin').stat().st_size
assert app_size <= 0x400000, f'app.bin {app_size} bytes does not fit the factory partition'
assert all(offset + size <= 16 * 1024 * 1024 for _, _, offset, size in partitions.values())

with (build / 'tdongle.elf').open('rb') as f:
    elf = ELFFile(f); sym = elf.get_section_by_name('.symtab')
    def value(name):
        entry = sym.get_symbol_by_name(name)[0]
        section = elf.get_section(entry['st_shndx'])
        offset = entry['st_value'] - section['sh_addr']
        return section.data()[offset:offset + entry['st_size']]
    device = value('descriptor_dev_default')
    descriptors = value('descriptor_fs_cfg_default')
assert device[0:2] == bytes([18, 1])
vid, pid = struct.unpack_from('<HH', device, 8)
assert descriptors[0:2] == bytes([9, 2])
assert struct.unpack_from('<H', descriptors, 2)[0] == len(descriptors)
assert descriptors[8] * 2 == 500
interfaces = []; i = 0
while i < len(descriptors):
    length, kind = descriptors[i:i + 2]; assert length >= 2
    d = descriptors[i:i + length]; assert len(d) == length
    if kind == 4: interfaces.append(dict(number=d[2], alt=d[3], cls=d[5], subclass=d[6], protocol=d[7]))
    i += length
assert any(d['cls'] == 2 and d['subclass'] == 13 for d in interfaces), 'NCM control interface absent'
assert any(d['cls'] == 2 and d['subclass'] == 2 for d in interfaces), 'CDC-ACM management console absent'
assert any(d['cls'] == 10 and d['alt'] == 1 for d in interfaces)
# The traffic counters wrap two TinyUSB NCM callbacks at link time (main/traffic_hooks.c): the wrappers must be in the image, and the
# USB product strings of both modes (usb_identity.h) must be in it as UTF-8 source strings.
image = (build / 'tdongle.elf').read_bytes()
with (build / 'tdongle.elf').open('rb') as f:
    symbols = ELFFile(f).get_section_by_name('.symtab')
    for name in ('__wrap_tud_network_recv_cb', '__wrap_tud_network_xmit_cb'):
        assert symbols.get_symbol_by_name(name), f'{name} missing: the traffic counters are not wired in'
for text in (b'T-Dongle-S3 NCM\0', b'T-Dongle-S3 tailnet gateway\0'):
    assert text in image, f'USB product string {text[:-1].decode()!r} missing from the image'
print(json.dumps({'compiled_descriptors': 'PASS', 'variant': variant, 'vid': hex(vid), 'pid': hex(pid), 'usb_max_power_ma': 500,
                  'flash': images['app.bin'], 'bootloader_flash': images['bootloader.bin'], 'app_bytes': app_size,
                  'partitions': {k: [hex(v[2]), hex(v[3])] for k, v in partitions.items()}, 'interfaces': interfaces}, indent=2))
