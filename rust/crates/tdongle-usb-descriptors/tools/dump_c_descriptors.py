#!/usr/bin/env python3
"""Dump the USB descriptors the C firmware enumerates with, from its linked ELF, into tests/golden/.

Usage: dump_c_descriptors.py path/to/tdongle.elf   (needs pyelftools: the ESP-IDF Python environment has it)

The C descriptors come from esp_tinyusb's usb_descriptors.c (`descriptor_dev_default`, `descriptor_fs_cfg_default`) for CDC x1 + NCM; the Rust
firmware must enumerate identically so a host that knows the adapter keeps its device and interface identity across the switch.
"""
import sys
from pathlib import Path
from elftools.elf.elffile import ELFFile

elf = ELFFile(open(sys.argv[1], 'rb'))
symbols = {s.name: s for s in elf.get_section_by_name('.symtab').iter_symbols()}
out = Path(__file__).resolve().parent.parent / 'tests' / 'golden'


def read(name):
    symbol = symbols[name]
    address, size = symbol['st_value'], symbol['st_size']
    for section in elf.iter_sections():
        if section['sh_addr'] <= address < section['sh_addr'] + section['sh_size'] and section['sh_type'] != 'SHT_NOBITS':
            offset = address - section['sh_addr']
            return section.data()[offset:offset + size]
    raise SystemExit(f'{name}: not in a loadable section')


(out / 'c_device_descriptor.bin').write_bytes(read('descriptor_dev_default'))
(out / 'c_config_descriptor_fs.bin').write_bytes(read('descriptor_fs_cfg_default'))
print('wrote', out)
