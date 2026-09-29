#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect actual linked USB descriptors and build configuration, not source guesses."""
import json
from pathlib import Path
import struct
import sys
from elftools.elf.elffile import ELFFile

build=Path(sys.argv[1]);variant=sys.argv[2]
config=(build/'sdkconfig').read_text()
assert 'CONFIG_IDF_TARGET="esp32s3"' in config
assert 'CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y' in config
assert '# CONFIG_SPIRAM is not set' in config
assert 'CONFIG_TINYUSB_NET_MODE_NCM=y' in config
assert 'CONFIG_APP_REPRODUCIBLE_BUILD=y' in config
# The setup AP is passwordless by owner decision. A stale cached sdkconfig once dropped this silently.
# Kconfig silently drops a default whose dependency is off; fail instead of shipping without it.
for opt in ('CONFIG_ESP_WIFI_11KV_SUPPORT=y','CONFIG_ESP_WIFI_RRM_SUPPORT=y','CONFIG_ESP_WIFI_WNM_SUPPORT=y',
            'CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT=4'):
    assert opt in config, f'{opt} missing from effective sdkconfig (dependency off or stale build sdkconfig)'
assert 'CONFIG_ADAPTER_OPEN_SETUP_AP=y' in config, 'setup AP must be open (no password); delete the stale build sdkconfig'
with (build/'tdongle_adapter.elf').open('rb') as f:
    elf=ELFFile(f);sym=elf.get_section_by_name('.symtab')
    def value(name):
        entry=sym.get_symbol_by_name(name)[0]
        section=elf.get_section(entry['st_shndx'])
        offset=entry['st_value']-section['sh_addr']
        return section.data()[offset:offset+entry['st_size']]
    device=value('descriptor_dev_default')
    descriptors=value('descriptor_fs_cfg_default')
assert device[0:2]==bytes([18,1])
vid,pid=struct.unpack_from('<HH',device,8)
assert descriptors[0:2]==bytes([9,2])
assert struct.unpack_from('<H',descriptors,2)[0]==len(descriptors)
assert descriptors[8]*2==500
interfaces=[];i=0
while i<len(descriptors):
    length,kind=descriptors[i:i+2];assert length>=2
    d=descriptors[i:i+length];assert len(d)==length
    if kind==4:interfaces.append(dict(number=d[2],alt=d[3],cls=d[5],subclass=d[6],protocol=d[7]))
    i+=length
assert any(d['cls']==2 and d['subclass']==13 for d in interfaces), 'NCM control interface absent'
acm=any(d['cls']==2 and d['subclass']==2 for d in interfaces)
assert acm==(variant!='network-only')
assert any(d['cls']==10 and d['alt']==1 for d in interfaces)
print(json.dumps({'compiled_descriptors':'PASS','variant':variant,'vid':hex(vid),'pid':hex(pid),'usb_max_power_ma':500,'interfaces':interfaces},indent=2))
