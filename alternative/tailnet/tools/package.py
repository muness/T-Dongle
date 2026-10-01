#!/usr/bin/env python3
"""Package an explicitly experimental, NVS-preserving companion payload."""
import hashlib,json,pathlib,shutil
root=pathlib.Path(__file__).resolve().parents[1]
out=root/'dist';out.mkdir(exist_ok=True)
images=[]
for source,name,offset in [('bootloader/bootloader.bin','bootloader.bin',0),('partition_table/partition-table.bin','partition-table.bin',0x8000),('tdongle_tailnet.bin','app.bin',0x20000)]:
    data=(root/'build'/source).read_bytes();(out/name).write_bytes(data)
    images.append(dict(name=name,offset=offset,sha256=hashlib.sha256(data).hexdigest()))
(out/'android-firmware.json').write_text(json.dumps(dict(schema=1,board='tdongle-s3-original',managementProtocol=1,layout='factory-nvs-v1',version='0.2.0',variant='tailnet-gateway-experimental',hardwareQualified=False,images=images),indent=2)+'\n')
shutil.copyfile(root/'README.md',out/'README.md')
