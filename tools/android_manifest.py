#!/usr/bin/env python3
"""Release-owned Android compatibility descriptor; no app-side version table."""
import hashlib,json,re,sys
from pathlib import Path

def descriptor(package, version):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",version):
        raise ValueError("Release version must be numeric semantic version")
    images=[]
    for name,offset in (("bootloader.bin",0),("partition-table.bin",0x8000),("app.bin",0x20000)):
        data=(package/name).read_bytes()
        if not data: raise ValueError("Empty firmware image")
        images.append({"name":name,"offset":offset,"sha256":hashlib.sha256(data).hexdigest()})
    return {"schema":1,"board":"tdongle-s3-original","managementProtocol":1,"layout":"factory-nvs-v1","version":version,"images":images}

if __name__ == "__main__":
    package=Path(sys.argv[1]); (package/"android-firmware.json").write_text(json.dumps(descriptor(package,sys.argv[2]),indent=2)+"\n")
