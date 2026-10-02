#!/usr/bin/env python3
from pathlib import Path
import os,subprocess
r=Path(__file__).resolve().parents[1];build=r/'build-host';build.mkdir(exist_ok=True)
s=(r/'main/gateway_main.c').read_text();a=s.index('static bool save_members(');b=s.index('static bool stop_member(',a)
(build/'settings.inc').write_text(s[a:b])
cj=Path(os.environ['IDF_PATH'])/'components/json/cJSON'
(build/'route_ingress.inc').write_text('int gateway_host_input(struct pbuf *p,struct netif *input) {'+(r/'main/router.c').read_text().split('int gateway_host_input(struct pbuf *p,struct netif *input) {')[1])
boot=(r/'main/boot_health.c').read_text()
(build/'boot_health.inc').write_text((r/'main/json_writer.inc').read_text()+'\n'+boot[boot.index('#define BOOT_MAGIC'):])
directory=(r/'components/microlink/src/ml_directory.c').read_text()
(build/'directory_mount.inc').write_text(directory[directory.index('bool ml_directory_mount(void)'):directory.index('\n#else')])
dns=(r/'main/dns.c').read_text()
(build/'dns.inc').write_text(dns[dns.index('static uint16_t read16'):])
(build/'usb_health.inc').write_text('\n'.join(line for line in (r/'main/usb_health.c').read_text().splitlines() if not line.startswith('#include')))
for name in ['usb_health','startup','settings','derp_owner','route_ingress','boot_health','directory_mount','dns']:
    cmd=['cc','-std=c11','-g','-fsanitize=address,undefined','-I',str(build),'-I',str(cj),str(r/f'tests/test_{name}.c')]
    if name=='settings':cmd.append(str(cj/'cJSON.c'))
    cmd+=['-o',str(build/f'test_{name}')];subprocess.run(cmd,check=True);subprocess.run([str(build/f'test_{name}')],check=True)

# A second reader would reintroduce both the TLS/free race and 10 KiB per identity.
assert 'xTaskCreatePinnedToCore(ml_derp_rx_task' not in (r/'components/microlink/src/microlink.c').read_text()
assert 'void ml_derp_rx_task(' not in (r/'components/microlink/src/ml_derp.c').read_text()
