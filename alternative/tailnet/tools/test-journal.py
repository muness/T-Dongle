#!/usr/bin/env python3
from pathlib import Path
import subprocess,os
r=Path(__file__).resolve().parents[1];s=(r/'main/gateway_main.c').read_text()
a=s.index('enum { DIAG_RING_MAGIC');b=s.index('static wifi_config_t',a)
c=s.index('static esp_err_t diagnostics(');d=s.index('static esp_err_t home(',c)
(r/'build-host/diagnostic_journal.inc').write_text(s[a:b]+s[c:d])
cj=Path(os.environ['IDF_PATH'])/'components/json/cJSON'
subprocess.run(['cc','-std=c11','-g','-fsanitize=address,undefined','-I',str(r/'build-host'),'-I',str(cj),str(r/'tests/test_diagnostic_journal.c'),str(cj/'cJSON.c'),'-o',str(r/'build-host/test_diagnostic_journal')],check=True)
subprocess.run([str(r/'build-host/test_diagnostic_journal')],check=True)
