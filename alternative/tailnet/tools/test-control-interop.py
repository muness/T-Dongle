#!/usr/bin/env python3
from pathlib import Path
import os,subprocess
r=Path(__file__).resolve().parents[1];cj=Path(os.environ['IDF_PATH'])/'components/json/cJSON'
client=r/'build-host/test_control_interop'
subprocess.run(['cc','-std=c11','-fsanitize=address,undefined','-g','-I',str(r/'build-host'),'-I',str(cj),str(r/'tests/test_control_interop.c'),str(cj/'cJSON.c'),'-o',str(client)],check=True)
subprocess.run(['go','run',str(r/'tests/control_interop.go'),str(client)],check=True)
