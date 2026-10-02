#!/usr/bin/env python3
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1]
source=(root/'main/socket_budget.c').read_text()
source="\n".join(line for line in source.splitlines() if not line.startswith('#include'))
(root/'build-host/socket_accounting.inc').write_text(source)
subprocess.run(['cc','-std=c11','-g','-fsanitize=address,undefined','-pthread','-I',str(root/'build-host'),str(root/'tests/test_socket_budget.c'),'-o',str(root/'build-host/test_socket_budget')],check=True)
subprocess.run([str(root/'build-host/test_socket_budget')],check=True)
