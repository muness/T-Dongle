#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import os, shlex, subprocess
from pathlib import Path
src='\n'.join(s for s in Path('legacy/settings.c').read_text().splitlines() if not s.startswith('#include'))
Path('build-host/test_settings.c').write_text(Path('tests/mocks/nvs.h').read_text()+'\n'+src+'\n'+Path('tests/mocks/nvs_cases.c').read_text())
subprocess.run(shlex.split(os.environ.get('CC','cc'))+shlex.split(os.environ.get('TEST_CFLAGS',''))+['-std=c11','-I','main','-I','legacy','main/core.c','build-host/test_settings.c','-o','build-host/test_settings'],check=True)
subprocess.run(['build-host/test_settings'],check=True)
