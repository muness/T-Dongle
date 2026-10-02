#!/usr/bin/env python3
"""Guard the compiled startup budget, not just an sdkconfig.defaults intention."""
import pathlib
import re
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
config = (root / "sdkconfig").read_text()
stack = int(re.search(r"^CONFIG_ESP_MAIN_TASK_STACK_SIZE=(\d+)$", config, re.M)[1])
assert stack >= 7168, f"Startup stack regressed to {stack} bytes"
obj = root / "build/esp-idf/main/CMakeFiles/__idf_main.dir/gateway_main.c.obj"
disassembly = subprocess.check_output(["xtensa-esp32s3-elf-objdump", "-d", str(obj)], text=True)
match = re.search(r"<gateway_diag_write>:\s*\n\s*[0-9a-f]+:\s+[0-9a-f]+\s+entry\s+a1,\s*(0x[0-9a-f]+|\d+)", disassembly)
assert match, "Cannot measure the compiled diagnostic writer frame"
frame = int(match[1], 0)
assert frame <= 256, f"Journal moved back onto task stacks: frame={frame} bytes"
print(f"Startup stack: {stack} bytes, journal writer frame: {frame} bytes (not a runtime high-water measurement)")
