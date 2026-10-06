#!/usr/bin/env python3
"""Guard the compiled startup budget, not just an sdkconfig.defaults intention."""
import pathlib
import re
import subprocess
import sys

# Usage: check-startup-stack.py BUILD_DIR (the unified firmware's build directory).
build = pathlib.Path(sys.argv[1]).resolve()
config = (build / "sdkconfig").read_text()
stack = int(re.search(r"^CONFIG_ESP_MAIN_TASK_STACK_SIZE=(\d+)$", config, re.M)[1])
assert stack >= 7168, f"Startup stack regressed to {stack} bytes"
for option in ("ESP_COREDUMP_ENABLE_TO_FLASH", "MBEDTLS_DYNAMIC_BUFFER"):
    assert f"CONFIG_{option}=y" in config, f"Required runtime setting missing: {option}"
for option in ("ESP_COREDUMP_LOGS", "ESP_COREDUMP_CAPTURE_DRAM", "MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"):
    assert f"CONFIG_{option}=y" not in config, f"Unexpected retained RAM setting: {option}"
assert "CONFIG_APP_RETRIEVE_LEN_ELF_SHA=64" in config, "Crash summaries require a full ELF identity"
objects = list((build / "esp-idf/main/CMakeFiles/__idf_main.dir").rglob("gateway_main.c.obj"))
assert len(objects) == 1, f"Expected one compiled gateway_main.c.obj under {build}, found {len(objects)}"
obj = objects[0]
disassembly = subprocess.check_output(["xtensa-esp32s3-elf-objdump", "-d", str(obj)], text=True)
match = re.search(r"<gateway_diag_write>:\s*\n\s*[0-9a-f]+:\s+[0-9a-f]+\s+entry\s+a1,\s*(0x[0-9a-f]+|\d+)", disassembly)
assert match, "Cannot measure the compiled diagnostic writer frame"
frame = int(match[1], 0)
assert frame <= 256, f"Journal moved back onto task stacks: frame={frame} bytes"
print(f"Startup stack: {stack} bytes, journal writer frame: {frame} bytes (not a runtime high-water measurement)")
dns_obj = obj.with_name("dns.c.obj")
dns_disassembly = subprocess.check_output(["xtensa-esp32s3-elf-objdump", "-d", str(dns_obj)], text=True)
dns_match = re.search(r"<dns_task>:\s*\n\s*[0-9a-f]+:\s+[0-9a-f]+\s+entry\s+a1,\s*(0x[0-9a-f]+|\d+)", dns_disassembly)
assert dns_match, "Cannot measure the compiled DNS task frame"
dns_frame = int(dns_match[1], 0)
assert dns_frame <= 256, f"DNS workspace moved back onto its stack: frame={dns_frame} bytes"
print(f"DNS task frame: {dns_frame} bytes; task budget remains 4096 bytes")
