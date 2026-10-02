# Confirmed DNS stack overflow and Android status incompatibility

Android v121's saved report names `gateway_dns` as the crashed task. Its ELF SHA matches the archived 0.2.12 firmware exactly. The decoded trace reaches `vApplicationStackOverflowHook` through the normal panic path. The [sanitized evidence](v121-dns-stack-overflow-2026-10-02.json) retains the task, ELF, addresses and management failure without network identities or credentials.

The firmware's recovery latch worked, including after power removal: `recovery=true`, no startup errors, about 219 KB free heap and a readable boot report. Android nevertheless closed management at `STATUS_READ:STATUS_FORMAT_REJECTED`. Firmware 0.2.12 appended `firmware=0.2.12` to a status line whose Android parser required an immediate line ending. This was a compatibility regression introduced by the preceding update, not a missing USB response. Previous Activity tests injected an already-connected client and therefore could not catch it.

## Changes

Firmware 0.2.13 allocates one DNS workspace before creating its task. The 1500-byte packet, query/name buffers and directory record no longer occupy the task's stack during nested socket, FAT and flash calls. The compiled Xtensa frame falls from 2336 to 144 bytes; the task stack remains 4096 bytes. The workspace is 2240 bytes on the ESP32-S3 and allocation, socket, bind and task-creation failures clean up without aborting. DNS stack high-water is exported in the automatically archived boot report. This trades a small explicit lifetime heap allocation for stack headroom; it does not claim lower total RAM use.

The firmware places its version on a separate line, preserving the original status contract. Android also accepts the bounded inline version emitted by already-installed 0.2.12, allowing management/recovery without a preceding firmware update. Other required fields and their validation remain strict. A rejected status response is reported as a parser failure instead of claiming the console did not answer.

## Checks and review

- `tools/check-startup-stack.py` measures the actual compiled DNS frame and rejects anything above 256 bytes. The prior binary's 2336-byte frame fails that limit; a defaults-only edit cannot pass it.
- `tests/test_dns.c` executes the production DNS task with socket/task fixtures under ASan/UBSan: normal forwarding, flash-directory lookup and translated answer, unknown name, malformed/truncated request, all startup allocation/socket/bind/task failures and full 1500-byte buffer capacities. It rejects accidentally replacing array sizes with pointer sizes.
- `tools/check-android-status.py <android-repo>` compiles the production C status formatter and runs all eight Wi-Fi/USB combinations through Android's production Java parser. Android's fragmented-serial regression additionally covers 0.2.12, separate-line and legacy responses, malformed version values and invalid USB readiness.
- The existing recovery tests continue to preserve saved identities and crash evidence. The original NVS, application, peerstore and coredump partition layout is unchanged.

Review: this is a bounded correction to two observed failures, with no new enrollment/routing architecture. Final builds use isolated committed trees because concurrent UI/LCD work is present in the shared working directories. Hardware confirmation remains necessary for sustained DNS/peer traffic; the compiled frame bound is not a measured runtime stack high-water. No physical device was flashed by the agent.
