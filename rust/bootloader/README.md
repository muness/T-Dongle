The rescue bootloader (ESP-IDF v5.5.5 second stage + `bootloader_components/tdongle_rescue`, PR #49, branch `fix/bootloader-rescue`, commits ce158d6, 2778540, fdb3257).
`bootloader-rescue.bin` is the binary the board tests verified (sha256 in `SHA256`). The Rust image's release package uses it at 0x0; DIO, 40 MHz, 16 MB header.
Rebuild: check out PR #49, `tools/build.sh` of the C tree, take `build/bootloader/bootloader.bin`, and update `SHA256`; `rust/tools/package.py` refuses a bootloader whose hash is not in `SHA256`.
