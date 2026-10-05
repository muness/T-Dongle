# Evidence sources for the DERP research notes (2026-10-05)

Scratch programs used for the numbers in the three notes one level up. Not part of the firmware build.

- `host_mbedtls_handshake.c`, `host_mbedtls_config.h`: host mbedTLS 3.6.6 client with an allocation counter. Build from the ESP-IDF 5.5.5 tree: `clang -O1 -w -DMBEDTLS_CONFIG_FILE='"host_mbedtls_config.h"' -I. -I$IDF/components/mbedtls/mbedtls/include -I$IDF/components/mbedtls/mbedtls/library host_mbedtls_handshake.c $IDF/components/mbedtls/mbedtls/library/*.c -o cli && ./cli derp1.tailscale.com`. Host is 64-bit, so struct-heavy numbers overstate the target.
- `xtensa_sizeof.c`: compiled with `xtensa-esp32s3-elf-gcc -S` using the flags of `ssl_tls.c` from `compile_commands.json` of an `idf.py reconfigure` run, to read struct sizes for the target.
- `derp_chain_probe.go`: Go TLS 1.2 probe over `hosts.txt` (hostnames from `https://login.tailscale.com/derpmap/default`); prints suite, key types and issuers.
- `derp_connect_timing.go`: TCP, TLS 1.2 and HTTP-upgrade timing to given DERP hosts.
