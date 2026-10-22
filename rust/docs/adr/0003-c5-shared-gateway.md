# C5: one application, two downstream transports

Accepted for the experimental C5 build; hardware qualification remains pending.

A separate serial-IP/NAPT binary duplicated connection policy and bypassed the tailnet engine. The C5 manifest now builds `firmware/src/main.rs`, the same application as S3. Chip-specific peripherals, memory, watchdog and transport live under `firmware/src/c5/`. Saved profiles, settings, registry, identities, tailnet workers, packet routing, HTTP management and display/button logic remain shared.

C5 has USB Serial/JTAG rather than S3 USB OTG. Its USB mode carries IPv4 between Android VpnService and a virtual Ethernet host in the existing gateway runtime. It does not implement NCM or transparently carry Android tethered clients. Native S3 NCM remains unchanged.

Wireless mode replaces that downstream transport with a protected AP. Both feed the same runtime, including DHCP, DNS aliases, tailnet routes and ordinary upstream NAPT. Replies look up the destination IP's neighbor, not the first host. Four AP clients match the four-neighbor bound. AP transmit completions must not release station credits. AP and station use one radio: simultaneous independent bands/channels are not promised.

The `c5_transport/mode` byte (schema v1: USB=0, wireless=1) changes independently of membership/identity namespaces. Unknown values fail closed without overwriting them. A successful mode save acknowledges then reboots. Power-cut tests exercise both transitions and preserve three identity blobs plus a registry. Changing transport never creates a new tailnet identity.

Normal wireless mode is an explicitly selected, persistent gateway. Temporary provisioning remains a separate bounded setup boot with no forwarding; C5 protects it with a fresh password shown on-screen. Save/cancel/expiry returns through the existing setup state machine. The persistent gateway password is unique, saved in ordinary unencrypted NVS, and shown only on the local setup page or an explicit owner console request.

The allocator keeps radio/RTOS allocations internal. Application allocations of at least 512 bytes, or those that would breach the 32 KiB application reserve, use PSRAM. Three actual worker sets are compiled. Runtime asserts the shared tailnet state lies in the initialized external region. NVS reads/writes stage through internal stack buffers before cache-disabled flash operations. Recovery skips PSRAM initialization and does not start the radio/tailnet runtime. Three is a build target, not measured capacity or throughput.

No automatic ROM-entry or S3 rescue-bootloader guarantee is asserted for C5. BOOT at plug-in remains the recovery procedure. Hardware validation must include PSRAM/flash coexistence, all three memberships under rekey/DERP load, two wireless clients, USB detach and Android VPN revocation before this becomes a release candidate for deployment.
