# MicroLink audit source

Vendored from https://github.com/Csontikka/microlink at 7de6a93684a34991fdfa1eeb9281e08523646ef7. MIT notices and the X25519 notice are included. Nested wireguard_lwip notices are preserved. The only initial integration change removes PlatformIO-specific include paths; native ESP-IDF REQUIRES exports the headers.

This alternative project is initially a compile-time audit instrument, not working multi-tailnet firmware. It does not start networking, accept credentials, or enroll a node. Do not distribute its binary as a gateway or install it through the companion app.
