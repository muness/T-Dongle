# Alternative multi-tailnet firmware: feasibility gate

This project currently builds an audit instrument, not a usable gateway. It does not initialize Wi-Fi, USB networking or a Tailscale client, accept secrets or enroll devices. Do not flash this artifact or add it to the APK firmware selector. It uses the default audit partition layout, not the existing adapter recovery layout.

The intended product supports a dynamic membership collection: 0, 1 or N. N is bounded by measured hardware resources and explicit admission, not a fixed pair of slots. Two is the minimum concurrency test; a third is required to reject a hidden two-member model.

## Reproduce

Source the project's pinned ESP-IDF v5.5.5 export.sh, then run `tools/build-audit.sh` from this directory. It builds all pinned MicroLink source into component archives and extracts Xtensa ABI sizes from a linked read-only table. The audit app deliberately does not reference the client's runtime entry point, so linked binary size is not a complete networking firmware size measurement.

`build/memory-audit.json` distinguishes compile-time lower bounds from physical peak-memory evidence. No runtime, hardware, tailnet-policy or end-to-end claim follows from successful compilation. See AUDIT.md for the current stop/pivot result and exact source paths. Existing full/headless/network-only firmware remains unchanged.
