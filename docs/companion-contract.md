# Optional companion extensions

The paid Android application sells its UI, not exclusive firmware access. Existing public console, portal and physical controls retain their behavior; there is no entitlement enforcement or account requirement.

Help advertises capabilities. `capabilities` returns `capabilities schema=1 features=telemetry` and the normal done marker. Unknown names are additive; incompatible schemas must disable extensions while leaving legacy setup available. The command is read-only and safe in setup or trial. Subsequent changes add capabilities only when their corresponding handlers and bounded readbacks exist.

Firmware release assets must include android-firmware.json with schema 1, original-board identity, managementProtocol 1, factory-nvs-v1 layout, image offsets and SHA256 digests. The companion repository tools/firmware_release.py publish command produces this descriptor for a fixed published tag. Publish it before announcing a release as installable by the app. No firmware version table is compiled into the application.

Metadata capability adds read-only `preference` (`preferred=0..8`) and `metadata JSON`. JSON carries slot, expectedName, expectedSsid, expectedPriority, name, priority and preferred boolean. Exact old identity is checked before mutation. Name is printable ASCII 1–24, priority 0–100; preferred true selects this slot for subsequent reconnection without switching now. Preferred false leaves the existing preference unchanged. Setup/trial requests are rejected. Persistence uses the existing cooldown and whole-configuration rollback. Password and SSID bytes are untouched. Success is `OK metadata saved; association unchanged`; read list/preference back after every submission, including timeout. Never retry an uncertain write automatically.

Selection policy remains preferred first, then highest priority among remaining untried profiles; ties choose the lower slot. This changes no existing use/portal/menu semantics. Release CI now generates android-firmware.json from actual built images and uploads it with each tag.
