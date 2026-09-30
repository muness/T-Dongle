# Optional companion extensions

The paid Android application sells its UI, not exclusive firmware access. Existing public console, portal and physical controls retain their behavior; there is no entitlement enforcement or account requirement.

Help advertises capabilities. `capabilities` returns `capabilities schema=1 features=telemetry` and the normal done marker. Unknown names are additive; incompatible schemas must disable extensions while leaving legacy setup available. The command is read-only and safe in setup or trial. Subsequent changes add capabilities only when their corresponding handlers and bounded readbacks exist.

Firmware release assets must include android-firmware.json with schema 1, original-board identity, managementProtocol 1, factory-nvs-v1 layout, image offsets and SHA256 digests. The companion repository tools/firmware_release.py publish command produces this descriptor for a fixed published tag. Publish it before announcing a release as installable by the app. No firmware version table is compiled into the application.
