# Archived bridge-only firmware (v0.1.x)

These files are the original standalone bridge firmware (setup access point with captive portal, LVGL status pages, APA102 light, button menu, Wi-Fi trial and factory reset). **They are not built.** The shipped firmware is the unified image (`main/` plus `alternative/tailnet/main/`). They are kept as the reference for how each feature worked in v0.1.1; git history and tag `v0.1.1` keep them regardless.

Where each part went in the unified image (the change that restored them is described in docs/REFERENCE.md and ADR 0024):

| v0.1.x | Unified |
|---|---|
| `portal.c` setup AP, DHCP, captive DNS, page | `alternative/tailnet/main/setup_ap.inc`, `setup_ap.html`, the shared HTTP handlers in `gateway_main.c`; `main/captive_dns.c`, `main/setup_access.c`, `main/scan_list.c`, `main/setup_boot.c` |
| `control.c` commands, setup reboot flags, factory reset | `serial_setup.inc` (`setup`, `cancel`, `reset`, `confirm-reset`, `display`, `use`), `main/setup_boot.c`, `wifi_profiles.inc` (`wifi_factory_reset`) |
| `control.c` candidate trial (45 s) | **not ported** (see docs/REFERENCE.md, Known differences) |
| `ui.c` button, menu, LED, LCD | `device_ui.inc`, `main/menu.c`, `main/led.c`, `lcd.c`, `lcd_view.c` |
| `view.c` screen pages | `lcd_view.c` (Connection, Traffic, Health, Setup) |
| `settings.c` NVS settings | read-only import: `main/legacy_import.c`; display settings: `main/ui_settings.c`; priorities, names, preferred: `main/wifi_meta.c` |
| `bridge.c` roaming flags, radio profile, crash tallies | `wifi_profiles.inc` (`wifi_fill_station`), `gateway_main.c` (`wifi_radio_profile`), `main/health.c` |
| `console.c`, `app.h`, `bridge.h` | superseded by `console.c`/`control.c` in `alternative/tailnet/main` and the bridge in `components/tdongle_runtime/l2.c` |

Their host tests still run from `tools/test.sh` (`legacy/view.c` with `tests/test_core.c`, `legacy/settings.c` with `tools/test_settings.py`). `main/core.c`, `main/profile_json.c` and `main/board.h` stay in `main/` because the unified image uses them (the v0.1.x settings layout in `main/core.h` is the format of the stored blob and must not change).
