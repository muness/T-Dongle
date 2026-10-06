# Archived bridge-only firmware (v0.1.x)

These files are the original standalone bridge firmware (setup access point with captive portal, LVGL status pages, APA102 light, button menu, Wi-Fi trial and factory reset). **They are not built.** The shipped firmware is the unified image (`main/` plus `alternative/tailnet/main/`). They are kept in the tree only as the reference for porting the features the unified image does not have yet (see the parity audit in the pull request that archived them), and should be deleted once those are ported or dropped. Git history and tag `v0.1.1` keep them regardless.

Their host tests still run from `tools/test.sh` (`legacy/view.c` with `tests/test_core.c`, `legacy/settings.c` with `tools/test_settings.py`, `legacy/portal.c` open-AP guard in `tests/test_open_ap.py`). `main/core.c`, `main/profile_json.c` and `main/board.h` stay in `main/` because the unified image uses them.
