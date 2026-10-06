#!/usr/bin/env python3
"""Rule 13 of ADR 0001, checked on source: in an image's `main`, the USB device and console are spawned before anything that can block or fail (storage,
radio, scan, connect), and `main` itself contains none of those calls (they belong in `init_task`, after the console is up).

Usage: check_boot_order.py FILE... (no_std spike images: s1-wifi-l2, s3-bridge).  Exit status 1 on a violation."""
import re
import sys

BLOCKING = ["WifiController::new", "FlashStorage::new", "saved::load", "scan_async", "connect_async", "wait_for_disconnect_async"]


def body(src: str, name: str) -> str:
    m = re.search(r"async fn %s\b[^{]*\{" % name, src)
    if not m:
        raise SystemExit(f"no `async fn {name}`")
    depth, i = 1, m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        i += 1
    return src[m.end():i - 1]


def main() -> int:
    bad = 0
    for path in sys.argv[1:]:
        src = open(path).read()
        main_body = body(src, "main")
        usb = main_body.find("spawner.spawn(usb_task")
        console = main_body.find("spawner.spawn(console_task")
        if usb < 0 or console < 0:
            print(f"{path}: main does not spawn usb_task and console_task"); bad += 1; continue
        for call in BLOCKING:
            at = main_body.find(call)
            if at >= 0 and at < max(usb, console):
                print(f"{path}: `{call}` runs in main before the USB device and console are spawned"); bad += 1
        if "esp_hal::init" in main_body and main_body.find("guard::begin") > main_body.find("esp_hal::init"):
            print(f"{path}: the guard record must be read before esp_hal::init"); bad += 1
        if "println!" in main_body[main_body.find("Usb::new_fs"):usb]:
            print(f"{path}: println between Usb::new_fs and the USB task spawn"); bad += 1
        print(f"{path}: ok" if not bad else f"{path}: FAILED")
    return 1 if bad else 0


sys.exit(main())
