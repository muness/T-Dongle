#!/usr/bin/env python3
"""Lockout rescue rule (ADR 0001 rule 13): every firmware or spike binary that can leave the device without a way back (anything that starts the USB OTG device) calls
`tdongle_rescue::arm()` as the first statement after `esp_hal::init` (no_std images) or `rescue::arm()` as the first statement of `main` (the std firmware). `esp_hal::init`
disables every watchdog and the bootloader counts boots that never became healthy, so nothing protects an image until `arm` runs.

Usage: check_rescue_first.py [FILE...]   (default: the firmware and every spike binary). An image that never starts the OTG device (USB-Serial-JTAG only, flashable
without BOOT) may carry the line `// rescue: exempt (reason)`. Exit status 1 on a violation."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def body_of(src: str, pattern: str) -> tuple[str, int]:
    m = re.search(pattern, src)
    if not m:
        raise ValueError(f"no match for {pattern}")
    depth, i = 1, m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        i += 1
    return src[m.end():i - 1], m.end()


def strip_comments(s: str) -> str:
    return re.sub(r"//[^\n]*", "", s)


def first_statement_after(body: str, marker: str) -> str:
    """The text of the statement that follows the one containing `marker`."""
    at = body.index(marker)
    depth, i = 0, at
    while True:
        c = body[i]
        depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(c, 0)
        if c == ";" and depth == 0:
            break
        i += 1
    rest = strip_comments(body[i + 1:]).lstrip()
    return rest.split(";", 1)[0] if rest else ""


def check(path: pathlib.Path) -> list[str]:
    src = path.read_text()
    if "// rescue: exempt" in src:
        if "Usb::new_fs" in src or "esp_hal::usb::otg" in src:
            return [f"{path}: exempt, but the image starts the USB OTG device"]
        return []
    if "esp_hal::init(" in src:
        body, _ = body_of(src, r"async fn main\b[^{]*\{")
        body = strip_comments(body)
        nxt = first_statement_after(body, "esp_hal::init(").strip()
        if not nxt.startswith("tdongle_rescue::arm()"):
            return [f"{path}: the first statement after esp_hal::init must be `tdongle_rescue::arm();` (found `{nxt[:50]}`)"]
        return []
    if "link_patches" in src:
        body, _ = body_of(src, r"\bfn main\(\)\s*\{")
        first = strip_comments(body).lstrip().split(";", 1)[0].strip()
        if not first.startswith("rescue::arm()"):
            return [f"{path}: the first statement of main must be `rescue::arm();` (found `{first[:50]}`)"]
        return []
    return []


def main() -> int:
    files = [pathlib.Path(a) for a in sys.argv[1:]] or [ROOT / "firmware/src/main.rs", *sorted(ROOT.glob("spikes/*/src/main.rs"))]
    problems = []
    for f in files:
        problems += check(f)
    for p in problems:
        print(p)
    if not problems:
        print(f"rescue arm first: ok ({len(files)} files)")
    return 1 if problems else 0


sys.exit(main())
