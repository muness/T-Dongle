#!/usr/bin/env python3
"""Generate the golden files of tdongle-lcd from the REAL C sources. Nothing is transcribed: the expected bytes and pixels come from
compiling and running

  * alternative/tailnet/main/lcd_view.c (included whole, so its static glyph table and renderer are reachable), main/traffic.c
    (traffic_format_mbps / traffic_format_megabytes) and main/ui_settings.c (ui_settings_backlight_duty), through tools/golden_harness.c;
  * components/st7735/esp_lcd_st7735.c (the panel driver, unmodified) against stub ESP-IDF headers (tools/stubs), driven with the
    call sequence of alternative/tailnet/main/lcd.c, through tools/panel_harness.c.

Regenerate and check (what CI runs; needs a host `cc` and python3 only):

    python3 rust/crates/tdongle-lcd/tools/gen_golden.py            # rewrites tests/golden/*
    python3 rust/crates/tdongle-lcd/tools/gen_golden.py --check    # regenerates into a temp dir and fails on any diff
    python3 rust/crates/tdongle-lcd/tools/gen_golden.py --ppm DIR  # also writes one PPM per named scenario for review

Outputs (tests/golden/):
  scenarios.txt   the inputs (S state, V raw view, R menu rows, F formatter, D duty, G glyph table); seeded, reproducible
  expected.txt    per scenario: view=<the 170 bytes of the C lcd_view> crc=<CRC-32 of the pixels of rows 0..81 and 255> [frame=off:len]
  frames.bin      run-length coded 160x80 RGB565 frames of the named scenarios (per row: run count u8, then (u16 LE value, u8 length))
  panel.txt       the wire events (commands, delays, GPIO levels, colour transfers) of the real ST7735 driver
"""
import argparse
import difflib
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
REPO = HERE.parents[3]
GOLDEN = CRATE / "tests" / "golden"
CC = ["cc", "-std=gnu11", "-O0", "-g", "-w"]


def hx(b):
    return bytes(b).hex()


def cs(text, size):
    """A C string in a fixed char array, zero padded."""
    b = text.encode() if isinstance(text, str) else bytes(text)
    assert len(b) < size
    return b + b"\0" * (size - len(b))


def state_line(name, ver="0.3.0", full=False, **f):
    parts = ["S", name, "ver=" + hx(ver.encode())]
    if full:
        parts.append("full=1")
    for k, v in f.items():
        if k in ("ssid", "ap_ssid", "active_name"):
            v = hx(cs(v, {"ssid": 33, "ap_ssid": 16, "active_name": 25}[k]))
        elif k == "bars":
            v = hx(bytes(v))
        elif isinstance(v, bool):
            v = int(v)
        parts.append(f"{k}={v}")
    return " ".join(parts)


def scenarios():
    L = []
    S = lambda name, **f: L.append(state_line(name, full=f.pop("full", True), **f))
    # ---- Connection page: the cases of tests/test_lcd.c
    S("wifi")
    S("wifi_saved", saved_wifi=True)
    S("bridge_setup", bridge=True)
    S("bridge_wait", wifi=True, bridge=True)
    S("bridge_usb", wifi=True, bridge=True, usb=True)
    S("suspended", wifi=True, bridge=True, usb_configured=True, usb_suspended=True, ver="0.2.22")
    S("tailnet_ready_suspended", wifi=True, ready=1, enabled=1, usb_configured=True, usb_suspended=True, ver="0.2.22")
    S("tailnet_ready_wait", wifi=True, ready=1, enabled=1, usb_configured=True)
    S("tailnet_ready_usb", wifi=True, ready=1, enabled=1, usb_configured=True, usb=True)
    S("starting", starting=True)
    S("installing", installing=True, ready=1, recovery=True)
    S("empty", wifi=True)
    S("off", wifi=True, saved=1)
    S("signin", wifi=True, saved=1, enabled=1, login=1)
    S("ready", wifi=True, saved=1, enabled=1, ready=1)
    S("multiple", wifi=True, saved=3, enabled=3, ready=2, usb=True)
    S("multiple_wait_for_usb", wifi=True, saved=3, enabled=3, ready=3)
    S("connecting", wifi=True, saved=1, enabled=1)
    S("retry", wifi=True, saved=1, enabled=1, failed=1)
    S("recovery", wifi=True, saved=1, enabled=1, ready=1, recovery=True)
    S("recovery_nowifi", recovery=True)
    S("huge_counts", wifi=True, enabled=2**32 - 1, ready=2**32 - 1, usb=True, ver="1234567890123456789")
    S("version_nul", wifi=True, bridge=True, ver="0.3\x00junk")
    # ---- signal line
    S("signal", wifi=True, bridge=True, usb=True, usb_configured=True, rssi_valid=True, rssi=-57, ssid="HomeNet")
    S("signal_nossid", wifi=True, bridge=True, usb=True, rssi_valid=True, rssi=-57)
    S("signal_nolevel", wifi=True, bridge=True, usb=True, ssid="H")
    S("signal_none", wifi=True, bridge=True, usb=True)
    S("signal_long_ssid", wifi=True, bridge=True, usb=True, rssi_valid=True, rssi=-100, ssid="N" * 32)
    S("signal_rssi_pos", wifi=True, bridge=True, rssi_valid=True, rssi=500, ssid="Net")
    S("signal_rssi_min", wifi=True, bridge=True, rssi_valid=True, rssi=-100000, ssid="Net")
    S("signal_rssi_0", wifi=True, bridge=True, rssi_valid=True, rssi=0, ssid="Net")
    S("signal_not_joined", rssi_valid=True, rssi=-50, ssid="Joining")
    S("signal_tailnet", wifi=True, saved=1, enabled=1, ready=1, usb=True, rssi_valid=True, rssi=-71, ssid="Office")
    S("signal_lowercase_glyphs", wifi=True, bridge=True, rssi_valid=True, rssi=-60, ssid="abc xyz?!@#~")
    S("signal_truncate_26", wifi=True, bridge=True, rssi_valid=True, rssi=-9, ssid="X" * 31)
    S("signal_high_bytes", wifi=True, bridge=True, ssid=b"caf\xc3\xa9 \xff\x80x")
    S("signal_installing_hidden", installing=True, wifi=True, rssi_valid=True, rssi=-50, ssid="Hidden")
    # ---- Traffic
    bars = [i % 21 for i in range(32)]
    S("traffic", page=1, wifi=True, bridge=True, down_kbps=1234, up_kbps=56, down_bytes=12345678, up_bytes=2345678,
      down_frames=1234567, up_frames=89, bars=bars)
    S("traffic_zero", page=1)
    S("traffic_max", page=1, down_kbps=2**32 - 1, up_kbps=2**32 - 1, down_bytes=2**64 - 1, up_bytes=2**64 - 1,
      down_frames=2**64 - 1, up_frames=2**64 - 1, bars=[255] * 32)
    S("traffic_bars_clamp", page=1, bars=[0, 1, 2, 19, 20, 21, 22, 255] * 4)
    S("traffic_bars_flat", page=1, bars=[0] * 32)
    S("traffic_mb_wrap", page=1, down_bytes=2**32 * 100000 * 10 + 123456789, up_bytes=99_999_999)
    S("traffic_mb_boundary", page=1, down_bytes=99_900_000, up_bytes=100_000_000)
    S("traffic_overlay", page=1, starting=True)
    # ---- Health (three sub-views, recovery attention, wrap of the view number)
    h = dict(page=2, uptime_s=3 * 3600 + 12 * 60, wifi_up_s=3 * 3600 + 10 * 60, connects=4, last_reason=201, usb_resets=2,
             heap_free=123456, heap_min=98765, heap_largest=55000, reset_reason=3, boots=5, watchdogs=1, panics=2)
    for v in range(3):
        S(f"health{v + 1}", health_view=v, **h)
    S("health3_recovery", health_view=2, recovery=True, **h)
    S("health1_recovery", health_view=0, recovery=True, **h)
    S("health_view7", health_view=7, **h)
    big = dict(page=2, uptime_s=2**32 - 1, wifi_up_s=86400 * 2, connects=2**32 - 1, last_reason=2**32 - 1, usb_resets=2**32 - 1,
               heap_free=2**32 - 1, heap_min=2**32 - 1, heap_largest=2**32 - 1, reset_reason=2**32 - 1, boots=2**32 - 1,
               watchdogs=2**32 - 1, panics=2**32 - 1)
    for v in range(3):
        S(f"health{v + 1}_max", health_view=v, **big)
    # ---- Setup page
    S("setup_page", page=3, bridge=True, saved_wifi=True, active_slot=2, active_name="Phone hotspot")
    S("setup_page_none", page=3, bridge=True, saved_wifi=True)
    S("setup_page_nosaved", page=3)
    S("setup_page_slot12", page=3, active_slot=12, active_name="N" * 24)
    S("setup_page_long_name", page=3, active_slot=9, active_name="W" * 24)
    S("page_out_of_range", page=9, wifi=True, bridge=True)
    S("page_4", page=4, wifi=True, bridge=True)
    S("page_max", page=2**32 - 1, wifi=True)
    for page in range(4):
        S(f"overlay_installing_p{page}", page=page, installing=True)
        S(f"overlay_starting_p{page}", page=page, starting=True)
    S("recovery_page1", page=1, recovery=True, wifi=True)
    # ---- Setup access point countdown
    ap = dict(setup=True, bridge=True, ap_ssid="TDongle-AB0CF9")
    S("ap", page=2, setup_seconds_left=581, **ap)
    S("ap_zero", setup_seconds_left=0, **ap)
    S("ap_59", setup_seconds_left=59, **ap)
    S("ap_60", setup_seconds_left=60, **ap)
    S("ap_5999", setup_seconds_left=5999, **ap)
    S("ap_6000_clamp", setup_seconds_left=6000, **ap)
    S("ap_huge_clamp", setup_seconds_left=2**32 - 1, **ap)
    S("ap_long_ssid", setup_seconds_left=300, setup=True, ap_ssid="A" * 15)
    S("ap_overlay_installing", setup_seconds_left=300, installing=True, **ap)
    S("ap_overlay_starting", setup_seconds_left=300, starting=True, **ap)
    S("ap_recovery", setup_seconds_left=300, recovery=True, **ap)
    # ---- Every printable and special glyph on the status screen (scale 1 lines and the scale 2 title via states)
    for i, chunk in enumerate(["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789-.:/,;<()+%=? ", "!\"#$&'*>@[\\]^_`{|}~"]):
        S(f"glyphs{i}", wifi=True, bridge=True, ssid=chunk[:32])
    # ---- the sweep of tests/test_lcd.c: every combination of the booleans (view bytes + pixel CRC only)
    for mask in range(2048):
        f = dict(bridge=mask & 1, wifi=mask & 2, saved_wifi=mask & 4, recovery=mask & 8, starting=mask & 16, installing=mask & 32,
                 usb=mask & 64, saved=3 if mask & 128 else 0, enabled=3 if mask & 256 else 0, ready=1 if mask & 512 else 0,
                 login=1 if mask & 1024 else 0, failed=1)
        L.append(state_line(f"mask{mask}", **f))
    # ---- random states
    rnd = random.Random(0x7DC0)
    def r32():
        return rnd.choice([0, 1, 2, 9, 10, 59, 60, 61, 999, 1000, 1001, 3599, 3600, 86399, 86400, 999999, 1000000, 2**31, 2**32 - 1,
                           rnd.randrange(2**32), rnd.randrange(1000)])
    def r64():
        return rnd.choice([0, 1, 99999, 100000, 999999, 1000000, 999999999, 1000000000, 10**15, 2**32, 2**64 - 1, rnd.randrange(2**64)])
    def rtext(n):
        k = rnd.randrange(0, n - 1)
        return bytes(rnd.choice([rnd.randrange(32, 127), rnd.randrange(1, 256), ord("a") + rnd.randrange(26)]) for _ in range(k))
    for i in range(400):
        f = {b: rnd.random() < 0.4 for b in ["bridge", "wifi", "saved_wifi", "recovery", "starting", "installing", "usb", "usb_configured",
                                              "usb_suspended", "rssi_valid", "setup"]}
        if rnd.random() < 0.5:
            f["wifi"] = True
        for k in ["saved", "enabled", "ready", "login", "failed"]:
            f[k] = rnd.choice([0, 0, 1, 2, 3, 999, 1000, 2**32 - 1])
        f["page"] = rnd.choice([0, 1, 2, 3, 0, 1, 2, 3, 4, 7, 2**32 - 1])
        f["rssi"] = rnd.choice([0, -1, -57, -127, -128, -200, 1, 500, rnd.randrange(-2**31, 2**31)])
        f["ssid"] = rtext(33)
        f["ap_ssid"] = rtext(16)
        f["active_name"] = rtext(25)
        f["setup_seconds_left"] = rnd.choice([0, 1, 59, 60, 5999, 6000, 2**32 - 1, rnd.randrange(7000)])
        for k in ["down_kbps", "up_kbps", "uptime_s", "wifi_up_s", "connects", "last_reason", "usb_resets", "heap_free", "heap_min",
                  "heap_largest", "reset_reason", "boots", "watchdogs", "panics", "health_view", "active_slot"]:
            f[k] = r32()
        for k in ["down_bytes", "up_bytes", "down_frames", "up_frames"]:
            f[k] = r64()
        f["bars"] = bytes(rnd.choice([0, 1, 5, 20, 21, 255, rnd.randrange(256)]) for _ in range(32))
        f["ver"] = bytes(c if 0 < c < 128 else 0x41 for c in rtext(24)).decode()
        ver = f.pop("ver")
        line = state_line(f"rand{i}", ver=ver, **{k: (int(v) if isinstance(v, bool) else v) for k, v in f.items()})
        L.append(line)
    # ---- formatters, including snprintf truncation at every small size
    durs = [0, 1, 59, 60, 61, 599, 600, 3599, 3600, 3601, 86399, 86400, 86401, 90061, 2**31, 2**32 - 1, 4294967295 - 86400]
    cnts = [0, 1, 999999, 1000000, 1000001, 1234567, 999999999, 1000000000, 1000000001, 999999999999999, 10**15, 2**40, 2**64 - 1]
    kbps = [0, 9, 10, 999, 1000, 1234, 9999, 65535, 99999, 123456, 2**32 - 1]
    mbs = [0, 99999, 100000, 12345678, 99_900_000, 99_999_999, 100_000_000, 123_456_789, 10**12, 2**40, 2**44, 2**64 - 1]
    n = 0
    for size in [1, 2, 3, 4, 8, 10, 16]:
        for v in durs:
            L.append(f"F fdur{n} dur {size} {v}"); n += 1
        for v in cnts:
            L.append(f"F fcnt{n} cnt {size} {v}"); n += 1
        for v in kbps:
            L.append(f"F fmbps{n} mbps {size} {v}"); n += 1
        for v in mbs:
            L.append(f"F fmb{n} mb {size} {v}"); n += 1
    for _ in range(300):
        size = rnd.choice([8, 10, 12, 16])
        L.append(f"F frd{n} dur {size} {rnd.randrange(2**32)}"); n += 1
        L.append(f"F frc{n} cnt {size} {rnd.randrange(2**64)}"); n += 1
        L.append(f"F frm{n} mbps {size} {rnd.randrange(2**32)}"); n += 1
        L.append(f"F frb{n} mb {size} {rnd.randrange(2**64)}"); n += 1
    # ---- backlight duty, including out-of-range percentages
    for p in list(range(0, 130)) + [255, 1000, 2**31]:
        L.append(f"D duty{p} {p}")
    L.append("G glyphs")
    # ---- menu rows (lcd_compose_rows)
    def rows(*rs):
        out = b""
        for r in rs:
            out += cs(r, 27)
        return out + b"\0" * (27 * 5 - len(out))
    L.append("R menu_setup attention=0 rows=" + hx(rows("SETUP MENU", "Enter setup AP", "", "Short: next  Hold: select")))
    L.append("R menu_net attention=0 rows=" + hx(rows("SETUP MENU", "2 Phone hotspot", "", "Short: next  Hold: select")))
    L.append("R menu_confirm attention=1 rows=" + hx(rows("CONFIRM FACTORY RESET", "Release; hold again <10s", "Short press cancels")))
    L.append("R menu_full attention=0 rows=" + hx(b"".join(cs(b"Z" * 26, 27) for _ in range(5))))
    L.append("R menu_lower attention=0 rows=" + hx(rows("lower case row", "mIxEd 123", "~~~", "x", "y")))
    for i in range(300):
        raw = bytes(rnd.choice([0, rnd.randrange(32, 127), rnd.randrange(256)]) if rnd.random() < 0.7 else 0 for _ in range(27 * 5))
        raw = bytearray(raw)
        for r in range(5):
            raw[r * 27 + 26] = 0   # the C reads each row as a string: a NUL ends it inside the array
        L.append(f"R menurand{i} attention={rnd.randrange(2)} rows=" + hx(bytes(raw)))
    # ---- raw views (any bytes: the renderer must match the C and stay in bounds)
    for i in range(300):
        text = bytes(rnd.choice([0, 0, rnd.randrange(32, 127), rnd.randrange(256)]) for _ in range(135))
        if rnd.random() < 0.3:
            text = bytes(rnd.randrange(1, 256) for _ in range(135))   # no NUL at all
        L.append(f"V view{i} layout={rnd.choice([0, 1, 1, 2, 255])} attention={rnd.randrange(2)} bar_count={rnd.choice([0, 1, 31, 32, 33, 255, rnd.randrange(256)])} "
                 f"text={hx(text)} bars={hx(bytes(rnd.choice([0, 1, 20, 21, 255, rnd.randrange(256)]) for _ in range(32)))}")
    return L


def run(cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def check_lcd_c_calls():
    """The panel harness replays lcd.c's call chain; fail loudly if lcd.c changed it."""
    src = (REPO / "alternative/tailnet/main/lcd.c").read_text()
    for needle in ["esp_lcd_panel_reset(panel)", "esp_lcd_panel_init(panel)", "esp_lcd_panel_invert_color(panel,true)",
                   "esp_lcd_panel_set_gap(panel,1,26)", "esp_lcd_panel_swap_xy(panel,true)", "esp_lcd_panel_mirror(panel,false,true)",
                   "esp_lcd_panel_disp_on_off(panel,true)", "esp_lcd_panel_mirror(panel,rotation!=0,rotation==0)",
                   "pixels[x]=(pixels[x]<<8)|(pixels[x]>>8)", "esp_lcd_panel_draw_bitmap(panel,0,y,160,y+1,pixels)",
                   ".reset_gpio_num=BOARD_LCD_RST,.rgb_ele_order=LCD_RGB_ELEMENT_ORDER_BGR,.bits_per_pixel=16", "cfg.pclk_hz=20000000"]:
        if needle not in src:
            sys.exit(f"lcd.c no longer contains `{needle}`: update tools/panel_harness.c and src/panel.rs")
    board = (REPO / "main/board.h").read_text()
    for needle in ["BOARD_LCD_MOSI 3", "BOARD_LCD_CLK 5", "BOARD_LCD_CS 4", "BOARD_LCD_DC 2", "BOARD_LCD_RST 1", "BOARD_LCD_BL 38",
                   "BOARD_LCD_BL_ACTIVE_LOW 1", "BOARD_WIDTH 160", "BOARD_HEIGHT 80"]:
        if needle not in board:
            sys.exit(f"board.h no longer contains `{needle}`: update src/panel.rs")


def generate(out: Path, ppm: Path | None):
    out.mkdir(parents=True, exist_ok=True)
    check_lcd_c_calls()
    lines = scenarios()
    (out / "scenarios.txt").write_text("# generated by tools/gen_golden.py: inputs for tools/golden_harness.c\n" + "\n".join(lines) + "\n")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        run(CC + ["-I", str(REPO / "alternative/tailnet/main"), "-I", str(REPO / "main"), str(HERE / "golden_harness.c"),
                  str(REPO / "main/traffic.c"), str(REPO / "main/ui_settings.c"), "-o", str(tmp / "golden_harness")])
        run([str(tmp / "golden_harness"), str(out / "scenarios.txt"), str(out / "expected.txt"), str(out / "frames.bin")])
        run(CC + ["-I", str(HERE / "stubs"), "-I", str(REPO / "components/st7735"), str(HERE / "panel_harness.c"),
                  str(REPO / "components/st7735/esp_lcd_st7735.c"), "-o", str(tmp / "panel_harness")])
        text = subprocess.run([str(tmp / "panel_harness")], check=True, capture_output=True, text=True).stdout
        (out / "panel.txt").write_text(text)
    if ppm:
        write_ppms(out, ppm)


def write_ppms(out: Path, ppm: Path):
    ppm.mkdir(parents=True, exist_ok=True)
    frames = (out / "frames.bin").read_bytes()
    for line in (out / "expected.txt").read_text().splitlines():
        m = re.match(r"(\S+) .*frame=(\d+):(\d+)", line)
        if not m:
            continue
        name, off, ln = m.group(1), int(m.group(2)), int(m.group(3))
        data, pos, rgb = frames[off:off + ln], 0, bytearray()
        for _ in range(80):
            n = data[pos]; pos += 1
            for _ in range(n):
                v = data[pos] | data[pos + 1] << 8; cnt = data[pos + 2]; pos += 3
                px = bytes([(v >> 11 & 31) * 255 // 31, (v >> 5 & 63) * 255 // 63, (v & 31) * 255 // 31])
                rgb += px * cnt
        (ppm / f"{name}.ppm").write_bytes(b"P6\n160 80\n255\n" + bytes(rgb))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--ppm", type=Path)
    a = ap.parse_args()
    if a.check:
        with tempfile.TemporaryDirectory() as tmp:
            generate(Path(tmp), None)
            bad = False
            for f in sorted(p.name for p in Path(tmp).iterdir()):
                if (Path(tmp) / f).read_bytes() != (GOLDEN / f).read_bytes():
                    bad = True
                    print(f"DIFF {f}", file=sys.stderr)
                    if f.endswith(".txt"):
                        d = difflib.unified_diff((GOLDEN / f).read_text().splitlines(), (Path(tmp) / f).read_text().splitlines(), lineterm="", n=0)
                        print("\n".join(list(d)[:20]), file=sys.stderr)
            if bad:
                sys.exit("golden files are stale: run tools/gen_golden.py and commit")
            print("golden files up to date")
    else:
        generate(GOLDEN, a.ppm)
        print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    main()
