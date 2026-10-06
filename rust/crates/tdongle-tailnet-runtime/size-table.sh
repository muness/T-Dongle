#!/bin/sh
# The runtime's memory table on the device target (M-elf): sizes of the top-level futures and the statics, from rustc's own layout of the xtensa build.
#   rust/crates/tdongle-tailnet-runtime/size-table.sh            (from anywhere; needs the esp toolchain, `cargo +esp`)
# The host figures (M-host) are printed by `cargo test -p tdongle-tailnet-host --test memory -- --nocapture`.
set -e
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/tdongle-tailnet-target}"
OUT="${TMPDIR:-/tmp}/tdongle-runtime-typesizes.txt"
# rustc prints the layouts only when it runs: make sure it does
touch crates/tdongle-tailnet-runtime/src/lib.rs
CARGO_INCREMENTAL=0 RUSTFLAGS="-Zprint-type-sizes" cargo +esp rustc -p tdongle-tailnet-runtime --lib --target xtensa-esp32s3-none-elf \
    -Zbuild-std=core,alloc --features size-probe > "$OUT" 2>&1
python3 - "$OUT" <<'PY'
import re, sys
rows = {}
for line in open(sys.argv[1]):
    m = re.match(r'print-type-size type: `(.*)`: (\d+) bytes', line)
    if m:
        rows[m.group(1)] = int(m.group(2))

def first(pat):
    best = [(n, b) for n, b in rows.items() if re.search(pat, n)]
    best.sort(key=lambda x: -x[1])
    return best[0][1] if best else 0

def exact(prefix):
    for n, b in rows.items():
        if n.startswith(prefix):
            return b
    return 0

fut = lambda name: exact('{async fn body of ' + name)
shared_full = exact('shared::Shared<embassy_sync')
engine = exact('tdongle_tailnet_engine::Engine<tdongle_tailnet_engine::RamDirectory<3, 16, 32>')
ramdir = exact('tdongle_tailnet_engine::RamDirectory<3, 16, 32>`') or (engine - 58960)
print("M-elf (xtensa-esp32s3-none-elf), bytes")
print("  top-level futures")
for label, key in [("control, per slot", "control::control_slot"), ("derp, per slot", "derp::derp_slot"), ("udp, per slot", "udp::udp_slot"),
                   ("usb pump", "usb::usb_pump"), ("supervisor", "members::supervisor"), ("engine timer", "tasks::engine_timer"),
                   ("link watch", "tasks::link_watch"), ("dns upstream", "tasks::dns_upstream"), ("run (everything joined)", "runner::run")]:
    print(f"    {label:<28}{fut(key):>9}")
print("  statics")
slot = exact('shared::Slot<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex>')
print(f"    Slot (per membership slot) {slot:>9}   of which Workspace {exact('tdongle_tailnet_ctl::Workspace'):>6}, UDP queue, DERP queue, status {exact('shared::SlotStatus')}, identity {exact('shared::Ident')}")
print(f"    Shared, test directory     {shared_full:>9}   (engine {engine}, of which the RAM test directory {ramdir})")
print(f"    Shared, firmware estimate  {shared_full - ramdir:>9}   (without the test directory: add the flash directory's own state)")
print(f"    TLS record lease (shared)  {exact('tdongle_tailnet_tls::lease::LeasePool<'):>9}")
print(f"    DERP link (in the derp future) {exact('tdongle_tailnet_derp::Link<'):>5}")
print(f"    EmbassyNet handle          {exact('net_embassy::EmbassyNet'):>9}   (its buffers: GatewayBuffers::PER_MEMBER per slot + GATEWAY)")
PY
