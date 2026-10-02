#!/usr/bin/env python3
"""Extract Xtensa ABI measurements; never infer hardware success from a build."""
import argparse
import json
import struct
from pathlib import Path

NAMES = ("context_bytes", "peer_bytes", "task_stack_bytes", "map_exchange_h2_bytes", "map_exchange_json_bytes", "queue_item_bytes", "peer_update_bytes")

def read_metrics(path):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        matches = elf.get_section_by_name(".symtab").get_symbol_by_name("tailnet_audit_metrics")
        if not matches or matches[0]["st_size"] != 28:
            raise ValueError("Missing or incompatible audit metrics")
        sym = matches[0]
        section = elf.get_section(sym["st_shndx"])
        offset = sym["st_value"] - section["sh_addr"]
        raw = section.data()[offset:offset + sym["st_size"]]
        return dict(zip(NAMES, struct.unpack("<7I", raw)))

def memory_report(metrics, counts):
    # The current long-poll path holds a fixed 65536-byte h2_acc plus
    # ML_JSON_BUFFER_SIZE+1 lp_acc. Use 65536+configured JSON as a lower
    # bound (ignores one byte and allocator overhead). Map-exchange buffers
    # are separate transients and must not be mistaken for retained buffers.
    base = metrics["context_bytes"] + metrics["task_stack_bytes"] + metrics["queue_item_bytes"]
    retained = 65536 + metrics["map_exchange_json_bytes"]
    per_member = base + retained
    return {"measurement": "compile-time fragmented-stream retained-state lower bound, not observed runtime peak",
            "chip_sram_bytes": 512 * 1024,
            "excluded": ["Wi-Fi", "USB", "TLS allocations", "WireGuard state", "task/queue control blocks", "packet queues", "JSON parse tree", "gateway", "map-exchange transients", "allocator overhead"],
            "abi_metrics": metrics, "per_member_lower_bound_bytes": per_member,
            "memberships": [{"count": n, "lower_bound_bytes": n * per_member,
                              "exceeds_entire_chip_sram": n * per_member > 512 * 1024} for n in counts],
            "hardware_qualified": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--counts", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    args = parser.parse_args()
    if any(n < 0 for n in args.counts):
        parser.error("Membership counts must be nonnegative")
    print(json.dumps(memory_report(read_metrics(args.elf), args.counts), indent=2))

if __name__ == "__main__":
    main()
