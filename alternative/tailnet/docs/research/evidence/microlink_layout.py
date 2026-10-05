#!/usr/bin/env python3
"""Classify every top-level member of struct microlink_s (xtensa layout from gdb 'ptype /o') as
needed-per-membership / shareable / negotiation-only / dead-in-gateway, and print the top-N table.

  xtensa-esp32s3-elf-gdb -batch -ex 'ptype /o struct microlink_s' probe.o > xtensa_microlink_s_layout.txt
  python3 microlink_layout.py xtensa_microlink_s_layout.txt [N]

The class of a member is a judgement made from reading its users in components/microlink/src (see
membership-bytes.md section 1); this script only keeps the arithmetic honest."""
import re, sys, collections

NEG = r'^(auth_url|advertise_routes|nvs_auth_key|nvs_device_name|ctrl_host_parsed|ctrl_port_str|node_key_challenge|has_node_key_challenge|h2_debug|read_\w+|conn_tls_result|noise_error|noise_frame_bytes|map_(attempts|failures|bytes|declared_bytes|projected_bytes|heap_before|heap_after|largest_before|error|stream_id|frame_type|h2_error|h2_last_stream)|control_stage)$'
SHARE = r'^(derp_regions|ctrl_noise_pubkey|ctrl_noise_pubkey_valid|ctrl_key_\w+|ctrl_host|stun_primary_ip6?|stun_fallback_ip)$'
DEAD = r'^(lp_acc|lp_acc_len|config_httpd|state_cb|state_cb_data|peer_cb|peer_cb_data|data_cb|data_cb_data|disco_sock6)$'

def classify(name):
    if re.match(NEG, name): return 'negotiation-only'
    if re.match(SHARE, name): return 'shareable'
    if re.match(DEAD, name): return 'dead-in-gateway'
    return 'per-membership'

rows = []
for line in open(sys.argv[1]):
    m = re.match(r'/\*\s+(\d+)\s*\|\s+(\d+)\s*\*/(\s*)(.*)', line)
    if not m or len(m[3]) != 4 or m[4].startswith('}'): continue
    decl = m[4]
    name = re.search(r'(\w+)(\[\d+\])?;$', decl)
    if decl.startswith('struct {'): decl = {2496: 'struct { packet, expires } jit_pending[8];', 2656: 'struct { ... } inbound_trial;'}.get(int(m[1]), decl)
    rows.append((int(m[2]), int(m[1]), name.group(1) if name else decl, decl))
total = sum(r[0] for r in rows)
by = collections.Counter()
for sz, off, name, decl in rows: by[classify(name)] += sz
print(f'{len(rows)} members, {total} B of members (sizeof is 10256; the rest is alignment holes)')
for k, v in by.most_common(): print(f'  {k:18} {v:6}')
n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
print(f'\ntop {n}:')
for sz, off, name, decl in sorted(rows, reverse=True)[:n]:
    print(f'{sz:6} @{off:<6} {classify(name):18} {decl}')
