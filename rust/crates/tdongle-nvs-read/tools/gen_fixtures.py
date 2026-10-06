#!/usr/bin/env python3
"""Generate the NVS test images with ESP-IDF's own nvs_partition_gen.py and dump what ESP-IDF's own nvs_parser.py reads back.

Usage: gen_fixtures.py <idf-path> <out-dir>   (run with the IDF python env; see regen.sh)

For every image X.bin an X.expected is written: one line per live (namespace, key) as `ns<TAB>key<TAB>type<TAB>len<TAB>entry_offset<TAB>hex`,
computed with IDF's parser (CRCs verified, children joined, chunked blobs reassembled, newest page wins). The Rust tests compare against it.
"""
import csv, os, struct, subprocess, sys, tempfile, zlib

IDF = os.path.abspath(sys.argv[1])
OUT = os.path.abspath(sys.argv[2])
GEN = os.path.join(IDF, 'components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py')
sys.path.insert(0, os.path.join(IDF, 'components/nvs_flash/nvs_partition_tool'))
import nvs_parser  # noqa: E402

SIZE = 0x10000


def profiles_blob():
    """tn_settings/wifi_profiles: u32 schema=1, u32 count, 8 x {char ssid[33]; char password[64]} = 784 bytes."""
    nets = [('HomeNet', 'hunter2hunter2'), ('Cafe Wi-Fi', ''), ('x' * 32, 'p' * 63)]
    b = struct.pack('<II', 1, len(nets))
    for i in range(8):
        s, p = nets[i] if i < len(nets) else ('', '')
        b += s.encode().ljust(33, b'\0') + p.encode().ljust(64, b'\0')
    assert len(b) == 784
    return b


def meta_blob():
    return struct.pack('<II', 1, 0) + bytes((i * 7 + 3) & 0xFF for i in range(516 - 8))


def display_blob():
    return bytes([1, 0, 2, 0xB0, 0x20, 0, 0, 0])


def adapter_blob():
    return bytes((i * 13 + 1) & 0xFF for i in range(1004))


def pattern(n, seed):
    x = seed
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def rows_main():
    return [
        ('tn_settings', 'namespace', '', ''),
        ('mode', 'data', 'u8', 2),
        ('members', 'data', 'string', 'alice,bob,carol'),
        ('wifi_profiles', 'blob', 'binary', profiles_blob()),
        ('wifi_meta', 'blob', 'binary', meta_blob()),
        ('display', 'blob', 'binary', display_blob()),
        ('adapter', 'namespace', '', ''),
        ('config', 'blob', 'binary', adapter_blob()),
    ]


def rows_prims():
    return [
        ('prims', 'namespace', '', ''),
        ('u8', 'data', 'u8', 255), ('i8', 'data', 'i8', -128), ('u16', 'data', 'u16', 65535), ('i16', 'data', 'i16', -32768),
        ('u32', 'data', 'u32', 4294967295), ('i32', 'data', 'i32', -2147483648),
        ('u64', 'data', 'u64', 18446744073709551615), ('i64', 'data', 'i64', -9223372036854775808),
        ('str', 'data', 'string', 'x' * 100),
        ('k_exactly_15ch', 'data', 'u8', 15),
    ]


def rows_big():
    rows = rows_main()
    rows += [('big', 'namespace', '', ''),
             ('blob6000', 'blob', 'binary', pattern(6000, 1)),
             ('blob4000', 'blob', 'binary', pattern(4000, 2)),
             ('blob8000', 'blob', 'binary', pattern(8000, 3)),
             ('small', 'blob', 'binary', b'abc'),
             ('empty', 'data', 'string', 'e')]
    return rows


def rows_many():
    rows = [('many', 'namespace', '', '')]
    for i in range(400):
        rows.append((f'k{i}', 'data', 'u32', i * 65537))
        if i % 10 == 0:
            rows.append((f's{i}', 'data', 'string', f'value number {i} ' + 'z' * (i % 90)))
    rows.append(('second', 'namespace', '', ''))
    rows += [('k1', 'data', 'u8', 77), ('b', 'blob', 'binary', pattern(1500, 9))]
    return rows


def rows_overwrite():
    # The generator appends items in order, so a repeated key is a newer item superseding the older one (as after an NVS update that
    # left the old item behind).
    return [
        ('tn_settings', 'namespace', '', ''),
        ('mode', 'data', 'u8', 1),
        ('members', 'data', 'string', 'old'),
        ('wifi_profiles', 'blob', 'binary', pattern(784, 4)),
        ('big', 'blob', 'binary', pattern(6000, 5)),
        ('mode', 'data', 'u8', 3),
        ('members', 'data', 'string', 'new members'),
        ('wifi_profiles', 'blob', 'binary', profiles_blob()),
        ('big', 'blob', 'binary', pattern(5000, 6)),
        ('other', 'namespace', '', ''),
        ('mode', 'data', 'u8', 9),
    ]


BOARD_NETS = [('217IoT', 'iot-password-217', 'Home', 50), ('iPhone', 'phone-password', 'Phone', 80), ('217IoT_EXT', 'iot-password-217', 'Extender', 60)]


def legacy_blob(nets, preferred):
    """adapter/config of the v0.1.x firmware: u32 version=1, 8 x profile_t {name[25], ssid[33], pass[65], priority}, preferred @996, brightness, rotation,
    pad, dim_seconds u16 @1000, 2 bytes of tail padding (1004 bytes)."""
    b = struct.pack('<I', 1)
    for i in range(8):
        if i < len(nets):
            ssid, pw, name, prio = nets[i]
            b += name.encode().ljust(25, b'\0') + ssid.encode().ljust(33, b'\0') + pw.encode().ljust(65, b'\0') + bytes([prio])
        else:
            b += bytes(124)
    b += bytes([preferred, 60, 0, 0]) + struct.pack('<H', 30) + bytes(2)
    assert len(b) == 1004
    return b


def wifi_config_blob(ssid, password):
    """tn_settings/wifi: a wifi_config_t (184 bytes in IDF v5.5.5: sta = ssid[32], password[64], ...), as `nvs_set_blob(store, "wifi", &wifi_config)`."""
    b = ssid.encode().ljust(32, b'\0') + password.encode().ljust(64, b'\0')
    return b + bytes(184 - len(b))


def meta_blob_for(nets, preferred_ssid):
    b = struct.pack('<II', 1, len(nets)) + preferred_ssid.encode().ljust(33, b'\0')
    for i in range(8):
        if i < len(nets):
            ssid, _pw, name, prio = nets[i]
            b += ssid.encode().ljust(33, b'\0') + name.encode().ljust(25, b'\0') + bytes([prio])
        else:
            b += bytes(59)
    b += bytes(3)
    assert len(b) == 516
    return b


def profiles_for(nets):
    b = struct.pack('<II', 1, len(nets))
    for i in range(8):
        s, p = (nets[i][0], nets[i][1]) if i < len(nets) else ('', '')
        b += s.encode().ljust(33, b'\0') + p.encode().ljust(64, b'\0')
    assert len(b) == 784
    return b


def rows_board_v01():
    """A board that ran the v0.1.x bridge firmware, then the unified firmware without ever saving the list: the first network is the driver's
    single `tn_settings/wifi` config, the others are only in `adapter/config`. There is no `wifi_profiles` key."""
    return [
        ('tn_settings', 'namespace', '', ''),
        ('mode', 'data', 'u8', 1),
        ('wifi', 'blob', 'binary', wifi_config_blob('217IoT', 'iot-password-217')),
        ('adapter', 'namespace', '', ''),
        ('config', 'blob', 'binary', legacy_blob([BOARD_NETS[1], BOARD_NETS[2], BOARD_NETS[0]], 0)),
    ]


def rows_board_v03():
    """A board that saved its list with the unified firmware: `wifi_profiles` and `wifi_meta` (preferred = iPhone), and the old keys still there."""
    return [
        ('tn_settings', 'namespace', '', ''),
        ('mode', 'data', 'u8', 1),
        ('wifi', 'blob', 'binary', wifi_config_blob('217IoT', 'iot-password-217')),
        ('wifi_profiles', 'blob', 'binary', profiles_for(BOARD_NETS)),
        ('wifi_meta', 'blob', 'binary', meta_blob_for(BOARD_NETS, 'iPhone')),
        ('adapter', 'namespace', '', ''),
        ('config', 'blob', 'binary', legacy_blob([BOARD_NETS[1]], 0)),
    ]


def write_csv(rows, path, tmp):
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['key', 'type', 'encoding', 'value'])
        for key, typ, enc, val in rows:
            if typ == 'blob':
                p = os.path.join(tmp, f'blob_{abs(hash((key, val)))}.bin')
                with open(p, 'wb') as bf:
                    bf.write(val)
                w.writerow([key, 'file', 'binary', p])
            else:
                w.writerow([key, typ, enc, val])


def generate(name, rows, version=2, size=SIZE):
    with tempfile.TemporaryDirectory() as tmp:
        csvp = os.path.join(tmp, name + '.csv')
        write_csv(rows, csvp, tmp)
        outp = os.path.join(OUT, name + '.bin')
        subprocess.run([sys.executable, GEN, 'generate', '--version', str(version), csvp, outp, hex(size)],
                       check=True, stdout=subprocess.DEVNULL)
    dump(name)


def dump(name):
    """What IDF's parser reads from OUT/name.bin, written to OUT/name.expected."""
    data = bytearray(open(os.path.join(OUT, name + '.bin'), 'rb').read())
    part = nvs_parser.NVS_Partition(name, data)
    pages = [p for p in part.pages if p.header['status'] in ('Active', 'Full', 'Erasing')]
    for p in pages:
        assert p.header['crc']['original'] == p.header['crc']['computed']
    pages.sort(key=lambda p: p.header['page_index'])
    ns_names, live, chunks, idx = {}, {}, {}, {}
    for p in pages:
        for e in p.entries:  # the parser lists item headers only; data entries hang off them as children
            m = e.metadata
            if e.state != 'Written' or e.is_empty:
                continue
            if m['crc']['original'] != m['crc']['computed']:
                continue
            off = p.start_address + 64 + e.index * 32
            if m['namespace'] == 0:
                ns_names[e.key] = e.data['value']
                continue
            typ = m['type']
            k = (m['namespace'], e.key)
            if typ == 'blob_data':
                assert m['crc']['data_original'] == m['crc']['data_computed']
                chunks[(k, m['chunk_index'])] = b''.join(c.raw for c in e.children)[:e.data['size']]
            elif typ == 'blob_index':
                idx[k] = (e.data['size'], e.data['chunk_count'], e.data['chunk_start'], off)
                live.pop(k, None)
            else:
                if typ in ('string', 'blob'):
                    assert m['crc']['data_original'] == m['crc']['data_computed']
                    val = b''.join(c.raw for c in e.children)[:e.data['size']]
                else:
                    size = int(typ.replace('uint', '').replace('int', '').replace('_t', '')) // 8
                    val = int(e.data['value']).to_bytes(size, 'little', signed=typ.startswith('int'))
                live[k] = (typ, val, off)
                idx.pop(k, None)
    for k, (size, count, start, off) in idx.items():
        val = b''.join(chunks[(k, start + i)] for i in range(count))
        assert len(val) == size
        live[k] = ('blob_index', val, off)
    names = {v: k for k, v in ns_names.items()}
    with open(os.path.join(OUT, name + '.expected'), 'w') as f:
        for (ns, key), (typ, val, off) in sorted(live.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            f.write(f'{names[ns]}\t{key}\t{typ}\t{len(val)}\t{off}\t{val.hex()}\n')


def main():
    os.makedirs(OUT, exist_ok=True)
    generate('main_v2', rows_main())
    generate('main_v1', rows_main(), version=1)
    generate('prims', rows_prims())
    generate('big_v2', rows_big())
    generate('many_v2', rows_many())
    generate('overwrite_v2', rows_overwrite())
    generate('overwrite_v1', [r for r in rows_overwrite() if r[0] != 'big'], version=1)
    generate('board_v01', rows_board_v01())
    generate('board_v03', rows_board_v03())
    # A one-page image (the generator emits 0x1000 bytes for a 0x2000 request).
    generate('tiny_v2', rows_main()[:4], size=0x2000)


if __name__ == '__main__':
    main()
