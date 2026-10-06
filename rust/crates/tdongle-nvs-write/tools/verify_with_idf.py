#!/usr/bin/env python3
"""Check images written by tdongle-nvs-write with ESP-IDF's own NVS tooling.

Usage: verify_with_idf.py [--idf PATH] [--keep-going] DIR-or-IMAGE.bin ...

For every `X.bin` in the directories that has an `X.tsv` next to it (written by the Rust tests, see tests/idf.rs), this

  1. parses the image with IDF's `nvs_parser.py` (components/nvs_flash/nvs_partition_tool) and rebuilds the live key/values the way the C
     NVS reads them: pages by sequence number, entries in the written state with a valid header CRC, strings and blobs only when their
     data CRC verifies, blobs reassembled from their index and chunks, the newest item of a key wins;
  2. compares that, key by key, byte by byte, with the key/values the Rust writer reports (`X.tsv`: `namespace key type length hex`);
  3. unless `X.nocheck` exists, runs IDF's integrity checker (`nvs_check.integrity_check`, what `nvs_tool.py -i` runs) and fails on any
     finding it prints in red (duplicate entries, a blob with a missing chunk or index, an undefined namespace, a bad page CRC, no free
     page, an empty page that is not empty).

The reverse direction (images made by `nvs_partition_gen.py`, modified by the writer) is the same script: the tests copy a generated
fixture, modify it with the writer, and export the result.

Run with IDF's python environment (it only needs the standard library) from anywhere:

    ~/.espressif/python_env/idf5.5_py3.12_env/bin/python verify_with_idf.py /path/to/export-dir

Exit status 0 when every image agrees.
"""
import contextlib
import io
import os
import sys

args = sys.argv[1:]
IDF = os.environ.get('IDF_PATH', os.path.expanduser('~/.cache/tdongle/esp-idf-v5.5.5'))
keep_going = False
dirs = []
i = 0
while i < len(args):
    if args[i] == '--idf':
        IDF = args[i + 1]
        i += 2
    elif args[i] == '--keep-going':
        keep_going = True
        i += 1
    else:
        dirs.append(args[i])
        i += 1
if not dirs:
    sys.exit(__doc__)

sys.path.insert(0, os.path.join(IDF, 'components/nvs_flash/nvs_partition_tool'))
import nvs_check  # noqa: E402
import nvs_logger  # noqa: E402
import nvs_parser  # noqa: E402

RED = '\033[31m'


def live_view(data):
    """key -> (type, bytes) as the C NVS reads the partition."""
    part = nvs_parser.NVS_Partition('image', bytearray(data))
    pages = [p for p in part.pages if p.header['status'] in ('Active', 'Full', 'Erasing')
             and p.header['crc']['original'] == p.header['crc']['computed']]
    pages.sort(key=lambda p: p.header['page_index'])
    ns_names, live, chunks, idx = {}, {}, {}, {}
    for p in pages:
        for e in p.entries:
            m = e.metadata
            if e.state != 'Written' or e.is_empty or m['crc']['original'] != m['crc']['computed']:
                continue
            if m['span'] > 1 and (len(e.children) != m['span'] - 1 or any(c.state != 'Written' for c in e.children)):
                continue  # an item cut in the middle of its write
            typ = m['type']
            if typ in ('string', 'blob', 'blob_data') and m['crc']['data_original'] != m['crc']['data_computed']:
                continue
            if m['namespace'] == 0:
                ns_names[e.key] = e.data['value']
                continue
            k = (m['namespace'], e.key)
            if typ == 'blob_data':
                chunks[(k, m['chunk_index'])] = b''.join(c.raw for c in e.children)[:e.data['size']]
            elif typ == 'blob_index':
                idx[k] = (e.data['size'], e.data['chunk_count'], e.data['chunk_start'])
                live.pop(k, None)
            else:
                if typ in ('string', 'blob'):
                    val = b''.join(c.raw for c in e.children)[:e.data['size']]
                else:
                    size = int(typ.replace('uint', '').replace('int', '').replace('_t', '')) // 8
                    val = int(e.data['value']).to_bytes(size, 'little', signed=typ.startswith('int'))
                live[k] = (typ, val)
                idx.pop(k, None)
    for k, (size, count, start) in idx.items():
        try:
            val = b''.join(chunks[(k, start + i)] for i in range(count))
        except KeyError:
            continue  # a blob with a missing chunk is not readable
        if len(val) == size:
            live[k] = ('blob', val)
    names = {v: k for k, v in ns_names.items()}
    out = {}
    for (ns, key), (typ, val) in live.items():
        if ns in names:
            out[(names[ns], key)] = ('blob' if typ == 'blob_index' else typ, val)
    return out


def read_tsv(path):
    out = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            ns, key, typ, length, hexval = line.split('\t')
            val = bytes.fromhex(hexval)
            assert len(val) == int(length), (path, ns, key)
            out[(ns, key)] = (typ, val)
    return out


def integrity(data):
    """Run IDF's integrity checker; return the red findings."""
    log = nvs_logger.NVS_Logger(color='always')
    part = nvs_parser.NVS_Partition('image', bytearray(data))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        nvs_check.integrity_check(part, log)
    return [l for l in buf.getvalue().splitlines() if RED in l]


def main():
    failures = 0
    checked = 0
    for d in dirs:
        if d.endswith('.bin'):
            d, names = os.path.dirname(d) or '.', [os.path.basename(d)[:-4]]
        else:
            names = sorted(f[:-4] for f in os.listdir(d) if f.endswith('.bin') and os.path.exists(os.path.join(d, f[:-4] + '.tsv')))
        for name in names:
            base = os.path.join(d, name)
            data = open(base + '.bin', 'rb').read()
            problems = []
            want = read_tsv(base + '.tsv')
            got = live_view(data)
            for k in sorted(set(want) | set(got)):
                if k not in got:
                    problems.append(f'IDF does not see {k} (writer has {want[k][0]} len {len(want[k][1])})')
                elif k not in want:
                    problems.append(f'IDF sees {k} that the writer does not report')
                elif want[k] != got[k]:
                    problems.append(f'{k}: writer {want[k][0]} {want[k][1][:16].hex()}.. ({len(want[k][1])} B), IDF {got[k][0]} {got[k][1][:16].hex()}.. ({len(got[k][1])} B)')
            if not os.path.exists(base + '.nocheck'):
                problems += ['integrity: ' + l.replace(RED, '').replace('\033[0m', '') for l in integrity(data)]
            checked += 1
            if problems:
                failures += 1
                print(f'FAIL {name}')
                for p in problems[:20]:
                    print('   ', p)
                if not keep_going:
                    sys.exit(1)
            else:
                print(f'ok   {name} ({len(want)} keys)')
    print(f'{checked} images checked, {failures} failed')
    sys.exit(1 if failures or checked == 0 else 0)


main()
