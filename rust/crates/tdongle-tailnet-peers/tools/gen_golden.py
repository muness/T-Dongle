#!/usr/bin/env python3
"""Generate tests/golden/wg_pool.golden of tdongle-tailnet-peers from the REAL C source.

The `"wg_pool":{...},` fragment is cut programmatically out of main/runtime_status.inc (by marker), compiled with the real `json_writer.inc` and the real
`ml_wg_pool_status_t` typedef (cut out of microlink_internal.h), and run over seeded scenarios. Output: tests/golden/wg_pool.scen (inputs) and
wg_pool.golden (container of `@@@@ SCENARIO <name> LEN <n> @@@@\\n<n bytes>\\n@@@@ END @@@@\\n`). Run `sh tools/regen.sh`; needs `cc` and python3.
"""
import random
import re
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "tests" / "golden"
TAILNET = HERE.parents[3] / "alternative" / "tailnet"
MAIN = TAILNET / "main"
INC = TAILNET / "components" / "microlink" / "include"

status = (MAIN / "runtime_status.inc").read_text()
a = status.index('jw_raw(w, "\\"wg_pool\\":{");')
b = status.index("ml_rng_stats_t rng;")
BLOCK = status[a:b]
RNUM = re.search(r"#define RNUM\(name, value\).*", status).group(0)
TYPEDEF = re.search(r"typedef struct \{\s*uint32_t capacity, used.*?\} ml_wg_pool_status_t;", (INC / "microlink_internal.h").read_text(), re.S).group(0)
KEYS = "capacity used peak refused_full refused_nomem evictions_own evictions_other rejected refused_largest refused_heap largest_low slot_bytes device_bytes".split()

random.seed(0x9001)
scen = []
scen.append(("zero", {k: 0 for k in KEYS} | {"largest_low": 4294967295}))
scen.append(("none_yet", {k: 7 for k in KEYS} | {"largest_low": 4294967295}))
scen.append(("max", {k: 4294967295 for k in KEYS} | {"largest_low": 4294967294}))
for i in range(30):
    d = {k: random.randint(0, 2**32 - 1) for k in KEYS}
    d["largest_low"] = 4294967295 if i % 4 == 0 else random.randint(0, 60000)
    d["capacity"] = random.randint(1, 16)
    scen.append((f"random{i}", d))

C = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
''' + f'''
#include "json_writer.inc"
{TYPEDEF}
{RNUM}
static ml_wg_pool_status_t pool;
static void emit_pool(jw_writer *w) {{
{BLOCK}
}}
''' + r'''
typedef struct { char *data; size_t len, cap; } outbuf;
static int out_sink(void *ctx, const char *p, size_t n) {
    outbuf *o = ctx;
    if (o->len + n + 1 > o->cap) { o->cap = (o->len + n + 1) * 2; o->data = realloc(o->data, o->cap); }
    memcpy(o->data + o->len, p, n); o->len += n; o->data[o->len] = 0; return 0;
}
int main(int argc, char **argv) {
    (void)argc; FILE *f = fopen(argv[1], "r"); char line[1024]; outbuf o = {0};
    while (fgets(line, sizeof line, f)) {
        char name[64]; unsigned long long v[13];
        if (sscanf(line, "%63s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", name, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10], &v[11], &v[12]) != 14) continue;
        pool = (ml_wg_pool_status_t){v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12]};
        jw_writer w = {.context = &o, .sink = out_sink}; o.len = 0;
        emit_pool(&w); jw_flush(&w);
        printf("@@@@ SCENARIO %s LEN %zu @@@@\n", name, o.len); fwrite(o.data, 1, o.len, stdout); printf("\n@@@@ END @@@@\n");
    }
    return 0;
}
'''


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    lines = [name + " " + " ".join(str(d[k]) for k in KEYS) for name, d in scen]
    (OUT / "wg_pool.scen").write_text("\n".join(lines) + "\n")
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        (t / "g.c").write_text(C)
        subprocess.run(["cc", "-std=c11", "-O0", "-Wno-unused-function", "-I", str(MAIN), str(t / "g.c"), "-o", str(t / "g")], check=True)
        res = subprocess.run([str(t / "g"), str(OUT / "wg_pool.scen")], check=True, stdout=subprocess.PIPE).stdout
    (OUT / "wg_pool.golden").write_bytes(res)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
