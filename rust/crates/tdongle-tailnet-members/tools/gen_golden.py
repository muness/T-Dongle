#!/usr/bin/env python3
"""Generate tests/golden/{load,save}.golden from the REAL C code: `save_members`, `identify` and `load_members` are cut out of
alternative/tailnet/main/gateway_main.c (as tools/test-resilience.py does for test_settings.c) and compiled with the real cJSON.c of ESP-IDF
(cJSON 1.7.19) behind NVS stubs. A seeded corpus (valid documents, hand-made edge cases, mutations) is run through them.

  load.golden   one line per input:   <hex of input>\t<REJECT | OK next_id=N n=K [id,enabled,label_hex,key_hex,namespace,hostname]...>
  save.golden   one line per input:   <next_id> <count> (<id> <enabled> <label_hex|-> <key_hex|->)... \t<OK hex(json) | FAIL>

Needs `cc`, python3 and an ESP-IDF checkout (IDF_PATH, default ~/esp/esp-idf-v5.5.5) for cJSON. Output is checked in; run through this script only when
the C changes."""
import os, random, re, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
REPO = HERE.parents[3]
MAIN_C = REPO / "alternative/tailnet/main/gateway_main.c"
IDF = Path(os.environ.get("IDF_PATH") or Path.home() / "esp/esp-idf-v5.5.5")
CJSON = IDF / "components/json/cJSON"
GOLDEN = CRATE / "tests/golden"

PRELUDE = r'''
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "cJSON.h"
#ifndef __APPLE__
static size_t strlcpy(char *d, const char *s, size_t n){size_t l=strlen(s);if(n){size_t c=l>=n?n-1:l;memcpy(d,s,c);d[c]=0;}return l;}
#endif
#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 2
#define ESP_ERR_INVALID_SIZE 3
#define TDONGLE_OWNER_MAP 0
#define tdongle_heap_free(o,p) free(p)
typedef int esp_err_t;
typedef struct membership {struct membership *next;uint32_t id;char label[24],ns[16],key[160],hostname[48],error[64];bool enabled;} membership_t;
static membership_t *members;
static bool settings_ok=true;
static uint32_t next_id=1;
static int store;
static char persisted[1<<17];
static int nvs_set_str(int h,const char *key,const char *s){assert(strlen(s)<sizeof(persisted));strcpy(persisted,s);return 0;}
static int nvs_get_str(int h,const char *key,char *s,size_t *n){if(!persisted[0])return ESP_ERR_NVS_NOT_FOUND;if(s)memcpy(s,persisted,strlen(persisted)+1);*n=strlen(persisted)+1;return 0;}
static int nvs_commit(int h){return 0;}
'''

MAIN = r'''
static int unhex(const char *h, unsigned char *out){ if(!strcmp(h,"-"))return 0; int n=strlen(h)/2; for(int i=0;i<n;i++){unsigned v;sscanf(h+2*i,"%2x",&v);out[i]=v;} return n; }
static void hexout(const unsigned char *b,int n){ if(!n){printf("-");return;} for(int i=0;i<n;i++)printf("%02x",b[i]); }
int main(void){
  static char line[1<<18];
  while(fgets(line,sizeof line,stdin)){
    line[strcspn(line,"\n")]=0;
    if(line[0]=='L'){
      int n=unhex(line+2,(unsigned char*)persisted); persisted[n]=0;
      members=NULL; next_id=777;
      bool ok=load_members();
      if(!ok){puts("REJECT");continue;}
      unsigned count=0;for(membership_t *m=members;m;m=m->next)count++;
      printf("OK next_id=%u n=%u",(unsigned)next_id,count);
      for(membership_t *m=members;m;m=m->next){printf(" [%u,%d,",(unsigned)m->id,m->enabled);hexout((unsigned char*)m->label,strlen(m->label));printf(",");hexout((unsigned char*)m->key,strlen(m->key));printf(",%s,",m->ns);hexout((unsigned char*)m->hostname,strlen(m->hostname));printf("]");}
      puts("");
      while(members){membership_t *x=members->next;free(members);members=x;}
    } else if(line[0]=='S'){
      char *p=line+2; unsigned nid,cnt; int off; sscanf(p,"%u %u%n",&nid,&cnt,&off); p+=off;
      membership_t *head=NULL,**tail=&head;
      for(unsigned i=0;i<cnt;i++){
        unsigned id; int en; char lh[600],kh[600]; sscanf(p,"%u %d %599s %599s%n",&id,&en,lh,kh,&off); p+=off;
        membership_t *m=calloc(1,sizeof *m); m->id=id; m->enabled=en;
        unsigned char tmp[400]; int l=unhex(lh,tmp); memcpy(m->label,tmp,l>23?23:l);
        l=unhex(kh,tmp); memcpy(m->key,tmp,l>159?159:l);
        *tail=m; tail=&m->next;
      }
      members=head; next_id=nid; persisted[0]=0;
      bool ok=save_members();
      if(!ok){puts("FAIL");}else{printf("OK ");hexout((unsigned char*)persisted,strlen(persisted));puts("");}
      while(members){membership_t *x=members->next;free(members);members=x;}
    }
  }
  return 0;
}
'''

def hx(b): return b.hex() if b else "-"

def build():
    src = MAIN_C.read_text()
    a = src.index("static bool save_members(")
    b = src.index("static bool stop_member(", a)
    body = src[a:b]
    d = Path(tempfile.mkdtemp())
    (d / "h.c").write_text(PRELUDE + body + MAIN)
    exe = d / "h"
    subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-I", str(CJSON), str(d / "h.c"), str(CJSON / "cJSON.c"), "-o", str(exe)], check=True)
    return exe

def run(exe, lines):
    p = subprocess.run([str(exe)], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    out = p.stdout.splitlines()
    assert len(out) == len(lines), (len(out), len(lines), p.stderr[:500])
    return out

def doc(members, next_id):
    items = ",".join('{"id":%d,"label":"%s","key":"%s","enabled":%s}' % (i, l, k, "true" if e else "false") for i, l, k, e in members)
    return '{"members":[%s],"next_id":%s}' % (items, next_id)

def corpus(rnd):
    c = []
    base = [
        doc([(1, "work", "", True), (2, "personal", "tskey-auth-abc", False)], 3),
        doc([], 1), doc([(1, "a", "", True)], 2),
        doc([(5, "Work-1", "k" * 159, True), (2, "x" * 20, "", False)], 9),
    ]
    c += base
    edge = [
        '', ' ', '{}', '[]', 'null', '{"members":[],"next_id":1}', '{"next_id":1,"members":[]}', ' \n\t{"members":[],"next_id":1} trailing garbage',
        '﻿{"members":[],"next_id":1}', '\xef\xbb\xbf{"members":[],"next_id":1}',
        '{"MEMBERS":[],"NEXT_ID":2}', '{"members":[],"members":5,"next_id":2}', '{"members":5,"members":[],"next_id":2}',
        '{"members":[],"next_id":0}', '{"members":[],"next_id":4294967295}', '{"members":[],"next_id":4294967294}', '{"members":[],"next_id":4294967296}',
        '{"members":[],"next_id":1.5}', '{"members":[],"next_id":3.0}', '{"members":[],"next_id":3e0}', '{"members":[],"next_id":03}', '{"members":[],"next_id":3.}',
        '{"members":[],"next_id":-3}', '{"members":[],"next_id":"3"}', '{"members":[],"next_id":+3}', '{"members":[],"next_id":.5}', '{"members":[],"next_id":1e}',
        '{"members":[],"next_id":1e999}', '{"members":[],"next_id":0x3}', '{"members":[],"next_id":2,}', '{"members":[],"next_id":2 "x":1}', '{"members":[,],"next_id":2}',
        '{"members":[{"id":1,"label":"a","key":"","enabled":true}],"next_id":2}',
        '{"members":[{"id":1,"label":"a","key":"","enabled":true}],"next_id":1}',
        '{"members":[{"id":1,"label":"a","key":"","enabled":1}],"next_id":2}',
        '{"members":[{"id":1,"label":"a","key":"","enabled":null}],"next_id":2}',
        '{"members":[{"id":1,"label":"a","key":null,"enabled":true}],"next_id":2}',
        '{"members":[{"id":1,"label":"a","enabled":true}],"next_id":2}',
        '{"members":[{"id":1,"label":"","key":"","enabled":true}],"next_id":2}',
        '{"members":[{"id":1,"label":"a","key":"","enabled":true},{"id":2,"label":"A","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"a","key":"","enabled":true},{"id":1,"label":"b","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":2,"label":"a","key":"","enabled":true},{"id":1,"label":"b","key":"","enabled":false}],"next_id":3}',
        '{"members":[{"id":1.5,"label":"a","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":0,"label":"a","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"ID":1,"LABEL":"a","Key":"k","Enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"id":2,"label":"a","label":"b","key":"","enabled":true,"enabled":false}],"next_id":3}',
        '{"members":[{"id":1,"label":"a\\u0000b","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"\\u0000","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"\\u00e9\\u20ac\\ud83d\\ude00","key":"\\u0041\\u0042","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"\\ud83d","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"\\udc00","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"\\ud83dx","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"\\uZZZZ","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"\\u12","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"a\\q","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"a\\/\\b\\f\\n\\r\\t\\"\\\\","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"a\tb","key":"raw\nnewline\x7f\xc3\xa9\xff","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"' + "x" * 20 + '","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"' + "x" * 21 + '","key":"","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"a","key":"' + "k" * 159 + '","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"a","key":"' + "k" * 160 + '","enabled":true}],"next_id":3}',
        '{"members":[{"id":1,"label":"a","key":"' + "k\\u0000" + "k" * 300 + '","enabled":true}],"next_id":3}',
        '{"members":[5],"next_id":3}', '{"members":[[]],"next_id":3}', '{"members":[{}],"next_id":3}', '{"members":[null],"next_id":3}',
        '{"members":[{"id":1,"label":"a","key":"","enabled":true,"extra":[1,2,{"x":[]}]}],"next_id":3}',
        '{"x":' + "[" * 998 + "]" * 998 + ',"members":[],"next_id":1}',
        '{"x":' + "[" * 999 + "]" * 999 + ',"members":[],"next_id":1}',
        '{"x":' + "[" * 1000 + "]" * 1000 + ',"members":[],"next_id":1}',
        '{"x":' + "[" * 1001 + "]" * 1001 + ',"members":[],"next_id":1}',
        '{"x":' + "[" * 600 + "{\"a\":" * 400 + "1" + "}" * 400 + "]" * 600 + ',"members":[],"next_id":1}',
        '{"members":[],"next_id":1,"x":nul}', '{"members":[],"next_id":1,"x":nullx}', '{"members":[],"next_id":1,"x":truefalse}',
        '{"members":[] "next_id":1}', '{"members":[],"next_id" 1}', '{members:[],"next_id":1}', "{'members':[],'next_id':1}",
        '{"members":[],"next_id":1', '{"members":[]', '{"members":[],"next_id":1}}',
        '{"mem\\u0062ers":[],"next\\u005fid":2}',
        '{"members":[],"next_id":1}' + " " * (16383 - 26),
        '{"members":[],"next_id":1}' + " " * (16384 - 26),
        '{"members":[],"next_id":1}' + " " * (16385 - 26),
    ]
    c += edge
    muts = ['"', '\\', '\\u0000', '\\ud83d\\ude00', '\\udc00', 'null', 'true', 'false', '1e999', '-1', '0', '1.5', '01', '+1', ' ', '\n', '{', '}', '[', ']', ',', ':',
            '"id"', '"ID"', '"Label"', 'x' * 21, '9' * 12, '\x00'[:0], '\x7f', '\xc3\xa9', '\xff', 'e', '.', '-', '"members"']
    for _ in range(2600):
        s = rnd.choice(base + edge[:60])
        for _ in range(rnd.choice([1, 1, 2, 3])):
            kind = rnd.randrange(5)
            if not s: break
            i = rnd.randrange(len(s) + 1)
            if kind == 0: s = s[:i] + rnd.choice(muts) + s[i:]
            elif kind == 1: s = s[:i] + s[i + rnd.randrange(1, 4):]
            elif kind == 2: s = s[:i]
            elif kind == 3:
                j = min(len(s), i + rnd.randrange(1, 6)); s = s[:i] + rnd.choice(muts) + s[j:]
            else: s = s[:i] + s[i:i + 6] + s[i:]
        c.append(s)
    return c

def to_bytes(s):
    # corpus strings are latin-1 style for the raw-byte cases; encode: chars < 256 as single bytes except the explicit BOM char
    if "﻿" in s: return s.encode("utf-8")
    return s.encode("latin-1", errors="strict")

def save_cases(rnd):
    cases = []
    cases.append((3, [(1, True, b"work", b""), (2, False, b"personal", b"test-key")]))
    cases.append((1, []))
    cases.append((4294967294, [(4294967293, True, b"max", b"k")]))
    tricky = [b'qu"ote', b"back\\slash", b"tab\there", bytes(range(1, 32)), b"\x7f\x80\xff\xc3\xa9", b"/slash", b"{}[],:"]
    for t in tricky:
        cases.append((9, [(1, True, b"a", t), (2, False, t[:20], b"")]))
    for _ in range(300):
        n = rnd.randrange(0, 10)
        mem = []
        for i in range(n):
            lab = bytes(rnd.choice(b"abcXYZ019-_ \"\\\n\x01\x7f\xe9") for _ in range(rnd.randrange(1, 21)))
            key = bytes(rnd.randrange(1, 256) for _ in range(rnd.choice([0, 0, 5, 40, 159])))
            mem.append((rnd.randrange(1, 1 << 32), rnd.random() < .5, lab, key))
        cases.append((rnd.randrange(1, 1 << 32), mem))
    # the 16 KB limit: 16384 bytes or more is refused by save_members()
    for count in (60, 70, 72, 75, 80, 100):
        cases.append((200, [(i + 1, True, ("m%d" % i).encode(), b"k" * 159) for i in range(count)]))
    # land exactly on the 16383 / 16384 / 16385 byte boundary: 69 full members and one whose key length is tuned
    for target in (16383, 16384, 16385):
        done = False
        for full in range(60, 90):
            for t1 in range(0, 160):
                def build_mem(t2):
                    return ([(i + 1, True, ("m%d" % i).encode(), b"k" * 159) for i in range(full)]
                            + [(full + 1, True, b"p", b"j" * t1), (full + 2, True, b"q", b"j" * t2)])
                base_len = len(doc([(i, l.decode(), k.decode(), e) for i, e, l, k in build_mem(0)], 200))
                need = target - base_len
                if 0 <= need <= 159:
                    cases.append((200, build_mem(need)))
                    done = True
                    break
            if done:
                break
        assert done
    return cases

def main():
    exe = build()
    rnd = random.Random(20260506)
    inputs = [to_bytes(s) for s in corpus(rnd)]
    # a bare newline would split the line protocol; the C reads NVS strings, not lines: map it to a 'space' only where it cannot matter -> keep \n via hex.
    lines = ["L " + (hx(b) if b else "-") for b in inputs]
    outs = run(exe, lines)
    GOLDEN.mkdir(parents=True, exist_ok=True)
    with open(GOLDEN / "load.golden", "w") as f:
        for b, o in zip(inputs, outs):
            f.write("%s\t%s\n" % (hx(b), o))
    cases = save_cases(rnd)
    slines = []
    specs = []
    for nid, mem in cases:
        spec = "%d %d" % (nid, len(mem)) + "".join(" %d %d %s %s" % (i, 1 if e else 0, hx(l), hx(k)) for i, e, l, k in mem)
        specs.append(spec)
        slines.append("S " + spec)
    souts = run(exe, slines)
    with open(GOLDEN / "save.golden", "w") as f:
        for s, o in zip(specs, souts):
            f.write("%s\t%s\n" % (s, o))
    n_ok = sum(1 for o in outs if o.startswith("OK"))
    print("load: %d cases, %d accepted; save: %d cases, %d refused" % (len(outs), n_ok, len(souts), sum(1 for o in souts if o == "FAIL")))

if __name__ == "__main__":
    main()
