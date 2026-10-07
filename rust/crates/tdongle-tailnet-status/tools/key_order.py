#!/usr/bin/env python3
"""The ordered key sequence of the tailnet gateway's /status, extracted from the C SOURCE (no compilation): alternative/tailnet/main/gateway_main.c
(status()) and runtime_status.inc (status_shared_runtime, status_power), the latter spliced in where status() calls them.

A key is what a `NUM/STR/BOOL/RNUM/PNUM/PSIGNED("name", ...)` macro writes, a `jw_key(w, "name")` call, or a `\\"name\\":` inside a `jw_raw` literal. Loops are
expanded as for a fully populated sample: the shared tasks once per task name (read from `task_names[]`), `map_diagnostics` and `stack_free_bytes` over their
name tables (read from `diagnostic_names[]` / `stack_names[]`), a power lock once under the placeholder `<lock>` (its name is data), and the members and peers
bodies once. `if` branches are all taken.

Usage: key_order.py            print one key per line
       key_order.py --write    also (re)write tests/golden/key_order.txt (the Rust test compares against both)
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
REPO = HERE.parents[3]
MAIN = REPO / "alternative/tailnet/main"


def strip_comments(s):
    out, i, n = [], 0, len(s)
    while i < n:
        if s.startswith("/*", i):
            j = s.index("*/", i + 2)
            i = j + 2
        elif s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j < 0 else j
        elif s[i] == '"':
            j = i + 1
            while s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            out.append(s[i : j + 1])
            i = j + 1
        elif s[i] == "'":
            j = i + 1
            while s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            out.append(s[i : j + 1])
            i = j + 1
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def strip_defines(s):
    """Drop `#define` lines and their continuations: the NUM/STR/... macro bodies call jw_key(w, name) with a parameter, not a key."""
    out, skipping = [], False
    for line in s.split("\n"):
        if skipping or line.lstrip().startswith("#define"):
            skipping = line.rstrip().endswith("\\")
            continue
        out.append(line)
    return "\n".join(out)


def block(s, open_idx):
    depth = 0
    i = open_idx
    while i < len(s):
        c = s[i]
        if c == '"':
            i += 1
            while s[i] != '"':
                i += 2 if s[i] == "\\" else 1
        elif c == "'":
            i += 1
            while s[i] != "'":
                i += 2 if s[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced")


def function(s, signature):
    start = s.index(signature)
    brace = s.index("{", s.index(")", start))
    return s[brace : block(s, brace) + 1]


def literal_array(s, name):
    m = re.search(r"%s\s*(?:\[[^\]]*\])?\s*=\s*\{([^}]*)\}" % re.escape(name), s)
    return re.findall(r'"([^"]*)"', m.group(1))


EVENT = re.compile(
    r"""(?P<macro>\b(?:NUM|STR|BOOL|RNUM|PNUM|PSIGNED)\("(?P<mk>[A-Za-z0-9_]+)")
      |(?P<jwkey>\bjw_key\(w,\s*(?:"(?P<jk>[A-Za-z0-9_]+)"|(?P<dyn>[A-Za-z_][A-Za-z0-9_\[\]>.-]*))\s*\))
      |(?P<raw>\bjw_raw\(w,\s*(?P<lit>"(?:[^"\\]|\\.)*")\s*\))
      |(?P<call>\bstatus_(?:shared_runtime|power)\(w\))
      |(?P<loop>\bfor\s*\(unsigned\s+t\s*=\s*0;\s*t\s*<\s*ML_RT_TASK_COUNT;\s*t\+\+\)\s*\{)""",
    re.X | re.S,
)


def events(text, tables, functions):
    out = []
    pos = 0
    while True:
        m = EVENT.search(text, pos)
        if not m:
            return out
        if m.group("macro"):
            out.append(m.group("mk"))
            pos = m.end()
        elif m.group("jwkey"):
            if m.group("jk"):
                out.append(m.group("jk"))
            else:
                d = m.group("dyn")
                if d.startswith("task_names"):
                    out.append("@task")  # replaced per task by the loop below
                elif d.startswith("diagnostic_names"):
                    out.extend(tables["diagnostic_names"])
                elif d.startswith("stack_names"):
                    out.extend(tables["stack_names"])
                elif d == "b->name":
                    out.append("<lock>")
                else:
                    raise SystemExit("unknown dynamic key: " + d)
            pos = m.end()
        elif m.group("raw"):
            lit = m.group("lit")
            out.extend(re.findall(r'\\"([A-Za-z0-9_]+)\\":', lit))
            pos = m.end()
        elif m.group("call"):
            name = m.group("call")[:-3]
            out.extend(events(functions[name], tables, functions))
            pos = m.end()
        else:  # the shared-task loop
            brace = m.end() - 1
            end = block(text, brace)
            body = events(text[brace : end + 1], tables, functions)
            for task in tables["task_names"]:
                out.extend(task if k == "@task" else k for k in body)
            pos = end + 1


def extract():
    gw = strip_defines(strip_comments((MAIN / "gateway_main.c").read_text()))
    rs = strip_defines(strip_comments((MAIN / "runtime_status.inc").read_text()))
    status_fn = function(gw, "static esp_err_t status(httpd_req_t *req)")
    functions = {
        "status_shared_runtime": function(rs, "static void status_shared_runtime(jw_writer *w)"),
        "status_power": function(rs, "static void status_power(jw_writer *w)"),
    }
    tables = {
        "task_names": literal_array(rs, "task_names"),
        "diagnostic_names": literal_array(status_fn, "diagnostic_names"),
        "stack_names": literal_array(status_fn, "stack_names"),
    }
    return events(status_fn, tables, functions)


if __name__ == "__main__":
    keys = extract()
    text = "\n".join(keys) + "\n"
    sys.stdout.write(text)
    if "--write" in sys.argv:
        (CRATE / "tests/golden/key_order.txt").write_text(text)
