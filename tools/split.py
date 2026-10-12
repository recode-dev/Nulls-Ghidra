#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import sys
import time

TYPES = """#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint8_t code;
typedef uint8_t undefined;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef void _UNKNOWN;
typedef void UNRECOVERED_JUMPTABLE;
"""

CFLAGS = ["-x", "c", "-std=gnu11", "-Wno-everything", "-ferror-limit=0"]

VSCODE = """{
  "files.associations": { "*.c": "c", "*.h": "c" },
  "C_Cpp.default.cStandard": "gnu11",
  "editor.tabSize": 4,
  "editor.wordWrap": "off",
  "files.trimTrailingWhitespace": false
}
"""

WORKSPACE = """{
  "folders": [ { "path": "." } ],
  "settings": {
    "files.associations": { "*.c": "c", "*.h": "c" },
    "editor.wordWrap": "off"
  }
}
"""

README = """# Decompiled build {ver}

engine {engine}, r2 {r2}, ghidra plugin {plugin}

## Open

| IDE | open |
|---|---|
| VS Code / Cursor / VSCodium | `decompiled.code-workspace` |
| CLion / IDEA | this folder |
| anything | `all.c` |

## Files

| file | what |
|---|---|
| `src/0x<addr>_<name>.c` | one function per file, header has addr/size/blocks/xrefs |
| `all.c` | every function in address order |
| `index.md` | table: addr, name, size, blocks, xrefs, file |
| `functions.csv` | all functions, dumped or not |
| `include/ghidra_types.h` | base types so the IDE is quiet |
| `include/prototypes.h` | prototypes, so ctrl+click on a call works |
| `manifest.json` | counts and timings |

## Notes

- Names like `arg1`, `iVar2`, `*(int *)(arg1 + 0xc)` come from the decompiler.
- Casts are on (`r2ghidra.casts`), lines are not wrapped.
- Import stubs (`sym.imp.*`) are not dumped.
"""


def safe(name):
    s = re.sub(r"[^A-Za-z0-9_]", "_", str(name)).strip("_")
    return (s or "sub")[:80]


def strip_lit(line):
    out = []
    i = 0
    n = len(line)
    q1 = False
    q2 = False
    while i < n:
        c = line[i]
        if q1:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                q1 = False
            i += 1
            continue
        if q2:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                q2 = False
            i += 1
            continue
        if c == '"':
            q1 = True
            i += 1
            continue
        if c == "'":
            q2 = True
            i += 1
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def braces(line):
    s = strip_lit(line)
    return s.count("{") - s.count("}")


def sig_start(s):
    if not s or s[0] in " \t}*/#":
        return False
    if "(" not in s:
        return False
    head = s.split("(", 1)[0]
    return not ("=" in head or ";" in head)


def sig_name(sig):
    head = sig.split("(", 1)[0].strip()
    if not head:
        return "unknown"
    return head.split()[-1].strip("*&") or "unknown"


def load_funcs(path):
    if not path or not os.path.exists(path):
        return {}, []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {}, []
    if not isinstance(data, list):
        return {}, []
    by = {}
    for f in data:
        if isinstance(f, dict) and f.get("name"):
            by.setdefault(f["name"], f)
    return by, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="decompiled.c")
    ap.add_argument("--funcs", default="functions.json")
    ap.add_argument("--engine", default="engine.txt")
    ap.add_argument("--out", default="decompiled")
    ap.add_argument("--ver", default="unknown")
    ap.add_argument("--keep-imports", action="store_true")
    a = ap.parse_args()

    if not os.path.exists(a.code):
        print("no %s" % a.code, file=sys.stderr)
        return 1

    src = os.path.join(a.out, "src")
    inc = os.path.join(a.out, "include")
    for d in (a.out, src, inc, os.path.join(a.out, ".vscode")):
        os.makedirs(d, exist_ok=True)

    meta, meta_list = load_funcs(a.funcs)
    eng = {}
    if os.path.exists(a.engine):
        for line in open(a.engine, encoding="utf-8"):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                eng[k] = v

    rows = []
    protos = []
    seen = set()
    state = {"w": 0, "imp": 0, "unk": 0, "orph": 0}

    all_fh = open(os.path.join(a.out, "all.c"), "w", encoding="utf-8", newline="\n")
    all_fh.write('#include "ghidra_types.h"\n#include "prototypes.h"\n\n')

    cur = None
    pend = []
    depth = 0
    opened = False
    insig = None

    def flush():
        nonlocal cur, pend, depth, opened, insig
        if cur is None:
            return
        name = cur["name"]
        pre = list(cur["pre"])
        lines = cur["lines"]
        cur = None
        opened = False
        if not a.keep_imports and (name.startswith("sym.imp.") or name.startswith("imp.")):
            state["imp"] += 1
            return
        m = meta.get(name, {})
        addr = m.get("addr")
        flags = []
        if m.get("noreturn"):
            flags.append("noreturn")
        if m.get("recursive"):
            flags.append("recursive")
        if addr is None:
            state["unk"] += 1
            fname = "zz_unknown_%03d_%s.c" % (state["unk"], safe(name))
            atxt = "?"
        else:
            fname = "0x%08x_%s.c" % (addr, safe(name))
            atxt = "0x%x" % addr
        while pre and not pre[0].strip():
            pre.pop(0)
        body = "".join(lines)
        if not body.endswith("\n"):
            body += "\n"
        head = "/* %s  %s\n * size %s  blocks %s  xrefs %s  args %s%s\n */\n" % (
            atxt, name, m.get("size", 0), m.get("nbbs", 0), m.get("indegree", 0),
            m.get("nargs", 0), "  flags: " + ",".join(flags) if flags else "")
        with open(os.path.join(src, fname), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(head)
            fh.write('#include "ghidra_types.h"\n#include "prototypes.h"\n\n')
            fh.write("".join(pre))
            fh.write(body)
        all_fh.write("/* ---- %s  %s ---- */\n" % (atxt, name))
        all_fh.write("".join(pre))
        all_fh.write(body + "\n")
        protos.append(cur_sig + ";")
        rows.append((addr or 0, atxt, name, m.get("size", 0), m.get("nbbs", 0),
                     m.get("indegree", 0), m.get("nargs", 0), " ".join(flags), fname))
        state["w"] += 1

    cur_sig = None
    with open(a.code, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.rstrip("\n")
            c = s.rstrip()

            if insig is not None:
                if not c.strip() or len(insig) >= 8 or c.startswith("}") or c.startswith("//"):
                    for x in insig:
                        pend.append(x + "\n")
                    insig = None
                    if len(pend) > 60:
                        state["orph"] += 1
                        pend = []
                    continue
                insig.append(c.strip())
                if c.endswith(")") or c.endswith("{"):
                    j = " ".join(insig)
                    cur_sig = j.rstrip("{").rstrip()
                    cur = {"name": sig_name(cur_sig), "pre": pend, "lines": [x + "\n" for x in insig]}
                    pend = []
                    depth = braces(j)
                    opened = j.endswith("{")
                    insig = None
                    if opened and depth <= 0:
                        depth = 0
                        flush()
                continue

            if cur is None:
                if depth == 0 and sig_start(c):
                    if c.endswith(")") or c.endswith("{"):
                        cur_sig = c.rstrip("{").rstrip()
                        cur = {"name": sig_name(cur_sig), "pre": pend, "lines": [line]}
                        pend = []
                        depth = braces(c)
                        opened = c.endswith("{")
                        if opened and depth <= 0:
                            depth = 0
                            flush()
                        continue
                    insig = [c]
                    continue
                pend.append(line)
                if len(pend) > 60:
                    state["orph"] += 1
                    pend = []
                continue

            cur["lines"].append(line)
            clean = strip_lit(c)
            depth += clean.count("{") - clean.count("}")
            if "{" in clean:
                opened = True
            if opened and depth <= 0:
                depth = 0
                flush()

    flush()
    all_fh.close()

    with open(os.path.join(inc, "ghidra_types.h"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(TYPES)
    with open(os.path.join(inc, "prototypes.h"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write('#pragma once\n#include "ghidra_types.h"\n\n')
        for p in protos:
            n = sig_name(p)
            if n in seen:
                continue
            seen.add(n)
            fh.write(p + "\n")

    with open(os.path.join(a.out, "compile_flags.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(CFLAGS + ["-Iinclude"]) + "\n")
    with open(os.path.join(src, "compile_flags.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(CFLAGS + ["-I../include"]) + "\n")
    with open(os.path.join(a.out, ".vscode", "settings.json"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(VSCODE)
    with open(os.path.join(a.out, "decompiled.code-workspace"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(WORKSPACE)

    rows.sort(key=lambda r: (r[0], r[2]))
    with open(os.path.join(a.out, "index.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("| addr | name | size | blocks | xrefs | args | flags | file |\n")
        fh.write("|---|---|---|---|---|---|---|---|\n")
        for _x, atxt, name, size, nbbs, xrefs, nargs, flags, fname in rows:
            fh.write("| `%s` | `%s` | %s | %s | %s | %s | %s | [%s](src/%s) |\n"
                     % (atxt, name, size, nbbs, xrefs, nargs, flags, fname, fname))

    dumped = set(r[2] for r in rows)
    with open(os.path.join(a.out, "functions.csv"), "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh)
        w.writerow(["address", "name", "size", "blocks", "xrefs", "args", "dumped"])
        for f in meta_list:
            if not isinstance(f, dict) or not f.get("name"):
                continue
            w.writerow(["0x%x" % f.get("addr", 0), f.get("name"), f.get("size", 0),
                        f.get("nbbs", 0), f.get("indegree", 0), f.get("nargs", 0),
                        "yes" if f.get("name") in dumped else "no"])

    man = {
        "version": a.ver,
        "engine": eng.get("engine", "?"),
        "r2": eng.get("r2", "?"),
        "plugin": eng.get("plugin", "?"),
        "funcs_total": len(meta_list),
        "funcs_dumped": state["w"],
        "funcs_imports": state["imp"],
        "funcs_no_addr": state["unk"],
        "unparsed": state["orph"],
        "analyze_s": eng.get("analyze_s", "0"),
        "dump_s": eng.get("dump_s", "0"),
        "renames": eng.get("renames", "0"),
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(a.out, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(a.out, "README.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(README.format(ver=a.ver, engine=man["engine"], r2=man["r2"], plugin=man["plugin"]))

    print("dumped %d, imports %d, no_addr %d, unparsed %d"
          % (state["w"], state["imp"], state["unk"], state["orph"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
