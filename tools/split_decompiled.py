#!/usr/bin/env python3
"""Раскладывает дамп декомпилятора в дерево, которое удобно читать в IDE.

Что получается в каталоге --out:
  src/0x<адрес>_<имя>.c    по файлу на функцию, в шапке адрес/размер/блоки/xrefs
  all.c                    те же функции подряд (поиск и outline по одному файлу)
  include/ghidra_types.h   типы, которые встречаются в коде (чтобы IDE их понимала)
  include/prototypes.h     прототипы всех выгруженных функций
  index.md                 таблица: адрес, имя, размер, блоки, xrefs, ссылка на файл
  functions.csv            метаданные по всем функциям бинаря
  manifest.json            что и как выгружалось
  compile_flags.txt, src/compile_flags.txt, .vscode/settings.json, *.code-workspace
  README.md                как это открыть

Запуск:
  split_decompiled.py --code decompiled.c --functions functions.json --out decompiled
"""

import argparse
import csv
import json
import os
import re
import sys
import time

TYPES_HEADER = """#pragma once
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

COMPILE_FLAGS = ["-x", "c", "-std=gnu11", "-Wno-everything", "-ferror-limit=0"]
VSCODE = """{
  "files.associations": { "*.c": "c", "*.h": "c" },
  "C_Cpp.default.cStandard": "gnu11",
  "editor.tabSize": 4,
  "editor.wordWrap": "off",
  "editor.minimap.enabled": true,
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


def safe_name(name):
    nm = re.sub(r"[^A-Za-z0-9_]", "_", str(name)).strip("_")
    return (nm or "sub")[:80]


def is_signature(line):
    s = line.rstrip("\n").rstrip()
    if not s or s[0] in " \t}*/#":
        return False
    if "(" not in s:
        return False
    head = s.split("(", 1)[0]
    if "=" in head or ";" in head:
        return False
    if s.endswith("{"):
        body = s[:-1].rstrip()
    elif s.endswith(")"):
        body = s
    else:
        return False
    return ")" in body


def strip_literals(line):
    out = []
    i = 0
    n = len(line)
    in_str = False
    in_chr = False
    while i < n:
        c = line[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if in_chr:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_chr = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == "'":
            in_chr = True
            i += 1
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def brace_delta(line):
    clean = strip_literals(line)
    return clean.count("{") - clean.count("}")


def is_sig_start(s):
    if not s or s[0] in " \t}*/#":
        return False
    if "(" not in s:
        return False
    head = s.split("(", 1)[0]
    if "=" in head or ";" in head:
        return False
    return True


def sig_name(sig):
    head = sig.split("(", 1)[0].strip()
    if not head:
        return "unknown"
    tok = head.split()[-1].strip("*&")
    return tok or "unknown"


def load_functions(path):
    if not path or not os.path.exists(path):
        return {}, []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print("не прочитал %s: %s" % (path, e), file=sys.stderr)
        return {}, []
    if not isinstance(data, list):
        return {}, []
    by_name = {}
    for fn in data:
        if isinstance(fn, dict) and fn.get("name"):
            by_name.setdefault(fn["name"], fn)
    return by_name, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="decompiled.c")
    ap.add_argument("--functions", default="functions.json")
    ap.add_argument("--engine-file", default="engine.txt")
    ap.add_argument("--out", default="decompiled")
    ap.add_argument("--version", default="unknown")
    ap.add_argument("--keep-imports", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.code):
        print("нет файла %s" % args.code, file=sys.stderr)
        return 1

    out = args.out
    src = os.path.join(out, "src")
    inc = os.path.join(out, "include")
    for d in (out, src, inc, os.path.join(out, ".vscode")):
        os.makedirs(d, exist_ok=True)

    meta_by_name, meta_list = load_functions(args.functions)
    engine = {}
    if os.path.exists(args.engine_file):
        for line in open(args.engine_file, encoding="utf-8"):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                engine[k] = v

    written = 0
    skipped_imports = 0
    unknown_addr = 0
    rows = []
    protos = []
    proto_seen = set()

    all_path = os.path.join(out, "all.c")
    all_fh = open(all_path, "w", encoding="utf-8", newline="\n")
    all_fh.write("/* all.c — все функции подряд, сгенерировано из %s (движок %s) */\n"
                 % (os.path.basename(args.code), engine.get("engine", "?")))
    all_fh.write('#include "ghidra_types.h"\n#include "prototypes.h"\n\n')

    cur_sig = None
    cur_name = None
    cur_lines = []
    cur_preamble = []
    pending = []
    depth = 0
    cur_opened = False
    insig = None
    orphans = []

    def flush():
        nonlocal written, unknown_addr, skipped_imports, cur_sig, cur_name, cur_lines, cur_preamble, cur_opened
        if cur_sig is None:
            return
        name = cur_name
        if not args.keep_imports and (name.startswith("sym.imp.") or name.startswith("imp.")):
            skipped_imports += 1
            cur_sig = None
            cur_name = None
            cur_lines = []
            cur_preamble = []
            cur_opened = False
            return
        meta = meta_by_name.get(name, {})
        addr = meta.get("addr")
        size = meta.get("size", 0)
        nbbs = meta.get("nbbs", 0)
        xrefs = meta.get("indegree", 0)
        nargs = meta.get("nargs", 0)
        flags = []
        if meta.get("noreturn"):
            flags.append("noreturn")
        if meta.get("recursive"):
            flags.append("recursive")
        if addr is None:
            unknown_addr += 1
            fname = "zz_unknown_%03d_%s.c" % (unknown_addr, safe_name(name))
            addr_txt = "?"
        else:
            fname = "0x%08x_%s.c" % (addr, safe_name(name))
            addr_txt = "0x%x" % addr
        head = "/* %s  %s\n * size %s  blocks %s  xrefs %s  args %s%s\n */\n" % (
            addr_txt, name, size, nbbs, xrefs, nargs,
            "  flags: " + ",".join(flags) if flags else "")
        preamble = list(cur_preamble)
        while preamble and not preamble[0].strip():
            preamble.pop(0)
        body = "".join(cur_lines)
        if not body.endswith("\n"):
            body += "\n"
        with open(os.path.join(src, fname), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(head)
            fh.write('#include "ghidra_types.h"\n#include "prototypes.h"\n\n')
            fh.write("".join(preamble))
            fh.write(body)
        all_fh.write("/* ---- %s  %s ---- */\n" % (addr_txt, name))
        all_fh.write("".join(preamble))
        all_fh.write(body)
        all_fh.write("\n")
        protos.append(cur_sig + ";")
        rows.append((addr if addr is not None else 0, addr_txt, name, size, nbbs, xrefs,
                     nargs, " ".join(flags), fname))
        written += 1
        cur_sig = None
        cur_name = None
        cur_lines = []
        cur_preamble = []
        cur_opened = False

    def write_orphan(lines):
        n = len(orphans) + 1
        orphans.append(n)
        with open(os.path.join(src, "zz_unparsed_%03d.c" % n), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("/* нераспознанный фрагмент вывода, строк: %d */\n" % len(lines))
            fh.write("".join(lines))

    with open(args.code, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.rstrip("\n")
            cand = stripped.rstrip()

            if insig is not None:
                last = cand.rstrip()
                if not last.strip() or len(insig) >= 8 or last.startswith("}") or last.startswith("//"):
                    for extra in insig:
                        pending.append(extra + "\n")
                    insig = None
                    if len(pending) > 60:
                        write_orphan(pending)
                        pending = []
                    continue
                insig.append(last.strip())
                if last.endswith(")") or last.endswith("{"):
                    joined = " ".join(insig)
                    cur_sig = joined.rstrip("{").rstrip()
                    cur_name = sig_name(cur_sig)
                    cur_preamble = pending
                    pending = []
                    cur_lines = [x + "\n" for x in insig]
                    depth += brace_delta(joined)
                    cur_opened = joined.endswith("{")
                    insig = None
                    if cur_opened and depth <= 0:
                        depth = 0
                        flush()
                continue

            if cur_sig is None:
                if depth == 0 and is_sig_start(cand):
                    if cand.endswith(")") or cand.endswith("{"):
                        cur_sig = cand.rstrip("{").rstrip()
                        cur_name = sig_name(cur_sig)
                        cur_preamble = pending
                        pending = []
                        cur_lines = [line]
                        depth += brace_delta(cand)
                        cur_opened = cand.endswith("{")
                        if cur_opened and depth <= 0:
                            depth = 0
                            flush()
                        continue
                    insig = [cand]
                    continue
                pending.append(line)
                if len(pending) > 60:
                    write_orphan(pending)
                    pending = []
                continue

            cur_lines.append(line)
            clean = strip_literals(stripped)
            depth += clean.count("{") - clean.count("}")
            if "{" in clean:
                cur_opened = True
            if cur_opened and depth <= 0:
                depth = 0
                flush()

    flush()
    all_fh.close()

    with open(os.path.join(inc, "ghidra_types.h"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(TYPES_HEADER)
    with open(os.path.join(inc, "prototypes.h"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("#pragma once\n#include \"ghidra_types.h\"\n\n")
        for p in protos:
            name = sig_name(p)
            if name in proto_seen:
                continue
            proto_seen.add(name)
            fh.write(p + "\n")

    with open(os.path.join(out, "compile_flags.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(COMPILE_FLAGS + ["-Iinclude"]) + "\n")
    with open(os.path.join(src, "compile_flags.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(COMPILE_FLAGS + ["-I../include"]) + "\n")
    with open(os.path.join(out, ".vscode", "settings.json"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(VSCODE)
    with open(os.path.join(out, "decompiled.code-workspace"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(WORKSPACE)

    rows.sort(key=lambda r: (r[0], r[2]))
    with open(os.path.join(out, "index.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# Функции\n\n")
        fh.write("| адрес | имя | размер | блоков | xrefs | args | флаги | файл |\n")
        fh.write("|---|---|---|---|---|---|---|---|\n")
        for _a, addr_txt, name, size, nbbs, xrefs, nargs, flags, fname in rows:
            if fname:
                fh.write("| `%s` | `%s` | %s | %s | %s | %s | %s | [%s](src/%s) |\n"
                         % (addr_txt, name, size, nbbs, xrefs, nargs, flags, fname, fname))
            else:
                fh.write("| `%s` | `%s` | %s | %s | %s | %s | %s | — |\n"
                         % (addr_txt, name, size, nbbs, xrefs, nargs, flags))

    dumped = set(r[2] for r in rows)
    with open(os.path.join(out, "functions.csv"), "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh)
        w.writerow(["address", "name", "size", "blocks", "xrefs", "args", "dumped"])
        for fn in meta_list:
            if not isinstance(fn, dict) or not fn.get("name"):
                continue
            w.writerow(["0x%x" % fn.get("addr", 0), fn.get("name"), fn.get("size", 0),
                        fn.get("nbbs", 0), fn.get("indegree", 0), fn.get("nargs", 0),
                        "yes" if fn.get("name") in dumped else "no"])

    manifest = {
        "version": args.version,
        "engine": engine.get("engine", "unknown"),
        "r2_version": engine.get("r2_version", "unknown"),
        "ghidra_plugin": engine.get("ghidra_plugin", "unknown"),
        "functions_in_binary": len(meta_list),
        "functions_dumped": written,
        "functions_skipped_imports": skipped_imports,
        "functions_without_address": unknown_addr,
        "unparsed_chunks": len(orphans),
        "code_bytes": os.path.getsize(args.code),
        "analyze_seconds": engine.get("analyze_elapsed_seconds", "0"),
        "decompile_seconds": engine.get("elapsed_seconds", "0"),
        "renames_applied": engine.get("renames_applied", "0"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    with open(os.path.join(out, "README.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("""# Декомпилированный бинарь (версия {ver})

Движок: {engine}, r2 {r2}, плагин r2ghidra: {plug}.

## Как открыть

| IDE | что открыть |
|---|---|
| VS Code / Cursor / VSCodium | файл `decompiled.code-workspace` |
| CLion / IDEA | папку, в которой лежит этот README |
| чем угодно | `all.c` — все функции подряд |

## Что где

| файл | что это |
|---|---|
| `src/0x<адрес>_<имя>.c` | по функции на файл, в шапке адрес, размер, блоки, xrefs |
| `all.c` | те же функции подряд по адресам |
| `index.md` | таблица: адрес, имя, размер, блоки, xrefs, ссылка на файл |
| `functions.csv` | все функции бинаря, включая невыгруженные |
| `include/ghidra_types.h` | базовые типы (чтобы IDE не красила код) |
| `include/prototypes.h` | прототипы выгруженных функций (работает Ctrl+клик по вызову) |
| `manifest.json` | что и как выгружалось, сколько времени заняло |

## Что помнить

- Имена переменных и часть типов восстановлены декомпилятором: `arg1`, `iVar2`, `*(int *)(arg1 + 0xc)` — это ожидаемо.
- Строки не переносятся по 120 символов, включены явные касты как в IDA (`r2ghidra.casts`).
- Импортные заглушки (`sym.imp.*`) в дамп не попали — это не код игры.
""".format(ver=args.version, engine=manifest["engine"], r2=manifest["r2_version"],
           plug=manifest["ghidra_plugin"]))

    print("функций выгружено: %d, без адреса: %d, импортов пропущено: %d"
          % (written, unknown_addr, skipped_imports))
    print("дерево: %s (src/*.c, all.c, index.md, include/*.h)" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
