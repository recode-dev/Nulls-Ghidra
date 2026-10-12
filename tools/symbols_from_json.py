#!/usr/bin/env python3
"""Превращает symbols/**/*.json в команды для radare2 (печатает в stdout).

Живые форматы:
    {"Имя": "0x1a2b3c"}
    [{"name": "Имя", "address": "0x1a2b3c"}]
    {"Класс": {"метод": "0x1a2b3c"}}

Ключи адреса: address, addr, offset, rva, va, value, start.
Ключи имени: name, symbol, func, function, label, method.
Адрес может быть RVA от базы образа или абсолютным.

Запуск: symbols_from_json.py <каталог|файл> <бинарь>
"""

import json
import os
import re
import subprocess
import sys

AKEYS = ("address", "addr", "offset", "rva", "va", "value", "start")
NKEYS = ("name", "symbol", "func", "function", "label", "method")


def image_base(binary):
    try:
        out = subprocess.run(["r2", "-q", "-e", "scr.color=0", "-c", "?v $B", binary],
                             capture_output=True, text=True, timeout=120).stdout
        lines = [l for l in out.strip().splitlines() if l.strip()]
        return int(lines[-1], 16) if lines else 0
    except Exception:
        return 0


def json_files(root):
    if os.path.isfile(root):
        return [root]
    found = []
    for dirpath, _dirs, names in os.walk(root):
        for n in sorted(names):
            if n.endswith(".json"):
                found.append(os.path.join(dirpath, n))
    return sorted(found)


def safe(name):
    nm = re.sub(r"[^A-Za-z0-9_]", "_", str(name).split("(")[0]).strip("_")
    return (nm or "sub")[:120]


def pick(d, keys):
    for k in keys:
        if k in d:
            return d[k]
    return None


def number(val):
    if isinstance(val, bool) or val is None:
        return None
    try:
        if isinstance(val, str):
            s = val.strip().replace("_", "")
            if s.lower().startswith("0x"):
                return int(s, 16)
            return int(s, 10)
        return int(val)
    except (TypeError, ValueError):
        return None


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    root, binary = sys.argv[1], sys.argv[2]
    base = image_base(binary)
    out = []
    seen_files = []

    def add(name, val):
        v = number(val)
        if v is None or name is None:
            return
        addr = v if v >= base else base + v
        nm = safe(name)
        out.append("f %s @ 0x%x" % (nm, addr))
        out.append("afn %s @ 0x%x" % (nm, addr))

    for path in json_files(root):
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            print("# пропустил %s: %s" % (path, e), file=sys.stderr)
            continue
        seen_files.append(path)
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict):
                    a = pick(v, AKEYS)
                    n = pick(v, NKEYS)
                    if a is not None:
                        add(n if n else k, a)
                        continue
                    for k2, v2 in v.items():
                        add("%s_%s" % (k, k2), v2)
                else:
                    add(k, v)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    a = pick(item, AKEYS)
                    n = pick(item, NKEYS)
                    if a is not None and n is not None:
                        add(n, a)
        print("# %s: ок" % path, file=sys.stderr)

    print("\n".join(out))
    print("файлов: %d, имён: %d" % (len(seen_files), len(out) // 2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
