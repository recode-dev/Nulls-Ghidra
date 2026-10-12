#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys

AK = ("address", "addr", "offset", "rva", "va", "value", "start")
NK = ("name", "symbol", "func", "function", "label", "method")


def base(binary):
    if not binary:
        return 0
    try:
        out = subprocess.run(["r2", "-q", "-c", "?v $B", binary],
                             capture_output=True, text=True, timeout=120).stdout
        rows = [r for r in out.strip().splitlines() if r.strip()]
        return int(rows[-1], 16) if rows else 0
    except Exception:
        return 0


def num(v):
    if isinstance(v, bool) or v is None:
        return None
    try:
        if isinstance(v, str):
            s = v.strip().replace("_", "")
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        return int(v)
    except (TypeError, ValueError):
        return None


def files(root):
    if not os.path.isdir(root):
        return []
    out = []
    for d, _, ns in os.walk(root):
        for n in sorted(ns):
            if n.endswith(".json"):
                out.append(os.path.join(d, n))
    return sorted(out)


def pick(d, ks):
    for k in ks:
        if k in d:
            return d[k]
    return None


def short(x):
    s = re.sub(r"[^A-Za-z0-9_]", "_", str(x).split("(")[0]).strip("_")
    return (s or "sub")[:120]


def walk(data, b, out):
    def add(n, v):
        a = num(v)
        if a is None or n is None:
            return
        a = a if a >= b else b + a
        nm = short(n)
        out.append("f %s @ 0x%x" % (nm, a))
        out.append("afn %s @ 0x%x" % (nm, a))

    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                a = pick(v, AK)
                n = pick(v, NK)
                if a is not None:
                    add(n if n else k, a)
                else:
                    for k2, v2 in v.items():
                        add("%s_%s" % (k, k2), v2)
            else:
                add(k, v)
    elif isinstance(data, list):
        for it in data:
            if isinstance(it, dict):
                a = pick(it, AK)
                n = pick(it, NK)
                if a is not None and n is not None:
                    add(n, a)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "symbols"
    binary = sys.argv[2] if len(sys.argv) > 2 else ""
    fs = files(root)
    if not fs:
        return 0
    b = base(binary)
    out = []
    for f in fs:
        try:
            data = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        walk(data, b, out)
    if out:
        print("\n".join(out))
    print("%d files %d names" % (len(fs), len(out) // 2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
