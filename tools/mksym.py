#!/usr/bin/env python3
import argparse
import csv
import json
import os


def load(path):
    if not path or not os.path.exists(path):
        return {}
    d = json.load(open(path))
    items = d if isinstance(d, list) else d.get('named', [])
    out = {}
    for e in items:
        if not isinstance(e, dict):
            continue
        rva = e.get('rva', e.get('address'))
        try:
            rva = int(rva, 16) if isinstance(rva, str) else int(rva)
        except (TypeError, ValueError):
            continue
        name = e.get('name')
        if name:
            out[rva] = name
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv')
    ap.add_argument('--table')
    ap.add_argument('--merge')
    ap.add_argument('--ver', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    sym = {}
    if a.merge:
        sym.update(load(a.merge))
    if a.table:
        sym.update(load(a.table))
    rows = 0
    if a.csv and os.path.exists(a.csv):
        for r in csv.DictReader(open(a.csv)):
            if r.get('status') not in ('matched', 'weak', 'resolved'):
                continue
            name = r.get('name') or ''
            if not name or name.startswith('sub_') or not r.get('new_rva'):
                continue
            sym[int(r['new_rva'], 16)] = name
            rows += 1

    prev = 0
    if a.merge and os.path.exists(a.merge):
        prev = len(load(a.merge))
    if len(sym) < prev:
        print('symbols %d < existing %d, keeping existing' % (len(sym), prev))
        return 0

    os.makedirs(os.path.dirname(a.out) or '.', exist_ok=True)
    json.dump([{'rva': hex(k), 'name': sym[k]} for k in sorted(sym)], open(a.out, 'w'))
    print('symbols %s: %d names (csv rows %d) -> %s' % (a.ver, len(sym), rows, a.out))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
