#!/usr/bin/env python3

import argparse, json, os, sys

def load(p, n):
    return json.load(open(os.path.join(p, n), encoding='utf-8'))

def prep(rows):
    out = {}
    for k, e in rows.items():
        out[k] = {
            'name': e.get('name'), 'size': e.get('size_chars') or 0,
            'bytes': e.get('size_bytes') or 0, 'fields': set(e.get('field_offsets') or []),
            'consts': set(e.get('consts') or []), 'calls': e.get('calls') or [],
            'callers': e.get('callers') or [],
        }
    return out

def jac(a, b):
    return len(a & b) / len(a | b) if a or b else 0.0

def ratio(a, b):
    return min(a, b) / max(a, b) if a and b else 0.0

def deltas(fields):
    f = sorted(fields)
    return {b - a for a, b in zip(f, f[1:])}

def score(s, c):
    ds, dc = deltas(s['fields']), deltas(c['fields'])
    base = (0.32 * jac(ds, dc) + 0.18 * jac(s['fields'], c['fields'])
            + 0.18 * ratio(s['size'], c['size']) + 0.12 * ratio(s['bytes'], c['bytes'])
            + 0.12 * ratio(len(s['calls']), len(c['calls'])) + 0.08 * jac(s['consts'], c['consts']))
    if s['bytes'] == c['bytes']:
        base += 0.25
    return base

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True)
    p.add_argument('--target', required=True)
    p.add_argument('--offset', required=True)
    p.add_argument('--pairs', default='', help='json 36-offset -> 69-offset')
    p.add_argument('--top', type=int, default=5)
    a = p.parse_args()
    src = prep(load(a.source, 'functions.json'))
    dst = prep(load(a.target, 'functions.json'))
    pairs = json.load(open(a.pairs)) if a.pairs and os.path.exists(a.pairs) else {}
    s = src.get(a.offset)
    if not s:
        print('source offset missing'); return
    pool = {}
    for c in s['callers']:
        m = pairs.get(c)
        if not m:
            continue
        for callee in (dst.get(m) or {}).get('calls', []):
            if callee in dst:
                pool[callee] = pool.get(callee, 0) + 3
    for m in pairs.values():
        for callee in (dst.get(m) or {}).get('calls', []):
            if callee in dst:
                pool[callee] = pool.get(callee, 0) + 1
    if not pool:
        pool = {k: 1 for k in dst}
    rows = sorted(((score(s, dst[k]) + 0.05 * w, k) for k, w in pool.items()), reverse=True)
    print(f"{a.offset} {s['name']} bytes={s['bytes']} chars={s['size']} fields={sorted(s['fields'])[:6]} candidates={len(pool)}")
    for total, k in rows[:a.top]:
        e = dst[k]
        print(f"  {total:.3f} {k} bytes={e['bytes']} chars={e['size']} calls={len(e['calls'])} fields={sorted(e['fields'])[:6]}")

if __name__ == '__main__':
    main()
