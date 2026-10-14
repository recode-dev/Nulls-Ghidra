#!/usr/bin/env python3
import argparse
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import offsig


def table_of(path):
    d = json.load(open(path))
    names = {e['rva']: e['name'] for e in d.get('named', [])}
    return {r: (names.get(r) or 'sub_%08x' % r) for r in d['starts']}


def open_out(path):
    return gzip.open(path, 'wt') if path.endswith('.gz') else open(path, 'w')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--table', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--k', type=int, default=offsig.K)
    ap.add_argument('--ext', type=int, default=offsig.EXT)
    ap.add_argument('--version', default='')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--keep-templates', action='store_true')
    a = ap.parse_args()

    img = offsig.Img(a.bin)
    code = offsig.Code(img, offsig.mdcs())
    table = table_of(a.table)
    if not a.all:
        table = {r: n for r, n in table.items() if not n.startswith('sub_')}
    span_len = max(a.k, a.ext)
    entries = []
    seen = set()
    short = 0
    skipped = 0
    for rva, name in sorted(table.items()):
        w, _, base = code.window(rva, span_len, span_len)
        if w is None:
            w, _, base = code.window(rva, a.k, a.k)
            if w is None:
                skipped += 1
                continue
            short += 1
        eid = name if name not in seen else '%s@%x' % (name, rva)
        seen.add(name)
        entries.append({'id': eid, 'name': name, 'rva': hex(rva), 'head': base - rva,
                        'span': list(w)})
        if a.limit and len(entries) >= a.limit:
            break

    seen_hash = {}
    for e in entries:
        h = offsig.win_hash(e['span'][:a.k])
        seen_hash[h] = seen_hash.get(h, 0) + 1
    tmpl = 0
    if not a.keep_templates:
        keep = []
        for e in entries:
            h = offsig.win_hash(e['span'][:a.k])
            if seen_hash[h] > 1:
                tmpl += 1
                e['tmpl'] = True
                continue
            keep.append(e)
        entries = keep

    inv = {}
    for t, i in code.intern.items():
        inv.setdefault(i, t)
    remap = {}
    used = []
    for e in entries:
        span = []
        for i in e['span']:
            j = remap.get(i)
            if j is None:
                j = len(used)
                remap[i] = j
                used.append(inv.get(i, ''))
            span.append(j)
        e['span'] = span

    out = {'version': a.version, 'bin': os.path.basename(a.bin), 'k': a.k, 'ext': a.ext,
           'source_size': len(img.data), 'count': len(entries), 'intern': used,
           'entries': entries}
    with open_out(a.out) as f:
        json.dump(out, f)
    print('patterns %d (short %d skipped %d) intern %d table %d -> %s'
          % (len(entries), short, skipped, len(used), len(table), a.out))


if __name__ == '__main__':
    main()
