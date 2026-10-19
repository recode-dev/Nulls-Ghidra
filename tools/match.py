#!/usr/bin/env python3

import argparse
import collections
import json
import math
import os


def parse_args():
    p = argparse.ArgumentParser(description='Match functions across builds by call profile, fields, constants and shape')
    p.add_argument('--source', required=True, help='source index directory')
    p.add_argument('--target', required=True, help='target index directory')
    p.add_argument('--offsets', required=True, help='comma separated 0x offsets from the source index')
    p.add_argument('--top', type=int, default=5, help='rows printed per offset')
    p.add_argument('--band', type=float, default=3.0, help='max size ratio between source and candidate')
    p.add_argument('--min-score', type=float, default=0.0, help='drop rows below this score')
    return p.parse_args()


def load(path, name):
    with open(os.path.join(path, name), 'r', encoding='utf-8') as f:
        return json.load(f)


def bucket(value):
    return int(math.log2(max(1, value)))


def hist(values):
    return collections.Counter(bucket(v) for v in values)


def hist_sim(a, b):
    if not a or not b:
        return 0.0
    common = sum((a & b).values())
    return common / max(sum(a.values()), sum(b.values()))


def jac(a, b):
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def ratio(a, b):
    if not a or not b:
        return 0.0
    return min(a, b) / max(a, b)


def prepare(index):
    rows = load(index, 'functions.json')
    sizes = {key: value.get('size_chars') or 0 for key, value in rows.items()}
    profiles = {}
    for key, entry in rows.items():
        callees = [sizes.get(call, 0) for call in entry.get('calls') or [] if sizes.get(call, 0)]
        callers = [sizes.get(call, 0) for call in entry.get('callers') or [] if sizes.get(call, 0)]
        profiles[key] = {
            'offset': entry.get('offset'),
            'name': entry.get('name'),
            'size': sizes[key],
            'callees': hist(callees),
            'callers': hist(callers),
            'degree': len(entry.get('calls') or []),
            'indegree': len(entry.get('callers') or []),
            'fields': set(entry.get('field_offsets') or []),
            'consts': set(entry.get('consts') or []),
            'vcalls': set(entry.get('vcall_slots') or []),
            'branches': entry.get('branches') or 0,
            'loops': entry.get('loops') or 0,
            'callee_names': set(entry.get('callee_names') or []),
        }
    return profiles


def weighted(src, dst, weights):
    if not src and not dst:
        return 0.0
    shared = sum(weights.get(v, 0.0) for v in src & dst)
    total = sum(weights.get(v, 0.0) for v in src | dst)
    return shared / total if total else 0.0


def score(src, dst, weights, df):
    parts = {
        'callees': hist_sim(src['callees'], dst['callees']),
        'callers': hist_sim(src['callers'], dst['callers']),
        'fields': jac(src['fields'], dst['fields']),
        'consts': weighted(src['consts'], dst['consts'], weights),
        'vcalls': jac(src['vcalls'], dst['vcalls']),
        'names': jac(src['callee_names'], dst['callee_names']),
        'size': ratio(src['size'], dst['size']),
        'degree': ratio(src['degree'], dst['degree']),
        'branches': ratio(src['branches'], dst['branches']),
    }
    parts['rare'] = sum(1 for value in src['consts'] & dst['consts'] if df.get(value, 999) <= 10)
    if not parts['rare']:
        parts['consts'] = 0.0
    total = (0.45 * parts['consts'] + 0.20 * parts['callees'] + 0.15 * parts['fields']
             + 0.10 * parts['size'] + 0.10 * parts['degree'])
    return total, parts


def main():
    args = parse_args()
    source = prepare(args.source)
    target = prepare(args.target)
    candidates = [item for item in target.values() if item['size'] > 0]
    df = collections.Counter()
    for item in candidates:
        df.update(item['consts'])
    total = max(1, len(candidates))
    cutoff = max(4.0, total * 0.01)
    weights = {value: (math.log(1.0 + total / count) if count <= cutoff else 0.0)
               for value, count in df.items()}

    for token in [t.strip() for t in args.offsets.split(',') if t.strip()]:
        value = int(token, 16)
        key = f'0x{value:x}'
        src = source.get(key)
        if src is None:
            print(f'{key} missing in source')
            continue
        rows = []
        for dst in candidates:
            if not (1 / args.band <= (dst['size'] + 1) / (src['size'] + 1) <= args.band):
                continue
            total, parts = score(src, dst, weights, df)
            rows.append((total, parts, dst))
        rows.sort(key=lambda row: -row[0])
        best = rows[0][0] if rows else 0.0
        second = rows[1][0] if len(rows) > 1 else 0.0
        top_parts = rows[0][1] if rows else {}
        strong = top_parts.get('rare', 0) >= 2 and top_parts.get('consts', 0) >= 0.35
        verdict = 'strong' if strong or (best >= 0.62 and best - second >= 0.08) else 'weak' if best >= 0.5 else 'none'
        print(f'\n{key} {src["name"]} size={src["size"]} deg={src["degree"]}/{src["indegree"]} -> {verdict}')
        shown = 0
        for total, parts, dst in rows:
            if total < args.min_score or shown >= args.top:
                break
            shown += 1
            print(f'  {total:.3f} {dst["offset"]:#x} {dst["name"][:44]:44s} '
                  f'cal {parts["callees"]:.2f} fld {parts["fields"]:.2f} '
                  f'cst {parts["consts"]:.2f} rare {parts["rare"]} sz {parts["size"]:.2f}')


if __name__ == '__main__':
    main()
