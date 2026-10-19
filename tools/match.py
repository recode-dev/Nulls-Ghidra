#!/usr/bin/env python3

import argparse
import json
import os


def parse_args():
    p = argparse.ArgumentParser(description='Match functions between two index directories by structure and resolved calls')
    p.add_argument('--source', required=True, help='source index directory')
    p.add_argument('--target', required=True, help='target index directory')
    p.add_argument('--offsets', required=True, help='comma separated 0x offsets from the source index')
    p.add_argument('--top', type=int, default=5, help='rows printed per offset')
    p.add_argument('--min-score', type=float, default=0.0, help='drop rows below this score')
    return p.parse_args()


def load(path, name):
    with open(os.path.join(path, name), 'r', encoding='utf-8') as f:
        return json.load(f)


def feats(entry):
    return {
        'offset': entry.get('offset'),
        'name': entry.get('name'),
        'size': entry.get('size_chars') or 0,
        'fields': set(entry.get('field_offsets') or []),
        'consts': set(entry.get('consts') or []),
        'vcalls': set(entry.get('vcall_slots') or []),
        'callees': set(entry.get('callee_names') or []),
        'calls': len(entry.get('calls') or []),
        'branches': entry.get('branches') or 0,
        'loops': entry.get('loops') or 0,
    }


def jac(a, b):
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def ratio(a, b):
    if not a or not b:
        return 0.0
    return min(a, b) / max(a, b)


def score(src, dst):
    parts = {
        'callees': jac(src['callees'], dst['callees']),
        'fields': jac(src['fields'], dst['fields']),
        'consts': jac(src['consts'], dst['consts']),
        'vcalls': jac(src['vcalls'], dst['vcalls']),
        'size': ratio(src['size'], dst['size']),
        'calls': ratio(src['calls'], dst['calls']),
        'branches': ratio(src['branches'], dst['branches']),
    }
    total = (0.30 * parts['callees'] + 0.20 * parts['fields'] + 0.15 * parts['consts']
             + 0.10 * parts['vcalls'] + 0.15 * parts['size'] + 0.10 * parts['calls']
             + 0.05 * parts['branches'])
    return total, parts


def main():
    args = parse_args()
    source = load(args.source, 'functions.json')
    target_rows = [feats(v) for v in load(args.target, 'functions.json').values() if v.get('size_chars')]

    for token in [t.strip() for t in args.offsets.split(',') if t.strip()]:
        value = int(token, 16)
        key = f'0x{value:x}'
        entry = source.get(key)
        if entry is None:
            print(f'{key} missing in source')
            continue
        src = feats(entry)
        rows = []
        for dst in target_rows:
            total, parts = score(src, dst)
            rows.append((total, parts, dst))
        rows.sort(key=lambda row: -row[0])
        best = rows[0][0] if rows else 0.0
        second = rows[1][0] if len(rows) > 1 else 0.0
        verdict = 'strong' if best >= 0.55 and best - second >= 0.10 else 'weak' if best >= 0.45 else 'none'
        print(f'\n{key} {src["name"]} size={src["size"]} calls={src["calls"]} callees={len(src["callees"])} -> {verdict}')
        shown = 0
        for total, parts, dst in rows:
            if total < args.min_score or shown >= args.top:
                break
            shown += 1
            print(f'  {total:.3f} {dst["offset"]:#x} {dst["name"][:48]:48s} '
                  f'cal {parts["callees"]:.2f} fld {parts["fields"]:.2f} cst {parts["consts"]:.2f} '
                  f'sz {parts["size"]:.2f} calls {parts["calls"]:.2f}')


if __name__ == '__main__':
    main()
