#!/usr/bin/env python3
import argparse
import collections
import json
import math
import os


def parse_args():
    p = argparse.ArgumentParser(description='Find functions by structure, location or similarity')
    p.add_argument('--index_dir', default='index_data')
    p.add_argument('--near', default='', help='anchor function, e.g. 0xac3cfc; lists its layout neighbours')
    p.add_argument('--window', type=lambda v: int(v, 0), default=0x2000, help='neighbour window in bytes')
    p.add_argument('--like', default='', help='reference function; ranks by weighted similarity')
    p.add_argument('--min-size', type=lambda v: int(v, 0), default=0)
    p.add_argument('--max-size', type=lambda v: int(v, 0), default=0)
    p.add_argument('--min-loops', type=int, default=0)
    p.add_argument('--min-branches', type=int, default=0)
    p.add_argument('--min-depth', type=int, default=0)
    p.add_argument('--max-callers', type=int, default=-1)
    p.add_argument('--field', action='append', default=[], help='offset the function must touch, e.g. 0x28')
    p.add_argument('--writes', action='append', default=[], help='offset the function must write, e.g. 0x1c')
    p.add_argument('--section', default='')
    p.add_argument('--sort', default='', choices=('size', 'lines', 'loops', 'branches', 'depth', 'calls', 'callers', 'score'))
    p.add_argument('--limit', type=int, default=20)
    p.add_argument('--json', action='store_true', help='print JSON instead of a table')
    return p.parse_args()


def to_int(value):
    return int(value, 16) if value.lower().startswith('0x') else int(value)


def load_functions(index_dir):
    path = os.path.join(index_dir, 'functions.json')
    if not os.path.exists(path):
        raise SystemExit(f'[-] {path} not found')
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def similarity(reference, functions, fields_idf):
    def vector(entry):
        weights = collections.Counter(entry['field_offsets'])
        return {offset: (1 + math.log(count)) * fields_idf.get(offset, 1.0)
                for offset, count in weights.items()}

    def cosine(left, right):
        if not left or not right:
            return 0.0
        dot = sum(weight * right.get(offset, 0.0) for offset, weight in left.items())
        norm_left = math.sqrt(sum(weight * weight for weight in left.values()))
        norm_right = math.sqrt(sum(weight * weight for weight in right.values()))
        return dot / (norm_left * norm_right) if norm_left and norm_right else 0.0

    base = vector(reference)
    base_calls = set(reference['calls'])
    base_size = reference['size_bytes'] or 1
    rows = []
    for key, entry in functions.items():
        if entry is reference or not entry['size_bytes']:
            continue
        ratio = entry['size_bytes'] / base_size
        if ratio < 0.25 or ratio > 4:
            continue
        call_overlap = len(base_calls & set(entry['calls'])) / max(1, len(base_calls | set(entry['calls'])))
        same_shape = 1.0 / (1.0 + abs(math.log(ratio)))
        loop_similarity = 1.0 / (1.0 + abs(math.log((entry['loops'] + 1) / (reference['loops'] + 1))))
        score = (3.0 * cosine(base, vector(entry)) + 1.5 * call_overlap
                 + 0.5 * same_shape + 0.5 * loop_similarity)
        rows.append((score, key, entry))
    rows.sort(key=lambda row: -row[0])
    return rows


def fields_idf(functions):
    total = len(functions)
    frequency = collections.Counter()
    for entry in functions.values():
        for offset in set(entry['field_offsets']):
            frequency[offset] += 1
    return {offset: math.log(total / count) for offset, count in frequency.items()}


def score_of(entry):
    size = entry['size_bytes'] or 1
    value = math.log2(max(size, 2)) * max(entry['branches'], 1) * math.sqrt(max(entry['loops'], 1))
    if len(entry['callers']) <= 1:
        value *= 1.5
    if not entry['strings']:
        value *= 1.2
    return value


def main():
    args = parse_args()
    functions = load_functions(args.index_dir)
    wanted_fields = {to_int(value) for value in args.field}
    wanted_writes = {to_int(value) for value in args.writes}
    anchor = to_int(args.near) if args.near else None
    reference = functions.get(f'0x{to_int(args.like):x}') if args.like else None

    if args.like and reference is None:
        raise SystemExit(f'[-] {args.like} not in index')

    if reference is not None:
        rows = [(score, key, entry) for score, key, entry in similarity(reference, functions, fields_idf(functions))]
    else:
        rows = []
        for key, entry in functions.items():
            if anchor is not None and abs(entry['offset'] - anchor) > args.window:
                continue
            if args.min_size and (entry['size_bytes'] or 0) < args.min_size:
                continue
            if args.max_size and (entry['size_bytes'] or 0) > args.max_size:
                continue
            if entry['loops'] < args.min_loops or entry['branches'] < args.min_branches:
                continue
            if entry['depth'] < args.min_depth:
                continue
            if args.max_callers >= 0 and len(entry['callers']) > args.max_callers:
                continue
            if wanted_fields and not wanted_fields <= set(entry['field_offsets']):
                continue
            if wanted_writes and not wanted_writes <= set(entry['field_writes']):
                continue
            if args.section and entry['section'] != args.section:
                continue
            rows.append((score_of(entry), key, entry))

    sorters = {
        'size': lambda row: row[2]['size_bytes'] or 0,
        'lines': lambda row: row[2]['lines'],
        'loops': lambda row: row[2]['loops'],
        'branches': lambda row: row[2]['branches'],
        'depth': lambda row: row[2]['depth'],
        'calls': lambda row: len(row[2]['calls']),
        'callers': lambda row: len(row[2]['callers']),
        'score': lambda row: row[0],
    }
    rows.sort(key=sorters[args.sort or ('score' if reference is not None else 'size')], reverse=True)
    rows = rows[:args.limit]

    if args.json:
        payload = [{
            'rva': key,
            'score': round(score, 3),
            'size': entry['size_bytes'],
            'lines': entry['lines'],
            'loops': entry['loops'],
            'branches': entry['branches'],
            'depth': entry['depth'],
            'args': entry['args'],
            'callers': len(entry['callers']),
            'calls': len(entry['calls']),
            'fields': len(entry['field_offsets']),
            'section': entry['section'],
            'signature': entry['signature'],
        } for score, key, entry in rows]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    header = f'{"rva":>10} {"score":>9} {"size":>7} {"lines":>6} {"loops":>5} {"br":>4} {"dep":>4} {"args":>4} {"in":>4} {"out":>4} {"fld":>4}'
    print(header)
    print('-' * len(header))
    for score, key, entry in rows:
        print(f'{key:>10} {score:>9.1f} {entry["size_bytes"] or 0:>7} {entry["lines"]:>6} '
              f'{entry["loops"]:>5} {entry["branches"]:>4} {entry["depth"]:>4} {entry["args"]:>4} '
              f'{len(entry["callers"]):>4} {len(entry["calls"]):>4} {len(entry["field_offsets"]):>4}')
    print(f'\n{len(rows)} shown')


if __name__ == '__main__':
    main()
