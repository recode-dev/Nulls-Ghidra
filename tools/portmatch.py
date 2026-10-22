#!/usr/bin/env python3

import argparse
import collections
import json
import math
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from binary import load_image
from elf import EM_AARCH64

MAX_BODY = 8192
EDGE_INDEX_BONUS = 0.05
EDGE_BINARY_BONUS = 0.08
EDGE_DOUBLE_BONUS = 0.04


def parse_args():
    p = argparse.ArgumentParser(description='Match one build onto another by constants, field deltas and shape')
    p.add_argument('--source', required=True, help='old index directory')
    p.add_argument('--target', required=True, help='new index directory')
    p.add_argument('-o', '--offset', default='', help='old rva, comma separated')
    p.add_argument('-n', '--name', default='', help='old function name to resolve')
    p.add_argument('--anchor', default='', help='old:new pair of already bound functions')
    p.add_argument('--target-bin', default='', help='image of the target build, used to read bl edges')
    p.add_argument('--batch', default='', help='file with one old rva or name per line')
    p.add_argument('--top', type=int, default=5)
    p.add_argument('--band', type=float, default=6.0, help='max char size ratio')
    p.add_argument('--min-score', type=float, default=0.0)
    p.add_argument('--ladder', action='store_true', help='walk callees from the anchor and bind them in turn')
    p.add_argument('--depth', type=int, default=2)
    p.add_argument('--accept', type=float, default=0.10, help='min gap to accept a ladder binding')
    p.add_argument('--pairs', default='', help='write accepted old:new pairs as json')
    p.add_argument('--json', action='store_true')
    return p.parse_args()


def load(path, name, default=None):
    full = os.path.join(path, name)
    if not os.path.exists(full):
        return default
    with open(full, 'r', encoding='utf-8') as f:
        return json.load(f)


def to_int(token):
    token = token.strip()
    return int(token, 16) if token.lower().startswith('0x') else int(token, 16)


def split_tokens(value):
    return [t for t in (value or '').replace(';', ',').split(',') if t.strip()]


def derive_base(rows):
    for entry in rows.values():
        address = entry.get('address')
        offset = entry.get('offset')
        if address and offset and address >= offset:
            return address - offset
    return 0


def ratio(a, b):
    if not a or not b:
        return 0.0
    return min(a, b) / max(a, b)


def jac(a, b):
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def weighted(a, b, weights):
    if not a and not b:
        return 0.0
    total = sum(weights.get(v, 0.0) for v in a | b)
    if not total:
        return 0.0
    return sum(weights.get(v, 0.0) for v in a & b) / total


def deltas(values):
    ordered = sorted(values)
    return {b - a for a, b in zip(ordered, ordered[1:])}


SPECIAL = {'C1': 'ctor', 'C2': 'ctor', 'C3': 'ctor', 'D0': 'dtor', 'D1': 'dtor', 'D2': 'dtor'}


def mangled_path(symbol):
    """`Class::method` out of an Itanium member mangling, with no external demangler."""
    if symbol.startswith('_ZNK'):
        index = 4
    elif symbol.startswith('_ZN'):
        index = 3
    else:
        return ''
    parts = []
    while index < len(symbol) and symbol[index].isdigit():
        end = index
        while end < len(symbol) and symbol[end].isdigit():
            end += 1
        size = int(symbol[index:end])
        part = symbol[end:end + size]
        if len(part) != size:
            return ''
        parts.append(part)
        index = end + size
    if not parts or index >= len(symbol):
        return ''
    code = symbol[index:index + 2]
    if symbol[index] in 'CD' and index + 1 < len(symbol) and symbol[index + 1].isdigit():
        if code not in SPECIAL:
            return ''
        parts.append(SPECIAL[code])
    elif len(parts) < 2:
        return ''
    return '::'.join(parts)


def qualified_names(index, out):
    """functions.json names are unqualified (the Ghidra label keeps only the last
    component), so `Class::method` queries miss.  Recover the full path from the
    mangled symbol table when the build still has one."""
    payload = load(index, 'symbols.json', None)
    if not payload:
        return 0
    rows = payload.get('symbols') if isinstance(payload, dict) else payload
    patched = 0
    for symbol, value in (rows or {}).items():
        if isinstance(value, dict):
            value = value.get('address')
        if isinstance(value, int):
            address = value
        elif isinstance(value, str):
            try:
                address = int(value, 16)
            except ValueError:
                continue
        else:
            continue
        label = mangled_path(symbol)
        key = f'0x{address:x}'
        entry = out.get(key)
        if entry and label and label not in entry['name']:
            entry['name'] = label
            patched += 1
    return patched


def prepare(index):
    rows = load(index, 'functions.json', None)
    if not rows:
        raise SystemExit(f'[-] {os.path.join(index, "functions.json")} not found')
    out = {}
    for key, entry in rows.items():
        out[key] = {
            'key': key,
            'offset': entry.get('offset') or int(key, 16),
            'name': entry.get('name') or '',
            'size': entry.get('size_chars') or 0,
            'bytes': entry.get('size_bytes') or 0,
            'loops': entry.get('loops') or 0,
            'branches': entry.get('branches') or 0,
            'fields': set(entry.get('field_offsets') or []),
            'consts': set(entry.get('consts') or []),
            'strings': set(entry.get('strings') or []),
            'calls': list(entry.get('calls') or []),
            'callers': list(entry.get('callers') or []),
        }
    named = qualified_names(index, out)
    if named and not os.environ.get('PORTMATCH_QUIET'):
        print(f'[.] {index}: {named} names qualified from symbols.json')
    return out, derive_base(rows)


def section_of(sections, va):
    for section in sections:
        if section['addr'] <= va < section['addr'] + section['size']:
            return section
    return None


def read_body(raw, sections, start, length):
    section = section_of(sections, start)
    if section is None:
        return b'', 0
    end = min(start + length, section['addr'] + section['size'])
    begin = section['fileoff'] + (start - section['addr'])
    stop = begin + (end - start)
    return raw[begin:stop], start


def sign(value, bits):
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def arm_targets(blob, va):
    out = set()
    for pos in range(0, max(0, len(blob) - 3), 4):
        word = struct.unpack_from('<I', blob, pos)[0]
        site = va + pos
        if word & 0xFF000000 == 0xEB000000:
            out.add(site + 8 + (sign(word & 0xFFFFFF, 24) << 2))
        elif word & 0xFE000000 == 0xFA000000:
            half = (word >> 24) & 1
            out.add(site + 8 + (sign(word & 0xFFFFFF, 24) << 2) + half * 2)
    return out


def aarch64_targets(blob, va):
    out = set()
    for pos in range(0, max(0, len(blob) - 3), 4):
        word = struct.unpack_from('<I', blob, pos)[0]
        if word & 0xFC000000 == 0x94000000:
            out.add(va + pos + (sign(word & 0x3FFFFFF, 26) << 2))
    return out


def thumb_targets(blob, va):
    out = set()
    for pos in range(0, max(0, len(blob) - 3), 2):
        first, second = struct.unpack_from('<HH', blob, pos)
        if first & 0xF800 != 0xF000 or second & 0xD000 != 0xD000:
            continue
        s = (first >> 10) & 1
        j1 = (second >> 13) & 1
        j2 = (second >> 11) & 1
        i1 = 0 if j1 ^ s else 1
        i2 = 0 if j2 ^ s else 1
        imm = ((s << 24) | (i1 << 23) | (i2 << 22) | ((first & 0x3FF) << 12) | ((second & 0x7FF) << 1))
        if s:
            imm -= 1 << 25
        out.add(va + pos + 4 + imm)
    return out


def binary_edges(path, start_va, length, index_base):
    with open(path, 'rb') as f:
        raw = f.read()
    _start, machine, binary_base, sections = load_image(raw)
    blob, va = read_body(raw, sections, start_va, min(length, MAX_BODY))
    if not blob:
        return set(), [], binary_base
    if machine & 0x1000000 or machine == EM_AARCH64:
        found = aarch64_targets(blob, va)
    else:
        found = arm_targets(blob, va) | thumb_targets(blob, va)
    rvas = set()
    for target in found:
        rvas.add(target - index_base if target >= index_base else target - binary_base)
    return rvas, sections, binary_base


def df_weights(candidates):
    df = collections.Counter()
    for item in candidates:
        df.update(item['consts'])
    total = max(1, len(candidates))
    cutoff = max(4.0, total * 0.01)
    return df, {value: (math.log(1.0 + total / count) if count <= cutoff else 0.0)
                for value, count in df.items()}


def score(src, dst, weights, df):
    form = 0.5 * ratio(src['loops'], dst['loops']) + 0.5 * ratio(src['branches'], dst['branches'])
    parts = {
        'consts': weighted(src['consts'], dst['consts'], weights),
        'deltas': jac(deltas(src['fields']), deltas(dst['fields'])),
        'fields': jac(src['fields'], dst['fields']),
        'form': form,
        'chars': ratio(src['size'], dst['size']),
        'bytes': ratio(src['bytes'], dst['bytes']),
        'strings': jac(src['strings'], dst['strings']),
    }
    parts['rare'] = sum(1 for value in src['consts'] & dst['consts'] if df.get(value, 999) <= 10)
    weights = {'consts': 0.22, 'strings': 0.26, 'deltas': 0.16, 'fields': 0.10, 'form': 0.14,
               'chars': 0.06, 'bytes': 0.06}
    active = set()
    if src['consts'] and dst['consts']:
        active.add('consts')
    if src['strings'] and dst['strings']:
        active.add('strings')
    if src['fields'] or dst['fields']:
        active.update(('deltas', 'fields'))
    if src['loops'] or src['branches'] or dst['loops'] or dst['branches']:
        active.add('form')
    if src['size'] and dst['size']:
        active.add('chars')
    if src['bytes'] and dst['bytes']:
        active.add('bytes')
    total = sum(weights[k] * parts[k] for k in active) / sum(weights[k] for k in active) if active else 0.0
    if src['bytes'] and src['bytes'] == dst['bytes']:
        total += 0.05
    shared = {text for text in src['strings'] & dst['strings'] if len(text) >= 8}
    if shared:
        total += min(0.12, 0.03 * len(shared))
    return max(0.0, min(1.0, total)), parts


def build_pool(target, anchor_pair, bin_path, index_base, notes):
    pool = {}
    if anchor_pair:
        anchor_new = f'0x{anchor_pair[1]:x}'
        entry = target.get(anchor_new)
        if entry is None:
            notes.append(f'anchor {anchor_new} missing in target index')
        else:
            for callee in entry['calls']:
                pool.setdefault(callee, set()).add('index')
            notes.append(f'anchor {anchor_new} index callees={len(entry["calls"])}')
    if bin_path and anchor_pair:
        entry = target.get(f'0x{anchor_pair[1]:x}')
        if entry is not None:
            start = entry['offset'] + index_base
            length = entry['bytes'] or target_span(target, entry)
            rvas, _sections, binary_base = binary_edges(bin_path, start, length, index_base)
            hits = 0
            for rva in rvas:
                key = f'0x{rva:x}'
                if key in target:
                    pool.setdefault(key, set()).add('bin')
                    hits += 1
            notes.append(f'anchor bl targets={len(rvas)} in index={hits} binary_base=0x{binary_base:x}')
    return pool


def target_span(target, entry):
    following = [item['offset'] for item in target.values() if item['offset'] > entry['offset']]
    if not following:
        return MAX_BODY
    return min(min(following) - entry['offset'], MAX_BODY)


def resolve_source(source, token):
    token = token.strip()
    if token.lower().startswith('0x'):
        return f'0x{to_int(token):x}'
    lowered = token.lower()
    for key, entry in source.items():
        if entry['name'].lower() == lowered:
            return key
    best = None
    for key, entry in source.items():
        if lowered in entry['name'].lower():
            if best is None or entry['size'] > source[best]['size']:
                best = key
    return best


def jobs(args):
    out = []
    if args.batch:
        with open(args.batch, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.split('#', 1)[0].strip()
                if not line:
                    continue
                out.append(line)
    if args.name:
        out.append(args.name)
    out.extend(split_tokens(args.offset))
    return out


def parse_anchor(value):
    if not value:
        return None
    left, _, right = value.partition(':')
    if not left:
        return None
    old = to_int(left)
    new = to_int(right) if right else old
    return old, new


def run_one(args, source, target, weights, df, token, anchor_pair):
    key = resolve_source(source, token)
    if key is None or key not in source:
        return {'input': token, 'error': 'missing in source'}
    src = source[key]
    notes = []
    pool = build_pool(target, anchor_pair, args.target_bin, args.index_base, notes)
    origin = 'pool'
    if not pool:
        origin = 'full'
        notes.append('pool empty, scanned the whole target index')
    candidates = []
    keys = list(pool) if pool else list(target)
    for candidate in keys:
        dst = target.get(candidate)
        if dst is None:
            continue
        if src['size'] and not (1 / args.band <= (dst['size'] + 1) / (src['size'] + 1) <= args.band):
            continue
        total, parts = score(src, dst, weights, df)
        edges = pool.get(candidate, set())
        if 'index' in edges:
            total += EDGE_INDEX_BONUS
        if 'bin' in edges:
            total += EDGE_BINARY_BONUS
        if len(edges) > 1:
            total += EDGE_DOUBLE_BONUS
        candidates.append((min(1.0, total), parts, dst, edges))
    candidates.sort(key=lambda row: -row[0])
    rows = [row for row in candidates if row[0] >= args.min_score][:max(1, args.top)]
    best = rows[0][0] if rows else 0.0
    second = rows[1][0] if len(rows) > 1 else 0.0
    gap = best - second
    top_edges = bool(rows) and bool(rows[0][3])
    if gap >= 0.08 and (best >= 0.55 or top_edges):
        verdict = 'strong'
    elif gap >= 0.05:
        verdict = 'weak'
    else:
        verdict = 'none'
    return {
        'input': token,
        'old': key,
        'name': src['name'],
        'size': src['size'],
        'origin': origin,
        'notes': notes,
        'verdict': verdict,
        'gap': round(best - second, 3),
        'rows': [{'score': round(total, 3), 'key': dst['key'], 'name': dst['name'],
                  'size': dst['size'], 'bytes': dst['bytes'], 'edges': sorted(edges), 'parts': parts}
                 for total, parts, dst, edges in rows],
    }


def ladder(args, source, target, weights, df, anchor_pair):
    bound = {f'0x{anchor_pair[0]:x}': f'0x{anchor_pair[1]:x}'}
    queue = [(f'0x{anchor_pair[0]:x}', 0)]
    accepted = []
    while queue:
        old_key, level = queue.pop(0)
        if level >= args.depth:
            continue
        pair = (int(old_key, 16), int(bound[old_key], 16))
        for callee in source.get(old_key, {}).get('calls') or []:
            if callee in bound or callee not in source:
                continue
            result = run_one(args, source, target, weights, df, callee, pair)
            if result.get('error') or not result['rows']:
                continue
            top = result['rows'][0]
            if top['score'] < 0.45 or result['gap'] < args.accept:
                continue
            bound[callee] = top['key']
            accepted.append({'old': callee, 'new': top['key'], 'score': top['score'],
                             'gap': result['gap'], 'name': result['name']})
            queue.append((callee, level + 1))
    return accepted


def main():
    args = parse_args()
    source, _source_base = prepare(args.source)
    target, index_base = prepare(args.target)
    args.index_base = index_base
    candidates = [item for item in target.values() if item['size'] > 0]
    df, weights = df_weights(candidates)
    anchor_pair = parse_anchor(args.anchor)
    if args.ladder:
        if not anchor_pair:
            raise SystemExit('[-] --ladder needs --anchor')
        accepted = ladder(args, source, target, weights, df, anchor_pair)
        if args.pairs:
            with open(args.pairs, 'w', encoding='utf-8') as f:
                json.dump({row['old']: row['new'] for row in accepted}, f, indent=1)
        for row in accepted:
            print(f"{row['old']} -> {row['new']}  {row['score']:.3f} gap={row['gap']:.3f}  {row['name'][:40]}")
        print(f'[{len(accepted)} bindings]')
        return
    tokens = jobs(args)
    if not tokens:
        raise SystemExit('[-] pass -o, -n or --batch')
    results = [run_one(args, source, target, weights, df, token, anchor_pair) for token in tokens]
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
        return
    for result in results:
        if result.get('error'):
            print(f'{result["input"]}: {result["error"]}')
            continue
        head = (f'{result["old"]} {result["name"][:38]:38s} size={result["size"]:5d} '
                f'{result["origin"]:4s} gap={result["gap"]:.3f} -> {result["verdict"]}')
        print(f'\n{head}')
        for note in result['notes']:
            print(f'  . {note}')
        for row in result['rows']:
            parts = row['parts']
            print(f'  {row["score"]:.3f} {row["key"]:>10s} {row["name"][:38]:38s} '
                  f'cst {parts["consts"]:.2f} dlt {parts["deltas"]:.2f} fld {parts["fields"]:.2f} '
                  f'frm {parts["form"]:.2f} ch {parts["chars"]:.2f} by {parts["bytes"]:.2f} '
                  f'rare {parts["rare"]} edge {",".join(row["edges"]) or "-"}')


if __name__ == '__main__':
    main()
