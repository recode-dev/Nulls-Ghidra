#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys

MAX_ROWS = 200


def parse_args():
    p = argparse.ArgumentParser(description='Find functions in a decompile index by name, symbol or address')
    p.add_argument('-i', '--index', required=True, help='index directory (functions.json)')
    p.add_argument('-n', '--name', default='', help='name substring or regex')
    p.add_argument('-s', '--symbol', default='', help='mangled symbol substring or regex')
    p.add_argument('-o', '--offset', default='', help='comma separated rva values')
    p.add_argument('-a', '--address', default='', help='comma separated absolute addresses')
    p.add_argument('--base', default='', help='image base used to print va (default: derived from the index)')
    p.add_argument('-l', '--limit', type=int, default=20, help='rows printed')
    p.add_argument('--calls', action='store_true', help='print callees')
    p.add_argument('--callers', action='store_true', help='print callers')
    p.add_argument('--expand', type=int, default=0, help='walk the call graph to this depth')
    p.add_argument('--min-size', type=int, default=-1, help='drop rows with fewer chars')
    p.add_argument('--json', action='store_true', help='json output')
    return p.parse_args()


def load(path, name, default=None):
    full = os.path.join(path, name)
    if not os.path.exists(full):
        return default
    with open(full, 'r', encoding='utf-8') as f:
        return json.load(f)


def to_int(token):
    token = token.strip()
    if not token:
        return None
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


def symbol_table(index, base):
    payload = load(index, 'symbols.json', None)
    if not payload:
        return {}, {}
    symbols = payload.get('symbols') if isinstance(payload, dict) else None
    if symbols is None:
        symbols = payload
    by_rva = {}
    by_name = {}
    for name, value in symbols.items():
        if isinstance(value, str):
            address = to_int(value)
        else:
            address = value
        if address is None:
            continue
        rva = address - base if address >= base else address
        by_rva.setdefault(rva, []).append(name)
        by_name[name] = rva
    return by_rva, by_name


def matcher(pattern):
    if not pattern:
        return None
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return lambda text: pattern.lower() in text.lower()
    return lambda text: bool(rx.search(text))


def row_text(key, entry, names):
    rva = entry.get('offset') or int(key, 16)
    chars = entry.get('size_chars') or 0
    size = entry.get('size_bytes') or 0
    name = entry.get('name') or ''
    mangled = names[0] if names else ''
    return (key, rva, chars, size, name, mangled)


def pretty(key, entry, names, base):
    rva = entry.get('offset') or int(key, 16)
    title = entry.get('name') or ''
    if names and names[0] and names[0] != title:
        title = f'{title}  {names[0]}'
    loops = entry.get('loops') or 0
    branches = entry.get('branches') or 0
    chars = entry.get('size_chars') or 0
    size = entry.get('size_bytes') or 0
    va = f'0x{base + rva:x}' if base else ''
    return (f'{key:>10s}  {va:>12s}  {size:>6d}b/{chars:>5d}c  '
            f'{loops:>2d}L/{branches:>3d}B  {entry.get("section") or "-":>10s}  {title[:70]}')


def dump(entry, names, base, functions, depth, args, seen, out, by_rva=None):
    key = f'0x{entry.get("offset") or 0:x}'
    if names is None and by_rva is not None:
        names = by_rva.get(entry.get('offset') or 0)
    out.append(pretty(key, entry, names, base))
    if depth <= 0:
        return
    edges = entry.get('calls') if args.calls or args.expand else None
    if edges:
        for callee in edges:
            if callee in seen:
                continue
            seen.add(callee)
            child = functions.get(callee)
            if child:
                dump(child, None, base, functions, depth - 1, args, seen, out, by_rva)
            else:
                out.append(f'{callee:>10s}  {"":>12s}  missing in index')


def main():
    args = parse_args()
    if not os.path.isdir(args.index):
        raise SystemExit(f'[-] {args.index} is not a directory')
    functions = load(args.index, 'functions.json', None)
    if not functions:
        raise SystemExit(f'[-] {os.path.join(args.index, "functions.json")} not found, build the index first')
    index_base = derive_base(functions)
    base = (to_int(args.base) if args.base else index_base) or 0
    by_rva, by_name = symbol_table(args.index, index_base)

    name_rx = matcher(args.name)
    symbol_rx = matcher(args.symbol)
    wanted_offsets = {to_int(t) for t in split_tokens(args.offset)}
    wanted_offsets.discard(None)
    for token in split_tokens(args.address):
        address = to_int(token)
        if address is None:
            continue
        wanted_offsets.add(address - index_base if address >= index_base else address)

    picked = []
    if name_rx or symbol_rx:
        for key, entry in functions.items():
            text = entry.get('name') or ''
            symbols = by_rva.get(entry.get('offset') or int(key, 16)) or []
            if name_rx and not (name_rx(text) or any(name_rx(s) for s in symbols)):
                continue
            if symbol_rx and not any(symbol_rx(s) for s in symbols):
                continue
            picked.append(key)
        picked.sort(key=lambda k: (functions[k].get('size_chars') or 0), reverse=True)
    elif not wanted_offsets:
        raise SystemExit('[-] pass -n, -s, -o or -a')

    explicit = [f'0x{rva:x}' for rva in sorted(wanted_offsets) if f'0x{rva:x}' in functions]
    missing = [f'0x{rva:x}' for rva in sorted(wanted_offsets) if f'0x{rva:x}' not in functions]
    if args.offset or args.address:
        picked = explicit

    rows = []
    for key in picked:
        entry = functions[key]
        if args.min_size >= 0 and (entry.get('size_chars') or 0) < args.min_size:
            continue
        rows.append((key, entry))
        if len(rows) >= max(1, args.limit):
            break

    if args.json:
        payload = []
        for key, entry in rows:
            item = {k: entry.get(k) for k in ('name', 'offset', 'address', 'section', 'size_bytes',
                                              'size_chars', 'loops', 'branches', 'switches', 'args',
                                              'depth', 'callers', 'calls', 'consts', 'field_offsets')}
            item['key'] = key
            item['va'] = f'0x{base + (entry.get("offset") or 0):x}' if base else ''
            item['symbols'] = by_rva.get(entry.get('offset') or int(key, 16)) or []
            payload.append(item)
        json.dump({'base': f'0x{base:x}', 'rows': payload, 'missing': missing}, sys.stdout, indent=2)
        print()
        return

    out = []
    for key, entry in rows:
        names = by_rva.get(entry.get('offset') or int(key, 16)) or []
        depth = args.expand if args.expand else (1 if args.calls else 0)
        if depth and not (entry.get('calls') or []):
            depth = 0
        dump(entry, names, base, functions, depth, args, {key}, out, by_rva)
        if args.callers:
            for caller in entry.get('callers') or []:
                parent = functions.get(caller)
                if parent:
                    out.append(f'  <- {pretty(caller, parent, by_rva.get(parent.get("offset") or 0), base).strip()}')

    if out:
        print('\n'.join(out))
    for key in missing:
        print(f'{key} missing in index')
    print(f'[{len(rows)} rows, base=0x{base:x}, index={args.index}]')


if __name__ == '__main__':
    main()
