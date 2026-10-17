#!/usr/bin/env python3
import argparse
import json
import os
import struct

from binary import detect_base, macho_sections

DATA_SECTIONS = ('__const', '__data', '__objc_const', '__objc_data')
PTR_MASKS = ((1 << 36) - 1, (1 << 43) - 1, (1 << 48) - 1)
MAX_SLOTS = 1024


def parse_args():
    p = argparse.ArgumentParser(description='Recover vtables from pointer arrays in data sections')
    p.add_argument('--bin', required=True, help='Mach-O binary')
    p.add_argument('--index_dir', default='index_data', help='index directory holding functions.json')
    p.add_argument('--out', default='', help='output path, defaults to <index_dir>/vtables.json')
    p.add_argument('--min-slots', type=int, default=3, help='minimum slot count kept as a vtable')
    return p.parse_args()


def load(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def decode_slot(value, base, starts):
    for mask in PTR_MASKS:
        rva = (value & mask) - base
        if rva in starts:
            return rva
    return None


def data_sections(data):
    return [s for s in macho_sections(data)
            if s['sect'] in DATA_SECTIONS and s['size'] and s['fileoff']]


def scan_section(data, section, base, starts, min_slots):
    lo = section['addr']
    hi = lo + section['size']
    tables = {}
    run = []
    start = 0
    pos = lo
    while pos + 8 <= hi:
        fileoff = section['fileoff'] + (pos - lo)
        rva = decode_slot(struct.unpack_from('<Q', data, fileoff)[0], base, starts)
        if rva is not None and len(run) < MAX_SLOTS:
            if not run:
                start = pos
            run.append(rva)
        else:
            if len(run) >= min_slots:
                tables[start] = run
            run = []
        pos += 8
    if len(run) >= min_slots:
        tables[start] = run
    return tables


def roles_of(fingerprints, methods):
    out = []
    for rva in methods:
        entry = fingerprints.get(f'0x{rva:x}')
        out.append(entry.get('topology_role') if entry else None)
    return out


def mark_aliases(vtables):
    canonical = {}
    for address in sorted(vtables):
        key = tuple(vtables[address]['methods'])
        if key in canonical:
            vtables[canonical[key]].setdefault('aliases', []).append(address)
            vtables[address]['alias_of'] = canonical[key]
        else:
            canonical[key] = address


def mark_prefixes(vtables, depth=3):
    heads = {}
    for address, entry in vtables.items():
        if entry.get('alias_of') or len(entry['methods']) < depth:
            continue
        heads.setdefault(tuple(entry['methods'][:depth]), []).append(address)
    for group in heads.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda a: -vtables[a]['slots'])
        base = group[0]
        for address in group[1:]:
            vtables[address]['extends'] = base
            vtables[address]['shared_prefix'] = depth


def main():
    args = parse_args()
    out = args.out or os.path.join(args.index_dir, 'vtables.json')
    functions = load(os.path.join(args.index_dir, 'functions.json'), None)
    if functions is None:
        raise SystemExit(f'[-] {os.path.join(args.index_dir, "functions.json")} not found, run xrefs.py first')
    fingerprints = load(os.path.join(args.index_dir, 'fingerprints.json'), {})
    starts = sorted(v['offset'] for v in functions.values())
    starts_set = set(starts)
    if not starts:
        raise SystemExit('[-] functions.json is empty')

    with open(args.bin, 'rb') as f:
        data = f.read()
    base = detect_base(args.bin)

    vtables = {}
    for section in data_sections(data):
        for address, methods in scan_section(data, section, base, starts_set, args.min_slots).items():
            roles = roles_of(fingerprints, methods)
            entry = {
                'address': f'0x{address:x}',
                'section': f"{section['seg']}.{section['sect']}",
                'slots': len(methods),
                'methods': [f'0x{m:x}' for m in methods],
                'chars': sum(functions.get(f'0x{m:x}', {}).get('size_chars', 0) for m in methods),
            }
            if any(roles):
                entry['roles'] = roles
            vtables[address] = entry

    mark_aliases(vtables)
    mark_prefixes(vtables)

    export = {}
    for address, entry in vtables.items():
        item = dict(entry)
        for key in ('alias_of', 'extends'):
            if isinstance(item.get(key), int):
                item[key] = f'0x{item[key]:x}'
        if 'aliases' in item:
            item['aliases'] = [f'0x{a:x}' for a in item['aliases']]
        export[f'0x{address:x}'] = item
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(export, f, ensure_ascii=False)

    unique = [v for v in vtables.values() if not v.get('alias_of')]
    slots = sum(v['slots'] for v in vtables.values())
    inherited = sum(1 for v in unique if v.get('extends'))
    biggest = max(vtables.values(), key=lambda v: v['slots']) if vtables else None
    print(f'[+] vtables={len(vtables)} slots={slots} signatures={len(unique)} '
          f'aliases={len(vtables) - len(unique)} extends={inherited} '
          f'max={biggest["slots"] if biggest else 0}@{biggest["address"] if biggest else "-"} -> {out}')


if __name__ == '__main__':
    main()
