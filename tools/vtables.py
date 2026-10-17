#!/usr/bin/env python3
import argparse
import json
import os
import struct

from binary import detect_base, macho_sections

DATA_SECTIONS = ('__const', '__data', '__objc_const', '__objc_data',
                 '__mod_init_func', '__init_offsets')
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


def decode_slot(value, base, starts, code_range=None):
    for mask in PTR_MASKS:
        rva = (value & mask) - base
        if rva in starts:
            return rva
    if code_range:
        for mask in PTR_MASKS:
            rva = (value & mask) - base
            if code_range[0] <= rva < code_range[1]:
                return rva
    return None


def data_sections(data):
    return [s for s in macho_sections(data)
            if s['sect'] in DATA_SECTIONS and s['size'] and s['fileoff']]


def scan_section(data, section, base, starts, min_slots, code_range=None, max_gap=2, ranges=()):
    lo = section['addr']
    hi = lo + section['size']
    tables = {}
    run = []
    start = 0
    gap = 0
    pos = lo
    while pos + 8 <= hi:
        fileoff = section['fileoff'] + (pos - lo)
        value = struct.unpack_from('<Q', data, fileoff)[0]
        rva = decode_slot(value, base, starts)
        loose = False
        if rva is None and code_range:
            for mask in PTR_MASKS:
                candidate = (value & mask) - base
                if code_range[0] <= candidate < code_range[1]:
                    rva = candidate
                    loose = True
                    break
        boundary = False
        if loose and pos - 16 >= lo:
            head = section['fileoff'] + pos - 16 - lo
            top = struct.unpack_from('<i', data, head)[0]
            info = struct.unpack_from('<Q', data, head + 8)[0]
            boundary = -0x10000 < top <= 0 and (info == 0 or any(lo2 <= info < hi2 for lo2, hi2 in ranges))
        if boundary:
            if len(run) >= min_slots:
                tables[start] = run
            run = []
            gap = 0
        elif rva is not None and len(run) < MAX_SLOTS and (not loose or (run and gap < max_gap)):
            if not run:
                start = pos
            run.append(rva)
            gap = gap + 1 if loose else 0
        else:
            if len(run) >= min_slots:
                tables[start] = run
            run = []
            gap = 0
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


def mark_prefixes(vtables):
    heads = {}
    for address, entry in vtables.items():
        if entry.get('alias_of'):
            continue
        methods = entry['methods']
        for depth in range(2, min(len(methods), 8) + 1):
            heads.setdefault(tuple(methods[:depth]), []).append(address)
    for address, entry in vtables.items():
        if entry.get('alias_of'):
            continue
        methods = entry['methods']
        for depth in range(min(len(methods), 8), 1, -1):
            group = heads.get(tuple(methods[:depth]))
            if not group:
                continue
            candidates = [a for a in group if a != address and vtables[a]['slots'] >= depth]
            if candidates:
                candidates.sort(key=lambda a: -vtables[a]['slots'])
                entry['extends'] = candidates[0]
                entry['shared_prefix'] = depth
                break


def header_of(data, address, base, data_ranges, segments):
    if address - base < 16:
        return None
    offset_to_top = struct.unpack_from('<i', data, address - base - 16)[0]
    typeinfo = struct.unpack_from('<Q', data, address - base - 8)[0]
    info_ok = typeinfo == 0 or any(lo <= typeinfo < hi for lo, hi in data_ranges)
    if not (info_ok and -0x10000 < offset_to_top <= 0):
        return None
    header = {'offset_to_top': offset_to_top,
              'typeinfo': f'0x{typeinfo:x}' if typeinfo else None}
    if typeinfo:
        name_ptr = 0
        holder = next((s for s in segments if s['addr'] <= typeinfo < s['addr'] + s['size']), None)
        if holder:
            position = holder['fileoff'] + typeinfo - holder['addr'] + 8
            if 0 <= position <= len(data) - 8:
                name_ptr = struct.unpack_from('<Q', data, position)[0]
        section = next((s for s in segments if s['addr'] <= name_ptr < s['addr'] + s['size']), None) \
            if name_ptr else None
        if section:
            start = section['fileoff'] + name_ptr - section['addr']
            end = data.find(b'\0', start)
            if 0 <= start < len(data) and end > start:
                raw = data[start:end].decode('utf-8', 'replace')
                if raw.startswith('_Z'):
                    raw = raw[2:]
                if raw.startswith('N'):
                    raw = raw[1:]
                parts = []
                index = 0
                while index < len(raw) and raw[index].isdigit():
                    digits = index
                    while digits < len(raw) and raw[digits].isdigit():
                        digits += 1
                    length = int(raw[index:digits])
                    part = raw[digits:digits + length]
                    if not part:
                        break
                    parts.append(part)
                    index = digits + length
                header['class_name'] = '::'.join(parts) if parts else raw
                header['typeinfo_name'] = raw
    return header


def main():
    args = parse_args()
    out = args.out or os.path.join(args.index_dir, 'vtables.json')
    functions = load(os.path.join(args.index_dir, 'functions.json'), None)
    if functions is None:
        raise SystemExit(f'[-] {os.path.join(args.index_dir, "functions.json")} not found, run xrefs.py first')
    fingerprints = load(os.path.join(args.index_dir, 'fingerprints.json'), {})
    unwind_path = os.path.join(args.index_dir, 'unwind.json')
    unwind = set()
    if os.path.exists(unwind_path):
        with open(unwind_path) as f:
            unwind = {int(v, 16) for v in json.load(f).get('starts', [])}
    starts = sorted(set(v['offset'] for v in functions.values()) | unwind)
    starts_set = set(starts)
    if not starts:
        raise SystemExit('[-] functions.json is empty')

    with open(args.bin, 'rb') as f:
        data = f.read()
    base = detect_base(args.bin)

    segments = macho_sections(data)
    sections = data_sections(data)
    data_ranges = [(section['addr'], section['addr'] + section['size']) for section in segments]
    function_keys = {f'0x{v["offset"]:x}' for v in functions.values()}
    text = next((s for s in segments if s['sect'] == '__text'), None)
    code_range = (text['addr'] - base, text['addr'] - base + text['size']) if text else None
    vtables = {}
    inits = {}
    for section in sections:
        if section['sect'] == '__init_offsets':
            targets = []
            for pos in range(section['addr'], section['addr'] + section['size'] - 3, 4):
                rva = struct.unpack_from('<I', data, section['fileoff'] + pos - section['addr'])[0]
                if rva in starts_set:
                    targets.append(rva)
            if targets:
                inits[section['addr']] = {
                    'address': f"0x{section['addr']:x}",
                    'section': f"{section['seg']}.{section['sect']}",
                    'kind': 'init_func',
                    'slots': len(targets),
                    'methods': [f'0x{m:x}' for m in targets],
                    'chars': sum(functions.get(f'0x{m:x}', {}).get('size_chars', 0) for m in targets),
                    'bytes': len(targets) * 4,
                }
            continue
        is_init = section['sect'] == '__mod_init_func'
        for address, methods in scan_section(data, section, base, starts_set, args.min_slots,
                                             code_range, 2, data_ranges).items():
            roles = roles_of(fingerprints, methods)
            entry = {
                'address': f'0x{address:x}',
                'section': f"{section['seg']}.{section['sect']}",
                'kind': 'init_func' if is_init else 'vtable',
                'slots': len(methods),
                'methods': [f'0x{m:x}' for m in methods],
                'chars': sum(functions.get(f'0x{m:x}', {}).get('size_chars', 0) for m in methods),
                'bytes': len(methods) * 8,
            }
            if any(roles):
                entry['roles'] = roles
            shadow = [i for i, m in enumerate(methods) if f'0x{m:x}' not in function_keys]
            if shadow:
                entry['shadow'] = shadow
            header = header_of(data, address, base, data_ranges, segments)
            if header:
                entry['header'] = header
            (inits if is_init else vtables)[address] = entry

    mark_aliases(vtables)
    mark_prefixes(vtables)
    vtables.update(inits)

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

    real = [v for v in vtables.values() if v.get('kind') == 'vtable']
    unique = [v for v in real if not v.get('alias_of')]
    slots = sum(v['slots'] for v in real)
    inherited = sum(1 for v in unique if v.get('extends'))
    shadows = sum(len(v.get('shadow', [])) for v in real)
    headers = sum(1 for v in real if v.get('header'))
    names = sum(1 for v in real if (v.get('header') or {}).get('class_name'))
    biggest = max(real, key=lambda v: v['slots']) if real else None
    print(f'[+] vtables={len(real)} inits={len(inits)} slots={slots} signatures={len(unique)} '
          f'aliases={len(real) - len(unique)} extends={inherited} names={names} '
          f'starts={len(starts)} shadow={shadows} headers={headers} '
          f'max={biggest["slots"] if biggest else 0}@{biggest["address"] if biggest else "-"} -> {out}')


if __name__ == '__main__':
    main()
