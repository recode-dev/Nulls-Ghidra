#!/usr/bin/env python3

import argparse
import json
import os
import struct

from binary import BadImage, file_offset, macho_image

DATA_SECTIONS = ('__const', '__data', '__objc_const', '__objc_data',
                 '__mod_init_func', '__init_offsets', '.init_array', '.preinit_array')
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


def decode_slot(value, base, starts, width=8):
    if width == 4:
        rva = value - base
        return rva if rva in starts else None
    for mask in PTR_MASKS:
        rva = (value & mask) - base
        if rva in starts:
            return rva
    return None


def data_sections(sections):
    return [s for s in sections if s['sect'] in DATA_SECTIONS and s['size'] and s['fileoff']]


def scan_section(data, section, base, starts, min_slots, width=8):
    lo = section['addr']
    hi = lo + section['size']
    reader = '<I' if width == 4 else '<Q'
    tables = {}
    run = []
    start = 0
    pos = lo
    while pos + width <= hi:
        fileoff = section['fileoff'] + (pos - lo)
        if fileoff + width > len(data):
            break
        value = struct.unpack_from(reader, data, fileoff)[0]
        rva = decode_slot(value, base, starts, width)
        if rva is not None and len(run) < MAX_SLOTS:
            if not run:
                start = pos
            run.append(rva)
        else:
            if len(run) >= min_slots:
                tables[start] = run
            run = []
        pos += width
    if len(run) >= min_slots:
        tables[start] = run
    return tables


def demangle(mangled):
    text = mangled
    if text.startswith('_ZTV') or text.startswith('_ZTI'):
        text = text[4:]
    if text.startswith('N'):
        text = text[1:]
    parts = []
    index = 0
    while index < len(text) and text[index].isdigit():
        end = index
        while end < len(text) and text[end].isdigit():
            end += 1
        length = int(text[index:end])
        part = text[end:end + length]
        if not part:
            break
        parts.append(part)
        index = end + length
    return '::'.join(parts)


def symbol_vtables(data, symbols, base, width, fingerprints, code_range, sections):
    named = {name: int(value, 16) for name, value in (symbols.get('symbols') or {}).items()}
    types = {address: name for name, address in named.items() if name.startswith('_ZTI')}
    reader = '<I' if width == 4 else '<Q'
    out = {}
    for name, address in named.items():
        if not name.startswith('_ZTV') or address <= 0:
            continue
        pos = file_offset(sections, address)
        if pos is None or pos + width * 2 > len(data):
            continue
        start = address + width * 2
        methods = []
        cursor = pos + width * 2
        while cursor + width <= len(data) and len(methods) < MAX_SLOTS:
            value = struct.unpack_from(reader, data, cursor)[0]
            rva = value - base
            if width == 4 and rva & 1:
                rva &= ~1
            if not (code_range[0] <= rva < code_range[1]):
                break
            methods.append(rva)
            cursor += width
        if len(methods) < 2:
            continue
        typeinfo = struct.unpack_from(reader, data, pos + width)[0]
        entry = {
            'address': f'0x{start:x}',
            'section': '__const',
            'kind': 'vtable',
            'slots': len(methods),
            'methods': [f'0x{m:x}' for m in methods],
            'chars': sum(fingerprints.get(f'0x{m:x}', {}).get('size', 0) for m in methods),
            'bytes': len(methods) * width,
            'header': {'offset_to_top': struct.unpack_from('<i', data, pos)[0],
                       'typeinfo': f'0x{typeinfo:x}' if typeinfo else None},
        }
        class_name = demangle(types.get(typeinfo, name))
        if class_name:
            entry['header']['class_name'] = class_name
            entry['header']['typeinfo_name'] = types.get(typeinfo, name).lstrip('_')
        roles = roles_of(fingerprints, methods)
        if any(roles):
            entry['roles'] = roles
        out[start] = entry
    return out


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


def header_of(data, address, data_ranges, segments, width=8):
    offset = file_offset(segments, address)
    if offset is None or offset < width * 2:
        return None
    offset_to_top = struct.unpack_from('<i', data, offset - width * 2)[0]
    typeinfo = struct.unpack_from('<Q' if width == 8 else '<I', data, offset - width)[0]
    info_ok = typeinfo == 0 or any(lo <= typeinfo < hi for lo, hi in data_ranges)
    if not (info_ok and -0x10000 < offset_to_top <= 0):
        return None
    header = {'offset_to_top': offset_to_top,
              'typeinfo': f'0x{typeinfo:x}' if typeinfo else None}
    if typeinfo:
        name_ptr = 0
        holder = next((s for s in segments if s['addr'] <= typeinfo < s['addr'] + s['size']), None)
        if holder:
            position = holder['fileoff'] + typeinfo - holder['addr'] + width
            if 0 <= position <= len(data) - width:
                name_ptr = struct.unpack_from('<Q' if width == 8 else '<I', data, position)[0]
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
    width = 4 if data[:4] == b'\x7fELF' and data[4] == 1 else 8
    _start, _cputype, base, segments = macho_image(data)
    sections = data_sections(segments)
    data_ranges = [(section['addr'], section['addr'] + section['size']) for section in segments]
    function_keys = {f'0x{v["offset"]:x}' for v in functions.values()}
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
        is_init = section['sect'] in ('__mod_init_func', '.init_array', '.preinit_array')
        for address, methods in scan_section(data, section, base, starts_set, args.min_slots,
                                             width).items():
            roles = roles_of(fingerprints, methods)
            entry = {
                'address': f'0x{address:x}',
                'section': f"{section['seg']}.{section['sect']}",
                'kind': 'init_func' if is_init else 'vtable',
                'slots': len(methods),
                'methods': [f'0x{m:x}' for m in methods],
                'chars': sum(functions.get(f'0x{m:x}', {}).get('size_chars', 0) for m in methods),
                'bytes': len(methods) * width,
            }
            if any(roles):
                entry['roles'] = roles
            shadow = [i for i, m in enumerate(methods) if f'0x{m:x}' not in function_keys]
            if shadow:
                entry['shadow'] = shadow
            header = header_of(data, address, data_ranges, segments, width)
            if header:
                entry['header'] = header
            (inits if is_init else vtables)[address] = entry

    symbols = load(os.path.join(args.index_dir, 'symbols.json'), {})
    if any(name.startswith('_ZTV') for name in (symbols.get('symbols') or {})):
        text = next((s for s in segments if s['sect'] == '__text'), None)
        code_range = (text['addr'] - base, text['addr'] - base + text['size']) if text else (0, len(data))
        vtables = symbol_vtables(data, symbols, base, width, fingerprints, code_range, segments)

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
    try:
        main()
    except (BadImage, struct.error, OSError, ValueError) as exc:
        raise SystemExit(f'[-] {exc}')
