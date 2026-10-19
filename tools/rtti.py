#!/usr/bin/env python3
"""Recover C++ class names for every vtable from the binary itself.

A stripped target has no symbol names, but the Itanium ABI keeps the class name
inside the run-time type information the vtable points at:

    vtable[-1] -> type_info { vptr, name }  ->  mangled class name

Reading those three pointers turns a pile of anonymous function addresses into
named classes, so an offset can be requested by name (``BattleScreen::update``)
and located without any hint about the target build.

Output: vtables_named.json
    {vtable_address: {class, mangled, typeinfo, slots, methods, pure, section}}
"""

import argparse
import json
import os
import struct
import sys

from binary import CPU_TYPE_ARM64, load_image


def parse_args():
    p = argparse.ArgumentParser(description='Resolve vtable class names through RTTI')
    p.add_argument('--bin', required=True, help='binary the dump was produced from')
    p.add_argument('--index', required=True, help='index directory holding vtables.json')
    p.add_argument('--out', default='', help='output directory, defaults to --index')
    p.add_argument('--vtables', default='vtables.json', help='vtable index file name')
    return p.parse_args()


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def to_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.startswith('0x'):
        return int(value, 16)
    return None


def demangle(name):
    """Reduce a mangled type name to a readable class path."""
    if not name:
        return None
    text = name
    if text.startswith('_Z'):
        text = text[2:]
    prefix = ''
    if text.startswith('TK') or text.startswith('N'):
        if text.startswith('TK'):
            prefix, text = 'typeinfo for ', text[2:]
        else:
            text = text[1:]
    parts = []
    index = 0
    while index < len(text) and text[index].isdigit():
        end = index
        while end < len(text) and text[end].isdigit():
            end += 1
        size = int(text[index:end])
        part = text[end:end + size]
        if len(part) != size:
            break
        parts.append(part)
        index = end + size
    if len(parts) < 2:
        single = text.rstrip('E0123456789')
        return prefix + single if single else None
    tail = parts[-1]
    if tail in ('C1', 'C2', 'C3'):
        parts[-1] = f'{parts[-2]}::{parts[-2]}'
    elif tail in ('D0', 'D1', 'D2'):
        parts[-1] = f'~{parts[-2]}'
    return prefix + '::'.join(parts)


class Reader:
    def __init__(self, data, sections, width):
        self.data = data
        self.sections = sections
        self.width = width
        self.fmt = '<Q' if width == 8 else '<I'

    def pointer(self, address):
        if address is None:
            return None
        for section in self.sections:
            if section['addr'] <= address < section['addr'] + section['size']:
                offset = section['fileoff'] + address - section['addr']
                if 0 <= offset and offset + self.width <= len(self.data):
                    return struct.unpack_from(self.fmt, self.data, offset)[0]
                return None
        return None


def main():
    args = parse_args()
    out = args.out or args.index
    with open(args.bin, 'rb') as handle:
        data = handle.read()
    _, machine, base, sections = load_image(data)
    width = 8 if machine == CPU_TYPE_ARM64 else 4
    reader = Reader(data, sections, width)

    vtables = load_json(os.path.join(args.index, args.vtables), {})
    if not vtables:
        raise SystemExit(f'[-] {args.vtables} not found in {args.index}')

    strings = load_json(os.path.join(args.index, 'strings.json'), {})
    by_address = {}
    for text, entry in strings.items():
        address = entry.get('address') if isinstance(entry, dict) else entry
        address = to_int(address)
        if address:
            by_address.setdefault(address, text)

    named = {}
    resolved = 0
    for key, entry in vtables.items():
        address = to_int(entry.get('address')) or to_int(key)
        if address is None:
            continue
        header = entry.get('header') or {}
        typeinfo = to_int(header.get('typeinfo')) or reader.pointer(address - width)
        mangled = None
        if typeinfo:
            candidate = reader.pointer(typeinfo + width)
            mangled = by_address.get(candidate)
            if not mangled and header.get('typeinfo_name'):
                mangled = str(header['typeinfo_name']).lstrip('_Z')
        class_name = (header.get('class_name') or (demangle(mangled) if mangled else None))
        methods = entry.get('methods') or []
        pure = [i for i, m in enumerate(methods) if m == f'0x{address:x}']
        if class_name:
            resolved += 1
        named[key] = {
            'class': class_name,
            'mangled': mangled,
            'typeinfo': f'0x{typeinfo:x}' if typeinfo else None,
            'name_ptr': None,
            'slots': entry.get('slots') or len(methods),
            'methods': methods,
            'pure': pure,
            'section': entry.get('section'),
        }

    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, 'vtables_named.json')
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(named, handle, ensure_ascii=False)

    by_class = {}
    for key, item in named.items():
        if item['class']:
            by_class.setdefault(item['class'].lower(), []).append(key)
    print(f'[+] vtables={len(named)} named={resolved} classes={len(by_class)} -> {path}')
    multi = {c: keys for c, keys in by_class.items() if len(keys) > 1}
    if multi:
        print(f'[+] classes with several vtables: {len(multi)} '
              f'(e.g. {next(iter(multi.items()))[0]} -> {len(next(iter(multi.values())))})')


if __name__ == '__main__':
    sys.exit(main())
