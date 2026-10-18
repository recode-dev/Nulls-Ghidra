#!/usr/bin/env python3

import argparse
import json
import os
import re

C_TYPES = {
    'bool': 'bool',
    'char': 'char',
    'short': 'int16_t',
    'int': 'int32_t',
    'uint': 'uint32_t',
    'long': 'int64_t',
    'ulong': 'uint64_t',
    'undefined1': 'uint8_t',
    'undefined2': 'uint16_t',
    'undefined4': 'uint32_t',
    'undefined8': 'uint64_t',
    'float': 'float',
    'double': 'double',
}


def parse_args():
    p = argparse.ArgumentParser(description='Turn recovered class layouts into a C header')
    p.add_argument('--index_dir', default='index_data', help='index directory')
    p.add_argument('--out', default='structs.h', help='C header output')
    p.add_argument('--json', default='structs.json', help='JSON layout output, empty to skip')
    p.add_argument('--min-fields', type=int, default=1, help='skip classes with fewer fields')
    return p.parse_args()


def ident(name):
    clean = re.sub(r'[^0-9A-Za-z_]', '_', name)
    if not clean or clean[0].isdigit():
        clean = f'cls_{clean}'
    return clean


def scalar(field):
    types = field.get('types') or {}
    width = field.get('width') or 0
    if types and width in (1, 2, 4, 8):
        name = max(types, key=types.get)
        return C_TYPES.get(name, f'uint{width * 8}_t')
    return ''


def emit(name, entry):
    fields = sorted(entry.get('field_layout') or [], key=lambda item: int(item['offset'], 16))
    lines = ['typedef struct {']
    cursor = 0
    for field in fields:
        offset = int(field['offset'], 16)
        width = field.get('width') or 8
        if offset > cursor:
            lines.append(f'  uint8_t pad_0x{cursor:x}[{offset - cursor}];')
        declared = scalar(field)
        if declared:
            lines.append(f'  {declared} field_0x{offset:x};')
        elif width:
            lines.append(f'  uint8_t field_0x{offset:x}[{width}];')
        cursor = max(cursor, offset + (width or 0))
    size = entry.get('size') or cursor
    if size > cursor:
        lines.append(f'  uint8_t pad_0x{cursor:x}[{size - cursor}];')
    lines.append(f'}} {ident(name)};')
    return '\n'.join(lines)


def main():
    args = parse_args()
    path = os.path.join(args.index_dir, 'classes.json')
    if not os.path.exists(path):
        raise SystemExit(f'[-] {path} not found, build the index first')
    with open(path, 'r', encoding='utf-8') as f:
        classes = json.load(f)

    blocks = []
    layouts = {}
    for name, entry in sorted(classes.items()):
        fields = entry.get('field_layout') or []
        if len(fields) < args.min_fields:
            continue
        blocks.append(emit(name, entry))
        layouts[ident(name)] = {
            'vtable': entry.get('vtable'),
            'size': entry.get('size'),
            'fields': [{'offset': item['offset'], 'width': item.get('width'),
                        'types': item.get('types') or {}, 'readers': item.get('funcs') or [],
                        'writers': item.get('writers') or []} for item in fields],
        }

    with open(args.out, 'w', encoding='utf-8') as f:
        f.write('#include <stdint.h>\n#include <stdbool.h>\n\n')
        f.write('\n\n'.join(blocks))
        if blocks:
            f.write('\n')
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(layouts, f, indent=2)

    total = sum(len(entry['fields']) for entry in layouts.values())
    print(f'[+] structs={len(layouts)} fields={total} -> {args.out}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit(f'[-] {exc}')
