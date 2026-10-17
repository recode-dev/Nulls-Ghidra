#!/usr/bin/env python3
import argparse
import bisect
import collections
import json
import os
import re

from xrefs import FUNC_RE

TYPED_RE = re.compile(
    r'\*\s*\(\s*(?P<type>[A-Za-z_][A-Za-z0-9_]*)\s*\*\s*\)\s*'
    r'\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\)'
)
INDEX_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\s*\[\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\]')
ARROW_RE = re.compile(
    r'[A-Za-z_][A-Za-z0-9_]*\s*->\s*(?P<name>field_0x(?P<offset>[0-9a-fA-F]+))'
)
WIDTHS = {
    'char': 1, 'uchar': 1, 'byte': 1, 'undefined1': 1, 'int8_t': 1, 'uint8_t': 1,
    'short': 2, 'ushort': 2, 'undefined2': 2, 'int16_t': 2, 'uint16_t': 2,
    'int': 4, 'uint': 4, 'undefined4': 4, 'float': 4, 'int32_t': 4, 'uint32_t': 4,
    'long': 8, 'ulong': 8, 'undefined8': 8, 'double': 8, 'int64_t': 8, 'uint64_t': 8,
    'code': 8, 'pointer': 8,
}


def parse_args():
    p = argparse.ArgumentParser(description='Aggregate struct field accesses: readers, writers, types, widths')
    p.add_argument('--code', required=True, help='decompiled.c')
    p.add_argument('--out', default='index_data/fields.json', help='output path')
    p.add_argument('--max-offset', type=lambda v: int(v, 0), default=0x20000,
                   help='largest value treated as a field offset')
    p.add_argument('--min-accesses', type=int, default=1, help='drop fields with fewer accesses')
    return p.parse_args()


def width_of(kind):
    base = kind.rstrip('*').strip()
    if kind.endswith('*'):
        return 8
    return WIDTHS.get(base)


def is_write(text, end):
    index = end
    while index < len(text) and text[index] in ' )':
        index += 1
    return index < len(text) and text[index] == '=' and text[index:index + 2] != '=='


def main():
    args = parse_args()
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.code, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    functions = []
    for match in FUNC_RE.finditer(text):
        if not match.group(3):
            continue
        try:
            functions.append((match.start(), int(match.group(3), 16)))
        except ValueError:
            continue
    positions = [p for p, _ in functions]
    base = (functions[0][1] >> 32) << 32 if functions else 0

    fields = {}
    indices = {}

    def touch(offset, kind, write, owner):
        entry = fields.setdefault(offset, {'reads': 0, 'writes': 0,
                                           'types': collections.Counter(),
                                           'funcs': set(), 'wfuncs': set()})
        entry['writes' if write else 'reads'] += 1
        if kind:
            entry['types'][kind] += 1
        if owner is not None:
            entry['funcs'].add(owner)
            if write:
                entry['wfuncs'].add(owner)

    def touch_index(offset, write):
        entry = indices.setdefault(offset, {'reads': 0, 'writes': 0})
        entry['writes' if write else 'reads'] += 1

    for match in TYPED_RE.finditer(text):
        token = match.group('offset')
        offset = int(token, 16) if token.lower().startswith('0x') else int(token)
        if offset >= args.max_offset:
            continue
        position = bisect.bisect_right(positions, match.start()) - 1
        owner = f'0x{functions[position][1] - base:x}' if position >= 0 else None
        touch(offset, match.group('type'), is_write(text, match.end()), owner)

    for match in ARROW_RE.finditer(text):
        offset = int(match.group('offset'), 16)
        if offset >= args.max_offset:
            continue
        position = bisect.bisect_right(positions, match.start()) - 1
        owner = f'0x{functions[position][1] - base:x}' if position >= 0 else None
        touch(offset, None, is_write(text, match.end()), owner)

    for match in INDEX_RE.finditer(text):
        token = match.group('offset')
        offset = int(token, 16) if token.lower().startswith('0x') else int(token)
        if offset >= args.max_offset:
            continue
        position = bisect.bisect_right(positions, match.start()) - 1
        owner = f'0x{functions[position][1] - base:x}' if position >= 0 else None
        touch_index(offset, is_write(text, match.end()))

    export = {}
    for offset, entry in sorted(fields.items()):
        total = entry['reads'] + entry['writes']
        if total < args.min_accesses:
            continue
        types = dict(entry['types'].most_common(4))
        width = next((width_of(k) for k, _ in entry['types'].most_common() if width_of(k)), None)
        export[f'0x{offset:x}'] = {
            'reads': entry['reads'],
            'writes': entry['writes'],
            'width': width,
            'types': types,
            'funcs': sorted(entry['funcs']),
            'writers': sorted(entry['wfuncs']),
        }

    index_export = {f'0x{offset:x}': entry for offset, entry in sorted(indices.items())}
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'fields': export, 'indices': index_export}, f, ensure_ascii=False)

    total = sum(entry['reads'] + entry['writes'] for entry in fields.values())
    indexed = sum(entry['reads'] + entry['writes'] for entry in indices.values())
    print(f'[+] fields={len(export)} typed_accesses={total} array_indices={indexed} '
          f'({len(index_export)} offsets) -> {args.out}')


if __name__ == '__main__':
    main()
