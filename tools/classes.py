#!/usr/bin/env python3

import argparse
import json
import os


def parse_args():
    p = argparse.ArgumentParser(description='Merge vtables, field layouts and constructors into classes')
    p.add_argument('--index_dir', default='index_data', help='index directory')
    p.add_argument('--out', default='', help='output classes JSON path')
    p.add_argument('--max-offset', type=lambda v: int(v, 0), default=0x20000,
                   help='largest value treated as a struct field offset')
    p.add_argument('--field', default='', help='print classes whose layout contains this field offset (hex)')
    return p.parse_args()


def load(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def offset_arg(text):
    return int(text[2:] if text.lower().startswith('0x') else text, 16)


def field_layout(fields, methods, max_offset):
    layout = {}
    for offset, entry in fields.items():
        value = int(offset, 16)
        if value >= max_offset:
            continue
        shared = set(entry.get('funcs') or ()) & methods
        if not shared:
            continue
        layout[value] = {
            'offset': offset,
            'width': entry.get('width'),
            'reads': entry.get('reads', 0),
            'writes': entry.get('writes', 0),
            'types': entry.get('types') or {},
            'funcs': sorted(shared),
            'writers': sorted(shared & set(entry.get('writers') or [])),
        }
    return [layout[key] for key in sorted(layout)]


def class_entry(group, fields, constructors, max_offset):
    primary = max(group, key=lambda item: item[1].get('slots', 0))
    ordered = [primary] + [item for item in group if item is not primary]
    methods = []
    for _address, table in ordered:
        for method in table.get('methods', []):
            if method not in methods:
                methods.append(method)
    layout = field_layout(fields, set(methods) | set(constructors), max_offset)
    header = primary[1].get('header') or {}
    entry = {
        'vtable': primary[0],
        'methods_count': len(methods),
        'methods': methods,
        'fields': [field['offset'] for field in layout],
        'field_layout': layout,
        'aliases': sum(len(table.get('aliases', [])) for _address, table in group),
    }
    if len(group) > 1:
        entry['vtables'] = [address for address, _table in group]
    if header.get('class_name'):
        entry['typeinfo'] = header.get('typeinfo_name')
    if primary[1].get('extends'):
        entry['extends'] = primary[1]['extends']
    if primary[1].get('roles'):
        entry['roles'] = primary[1]['roles']
    if constructors:
        entry['constructors'] = constructors
    if layout:
        entry['size'] = max(int(field['offset'], 16) + (field['width'] or 8) for field in layout)
    return entry


def main():
    args = parse_args()
    out_path = args.out or os.path.join(args.index_dir, 'classes.json')
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)

    vtables = load(os.path.join(args.index_dir, 'vtables.json'), None)
    if vtables is None:
        raise SystemExit(f'[-] {os.path.join(args.index_dir, "vtables.json")} not found')
    fields = load(os.path.join(args.index_dir, 'fields.json'), {}).get('fields', {})
    ctors = load(os.path.join(args.index_dir, 'ctors.json'), {})
    constructors = {address: entry.get('funcs') or []
                    for address, entry in ctors.items() if entry.get('store')}

    grouped = {}
    for address, table in vtables.items():
        if table.get('alias_of') or table.get('kind', 'vtable') != 'vtable':
            continue
        header = table.get('header') or {}
        name = header.get('class_name') or f'VTableClass_{address}'
        grouped.setdefault(name, []).append((address, table))

    classes = {}
    for name, group in sorted(grouped.items()):
        owners = sorted({owner for address, _table in group
                         for owner in constructors.get(address, [])})
        classes[name] = class_entry(group, fields, owners, args.max_offset)

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(classes, f, indent=2)

    if args.field:
        needle = f'0x{offset_arg(args.field):x}'
        rows = [(name, entry, field) for name, entry in classes.items()
                for field in entry['field_layout'] if field['offset'] == needle]
        print(f'[+] field {needle} -> {len(rows)} classes')
        for name, entry, field in sorted(rows):
            print(f'{name}  vtable={entry["vtable"]}  reads={field["reads"]} writes={field["writes"]} '
                  f'width={field["width"]}')
            print(f'  funcs {" ".join(field["funcs"])}')
            print(f'  writers {" ".join(field["writers"]) or "-"}')

    with_fields = sum(1 for entry in classes.values() if entry['fields'])
    with_ctors = sum(1 for entry in classes.values() if entry.get('constructors'))
    print(f'[+] classes={len(classes)} with_fields={with_fields} with_ctors={with_ctors} '
          f'fields={len(fields)} ctors={len(constructors)} -> {out_path}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit(f'[-] {exc}')
