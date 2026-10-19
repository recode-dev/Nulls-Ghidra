#!/usr/bin/env python3

import argparse
import json
import os


def parse_args():
    p = argparse.ArgumentParser(description='Rewrite a 32-bit arm index into a 64-bit address space for cross-arch matching')
    p.add_argument('--index_dir', required=True, help='32-bit index directory')
    p.add_argument('--out', required=True, help='output directory for the 64-bit view')
    p.add_argument('--base', type=lambda v: int(v, 0), default=0x100000000,
                   help='64-bit image base applied to every rva')
    p.add_argument('--inverse', action='store_true', help='map 64-bit addresses back to rvas')
    return p.parse_args()


def load(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save(path, payload):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)


def to64(addr, base):
    return base + (addr & 0xFFFFFFFF)


def to32(addr, base):
    return addr - base


def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)
    sign = -1 if args.inverse else 1

    def map_addr(value):
        if not isinstance(value, str) or not value.startswith('0x'):
            return value
        number = int(value, 16)
        if number > 0xFFFFFFFF and not args.inverse:
            return value
        mapped = to32(number, args.base) if args.inverse else to64(number, args.base)
        return f'0x{mapped:x}'

    functions = load(os.path.join(args.index_dir, 'functions.json'))
    out_functions = {}
    for key, entry in functions.items():
        item = dict(entry)
        if args.inverse:
            item['offset'] = to32(item['offset'], args.base)
            item['address'] = to32(item['address'], args.base)
        else:
            item['address'] = to64(item['offset'], args.base)
            item['address64'] = item['address']
            item['rva'] = item['offset']
            item['arch'] = 'arm32'
            item['ptr_size'] = 4
        item['calls'] = [map_addr(v) for v in item.get('calls') or []]
        item['callers'] = [map_addr(v) for v in item.get('callers') or []]
        item['unresolved_calls'] = [map_addr(v) for v in item.get('unresolved_calls') or []]
        item['data_refs'] = [map_addr(v) for v in item.get('data_refs') or []]
        item['call_sites'] = {map_addr(k): v for k, v in (item.get('call_sites') or {}).items()}
        out_functions[f'0x{item["offset"]:x}'] = item
    save(os.path.join(args.out, 'functions.json'), out_functions)

    vtables_path = os.path.join(args.index_dir, 'vtables.json')
    if os.path.exists(vtables_path):
        vtables = load(vtables_path)
        out_vtables = {}
        for key, entry in vtables.items():
            item = dict(entry)
            item['methods'] = [map_addr(v) for v in item.get('methods') or []]
            if not args.inverse:
                item['slot_size'] = 8
                item['bytes'] = len(item['methods']) * 8
                item['arch'] = 'arm32'
            out_vtables[map_addr(key)] = item
        save(os.path.join(args.out, 'vtables.json'), out_vtables)

    for name in ('classes.json', 'ctors.json', 'fields.json', 'fingerprints.json'):
        source = os.path.join(args.index_dir, name)
        if os.path.exists(source):
            save(os.path.join(args.out, name), load(source))

    print(f'[+] functions={len(out_functions)} base=0x{args.base:x} inverse={args.inverse} -> {args.out}')


if __name__ == '__main__':
    main()
