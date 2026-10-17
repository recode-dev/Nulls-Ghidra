#!/usr/bin/env python3
import argparse
import json
import os
import struct

from binary import detect_base

PTR_MASK = (1 << 48) - 1


def parse_args():
    p = argparse.ArgumentParser(description='Recover vtables as runs of pointers to known function starts')
    p.add_argument('--bin', required=True, help='Mach-O / ELF binary')
    p.add_argument('--index_dir', default='index_data', help='index directory holding functions.json')
    p.add_argument('--out', default='', help='output path, defaults to <index_dir>/vtables.json')
    p.add_argument('--min-slots', type=int, default=3, help='minimum run length treated as a vtable')
    return p.parse_args()


def load_functions(index_dir):
    path = os.path.join(index_dir, 'functions.json')
    if not os.path.exists(path):
        raise SystemExit(f'[-] {path} not found, run xrefs.py first')
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def scan(path, starts, base, min_slots):
    vtables = {}
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return vtables
    aligned = len(data) - (len(data) % 8)
    run = []
    run_start = 0
    for index, (value,) in enumerate(struct.iter_unpack('<Q', memoryview(data)[:aligned])):
        candidate = value & PTR_MASK
        if candidate >= base:
            candidate -= base
        if candidate in starts:
            if not run:
                run_start = index * 8
            run.append(candidate)
        else:
            if len(run) >= min_slots:
                vtables[f'0x{run_start:x}'] = {
                    'source': 'binary_scan',
                    'slots': len(run),
                    'methods': [f'0x{c:x}' for c in run],
                }
            run = []
    if len(run) >= min_slots:
        vtables[f'0x{run_start:x}'] = {
            'source': 'binary_scan',
            'slots': len(run),
            'methods': [f'0x{c:x}' for c in run],
        }
    return vtables


def main():
    args = parse_args()
    out = args.out or os.path.join(args.index_dir, 'vtables.json')
    functions = load_functions(args.index_dir)
    starts = {v['offset'] for v in functions.values()}
    base = detect_base(args.bin)
    vtables = scan(args.bin, starts, base, args.min_slots)

    with open(out, 'w', encoding='utf-8') as f:
        json.dump(vtables, f, ensure_ascii=False)

    longest = max((v['slots'] for v in vtables.values()), default=0)
    print(f'[+] base=0x{base:x} starts={len(starts)} vtables={len(vtables)} '
          f'max_slots={longest} -> {out}')


if __name__ == '__main__':
    main()
