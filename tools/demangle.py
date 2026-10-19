#!/usr/bin/env python3

import argparse
import json
import subprocess


def parse_args():
    p = argparse.ArgumentParser(description='Write an address to demangled name table from symbols.json')
    p.add_argument('--symbols', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--grep', default='', help='only rows whose demangled name contains this text')
    return p.parse_args()


def main():
    args = parse_args()
    payload = json.load(open(args.symbols, 'r', encoding='utf-8'))
    symbols = payload.get('symbols') or payload
    names = list(symbols)
    proc = subprocess.run(['c++filt'], input='\n'.join(names), capture_output=True, text=True, check=True)
    demangled = proc.stdout.splitlines()
    rows = []
    for name, pretty in zip(names, demangled):
        if args.grep and args.grep.lower() not in pretty.lower():
            continue
        rows.append((int(symbols[name], 16), pretty, name))
    rows.sort()
    with open(args.out, 'w', encoding='utf-8') as f:
        for address, pretty, name in rows:
            f.write(f'0x{address:x}\t{pretty}\t{name}\n')
    print(f'[+] rows={len(rows)} -> {args.out}')


if __name__ == '__main__':
    main()
