#!/usr/bin/env python3

import argparse
import json
import os
import re

COMPONENT = re.compile(r'^_ZN((?:\d+[A-Za-z0-9_$.]+)+)E')
SIMPLE = re.compile(r'^_Z(\d+)([A-Za-z0-9_$.]+)')
SPECIAL = {'C1': '{class}', 'C2': '{class}', 'C3': '{class}', 'D0': '~{class}', 'D1': '~{class}', 'D2': '~{class}'}


def parse_args():
    p = argparse.ArgumentParser(description='Find mangled symbols by class and method')
    p.add_argument('--symbols', required=True, help='symbols.json produced by imports.py')
    p.add_argument('--class', dest='klass', default='', help='class or namespace component to match')
    p.add_argument('--method', default='', help='method name to match')
    p.add_argument('--limit', type=int, default=20)
    return p.parse_args()


def split(symbol):
    if symbol.startswith('_ZNK'):
        index = 4
    elif symbol.startswith('_ZN'):
        index = 3
    else:
        return None
    parts = []
    while index < len(symbol) and symbol[index].isdigit():
        end = index
        while end < len(symbol) and symbol[end].isdigit():
            end += 1
        size = int(symbol[index:end])
        part = symbol[end:end + size]
        if len(part) != size:
            return None
        parts.append(part)
        index = end + size
    if index < len(symbol):
        tail = symbol[index]
        if tail in 'CD' and index + 1 < len(symbol) and symbol[index + 1].isdigit():
            parts.append(symbol[index:index + 2])
    return parts if len(parts) >= 2 else None


def main():
    args = parse_args()
    with open(args.symbols, 'r', encoding='utf-8') as f:
        payload = json.load(f)
    symbols = payload.get('symbols') or payload

    rows = []
    for name, value in symbols.items():
        parts = split(name)
        if not parts:
            continue
        klass = parts[-2]
        method = parts[-1]
        label = SPECIAL.get(method, method).format(**{'class': klass})
        full = '::'.join(parts[:-1] + [label])
        if args.klass and args.klass.lower() not in full.lower():
            continue
        if args.method and args.method.lower() not in label.lower():
            continue
        rows.append((int(value, 16), full, name))

    rows.sort()
    for address, full, mangled in rows[:args.limit]:
        print(f'0x{address:x}  {full}  {mangled}')
    print(f'[+] matches={len(rows)}')


if __name__ == '__main__':
    main()
