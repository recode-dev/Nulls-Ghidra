#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diff_versions as resolver


def parse_args():
    p = argparse.ArgumentParser(description='Re-verify a resolved offset map against an index')
    p.add_argument('--resolved', required=True, help='resolved map (JS/TS/JSON/C)')
    p.add_argument('--index_dir', default='index_data', help='index directory of the checked build')
    p.add_argument('--out', default='', help='optional markdown report path')
    return p.parse_args()


def main():
    args = parse_args()
    text = resolver.read_source(args.resolved)
    if text is None:
        print(f'[-] cannot read {args.resolved}')
        raise SystemExit(1)
    entries = resolver.parse_entries(text)

    fn_path = os.path.join(args.index_dir, 'functions.json')
    if not os.path.exists(fn_path):
        print(f'[-] {fn_path} not found')
        raise SystemExit(1)
    with open(fn_path, 'r', encoding='utf-8') as f:
        functions = json.load(f)
    keys = set(int(k, 16) for k in functions)
    used = set()
    for entry in functions.values():
        used.update(entry.get('field_offsets', []))

    verified, layout, failed = [], [], []
    seen = {}
    for name, value in sorted(entries.items()):
        in_keys = value in keys
        in_used = value in used
        if in_keys and in_used:
            failed.append((name, value, 'ambiguous: both a function start and a field offset'))
            continue
        if in_keys:
            kind = resolver.infer_kind(name)
            ok, detail = resolver.verify(kind, name, value, functions)
            if not ok:
                failed.append((name, value, detail))
                continue
            if value in seen:
                failed.append((name, value, f'duplicate of {seen[value]}'))
                continue
            seen[value] = name
            verified.append((name, value, detail))
        elif in_used:
            layout.append((name, value))
        else:
            failed.append((name, value, 'not a function start and not a used field offset'))

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(f'# verification of `{os.path.basename(args.resolved)}`\n\n')
            f.write(f'- functions verified: **{len(verified)}**\n')
            f.write(f'- layout offsets: **{len(layout)}**\n')
            f.write(f'- failed: **{len(failed)}**\n\n')
            if failed:
                f.write('## failed\n\n| name | value | reason |\n|---|---|---|\n')
                for name, value, reason in failed:
                    f.write(f'| {name} | 0x{value:x} | {reason} |\n')

    print(f'[+] verified={len(verified)} layout={len(layout)} failed={len(failed)}')
    for name, value, reason in failed[:10]:
        print(f'    ! {name} 0x{value:x} {reason}')


if __name__ == '__main__':
    main()
