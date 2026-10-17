#!/usr/bin/env python3
import argparse
import json
import os
import re
import urllib.request

ENTRY_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_:]{1,80})\s*[:=]\s*(?:ptr\()?\s*[\'"]?(0x[0-9a-fA-F]+|\d+)')
DEFINE_RE = re.compile(r'#define\s+([A-Za-z_][A-Za-z0-9_:]{1,80})\s+(0x[0-9a-fA-F]+|\d+)')
PAIR_RE = re.compile(r'\[\s*"([A-Za-z_][A-Za-z0-9_:]{1,80})"\s*,\s*(0x[0-9a-fA-F]+|\d+)')
GETTER_TOKENS = ('get', 'is', 'has', 'can', 'should', 'width', 'height', 'radius', 'speed',
                 'index', 'count', 'team', 'owner', 'data', 'id', 'pos', 'x', 'y', 'z')
ACTIVE_TOKENS = ('update', 'tick', 'process', 'handle', 'render', 'draw', 'calculate', 'movement',
                 'activate', 'send', 'receive', 'load', 'save', 'init', 'enter', 'setup')


def parse_args():
    p = argparse.ArgumentParser(description='Re-verify a resolved offset map against an index')
    p.add_argument('--resolved', required=True, help='resolved map (JS/TS/JSON/C)')
    p.add_argument('--index_dir', default='index_data', help='index directory of the checked build')
    p.add_argument('--out', default='', help='optional markdown report path')
    return p.parse_args()


def read_source(src):
    if not src:
        return None
    if src.startswith(('http://', 'https://')):
        req = urllib.request.Request(src, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    if os.path.exists(src):
        with open(src, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return src


def parse_entries(text):
    entries = {}
    for pat in (DEFINE_RE, PAIR_RE, ENTRY_RE):
        for m in pat.finditer(text):
            name = m.group(1)
            token = m.group(2)
            value = int(token, 16) if token.lower().startswith('0x') else int(token)
            if name not in entries:
                entries[name] = value
    return entries


def infer_kind(name):
    tokens = [t for t in re.split(r'[_,:\s]+', name) if t]
    lowered = [t.lower() for t in tokens]
    if len(tokens) >= 2 and lowered[-1] == lowered[0]:
        return 'constructor'
    if any(token.endswith('ctor') or token in ('new', 'create', 'init', 'construct') for token in lowered):
        return 'constructor'
    if any(token in GETTER_TOKENS for token in lowered):
        return 'getter'
    if any(token in ACTIVE_TOKENS for token in lowered):
        return 'action'
    return 'unknown'


def verify(kind, name, rva, functions):
    entry = functions.get(f'0x{rva:x}')
    if entry is None:
        entry = functions.get(hex(rva))
    if not entry:
        return False, 'not-a-function-start'
    lines = entry.get('lines', 0)
    calls = entry.get('calls', [])
    fields = entry.get('field_offsets', [])
    vtable = entry.get('vtables_assigned', [])
    if kind == 'getter':
        if lines > 60:
            return False, f'getter-like name but {lines} lines'
        if not fields and not calls:
            return False, 'getter-like name but no field access'
    if kind == 'action' and not calls:
        return False, 'action-like name but no calls'
    if kind == 'constructor' and not vtable and not calls:
        return False, 'constructor-like name but no vtable/calls'
    return True, 'structural-check-passed'


def main():
    args = parse_args()
    text = read_source(args.resolved)
    if text is None:
        print(f'[-] cannot read {args.resolved}')
        raise SystemExit(1)
    entries = parse_entries(text)

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
            kind = infer_kind(name)
            ok, detail = verify(kind, name, value, functions)
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
