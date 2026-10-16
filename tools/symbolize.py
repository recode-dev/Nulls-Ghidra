#!/usr/bin/env python3
import argparse
import json
import os
import re

CPP_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{1,40}::[A-Za-z0-9_:~]{1,60})')
OBJC_RE = re.compile(r'[+-]\[([A-Za-z_][A-Za-z0-9_]{1,40})\s+([A-Za-z0-9_:]{1,60})\]')
FILE_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{2,40})\.(?:cpp|cc|cxx|mm|hpp)\b')
FUNC_TOKEN_RE = re.compile(r'\b([a-z][A-Za-z0-9_]{6,40})\s*(?:called|failed|invalid|error|assert)',
                           re.IGNORECASE)

NOISE = {
    'std', 'this', 'void', 'int', 'char', 'bool', 'float', 'double', 'unsigned', 'signed',
    'const', 'class', 'struct', 'namespace', 'public', 'private', 'protected', 'virtual',
    'http', 'https', 'file', 'string',
}


def parse_args():
    p = argparse.ArgumentParser(description='Recover function names from a stripped Supercell dump')
    p.add_argument('--index_dir', default='index_data')
    p.add_argument('--out_dir', default='symbols_out')
    p.add_argument('--max-owners', type=int, default=2,
                   help='a string naming a symbol must not appear in more functions than this')
    return p.parse_args()


def candidate_names(text):
    names = []
    for m in CPP_RE.finditer(text):
        owner, _, method = m.group(1).partition('::')
        if owner in NOISE or not method:
            continue
        names.append((m.group(1), 'cpp'))
    for m in OBJC_RE.finditer(text):
        if m.group(1) in NOISE:
            continue
        names.append((f'{m.group(1)}.{m.group(2)}', 'objc'))
    for m in FILE_RE.finditer(text):
        if m.group(1) in NOISE:
            continue
        names.append((m.group(1), 'file'))
    for m in FUNC_TOKEN_RE.finditer(text):
        names.append((m.group(1), 'log'))
    return names


def main():
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    xref_path = os.path.join(args.index_dir, 'strings_xref.json')
    fn_path = os.path.join(args.index_dir, 'functions.json')
    fp_path = os.path.join(args.index_dir, 'fingerprints.json')
    if not (os.path.exists(xref_path) and os.path.exists(fn_path)):
        print('[-] index_data/functions.json + strings_xref.json required')
        return

    with open(xref_path, 'r', encoding='utf-8') as f:
        xref = json.load(f)
    with open(fn_path, 'r', encoding='utf-8') as f:
        functions = json.load(f)
    fingerprints = {}
    if os.path.exists(fp_path):
        with open(fp_path, 'r', encoding='utf-8') as f:
            fingerprints = json.load(f)

    evidence = {}
    taken = {}
    for text, owners in xref.items():
        if len(owners) > args.max_owners:
            continue
        for name, source in candidate_names(text):
            for owner in owners:
                if owner not in functions:
                    continue
                current = evidence.get(owner)
                rank = {'cpp': 3, 'objc': 3, 'file': 2, 'log': 1}[source]
                if current and current['rank'] >= rank:
                    continue
                evidence[owner] = {'name': name, 'source': source, 'rank': rank, 'text': text[:120]}

    symbols = {}
    for rva in sorted(evidence, key=lambda k: int(k, 16)):
        entry = evidence[rva]
        name = re.sub(r'[^A-Za-z0-9_]', '_', entry['name']).strip('_')
        name = re.sub(r'_+', '_', name)
        if not name:
            continue
        if name in taken:
            if taken[name] != rva:
                continue
            continue
        taken[name] = rva
        symbols[rva] = name

    with open(os.path.join(args.out_dir, 'symbols.json'), 'w', encoding='utf-8') as f:
        json.dump(symbols, f, indent=2, sort_keys=True)
    with open(os.path.join(args.out_dir, 'names.json'), 'w', encoding='utf-8') as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
    with open(os.path.join(args.out_dir, 'symbols.r2'), 'w', encoding='utf-8') as f:
        for rva, name in sorted(symbols.items(), key=lambda kv: int(kv[0], 16)):
            f.write(f'f sym.{name} @ {int(rva, 16):#x}\n')

    by_source = {}
    for entry in evidence.values():
        by_source[entry['source']] = by_source.get(entry['source'], 0) + 1
    print(f'[+] symbols={len(symbols)} evidence={len(evidence)} sources={by_source}')


if __name__ == '__main__':
    main()
