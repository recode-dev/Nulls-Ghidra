#!/usr/bin/env python3
import argparse
import json
import os
import re
import urllib.request

FIELD_LIMIT = 0x20000
PREFIXES = ('RVA_', 'RCL_', 'OFF_', 'ADDR_', 'OPT_', 'OFFSET_')
SUFFIXES = ('_OFF', '_ADDR', '_PTR', '_RVA')
GENERIC = {'rva', 'rcl', 'off', 'addr', 'offset', 'ptr', 'get', 'set', 'is', 'client', 'server', 'data'}


def parse_args():
    p = argparse.ArgumentParser(description='Bridge a named offsets map onto a build using a same-build map plus binary validation')
    p.add_argument('--map', required=True, dest='map_path', help='map to resolve (names of any build)')
    p.add_argument('--source', required=True, action='append', help='same-build map(s) providing real addresses; repeatable')
    p.add_argument('--index_dir', required=True)
    p.add_argument('--binary', default='')
    p.add_argument('--code', default='')
    p.add_argument('--out', default='')
    p.add_argument('--report', default='')
    return p.parse_args()


def read_text(src):
    if src.startswith(('http://', 'https://')):
        req = urllib.request.Request(src, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    if os.path.exists(src):
        with open(src, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return src


def parse_map(text):
    out = {}
    for m in re.finditer(r'#define\s+([A-Za-z0-9_]+)\s+(0x[0-9a-fA-F]+)', text):
        out.setdefault(m.group(1), int(m.group(2), 16))
    for m in re.finditer(r'["\']?([A-Za-z0-9_:]{2,80})["\']?\s*[=:]\s*(0x[0-9a-fA-F]+)', text):
        out.setdefault(m.group(1), int(m.group(2), 16))
    return out


def canonical(name):
    n = name
    for prefix in PREFIXES:
        if n.upper().startswith(prefix):
            n = n[len(prefix):]
    for suffix in SUFFIXES:
        if n.upper().endswith(suffix):
            n = n[:-len(suffix)]
    return re.sub(r'[^a-z0-9]', '', n.lower())


def tokens(name):
    parts = [p for p in canonical(name).split('_') if p and p not in GENERIC]
    return set(parts)


def jaccard(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def load_index(index_dir):
    funcs = json.load(open(os.path.join(index_dir, 'functions.json'), encoding='utf-8'))
    fp_path = os.path.join(index_dir, 'fingerprints.json')
    fps = json.load(open(fp_path, encoding='utf-8')) if os.path.exists(fp_path) else {}
    return funcs, fps


def main():
    args = parse_args()
    target = parse_map(read_text(args.map_path))
    sources = {}
    for src in args.source:
        for name, value in parse_map(read_text(src)).items():
            sources.setdefault(name, value)
    sources = {k: v for k, v in sources.items() if v}

    funcs, fps = load_index(args.index_dir)
    starts = {int(k, 16) for k in funcs}
    code_starts = starts
    field_access = {}
    for off, meta in fps.items():
        for f in meta.get('fields_accessed', []):
            field_access.setdefault(f, set()).add(int(off, 16))
        rf = meta.get('ret_field')
        if rf:
            field_access.setdefault(rf, set()).add(int(off, 16))

    by_canon = {}
    by_token = {}
    for name, value in sources.items():
        by_canon.setdefault(canonical(name), []).append((name, value))
        for tok in tokens(name):
            by_token.setdefault(tok, []).append((name, value))

    resolved, candidate, unresolved = {}, {}, {}
    method = {}
    for name, value in target.items():
        is_field = value < FIELD_LIMIT
        pick = None
        how = ''
        exact = by_canon.get(canonical(name))
        if exact:
            pick, how = exact[0], 'canonical name'
        else:
            toks = tokens(name)
            best = (0.0, None)
            for tok in toks:
                for cand_name, cand_value in by_token.get(tok, []):
                    score = jaccard(toks, tokens(cand_name))
                    if score > best[0]:
                        best = (score, (cand_name, cand_value))
            if best[0] >= 0.5:
                pick, how = best[1], f'token Jaccard {best[0]:.2f}'
            elif is_field:
                same = [kv for kv in sources.items() if kv[1] == value and jaccard(toks, tokens(kv[0])) >= 0.34]
                if same:
                    pick, how = same[0], 'equal struct offset + token overlap'
        if pick is None:
            unresolved[name] = value
            continue
        src_name, src_value = pick
        if src_value < FIELD_LIMIT:
            ok = bool(field_access.get(hex(src_value)))
            why = f'field 0x{src_value:x} has {len(field_access.get(hex(src_value), ()))} accessor(s) in the binary'
        else:
            ok = src_value in code_starts
            why = f'0x{src_value:x} is a function start in the index' if ok else 'address is not a function start'
        if ok:
            resolved[name] = src_value
            method[name] = f'{how} -> {src_name}: {why}'
        else:
            candidate[name] = src_value
            method[name] = f'{how} -> {src_name}: {why}'

    lines = ['# Offset bridge', '',
             f'- names to resolve: {len(target)}',
             f'- addresses available in same-build sources: {len(sources)}',
             f'- resolved and validated against the binary: {len(resolved)}',
             f'- bridged but not confirmed by the binary: {len(candidate)}',
             f'- no counterpart in the sources: {len(unresolved)}', '',
             '| name | result | validation |', '|---|---|---|']
    for name in sorted(resolved):
        lines.append(f'| {name} | 0x{resolved[name]:x} | {method[name]} |')
    for name in sorted(candidate):
        lines.append(f'| {name} | 0x{candidate[name]:x} | CANDIDATE — {method[name]} |')
    for name in sorted(unresolved):
        lines.append(f'| {name} | - | no counterpart in the same-build sources |')
    report = '\n'.join(lines)
    print('\n'.join(lines[:8]))
    if args.report:
        open(args.report, 'w', encoding='utf-8').write(report + '\n')
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write('export const offsets = {\n')
            for name in sorted(resolved):
                f.write(f'    "{name}": 0x{resolved[name]:x},\n')
            f.write('};\n')
    print(f'\nresolved {len(resolved)}/{len(target)}')


if __name__ == '__main__':
    main()
