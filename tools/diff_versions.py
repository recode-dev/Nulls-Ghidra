#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import urllib.request

FUNC_RE = re.compile(
    r'\n([A-Za-z0-9_* ]+)\s+((?:fcn|sym\.func)\.([0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n?\s*\{'
)
CALL_RE = re.compile(r'(?:fcn|sym\.func)\.([0-9a-fA-F]+)')
STR_RE = re.compile(r'"([^"]{2,200})"')
CONST_RE = re.compile(r'\b(0x[0-9a-fA-F]{4,16})\b')
FIELD_RE = re.compile(r'\+\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\b')
LOOP_RE = re.compile(r'\b(while|for|do)\b')
ENTRY_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_:]{1,80})\s*[:=]\s*(?:ptr\()?\s*[\'"]?(0x[0-9a-fA-F]+|\d+)')
DEFINE_RE = re.compile(r'#define\s+([A-Za-z_][A-Za-z0-9_:]{1,80})\s+(0x[0-9a-fA-F]+|\d+)')
PAIR_RE = re.compile(r'\[\s*"([A-Za-z_][A-Za-z0-9_:]{1,80})"\s*,\s*(0x[0-9a-fA-F]+|\d+)')
GETTER_TOKENS = ('get', 'is', 'has', 'can', 'should', 'width', 'height', 'radius', 'speed',
                 'index', 'count', 'team', 'owner', 'data', 'id', 'pos', 'x', 'y', 'z')
ACTIVE_TOKENS = ('update', 'tick', 'process', 'handle', 'render', 'draw', 'calculate', 'movement',
                 'activate', 'send', 'receive', 'load', 'save', 'init', 'enter', 'setup')


def parse_args():
    p = argparse.ArgumentParser(description='Resolve named offsets across Supercell builds')
    p.add_argument('--old_offsets', required=True, help='path or URL of the name -> offset map')
    p.add_argument('--new_index', required=True, help='index directory of the target build')
    p.add_argument('--old_index', default='', help='index directory of the reference build')
    p.add_argument('--new_code', default='', help='path to the target decompiled.c')
    p.add_argument('--old_code', default='', help='path or URL of the reference decompiled.c')
    p.add_argument('--out', default='offsets.js', help='JS export path')
    p.add_argument('--out_md', default='', help='markdown report path')
    p.add_argument('--threshold', type=float, default=0.60, help='minimum structural score')
    p.add_argument('--margin', type=float, default=0.05, help='required lead over the runner-up')
    p.add_argument('--max-lines-ratio', type=float, default=4.0, help='max line ratio for candidates')
    return p.parse_args()


def read_source(src, allow_inline=False):
    if not src:
        return None
    if src.startswith(('http://', 'https://')):
        req = urllib.request.Request(src, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    if os.path.exists(src):
        with open(src, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return src if allow_inline else None


def normalize_name(name):
    return re.sub(r'[^a-z0-9]', '', name.replace('::', '_').replace('__', '_').lower())


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


def extract_nodes(code, base):
    matches = list(FUNC_RE.finditer(code))
    nodes = {}
    for i, m in enumerate(matches):
        addr = int(m.group(3), 16)
        rva = addr - base if addr >= base else addr
        end = matches[i + 1].start() if i + 1 < len(matches) else len(code)
        body = code[m.start():end]
        calls = set()
        for c in CALL_RE.findall(body):
            try:
                c_addr = int(c, 16)
            except ValueError:
                continue
            c_rva = c_addr - base if c_addr >= base else c_addr
            if c_rva != rva:
                calls.add(c_rva)
        fields = set()
        consts = set()
        for token in FIELD_RE.findall(body):
            value = int(token, 16) if token.lower().startswith('0x') else int(token)
            (fields if value < 0x20000 else consts).add(value)
        nodes[rva] = {
            'lines': len(body.splitlines()),
            'strings': set(STR_RE.findall(body)),
            'fields': fields,
            'consts': consts,
            'calls': calls,
            'loops': len(LOOP_RE.findall(body)),
        }
    return nodes


def similarity(a, b):
    weights = (('strings', 4.0), ('consts', 2.0), ('fields', 3.0), ('calls', 2.0))
    gained = 0.0
    total = 0.0
    for key, weight in weights:
        left, right = a[key], b[key]
        if left or right:
            gained += weight * (len(left & right) / len(left | right))
            total += weight
    la, lb = max(1, a['lines']), max(1, b['lines'])
    gained += 1.0 - abs(la - lb) / max(la, lb)
    total += 1.0
    return gained / total if total else 0.0


def infer_kind(name):
    tokens = [t for t in re.split(r'[_:\s]+', name) if t]
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


def write_js(path, entries):
    lines = ['export const offsets = Object.freeze(', '    Object.fromEntries([']
    for name in sorted(entries):
        lines.append(f'        ["{name}", {entries[name]:#x}],')
    lines.append('    ]),')
    lines.append(');')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    formatter = shutil.which('clang-format')
    if formatter:
        subprocess.run([formatter, '-i', path], check=False)


def write_md(path, source_label, verified, layout, rejects, evidence):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'# Offset resolution against `{source_label}`\n\n')
        f.write('| status | count |\n|---|---|\n')
        f.write(f'| verified | {len(verified)} |\n')
        f.write(f'| layout | {len(layout)} |\n')
        f.write(f'| unresolved | {len(rejects)} |\n\n')
        f.write('## verified\n\n| name | offset | evidence |\n|---|---|---|\n')
        for name in sorted(verified):
            f.write(f'| {name} | 0x{verified[name]:x} | {evidence.get(name, "-")} |\n')
        f.write('\n## layout (build-independent struct offsets)\n\n```\n')
        for name in sorted(layout):
            f.write(f'{name} = 0x{layout[name]:x}\n')
        f.write('```\n\n## unresolved\n\n| name | seed | reason |\n|---|---|---|\n')
        for name in sorted(rejects):
            f.write(f'| {name} | 0x{rejects[name][0]:x} | {rejects[name][1]} |\n')


def main():
    args = parse_args()
    old_text = read_source(args.old_offsets, allow_inline=True)
    entries = parse_entries(old_text)
    if not entries:
        print('[-] no name -> offset pairs found in old_offsets')
        raise SystemExit(1)

    fn_path = os.path.join(args.new_index, 'functions.json')
    if not os.path.exists(fn_path):
        print(f'[-] {fn_path} not found')
        raise SystemExit(1)
    with open(fn_path, 'r', encoding='utf-8') as f:
        functions = json.load(f)
    if not functions:
        print('[-] functions.json is empty, nothing to resolve against')
        raise SystemExit(1)

    starts = sorted(int(k, 16) for k in functions)
    function_keys = set(starts)
    min_rva, max_rva = starts[0], starts[-1]
    used_offsets = set()
    for entry in functions.values():
        used_offsets.update(entry.get('field_offsets', []))

    names_evidence = {}
    for candidate in (os.path.join(args.new_index, '..', 'symbols_out', 'names.json'),
                      os.path.join('symbols_out', 'names.json')):
        if os.path.exists(candidate):
            with open(candidate, 'r', encoding='utf-8') as f:
                names_evidence = json.load(f)
            break
    by_name = {}
    for rva_key, data in names_evidence.items():
        by_name.setdefault(normalize_name(data['name']), []).append((rva_key, data))

    new_code_path = args.new_code or os.path.join(args.new_index, 'decompiled.c')
    if not os.path.exists(new_code_path) and os.path.exists('decompiled.c'):
        new_code_path = 'decompiled.c'
    new_nodes = {}
    if os.path.exists(new_code_path):
        new_nodes = extract_nodes(read_source(new_code_path), 0)
    old_code_path = args.old_code
    if not old_code_path and args.old_index:
        old_code_path = os.path.join(args.old_index, 'decompiled.c')
    old_nodes = extract_nodes(read_source(old_code_path), 0) if old_code_path else {}

    verified, layout, rejects, evidence = {}, {}, {}, {}
    claimed = {}

    for name, value in entries.items():
        if value <= 0:
            rejects[name] = (value, 'non-positive offset')
            continue
        if value in function_keys and value in used_offsets:
            rejects[name] = (value, 'ambiguous: both a function start and a used field offset')
            continue
        if value in used_offsets:
            layout[name] = value
            continue
        if value not in function_keys and not (min_rva <= value <= max_rva):
            rejects[name] = (value, 'no function start and no field usage at this offset')
            continue

        resolved = None
        why = ''

        if value in function_keys:
            resolved, why = value, 'same rva present in target build'

        if resolved is None:
            matches = by_name.get(normalize_name(name), [])
            matches = [(r, d) for r, d in matches if int(r, 16) in function_keys]
            if len(matches) == 1:
                resolved, why = int(matches[0][0], 16), f'symbol evidence ({matches[0][1]["source"]})'

        if resolved is None and old_nodes:
            old_node = old_nodes.get(value)
            if old_node:
                scored = []
                for rva, node in new_nodes.items():
                    if node['lines'] > old_node['lines'] * args.max_lines_ratio:
                        continue
                    if node['lines'] * args.max_lines_ratio < old_node['lines']:
                        continue
                    if not (old_node['calls'] & node['calls'] or old_node['fields'] & node['fields']
                            or old_node['strings'] & node['strings']):
                        continue
                    scored.append((similarity(old_node, node), rva))
                scored.sort(key=lambda pair: -pair[0])
                if scored:
                    best, best_rva = scored[0]
                    second = scored[1][0] if len(scored) > 1 else 0.0
                    if best >= args.threshold and best - second >= args.margin:
                        resolved, why = best_rva, f'structural match (score {best:.3f})'

        if resolved is None:
            reason = 'no reference index and no symbol evidence'
            if name in by_name:
                reason = 'symbol evidence is ambiguous'
            rejects[name] = (value, reason)
            continue

        kind = infer_kind(name)
        ok, detail = verify(kind, name, resolved, functions)
        if not ok:
            rejects[name] = (value, f'verification failed: {detail}')
            continue
        if resolved in claimed:
            rejects[name] = (value, f'address already used by {claimed[resolved]}')
            continue
        claimed[resolved] = name
        verified[name] = resolved
        evidence[name] = why

    write_js(args.out, {**layout, **verified})
    if args.out_md:
        write_md(args.out_md, os.path.basename(args.new_index.rstrip('/')) or args.new_index,
                 verified, layout, rejects, evidence)

    print(f'[+] requested={len(entries)} verified={len(verified)} layout={len(layout)} '
          f'unresolved={len(rejects)} -> {args.out}')


if __name__ == '__main__':
    main()
