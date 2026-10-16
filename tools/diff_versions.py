#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import urllib.request

IMAGE_BASE = 0x100000000
FN_RE = re.compile(r'\n[a-zA-Z0-9_* ]+\s+(fcn\.(10[0-9a-fA-F]+))\s*\([^)]*\)\s*\n?\s*\{')
CALL_RE = re.compile(r'fcn\.(10[0-9a-fA-F]+)')
STR_RE = re.compile(r'"([^"]{2,120})"')
CONST_RE = re.compile(r'\b(0x[0-9a-fA-F]{4,16})\b')
CHAIN_RE = re.compile(r'\*\((?:\w+\s*\*?\s*)*\([^)]+\+\s*(0x[0-9a-fA-F]+|\d+)\)')
LOOP_RE = re.compile(r'\b(while|for|do)\b')
TARGET_RES = [
    re.compile(r'#define\s+([a-zA-Z0-9_]+)\s+(0x[0-9a-fA-F]+)', re.MULTILINE),
    re.compile(r'[\'"]([a-zA-Z0-9_]+)[\'"]\s*:\s*[\'"]?(0x[0-9a-fA-F]+)', re.MULTILINE),
    re.compile(r'([a-zA-Z0-9_]+)\s*:\s*(?:ptr\()?\s*[\'"]?(0x[0-9a-fA-F]+)', re.MULTILINE),
    re.compile(r'([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)', re.MULTILINE),
]
FEATURES = (('strings', 4.0), ('consts', 3.0), ('field_chains', 2.5), ('calls', 2.0))


def parse_args():
    p = argparse.ArgumentParser(description='Structural RVA carry-over between two decompiled builds')
    p.add_argument('--old_offsets', required=True, help='path or URL of the previous name -> RVA map (C/JS/TS/JSON)')
    p.add_argument('--new_index', required=True, help='index directory of the target build')
    p.add_argument('--old_index', default='', help='index directory of the previous build (optional)')
    p.add_argument('--new_code', default='', help='path to the target decompiled.c')
    p.add_argument('--old_code', default='', help='path or URL of the previous decompiled.c (optional)')
    p.add_argument('--out', default='offsets.js', help='JS export path')
    p.add_argument('--out_md', default='', help='markdown report path')
    p.add_argument('--threshold', type=float, default=0.55, help='minimum structural score to accept a candidate')
    p.add_argument('--margin', type=float, default=0.05, help='required lead over the runner-up candidate')
    p.add_argument('--lines-ratio', dest='lines_ratio', type=float, default=3.0, help='max line-count ratio between candidates')
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


def parse_targets(text):
    targets = {}
    for pat in TARGET_RES:
        for m in pat.finditer(text):
            name = m.group(1).strip()
            value = int(m.group(2).strip(), 16)
            rva = value - IMAGE_BASE if value >= IMAGE_BASE else value
            if rva > 0 and name not in targets:
                targets[name] = rva
    return targets


def extract_nodes(code):
    matches = list(FN_RE.finditer(code))
    nodes = {}
    for i, m in enumerate(matches):
        addr = int(m.group(2), 16)
        rva = addr - IMAGE_BASE if addr >= IMAGE_BASE else addr
        end = matches[i + 1].start() if i + 1 < len(matches) else len(code)
        body = code[m.start():end]
        calls = {int(a, 16) - IMAGE_BASE for a in CALL_RE.findall(body) if int(a, 16) >= IMAGE_BASE}
        calls.discard(rva)
        nodes[rva] = {
            'lines': len(body.splitlines()),
            'strings': set(STR_RE.findall(body)),
            'consts': set(CONST_RE.findall(body)),
            'field_chains': set(CHAIN_RE.findall(body)),
            'calls': calls,
            'loops': len(LOOP_RE.findall(body)),
        }
    return nodes


def build_index(nodes, key):
    index = {}
    for rva, node in nodes.items():
        for token in node[key]:
            index.setdefault(token, set()).add(rva)
    return index


def similarity(a, b, stable_map=None):
    gained = 0.0
    total = 0.0
    for key, weight in FEATURES:
        left, right = a[key], b[key]
        if left or right:
            gained += weight * len(left & right) / len(left | right)
            total += weight
    
    if stable_map and (a['calls'] or b['calls']):
        mapped_calls = {stable_map[c] for c in a['calls'] if c in stable_map}
        if mapped_calls or b['calls']:
            inter = len(mapped_calls & b['calls'])
            union = len(mapped_calls | b['calls'])
            gained += 3.0 * (inter / union if union else 1.0)
            total += 3.0

    lines_a, lines_b = max(1, a['lines']), max(1, b['lines'])
    gained += 1.0 - abs(lines_a - lines_b) / max(lines_a, lines_b)
    total += 1.0
    return gained / total if total else 0.0


def score_candidates(old_rva, old_node, new_nodes, indexes, lines_ratio, stable_map=None):
    lines = old_node['lines']
    scored = []
    for rva in candidate_pool(old_node, indexes):
        node = new_nodes[rva]
        if node['lines'] > lines * lines_ratio or node['lines'] * lines_ratio < lines:
            continue
        score = similarity(old_node, node, stable_map)
        scored.append((score, abs(rva - old_rva), rva))
    scored.sort(key=lambda item: (-item[0], item[1], item[2]))
    return scored



def write_js(path, entries):
    lines = ['export const offsets = Object.freeze(', '    Object.fromEntries([']
    for name, rva in entries.items():
        lines.append(f'        ["{name}", 0x{rva:x}],')
    lines.append('    ]),')
    lines.append(');')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    formatter = shutil.which('clang-format')
    if formatter:
        subprocess.run([formatter, '-i', path], check=False)


def write_md(path, ver_target, stable, matched, unresolved, old_values):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'# Auto-Diffed Offsets ({ver_target})\n\n')
        f.write(f'- carried over unchanged: **{len(stable)}**\n')
        f.write(f'- resolved structurally: **{len(matched)}**\n')
        f.write(f'- unresolved: **{len(unresolved)}**\n\n')
        f.write('## Resolved\n\n```c\n')
        for name in sorted(stable):
            f.write(f'#define {name:<42} 0x{stable[name]:x}\n')
        for name in sorted(matched):
            f.write(f'#define {name:<42} 0x{matched[name]:x}\n')
        f.write('```\n\n## Unresolved\n\n')
        if unresolved:
            f.write('| name | old RVA |\n|---|---|\n')
            for name in sorted(unresolved):
                f.write(f'| {name} | 0x{old_values[name]:x} |\n')
        else:
            f.write('none\n')


def main():
    args = parse_args()
    old_text = read_source(args.old_offsets, allow_inline=True)
    targets = parse_targets(old_text)
    if not targets:
        print('[-] no name -> RVA pairs found in old_offsets')
        return

    new_code_path = args.new_code
    if not new_code_path:
        for cand in [os.path.join(args.new_index, 'decompiled.c'), 'decompiled.c']:
            if os.path.exists(cand):
                new_code_path = cand
                break
    new_text = read_source(new_code_path) if new_code_path else None
    if new_text is None:
        print(f'[-] decompiled code not found in {args.new_index} or root')
        raise SystemExit(1)
    if not new_text.strip():
        print(f'[-] decompiled code is empty: {new_code_path}')
        raise SystemExit(1)

    new_nodes = extract_nodes(new_text)
    old_code_path = args.old_code
    if not old_code_path and args.old_index:
        old_code_path = os.path.join(args.old_index, 'decompiled.c')
    old_text_code = read_source(old_code_path) if old_code_path else None
    old_nodes = extract_nodes(old_text_code) if old_text_code else {}

    indexes = {
        'calls': build_index(new_nodes, 'calls'),
        'strings': build_index(new_nodes, 'strings'),
        'consts': build_index(new_nodes, 'consts'),
    }

    stable = {}
    matched = {}
    unresolved = {}
    for name, old_rva in targets.items():
        if old_rva in new_nodes:
            stable[name] = old_rva
            continue
    
    # Резолвим остальное с учетом синергии (уже найденных функций)
    stable_rva_map = {v: v for v in stable.values()}
    for name, old_rva in targets.items():
        if name in stable:
            continue
        old_node = old_nodes.get(old_rva)
        if not old_node:
            unresolved[name] = old_rva
            continue
        scored = score_candidates(old_rva, old_node, new_nodes, indexes, args.lines_ratio, stable_rva_map)
        if not scored:
            unresolved[name] = old_rva
            continue
        best_score, _, best_rva = scored[0]
        runner_up = scored[1][0] if len(scored) > 1 else 0.0
        if best_score >= args.threshold and best_score - runner_up >= args.margin:
            matched[name] = best_rva
        else:
            unresolved[name] = old_rva

    entries = {}
    entries.update(stable)
    entries.update(matched)
    write_js(args.out, entries)

    if args.out_md:
        write_md(args.out_md, os.path.basename(args.new_index), stable, matched, unresolved, targets)

    print(f'[+] nodes new={len(new_nodes)} old={len(old_nodes)} requested={len(targets)} '
          f'stable={len(stable)} matched={len(matched)} unresolved={len(unresolved)} -> {args.out}')


if __name__ == '__main__':
    main()
