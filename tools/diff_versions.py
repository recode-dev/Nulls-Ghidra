#!/usr/bin/env python3
import json
import os
import re
import sys
import argparse
import urllib.request

def parse_args():
    p = argparse.ArgumentParser(description="Binary Differ & Symbol Resolver for Frida JS & C/C++")
    p.add_argument('--old_offsets', required=True, help="Header file, JS file, or key-value list of old offsets/macros")
    p.add_argument('--old_index', default='', help="Path to old version index directory")
    p.add_argument('--new_index', required=True, help="Path to new version index directory or dump folder")
    p.add_argument('--new_code', default='', help="Path to decompiled.c for AST/VTable resolution")
    p.add_argument('--out', default='offsets.js', help="Output file path (.js, .h, .json, .md)")
    p.add_argument('--format', default='auto', choices=['auto', 'js', 'header', 'json', 'md'], help="Output format")
    p.add_argument('--threshold', type=float, default=0.25, help="Confidence threshold")
    return p.parse_args()

def fetch_or_read(path_or_url):
    if path_or_url.startswith('http://') or path_or_url.startswith('https://'):
        req = urllib.request.Request(path_or_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    if os.path.exists(path_or_url):
        with open(path_or_url, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return path_or_url

def parse_any_offsets(text):
    offsets = {}
    pats = [
        re.compile(r'#define\s+([a-zA-Z0-9_]+)\s+(0x[0-9a-fA-F]+)', re.MULTILINE),
        re.compile(r'([a-zA-Z0-9_]+)\s*[:=]\s*(?:ptr\()?\s*[\'"]?(0x[0-9a-fA-F]+)[\'"]?', re.MULTILINE),
        re.compile(r'[\'"]([a-zA-Z0-9_]+)[\'"]\s*:\s*[\'"]?(0x[0-9a-fA-F]+)[\'"]?', re.MULTILINE),
        re.compile(r'([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)', re.MULTILINE)
    ]
    for pat in pats:
        for m in pat.finditer(text):
            k = m.group(1).strip()
            v = m.group(2).strip().lower()
            if k not in offsets:
                offsets[k] = v
    return offsets

def jaccard(set_a, set_b):
    if not set_a or not set_b:
        return 0.0
    s_a = set(set_a)
    s_b = set(set_b)
    inter = len(s_a.intersection(s_b))
    union = len(s_a.union(s_b))
    return inter / union if union > 0 else 0.0

def calculate_match_score(old_meta, old_fp, new_meta, new_fp):
    score = 0.0
    weight_total = 0.0

    old_strs = set(old_meta.get('strings', []))
    new_strs = set(new_meta.get('strings', []))
    if old_strs and new_strs:
        str_j = jaccard(old_strs, new_strs)
        score += str_j * 4.5
        weight_total += 4.5

    old_ret = old_fp.get('ret_field')
    new_ret = new_fp.get('ret_field')
    if old_ret and new_ret:
        if str(old_ret).lower() == str(new_ret).lower():
            score += 3.5
        weight_total += 3.5

    old_consts = old_fp.get('math_constants', [])
    new_consts = new_fp.get('math_constants', [])
    if old_consts and new_consts:
        score += jaccard(old_consts, new_consts) * 3.0
        weight_total += 3.0

    old_flds = old_fp.get('fields_accessed', [])
    new_flds = new_fp.get('fields_accessed', [])
    if old_flds and new_flds:
        score += jaccard(old_flds, new_flds) * 2.5
        weight_total += 2.5

    if old_fp.get('topology_role') and new_fp.get('topology_role'):
        if old_fp['topology_role'] == new_fp['topology_role']:
            score += 2.0
        weight_total += 2.0

    old_l = max(1, old_fp.get('lines', 1))
    new_l = max(1, new_fp.get('lines', 1))
    line_sim = 1.0 - min(1.0, abs(old_l - new_l) / max(old_l, new_l))
    score += line_sim * 1.0
    weight_total += 1.0

    return score / weight_total if weight_total > 0 else 0.0

def scan_decompiled_fast(code_path):
    ast_info = {
        "globals": {},
        "vtables": {},
        "getters": {},
        "string_ctors": [],
        "named_heuristics": {}
    }
    if not os.path.exists(code_path):
        return ast_info

    current_fn = None
    with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'fcn.10' in line and '(' in line:
                m = re.search(r'fcn\.(10[0-9a-fA-F]+)', line)
                if m:
                    current_fn = hex(int(m.group(1), 16) - 0x100000000)
            elif current_fn:
                if 'return *(uint *)0x101125ea0' in line:
                    ast_info["named_heuristics"]["Screen__getWidth"] = current_fn
                    ast_info["named_heuristics"]["Screen_widthGlobal"] = "0x1125ea0"
                elif 'return *(uint *)0x101125ea4' in line:
                    ast_info["named_heuristics"]["Screen__getHeight"] = current_fn
                    ast_info["named_heuristics"]["Screen_heightGlobal"] = "0x1125ea4"
                elif 'return *(uchar *)0x101125eac' in line:
                    ast_info["named_heuristics"]["Screen__getDpiClass"] = current_fn
                elif '*(ulong *)arg1 = 0x100ff3b98' in line:
                    ast_info["named_heuristics"]["VTABLE_CHARACTER_DATA"] = "0xff3b98"
                elif '*(ulong *)arg1 = 0x100ff3b18' in line:
                    ast_info["named_heuristics"]["VTABLE_PROJECTILE_DATA"] = "0xff3b18"
                elif 'return *(ulong *)(arg1 + 0x30);' in line or 'return *(int *)(arg1 + 0x30);' in line:
                    if "LogicGameObjectClient_getX" not in ast_info["named_heuristics"]:
                        ast_info["named_heuristics"]["LogicGameObjectClient_getX"] = current_fn
                elif 'return *(ulong *)(arg1 + 0x34);' in line or 'return *(int *)(arg1 + 0x34);' in line:
                    if "LogicGameObjectClient_getY" not in ast_info["named_heuristics"]:
                        ast_info["named_heuristics"]["LogicGameObjectClient_getY"] = current_fn

    return ast_info

def format_output(results, fmt, out_path):
    if fmt == 'auto':
        if out_path.endswith('.js') or out_path.endswith('.ts'):
            fmt = 'js'
        elif out_path.endswith('.h') or out_path.endswith('.hpp') or out_path.endswith('.c'):
            fmt = 'header'
        elif out_path.endswith('.json'):
            fmt = 'json'
        else:
            fmt = 'md'

    lines = []
    if fmt == 'js':
        lines.append("// Auto-generated by Nulls-Ghidra Differ")
        lines.append("export const offsets = Object.freeze({")
        for k, v in sorted(results.items()):
            val_formatted = f"{v}" if str(v).startswith("0x") else f"0x{v}"
            lines.append(f"    {k}: {val_formatted},")
        lines.append("});\n")
        lines.append("export default offsets;")
    elif fmt == 'header':
        lines.append("// Auto-generated by Nulls-Ghidra Differ")
        lines.append("#pragma once\n")
        for k, v in sorted(results.items()):
            lines.append(f"#define {k:<45} {v}ULL")
    elif fmt == 'json':
        return json.dumps(results, indent=2)
    else:
        lines.append("# Auto-Diffed Offsets\n\n```js\nexport const offsets = Object.freeze({")
        for k, v in sorted(results.items()):
            lines.append(f"    {k}: {v},")
        lines.append("});\n```")

    return "\n".join(lines)

def main():
    args = parse_args()

    content = fetch_or_read(args.old_offsets)
    old_offs = parse_any_offsets(content)

    new_fn_p = os.path.join(args.new_index, 'functions.json') if os.path.isdir(args.new_index) else args.new_index
    new_fp_p = os.path.join(args.new_index, 'fingerprints.json') if os.path.isdir(args.new_index) else ''
    
    if not os.path.exists(new_fn_p) and os.path.exists(os.path.join(args.new_index, 'index_data', 'functions.json')):
        new_fn_p = os.path.join(args.new_index, 'index_data', 'functions.json')
        new_fp_p = os.path.join(args.new_index, 'index_data', 'fingerprints.json')

    new_fn = json.load(open(new_fn_p)) if os.path.exists(new_fn_p) else {}
    new_fp = json.load(open(new_fp_p)) if os.path.exists(new_fp_p) else {}

    decomp_path = args.new_code or os.path.join(args.new_index, 'decompiled.c')
    ast_info = scan_decompiled_fast(decomp_path)

    old_fn = {}
    old_fp = {}
    if args.old_index:
        old_fn_p = os.path.join(args.old_index, 'functions.json') if os.path.isdir(args.old_index) else args.old_index
        old_fp_p = os.path.join(args.old_index, 'fingerprints.json') if os.path.isdir(args.old_index) else ''
        if os.path.exists(old_fn_p):
            old_fn = json.load(open(old_fn_p))
        if os.path.exists(old_fp_p):
            old_fp = json.load(open(old_fp_p))

    results = {}

    for name, old_addr in old_offs.items():
        best_cand = None
        best_score = 0.0

        # Direct Heuristics Map
        if name in ast_info.get("named_heuristics", {}):
            best_cand = ast_info["named_heuristics"][name]
            best_score = 1.0

        # Exact match if old_index not provided and address already valid in new index
        if not best_cand and not old_fn and old_addr in new_fn:
            best_cand = old_addr
            best_score = 1.0

        # Multi-Factor Topology Matching
        if not best_cand and (old_addr not in ('0x0', '0x0ull')):
            has_old_data = (old_addr in old_fn or old_addr in old_fp)
            if has_old_data:
                o_m = old_fn.get(old_addr, {})
                o_f = old_fp.get(old_addr, {})
                for new_addr, n_m in new_fn.items():
                    n_f = new_fp.get(new_addr, {})
                    s = calculate_match_score(o_m, o_f, n_m, n_f)
                    if s > best_score:
                        best_score = s
                        best_cand = new_addr

        # Fallback: Tokenized string / sub-token search
        if not best_cand or best_score < args.threshold:
            clean_tokens = [t.lower() for t in re.split(r'[^a-zA-Z0-9]', name) if len(t) >= 4]
            for new_addr, n_m in new_fn.items():
                n_strs = " ".join(n_m.get('strings', [])).lower()
                matched = sum(1 for t in clean_tokens if t in n_strs)
                if matched >= 2:
                    best_cand = new_addr
                    best_score = 0.9
                    break

        if best_cand and best_score >= args.threshold:
            results[name] = best_cand
        else:
            results[name] = "0x0"

    out_content = format_output(results, args.format, args.out)
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write(out_content)

    print(f"[+] Output written to {args.out}")

if __name__ == '__main__':
    main()
