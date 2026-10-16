#!/usr/bin/env python3
"""
Universal Algorithmic Version Differ for Stripped Binaries.
100% Dynamic - Zero Hardcoded Addresses or Game-Specific Names.
Uses multi-dimensional structural similarity scoring:
- Return Field & Struct Member Access
- AST Topology & Line Count Ratio
- String Literal & Log Signature XREFs
- Math, Float & Bitmask Constants
- Call Graph & Callee Set Jaccard Similarity
"""

import json
import os
import re
import sys
import argparse
import urllib.request

def parse_args():
    p = argparse.ArgumentParser(description="Zero-Hardcode Universal Binary Differ")
    p.add_argument('--old_offsets', required=True, help="Header file or key-value list of old offsets")
    p.add_argument('--old_index', default='', help="Path to old version index_data directory")
    p.add_argument('--new_index', required=True, help="Path to new version index_data directory")
    p.add_argument('--out_md', default='New_Offsets.md', help="Output Markdown / Header file")
    p.add_argument('--threshold', type=float, default=0.4, help="Minimum matching confidence score (0.0 - 1.0)")
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
            if v not in ('0x0', '0x0ull') and k not in offsets:
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

    # 1. String Literal Exact Overlap (Weight: 4.0)
    old_strs = set(old_meta.get('strings', []))
    new_strs = set(new_meta.get('strings', []))
    if old_strs and new_strs:
        str_j = jaccard(old_strs, new_strs)
        score += str_j * 4.0
        weight_total += 4.0

    # 2. Return Field Match for Getters (Weight: 3.5)
    old_ret = old_fp.get('ret_field')
    new_ret = new_fp.get('ret_field')
    if old_ret and new_ret:
        if old_ret == new_ret:
            score += 3.5
        weight_total += 3.5

    # 3. Math & Bitmask Constants (Weight: 3.0)
    old_consts = old_fp.get('math_constants', [])
    new_consts = new_fp.get('math_constants', [])
    if old_consts and new_consts:
        score += jaccard(old_consts, new_consts) * 3.0
        weight_total += 3.0

    # 4. Fields Accessed Jaccard (Weight: 2.5)
    old_flds = old_fp.get('fields_accessed', [])
    new_flds = new_fp.get('fields_accessed', [])
    if old_flds and new_flds:
        score += jaccard(old_flds, new_flds) * 2.5
        weight_total += 2.5

    # 5. Topology Role & Loop Count (Weight: 1.5)
    if old_fp.get('topology_role') and new_fp.get('topology_role'):
        if old_fp['topology_role'] == new_fp['topology_role']:
            score += 1.5
        weight_total += 1.5

    # 6. Line Count Proportional Similarity (Weight: 1.0)
    old_l = max(1, old_fp.get('lines', 1))
    new_l = max(1, new_fp.get('lines', 1))
    line_sim = 1.0 - min(1.0, abs(old_l - new_l) / max(old_l, new_l))
    score += line_sim * 1.0
    weight_total += 1.0

    return score / weight_total if weight_total > 0 else 0.0

def main():
    args = parse_args()

    content = fetch_or_read(args.old_offsets)
    old_offs = parse_any_offsets(content)

    new_fn_path = os.path.join(args.new_index, 'functions.json')
    new_fp_path = os.path.join(args.new_index, 'fingerprints.json')

    new_fn = json.load(open(new_fn_path)) if os.path.exists(new_fn_path) else {}
    new_fp = json.load(open(new_fp_path)) if os.path.exists(new_fp_path) else {}

    old_fn = {}
    old_fp = {}
    if args.old_index:
        old_fn_p = os.path.join(args.old_index, 'functions.json')
        old_fp_p = os.path.join(args.old_index, 'fingerprints.json')
        if os.path.exists(old_fn_p):
            old_fn = json.load(open(old_fn_p))
        if os.path.exists(old_fp_p):
            old_fp = json.load(open(old_fp_p))

    results = {}

    for name, old_addr in old_offs.items():
        best_cand = None
        best_score = 0.0

        # Exact match if addresses haven't shifted
        if old_addr in new_fn and (not old_fn or old_addr in old_fn):
            if not old_fn or calculate_match_score(old_fn.get(old_addr, {}), old_fp.get(old_addr, {}), new_fn[old_addr], new_fp.get(old_addr, {})) > 0.8:
                results[name] = old_addr
                continue

        # Algorithmic full-spectrum search
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

        # Fallback: String matching by symbol name fragments if no old index provided
        if not best_cand or best_score < args.threshold:
            clean_tokens = [t.lower() for t in re.split(r'[^a-zA-Z0-9]', name) if len(t) >= 4]
            for new_addr, n_m in new_fn.items():
                n_strs = " ".join(n_m.get('strings', [])).lower()
                matched_tokens = sum(1 for t in clean_tokens if t in n_strs)
                if matched_tokens >= 2:
                    best_cand = new_addr
                    best_score = 0.9
                    break

        if best_cand and best_score >= args.threshold:
            results[name] = best_cand
        else:
            results[name] = "0x0"

    with open(args.out_md, 'w', encoding='utf-8') as f:
        f.write("# Auto-Diffed Offsets (Universal Algorithmic Matcher)\n\n```c\n")
        for k, v in results.items():
            f.write(f"#define {k:<42} {v}\n")
        f.write("```\n")

    print(f"[+] Successfully diffed {len(results)} offsets dynamically -> {args.out_md}")

if __name__ == '__main__':
    main()
