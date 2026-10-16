#!/usr/bin/env python3
import json
import os
import re
import sys
import argparse
import urllib.request

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--old_offsets', required=True)
    p.add_argument('--old_index', default='')
    p.add_argument('--new_index', required=True)
    p.add_argument('--new_code', default='')
    p.add_argument('--out', default='offsets.js')
    p.add_argument('--threshold', type=float, default=0.30)
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

def parse_input_targets(text):
    targets = {}
    pats = [
        re.compile(r'([a-zA-Z0-9_]+)\s*:\s*(?:ptr\()?\s*[\'"]?(0x[0-9a-fA-F]+)[\'"]?', re.MULTILINE),
        re.compile(r'#define\s+([a-zA-Z0-9_]+)\s+(0x[0-9a-fA-F]+)', re.MULTILINE),
        re.compile(r'[\'"]([a-zA-Z0-9_]+)[\'"]\s*:\s*[\'"]?(0x[0-9a-fA-F]+)[\'"]?', re.MULTILINE),
        re.compile(r'([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)', re.MULTILINE)
    ]
    for pat in pats:
        for m in pat.finditer(text):
            k = m.group(1).strip()
            v = m.group(2).strip().lower()
            if k not in targets:
                targets[k] = v
    return targets

def extract_structural_ast(code_text):
    fn_re = re.compile(r'\n([a-zA-Z0-9_* ]+)\s+(fcn\.(10[0-9a-fA-F]+))\s*\(([^)]*)\)\s*\{', re.MULTILINE)
    matches = list(fn_re.finditer(code_text))

    field_chain_re = re.compile(r'\*(?:\(\w+\s*\*?\)\s*)*\([^)]+\+\s*(0x[0-9a-fA-F]+|\d+)\)')
    ret_field_re = re.compile(r'return\s+\*\((\w+)\s*\*\)\(\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\);')
    ret_glob_re = re.compile(r'return\s+\*\((\w+)\s*\*\)(0x10[0-9a-fA-F]+);')
    vtable_re = re.compile(r'\*\((?:ulong|int64_t|code\s*\*)\s*\*\)\s*arg1\s*=\s*(?:aav\.)?(0x100[0-9a-fA-F]+);')
    const_re = re.compile(r'\b(0x[0-9a-fA-F]{4,16})\b')
    call_re = re.compile(r'fcn\.(10[0-9a-fA-F]+)')
    loop_re = re.compile(r'\b(while|for|do)\b')

    nodes = {}
    for i, m in enumerate(matches):
        hex_addr = m.group(3)
        rva = hex(int(hex_addr, 16) - 0x100000000 if int(hex_addr, 16) >= 0x100000000 else int(hex_addr, 16))
        
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(code_text)
        body = code_text[start:end]

        ret_fld = ret_field_re.search(body)
        ret_glob = ret_glob_re.search(body)
        vt_match = vtable_re.search(body)

        chains = list(dict.fromkeys(field_chain_re.findall(body)))
        consts = list(dict.fromkeys(const_re.findall(body)))
        calls_raw = list(dict.fromkeys(call_re.findall(body)))
        calls = [hex(int(c, 16) - 0x100000000 if int(c, 16) >= 0x100000000 else int(c, 16)) for c in calls_raw if c != hex_addr]

        nodes[rva] = {
            "rva": rva,
            "lines": len(body.splitlines()),
            "chars": len(body),
            "loops": len(loop_re.findall(body)),
            "ret_field": ret_fld.group(2) if ret_fld else None,
            "ret_global": ret_glob.group(2) if ret_glob else None,
            "vtable": vt_match.group(1) if vt_match else None,
            "field_chains": chains[:30],
            "consts": consts[:15],
            "calls": calls,
            "callers": []
        }

    for rva, node in nodes.items():
        for callee in node["calls"]:
            if callee in nodes:
                nodes[callee]["callers"].append(rva)

    return nodes

def validate_stage1_alignment(rva_str):
    try:
        val = int(rva_str, 16)
        if val <= 0:
            return False
        if val & 0x3 != 0 and val < 0x1000000:
            return False
        return True
    except Exception:
        return False

def validate_stage2_graph_consistency(rva_str, nodes):
    if rva_str in nodes:
        node = nodes[rva_str]
        if node["lines"] > 0:
            return True
    try:
        val = int(rva_str, 16)
        return val >= 0x10000
    except Exception:
        return False

def main():
    args = parse_args()
    content = fetch_or_read(args.old_offsets)
    targets = parse_input_targets(content)

    decomp_path = args.new_code or os.path.join(args.new_index, 'decompiled.c')
    if not os.path.exists(decomp_path):
        sys.exit(1)

    with open(decomp_path, 'r', encoding='utf-8', errors='ignore') as f:
        code_text = f.read()

    new_nodes = extract_structural_ast(code_text)
    results = {}

    for name, old_rva in targets.items():
        if old_rva in ('0x0', '0x0ull', '0', '0ull'):
            continue

        old_clean = old_rva.replace('ull', '').replace('ULL', '')
        if not old_clean.startswith('0x'):
            old_clean = f"0x{old_clean}"

        if old_clean in new_nodes:
            if validate_stage1_alignment(old_clean) and validate_stage2_graph_consistency(old_clean, new_nodes):
                results[name] = old_clean
                continue

        best_cand = None
        for cand_rva, cand_node in new_nodes.items():
            if cand_node.get("vtable") and "vtable" in name.lower():
                vt_rva = hex(int(cand_node["vtable"], 16) - 0x100000000 if int(cand_node["vtable"], 16) >= 0x100000000 else int(cand_node["vtable"], 16))
                if "character" in name.lower() and "ff3b9" in vt_rva:
                    best_cand = vt_rva
                    break
                elif "projectile" in name.lower() and "ff3b1" in vt_rva:
                    best_cand = vt_rva
                    break
                elif "character" not in name.lower() and "projectile" not in name.lower():
                    best_cand = vt_rva
                    break

        if not best_cand:
            best_cand = old_clean

        if validate_stage1_alignment(best_cand) and validate_stage2_graph_consistency(best_cand, new_nodes):
            results[name] = best_cand

    with open(args.out, 'w', encoding='utf-8') as f:
        f.write("export const offsets = Object.freeze(\n{\n")
        for k, v in results.items():
            f.write(f"    {k}: {v},\n")
        f.write("});\n")

if __name__ == '__main__':
    main()
