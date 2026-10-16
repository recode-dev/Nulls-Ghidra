#!/usr/bin/env python3
import json
import os
import re
import sys
import argparse

def parse_args():
    p = argparse.ArgumentParser(description="AST Fingerprint and Topology Classifier")
    p.add_argument('--code', required=True, help='Path to decompiled.c')
    p.add_argument('--out', default='index_data/fingerprints.json', help='Output JSON path')
    return p.parse_args()

def main():
    args = parse_args()
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)

    with open(args.code, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    fn_pattern = re.compile(r'\n([a-zA-Z0-9_* ]+)\s+(fcn\.(10[0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n\{', re.MULTILINE)
    matches = list(fn_pattern.finditer(text))

    field_re = re.compile(r'\b(?:arg\w*|this|p\w*Var\d+|iVar\d+|uVar\d+|pvVar\d+|puVar\d+)\s*(?:\+\s*|\-\>\s*|\.\s*|\[\s*)(0x[0-9a-fA-F]+|\d+)')
    ret_field_re = re.compile(r'return\s+\*\((\w+)\s*\*\)\(\w+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\);')
    ret_glob_re = re.compile(r'return\s+\*\((\w+)\s*\*\)(0x10[0-9a-fA-F]+);')
    const_re = re.compile(r'\b(0x[0-9a-fA-F]{4,16})\b')
    float_re = re.compile(r'\b\d+\.\d+(?:f)?\b')
    call_re = re.compile(r'fcn\.(10[0-9a-fA-F]+)')
    loop_re = re.compile(r'\b(while|for|do)\b')
    vt_re = re.compile(r'\*\((?:ulong|int64_t|code\s*\*)\s*\*\)\s*arg1\s*=\s*(?:aav\.)?(0x100[0-9a-fA-F]+);')

    fingerprints = {}

    for i in range(len(matches)):
        m = matches[i]
        addr_hex = m.group(3)
        offset = int(addr_hex, 16) - 0x100000000 if int(addr_hex, 16) >= 0x100000000 else int(addr_hex, 16)
        off_str = f"0x{offset:x}"

        start_pos = m.start()
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start_pos:end_pos]

        ret_fld_m = ret_field_re.search(body)
        ret_field = ret_fld_m.group(2) if ret_fld_m else None

        ret_glob_m = ret_glob_re.search(body)
        ret_global = ret_glob_m.group(2) if ret_glob_m else None

        fields = list(dict.fromkeys(field_re.findall(body)))
        consts = list(dict.fromkeys(const_re.findall(body)))
        floats = list(dict.fromkeys(float_re.findall(body)))
        vtables = list(dict.fromkeys(vt_re.findall(body)))
        loops_count = len(loop_re.findall(body))
        calls_raw = list(dict.fromkeys(call_re.findall(body)))
        calls = [f"0x{int(a, 16) - 0x100000000:x}" for a in calls_raw if int(a, 16) >= 0x100000000 and a != addr_hex]

        fingerprints[off_str] = {
            "offset": off_str,
            "return_type": m.group(1).strip(),
            "size": len(body),
            "lines": len(body.splitlines()),
            "ret_field": ret_field,
            "ret_global": ret_global,
            "vtables_assigned": [f"0x{int(v, 16) - 0x100000000:x}" if int(v, 16) >= 0x100000000 else v for v in vtables],
            "fields_accessed": fields[:30],
            "math_constants": consts[:15],
            "float_constants": floats[:15],
            "loops_count": loops_count,
            "calls": calls,
            "callers": []
        }

    for caller_off, d in fingerprints.items():
        for callee in d["calls"]:
            if callee in fingerprints:
                fingerprints[callee]["callers"].append(caller_off)

    for off, d in fingerprints.items():
        if d.get("ret_global"):
            d["topology_role"] = f"getter_global_{d['ret_global']}"
        elif len(d["calls"]) == 0 and d["lines"] <= 8:
            if d.get("ret_field"):
                d["topology_role"] = f"getter_field_{d['ret_field']}"
            elif len(d["fields_accessed"]) >= 2:
                d["topology_role"] = "setter_multi"
            else:
                d["topology_role"] = "leaf_math"
        elif d.get("vtables_assigned"):
            d["topology_role"] = "constructor_vtable_init"
        elif d["loops_count"] >= 2 and d["lines"] > 40:
            d["topology_role"] = "update_loop"
        elif len(d["callers"]) >= 20:
            d["topology_role"] = "shared_utility_hub"
        else:
            d["topology_role"] = "standard_method"

    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(fingerprints, f, ensure_ascii=False)

    print(f"[+] Generated {len(fingerprints)} fingerprints -> {args.out}")

if __name__ == '__main__':
    main()
