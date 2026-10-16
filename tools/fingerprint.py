#!/usr/bin/env python3
import json
import os
import re
import sys
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--code', required=True, help='Path to decompiled.c')
    p.add_argument('--out', default='index_data/fingerprints.json', help='Output JSON path')
    return p.parse_args()

def main():
    args = parse_args()
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)

    with open(args.code, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    fn_pattern = re.compile(r'\n([a-zA-Z0-9_* ]+)\s+(fcn\.(100[0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n\{', re.MULTILINE)
    matches = list(fn_pattern.finditer(text))

    field_re = re.compile(r'(?:arg1|\bthis\b|puVar\d+|pvVar\d+)\s*(?:\+\s*|\-\>\s*|\.\s*)(0x[0-9a-fA-F]+|\d+)')
    const_re = re.compile(r'\b(0x[0-9a-fA-F]{4,16})\b')
    float_re = re.compile(r'\b\d+\.\d+(?:f)?\b')
    call_re = re.compile(r'fcn\.(100[0-9a-fA-F]+)')
    loop_re = re.compile(r'\b(while|for|do)\b')

    fingerprints = {}

    for i in range(len(matches)):
        m = matches[i]
        addr_hex = m.group(3)
        offset = int(addr_hex, 16) - 0x100000000
        off_str = f"0x{offset:x}"

        start_pos = m.start()
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start_pos:end_pos]

        fields = list(set(field_re.findall(body)))
        consts = list(set(const_re.findall(body)))
        floats = list(set(float_re.findall(body)))
        loops_count = len(loop_re.findall(body))
        calls_raw = list(set(call_re.findall(body)))
        calls = [f"0x{int(a, 16) - 0x100000000:x}" for a in calls_raw if a != addr_hex]

        fingerprints[off_str] = {
            "offset": off_str,
            "size": len(body),
            "lines": len(body.splitlines()),
            "fields_accessed": fields[:20],
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
        if len(d["callers"]) == 0 and d["lines"] > 50:
            d["topology_role"] = "root_update_loop"
        elif len(d["calls"]) == 0:
            d["topology_role"] = "leaf_math"
        elif len(d["callers"]) >= 15:
            d["topology_role"] = "shared_utility_hub"
        else:
            d["topology_role"] = "standard_method"

    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(fingerprints, f, ensure_ascii=False)

if __name__ == '__main__':
    main()
