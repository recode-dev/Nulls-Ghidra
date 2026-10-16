#!/usr/bin/env python3
import json
import os
import re
import sys
import struct
import argparse
import subprocess

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--bin', required=True, help='Binary path')
    p.add_argument('--code', required=True, help='decompiled.c path')
    p.add_argument('--out', default='index_data', help='Output directory')
    p.add_argument('--ver', default='unknown', help='Version')
    return p.parse_args()

def extract_strings_from_bin(bin_path):
    strings_map = {}
    try:
        out = subprocess.check_output(['strings', '-a', '-t', 'x', bin_path], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
        for line in out.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                off_hex, s = parts
                if len(s) >= 3:
                    strings_map[s] = f"0x{int(off_hex, 16):x}"
    except Exception:
        pass
    return strings_map

def extract_code_metadata(code_path):
    with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    fn_pattern = re.compile(r'\n([a-zA-Z0-9_* ]+)\s+(fcn\.(100[0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n\{', re.MULTILINE)
    raw_defs = []
    for m in fn_pattern.finditer(text):
        ret = m.group(1).strip()
        addr_hex = m.group(3)
        args = m.group(4).strip()
        offset = int(addr_hex, 16) - 0x100000000
        raw_defs.append((offset, addr_hex, ret, args, m.start()))

    raw_defs.sort(key=lambda x: x[0])

    funcs_data = {}
    strings_xref = {}

    for i in range(len(raw_defs)):
        offset, addr_hex, ret, args, start_pos = raw_defs[i]
        end_pos = raw_defs[i + 1][4] if i + 1 < len(raw_defs) else len(text)
        body = text[start_pos:end_pos]

        strs = list(set(re.findall(r'\"([^\"]{2,150})\"', body)))
        called_raw = list(set(re.findall(r'fcn\.(100[0-9a-fA-F]+)', body)))
        calls = [f"0x{int(a, 16) - 0x100000000:x}" for a in called_raw if a != addr_hex]

        consts = list(set(re.findall(r'0x[0-9a-fA-F]{3,16}', body)))

        off_str = f"0x{offset:x}"
        funcs_data[off_str] = {
            "address": f"0x100{addr_hex}",
            "offset": off_str,
            "return_type": ret,
            "args": args,
            "size_chars": len(body),
            "line_count": len(body.splitlines()),
            "strings": strs,
            "calls": calls,
            "callers": [],
            "constants": consts[:30]
        }

        for s in strs:
            if s not in strings_xref:
                strings_xref[s] = []
            strings_xref[s].append(off_str)

    for caller_off, data in funcs_data.items():
        for callee_off in data["calls"]:
            if callee_off in funcs_data:
                funcs_data[callee_off]["callers"].append(caller_off)

    return funcs_data, strings_xref

def extract_vtables(bin_path, funcs_data):
    vtables = {}
    if not os.path.exists(bin_path):
        return vtables
    try:
        with open(bin_path, 'rb') as f:
            data = f.read()

        fn_offsets = {int(k, 16): k for k in funcs_data.keys()}
        base = 0x100000000
        ptr_size = 8

        consecutive = []
        start_vtable = None

        for off in range(0, len(data) - ptr_size, ptr_size):
            val = struct.unpack('<Q', data[off:off+ptr_size])[0]
            val_off = val - base
            if val_off in fn_offsets:
                if not consecutive:
                    start_vtable = off
                consecutive.append(f"0x{val_off:x}")
            else:
                if len(consecutive) >= 4:
                    vtables[f"0x{start_vtable:x}"] = consecutive
                consecutive = []
                start_vtable = None
    except Exception:
        pass
    return vtables

def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)

    funcs_data, strings_xref = extract_code_metadata(args.code)
    bin_strings = extract_strings_from_bin(args.bin)
    vtables = extract_vtables(args.bin, funcs_data)

    with open(os.path.join(args.out, 'functions.json'), 'w', encoding='utf-8') as f:
        json.dump(funcs_data, f, ensure_ascii=False, indent=2)

    with open(os.path.join(args.out, 'strings_xref.json'), 'w', encoding='utf-8') as f:
        json.dump(strings_xref, f, ensure_ascii=False, indent=2)

    with open(os.path.join(args.out, 'strings.json'), 'w', encoding='utf-8') as f:
        json.dump(bin_strings, f, ensure_ascii=False, indent=2)

    with open(os.path.join(args.out, 'vtables.json'), 'w', encoding='utf-8') as f:
        json.dump(vtables, f, ensure_ascii=False, indent=2)

    compact_ai_map = {}
    for off, meta in funcs_data.items():
        if meta["strings"] or len(meta["callers"]) > 5 or meta["size_chars"] > 10000:
            compact_ai_map[off] = {
                "strs": meta["strings"],
                "calls": meta["calls"][:10],
                "callers": meta["callers"][:10],
                "size": meta["size_chars"]
            }

    with open(os.path.join(args.out, 'ai_compact_index.json'), 'w', encoding='utf-8') as f:
        json.dump(compact_ai_map, f, ensure_ascii=False, indent=2)

if __name__ == '__main__':
    main()