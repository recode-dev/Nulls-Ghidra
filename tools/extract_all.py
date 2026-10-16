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
    p.add_argument('--bin', required=True)
    p.add_argument('--code', required=True)
    p.add_argument('--out', default='index_data')
    p.add_argument('--ver', default='unknown')
    return p.parse_args()

def extract_strings_from_bin(bin_path):
    strings_map = {}
    if not os.path.exists(bin_path):
        return strings_map
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
    matches = list(fn_pattern.finditer(text))

    str_re = re.compile(r'\"([^\"]{2,120})\"')
    call_re = re.compile(r'fcn\.(100[0-9a-fA-F]+)')

    funcs_data = {}
    strings_xref = {}

    for i in range(len(matches)):
        m = matches[i]
        ret = m.group(1).strip()
        addr_hex = m.group(3)
        args = m.group(4).strip()
        offset = int(addr_hex, 16) - 0x100000000

        start_pos = m.start()
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start_pos:end_pos]

        strs = list(set(str_re.findall(body)))
        called_raw = list(set(call_re.findall(body)))
        calls = [f"0x{int(a, 16) - 0x100000000:x}" for a in called_raw if a != addr_hex]

        off_str = f"0x{offset:x}"
        funcs_data[off_str] = {
            "address": f"0x100{addr_hex}",
            "offset": off_str,
            "return_type": ret,
            "args": args,
            "size_chars": len(body),
            "strings": strs,
            "calls": calls,
            "callers": []
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

def extract_vtables_fast(bin_path, funcs_data):
    vtables = {}
    if not os.path.exists(bin_path):
        return vtables
    try:
        with open(bin_path, 'rb') as f:
            data = f.read()

        fn_offsets_set = {int(k, 16) for k in funcs_data.keys()}
        base = 0x100000000

        aligned_len = len(data) - (len(data) % 8)
        unpacked = struct.iter_unpack('<Q', memoryview(data)[:aligned_len])

        consecutive = []
        start_vtable = 0
        curr_offset = 0

        for (val,) in unpacked:
            val_off = val - base
            if val_off in fn_offsets_set:
                if not consecutive:
                    start_vtable = curr_offset
                consecutive.append(f"0x{val_off:x}")
            else:
                if len(consecutive) >= 4:
                    vtables[f"0x{start_vtable:x}"] = consecutive
                consecutive = []
            curr_offset += 8
    except Exception:
        pass
    return vtables

def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)

    funcs_data, strings_xref = extract_code_metadata(args.code)
    bin_strings = extract_strings_from_bin(args.bin)
    vtables = extract_vtables_fast(args.bin, funcs_data)

    with open(os.path.join(args.out, 'functions.json'), 'w', encoding='utf-8') as f:
        json.dump(funcs_data, f, ensure_ascii=False)

    with open(os.path.join(args.out, 'strings_xref.json'), 'w', encoding='utf-8') as f:
        json.dump(strings_xref, f, ensure_ascii=False)

    with open(os.path.join(args.out, 'strings.json'), 'w', encoding='utf-8') as f:
        json.dump(bin_strings, f, ensure_ascii=False)

    with open(os.path.join(args.out, 'vtables.json'), 'w', encoding='utf-8') as f:
        json.dump(vtables, f, ensure_ascii=False)

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
        json.dump(compact_ai_map, f, ensure_ascii=False)

if __name__ == '__main__':
    main()
