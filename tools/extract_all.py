#!/usr/bin/env python3
import json
import os
import re
import sys
import struct
import argparse
import subprocess

def parse_args():
    p = argparse.ArgumentParser(description="Full binary metadata, string, AST and VTable indexer")
    p.add_argument('--bin', required=True, help="Path to Mach-O / ELF binary")
    p.add_argument('--code', required=True, help="Path to decompiled.c")
    p.add_argument('--out', default='index_data', help="Output index directory")
    p.add_argument('--ver', default='unknown', help="Version tag")
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

    fn_pattern = re.compile(r'\n([a-zA-Z0-9_* ]+)\s+(fcn\.(10[0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n\{', re.MULTILINE)
    matches = list(fn_pattern.finditer(text))

    str_re = re.compile(r'\"([^\"]{2,120})\"')
    call_re = re.compile(r'fcn\.(10[0-9a-fA-F]+)')
    vt_re = re.compile(r'\*\((?:ulong|int64_t|code\s*\*)\s*\*\)\s*arg1\s*=\s*(?:aav\.)?(0x100[0-9a-fA-F]+);')

    funcs_data = {}
    strings_xref = {}
    ast_vtables = {}

    for i in range(len(matches)):
        m = matches[i]
        ret = m.group(1).strip()
        addr_hex = m.group(3)
        args = m.group(4).strip()
        offset = int(addr_hex, 16) - 0x100000000 if int(addr_hex, 16) >= 0x100000000 else int(addr_hex, 16)

        start_pos = m.start()
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start_pos:end_pos]

        strs = list(dict.fromkeys(str_re.findall(body)))
        called_raw = list(dict.fromkeys(call_re.findall(body)))
        calls = [f"0x{int(a, 16) - 0x100000000:x}" for a in called_raw if int(a, 16) >= 0x100000000 and a != addr_hex]

        vt_m = vt_re.findall(body)
        if vt_m:
            for vt in vt_m:
                vt_off = f"0x{int(vt, 16) - 0x100000000:x}" if int(vt, 16) >= 0x100000000 else vt
                if vt_off not in ast_vtables:
                    ast_vtables[vt_off] = []
                ast_vtables[vt_off].append(f"0x{offset:x}")

        off_str = f"0x{offset:x}"
        funcs_data[off_str] = {
            "address": f"0x100{addr_hex}",
            "offset": off_str,
            "return_type": ret,
            "args": args,
            "size_chars": len(body),
            "strings": strs,
            "calls": calls,
            "callers": [],
            "vtables_assigned": [f"0x{int(v, 16) - 0x100000000:x}" if int(v, 16) >= 0x100000000 else v for v in vt_m]
        }

        for s in strs:
            if s not in strings_xref:
                strings_xref[s] = []
            strings_xref[s].append(off_str)

    for caller_off, data in funcs_data.items():
        for callee_off in data["calls"]:
            if callee_off in funcs_data:
                funcs_data[callee_off]["callers"].append(caller_off)

    return funcs_data, strings_xref, ast_vtables

def unmask_target_ptr(val, base=0x100000000):
    """
    Decodes PAC (Pointer Authentication) and dyld chained fixups.
    Strips top PAC tags and resolves chained fixup targets.
    """
    # 1. Stripping PAC / auth bits (top 16-24 bits)
    raw = val & 0x0000007FFFFFFFFF
    if raw >= base:
        return raw - base

    # 2. Dyld chained fixup format ARM64E / 64 (target inside lower 36-40 bits)
    chained_target = (val & 0x0000000FFFFFFFFF)
    if chained_target >= base:
        return chained_target - base
    elif chained_target > 0:
        return chained_target

    return None

def extract_vtables_fast(bin_path, funcs_data, ast_vtables):
    vtables = {}
    
    # 1. Preload AST-extracted VTables
    for vt_addr, ctor_list in ast_vtables.items():
        vtables[vt_addr] = {
            "source": "ast_ctor",
            "ctors": ctor_list,
            "methods": []
        }

    # 2. Scan binary data with chained fixup & PAC handling
    if os.path.exists(bin_path):
        try:
            with open(bin_path, 'rb') as f:
                data = f.read()

            fn_offsets_set = {int(k, 16) for k in funcs_data.keys()}
            aligned_len = len(data) - (len(data) % 8)
            unpacked = struct.iter_unpack('<Q', memoryview(data)[:aligned_len])

            consecutive = []
            start_vtable = 0
            curr_offset = 0

            for (val,) in unpacked:
                val_off = unmask_target_ptr(val)
                if val_off is not None and val_off in fn_offsets_set:
                    if not consecutive:
                        start_vtable = curr_offset
                    consecutive.append(f"0x{val_off:x}")
                else:
                    if len(consecutive) >= 3:
                        vt_key = f"0x{start_vtable:x}"
                        if vt_key not in vtables:
                            vtables[vt_key] = {"source": "binary_scan", "ctors": [], "methods": consecutive}
                        else:
                            vtables[vt_key]["methods"] = consecutive
                    consecutive = []
                curr_offset += 8
        except Exception:
            pass

    return vtables

def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)

    funcs_data, strings_xref, ast_vtables = extract_code_metadata(args.code)
    bin_strings = extract_strings_from_bin(args.bin)
    vtables = extract_vtables_fast(args.bin, funcs_data, ast_vtables)

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

    print(f"[+] Extraction complete: {len(funcs_data)} functions, {len(strings_xref)} strings, {len(vtables)} vtables.")

if __name__ == '__main__':
    main()
