#!/usr/bin/env python3
import json
import os
import re
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--index_dir', default='index_data')
    p.add_argument('--out_dir', default='symbols_out')
    return p.parse_args()

def sanitize_name(name):
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    name = re.sub(r'_+', '_', name)
    return name.strip('_')

def extract_literal_signature(s):
    m_cpp = re.search(r'([A-Za-z0-9_]{2,40})::([A-Za-z0-9_]{2,40})', s)
    if m_cpp:
        return f"{m_cpp.group(1)}_{m_cpp.group(2)}"
    m_objc = re.search(r'[+-]\[([A-Za-z0-9_]{2,40})\s+([A-Za-z0-9_:]{2,40})\]', s)
    if m_objc:
        return f"{m_objc.group(1)}_{m_objc.group(2)}"
    return None

def main():
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    sx_path = os.path.join(args.index_dir, 'strings_xref.json')
    fn_path = os.path.join(args.index_dir, 'functions.json')
    fp_path = os.path.join(args.index_dir, 'fingerprints.json')

    if not os.path.exists(sx_path) or not os.path.exists(fn_path):
        return

    with open(sx_path, 'r', encoding='utf-8') as f:
        sx = json.load(f)
    with open(fn_path, 'r', encoding='utf-8') as f:
        fn = json.load(f)

    fps = {}
    if os.path.exists(fp_path):
        with open(fp_path, 'r', encoding='utf-8') as f:
            fps = json.load(f)

    valid_entry_points = set(fn.keys())
    symbols = {}
    used_names = {}

    for s, offsets in sx.items():
        if len(offsets) == 1:
            off = offsets[0]
            if off in valid_entry_points:
                sig = extract_literal_signature(s)
                if sig:
                    clean_name = sanitize_name(sig)
                    if clean_name not in used_names:
                        symbols[off] = clean_name
                        used_names[clean_name] = off

    for off, data in fps.items():
        if off not in valid_entry_points or off in symbols:
            continue

        fields = data.get('fields_accessed', [])
        lines = data.get('lines', 0)
        calls_cnt = len(data.get('calls', []))
        callers_cnt = len(data.get('callers', []))
        consts = data.get('math_constants', [])

        if lines <= 5 and calls_cnt == 0:
            if len(fields) == 1:
                fld = fields[0]
                if consts and any(c in ['300', '100', '60'] for c in consts):
                    scale = consts[0]
                    name = f"Getter_Scaled_{fld}_div_{scale}"
                else:
                    name = f"Getter_Raw_{fld}"
                if name not in used_names:
                    symbols[off] = name
                    used_names[name] = off
            elif len(fields) >= 2:
                f_tag = "_".join(fields[:3])
                name = f"Setter_Fields_{f_tag}"
                if name not in used_names:
                    symbols[off] = name
                    used_names[name] = off
        elif callers_cnt >= 500 and calls_cnt <= 2 and lines <= 20:
            name = f"Singleton_Getter_{off}"
            if name not in used_names:
                symbols[off] = name
                used_names[name] = off

    with open(os.path.join(args.out_dir, 'symbols.json'), 'w', encoding='utf-8') as f:
        json.dump(symbols, f, indent=2)

    with open(os.path.join(args.out_dir, 'symbols.idc'), 'w', encoding='utf-8') as f:
        f.write('#include <idc.idc>\nstatic main() {\n')
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f'  set_name({addr}, "{sym}");\n')
        f.write('}\n')

    with open(os.path.join(args.out_dir, 'symbols.r2'), 'w', encoding='utf-8') as f:
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f"f sym.{sym} @ {addr}\n")

if __name__ == '__main__':
    main()
