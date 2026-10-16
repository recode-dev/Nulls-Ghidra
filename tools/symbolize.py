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

def extract_symbol_from_string(s):
    m_cpp = re.search(r'([A-Za-z0-9_]{2,40})::([A-Za-z0-9_]{2,40})', s)
    if m_cpp:
        return f"{m_cpp.group(1)}_{m_cpp.group(2)}"

    m_objc = re.search(r'[+-]\[([A-Za-z0-9_]{2,40})\s+([A-Za-z0-9_:]{2,40})\]', s)
    if m_objc:
        return f"{m_objc.group(1)}_{m_objc.group(2)}"

    m_tag = re.search(r'^\[([A-Za-z0-9_]{2,30})\]', s)
    if m_tag:
        return f"Module_{m_tag.group(1)}"

    m_ctx = re.search(r'([A-Za-z0-9_]{3,30})\s*(?:failed|error|missing|warning|invalid|assert|not found|exception)', s, re.IGNORECASE)
    if m_ctx:
        return f"Handler_{m_ctx.group(1)}"

    return None

def main():
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    sx_path = os.path.join(args.index_dir, 'strings_xref.json')
    fn_path = os.path.join(args.index_dir, 'functions.json')
    fp_path = os.path.join(args.index_dir, 'fingerprints.json')
    cls_path = os.path.join(args.index_dir, 'classes.json')

    if not os.path.exists(sx_path) or not os.path.exists(fn_path):
        return

    with open(sx_path, 'r', encoding='utf-8') as f:
        sx = json.load(f)
    with open(fn_path, 'r', encoding='utf-8') as f:
        fn = json.load(f)

    symbols = {}

    for s, offsets in sx.items():
        if len(offsets) == 1:
            off = offsets[0]
            inferred = extract_symbol_from_string(s)
            if inferred and off not in symbols:
                symbols[off] = sanitize_name(inferred)

    if os.path.exists(fp_path):
        with open(fp_path, 'r', encoding='utf-8') as f:
            fps = json.load(f)
        for off, data in fps.items():
            if off in symbols:
                continue

            fields = data.get('fields_accessed', [])
            size = data.get('size', 0)
            calls_cnt = len(data.get('calls', []))
            callers_cnt = len(data.get('callers', []))
            role = data.get('topology_role', '')

            if len(fields) == 1 and calls_cnt == 0 and size < 80:
                symbols[off] = f"Getter_Field_{fields[0]}"
            elif len(fields) >= 2 and calls_cnt == 0 and size < 120:
                fields_tag = "_".join(fields[:3])
                symbols[off] = f"Setter_Fields_{fields_tag}"
            elif role == "root_update_loop":
                symbols[off] = f"UpdateLoop_{off}"
            elif role == "shared_utility_hub" and callers_cnt > 1000:
                symbols[off] = f"CoreUtility_{off}"

    if os.path.exists(cls_path):
        with open(cls_path, 'r', encoding='utf-8') as f:
            classes = json.load(f)
        for cls_id, data in classes.items():
            for idx, m_off in enumerate(data.get('methods', [])):
                if m_off not in symbols:
                    symbols[m_off] = f"{cls_id}_method_{idx}"

    with open(os.path.join(args.out_dir, 'symbols.json'), 'w', encoding='utf-8') as f:
        json.dump(symbols, f, indent=2)

    with open(os.path.join(args.out_dir, 'symbols.r2'), 'w', encoding='utf-8') as f:
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f"f sym.{sym} @ {addr}\n")

    with open(os.path.join(args.out_dir, 'symbols.idc'), 'w', encoding='utf-8') as f:
        f.write('#include <idc.idc>\nstatic main() {\n')
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f'  set_name({addr}, "{sym}");\n')
        f.write('}\n')

    with open(os.path.join(args.out_dir, 'symbols_ghidra.py'), 'w', encoding='utf-8') as f:
        f.write('# @category Symbols\nfm = currentProgram.getFunctionManager()\n')
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f'a = toAddr({addr})\nf = fm.getFunctionAt(a)\nif f: f.setName("{sym}", SourceType.USER_DEFINED)\n')

if __name__ == '__main__':
    main()
