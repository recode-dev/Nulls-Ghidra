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

def main():
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    sx_path = os.path.join(args.index_dir, 'strings_xref.json')
    fn_path = os.path.join(args.index_dir, 'functions.json')
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
            m = re.search(r'([A-Za-z0-9_]+)::([A-Za-z0-9_]+)', s)
            if m:
                cls_name = m.group(1)
                method_name = m.group(2)
                sym = f"{cls_name}_{method_name}"
                symbols[off] = sanitize_name(sym)
            elif "DescriptionResolver:" in s:
                m2 = re.search(r'DescriptionResolver:\s*([A-Za-z0-9_]+)', s)
                if m2:
                    symbols[off] = f"DescriptionResolver_{m2.group(1)}"
            elif "CombatHUD:" in s:
                symbols[off] = "CombatHUD_initGlyphs"
            elif "Failed to find textfield:" in s:
                symbols[off] = "MovieClip_findTextField"

    if os.path.exists(cls_path):
        with open(cls_path, 'r', encoding='utf-8') as f:
            classes = json.load(f)
        for cls_id, data in classes.items():
            methods = data.get('methods', [])
            for idx, m_off in enumerate(methods):
                if m_off not in symbols:
                    symbols[m_off] = f"{cls_id}_sub_{idx}"

    sym_json = os.path.join(args.out_dir, 'symbols.json')
    with open(sym_json, 'w', encoding='utf-8') as f:
        json.dump(symbols, f, indent=2)

    sym_r2 = os.path.join(args.out_dir, 'symbols.r2')
    with open(sym_r2, 'w', encoding='utf-8') as f:
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f"f sym.{sym} @ {addr}\n")

    sym_idc = os.path.join(args.out_dir, 'symbols.idc')
    with open(sym_idc, 'w', encoding='utf-8') as f:
        f.write('#include <idc.idc>\nstatic main() {\n')
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f'  set_name({addr}, "{sym}");\n')
        f.write('}\n')

    sym_ghidra = os.path.join(args.out_dir, 'symbols_ghidra.py')
    with open(sym_ghidra, 'w', encoding='utf-8') as f:
        f.write('# @category Symbols\n')
        f.write('fm = currentProgram.getFunctionManager()\n')
        for off, sym in symbols.items():
            addr = f"0x100{off[2:]}" if off.startswith('0x') else f"0x100{off}"
            f.write(f'a = toAddr({addr})\n')
            f.write(f'f = fm.getFunctionAt(a)\n')
            f.write(f'if f: f.setName("{sym}", SourceType.USER_DEFINED)\n')

if __name__ == '__main__':
    main()
