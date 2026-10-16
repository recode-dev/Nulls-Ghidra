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
            m = re.search(r'([A-Za-z0-9_]+)::([A-Za-z0-9_]+)', s)
            if m:
                symbols[off] = sanitize_name(f"{m.group(1)}_{m.group(2)}")
            elif "DescriptionResolver:" in s:
                m2 = re.search(r'DescriptionResolver:\s*([A-Za-z0-9_]+)', s)
                if m2:
                    symbols[off] = f"DescriptionResolver_{m2.group(1)}"
            elif "Failed to find textfield:" in s:
                symbols[off] = "MovieClip_findTextField"
            elif "CombatHUD:" in s:
                symbols[off] = "CombatHUD_preloadedGlyphs"

    if os.path.exists(fp_path):
        with open(fp_path, 'r', encoding='utf-8') as f:
            fps = json.load(f)
        for off, data in fps.items():
            fields = data.get('fields_accessed', [])
            size = data.get('size', 0)
            calls_cnt = len(data.get('calls', []))
            callers_cnt = len(data.get('callers', []))

            if '0x30' in fields and '0x34' in fields and '0x38' in fields and size < 120:
                symbols[off] = "LogicGameObjectClient_setPosition"
            elif '0x30' in fields and size < 80 and calls_cnt == 0:
                if '300' in data.get('math_constants', []):
                    symbols[off] = "LogicGameObjectClient_getTileX"
                else:
                    symbols[off] = "LogicGameObjectClient_getX"
            elif '0x34' in fields and size < 80 and calls_cnt == 0:
                if '300' in data.get('math_constants', []):
                    symbols[off] = "LogicGameObjectClient_getTileY"
                else:
                    symbols[off] = "LogicGameObjectClient_getY"
            elif '0x3c' in fields and '0x40' in fields and size < 150:
                symbols[off] = "LogicGameObjectClient_resolveTeam"
            elif callers_cnt > 500 and calls_cnt <= 2 and size < 200:
                symbols[off] = "BattleMode_getInstance"
            elif callers_cnt > 2000 and size < 150:
                symbols[off] = "String_ctor"

    if os.path.exists(cls_path):
        with open(cls_path, 'r', encoding='utf-8') as f:
            classes = json.load(f)
        for cls_id, data in classes.items():
            for idx, m_off in enumerate(data.get('methods', [])):
                if m_off not in symbols:
                    symbols[m_off] = f"{cls_id}_sub_{idx}"

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
