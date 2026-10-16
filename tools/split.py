#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--code', required=True, help='decompiled.c path')
    p.add_argument('--funcs', required=True, help='functions.json path')
    p.add_argument('--out', default='decompiled', help='Output directory')
    p.add_argument('--ver', default='unknown', help='Version')
    return p.parse_args()

def main():
    args = parse_args()
    src_dir = os.path.join(args.out, 'src')
    os.makedirs(src_dir, exist_ok=True)

    with open(args.code, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    fn_pattern = re.compile(r'\n([a-zA-Z0-9_* ]+)\s+(fcn\.(100[0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n\{', re.MULTILINE)
    raw_defs = []
    for m in fn_pattern.finditer(text):
        addr_hex = m.group(3)
        offset = int(addr_hex, 16) - 0x100000000
        raw_defs.append((offset, addr_hex, m.start()))

    raw_defs.sort(key=lambda x: x[0])

    for i in range(len(raw_defs)):
        offset, addr_hex, start_pos = raw_defs[i]
        end_pos = raw_defs[i + 1][2] if i + 1 < len(raw_defs) else len(text)
        body = text[start_pos:end_pos].strip()

        file_name = f"0x{offset:x}.c"
        out_path = os.path.join(src_dir, file_name)
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(body + "\n")

    manifest = {
        "version": args.ver,
        "total_functions": len(raw_defs),
        "source_dir": "src"
    }

    with open(os.path.join(args.out, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

if __name__ == '__main__':
    main()
