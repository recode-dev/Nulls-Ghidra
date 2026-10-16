#!/usr/bin/env python3
import json
import os
import re
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--old_offsets', required=True, help='Path to old Offsets.md')
    p.add_argument('--old_index', required=True, help='Path to old index_data dir')
    p.add_argument('--new_index', required=True, help='Path to new index_data dir')
    p.add_argument('--out_md', default='New_Offsets.md')
    return p.parse_args()

def parse_offsets_md(path):
    offsets = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            m = re.match(r'^\s*([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)', line)
            if m:
                offsets[m.group(1)] = m.group(2).lower()
    return offsets

def main():
    args = parse_args()

    old_offs = parse_offsets_md(args.old_offsets)
    
    with open(os.path.join(args.old_index, 'functions.json'), 'r') as f:
        old_fn = json.load(f)
    with open(os.path.join(args.new_index, 'functions.json'), 'r') as f:
        new_fn = json.load(f)
        
    old_str_p = os.path.join(args.old_index, 'strings_xref.json')
    new_str_p = os.path.join(args.new_index, 'strings_xref.json')
    
    old_sx = json.load(open(old_str_p)) if os.path.exists(old_str_p) else {}
    new_sx = json.load(open(new_str_p)) if os.path.exists(new_str_p) else {}

    results = {}

    for name, old_addr in old_offs.items():
        matched_addr = None
        old_meta = old_fn.get(old_addr)
        if not old_meta:
            results[name] = "0x0"
            continue

        if old_meta.get('strings'):
            anchor = old_meta['strings'][0]
            if anchor in new_sx and len(new_sx[anchor]) == 1:
                matched_addr = new_sx[anchor][0]

        if not matched_addr:
            old_size = old_meta.get('size_chars', 0)
            old_calls_cnt = len(old_meta.get('calls', []))
            
            candidates = []
            for n_addr, n_meta in new_fn.items():
                if abs(n_meta.get('size_chars', 0) - old_size) < max(500, old_size * 0.15):
                    if len(n_meta.get('calls', [])) == old_calls_cnt:
                        candidates.append(n_addr)
            if len(candidates) == 1:
                matched_addr = candidates[0]

        results[name] = matched_addr or "0x0"

    with open(args.out_md, 'w', encoding='utf-8') as f:
        for k, v in results.items():
            f.write(f"{k:<42} = {v}\n")

if __name__ == '__main__':
    main()
