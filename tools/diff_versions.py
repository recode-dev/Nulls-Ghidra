#!/usr/bin/env python3
import json
import os
import re
import sys
import argparse
import urllib.request

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--old_offsets', required=True)
    p.add_argument('--old_index', default='')
    p.add_argument('--new_index', required=True)
    p.add_argument('--out_md', default='New_Offsets.md')
    p.add_argument('--threshold', type=float, default=0.5)
    return p.parse_args()

def fetch_or_read(path_or_url):
    if path_or_url.startswith('http://') or path_or_url.startswith('https://'):
        req = urllib.request.Request(path_or_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    if os.path.exists(path_or_url):
        with open(path_or_url, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return path_or_url

def parse_any_offsets(text):
    offsets = {}
    pats = [
        re.compile(r'#define\s+([a-zA-Z0-9_]+)\s+(0x[0-9a-fA-F]+)', re.MULTILINE),
        re.compile(r'([a-zA-Z0-9_]+)\s*[:=]\s*(?:ptr\()?\s*[\'"]?(0x[0-9a-fA-F]+)[\'"]?', re.MULTILINE),
        re.compile(r'[\'"]([a-zA-Z0-9_]+)[\'"]\s*:\s*[\'"]?(0x[0-9a-fA-F]+)[\'"]?', re.MULTILINE),
        re.compile(r'([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)', re.MULTILINE)
    ]
    for pat in pats:
        for m in pat.finditer(text):
            k = m.group(1).strip()
            v = m.group(2).strip().lower()
            if v != '0x0' and v != '0x0ull' and k not in offsets:
                offsets[k] = v
    return offsets

def main():
    args = parse_args()

    content = fetch_or_read(args.old_offsets)
    old_offs = parse_any_offsets(content)

    with open(os.path.join(args.new_index, 'functions.json'), 'r') as f:
        new_fn = json.load(f)

    new_fp_p = os.path.join(args.new_index, 'fingerprints.json')
    new_fp = json.load(open(new_fp_p)) if os.path.exists(new_fp_p) else {}

    old_fn = {}
    old_fp = {}
    if args.old_index and os.path.exists(os.path.join(args.old_index, 'functions.json')):
        with open(os.path.join(args.old_index, 'functions.json'), 'r') as f:
            old_fn = json.load(f)
        if os.path.exists(os.path.join(args.old_index, 'fingerprints.json')):
            with open(os.path.join(args.old_index, 'fingerprints.json'), 'r') as f:
                old_fp = json.load(f)

    results = {}
    matched_mapping = {}

    for name, old_addr in old_offs.items():
        if old_addr in new_fn:
            results[name] = old_addr
            matched_mapping[old_addr] = old_addr

    for name, old_addr in old_offs.items():
        if name in results:
            continue

        best_cand = None
        best_score = 0.0

        if old_addr in old_fn:
            old_meta = old_fn[old_addr]
            old_strs = set(old_meta.get('strings', []))
            for new_addr, new_meta in new_fn.items():
                if old_strs and old_strs.intersection(set(new_meta.get('strings', []))):
                    best_cand = new_addr
                    best_score = 1.0
                    break

        results[name] = best_cand or (old_addr if old_addr in new_fn else "0x0")

    with open(args.out_md, 'w', encoding='utf-8') as f:
        f.write("# Auto-Diffed Offsets\n\n```c\n")
        for k, v in results.items():
            f.write(f"#define {k:<42} {v}\n")
        f.write("```\n")

if __name__ == '__main__':
    main()
