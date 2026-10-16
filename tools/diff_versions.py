#!/usr/bin/env python3
import json
import os
import re
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--old_offsets', required=True)
    p.add_argument('--old_index', required=True)
    p.add_argument('--new_index', required=True)
    p.add_argument('--out_md', default='New_Offsets.md')
    p.add_argument('--threshold', type=float, default=0.6)
    return p.parse_args()

def parse_offsets_md(path):
    offsets = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            m = re.match(r'^\s*([a-zA-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)', line)
            if m:
                offsets[m.group(1)] = m.group(2).lower()
    return offsets

def compute_similarity(f1, f2, sx1_map, sx2_map):
    score = 0.0
    weight = 0.0

    s1 = set(f1.get('strings', []))
    s2 = set(f2.get('strings', []))
    if s1 or s2:
        jaccard_str = len(s1.intersection(s2)) / max(1, len(s1.union(s2)))
        score += jaccard_str * 0.5
        weight += 0.5

    calls1 = set(f1.get('calls', []))
    calls2 = set(f2.get('calls', []))
    if calls1 or calls2:
        ratio_calls = min(len(calls1), len(calls2)) / max(1, max(len(calls1), len(calls2)))
        score += ratio_calls * 0.2
        weight += 0.2

    callers1 = set(f1.get('callers', []))
    callers2 = set(f2.get('callers', []))
    if callers1 or callers2:
        ratio_callers = min(len(callers1), len(callers2)) / max(1, max(len(callers1), len(callers2)))
        score += ratio_callers * 0.15
        weight += 0.15

    sz1 = f1.get('size_chars', 0)
    sz2 = f2.get('size_chars', 0)
    if sz1 and sz2:
        ratio_sz = min(sz1, sz2) / max(sz1, sz2)
        score += ratio_sz * 0.15
        weight += 0.15

    return score / weight if weight > 0 else 0.0

def main():
    args = parse_args()

    old_offs = parse_offsets_md(args.old_offsets)

    with open(os.path.join(args.old_index, 'functions.json'), 'r') as f:
        old_fn = json.load(f)
    with open(os.path.join(args.new_index, 'functions.json'), 'r') as f:
        new_fn = json.load(f)

    results = {}

    for name, old_addr in old_offs.items():
        if old_addr not in old_fn:
            results[name] = "0x0"
            continue

        target_meta = old_fn[old_addr]
        best_match = None
        best_score = 0.0

        for new_addr, cand_meta in new_fn.items():
            sim = compute_similarity(target_meta, cand_meta, None, None)
            if sim > best_score:
                best_score = sim
                best_match = new_addr

        if best_score >= args.threshold:
            results[name] = best_match
        else:
            results[name] = "0x0"

    with open(args.out_md, 'w', encoding='utf-8') as f:
        for k, v in results.items():
            f.write(f"{k:<42} = {v}\n")

if __name__ == '__main__':
    main()
