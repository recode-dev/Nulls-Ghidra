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
    p.add_argument('--threshold', type=float, default=0.55)
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

    old_fp_p = os.path.join(args.old_index, 'fingerprints.json')
    new_fp_p = os.path.join(args.new_index, 'fingerprints.json')

    old_fp = json.load(open(old_fp_p)) if os.path.exists(old_fp_p) else {}
    new_fp = json.load(open(new_fp_p)) if os.path.exists(new_fp_p) else {}

    results = {}
    matched_mapping = {}

    for name, old_addr in old_offs.items():
        if old_addr not in old_fn:
            continue
        old_meta = old_fn[old_addr]
        old_strs = set(old_meta.get('strings', []))
        if old_strs:
            best_cand = None
            best_overlap = 0
            for new_addr, new_meta in new_fn.items():
                overlap = len(old_strs.intersection(set(new_meta.get('strings', []))))
                if overlap > best_overlap:
                    best_overlap = overlap
                    best_cand = new_addr
            if best_cand and best_overlap >= min(1, len(old_strs)):
                results[name] = best_cand
                matched_mapping[old_addr] = best_cand

    for name, old_addr in old_offs.items():
        if name in results:
            continue
        if old_addr not in old_fn:
            results[name] = "0x0"
            continue

        old_meta = old_fn[old_addr]
        old_fprint = old_fp.get(old_addr, {})
        old_fields = set(old_fprint.get('fields_accessed', []))
        old_consts = set(old_fprint.get('math_constants', []))

        best_cand = None
        best_score = 0.0

        for new_addr, new_meta in new_fn.items():
            score = 0.0
            weight = 0.0

            old_callers = set(old_meta.get('callers', []))
            new_callers = set(new_meta.get('callers', []))
            propagated_callers = sum(1 for c in old_callers if matched_mapping.get(c) in new_callers)
            if old_callers:
                score += (propagated_callers / len(old_callers)) * 0.4
                weight += 0.4

            old_calls = set(old_meta.get('calls', []))
            new_calls = set(new_meta.get('calls', []))
            propagated_calls = sum(1 for c in old_calls if matched_mapping.get(c) in new_calls)
            if old_calls:
                score += (propagated_calls / len(old_calls)) * 0.3
                weight += 0.3

            new_fprint = new_fp.get(new_addr, {})
            new_fields = set(new_fprint.get('fields_accessed', []))
            new_consts = set(new_fprint.get('math_constants', []))

            if old_fields or new_fields:
                f_sim = len(old_fields.intersection(new_fields)) / max(1, len(old_fields.union(new_fields)))
                score += f_sim * 0.2
                weight += 0.2

            if old_consts or new_consts:
                c_sim = len(old_consts.intersection(new_consts)) / max(1, len(old_consts.union(new_consts)))
                score += c_sim * 0.1
                weight += 0.1

            sz1 = old_meta.get('size_chars', 0)
            sz2 = new_meta.get('size_chars', 0)
            if sz1 and sz2:
                sz_sim = min(sz1, sz2) / max(sz1, sz2)
                score += sz_sim * 0.1
                weight += 0.1

            final_sim = score / weight if weight > 0 else 0.0
            if final_sim > best_score:
                best_score = final_sim
                best_cand = new_addr

        if best_score >= args.threshold:
            results[name] = best_cand
            matched_mapping[old_addr] = best_cand
        else:
            results[name] = "0x0"

    with open(args.out_md, 'w', encoding='utf-8') as f:
        for k, v in results.items():
            f.write(f"{k:<42} = {v}\n")

if __name__ == '__main__':
    main()
