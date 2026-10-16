#!/usr/bin/env python3
import json
import os
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--index_dir', default='index_data')
    p.add_argument('--out', default='index_data/classes.json')
    return p.parse_args()

def main():
    args = parse_args()
    fp_path = os.path.join(args.index_dir, 'fingerprints.json')
    fn_path = os.path.join(args.index_dir, 'functions.json')

    if not os.path.exists(fp_path):
        return

    with open(fp_path, 'r', encoding='utf-8') as f:
        fps = json.load(f)

    with open(fn_path, 'r', encoding='utf-8') as f:
        funcs = json.load(f)

    classes = {}
    func_offsets = sorted([int(k, 16) for k in fps.keys()])

    current_cluster = []
    cluster_fields = set()

    for i in range(len(func_offsets)):
        curr = func_offsets[i]
        curr_str = f"0x{curr:x}"
        curr_fields = set(fps[curr_str].get('fields_accessed', []))

        if not current_cluster:
            current_cluster.append(curr_str)
            cluster_fields.update(curr_fields)
            continue

        prev = func_offsets[i - 1]
        dist = curr - prev
        overlap = len(cluster_fields.intersection(curr_fields))

        if dist < 0x8000 and (overlap > 0 or not curr_fields or dist < 0x2000):
            current_cluster.append(curr_str)
            cluster_fields.update(curr_fields)
        else:
            if len(current_cluster) >= 3 and len(cluster_fields) >= 2:
                base_addr = current_cluster[0]
                classes[f"Class_{base_addr}"] = {
                    "methods_count": len(current_cluster),
                    "methods": current_cluster,
                    "fields": sorted(list(cluster_fields))
                }
            current_cluster = [curr_str]
            cluster_fields = set(curr_fields)

    if len(current_cluster) >= 3:
        base_addr = current_cluster[0]
        classes[f"Class_{base_addr}"] = {
            "methods_count": len(current_cluster),
            "methods": current_cluster,
            "fields": sorted(list(cluster_fields))
        }

    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(classes, f, indent=2)

if __name__ == '__main__':
    main()
