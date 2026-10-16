#!/usr/bin/env python3
import json
import os
import argparse

def parse_args():
    p = argparse.ArgumentParser(description="Reconstruct C++ class layouts from VTables and field clustering")
    p.add_argument('--index_dir', default='index_data', help="Path to index directory")
    p.add_argument('--out', default='', help="Output classes JSON path")
    return p.parse_args()

def main():
    args = parse_args()
    out_path = args.out or os.path.join(args.index_dir, 'classes.json')
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    fp_path = os.path.join(args.index_dir, 'fingerprints.json')
    fn_path = os.path.join(args.index_dir, 'functions.json')
    vt_path = os.path.join(args.index_dir, 'vtables.json')

    if not os.path.exists(fp_path):
        return

    with open(fp_path, 'r', encoding='utf-8') as f:
        fps = json.load(f)

    vtables = {}
    if os.path.exists(vt_path):
        with open(vt_path, 'r', encoding='utf-8') as f:
            vtables = json.load(f)

    classes = {}

    # 1. Classes reconstructed directly from VTables
    for vt_addr, vt_data in vtables.items():
        ctors = vt_data.get("ctors", [])
        methods = vt_data.get("methods", [])
        cls_key = f"VTableClass_{vt_addr}"
        
        all_fields = set()
        for m in ctors + methods:
            if m in fps:
                all_fields.update(fps[m].get("fields_accessed", []))

        classes[cls_key] = {
            "vtable": vt_addr,
            "ctors": ctors,
            "methods_count": len(methods),
            "methods": methods,
            "fields": sorted(list(all_fields))
        }

    # 2. Spatial locality and field clustering
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
                cls_key = f"ClusterClass_{base_addr}"
                if cls_key not in classes:
                    classes[cls_key] = {
                        "vtable": None,
                        "ctors": [base_addr],
                        "methods_count": len(current_cluster),
                        "methods": current_cluster,
                        "fields": sorted(list(cluster_fields))
                    }
            current_cluster = [curr_str]
            cluster_fields = set(curr_fields)

    if len(current_cluster) >= 3 and len(cluster_fields) >= 2:
        base_addr = current_cluster[0]
        cls_key = f"ClusterClass_{base_addr}"
        if cls_key not in classes:
            classes[cls_key] = {
                "vtable": None,
                "ctors": [base_addr],
                "methods_count": len(current_cluster),
                "methods": current_cluster,
                "fields": sorted(list(cluster_fields))
            }

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(classes, f, indent=2)

    print(f"[+] Reconstructed {len(classes)} classes -> {out_path}")

if __name__ == '__main__':
    main()
