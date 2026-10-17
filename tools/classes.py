#!/usr/bin/env python3
import argparse
import json
import os

CLUSTER_GAP = 0x8000
CLUSTER_TIGHT = 0x2000
MIN_METHODS = 3
MIN_FIELDS = 2


def parse_args():
    p = argparse.ArgumentParser(description='Recover class layouts from vtables and field clustering')
    p.add_argument('--index_dir', default='index_data', help='index directory')
    p.add_argument('--out', default='', help='output classes JSON path')
    return p.parse_args()


def load(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def class_fields(fps, methods):
    fields = set()
    for m in methods:
        entry = fps.get(m)
        if entry:
            fields.update(entry.get('fields_accessed', []))
    return sorted(fields)


def flush(classes, cluster, fields):
    if len(cluster) >= MIN_METHODS and len(fields) >= MIN_FIELDS:
        key = f'ClusterClass_{cluster[0]}'
        classes.setdefault(key, {
            'vtable': None,
            'methods_count': len(cluster),
            'methods': list(cluster),
            'fields': sorted(fields),
        })


def main():
    args = parse_args()
    out_path = args.out or os.path.join(args.index_dir, 'classes.json')
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)

    fps = load(os.path.join(args.index_dir, 'fingerprints.json'), None)
    if fps is None:
        raise SystemExit(f'[-] {os.path.join(args.index_dir, "fingerprints.json")} not found')
    vtables = load(os.path.join(args.index_dir, 'vtables.json'), {})

    classes = {}
    for vt_addr, vt_data in vtables.items():
        methods = vt_data.get('methods', [])
        classes[f'VTableClass_{vt_addr}'] = {
            'vtable': vt_addr,
            'methods_count': len(methods),
            'methods': methods,
            'fields': class_fields(fps, methods),
        }

    offsets = sorted(int(k, 16) for k in fps)
    cluster = []
    fields = set()
    for offset in offsets:
        key = f'0x{offset:x}'
        current = set(fps[key].get('fields_accessed', []))
        if not cluster:
            cluster.append(key)
            fields.update(current)
            continue
        gap = offset - int(cluster[-1], 16)
        overlap = bool(fields.intersection(current))
        if gap < CLUSTER_GAP and (overlap or not current or gap < CLUSTER_TIGHT):
            cluster.append(key)
            fields.update(current)
        else:
            flush(classes, cluster, fields)
            cluster = [key]
            fields = set(current)
    flush(classes, cluster, fields)

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(classes, f, indent=2)

    print(f'[+] classes={len(classes)} -> {out_path}')


if __name__ == '__main__':
    main()
