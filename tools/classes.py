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
    if len(cluster) < MIN_METHODS or len(fields) < MIN_FIELDS:
        return
    # fold the cluster into the vtable class it overlaps most, if any
    best = None
    for name, entry in classes.items():
        if entry.get('vtable') is None:
            continue
        shared = len(fields.intersection(entry['fields']))
        if shared >= MIN_FIELDS and shared * 2 >= len(fields) and (best is None or shared > best[1]):
            best = (name, shared)
    if best:
        target = classes[best[0]]
        target['methods'].extend(m for m in cluster if m not in target['methods'])
        target['methods_count'] = len(target['methods'])
        target['clusters'] = target.get('clusters', 0) + 1
        return
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
        if vt_data.get('alias_of') or vt_data.get('kind', 'vtable') != 'vtable':
            continue
        methods = vt_data.get('methods', [])
        header = vt_data.get('header') or {}
        name = header.get('class_name') or f'VTableClass_{vt_addr}'
        entry = {
            'vtable': vt_addr,
            'methods_count': len(methods),
            'methods': methods,
            'fields': class_fields(fps, methods),
            'aliases': len(vt_data.get('aliases', [])),
        }
        if header.get('class_name'):
            entry['typeinfo'] = header.get('typeinfo_name')
        if vt_data.get('extends'):
            entry['extends'] = vt_data['extends']
        if vt_data.get('roles'):
            entry['roles'] = vt_data['roles']
        if name in classes:
            existing = classes[name]
            existing['methods'].extend(m for m in methods if m not in existing['methods'])
            existing['methods_count'] = len(existing['methods'])
            existing['aliases'] += 1
        else:
            classes[name] = entry

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
