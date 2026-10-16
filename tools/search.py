#!/usr/bin/env python3
import json
import os
import sys
import argparse

def parse_args():
    p = argparse.ArgumentParser(description='Universal Index Search CLI')
    p.add_argument('--index_dir', default='index_data')
    p.add_argument('--str', help='Search string')
    p.add_argument('--field', help='Search field offset (e.g. 0x1d0)')
    p.add_argument('--const', help='Search constant (e.g. 0x7fffffff)')
    p.add_argument('--fn', help='Inspect function offset (e.g. 0x7a60f4)')
    p.add_argument('--role', help='Filter by role (root_update_loop, leaf_math, etc.)')
    return p.parse_args()

def main():
    args = parse_args()
    
    strings_file = os.path.join(args.index_dir, 'strings_xref.json')
    funcs_file = os.path.join(args.index_dir, 'functions.json')
    fingerprints_file = os.path.join(args.index_dir, 'fingerprints.json')

    if args.str:
        if os.path.exists(strings_file):
            with open(strings_file, 'r', encoding='utf-8') as f:
                sx = json.load(f)
            matches = {k: v for k, v in sx.items() if args.str.lower() in k.lower()}
            print(f"[*] Found {len(matches)} matching strings:")
            for s, fns in list(matches.items())[:30]:
                print(f"  \"{s}\" -> {fns}")
        return

    if args.fn:
        if os.path.exists(funcs_file):
            with open(funcs_file, 'r', encoding='utf-8') as f:
                fn_data = json.load(f)
            data = fn_data.get(args.fn)
            if data:
                print(f"[*] Function {args.fn}:")
                print(f"  Return: {data.get('return_type')}")
                print(f"  Args:   {data.get('args')}")
                print(f"  Size:   {data.get('size_chars')} chars")
                print(f"  Strings: {data.get('strings')}")
                print(f"  Calls:   {data.get('calls')[:15]}")
                print(f"  Callers: {data.get('callers')[:15]}")
            else:
                print(f"[-] Function {args.fn} not found.")
        return

    if args.field or args.const or args.role:
        if os.path.exists(fingerprints_file):
            with open(fingerprints_file, 'r', encoding='utf-8') as f:
                fp_data = json.load(f)
            results = []
            for off, fp in fp_data.items():
                match = True
                if args.field and args.field not in fp.get('fields_accessed', []):
                    match = False
                if args.const and args.const not in fp.get('math_constants', []):
                    match = False
                if args.role and fp.get('topology_role') != args.role:
                    match = False
                if match:
                    results.append((off, fp))
            print(f"[*] Found {len(results)} matching functions:")
            for off, fp in results[:40]:
                print(f"  {off:<12} lines={fp.get('lines',0):<5} role={fp.get('topology_role'):<20} fields={fp.get('fields_accessed',[])[:5]}")
        return

if __name__ == '__main__':
    main()
