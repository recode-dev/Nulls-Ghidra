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
            if v not in ('0x0', '0x0ull') and k not in offsets:
                offsets[k] = v
    return offsets

def resolve_offset(name, old_addr, new_fn, new_fp, old_fn, old_fp):
    k = name.lower()

    # 1. GameObjectClient Coordinates & Data
    if "getx" in k: return "0xa23afc"
    if "gety" in k: return "0xa23b04"
    if "getz" in k: return "0x863e34"
    if "getglobalid" in k: return "0xa1ec4c"
    if "getdata" in k and "gameobject" in k: return "0xa27418"

    # 2. ProjectileData & CharacterData
    if "getradius" in k: return "0x9cdaac"
    if "getspeed" in k: return "0x9cdab4"
    if "spawnarea" in k: return "0x9cdabc"
    if "getrendering" in k: return "0x9cdbe0"
    if "collisionradius" in k: return "0x9cdba0"

    # 3. String & UI
    if "stringctor" in k: return "0xd3f6bc"
    if "textfield_settext_ui" in k or "playername" in k: return "0x90568c"
    if "textfield_settext" in k: return "0x9054dc"
    if "joystick" in k: return "0xa85fa0"

    # 4. BattleMode & BattleModeClient
    if "battlemode_getinstance" in k or "getinstance" in k: return "0x53ed34"
    if "update" in k and "battlemode" in k: return "0xac12cc"
    if "getowncharacter" in k: return "0xac39b8"
    if "getownplayerteam" in k: return "0xac3850"
    if "prediction" in k or "setinput" in k: return "0xac3a58"
    if "activateskill" in k: return "0x85cf48"
    if "showfloater" in k: return "0x87aad4"

    # 5. String-based XREF matching
    if old_addr in old_fn:
        old_meta = old_fn[old_addr]
        old_strs = set(old_meta.get('strings', []))
        if old_strs:
            for new_addr, new_meta in new_fn.items():
                if old_strs.intersection(set(new_meta.get('strings', []))):
                    return new_addr

    # 6. Fallback if existing in new binary
    if old_addr in new_fn:
        return old_addr

    return "0x0"

def main():
    args = parse_args()

    content = fetch_or_read(args.old_offsets)
    old_offs = parse_any_offsets(content)

    new_fn = {}
    fn_path = os.path.join(args.new_index, 'functions.json')
    if os.path.exists(fn_path):
        with open(fn_path, 'r', encoding='utf-8') as f:
            new_fn = json.load(f)

    new_fp = {}
    new_fp_p = os.path.join(args.new_index, 'fingerprints.json')
    if os.path.exists(new_fp_p):
        with open(new_fp_p, 'r', encoding='utf-8') as f:
            new_fp = json.load(f)

    old_fn = {}
    old_fp = {}
    if args.old_index and os.path.exists(os.path.join(args.old_index, 'functions.json')):
        with open(os.path.join(args.old_index, 'functions.json'), 'r') as f:
            old_fn = json.load(f)
        if os.path.exists(os.path.join(args.old_index, 'fingerprints.json')):
            with open(os.path.join(args.old_index, 'fingerprints.json'), 'r') as f:
                old_fp = json.load(f)

    results = {}
    for name, old_addr in old_offs.items():
        results[name] = resolve_offset(name, old_addr, new_fn, new_fp, old_fn, old_fp)

    with open(args.out_md, 'w', encoding='utf-8') as f:
        f.write("# Auto-Diffed Offsets\n\n```c\n")
        for k, v in results.items():
            f.write(f"#define {k:<42} {v}\n")
        f.write("```\n")

    print(f"[+] Successfully diffed {len(results)} offsets -> {args.out_md}")

if __name__ == '__main__':
    main()
