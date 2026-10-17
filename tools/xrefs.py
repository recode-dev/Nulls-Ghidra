#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess

from binary import detect_base

FUNC_RE = re.compile(
    r'\n([A-Za-z0-9_* ]+)\s+((?:fcn|sym\.func)\.([0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n?\s*\{'
)
CALL_RE = re.compile(r'(?:fcn|sym\.func)\.([0-9a-fA-F]+)')
STR_RE = re.compile(r'"([^"]{2,200})"')
FIELD_RE = re.compile(r'\+\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\b')
LOOP_RE = re.compile(r'\b(while|for|do)\b')
CODE_MARKERS = (';', '{', '}', 'fcn.', 'Var', '\\n', '\\x')


def parse_args():
    p = argparse.ArgumentParser(description='Index functions, strings, xrefs and the call graph of a decompiled dump')
    p.add_argument('--bin', required=True, help='Mach-O / ELF binary the dump was produced from')
    p.add_argument('--code', required=True, help='decompiled.c')
    p.add_argument('--out', default='index_data', help='output index directory')
    p.add_argument('--max-field-offset', type=lambda v: int(v, 0), default=0x20000,
                   help='largest value treated as a struct field offset')
    p.add_argument('--min-string', type=int, default=4, help='shortest binary string to keep')
    return p.parse_args()


def bin_strings(path, min_len=4):
    out = {}
    if not os.path.exists(path):
        return out
    try:
        raw = subprocess.check_output(['strings', '-a', '-t', 'x', path],
                                      stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
    except (OSError, subprocess.CalledProcessError):
        return out
    for line in raw.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        text = parts[1]
        if len(text) < min_len:
            continue
        try:
            out[text] = int(parts[0], 16)
        except ValueError:
            continue
    return out


def usable_string(text):
    if len(text) < 3:
        return False
    return not any(marker in text for marker in CODE_MARKERS)


def parse_code(code_path, base, max_field):
    with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    matches = list(FUNC_RE.finditer(text))
    functions = {}
    strings_xref = {}

    for i, m in enumerate(matches):
        try:
            addr = int(m.group(3), 16)
        except ValueError:
            continue
        rva = addr - base if addr >= base else addr
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[m.start():end]

        strings = []
        for s in STR_RE.findall(body):
            if usable_string(s) and s not in strings:
                strings.append(s)

        calls = []
        for c in CALL_RE.findall(body):
            try:
                c_addr = int(c, 16)
            except ValueError:
                continue
            c_rva = c_addr - base if c_addr >= base else c_addr
            if c_rva != rva and c_rva not in calls:
                calls.append(c_rva)

        consts = []
        fields = []
        for token in FIELD_RE.findall(body):
            value = int(token, 16) if token.lower().startswith('0x') else int(token)
            if value < max_field:
                if value not in fields:
                    fields.append(value)
            elif value not in consts:
                consts.append(value)

        key = f'0x{rva:x}'
        functions[key] = {
            'name': m.group(2),
            'address': addr,
            'offset': rva,
            'return_type': m.group(1).strip(),
            'size_chars': len(body),
            'lines': len(body.splitlines()),
            'strings': strings,
            'calls': [f'0x{c:x}' for c in calls],
            'callers': [],
            'consts': [f'0x{c:x}' for c in consts],
            'field_offsets': sorted(fields),
            'loops': len(LOOP_RE.findall(body)),
        }

        for s in strings:
            strings_xref.setdefault(s, []).append(key)

    for key, data in functions.items():
        for callee in data['calls']:
            if callee in functions:
                functions[callee]['callers'].append(key)

    return functions, strings_xref


def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)

    base = detect_base(args.bin)
    functions, strings_xref = parse_code(args.code, base, args.max_field_offset)
    strings = bin_strings(args.bin, args.min_string)

    with open(os.path.join(args.out, 'functions.json'), 'w', encoding='utf-8') as f:
        json.dump(functions, f, ensure_ascii=False)
    with open(os.path.join(args.out, 'strings_xref.json'), 'w', encoding='utf-8') as f:
        json.dump(strings_xref, f, ensure_ascii=False)
    with open(os.path.join(args.out, 'strings.json'), 'w', encoding='utf-8') as f:
        json.dump(strings, f, ensure_ascii=False)

    withstr = sum(1 for v in functions.values() if v['strings'])
    edges = sum(len(v['calls']) for v in functions.values())
    print(f'[+] base=0x{base:x} functions={len(functions)} with_strings={withstr} '
          f'edges={edges} strings={len(strings)} -> {args.out}')


if __name__ == '__main__':
    main()
