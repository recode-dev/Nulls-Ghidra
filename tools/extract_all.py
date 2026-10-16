#!/usr/bin/env python3
import argparse
import json
import os
import re
import struct
import subprocess

FUNC_RE = re.compile(
    r'\n([A-Za-z0-9_* ]+)\s+((?:fcn|sym\.func)\.([0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n?\s*\{'
)
CALL_RE = re.compile(r'(?:fcn|sym\.func)\.([0-9a-fA-F]+)')
STR_RE = re.compile(r'"([^"]{2,200})"')
FIELD_RE = re.compile(r'\+\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\b')
LOOP_RE = re.compile(r'\b(while|for|do)\b')
CODE_MARKERS = (';', '{', '}', 'fcn.', 'Var', '\\n', '\\x')


def parse_args():
    p = argparse.ArgumentParser(description='Index a decompiled Supercell binary dump')
    p.add_argument('--bin', required=True, help='path to Mach-O / ELF binary')
    p.add_argument('--code', required=True, help='path to decompiled.c')
    p.add_argument('--out', default='index_data', help='output index directory')
    p.add_argument('--ver', default='unknown', help='version tag')
    p.add_argument('--max-field-offset', type=lambda v: int(v, 0), default=0x20000,
                   help='largest value treated as a struct field offset')
    return p.parse_args()


def macho_base(data, offset=0):
    if len(data) < offset + 32:
        return None
    magic = struct.unpack_from('<I', data, offset)[0]
    if magic in (0xcafebabe, 0xcafebabf) or struct.unpack_from('>I', data, offset)[0] in (0xcafebabe, 0xcafebabf):
        n = struct.unpack_from('>I', data, offset + 4)[0]
        best = None
        for i in range(n):
            arch_off = struct.unpack_from('>I', data, offset + 8 + i * 20 + 8)[0]
            candidate = macho_base(data, arch_off)
            if candidate is not None and (best is None or candidate < best):
                best = candidate
        return best
    if magic != 0xfeedfacf:
        return None
    ncmds = struct.unpack_from('<I', data, offset + 16)[0]
    cur = offset + 32
    base = None
    for _ in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, size = struct.unpack_from('<II', data, cur)
        if cmd == 0x19 and size >= 72 and cur + 68 <= len(data):
            vmaddr, _vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, cur + 24)
            initprot = struct.unpack_from('<i', data, cur + 64)[0]
            if (initprot & 0x4) and filesize > 0:
                value = vmaddr - fileoff
                if base is None or value < base:
                    base = value
        if size <= 0:
            break
        cur += size
    return base


def elf_base(data):
    if data[:4] != b'\x7fELF':
        return None
    is64 = data[4] == 2
    try:
        if is64:
            phoff = struct.unpack_from('<Q', data, 0x20)[0]
            phentsize = struct.unpack_from('<H', data, 0x36)[0]
            phnum = struct.unpack_from('<H', data, 0x38)[0]
        else:
            phoff = struct.unpack_from('<I', data, 0x1c)[0]
            phentsize = struct.unpack_from('<H', data, 0x2a)[0]
            phnum = struct.unpack_from('<H', data, 0x2c)[0]
    except struct.error:
        return None
    base = None
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + phentsize > len(data):
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr = struct.unpack_from('<IIQQ', data, off)
        else:
            p_type, p_offset, p_vaddr, p_flags = struct.unpack_from('<IIII', data, off)
        if p_type == 1 and (p_flags & 0x1):
            value = p_vaddr - p_offset
            if base is None or value < base:
                base = value
    return base


def detect_base(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(1 << 20)
    except OSError:
        return 0
    base = elf_base(head) if head[:4] == b'\x7fELF' else macho_base(head)
    return base if base else 0


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


def scan_vtables(bin_path, functions, base, min_slots=3):
    vtables = {}
    if not os.path.exists(bin_path) or not functions:
        return vtables
    starts = {v['offset'] for v in functions.values()}
    try:
        with open(bin_path, 'rb') as f:
            data = f.read()
    except OSError:
        return vtables
    aligned = len(data) - (len(data) % 8)
    mask = (1 << 48) - 1
    run = []
    run_start = 0
    for index, (value,) in enumerate(struct.iter_unpack('<Q', memoryview(data)[:aligned])):
        candidate = value & mask
        if candidate >= base:
            candidate -= base
        if candidate in starts:
            if not run:
                run_start = index * 8
            run.append(candidate)
        else:
            if len(run) >= min_slots:
                vtables[f'0x{run_start:x}'] = {
                    'source': 'binary_scan',
                    'slots': len(run),
                    'methods': [f'0x{c:x}' for c in run],
                }
            run = []
    if len(run) >= min_slots:
        vtables[f'0x{run_start:x}'] = {
            'source': 'binary_scan',
            'slots': len(run),
            'methods': [f'0x{c:x}' for c in run],
        }
    return vtables


def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)

    base = detect_base(args.bin)
    functions, strings_xref = parse_code(args.code, base, args.max_field_offset)
    strings = bin_strings(args.bin)
    vtables = scan_vtables(args.bin, functions, base)

    with open(os.path.join(args.out, 'functions.json'), 'w', encoding='utf-8') as f:
        json.dump(functions, f, ensure_ascii=False)
    with open(os.path.join(args.out, 'strings_xref.json'), 'w', encoding='utf-8') as f:
        json.dump(strings_xref, f, ensure_ascii=False)
    with open(os.path.join(args.out, 'strings.json'), 'w', encoding='utf-8') as f:
        json.dump(strings, f, ensure_ascii=False)
    with open(os.path.join(args.out, 'vtables.json'), 'w', encoding='utf-8') as f:
        json.dump(vtables, f, ensure_ascii=False)

    withstr = sum(1 for v in functions.values() if v['strings'])
    print(f'[+] base=0x{base:x} functions={len(functions)} with_strings={withstr} '
          f'vtables={len(vtables)} strings={len(strings)} -> {args.out}')


if __name__ == '__main__':
    main()
