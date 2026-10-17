#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import subprocess

from binary import detect_base, macho_sections

FUNC_RE = re.compile(
    r'\n([A-Za-z0-9_* ]+)\s+((?:fcn|sym\.func)\.([0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n?\s*\{'
)
CALL_RE = re.compile(r'(?:fcn|sym\.func)\.([0-9a-fA-F]+)')
STR_RE = re.compile(r'"([^"]{2,200})"')
PLUS_FIELD_RE = re.compile(r'\+\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\b')
INDEX_FIELD_RE = re.compile(r'\[\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\s*\]')
ASSIGN_RE = re.compile(
    r'(?:\[\s*(?:0x[0-9a-fA-F]{1,6}|\d{1,6})\s*\]|\+\s*(?:0x[0-9a-fA-F]{1,6}|\d{1,6})\s*\))\s*=(?!=)'
)
HEX_RE = re.compile(r'\b(0x[0-9a-fA-F]{4,16})\b')
FLOAT_RE = re.compile(r'\b\d+\.\d+(?:f)?\b')
IF_RE = re.compile(r'\bif\s*\(')
CASE_RE = re.compile(r'\bcase\b')
GOTO_RE = re.compile(r'\bgoto\b')
SWITCH_RE = re.compile(r'\bswitch\s*\(')
LOOP_RE = re.compile(r'\b(while|for|do)\b')
CODE_MARKERS = (';', '{', '}', 'fcn.', 'Var', '\\n', '\\x')


def parse_args():
    p = argparse.ArgumentParser(description='Index functions, strings, xrefs and call graph of a decompiled dump')
    p.add_argument('--bin', required=True, help='Mach-O binary the dump was produced from')
    p.add_argument('--code', required=True, help='decompiled.c')
    p.add_argument('--out', default='index_data', help='output index directory')
    p.add_argument('--max-field-offset', type=lambda v: int(v, 0), default=0x20000,
                   help='largest value treated as a struct field offset')
    p.add_argument('--min-string', type=int, default=4, help='shortest binary string to keep')
    return p.parse_args()


def bin_strings(path, min_len):
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
        if len(parts) != 2 or len(parts[1]) < min_len:
            continue
        try:
            offset = int(parts[0], 16)
        except ValueError:
            continue
        text = parts[1]
        entry = out.setdefault(text, {'offset': offset, 'size': len(text), 'count': 0})
        entry['count'] += 1
    return out


def usable_string(text):
    return len(text) >= 3 and not any(marker in text for marker in CODE_MARKERS)


def to_int(token):
    return int(token, 16) if token.lower().startswith('0x') else int(token)


def depth_of(body):
    level = deepest = 0
    for char in body:
        if char == '{':
            level += 1
            deepest = max(deepest, level)
        elif char == '}':
            level -= 1
    return max(0, deepest - 1)


def parse_args_list(raw):
    items = []
    current = ''
    level = 0
    for char in raw:
        if char in '([{':
            level += 1
        elif char in ')]}':
            level -= 1
        if char == ',' and level == 0:
            items.append(current.strip())
            current = ''
        else:
            current += char
    if current.strip():
        items.append(current.strip())
    return items


def exec_sections(path):
    with open(path, 'rb') as f:
        data = f.read()
    return [s for s in macho_sections(data) if s['size'] and s['flags'] & 0x80000000]


def section_of(sections, address):
    for section in sections:
        if section['addr'] <= address < section['addr'] + section['size']:
            return section
    return None


def parse_code(code_path, base, image_size, max_field, sections):
    with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    matches = list(FUNC_RE.finditer(text))
    functions = {}
    strings_xref = {}
    data_refs = {}

    for i, m in enumerate(matches):
        try:
            address = int(m.group(3), 16)
        except ValueError:
            continue
        rva = address - base if address >= base else address
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[m.start():end]

        strings = []
        for s in STR_RE.findall(body):
            if usable_string(s) and s not in strings:
                strings.append(s)

        call_sites = {}
        for c in CALL_RE.findall(body[body.find('{'):]):
            target = int(c, 16)
            target = target - base if target >= base else target
            call_sites[target] = call_sites.get(target, 0) + 1

        reads = set()
        writes = set()
        consts = set()
        refs = set()
        for token in PLUS_FIELD_RE.findall(body) + INDEX_FIELD_RE.findall(body):
            value = to_int(token)
            if value < max_field:
                reads.add(value)
        for token in ASSIGN_RE.findall(body):
            match = re.search(r'0x[0-9a-fA-F]{1,6}|\d{1,6}', token)
            if match:
                value = to_int(match.group(0))
                if value < max_field:
                    writes.add(value)
        for token in HEX_RE.findall(body):
            value = int(token, 16)
            if value < max_field:
                continue
            if base <= value < base + image_size:
                refs.add(value)
            else:
                consts.add(value)

        args = parse_args_list(m.group(4))
        key = f'0x{rva:x}'
        functions[key] = {
            'name': m.group(2),
            'address': address,
            'offset': rva,
            'return_type': m.group(1).strip(),
            'signature': f"{m.group(1).strip()} ({', '.join(args)})" if args else f'{m.group(1).strip()} ()',
            'args': len(args),
            'section': (lambda s: f"{s['seg']}.{s['sect']}" if s else None)(section_of(sections, address)),
            'size_bytes': None,
            'size_chars': len(body),
            'lines': len(body.splitlines()),
            'depth': depth_of(body),
            'loops': len(LOOP_RE.findall(body)),
            'branches': len(IF_RE.findall(body)) + len(CASE_RE.findall(body)) + len(GOTO_RE.findall(body)),
            'switches': len(SWITCH_RE.findall(body)),
            'hash': hashlib.md5(body.encode('utf-8', 'ignore')).hexdigest()[:16],
            'strings': strings,
            'calls': [f'0x{t:x}' for t in sorted(call_sites)],
            'call_sites': {f'0x{t:x}': n for t, n in sorted(call_sites.items())},
            'callers': [],
            'unresolved_calls': [],
            'field_offsets': sorted(reads | writes),
            'field_writes': sorted(writes),
            'consts': [f'0x{c:x}' for c in sorted(consts)],
            'data_refs': [f'0x{c:x}' for c in sorted(refs)],
            'floats': sorted(set(FLOAT_RE.findall(body)))[:30],
        }

        for s in strings:
            strings_xref.setdefault(s, []).append(key)
        for ref in sorted(refs):
            data_refs.setdefault(f'0x{ref:x}', []).append(key)

    by_section = {}
    for key, entry in functions.items():
        by_section.setdefault(entry['section'], []).append(entry['offset'])
    for offsets in by_section.values():
        offsets.sort()
        for current, following in zip(offsets, offsets[1:]):
            functions[f'0x{current:x}']['size_bytes'] = following - current

    for key, entry in functions.items():
        for callee in entry['calls']:
            if callee in functions:
                if callee != key:
                    functions[callee]['callers'].append(key)
            else:
                entry['unresolved_calls'].append(callee)
        entry['leaf'] = not entry['calls']
        entry['recursive'] = key in entry['calls']

    for address, refs in data_refs.items():
        key = f'0x{int(address, 16) - base:x}'
        if key in functions:
            functions[key]['address_refs'] = refs

    edges = [[key, callee, sites]
             for key, entry in functions.items()
             for callee, sites in entry['call_sites'].items() if callee in functions]

    return functions, strings_xref, data_refs, edges


def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)

    base = detect_base(args.bin)
    image_size = os.path.getsize(args.bin)
    sections = exec_sections(args.bin)
    functions, strings_xref, data_refs, edges = parse_code(args.code, base, image_size,
                                                           args.max_field_offset, sections)
    strings = bin_strings(args.bin, args.min_string)
    for entry in strings.values():
        entry['address'] = base + entry.pop('offset')

    outputs = {
        'functions.json': functions,
        'strings_xref.json': strings_xref,
        'strings.json': strings,
        'data_refs.json': data_refs,
        'callgraph.json': edges,
    }
    for name, payload in outputs.items():
        with open(os.path.join(args.out, name), 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False)

    sizes = [v['size_bytes'] for v in functions.values() if v['size_bytes']]
    unresolved = sum(len(v['unresolved_calls']) for v in functions.values())
    outside = sum(1 for v in functions.values() if v['section'] is None)
    print(f'[+] base=0x{base:x} functions={len(functions)} outside_sections={outside} edges={len(edges)} '
          f'strings={len(strings)} data_refs={len(data_refs)} '
          f'unresolved={unresolved} median_size={sorted(sizes)[len(sizes) // 2] if sizes else 0} '
          f'-> {args.out}')


if __name__ == '__main__':
    main()
