#!/usr/bin/env python3
import argparse
import bisect
import hashlib
import json
import os
import re
import struct
import subprocess

from binary import FAT_MAGICS, MH_MAGIC_64, detect_base, macho_sections

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
    p.add_argument('--unwind', default='', help='unwind.json path, defaults to <out>/unwind.json')
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


def make_stub(rva, address, section):
    return {
        'name': f'unwind.{rva:x}',
        'address': address,
        'offset': rva,
        'return_type': '',
        'signature': f'unwind.{rva:x} ()',
        'args': 0,
        'section': f"{section['seg']}.{section['sect']}" if section else None,
        'size_bytes': None,
        'unwind': True,
        'size_chars': 0,
        'lines': 0,
        'depth': 0,
        'loops': 0,
        'branches': 0,
        'switches': 0,
        'hash': '',
        'strings': [],
        'calls': [],
        'call_sites': {},
        'callers': [],
        'unresolved_calls': [],
        'field_offsets': [],
        'field_writes': [],
        'consts': [],
        'data_refs': [],
        'floats': [],
    }


def arm64_text(data, offset=0):
    """Return (blob, vmaddr) of __TEXT.__text for the arm64 slice, or None."""
    if len(data) < offset + 32:
        return None
    magic = struct.unpack_from('<I', data, offset)[0]
    be = struct.unpack_from('>I', data, offset)[0]
    if magic in FAT_MAGICS or be in FAT_MAGICS:
        n = struct.unpack_from('>I', data, offset + 4)[0]
        for i in range(n):
            arch_off = struct.unpack_from('>I', data, offset + 8 + i * 20 + 8)[0]
            found = arm64_text(data, arch_off)
            if found:
                return found
        return None
    if magic != MH_MAGIC_64:
        return None
    cputype = struct.unpack_from('<i', data, offset + 4)[0]
    if cputype != 0x0100000c:  # CPU_TYPE_ARM64
        return None
    for section in macho_sections(data, offset):
        if section['sect'] == '__text' and section['size'] and (section['flags'] & 0x80000000):
            return data[section['fileoff']:section['fileoff'] + section['size']], section['addr']
    return None


def adrp_string_xrefs(bin_path, functions, strings):
    """Resolve string references via ADRP+ADD pairs in arm64 __TEXT.__text.

    r2ghidra renders most cstrings as a raw pointer constant (0x100xxxxxx), so
    STR_RE alone misses them. This pass decodes ADRP+ADD and attributes the
    referenced string back to the enclosing function.
    """
    with open(bin_path, 'rb') as f:
        data = f.read()
    located = arm64_text(data)
    if located is None:
        return {}
    blob, text_addr = located
    addr_to_string = {v['address']: k for k, v in strings.items() if v.get('address')}

    starts = sorted((v['address'], k) for k, v in functions.items() if v.get('address'))
    start_addrs = [s[0] for s in starts]

    def func_for(addr):
        i = bisect.bisect_right(start_addrs, addr) - 1
        if i < 0:
            return None
        return starts[i][1]

    result = {}
    off = 0
    limit = len(blob) - 3
    while off < limit:
        ins = struct.unpack_from('<I', blob, off)[0]
        off += 4
        if (ins & 0x9F000000) != 0x90000000:  # ADRP
            continue
        rd = ins & 0x1F
        immlo = (ins >> 29) & 0x3
        immhi = (ins >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = ((text_addr + off - 4) & ~0xFFF) + (imm << 12)
        for q in range(off, min(off + 16, limit), 4):
            ins2 = struct.unpack_from('<I', blob, q)[0]
            # ADD (immediate, 64-bit): add xN, xN, #imm12[, lsl 12]
            if (ins2 & 0xFF000000) == 0x91000000 and ((ins2 >> 5) & 0x1F) == rd:
                lo12 = (ins2 >> 10) & 0xFFF
                if (ins2 >> 22) & 0x1:
                    lo12 <<= 12
                target = (page + lo12) & 0xFFFFFFFFFFFFFFFF
            else:
                continue
            text_ = addr_to_string.get(target)
            if text_ is None:
                continue
            key = func_for(text_addr + off - 4)
            if key:
                result.setdefault(text_, set()).add(key)
            break
    return result


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


def parse_code(code_path, base, image_size, max_field, sections, unwind_starts):
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
            'unwind': rva in unwind_starts,
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

    # Merge __unwind_info starts that r2ghidra did not emit as separate
    # functions, so every authoritative boundary is searchable in the index.
    known_offsets = {int(k, 16) for k in functions}
    for rva in unwind_starts:
        if rva in known_offsets:
            continue
        address = base + rva
        functions[f'0x{rva:x}'] = make_stub(rva, address, section_of(sections, address))

    by_section = {}
    for entry in functions.values():
        if entry['section']:
            by_section.setdefault(entry['section'], set()).add(entry['offset'])
    for rva in unwind_starts:
        section = section_of(sections, base + rva)
        if section:
            by_section.setdefault(f"{section['seg']}.{section['sect']}", set()).add(rva)
    ends = {f"{s['seg']}.{s['sect']}": s['addr'] + s['size'] - base for s in sections}
    for name, offsets in by_section.items():
        ordered = sorted(offsets)
        for current, following in zip(ordered, ordered[1:]):
            key = f'0x{current:x}'
            if key in functions:
                functions[key]['size_bytes'] = following - current
        last = f'0x{ordered[-1]:x}'
        if last in functions and name in ends and ends[name] > ordered[-1]:
            functions[last]['size_bytes'] = ends[name] - ordered[-1]

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
    unwind_path = args.unwind or os.path.join(args.out, 'unwind.json')
    unwind_starts = set()
    if os.path.exists(unwind_path):
        with open(unwind_path) as f:
            unwind_starts = {int(v, 16) for v in json.load(f).get('starts', [])}
    functions, strings_xref, data_refs, edges = parse_code(args.code, base, image_size,
                                                           args.max_field_offset, sections,
                                                           unwind_starts)
    strings = bin_strings(args.bin, args.min_string)
    for entry in strings.values():
        entry['address'] = base + entry.pop('offset')

    for text_, keys in adrp_string_xrefs(args.bin, functions, strings).items():
        merged = set(strings_xref.get(text_, []))
        merged.update(keys)
        strings_xref[text_] = sorted(merged)

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
