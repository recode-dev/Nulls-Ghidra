#!/usr/bin/env python3

import argparse
import array
import bisect
import hashlib
import json
import math
import os
import re
import struct
import sys

from binary import BadImage, CPU_TYPE_ARM64, macho_image

FUNC_RE = re.compile(
    r'\n([A-Za-z0-9_* ]+)\s+((?:fcn|sym\.func)\.([0-9a-fA-F]+))\s*\(([^)]*)\)\s*\n?\s*\{'
)
CALL_RE = re.compile(r'(?:fcn|sym\.func)\.([0-9a-fA-F]+)')
GENERIC_FUNC_RE = re.compile(
    r'\n([A-Za-z0-9_* ]+?)\s+([A-Za-z_$][A-Za-z0-9_.$:~]*)\s*\(([^)]*)\)\s*\n?\s*\{'
)
NAME_CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_.:~]*)\s*\(')
VCALL_RE = re.compile(
    r'\*\*\s*\(\s*code\s*\*\s*\*\s*\)\s*\(\s*\*?\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*'
    r'(0x[0-9a-fA-F]+|\d+)\s*\)'
)
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
STRING_SECTIONS = ('__cstring', '__objc_methname', '__objc_classname', '__objc_methtype')


def parse_args():
    p = argparse.ArgumentParser(description='Index functions, strings, xrefs and call graph of a decompiled dump')
    p.add_argument('--bin', help='Mach-O binary the dump was produced from')
    p.add_argument('--code', help='decompiled.c')
    p.add_argument('--out', default='index_data', help='output index directory')
    p.add_argument('--max-field-offset', type=lambda v: int(v, 0), default=0x20000,
                   help='largest value treated as a struct field offset')
    p.add_argument('--min-string', type=int, default=4, help='shortest binary string to keep')
    p.add_argument('--unwind', default='', help='unwind.json path, defaults to <out>/unwind.json')
    p.add_argument('--names', default='', help='symbol map {name: address} for renamed functions')
    p.add_argument('--query', default='', help='search the existing index by words or by a hex offset, no rebuild')
    p.add_argument('--limit', type=int, default=20, help='maximum rows printed by --query')
    return p.parse_args()


def bin_strings(data, sections, min_len):
    out = {}
    for section in sections:
        if section['sect'] not in STRING_SECTIONS or not section['size']:
            continue
        blob = data[section['fileoff']:section['fileoff'] + section['size']]
        pos = 0
        while pos < len(blob):
            end = blob.find(b'\0', pos)
            if end < 0:
                break
            if end - pos >= min_len:
                text = blob[pos:end].decode('utf-8', 'replace')
                if text.isprintable():
                    entry = out.setdefault(text, {'address': section['addr'] + pos,
                                                  'size': end - pos, 'count': 0})
                    entry['count'] += 1
            pos = end + 1
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
        'line': 0,
        'strings': [],
        'calls': [],
        'call_sites': {},
        'callers': [],
        'unresolved_calls': [],
        'vcall_slots': [],
        'field_offsets': [],
        'field_writes': [],
        'consts': [],
        'data_refs': [],
        'floats': [],
    }


def arm64_text(data, sections):
    for section in sections:
        if section['sect'] == '__text' and section['size'] and section['flags'] & 0x80000000:
            return data[section['fileoff']:section['fileoff'] + section['size']], section['addr']
    return None


def adrp_string_xrefs(data, located, sections, functions, strings):
    blob, text_addr = located
    addr_to_string = {v['address']: k for k, v in strings.items() if v.get('address')}
    for section in sections:
        if section['sect'] != '__cfstring' or not section['size']:
            continue
        for struct_addr in range(section['addr'], section['addr'] + section['size'] - 31, 32):
            position = section['fileoff'] + struct_addr - section['addr'] + 16
            if position + 8 > len(data):
                break
            text_ptr = struct.unpack_from('<Q', data, position)[0]
            text_ = addr_to_string.get(text_ptr)
            if text_:
                addr_to_string.setdefault(struct_addr, text_)

    starts = sorted((v['address'], k) for k, v in functions.items() if v.get('address'))
    start_addrs = [s[0] for s in starts]

    def func_for(addr):
        i = bisect.bisect_right(start_addrs, addr) - 1
        if i < 0:
            return None
        return starts[i][1]

    def deref(address):
        for section in sections:
            if section['addr'] <= address < section['addr'] + section['size']:
                off = section['fileoff'] + address - section['addr']
                if 0 <= off <= len(data) - 8:
                    return struct.unpack_from('<Q', data, off)[0]
                break
        return None

    result = {}
    off = 0
    limit = len(blob) - 3
    while off < limit:
        ins = struct.unpack_from('<I', blob, off)[0]
        site = off
        off += 4
        if (ins & 0x9F000000) != 0x90000000:
            continue
        rd = ins & 0x1F
        immlo = (ins >> 29) & 0x3
        immhi = (ins >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = ((text_addr + site) & ~0xFFF) + (imm << 12)
        target = None
        for q in range(off, min(off + 32, limit), 4):
            ins2 = struct.unpack_from('<I', blob, q)[0]
            if (ins2 & 0xFF000000) == 0x91000000 and ((ins2 >> 5) & 0x1F) == rd:
                lo12 = (ins2 >> 10) & 0xFFF
                if (ins2 >> 22) & 0x1:
                    lo12 <<= 12
                target = (page + lo12) & 0xFFFFFFFFFFFFFFFF
            elif (ins2 & 0xFFC00000) == 0xF9400000 and ((ins2 >> 5) & 0x1F) == rd:
                slot = page + ((ins2 >> 10) & 0xFFF) * 8
                value = deref(slot)
                if value and value in addr_to_string:
                    target = value
                elif value:
                    inner = deref(value + 16)
                    if inner in addr_to_string:
                        target = inner
            else:
                continue
            if target is not None:
                break
        else:
            continue
        text_ = addr_to_string.get(target)
        if text_ is None:
            continue
        key = func_for(text_addr + site)
        if key:
            result.setdefault(text_, set()).add(key)
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


def section_of(sections, address):
    for section in sections:
        if section['addr'] <= address < section['addr'] + section['size']:
            return section
    return None


def parse_code(code_path, base, image_size, max_field, sections, unwind_starts,
               prologue_starts=None, name_map=None):
    with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    name_map = name_map or {}
    found = [(m.start(), m.group(1), m.group(2), m.group(3), m.group(4))
             for m in FUNC_RE.finditer(text)]
    if name_map:
        for m in GENERIC_FUNC_RE.finditer(text):
            if m.group(2) in name_map:
                found.append((m.start(), m.group(1), m.group(2), None, m.group(3)))
    found.sort(key=lambda item: item[0])
    matches = [item[0] for item in found]
    functions = {}
    strings_xref = {}
    data_refs = {}

    for i, (start, ret_type, name, hexaddr, argstr) in enumerate(found):
        if hexaddr:
            address = int(hexaddr, 16)
        else:
            address = name_map.get(name)
            if address is None:
                continue
        rva = address - base if address >= base else address
        end = matches[i + 1] if i + 1 < len(matches) else len(text)
        body = text[start:end]

        strings = []
        for s in STR_RE.findall(body):
            if usable_string(s) and s not in strings:
                strings.append(s)

        call_sites = {}
        for c in CALL_RE.findall(body[body.find('{'):]):
            target = int(c, 16)
            target = target - base if target >= base else target
            call_sites[target] = call_sites.get(target, 0) + 1
        if name_map:
            for token in NAME_CALL_RE.findall(body[body.find('{'):]):
                target = name_map.get(token)
                if target is None:
                    continue
                target = target - base if target >= base else target
                call_sites[target] = call_sites.get(target, 0) + 1
        vcalls = sorted({to_int(t) for t in VCALL_RE.findall(body)} - {0})
        vcalls = [v for v in vcalls if v < max_field]

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

        args = parse_args_list(argstr)
        key = f'0x{rva:x}'
        functions[key] = {
            'name': name,
            'address': address,
            'offset': rva,
            'return_type': ret_type.strip(),
            'signature': f"{ret_type.strip()} ({', '.join(args)})" if args else f'{ret_type.strip()} ()',
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
            'line': text.count('\n', 0, start) + 2,
            'strings': strings,
            'calls': [f'0x{t:x}' for t in sorted(call_sites)],
            'call_sites': {f'0x{t:x}': n for t, n in sorted(call_sites.items())},
            'callers': [],
            'unresolved_calls': [],
            'vcall_slots': vcalls,
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

    prologue_starts = prologue_starts or set()
    starts = set(unwind_starts) | set(prologue_starts)
    known_offsets = {int(k, 16) for k in functions}
    for rva in sorted(starts):
        if rva in known_offsets:
            continue
        address = base + rva
        entry = make_stub(rva, address, section_of(sections, address))
        entry['unwind'] = rva in unwind_starts
        if rva in prologue_starts:
            entry['prologue'] = True
        functions[f'0x{rva:x}'] = entry

    by_section = {}
    for entry in functions.values():
        if entry['section']:
            by_section.setdefault(entry['section'], set()).add(entry['offset'])
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


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def format_row(entry, note='', code='decompiled.c'):
    size = entry.get('size_bytes')
    callers = len(entry.get('callers') or [])
    label = f'{size}B' if size else '?'
    tag = ' lsda' if entry.get('has_lsda') else ''
    line = entry.get('line') or 0
    where = f'{code}:{line}' if line else code
    return f"0x{entry['offset']:x}  {entry['name']}  {label}  callers={callers}{tag}  {where}  {note}".rstrip()


def search(args):
    index = args.out
    functions = load_json(os.path.join(index, 'functions.json'), None)
    if not functions:
        raise SystemExit(f'[-] {os.path.join(index, "functions.json")} not found, build the index first')
    query = args.query.strip()
    if not query:
        raise SystemExit('[-] empty query')

    if re.fullmatch(r'0x[0-9a-fA-F]+', query) or re.fullmatch(r'[0-9]+', query):
        value = int(query, 16)
        key = f'0x{value:x}'
        entry = functions.get(key)
        if entry:
            print(format_row(entry))
            for text, keys in load_json(os.path.join(index, 'strings_xref.json'), {}).items():
                if key in keys:
                    print(f'  xref "{text}"')
            for callee, sites in list((entry.get('call_sites') or {}).items())[:10]:
                print(f'  call {callee} x{sites}')
            for caller in (entry.get('callers') or [])[:10]:
                print(f'  caller {caller}')
            return
        rows = [item for item in functions.values() if value in (item.get('field_offsets') or [])]
        if not rows:
            raise SystemExit(f'[-] nothing at {key}')
        print(f'[+] field {key} -> {len(rows)} functions')
        for item in sorted(rows, key=lambda item: item['offset']):
            print(format_row(item, 'write' if value in (item.get('field_writes') or []) else 'read'))
        return

    xrefs = load_json(os.path.join(index, 'strings_xref.json'), {})
    tokens = sorted({token for token in re.split(r'[^a-z0-9_]+', query.lower()) if len(token) > 1})
    if not tokens:
        raise SystemExit('[-] query needs at least one token of 2+ characters')
    df = {}
    for text in xrefs:
        low = text.lower()
        for token in tokens:
            if token in low:
                df[token] = df.get(token, 0) + 1
    if not df:
        raise SystemExit(f'[-] no strings match "{query}"')
    weight = {token: math.log(1.0 + max(1, len(xrefs)) / count) for token, count in df.items()}

    hits = {}
    for text, keys in xrefs.items():
        low = text.lower()
        score = sum(weight[token] for token in df if token in low)
        if not score:
            continue
        for key in keys:
            row = hits.setdefault(key, [0.0, []])
            row[0] += score
            if text not in row[1]:
                row[1].append(text)
    for key, item in functions.items():
        if any(token in item['name'].lower() for token in tokens):
            hits.setdefault(key, [0.0, []])[0] += 5.0
    if not hits:
        raise SystemExit(f'[-] no functions match "{query}"')

    ordered = sorted(hits.items(), key=lambda item: (-item[1][0], item[0]))
    print(f'[+] "{query}" -> {len(ordered)} functions, showing {min(args.limit, len(ordered))}')
    for key, (_score, texts) in ordered[:args.limit]:
        item = functions.get(key)
        if item is None:
            continue
        print(format_row(item, ' '.join(f'"{text}"' for text in texts[:4])))


def main():
    args = parse_args()
    if args.query:
        return search(args)
    if not args.bin or not args.code:
        raise SystemExit('[-] --bin and --code are required to build the index')
    os.makedirs(args.out, exist_ok=True)

    with open(args.bin, 'rb') as f:
        raw = f.read()
    start, cputype, base, sections = macho_image(raw)
    if cputype != CPU_TYPE_ARM64:
        raise BadImage(f'cputype 0x{cputype:x} is not arm64')
    located = arm64_text(raw, sections)
    if located is None:
        raise BadImage('no executable __text section')
    image_size = len(raw) - start
    name_map = {}
    names_path = args.names or ('imports.json' if os.path.exists('imports.json') else '')
    if names_path and os.path.exists(names_path):
        with open(names_path) as f:
            name_map = {k: v for k, v in json.load(f).items() if isinstance(v, int)}
    unwind_path = args.unwind or os.path.join(args.out, 'unwind.json')
    unwind_starts = set()
    lsda_starts = set()
    if os.path.exists(unwind_path):
        with open(unwind_path) as f:
            unwound = json.load(f)
        unwind_starts = {int(v, 16) for v in unwound.get('starts', [])}
        lsda_starts = {int(v, 16) for v in unwound.get('lsda', [])}
    blob, text_addr = located
    prologue_starts = set()
    thin_starts = set()
    words = array.array('I')
    words.frombytes(blob[:len(blob) & ~3])
    if sys.byteorder != 'little':
        words.byteswap()
    ret = 0xD65F03C0
    for i in range(1, len(words)):
        word = words[i]
        framed = ((word & 0xFF8003FF) in (0xD10003FF, 0xD14003FF)
                  or ((word & 0xFFC00000) == 0xA9800000 and ((word >> 5) & 0x1F) == 31))
        if not framed and word != ret:
            continue
        prev = words[i - 1]
        boundary = prev == ret or prev == 0xD503245F or (prev & 0xFC000000) == 0x14000000
        if not boundary and prev == 0xD503201F and i > 1:
            earlier = words[i - 2]
            boundary = earlier == ret or (earlier & 0xFC000000) == 0x14000000
        if boundary:
            (prologue_starts if framed else thin_starts).add(text_addr + i * 4 - base)
    code_lo = text_addr
    code_hi = text_addr + len(blob)
    pointed = set()
    for section in sections:
        if section['sect'] == '__text' or not section['size'] or not section['fileoff']:
            continue
        begin = section['fileoff']
        for off in range(begin, min(begin + section['size'], len(raw)) - 7, 8):
            value = struct.unpack_from('<Q', raw, off)[0]
            if not value:
                continue
            for mask in ((1 << 36) - 1, (1 << 43) - 1, (1 << 48) - 1):
                if code_lo <= (value & mask) < code_hi:
                    pointed.add(value & mask)
                    break
    for address in pointed:
        index = (address - text_addr) >> 2
        if index <= 0 or index >= len(words) or address & 3:
            continue
        prev = words[index - 1]
        if prev == ret or (prev & 0xFC000000) == 0x14000000:
            thin_starts.add(address - base)
    thin_starts -= prologue_starts
    prologue_starts |= thin_starts

    functions, strings_xref, data_refs, edges = parse_code(args.code, base, image_size,
                                                           args.max_field_offset, sections,
                                                           unwind_starts, prologue_starts,
                                                           name_map)
    for rva in thin_starts:
        entry = functions.get(f'0x{rva:x}')
        if entry:
            entry.pop('prologue', None)
            entry['thin'] = True
    for entry in functions.values():
        if entry['offset'] in lsda_starts:
            entry['has_lsda'] = True
    strings = bin_strings(raw, sections, args.min_string)

    for text_, keys in adrp_string_xrefs(raw, located, sections, functions, strings).items():
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
    print(f'[+] base=0x{base:x} functions={len(functions)} prologue={len(prologue_starts)} '
          f'outside_sections={outside} edges={len(edges)} '
          f'strings={len(strings)} data_refs={len(data_refs)} '
          f'unresolved={unresolved} median_size={sorted(sizes)[len(sizes) // 2] if sizes else 0} '
          f'-> {args.out}')


if __name__ == '__main__':
    try:
        main()
    except (BadImage, struct.error, OSError, ValueError) as exc:
        raise SystemExit(f'[-] {exc}')
