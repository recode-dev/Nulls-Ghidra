#!/usr/bin/env python3
import argparse
import array
import bisect
import json
import os
import struct

from binary import detect_base, macho_sections

PTR_MASKS = ((1 << 36) - 1, (1 << 43) - 1, (1 << 48) - 1)
ADRP_MASK = 0x9F000000
ADRP_OP = 0x90000000
ADD_MASK = 0xFF000000
ADD_OP = 0x91000000
STR_MASK = 0xFFC00000
STR_OP = 0xF9000000
STUR_OP = 0xF8000000
LDR_OP = 0xF9400000
LDUR_OP = 0xF8400000
STP_OP = 0xA9000000
LDP_OP = 0xA9400000
MAX_TABLE = 32


def parse_args():
    p = argparse.ArgumentParser(description='Link code to data tables: who stores, loads or takes a table address')
    p.add_argument('--bin', required=True, help='Mach-O binary')
    p.add_argument('--index_dir', default='index_data', help='index directory')
    p.add_argument('--out', default='', help='output path, defaults to <index_dir>/ctors.json')
    p.add_argument('--window', type=int, default=8, help='instructions inspected after adrp+add')
    return p.parse_args()


def load(path, default):
    if not os.path.exists(path):
        return default
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def adrp_target(word, pc):
    if (word & ADRP_MASK) != ADRP_OP:
        return None
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12), word & 0x1F


def add_offset(word, reg):
    if (word & ADD_MASK) != ADD_OP or (word & 0x1F) != reg or ((word >> 5) & 0x1F) != reg:
        return None
    shift = (word >> 22) & 3
    if shift > 1:
        return None
    return ((word >> 10) & 0xFFF) << (12 * shift)


def decode_code_pointer(value, base, starts):
    for mask in PTR_MASKS:
        rva = (value & mask) - base
        if rva in starts:
            return True
    return False


def main():
    args = parse_args()
    out = args.out or os.path.join(args.index_dir, 'ctors.json')
    functions = load(os.path.join(args.index_dir, 'functions.json'), None)
    if functions is None:
        raise SystemExit(f'[-] {os.path.join(args.index_dir, "functions.json")} not found, run xrefs.py first')
    vtables = load(os.path.join(args.index_dir, 'vtables.json'), {})

    starts = sorted(v['offset'] for v in functions.values())
    starts_set = set(starts)
    vtable_set = {int(key, 16) for key in vtables}

    with open(args.bin, 'rb') as f:
        data = f.read()
    base = detect_base(args.bin)
    sections = macho_sections(data)
    text = next((s for s in sections if s['sect'] == '__text'), None)
    if text is None:
        raise SystemExit('[-] no __text section')

    data_sections = [s for s in sections if s['sect'] != '__text' and s['size'] and s['fileoff']]
    words = array.array('I')
    words.frombytes(data[text['fileoff']:text['fileoff'] + text['size']])
    start = text['addr']

    refs = {}
    for i in range(len(words) - 1):
        page = adrp_target(words[i], start + i * 4)
        if page is None:
            continue
        target, reg = page
        offset = None
        step = 1
        for j in range(1, min(args.window, len(words) - i - 1) + 1):
            offset = add_offset(words[i + j], reg)
            if offset is not None:
                step = j
                break
        if offset is None:
            continue
        address = target + offset
        section = next((s for s in data_sections if s['addr'] <= address < s['addr'] + s['size']), None)
        if section is None:
            continue
        entry = refs.setdefault(address, {'section': f"{section['seg']}.{section['sect']}",
                                          'store': 0, 'load': 0, 'addr': 0, 'access': 0,
                                          'funcs': set(), 'sites': []})
        site = start + i * 4
        entry['funcs'].add(site)
        entry['sites'].append(site)
        hit = False
        for following in words[i + step + 1:i + step + 1 + args.window]:
            op = following & STR_MASK
            rt = following & 0x1F
            rn = (following >> 5) & 0x1F
            if op in (STR_OP, STUR_OP) and rt == reg:
                entry['store'] += 1
                hit = True
            elif op in (LDR_OP, LDUR_OP) and rt == reg:
                entry['load'] += 1
                hit = True
            elif op in (STP_OP, LDP_OP) and (rt == reg or ((following >> 10) & 0x1F) == reg):
                entry['access'] += 1
                hit = True
            elif rn == reg:
                entry['access'] += 1
                hit = True
        if not hit:
            entry['addr'] += 1

    export = {}
    linked = 0
    tables = 0
    for address, entry in refs.items():
        slots = 0
        position = address - base
        while slots < MAX_TABLE and 0 <= position + slots * 8 < len(data) - 8:
            value = struct.unpack_from('<Q', data, position + slots * 8)[0]
            if not decode_code_pointer(value, base, starts_set):
                break
            slots += 1
        owners = set()
        for site in entry['funcs']:
            index = bisect.bisect_right(starts, site - base) - 1
            if index >= 0:
                owners.add(f'0x{starts[index]:x}')
        record = {
            'section': entry['section'],
            'refs': entry['store'] + entry['load'] + entry['addr'] + entry['access'],
            'store': entry['store'],
            'load': entry['load'],
            'access': entry['access'],
            'addr': entry['addr'],
            'funcs': sorted(owners),
            'sites': [f'0x{s - base:x}' for s in entry['sites'][:20]],
        }
        if slots:
            record['table_slots'] = slots
        if slots >= 2:
            tables += 1
        if entry['store'] and slots:
            record['vptr_candidate'] = True
        if address in vtable_set:
            record['vtable'] = f'0x{address:x}'
            linked += 1
        export[f'0x{address:x}'] = record

    with open(out, 'w', encoding='utf-8') as f:
        json.dump(export, f, ensure_ascii=False)

    stored = sum(entry['store'] for entry in refs.values())
    total = sum(entry['store'] + entry['load'] + entry['addr'] + entry['access']
                for entry in refs.values())
    print(f'[+] targets={len(export)} refs={total} stores={stored} '
          f'tables={tables} linked_vtables={linked} -> {out}')


if __name__ == '__main__':
    main()
