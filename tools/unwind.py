#!/usr/bin/env python3

import argparse
import json
import os
import struct

from binary import macho_sections

SECOND_LEVEL_REGULAR = 2
SECOND_LEVEL_COMPRESSED = 3


def parse_args():
    p = argparse.ArgumentParser(description='Recover function starts, frames and LSDA from __unwind_info')
    p.add_argument('--bin', required=True, help='Mach-O binary')
    p.add_argument('--out', default='index_data/unwind.json', help='output path')
    return p.parse_args()


def section(data, name):
    for entry in macho_sections(data):
        if entry['sect'] == name and entry['size']:
            return entry
    return None


def parse_page(blob, base_offset, function_offset):
    kind = struct.unpack_from('<I', blob, base_offset)[0]
    out = []
    if kind == SECOND_LEVEL_COMPRESSED:
        entry_off, entry_count, _enc_off, _enc_count = struct.unpack_from('<HHHH', blob, base_offset + 4)
        for i in range(entry_count):
            value = struct.unpack_from('<I', blob, base_offset + entry_off + i * 4)[0]
            out.append(function_offset + (value & 0xFFFFFF))
    elif kind == SECOND_LEVEL_REGULAR:
        entry_off, entry_count = struct.unpack_from('<HH', blob, base_offset + 4)
        for i in range(entry_count):
            offset, _encoding = struct.unpack_from('<II', blob, base_offset + entry_off + i * 8)
            out.append(offset)
    return out


def main():
    args = parse_args()
    with open(args.bin, 'rb') as f:
        data = f.read()
    info = section(data, '__unwind_info')
    version = 0
    starts = set()
    lsda = set()
    if info is not None:
        blob = data[info['fileoff']:info['fileoff'] + info['size']]
        version, _ce_off, _ce_count, _pa_off, _pa_count, index_off, index_count = \
            struct.unpack_from('<7I', blob, 0)

        index = [struct.unpack_from('<3I', blob, index_off + i * 12) for i in range(index_count)]
        for i, (function_offset, page_off, lsda_off) in enumerate(index):
            limit = index[i + 1][0] if i + 1 < len(index) else info['size']
            record_off = lsda_off
            while record_off + 8 <= len(blob):
                function, _location = struct.unpack_from('<II', blob, record_off)
                if function < function_offset or function >= limit:
                    break
                lsda.add(function)
                record_off += 8
            for address in parse_page(blob, page_off, function_offset):
                starts.add(address)

    extra = set()
    text = section(data, '__text')
    eh = section(data, '__eh_frame')
    if eh and text:
        base = text['addr'] - text['fileoff']
        table = data[eh['fileoff']:eh['fileoff'] + eh['size']]
        off = 0
        while off + 8 <= len(table):
            length = struct.unpack_from('<I', table, off)[0]
            if length in (0, 0xFFFFFFFF) or off + 4 + length > len(table):
                break
            if struct.unpack_from('<I', table, off + 4)[0]:
                delta = struct.unpack_from('<i', table, off + 8)[0]
                address = eh['addr'] + off + 8 + delta
                if text['addr'] <= address < text['addr'] + text['size']:
                    extra.add(address - base)
            off += 4 + length
    starts |= extra

    payload = {
        'version': version,
        'count': len(starts),
        'starts': [f'0x{a:x}' for a in sorted(starts)],
        'lsda': [f'0x{a:x}' for a in sorted(lsda)],
        'eh_frame': len(extra),
    }
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)

    print(f'[+] version={version} starts={len(starts)} eh_frame={len(extra)} '
          f'lsda={len(lsda)} -> {args.out}')


if __name__ == '__main__':
    main()
