#!/usr/bin/env python3
import argparse
import json
import os
import struct

from binary import detect_base, macho_sections

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
        entry_off, entry_count, enc_off, enc_count = struct.unpack_from('<HHHH', blob, base_offset + 4)
        encodings = [struct.unpack_from('<I', blob, base_offset + enc_off + i * 4)[0]
                     for i in range(enc_count)]
        for i in range(entry_count):
            value = struct.unpack_from('<I', blob, base_offset + entry_off + i * 4)[0]
            delta = value & 0xFFFFFF
            index = value >> 24
            encoding = encodings[min(index, len(encodings) - 1)] if encodings else 0
            out.append((function_offset + delta, encoding))
    elif kind == SECOND_LEVEL_REGULAR:
        entry_off, entry_count = struct.unpack_from('<HH', blob, base_offset + 4)
        for i in range(entry_count):
            offset, encoding = struct.unpack_from('<II', blob, base_offset + entry_off + i * 8)
            out.append((offset, encoding))
    return out


def main():
    args = parse_args()
    with open(args.bin, 'rb') as f:
        data = f.read()
    base = detect_base(args.bin)
    info = section(data, '__unwind_info')
    if info is None:
        raise SystemExit('[-] no __unwind_info section')

    blob = data[info['fileoff']:info['fileoff'] + info['size']]
    version, _ce_off, _ce_count, _pa_off, _pa_count, index_off, index_count = struct.unpack_from('<7I', blob, 0)

    index = [struct.unpack_from('<3I', blob, index_off + i * 12) for i in range(index_count)]
    starts = {}
    lsda = set()
    for i, (function_offset, page_off, lsda_off) in enumerate(index):
        limit = index[i + 1][0] if i + 1 < len(index) else info['size']
        record_off = lsda_off
        while record_off + 8 <= len(blob):
            function, _location = struct.unpack_from('<II', blob, record_off)
            if function < function_offset or function >= limit:
                break
            lsda.add(function)
            record_off += 8
        for address, encoding in parse_page(blob, page_off, function_offset):
            starts.setdefault(address, encoding)

    payload = {
        'version': version,
        'count': len(starts),
        'starts': [f'0x{a:x}' for a in sorted(starts)],
        'lsda': [f'0x{a:x}' for a in sorted(lsda)],
    }
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)

    print(f'[+] version={version} starts={len(starts)} lsda={len(lsda)} -> {args.out}')


if __name__ == '__main__':
    main()
