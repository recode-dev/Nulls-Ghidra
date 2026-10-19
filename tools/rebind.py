#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import struct

from binary import is_elf, load_image


def parse_args():
    p = argparse.ArgumentParser(description='Move symbols that point at tiny arm32 stubs onto the next real prologue')
    p.add_argument('--bin', required=True, help='ELF/ELF32 binary the index was built from')
    p.add_argument('--index_dir', default='index_data', help='index directory')
    p.add_argument('--out', default='', help='output index directory, defaults to index_dir')
    p.add_argument('--max-stub', type=int, default=16, help='largest body treated as a stub')
    p.add_argument('--scan', type=int, default=32, help='bytes scanned for a prologue')
    return p.parse_args()


def prologue(word):
    if (word & 0xFFFF4000) == 0xE92D4000:
        return True
    if (word & 0xFFFF0000) == 0xE92D0000 and (word >> 14) & 1:
        return True
    if (word & 0xFFF00000) == 0xE24D0000:
        return True
    return False


def stub(word):
    return word in (0xE3A00000, 0xE1A00000, 0xE12FFF1E, 0xE320F000)


def entry_keys(payload):
    if not isinstance(payload, dict):
        return []
    return [key for key in payload if isinstance(key, str) and key.startswith('0x')]


def main():
    args = parse_args()
    out = args.out or args.index_dir
    os.makedirs(out, exist_ok=True)
    for name in os.listdir(args.index_dir):
        if name.endswith('.json'):
            shutil.copyfile(os.path.join(args.index_dir, name), os.path.join(out, name))

    path = os.path.join(out, 'functions.json')
    functions = json.load(open(path))
    data = open(args.bin, 'rb').read()
    if not is_elf(data) or data[4] != 1:
        print('[+] skipped: not elf32')
        return

    _start, _machine, base, sections = load_image(data)

    def position(address):
        for section in sections:
            if section['addr'] <= address < section['addr'] + section['size'] and section['fileoff']:
                return section['fileoff'] + address - section['addr']
        return None

    shift = 0
    symbols_path = os.path.join(out, 'symbols.json')
    if os.path.exists(symbols_path):
        values = [int(v, 16) for v in (json.load(open(symbols_path)).get('symbols') or {}).values()]
        best = 0
        for candidate in (0, 0x10000, 0x20000, 0x40000, -0x10000):
            hits = sum(1 for value in values if f'0x{value + candidate:x}' in functions)
            if hits > best:
                best, shift = hits, candidate
        if best < 32:
            shift = 0
    if shift:
        def move(value):
            return value - shift
        renamed = {}
        for key, entry in functions.items():
            item = dict(entry)
            item['offset'] = move(item['offset'])
            item['address'] = move(item.get('address') or item['offset'] + shift)
            if item.get('body_offset'):
                item['body_offset'] = move(item['body_offset'])
            item['calls'] = [f'0x{move(int(v, 16)):x}' for v in item.get('calls') or []]
            item['callers'] = [f'0x{move(int(v, 16)):x}' for v in item.get('callers') or []]
            item['unresolved_calls'] = [f'0x{move(int(v, 16)):x}' for v in item.get('unresolved_calls') or []]
            item['data_refs'] = [f'0x{move(int(v, 16)):x}' for v in item.get('data_refs') or []]
            item['call_sites'] = {f'0x{move(int(k, 16)):x}': v for k, v in (item.get('call_sites') or {}).items()}
            renamed[f'0x{item["offset"]:x}'] = item
        functions = renamed
        for name in ('vtables.json', 'classes.json', 'ctors.json'):
            target = os.path.join(out, name)
            if not os.path.exists(target):
                continue
            payload = json.load(open(target))
            text = json.dumps(payload)
            for key in list(entry_keys(payload)):
                text = text.replace(f'"{key}"', f'"0x{move(int(key, 16)):x}"')
            json.dump(json.loads(text), open(target, 'w'), ensure_ascii=False)
        print(f'[+] image shift -0x{shift:x}')

    moved = []
    for key, entry in list(functions.items()):
        size = entry.get('size_bytes') or 0
        if not size:
            continue
        ratio = (entry.get('size_chars') or 0) / size
        if size > args.max_stub and ratio <= 6:
            continue
        rva = entry['offset']
        pos = position(rva)
        if pos is None or pos + 8 > len(data):
            continue
        first = struct.unpack_from('<I', data, pos)[0]
        if not stub(first):
            continue
        delta = None
        for step in range(4, args.scan + 1, 4):
            if pos + step + 4 > len(data):
                break
            word = struct.unpack_from('<I', data, pos + step)[0]
            if prologue(word):
                delta = step
                break
        if delta is None:
            continue
        target = rva + delta
        new_key = f'0x{target:x}'
        if new_key in functions:
            holder = functions[new_key]
            if (holder.get('size_chars') or 0) > 0 and not holder.get('name', '').startswith('unwind.'):
                continue
            del functions[new_key]
        entry = dict(entry)
        entry['body_offset'] = rva
        entry['offset'] = target
        entry['size_bytes'] = max(0, size - delta)
        entry['rebound'] = True
        del functions[key]
        functions[new_key] = entry
        moved.append((rva, target, entry.get('name')))

    json.dump(functions, open(path, 'w'), ensure_ascii=False)
    mapping = {f'0x{old:x}': f'0x{new:x}' for old, new, _name in moved}
    for name in ('vtables.json', 'classes.json', 'ctors.json'):
        target = os.path.join(out, name)
        if not os.path.exists(target):
            continue
        payload = json.load(open(target))
        text = json.dumps(payload)
        for old, new in mapping.items():
            text = text.replace(f'"{old}"', f'"{new}"')
        json.dump(json.loads(text), open(target, 'w'), ensure_ascii=False)
    print(f'[+] rebound={len(moved)} -> {path}')
    for old, new, name in moved[:10]:
        print(f'  0x{old:x} -> 0x{new:x} {name}')


if __name__ == '__main__':
    main()
