#!/usr/bin/env python3

import argparse
import json
import os
import re
import struct
import sys

from binary import (BadImage, chained_slots, classic_slots, load_commands, macho_image,
                    resolve_stubs, u32, u64, uleb)

DYLIB_COMMANDS = (0xc, 0xd, 0x80000018, 0x8000001f)
LC_SYMTAB = 0x2
DYLD_INFO_ONLY = 0x80000022
DYLD_EXPORTS_TRIE = 0x80000033


def parse_args():
    p = argparse.ArgumentParser(description='Dump imports, exports, dylibs and surviving symbols of a mach-o')
    p.add_argument('--bin', required=True, help='Mach-O binary')
    p.add_argument('--out', default='symbols.json', help='rich JSON output')
    p.add_argument('--map', default='', help='flat {name: address} map for xrefs --names')
    p.add_argument('--names', default='', help='flat name table, one name and address per line')
    p.add_argument('--extra', default='', help='extra {name: address} json merged into the map')
    return p.parse_args()


def cstring(data, offset):
    if offset < 0 or offset >= len(data):
        return ''
    end = data.find(b'\0', offset)
    return data[offset:end if end >= 0 else len(data)].decode('utf-8', 'replace')


def clean(name):
    return name.lstrip('_')


def dylibs(data, start):
    names = []
    for cmd, cur, size in load_commands(data, start):
        if cmd in DYLIB_COMMANDS and size >= 24:
            names.append(cstring(data, cur + u32(data, cur + 8, 'dylib')))
    return names


def symbol_table(data, start):
    defined = {}
    undefined = {}
    for cmd, cur, size in load_commands(data, start):
        if cmd != LC_SYMTAB or size < 24:
            continue
        symoff = u32(data, cur + 8, 'symtab')
        nsyms = u32(data, cur + 12, 'symtab')
        stroff = u32(data, cur + 16, 'symtab')
        strsize = u32(data, cur + 20, 'symtab')
        if symoff + nsyms * 16 > len(data) or stroff + strsize > len(data):
            raise BadImage('symbol table out of bounds')
        for index in range(nsyms):
            pos = symoff + index * 16
            strx = u32(data, pos, 'nlist')
            ntype = data[pos + 4]
            value = u64(data, pos + 8, 'nlist')
            if ntype & 0xE0:
                continue
            name = clean(cstring(data, stroff + strx))
            if not name:
                continue
            kind = ntype & 0x0E
            if kind in (0x02, 0x0E) and value:
                defined.setdefault(name, value)
            elif kind == 0 and not value:
                undefined.setdefault(name, 0)
    return defined, undefined


def walk_trie(blob, offset, prefix, base, out, seen):
    if offset in seen or offset >= len(blob):
        return
    seen.add(offset)
    terminal, pos = uleb(blob, offset)
    if terminal:
        flags, pos = uleb(blob, pos)
        if flags & 0x08:
            _ordinal, pos = uleb(blob, pos)
            end = blob.find(b'\0', pos)
            if end < 0:
                return
            pos = end + 1
        elif flags & 0x10:
            stub, pos = uleb(blob, pos)
            _resolver, pos = uleb(blob, pos)
            out[clean(prefix)] = base + stub
        else:
            address, pos = uleb(blob, pos)
            out[clean(prefix)] = base + address
    if pos >= len(blob):
        return
    count = blob[pos]
    pos += 1
    for _ in range(count):
        end = blob.find(b'\0', pos)
        if end < 0:
            return
        edge = blob[pos:end].decode('utf-8', 'replace')
        child, pos = uleb(blob, end + 1)
        walk_trie(blob, child, prefix + edge, base, out, seen)


def exports(data, start, base):
    offset = length = 0
    for cmd, cur, size in load_commands(data, start):
        if cmd == DYLD_EXPORTS_TRIE and size >= 16:
            offset = u32(data, cur + 8, 'exports trie')
            length = u32(data, cur + 12, 'exports trie')
        elif cmd == DYLD_INFO_ONLY and size >= 48 and not length:
            offset = u32(data, cur + 40, 'dyld info')
            length = u32(data, cur + 44, 'dyld info')
    blob = data[start + offset:start + offset + length]
    out = {}
    if blob:
        walk_trie(blob, 0, '', base, out, set())
    return out


def imports(data, start, base, sections):
    slots = chained_slots(data, start, base, sections)
    slots.update(classic_slots(data, start))
    grouped = {}
    for slot, name in slots.items():
        grouped.setdefault(name, {'slots': [], 'stubs': []})['slots'].append(slot)
    for stub, name in resolve_stubs(data, sections, slots).items():
        grouped.setdefault(name, {'slots': [], 'stubs': []})['stubs'].append(stub)
    return grouped


def main():
    args = parse_args()
    with open(args.bin, 'rb') as f:
        data = f.read()
    start, _cputype, base, sections = macho_image(data)

    libraries = dylibs(data, start)
    defined, undefined = symbol_table(data, start)
    exported = exports(data, start, base)
    imported = imports(data, start, base, sections)

    mapping = {}
    for name, address in exported.items():
        mapping.setdefault(name, address)
    for name, address in defined.items():
        mapping.setdefault(name, address)
    for name, item in imported.items():
        mapping.setdefault(name, item['stubs'][0] if item['stubs'] else item['slots'][0])
    if args.extra and os.path.exists(args.extra):
        with open(args.extra, 'r', encoding='utf-8') as f:
            mapping.update({k: v for k, v in json.load(f).items() if isinstance(v, int)})

    if args.names:
        allowed = re.compile(r'[A-Za-z_][A-Za-z0-9_.]{0,180}')
        with open(args.names, 'w', encoding='utf-8') as f:
            for name, address in mapping.items():
                if allowed.fullmatch(name):
                    f.write(f'{name}\t0x{address:x}\n')

    payload = {
        'dylibs': libraries,
        'imports': {name: {'slots': [f'0x{a:x}' for a in item['slots']],
                           'stubs': [f'0x{a:x}' for a in item['stubs']]}
                    for name, item in sorted(imported.items())},
        'exports': {name: f'0x{a:x}' for name, a in sorted(exported.items())},
        'symbols': {name: f'0x{a:x}' for name, a in sorted(defined.items())},
        'unbound': sorted(name for name in undefined if name not in imported),
    }
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)
    if args.map:
        with open(args.map, 'w', encoding='utf-8') as f:
            json.dump(mapping, f, ensure_ascii=False)
    print(f'[+] dylibs={len(libraries)} imports={len(imported)} exports={len(exported)} '
          f'symbols={len(defined)} unbound={len(payload["unbound"])} -> {args.out}')


if __name__ == '__main__':
    try:
        main()
    except (BadImage, struct.error, OSError, ValueError) as exc:
        raise SystemExit(f'[-] {exc}')
