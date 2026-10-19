#!/usr/bin/env python3

import argparse
import json
import os
import re
import struct
import sys

from binary import (BadImage, chained_slots, classic_slots, is_elf, load_commands, load_image,
                    macho_image, resolve_stubs, u32, u64, uleb)

DYLIB_COMMANDS = (0xc, 0xd, 0x80000018, 0x8000001f)
LC_SYMTAB = 0x2
DYLD_INFO_ONLY = 0x80000022
DYLD_EXPORTS_TRIE = 0x80000033


def parse_args():
    p = argparse.ArgumentParser(description='Dump imports, exports, dylibs and surviving symbols of a mach-o')
    p.add_argument('--bin', required=True, help='Mach-O binary')
    p.add_argument('--out', default='index_data/symbols.json', help='rich JSON output')
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


def elf_symbol_tables(data, sections):
    is32 = data[4] == 1
    entry_size = 16 if is32 else 24
    tables = {}
    for section in sections:
        label = section.get('raw')
        if label not in ('.dynsym', '.symtab') or not section['size']:
            continue
        strings = next((s for s in sections if s.get('raw') == ('.dynstr' if label == '.dynsym' else '.strtab')), None)
        if strings is None:
            continue
        blob = data[section['fileoff']:section['fileoff'] + section['size']]
        pool = data[strings['fileoff']:strings['fileoff'] + strings['size']]
        rows = []
        for index in range(len(blob) // entry_size):
            pos = index * entry_size
            if is32:
                name_off, value, _size, info, _other, shndx = struct.unpack_from('<IIIBBH', blob, pos)
                kind = info & 0xF
            else:
                name_off, info, _other, shndx, value, _size = struct.unpack_from('<IBBHQQ', blob, pos)
                kind = info & 0xF
            name = cstring(pool, name_off) if name_off < len(pool) else ''
            rows.append({'name': name, 'value': value, 'shndx': shndx,
                         'bind': (info >> 4) & 0xF, 'type': kind})
        tables[label] = rows
    return tables


def elf_relocation_slots(data, sections, dynamic):
    is32 = data[4] == 1
    slots = {}
    for section in sections:
        if section.get('raw') not in ('.rel.dyn', '.rel.plt', '.rela.dyn', '.rela.plt') or not section['size']:
            continue
        rela = 'rela' in section['raw']
        entry_size = (12 if is32 else 24) if rela else (8 if is32 else 16)
        for index in range(section['size'] // entry_size):
            pos = section['fileoff'] + index * entry_size
            if pos + entry_size > len(data):
                break
            if is32:
                offset, info = struct.unpack_from('<II', data, pos)
                sym = info >> 8
            else:
                offset, info = struct.unpack_from('<QQ', data, pos)
                sym = info >> 32
            if sym and sym < len(dynamic):
                name = dynamic[sym]['name']
                if name:
                    slots.setdefault(name, []).append(offset)
    return slots


def elf_main(args, data):
    _start, _machine, _base, sections = load_image(data)
    tables = elf_symbol_tables(data, sections)
    dynamic = tables.get('.dynsym', [])
    slots = elf_relocation_slots(data, sections, dynamic)

    defined = {}
    exported = {}
    undefined = {}
    for label in ('.symtab', '.dynsym'):
        for row in tables.get(label, []):
            name = row['name']
            if not name or name.startswith('$') or row['type'] in (3, 4) or row['shndx'] >= 0xFFF1:
                continue
            if row['shndx'] == 0:
                undefined.setdefault(name, 0)
            elif row['value']:
                defined.setdefault(name, row['value'])
                if row['bind'] == 1 and row['type'] in (1, 2):
                    exported.setdefault(name, row['value'])

    imported = {}
    for name, hit in slots.items():
        if name in undefined:
            imported[name] = {'slots': hit, 'stubs': []}

    libraries = []
    dynstr = next((s for s in sections if s.get('raw') == '.dynstr'), None)
    dynamic_section = next((s for s in sections if s.get('raw') == '.dynamic'), None)
    if dynstr and dynamic_section:
        pool = data[dynstr['fileoff']:dynstr['fileoff'] + dynstr['size']]
        for pos in range(dynamic_section['fileoff'], dynamic_section['fileoff'] + dynamic_section['size'] - 7, 8):
            tag, value = struct.unpack_from('<iI', data, pos)
            if tag == 0:
                break
            if tag == 1:
                libraries.append(cstring(pool, value))

    mapping = {}
    for name, address in exported.items():
        mapping.setdefault(name, address)
    for name, address in defined.items():
        mapping.setdefault(name, address)
    for name, item in imported.items():
        if item['slots']:
            mapping.setdefault(name, item['slots'][0])
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
                           'stubs': []} for name, item in sorted(imported.items())},
        'exports': {name: f'0x{a:x}' for name, a in sorted(exported.items())},
        'symbols': {name: f'0x{a:x}' for name, a in sorted(defined.items())},
        'unbound': sorted(name for name in undefined if name not in imported),
    }
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)
    if args.map:
        with open(args.map, 'w', encoding='utf-8') as f:
            json.dump(mapping, f, ensure_ascii=False)
    print(f'[+] dylibs={len(libraries)} imports={len(imported)} exports={len(exported)} '
          f'symbols={len(defined)} unbound={len(payload["unbound"])} -> {args.out}')


def main():
    args = parse_args()
    with open(args.bin, 'rb') as f:
        data = f.read()
    if is_elf(data):
        return elf_main(args, data)
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
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
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
