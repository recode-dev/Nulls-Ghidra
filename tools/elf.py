#!/usr/bin/env python3

import struct

ELF_MAGIC = b'\x7fELF'
EM_ARM = 40
EM_AARCH64 = 183
SHT_REL = 9
SHT_RELA = 4
SHF_EXECINSTR = 0x4
PT_LOAD = 1
PF_X = 0x1


def elf_image(data):
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        raise ValueError('not an elf image')
    cls = data[4]
    if data[5] != 1:
        raise ValueError('only little endian elf is supported')
    if cls == 1:
        machine = struct.unpack_from('<H', data, 18)[0]
        phoff = struct.unpack_from('<I', data, 28)[0]
        shoff = struct.unpack_from('<I', data, 32)[0]
        phentsize = struct.unpack_from('<H', data, 42)[0]
        phnum = struct.unpack_from('<H', data, 44)[0]
        shentsize = struct.unpack_from('<H', data, 46)[0]
        shnum = struct.unpack_from('<H', data, 48)[0]
        shstrndx = struct.unpack_from('<H', data, 50)[0]
        header = '<IIIIIIIIII'
    elif cls == 2:
        machine = struct.unpack_from('<H', data, 18)[0]
        phoff = struct.unpack_from('<Q', data, 32)[0]
        shoff = struct.unpack_from('<Q', data, 40)[0]
        phentsize = struct.unpack_from('<H', data, 54)[0]
        phnum = struct.unpack_from('<H', data, 56)[0]
        shentsize = struct.unpack_from('<H', data, 58)[0]
        shnum = struct.unpack_from('<H', data, 60)[0]
        shstrndx = struct.unpack_from('<H', data, 62)[0]
        header = '<IIQQQQIIQQ'
    else:
        raise ValueError(f'unknown elf class {cls}')

    raw_sections = []
    for index in range(shnum):
        pos = shoff + index * shentsize
        if pos + shentsize > len(data):
            break
        if cls == 1:
            name, kind, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from(header, data, pos)
        else:
            name, kind, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from(header, data, pos)
        raw_sections.append({'name_off': name, 'type': kind, 'flags': flags, 'addr': addr,
                             'fileoff': offset, 'size': size, 'link': link, 'info': info,
                             'entsize': entsize})

    names = b''
    if 0 <= shstrndx < len(raw_sections):
        table = raw_sections[shstrndx]
        names = data[table['fileoff']:table['fileoff'] + table['size']]

    def section_name(offset):
        if not names or offset >= len(names):
            return ''
        end = names.find(b'\0', offset)
        if end < 0:
            end = len(names)
        return names[offset:end].decode('utf-8', 'replace')

    sections = []
    base = None
    for item in raw_sections:
        if item['type'] == 8:
            continue
        label = section_name(item['name_off'])
        if not item['size']:
            continue
        exec_flag = bool(item['flags'] & SHF_EXECINSTR)
        sections.append({'seg': '', 'sect': label, 'addr': item['addr'], 'size': item['size'],
                         'fileoff': item['fileoff'], 'flags': item['flags'], 'exec': exec_flag,
                         'type': item['type'], 'link': item['link'], 'info': item['info'],
                         'entsize': item['entsize']})
        if exec_flag and item['addr']:
            value = item['addr'] - item['fileoff']
            if base is None or value < base:
                base = value
    if base is None:
        for index in range(phnum):
            pos = phoff + index * phentsize
            if pos + 32 > len(data):
                break
            if cls == 1:
                kind, offset, vaddr, _paddr, filesz = struct.unpack_from('<IIIII', data, pos)
            else:
                kind, flags = struct.unpack_from('<II', data, pos)
                offset, vaddr, _paddr, filesz = struct.unpack_from('<QQQQ', data, pos + 8)
            if kind != PT_LOAD or not filesz:
                continue
            exec_flag = (flags & PF_X) if cls == 2 else True
            if exec_flag:
                base = vaddr - offset if base is None else min(base, vaddr - offset)
    return 0, machine, base or 0, sections


def elf_relocations(data, sections):
    is32 = data[4] == 1
    rel_sections = [s for s in sections if s.get('type') in (SHT_REL, SHT_RELA)]
    out = []
    for section in rel_sections:
        entry = 8 if section['type'] == SHT_REL else 12
        count = section['size'] // entry if entry else 0
        for index in range(count):
            pos = section['fileoff'] + index * entry
            if pos + entry > len(data):
                break
            if is32:
                offset, info = struct.unpack_from('<II', data, pos)
                kind = info & 0xFF
                addend = None
                if section['type'] == SHT_RELA:
                    addend = struct.unpack_from('<i', data, pos + 8)[0]
            else:
                offset, info = struct.unpack_from('<QQ', data, pos)
                kind = info & 0xFFFFFFFF
                addend = None
                if section['type'] == SHT_RELA:
                    addend = struct.unpack_from('<q', data, pos + 8)[0]
            out.append({'offset': offset, 'type': kind, 'addend': addend, 'rela': section['type'] == SHT_RELA})
    return out
